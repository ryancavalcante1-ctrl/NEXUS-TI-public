from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from io import BytesIO
from urllib.parse import quote
import psycopg2
from psycopg2.extras import DictCursor
import requests
import mimetypes
import secrets
import os
import hmac
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB por envio

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "nexus-anexos")

EXTENSOES_PERMITIDAS = {
    "png", "jpg", "jpeg", "webp", "gif",
    "pdf", "doc", "docx", "xls", "xlsx", "txt", "csv"
}
TAMANHO_MAXIMO_ARQUIVO = 8 * 1024 * 1024  # 8 MB por arquivo


class ConexaoPostgres:
    """Adaptador pequeno para manter o padrão execute/fetch usado no projeto."""
    def __init__(self, conexao):
        self._conexao = conexao

    def execute(self, sql, parametros=None):
        cursor = self._conexao.cursor(cursor_factory=DictCursor)
        # As consultas originais do Flask usavam placeholders SQLite (?)
        cursor.execute(sql.replace("?", "%s"), parametros or ())
        return cursor

    def commit(self):
        self._conexao.commit()

    def rollback(self):
        self._conexao.rollback()

    def close(self):
        self._conexao.close()


def conectar_banco():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não foi configurada no ambiente do servidor.")
    conexao = psycopg2.connect(DATABASE_URL, sslmode="require", connect_timeout=15)
    return ConexaoPostgres(conexao)


def storage_headers(content_type=None):
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY precisam ser configuradas.")
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def enviar_storage(caminho_objeto, conteudo, content_type):
    caminho = quote(caminho_objeto, safe="/")
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_STORAGE_BUCKET}/{caminho}"
    headers = storage_headers(content_type)
    headers["x-upsert"] = "false"
    resposta = requests.post(url, headers=headers, data=conteudo, timeout=60)
    if resposta.status_code not in (200, 201):
        raise RuntimeError(f"Falha ao enviar anexo ao Supabase Storage: {resposta.status_code} {resposta.text[:300]}")


def baixar_storage(caminho_objeto):
    caminho = quote(caminho_objeto, safe="/")
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_STORAGE_BUCKET}/{caminho}"
    resposta = requests.get(url, headers=storage_headers(), timeout=60)
    if resposta.status_code != 200:
        raise RuntimeError(f"Falha ao baixar anexo do Supabase Storage: {resposta.status_code}")
    return resposta.content


def administrador_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("administrador_logado"):
            flash("Entre com a conta de administrador para continuar.", "erro")
            return redirect(url_for("login_administrador", next=request.path))
        return func(*args, **kwargs)
    return wrapper


def colaborador_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("colaborador_id"):
            flash("Entre com sua conta de colaborador para continuar.", "erro")
            return redirect(url_for("login_colaborador", next=request.path))
        return func(*args, **kwargs)
    return wrapper


@app.route("/admin/login", methods=["GET", "POST"])
def login_administrador():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")
        usuario_configurado = os.environ.get("ADMIN_USERNAME", "")
        senha_configurada = os.environ.get("ADMIN_PASSWORD", "")

        if not usuario_configurado or not senha_configurada:
            flash("A conta administrativa ainda não foi configurada no servidor.", "erro")
            return render_template("login_administrador.html")

        usuario_ok = hmac.compare_digest(usuario, usuario_configurado)
        senha_ok = hmac.compare_digest(senha, senha_configurada)
        if usuario_ok and senha_ok:
            session.clear()
            session["administrador_logado"] = True
            destino = request.args.get("next", "")
            if not destino.startswith("/") or destino.startswith("//"):
                destino = url_for("inicio")
            return redirect(destino)

        flash("Usuário ou senha incorretos.", "erro")

    return render_template("login_administrador.html")


@app.route("/admin/sair")
def sair_administrador():
    session.pop("administrador_logado", None)
    flash("Você saiu da área administrativa.", "sucesso")
    return redirect(url_for("login_administrador"))


# --------------------------------------------------
# CONEXAO COM O BANCO DE DADOS
# --------------------------------------------------


# --------------------------------------------------
# CRIACAO E ATUALIZACAO DO BANCO DE DADOS
# --------------------------------------------------

def criar_banco():
    """Confere se as tabelas foram criadas no Supabase antes de iniciar o app."""
    if not DATABASE_URL:
        # Permite importar o módulo localmente sem credenciais; as rotas exigirão a URL.
        return
    conexao = conectar_banco()
    try:
        tabelas = conexao.execute("""
            SELECT
                to_regclass('public.tecnicos') AS tecnicos,
                to_regclass('public.chamados') AS chamados,
                to_regclass('public.historico_chamados') AS historico,
                to_regclass('public.observacoes_chamados') AS observacoes,
                to_regclass('public.anexos_chamados') AS anexos
        """).fetchone()
        ausentes = [nome for nome in ("tecnicos", "chamados", "historico", "observacoes", "anexos") if not tabelas[nome]]
        if ausentes:
            raise RuntimeError("Tabelas ausentes no Supabase: " + ", ".join(ausentes))

        # Cadastro de colaboradores e vínculo dos chamados ao solicitante.
        conexao.execute("""
            CREATE TABLE IF NOT EXISTS colaboradores (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(180) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                telefone VARCHAR(40),
                setor VARCHAR(120) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'Ativo',
                codigo_ativacao VARCHAR(120),
                senha_hash TEXT,
                ativado INTEGER NOT NULL DEFAULT 0,
                data_cadastro VARCHAR(30) NOT NULL
            )
        """)
        conexao.execute("""
            ALTER TABLE chamados
            ADD COLUMN IF NOT EXISTS colaborador_id INTEGER
            REFERENCES colaboradores(id) ON DELETE SET NULL
        """)
        conexao.execute("CREATE INDEX IF NOT EXISTS idx_chamados_colaborador_id ON chamados(colaborador_id)")
        conexao.commit()
    finally:
        conexao.close()


def registrar_historico(conexao, chamado_id, status_anterior, status_novo,
                        responsavel, observacao=""):
    conexao.execute("""
        INSERT INTO historico_chamados
        (chamado_id, status_anterior, status_novo, observacao,
         responsavel, data_evento)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        chamado_id,
        status_anterior,
        status_novo,
        observacao,
        responsavel,
        datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ))


def calcular_tempo_atendimento(data_abertura, data_conclusao=None):
    """Retorna uma duração legível entre a abertura e a conclusão (ou agora)."""
    try:
        inicio = datetime.strptime(data_abertura, "%d/%m/%Y %H:%M")
        fim = (
            datetime.strptime(data_conclusao, "%d/%m/%Y %H:%M:%S")
            if data_conclusao else datetime.now()
        )
        minutos_totais = max(0, int((fim - inicio).total_seconds() // 60))
        dias, resto = divmod(minutos_totais, 24 * 60)
        horas, minutos = divmod(resto, 60)
        partes = []
        if dias:
            partes.append(f"{dias} dia(s)")
        if horas:
            partes.append(f"{horas} hora(s)")
        if minutos or not partes:
            partes.append(f"{minutos} minuto(s)")
        return " e ".join(partes)
    except (TypeError, ValueError):
        return "Não disponível"


# --------------------------------------------------
# CADASTRO E GESTAO DE COLABORADORES (ADMINISTRADOR)
# --------------------------------------------------

@app.route("/admin/colaboradores", methods=["GET", "POST"])
@administrador_required
def gerenciar_colaboradores():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        telefone = request.form.get("telefone", "").strip()
        setor = request.form.get("setor", "").strip()
        if not all([nome, email, setor]):
            flash("Informe nome, e-mail e setor do colaborador.", "erro")
            return redirect(url_for("gerenciar_colaboradores"))
        codigo = secrets.token_urlsafe(9)
        conexao = conectar_banco()
        try:
            conexao.execute("""
                INSERT INTO colaboradores
                (nome, email, telefone, setor, status, codigo_ativacao, ativado, data_cadastro)
                VALUES (?, ?, ?, ?, 'Ativo', ?, 0, ?)
            """, (nome, email, telefone, setor, codigo, datetime.now().strftime("%d/%m/%Y %H:%M")))
            conexao.commit()
            flash(f"Colaborador cadastrado. Código de primeiro acesso: {codigo}", "sucesso")
        except psycopg2.IntegrityError:
            conexao.rollback()
            flash("Este e-mail já está cadastrado.", "erro")
        finally:
            conexao.close()
        return redirect(url_for("gerenciar_colaboradores"))

    conexao = conectar_banco()
    colaboradores = conexao.execute("SELECT id, nome, email, telefone, setor, status, ativado, data_cadastro FROM colaboradores ORDER BY nome").fetchall()
    conexao.close()
    return render_template("colaboradores.html", colaboradores=colaboradores)


@app.route("/admin/colaborador/<int:colaborador_id>/situacao", methods=["POST"])
@administrador_required
def alterar_situacao_colaborador(colaborador_id):
    situacao = request.form.get("status")
    if situacao not in ("Ativo", "Inativo"):
        flash("Situação inválida.", "erro")
        return redirect(url_for("gerenciar_colaboradores"))
    conexao = conectar_banco()
    conexao.execute("UPDATE colaboradores SET status = ? WHERE id = ?", (situacao, colaborador_id))
    conexao.commit()
    conexao.close()
    flash("Situação do colaborador atualizada.", "sucesso")
    return redirect(url_for("gerenciar_colaboradores"))


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
@administrador_required
def inicio():
    conexao = conectar_banco()
    chamados = conexao.execute("""
        SELECT
            chamados.*,
            tecnicos.nome AS tecnico_nome,
            tecnicos.especialidade AS tecnico_especialidade
        FROM chamados
        LEFT JOIN tecnicos ON chamados.tecnico_id = tecnicos.id
        ORDER BY chamados.id DESC
    """).fetchall()

    total = len(chamados)
    abertos = sum(1 for c in chamados if c["status"] == "Aberto")
    andamento = sum(1 for c in chamados if c["status"] == "Em andamento")
    concluidos = sum(1 for c in chamados if c["status"] == "Concluído")
    conexao.close()

    return render_template(
        "index.html",
        chamados=chamados,
        total=total,
        abertos=abertos,
        andamento=andamento,
        concluidos=concluidos
    )


# --------------------------------------------------
# ABERTURA DE CHAMADOS
# --------------------------------------------------

@app.route("/novo-chamado", methods=["GET", "POST"])
@administrador_required
def novo_chamado():
    if request.method == "POST":
        solicitante = request.form.get("solicitante", "").strip()
        titulo = request.form.get("titulo", "").strip()
        categoria = request.form.get("categoria", "").strip()
        prioridade = request.form.get("prioridade", "").strip()
        descricao = request.form.get("descricao", "").strip()
        tecnico_id = request.form.get("tecnico_id", "").strip()

        if not all([solicitante, titulo, categoria, prioridade, descricao, tecnico_id]):
            flash("Preencha todos os campos obrigatórios.", "erro")
            return redirect(url_for("novo_chamado"))

        if categoria not in ["Hardware", "Software", "Rede", "Impressora", "Acesso", "Outros"]:
            flash("Selecione uma categoria válida.", "erro")
            return redirect(url_for("novo_chamado"))

        if prioridade not in ["Baixa", "Média", "Alta"]:
            flash("Selecione uma prioridade válida.", "erro")
            return redirect(url_for("novo_chamado"))

        try:
            tecnico_id = int(tecnico_id)
        except ValueError:
            flash("Selecione um técnico válido.", "erro")
            return redirect(url_for("novo_chamado"))

        conexao = conectar_banco()
        try:
            tecnico = conexao.execute("""
                SELECT id FROM tecnicos
                WHERE id = ? AND status = 'Ativo'
            """, (tecnico_id,)).fetchone()

            if not tecnico:
                flash("Técnico não encontrado ou inativo.", "erro")
                return redirect(url_for("novo_chamado"))

            novo_chamado = conexao.execute("""
                INSERT INTO chamados
                (solicitante, titulo, categoria, prioridade,
                 descricao, status, data_abertura, tecnico_id)
                VALUES (?, ?, ?, ?, ?, 'Aberto', ?, ?)
                RETURNING id
            """, (
                solicitante, titulo, categoria, prioridade, descricao,
                datetime.now().strftime("%d/%m/%Y %H:%M"), tecnico_id
            )).fetchone()

            chamado_id_novo = novo_chamado["id"]

            registrar_historico(
                conexao, chamado_id_novo, None, "Aberto", "Sistema",
                "Chamado aberto e atribuído ao técnico."
            )
            conexao.commit()
        finally:
            conexao.close()

        flash("Chamado registrado com sucesso!", "sucesso")
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    tecnicos = conexao.execute("""
        SELECT id, nome, especialidade
        FROM tecnicos
        WHERE status = 'Ativo'
        ORDER BY nome ASC
    """).fetchall()
    conexao.close()

    return render_template("novo_chamado.html", tecnicos=tecnicos)


# --------------------------------------------------
# ATUALIZACAO DO STATUS PELO ADMINISTRADOR
# --------------------------------------------------

@app.route("/atualizar-status/<int:chamado_id>", methods=["POST"])
@administrador_required
def atualizar_status(chamado_id):
    novo_status = request.form.get("status")
    status_validos = ["Aberto", "Em andamento", "Concluído"]

    if novo_status not in status_validos:
        flash("Status inválido.", "erro")
        return redirect(url_for("inicio"))

    if novo_status == "Concluído":
        flash("O encerramento exige a solução técnica registrada pelo profissional responsável na área do técnico.", "erro")
        return redirect(url_for("inicio"))

    conexao = conectar_banco()
    chamado = conexao.execute(
        "SELECT status FROM chamados WHERE id = ?", (chamado_id,)
    ).fetchone()

    if not chamado:
        conexao.close()
        flash("Chamado não encontrado.", "erro")
        return redirect(url_for("inicio"))

    status_anterior = chamado["status"]
    if status_anterior != novo_status:
        conexao.execute(
            "UPDATE chamados SET status = ? WHERE id = ?",
            (novo_status, chamado_id)
        )
        registrar_historico(
            conexao, chamado_id, status_anterior, novo_status,
            "Administrador", request.form.get("observacao", "").strip()
        )

    conexao.commit()
    conexao.close()
    flash("Status do chamado atualizado com sucesso!", "sucesso")
    return redirect(url_for("inicio"))


# --------------------------------------------------
# EQUIPE TECNICA
# --------------------------------------------------

@app.route("/equipe-tecnica")
@administrador_required
def equipe_tecnica():
    conexao = conectar_banco()
    tecnicos = conexao.execute(
        "SELECT * FROM tecnicos ORDER BY nome ASC"
    ).fetchall()
    conexao.close()
    return render_template("tecnicos.html", tecnicos=tecnicos)


@app.route("/cadastrar-tecnico", methods=["POST"])
@administrador_required
def cadastrar_tecnico():
    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    telefone = request.form.get("telefone", "").strip()
    especialidade = request.form.get("especialidade", "").strip()

    if not nome or not email or not especialidade:
        flash("Preencha todos os campos obrigatórios.", "erro")
        return redirect(url_for("equipe_tecnica"))

    especialidades_validas = [
        "Hardware", "Software", "Redes", "Infraestrutura", "Suporte geral"
    ]
    if especialidade not in especialidades_validas:
        flash("Selecione uma especialidade válida.", "erro")
        return redirect(url_for("equipe_tecnica"))

    conexao = conectar_banco()
    # A senha temporária é exibida uma única vez ao administrador após o cadastro.
    # O hash é salvo no banco; a senha em texto puro não é armazenada.
    senha_temporaria = secrets.token_urlsafe(12)
    senha_hash = generate_password_hash(senha_temporaria)

    try:
        conexao.execute("""
            INSERT INTO tecnicos
            (nome, email, telefone, especialidade, senha_hash, ativado,
             codigo_ativacao, status)
            VALUES (?, ?, ?, ?, ?, 1, NULL, 'Ativo')
        """, (nome, email, telefone, especialidade, senha_hash))
        conexao.commit()
        flash(
            f"Técnico cadastrado e liberado para acesso. E-mail: {email} | "
            f"Senha temporária: {senha_temporaria}. Anote e entregue ao técnico por um canal seguro.",
            "sucesso"
        )
    except psycopg2.IntegrityError:
        conexao.rollback()
        flash("Este e-mail já está cadastrado.", "erro")
    finally:
        conexao.close()

    return redirect(url_for("equipe_tecnica"))


@app.route("/redefinir-senha-tecnico/<int:tecnico_id>", methods=["POST"])
@administrador_required
def redefinir_senha_tecnico(tecnico_id):
    """Gera uma nova senha temporária sem excluir ou recriar o técnico."""
    conexao = conectar_banco()
    try:
        tecnico = conexao.execute(
            "SELECT id, nome, email FROM tecnicos WHERE id = ?",
            (tecnico_id,)
        ).fetchone()

        if not tecnico:
            flash("Técnico não encontrado.", "erro")
            return redirect(url_for("equipe_tecnica"))

        senha_temporaria = secrets.token_urlsafe(12)
        senha_hash = generate_password_hash(senha_temporaria)
        conexao.execute(
            "UPDATE tecnicos SET senha_hash = ?, ativado = 1, codigo_ativacao = NULL WHERE id = ?",
            (senha_hash, tecnico_id)
        )
        conexao.commit()
        flash(
            f"Nova senha temporária gerada para {tecnico['nome']} ({tecnico['email']}): "
            f"{senha_temporaria}. Anote e entregue ao técnico por um canal seguro. A senha anterior deixou de funcionar.",
            "sucesso"
        )
    except Exception:
        conexao.rollback()
        app.logger.exception("Erro ao redefinir senha do técnico %s", tecnico_id)
        flash("Não foi possível gerar uma nova senha. Tente novamente.", "erro")
    finally:
        conexao.close()

    return redirect(url_for("equipe_tecnica"))


# --------------------------------------------------
# ACESSO DO COLABORADOR
# --------------------------------------------------

@app.route("/login-colaborador", methods=["GET", "POST"])
def login_colaborador():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        conexao = conectar_banco()
        colaborador = conexao.execute("""
            SELECT id, nome, email, setor, senha_hash, status, ativado
            FROM colaboradores WHERE email = ?
        """, (email,)).fetchone()
        conexao.close()
        if (colaborador and colaborador["status"] == "Ativo" and colaborador["ativado"] == 1
                and colaborador["senha_hash"] and check_password_hash(colaborador["senha_hash"], senha)):
            session.clear()
            session["colaborador_id"] = colaborador["id"]
            session["colaborador_nome"] = colaborador["nome"]
            session["colaborador_setor"] = colaborador["setor"]
            destino = request.args.get("next", "")
            if not destino.startswith("/") or destino.startswith("//"):
                destino = url_for("painel_colaborador")
            return redirect(destino)
        flash("E-mail ou senha incorretos. Confira os dados fornecidos pelo administrador.", "erro")
    return render_template("login_colaborador.html")


@app.route("/colaborador/primeiro-acesso", methods=["GET", "POST"])
def primeiro_acesso_colaborador():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        codigo = request.form.get("codigo", "").strip()
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar_senha", "")
        if not all([email, codigo, senha, confirmar]) or len(senha) < 8 or senha != confirmar:
            flash("Confira os dados. A senha deve ter ao menos 8 caracteres e as duas senhas devem coincidir.", "erro")
            return redirect(url_for("primeiro_acesso_colaborador"))
        conexao = conectar_banco()
        try:
            colaborador = conexao.execute("""
                SELECT id FROM colaboradores
                WHERE email = ? AND codigo_ativacao = ? AND ativado = 0 AND status = 'Ativo'
            """, (email, codigo)).fetchone()
            if not colaborador:
                flash("E-mail ou código de ativação inválido.", "erro")
                return redirect(url_for("primeiro_acesso_colaborador"))
            conexao.execute("""
                UPDATE colaboradores SET senha_hash = ?, ativado = 1, codigo_ativacao = NULL
                WHERE id = ?
            """, (generate_password_hash(senha), colaborador["id"]))
            conexao.commit()
        finally:
            conexao.close()
        flash("Conta ativada! Agora você já pode entrar.", "sucesso")
        return redirect(url_for("login_colaborador"))
    return render_template("primeiro_acesso_colaborador.html")


@app.route("/painel-colaborador")
@colaborador_required
def painel_colaborador():
    conexao = conectar_banco()
    chamados = conexao.execute("""
        SELECT c.id, c.titulo, c.categoria, c.prioridade, c.status, c.data_abertura,
               t.nome AS tecnico_nome
        FROM chamados c LEFT JOIN tecnicos t ON t.id = c.tecnico_id
        WHERE c.colaborador_id = ? ORDER BY c.id DESC
    """, (session["colaborador_id"],)).fetchall()
    conexao.close()
    return render_template("painel_colaborador.html", chamados=chamados,
                           nome=session.get("colaborador_nome", "Colaborador"),
                           setor=session.get("colaborador_setor", ""))


@app.route("/colaborador/novo-chamado", methods=["GET", "POST"])
@colaborador_required
def colaborador_novo_chamado():
    categorias = ["Hardware", "Software", "Rede", "Impressora", "Acesso", "Outros"]
    prioridades = ["Baixa", "Média", "Alta"]
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        categoria = request.form.get("categoria", "").strip()
        prioridade = request.form.get("prioridade", "").strip()
        descricao = request.form.get("descricao", "").strip()
        if not titulo or not descricao or categoria not in categorias or prioridade not in prioridades:
            flash("Preencha todos os campos e selecione categoria e prioridade válidas.", "erro")
            return redirect(url_for("colaborador_novo_chamado"))
        especialidades = {
            "Hardware": ["Hardware", "Suporte geral"],
            "Software": ["Software", "Suporte geral"],
            "Rede": ["Redes", "Infraestrutura", "Suporte geral"],
            "Impressora": ["Infraestrutura", "Hardware", "Suporte geral"],
            "Acesso": ["Software", "Suporte geral"],
            "Outros": ["Suporte geral", "Infraestrutura"]
        }
        conexao = conectar_banco()
        try:
            tecnico = None
            for especialidade in especialidades[categoria]:
                tecnico = conexao.execute("""
                    SELECT id FROM tecnicos WHERE status = 'Ativo' AND especialidade = ?
                    ORDER BY nome LIMIT 1
                """, (especialidade,)).fetchone()
                if tecnico:
                    break
            if not tecnico:
                tecnico = conexao.execute("SELECT id FROM tecnicos WHERE status = 'Ativo' ORDER BY nome LIMIT 1").fetchone()
            if not tecnico:
                flash("Ainda não há técnicos ativos para receber chamados. Procure o administrador.", "erro")
                return redirect(url_for("colaborador_novo_chamado"))
            chamado = conexao.execute("""
                INSERT INTO chamados
                (solicitante, titulo, categoria, prioridade, descricao, status,
                 data_abertura, tecnico_id, colaborador_id)
                VALUES (?, ?, ?, ?, ?, 'Aberto', ?, ?, ?) RETURNING id
            """, (session.get("colaborador_nome", "Colaborador"), titulo, categoria,
                  prioridade, descricao, datetime.now().strftime("%d/%m/%Y %H:%M"),
                  tecnico["id"], session["colaborador_id"])).fetchone()
            registrar_historico(conexao, chamado["id"], None, "Aberto", "Sistema",
                                "Chamado aberto pelo colaborador e encaminhado automaticamente.")
            conexao.commit()
        finally:
            conexao.close()
        flash("Chamado aberto e encaminhado à equipe responsável.", "sucesso")
        return redirect(url_for("painel_colaborador"))
    return render_template("colaborador_novo_chamado.html")


@app.route("/colaborador/sair")
def sair_colaborador():
    session.clear()
    flash("Você saiu da sua conta.", "sucesso")
    return redirect(url_for("login_colaborador"))


# --------------------------------------------------
# PRIMEIRO ACESSO: TECNICO CRIA A PROPRIA SENHA
# --------------------------------------------------

@app.route("/primeiro-acesso", methods=["GET", "POST"])
def primeiro_acesso():
    flash("A ativação não é mais necessária. O administrador fornece uma senha temporária no cadastro.", "info")
    return redirect(url_for("login_tecnico"))


# --------------------------------------------------
# LOGIN DO TECNICO
# --------------------------------------------------

@app.route("/login-tecnico", methods=["GET", "POST"])
def login_tecnico():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        if not email or not senha:
            flash("Informe seu e-mail e sua senha.", "erro")
            return redirect(url_for("login_tecnico"))

        conexao = conectar_banco()
        tecnico = conexao.execute("""
            SELECT id, nome, email, senha_hash, status, ativado
            FROM tecnicos
            WHERE email = ?
        """, (email,)).fetchone()
        conexao.close()

        if (
            tecnico
            and tecnico["status"] == "Ativo"
            and tecnico["senha_hash"]
            and check_password_hash(tecnico["senha_hash"], senha)
        ):
            session.clear()
            session["tecnico_id"] = tecnico["id"]
            session["tecnico_nome"] = tecnico["nome"]
            return redirect(url_for("painel_tecnico"))

        flash("E-mail ou senha incorretos. Confira os dados fornecidos pelo administrador.", "erro")
        return redirect(url_for("login_tecnico"))

    return render_template("login_tecnico.html")


# --------------------------------------------------
# PAINEL INDIVIDUAL DO TECNICO
# --------------------------------------------------

@app.route("/painel-tecnico")
def painel_tecnico():
    tecnico_id = session.get("tecnico_id")
    if not tecnico_id:
        flash("Faça login para acessar o painel.", "erro")
        return redirect(url_for("login_tecnico"))

    conexao = conectar_banco()
    chamados = conexao.execute("""
        SELECT * FROM chamados
        WHERE tecnico_id = ?
        ORDER BY id DESC
    """, (tecnico_id,)).fetchall()
    conexao.close()

    total = len(chamados)
    abertos = sum(1 for c in chamados if c["status"] == "Aberto")
    andamento = sum(1 for c in chamados if c["status"] == "Em andamento")
    concluidos = sum(1 for c in chamados if c["status"] == "Concluído")

    return render_template(
        "painel_tecnico.html",
        chamados=chamados,
        nome=session.get("tecnico_nome", "Técnico"),
        total=total,
        abertos=abertos,
        andamento=andamento,
        concluidos=concluidos
    )


# --------------------------------------------------
# DETALHES DO CHAMADO - AREA DO TECNICO
# --------------------------------------------------

@app.route("/tecnico/chamado/<int:chamado_id>")
def detalhes_chamado(chamado_id):
    tecnico_id = session.get("tecnico_id")
    if not tecnico_id:
        flash("Faça login para acessar o chamado.", "erro")
        return redirect(url_for("login_tecnico"))

    conexao = conectar_banco()
    chamado = conexao.execute("""
        SELECT id, solicitante, titulo, categoria, prioridade,
               descricao, status, data_abertura, solucao,
               data_conclusao, concluido_por
        FROM chamados
        WHERE id = ? AND tecnico_id = ?
    """, (chamado_id, tecnico_id)).fetchone()

    if not chamado:
        conexao.close()
        flash("Chamado não encontrado ou não atribuído a você.", "erro")
        return redirect(url_for("painel_tecnico"))

    historico = conexao.execute("""
        SELECT status_anterior, status_novo, observacao,
               responsavel, data_evento
        FROM historico_chamados
        WHERE chamado_id = ?
        ORDER BY id DESC
    """, (chamado_id,)).fetchall()

    observacoes = conexao.execute("""
        SELECT responsavel, observacao, data_evento
        FROM observacoes_chamados
        WHERE chamado_id = ?
        ORDER BY id DESC
    """, (chamado_id,)).fetchall()

    anexos = conexao.execute("""
        SELECT id, responsavel, nome_original, data_evento
        FROM anexos_chamados
        WHERE chamado_id = ?
        ORDER BY id DESC
    """, (chamado_id,)).fetchall()

    conexao.close()

    tempo_atendimento = calcular_tempo_atendimento(
        chamado["data_abertura"],
        chamado["data_conclusao"]
    )

    return render_template(
        "detalhes_chamado.html",
        chamado=chamado,
        historico=historico,
        observacoes=observacoes,
        anexos=anexos,
        tempo_atendimento=tempo_atendimento
    )


# --------------------------------------------------
# NOVA OBSERVACAO TECNICA
# --------------------------------------------------

@app.route("/tecnico/chamado/<int:chamado_id>/observacao", methods=["POST"])
def registrar_observacao_tecnica(chamado_id):
    tecnico_id = session.get("tecnico_id")
    if not tecnico_id:
        flash("Faça login para registrar uma observação.", "erro")
        return redirect(url_for("login_tecnico"))

    observacao = request.form.get("observacao", "").strip()
    if not observacao:
        flash("Digite uma observação antes de salvar.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    if len(observacao) > 3000:
        flash("A observação deve ter no máximo 3.000 caracteres.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    conexao = conectar_banco()
    chamado = conexao.execute("""
        SELECT id, status FROM chamados
        WHERE id = ? AND tecnico_id = ?
    """, (chamado_id, tecnico_id)).fetchone()

    if not chamado:
        conexao.close()
        flash("Chamado não encontrado ou não atribuído a você.", "erro")
        return redirect(url_for("painel_tecnico"))

    if chamado["status"] == "Concluído":
        conexao.close()
        flash("Este chamado está concluído. Reabra-o para registrar novas observações.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    conexao.execute("""
        INSERT INTO observacoes_chamados
        (chamado_id, tecnico_id, responsavel, observacao, data_evento)
        VALUES (?, ?, ?, ?, ?)
    """, (
        chamado_id,
        tecnico_id,
        session.get("tecnico_nome", "Técnico"),
        observacao,
        datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ))
    conexao.commit()
    conexao.close()

    flash("Observação técnica registrada com sucesso!", "sucesso")
    return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))


# --------------------------------------------------
# ANEXAR ARQUIVOS AO CHAMADO
# --------------------------------------------------

@app.route("/tecnico/chamado/<int:chamado_id>/anexo", methods=["POST"])
def anexar_arquivo_chamado(chamado_id):
    tecnico_id = session.get("tecnico_id")
    if not tecnico_id:
        flash("Faça login para anexar arquivos.", "erro")
        return redirect(url_for("login_tecnico"))

    conexao = conectar_banco()
    chamado = conexao.execute("""
        SELECT id, status FROM chamados
        WHERE id = ? AND tecnico_id = ?
    """, (chamado_id, tecnico_id)).fetchone()

    if not chamado:
        conexao.close()
        flash("Chamado não encontrado ou não atribuído a você.", "erro")
        return redirect(url_for("painel_tecnico"))

    if chamado["status"] == "Concluído":
        conexao.close()
        flash("Este chamado está concluído. Reabra-o para enviar novos anexos.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    arquivos = request.files.getlist("arquivos")
    arquivos_validos = [arquivo for arquivo in arquivos if arquivo and arquivo.filename]

    if not arquivos_validos:
        conexao.close()
        flash("Selecione pelo menos um arquivo.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    salvos = 0
    erros = []

    try:
        for arquivo in arquivos_validos:
            nome_original = os.path.basename(arquivo.filename).strip()
            nome_seguro = secure_filename(nome_original)
            extensao = nome_seguro.rsplit(".", 1)[1].lower() if "." in nome_seguro else ""

            if not nome_seguro or extensao not in EXTENSOES_PERMITIDAS:
                erros.append(f"{nome_original}: formato não permitido")
                continue

            arquivo.stream.seek(0, os.SEEK_END)
            tamanho = arquivo.stream.tell()
            arquivo.stream.seek(0)

            if tamanho == 0:
                erros.append(f"{nome_original}: arquivo vazio")
                continue
            if tamanho > TAMANHO_MAXIMO_ARQUIVO:
                erros.append(f"{nome_original}: excede o limite de 8 MB")
                continue

            nome_armazenado = f"chamados/{chamado_id}/{secrets.token_hex(16)}.{extensao}"
            conteudo = arquivo.read()
            content_type = arquivo.mimetype or mimetypes.guess_type(nome_original)[0] or "application/octet-stream"
            enviar_storage(nome_armazenado, conteudo, content_type)

            conexao.execute("""
                INSERT INTO anexos_chamados
                (chamado_id, tecnico_id, responsavel, nome_original,
                 nome_arquivo, data_evento)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                chamado_id,
                tecnico_id,
                session.get("tecnico_nome", "Técnico"),
                nome_original[:255],
                nome_armazenado,
                datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            ))
            salvos += 1

        conexao.commit()
    except Exception:
        conexao.rollback()
        conexao.close()
        raise
    else:
        conexao.close()

    if salvos:
        flash(f"{salvos} arquivo(s) anexado(s) com sucesso!", "sucesso")
    if erros:
        flash("Alguns arquivos não foram anexados: " + "; ".join(erros), "erro")

    return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))


# --------------------------------------------------
# DOWNLOAD PROTEGIDO DOS ANEXOS
# --------------------------------------------------

@app.route("/tecnico/anexo/<int:anexo_id>")
def baixar_anexo_chamado(anexo_id):
    tecnico_id = session.get("tecnico_id")
    if not tecnico_id:
        flash("Faça login para baixar anexos.", "erro")
        return redirect(url_for("login_tecnico"))

    conexao = conectar_banco()
    anexo = conexao.execute("""
        SELECT a.nome_arquivo, a.nome_original, a.chamado_id
        FROM anexos_chamados a
        INNER JOIN chamados c ON c.id = a.chamado_id
        WHERE a.id = ? AND c.tecnico_id = ?
    """, (anexo_id, tecnico_id)).fetchone()
    conexao.close()

    if not anexo:
        flash("Anexo não encontrado ou sem permissão de acesso.", "erro")
        return redirect(url_for("painel_tecnico"))

    try:
        conteudo = baixar_storage(anexo["nome_arquivo"])
    except Exception:
        app.logger.exception("Erro ao recuperar anexo do Supabase Storage")
        flash("Não foi possível baixar o anexo neste momento.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=anexo["chamado_id"]))

    return send_file(
        BytesIO(conteudo),
        as_attachment=True,
        download_name=anexo["nome_original"],
        mimetype="application/octet-stream"
    )


# --------------------------------------------------
# TECNICO ATUALIZA SOMENTE SEUS PROPRIOS CHAMADOS
# --------------------------------------------------

@app.route("/tecnico/atualizar-status/<int:chamado_id>", methods=["POST"])
def tecnico_atualizar_status(chamado_id):
    tecnico_id = session.get("tecnico_id")
    if not tecnico_id:
        flash("Faça login para continuar.", "erro")
        return redirect(url_for("login_tecnico"))

    novo_status = request.form.get("status")
    status_validos = ["Aberto", "Em andamento", "Concluído"]
    if novo_status not in status_validos:
        flash("Status inválido.", "erro")
        return redirect(url_for("painel_tecnico"))

    solucao = request.form.get("solucao", "").strip()
    if novo_status == "Concluído" and not solucao:
        flash("Antes de concluir, registre a solução técnica aplicada no chamado.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    if len(solucao) > 5000:
        flash("A solução técnica deve ter no máximo 5.000 caracteres.", "erro")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    conexao = conectar_banco()
    chamado = conexao.execute("""
        SELECT status FROM chamados
        WHERE id = ? AND tecnico_id = ?
    """, (chamado_id, tecnico_id)).fetchone()

    if not chamado:
        conexao.close()
        flash("Chamado não encontrado na sua lista.", "erro")
        return redirect(url_for("painel_tecnico"))

    status_anterior = chamado["status"]
    responsavel = session.get("tecnico_nome", "Técnico")

    if status_anterior != novo_status:
        if novo_status == "Concluído":
            data_conclusao = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            conexao.execute("""
                UPDATE chamados
                SET status = ?, solucao = ?, data_conclusao = ?, concluido_por = ?
                WHERE id = ? AND tecnico_id = ?
            """, (novo_status, solucao, data_conclusao, responsavel, chamado_id, tecnico_id))
            observacao_historico = "Solução técnica: " + solucao
        elif status_anterior == "Concluído":
            # Reabertura: o encerramento anterior permanece registrado no histórico.
            conexao.execute("""
                UPDATE chamados
                SET status = ?, solucao = NULL, data_conclusao = NULL, concluido_por = NULL
                WHERE id = ? AND tecnico_id = ?
            """, (novo_status, chamado_id, tecnico_id))
            observacao_historico = (
                request.form.get("observacao", "").strip()
                or "Chamado reaberto para continuidade do atendimento."
            )
        else:
            conexao.execute("""
                UPDATE chamados SET status = ?
                WHERE id = ? AND tecnico_id = ?
            """, (novo_status, chamado_id, tecnico_id))
            observacao_historico = request.form.get("observacao", "").strip()

        registrar_historico(
            conexao, chamado_id, status_anterior, novo_status,
            responsavel, observacao_historico
        )

    conexao.commit()
    conexao.close()
    if novo_status == "Concluído":
        flash("Chamado concluído com solução técnica registrada!", "sucesso")
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))

    flash("Status do chamado atualizado!", "sucesso")
    return redirect(url_for("painel_tecnico"))


# --------------------------------------------------
# SAIR DA CONTA DO TECNICO
# --------------------------------------------------

@app.route("/sair-tecnico")
def sair_tecnico():
    session.clear()
    flash("Você saiu da sua conta.", "sucesso")
    return redirect(url_for("login_tecnico"))


@app.errorhandler(413)
def arquivo_muito_grande(_erro):
    flash("O envio ultrapassou 16 MB. Envie menos arquivos por vez.", "erro")
    chamado_id = request.view_args.get("chamado_id") if request.view_args else None
    if chamado_id:
        return redirect(url_for("detalhes_chamado", chamado_id=chamado_id))
    return redirect(url_for("painel_tecnico"))


@app.route("/health")
def health():
    try:
        conexao = conectar_banco()
        conexao.execute("SELECT 1")
        conexao.close()
        return {"status": "ok"}, 200
    except Exception:
        app.logger.exception("Health check falhou")
        return {"status": "unavailable"}, 503


# --------------------------------------------------
# INICIALIZACAO DO SISTEMA
# --------------------------------------------------

# Inicializa o esquema também quando o aplicativo é carregado pelo Gunicorn.
criar_banco()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            use_reloader=False)
