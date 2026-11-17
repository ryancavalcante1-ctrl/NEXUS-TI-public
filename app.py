from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import sqlite3
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
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

# No Render, configure DATABASE_PATH e UPLOAD_FOLDER no disco persistente.
DATA_FOLDER = os.environ.get("DATA_FOLDER", app.root_path)
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(DATA_FOLDER, "nexus_ti.db"))

# Anexos enviados pelos técnicos (armazenados fora da pasta static).
UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER", os.path.join(DATA_FOLDER, "uploads", "chamados")
)
EXTENSOES_PERMITIDAS = {
    "png", "jpg", "jpeg", "webp", "gif",
    "pdf", "doc", "docx", "xls", "xlsx", "txt", "csv"
}
TAMANHO_MAXIMO_ARQUIVO = 8 * 1024 * 1024  # 8 MB por arquivo
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB por envio


def administrador_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("administrador_logado"):
            flash("Entre com a conta de administrador para continuar.", "erro")
            return redirect(url_for("login_administrador", next=request.path))
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

def conectar_banco():
    pasta_banco = os.path.dirname(os.path.abspath(DATABASE))
    os.makedirs(pasta_banco, exist_ok=True)
    conexao = sqlite3.connect(DATABASE)
    conexao.row_factory = sqlite3.Row
    return conexao


# --------------------------------------------------
# CRIACAO E ATUALIZACAO DO BANCO DE DADOS
# --------------------------------------------------

def criar_banco():
    conexao = conectar_banco()

    conexao.execute("""
        CREATE TABLE IF NOT EXISTS chamados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            solicitante TEXT NOT NULL,
            titulo TEXT NOT NULL,
            categoria TEXT NOT NULL,
            prioridade TEXT NOT NULL,
            descricao TEXT NOT NULL,
            status TEXT DEFAULT 'Aberto',
            data_abertura TEXT NOT NULL
        )
    """)

    conexao.execute("""
        CREATE TABLE IF NOT EXISTS tecnicos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            telefone TEXT,
            especialidade TEXT NOT NULL,
            status TEXT DEFAULT 'Ativo',
            codigo_ativacao TEXT,
            senha_hash TEXT,
            ativado INTEGER DEFAULT 0
        )
    """)

    # Atualiza bancos antigos sem apagar os dados existentes.
    colunas_tecnicos = conexao.execute(
        "PRAGMA table_info(tecnicos)"
    ).fetchall()
    nomes_colunas = [coluna["name"] for coluna in colunas_tecnicos]

    novas_colunas = {
        "codigo_ativacao": "TEXT",
        "senha_hash": "TEXT",
        "ativado": "INTEGER DEFAULT 0"
    }

    for coluna, tipo in novas_colunas.items():
        if coluna not in nomes_colunas:
            conexao.execute(
                f"ALTER TABLE tecnicos ADD COLUMN {coluna} {tipo}"
            )

    colunas_chamados = conexao.execute(
        "PRAGMA table_info(chamados)"
    ).fetchall()

    nomes_colunas_chamados = [coluna["name"] for coluna in colunas_chamados]
    if "tecnico_id" not in nomes_colunas_chamados:
        conexao.execute("""
            ALTER TABLE chamados
            ADD COLUMN tecnico_id INTEGER REFERENCES tecnicos(id)
        """)

    # Dados do encerramento técnico (migração segura de bancos existentes).
    for coluna, tipo in {
        "solucao": "TEXT",
        "data_conclusao": "TEXT",
        "concluido_por": "TEXT"
    }.items():
        if coluna not in nomes_colunas_chamados:
            conexao.execute(f"ALTER TABLE chamados ADD COLUMN {coluna} {tipo}")

    # Histórico de mudanças de status.
    conexao.execute("""
        CREATE TABLE IF NOT EXISTS historico_chamados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chamado_id INTEGER NOT NULL,
            status_anterior TEXT,
            status_novo TEXT NOT NULL,
            observacao TEXT,
            responsavel TEXT NOT NULL,
            data_evento TEXT NOT NULL,
            FOREIGN KEY (chamado_id) REFERENCES chamados(id)
        )
    """)

    # Novo recurso: anotações/observações técnicas independentes do status.
    conexao.execute("""
        CREATE TABLE IF NOT EXISTS observacoes_chamados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chamado_id INTEGER NOT NULL,
            tecnico_id INTEGER NOT NULL,
            responsavel TEXT NOT NULL,
            observacao TEXT NOT NULL,
            data_evento TEXT NOT NULL,
            FOREIGN KEY (chamado_id) REFERENCES chamados(id),
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        )
    """)

    # Arquivos anexados aos chamados.
    conexao.execute("""
        CREATE TABLE IF NOT EXISTS anexos_chamados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chamado_id INTEGER NOT NULL,
            tecnico_id INTEGER NOT NULL,
            responsavel TEXT NOT NULL,
            nome_original TEXT NOT NULL,
            nome_arquivo TEXT NOT NULL,
            data_evento TEXT NOT NULL,
            FOREIGN KEY (chamado_id) REFERENCES chamados(id),
            FOREIGN KEY (tecnico_id) REFERENCES tecnicos(id)
        )
    """)

    conexao.commit()
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

            conexao.execute("""
                INSERT INTO chamados
                (solicitante, titulo, categoria, prioridade,
                 descricao, status, data_abertura, tecnico_id)
                VALUES (?, ?, ?, ?, ?, 'Aberto', ?, ?)
            """, (
                solicitante, titulo, categoria, prioridade, descricao,
                datetime.now().strftime("%d/%m/%Y %H:%M"), tecnico_id
            ))

            chamado_id_novo = conexao.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]

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
    codigo = secrets.token_urlsafe(8)

    try:
        conexao.execute("""
            INSERT INTO tecnicos
            (nome, email, telefone, especialidade, codigo_ativacao)
            VALUES (?, ?, ?, ?, ?)
        """, (nome, email, telefone, especialidade, codigo))
        conexao.commit()
        flash(f"Técnico cadastrado! Código de ativação: {codigo}", "sucesso")
    except sqlite3.IntegrityError:
        flash("Este e-mail já está cadastrado.", "erro")
    finally:
        conexao.close()

    return redirect(url_for("equipe_tecnica"))


# --------------------------------------------------
# PRIMEIRO ACESSO: TECNICO CRIA A PROPRIA SENHA
# --------------------------------------------------

@app.route("/primeiro-acesso", methods=["GET", "POST"])
def primeiro_acesso():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        codigo = request.form.get("codigo", "").strip()
        senha = request.form.get("senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")

        if not all([email, codigo, senha, confirmar_senha]):
            flash("Preencha todos os campos.", "erro")
            return redirect(url_for("primeiro_acesso"))

        if len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "erro")
            return redirect(url_for("primeiro_acesso"))

        if senha != confirmar_senha:
            flash("As senhas não coincidem.", "erro")
            return redirect(url_for("primeiro_acesso"))

        conexao = conectar_banco()
        try:
            tecnico = conexao.execute("""
                SELECT id FROM tecnicos
                WHERE email = ?
                  AND codigo_ativacao = ?
                  AND ativado = 0
                  AND status = 'Ativo'
            """, (email, codigo)).fetchone()

            if not tecnico:
                flash("E-mail ou código inválido.", "erro")
                return redirect(url_for("primeiro_acesso"))

            senha_hash = generate_password_hash(senha)
            conexao.execute("""
                UPDATE tecnicos
                SET senha_hash = ?, ativado = 1, codigo_ativacao = NULL
                WHERE id = ?
            """, (senha_hash, tecnico["id"]))
            conexao.commit()

            flash("Conta ativada! Sua senha foi cadastrada com sucesso.", "sucesso")
            return render_template("primeiro_acesso.html", ativado=True)
        finally:
            conexao.close()

    return render_template("primeiro_acesso.html", ativado=False)


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
            and tecnico["ativado"] == 1
            and tecnico["senha_hash"]
            and check_password_hash(tecnico["senha_hash"], senha)
        ):
            session.clear()
            session["tecnico_id"] = tecnico["id"]
            session["tecnico_nome"] = tecnico["nome"]
            return redirect(url_for("painel_tecnico"))

        flash("E-mail ou senha incorretos, ou conta ainda não ativada.", "erro")
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

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
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

            nome_armazenado = f"{secrets.token_hex(16)}.{extensao}"
            caminho = os.path.join(UPLOAD_FOLDER, nome_armazenado)
            arquivo.save(caminho)

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
        SELECT a.nome_arquivo, a.nome_original
        FROM anexos_chamados a
        INNER JOIN chamados c ON c.id = a.chamado_id
        WHERE a.id = ? AND c.tecnico_id = ?
    """, (anexo_id, tecnico_id)).fetchone()
    conexao.close()

    if not anexo:
        flash("Anexo não encontrado ou sem permissão de acesso.", "erro")
        return redirect(url_for("painel_tecnico"))

    return send_from_directory(
        UPLOAD_FOLDER,
        anexo["nome_arquivo"],
        as_attachment=True,
        download_name=anexo["nome_original"]
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


# --------------------------------------------------
# INICIALIZACAO DO SISTEMA
# --------------------------------------------------

# Inicializa o esquema também quando o aplicativo é carregado pelo Gunicorn.
criar_banco()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            use_reloader=False)
