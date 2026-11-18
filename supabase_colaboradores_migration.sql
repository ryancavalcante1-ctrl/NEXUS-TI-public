-- Migração aditiva do portal de colaboradores NEXUS TI
CREATE TABLE IF NOT EXISTS public.colaboradores (
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
);
ALTER TABLE public.chamados ADD COLUMN IF NOT EXISTS colaborador_id INTEGER REFERENCES public.colaboradores(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_chamados_colaborador_id ON public.chamados(colaborador_id);
