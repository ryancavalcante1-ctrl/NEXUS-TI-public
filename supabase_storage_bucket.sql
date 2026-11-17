-- Cria o bucket privado usado pelos anexos do NEXUS TI.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('nexus-anexos', 'nexus-anexos', false, 8388608)
ON CONFLICT (id) DO UPDATE
SET public = false,
    file_size_limit = 8388608;
