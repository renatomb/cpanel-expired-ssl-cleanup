#!/bin/bash

# ============================================================================
# EXEMPLOS DE USO DO SCRIPT cpanel_ssl_cleanup.py v1.0
# ============================================================================
# 
# IMPORTANTE: Substitua os valores entre < > pelos seus dados reais antes de executar!
#
# Para obter sua API Key:
#   1. Faça login no cPanel
#   2. Vá em Segurança → Gerenciar Tokens de API
#   3. Crie um novo token e copie-o
#
# NOVIDADES DA VERSÃO 1.0:
#   - Parâmetros --username e --api-key agora são SEPARADOS e OBRIGATÓRIOS
#   - Removido suporte à API2 (apenas UAPI)
#   - Correções na exclusão de certificados
#   - Log agora mostra data de validade em formato legível
#
# ============================================================================

# ----------------------------------------------------------------------------
# EXEMPLO 1: Execução básica (apenas output no terminal)
# ----------------------------------------------------------------------------
# python3 cpanel_ssl_cleanup.py \
#   --username "<SEU_USERNAME>" \
#   --api-key "<SUA_API_KEY_AQUI>" \
#   --hostname "<SEU_HOSTNAME>.com" \
#   --domain "<SEU_DOMINIO>.com"


# ----------------------------------------------------------------------------
# EXEMPLO 2: Com gravação de log em arquivo (RECOMENDADO)
# ----------------------------------------------------------------------------
# python3 cpanel_ssl_cleanup.py \
#   --username "<SEU_USERNAME>" \
#   --api-key "<SUA_API_KEY_AQUI>" \
#   --hostname "<SEU_HOSTNAME>.com" \
#   --domain "<SEU_DOMINIO>.com" \
#   --log


# ----------------------------------------------------------------------------
# EXEMPLO 3: Usando variáveis (mais seguro, não expõe credenciais)
# ----------------------------------------------------------------------------
# CPANEL_USER="meuusuario"
# CPANEL_KEY="minha_api_key_aqui"
# CPANEL_HOST="servidor.exemplo.com"
# CPANEL_DOMAIN="meudominio.com"
# 
# python3 cpanel_ssl_cleanup.py \
#   --username "$CPANEL_USER" \
#   --api-key "$CPANEL_KEY" \
#   --hostname "$CPANEL_HOST" \
#   --domain "$CPANEL_DOMAIN" \
#   --log


# ----------------------------------------------------------------------------
# EXEMPLO 4: Ver ajuda e opções disponíveis
# ----------------------------------------------------------------------------
# python3 cpanel_ssl_cleanup.py --help


# ============================================================================
# EXEMPLO PRONTO PARA USO (substitua os valores):
# ============================================================================

# Defina suas variáveis aqui
USERNAME="cole_seu_username_aqui"
API_KEY="cole_sua_api_key_aqui"
HOSTNAME="servidor.exemplo.com"
DOMAIN="meudominio.com"

# Executar com log
python3 cpanel_ssl_cleanup.py \
  --username "$USERNAME" \
  --api-key "$API_KEY" \
  --hostname "$HOSTNAME" \
  --domain "$DOMAIN" \
  --log

# ============================================================================
# NOTAS IMPORTANTES:
# ============================================================================
# - ✅ O script NÃO é interativo, não fará perguntas durante a execução
# - ✅ Certificados válidos NÃO serão excluídos
# - ✅ Apenas certificados com data_validade < data_atual serão removidos
# - ✅ Use --log para manter registro detalhado das operações
# - ✅ O arquivo de log será salvo no diretório atual
# - ✅ O log mostra data de validade em formato legível e timestamp
# - ✅ Usa UAPI (API moderna do cPanel)
# - ⚠️  NUNCA compartilhe sua API key
# - ⚠️  NUNCA commite API keys em repositórios Git
# ============================================================================

# ============================================================================
# MIGRAÇÃO DA VERSÃO 0.1 PARA 1.0:
# ============================================================================
# 
# ANTES (v0.1):
#   --api-key "username:api_key_here"
#
# AGORA (v1.0):
#   --username "username" --api-key "api_key_here"
#
# O script concatena automaticamente username:api_key na requisição.
# ============================================================================
