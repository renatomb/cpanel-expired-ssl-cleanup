# cPanel SSL Certificate Cleanup Script

Script Python para limpeza automática de certificados SSL expirados no cPanel via UAPI.

## 📋 Funcionalidades

- ✅ Conexão ao cPanel via UAPI (API moderna do cPanel)
- ✅ Autenticação com username e API key separados
- ✅ Listagem automática de todos os certificados SSL da conta
- ✅ Verificação precisa de data de validade (suporta timestamps)
- ✅ Exclusão automática APENAS de certificados expirados
- ✅ Logging verboso com data de validade em formato legível
- ✅ Opção de gravação de log em arquivo
- ✅ Tratamento robusto de erros
- ✅ Modo não-interativo (sem perguntas ao usuário)
- ✅ Estatísticas completas da operação

## 🔧 Requisitos

### Sistema
- Python 3.6 ou superior
- Acesso ao cPanel com API key válida

### Dependências Python
```bash
pip install requests
```

## 📦 Instalação

1. Baixe o script:
```bash
wget -O cpanel_ssl_cleanup.py [URL_DO_SCRIPT]
# ou copie o arquivo diretamente
```

2. Torne o script executável:
```bash
chmod +x cpanel_ssl_cleanup.py
```

3. Instale as dependências:
```bash
pip install requests
```

## 🚀 Como Usar

### Sintaxe Básica
```bash
python3 cpanel_ssl_cleanup.py --username <USERNAME> --api-key <API_KEY> --hostname <HOSTNAME> --domain <DOMAIN> [--log]
```

### Parâmetros

#### Obrigatórios:
- `--username`: Username do cPanel
- `--api-key`: API key do cPanel (obtida em cPanel → Segurança → Tokens de API)
- `--hostname`: Hostname do servidor cPanel (ex: servidor.seuhost.com)
- `--domain`: Nome do domínio (usado para nomear o arquivo de log)

#### Opcionais:
- `--log`: Ativa gravação de log em arquivo

### Exemplos

#### Exemplo 1: Execução básica (apenas output no terminal)
```bash
python3 cpanel_ssl_cleanup.py \
  --username "meuusuario" \
  --api-key "abc123xyz789" \
  --hostname "server.example.com" \
  --domain "meudominio.com"
```

#### Exemplo 2: Com gravação de log em arquivo
```bash
python3 cpanel_ssl_cleanup.py \
  --username "meuusuario" \
  --api-key "abc123xyz789" \
  --hostname "server.example.com" \
  --domain "meudominio.com" \
  --log
```

#### Exemplo 3: Usando variáveis de ambiente (mais seguro)
```bash
CPANEL_USER="meuusuario"
CPANEL_KEY="abc123xyz789"

python3 cpanel_ssl_cleanup.py \
  --username "$CPANEL_USER" \
  --api-key "$CPANEL_KEY" \
  --hostname "server.example.com" \
  --domain "meudominio.com" \
  --log
```

## 🔑 Como Obter a API Key do cPanel

1. Faça login no cPanel
2. Navegue até **Segurança** → **Gerenciar Tokens de API**
3. Clique em **Criar Token**
4. Dê um nome ao token (ex: "SSL Cleanup Script")
5. Copie o token gerado (você só verá uma vez!)

## 📊 Output do Script

### Informações Exibidas:
- Total de certificados encontrados
- ID e domínio de cada certificado
- **Data de validade** (formato legível e timestamp)
- Status de cada certificado (válido/expirado)
- Ações realizadas (mantido/excluído)
- Resumo final com estatísticas

### Exemplo de Output:
```
================================================================================
CPANEL SSL CERTIFICATE CLEANUP SCRIPT v2.0
================================================================================
Username: meuusuario
Hostname: server.example.com
Domínio: meudominio.com
Logging em arquivo: Ativado
Data/Hora de início: 2025-12-16 10:30:45
================================================================================

Obtendo lista de certificados SSL via UAPI...
✓ Obtidos 5 certificados via UAPI

Total de certificados encontrados: 5
--------------------------------------------------------------------------------

[1/5] Processando certificado:
  ID: assembleia_copirn_org_br_edc11_3f217_1756182751_9c5da1f36ebdebcd28075379aff266e2
  Domínio: assembleia.copirn.org.br
  Data de validade: 2024-11-15 14:32:31 (timestamp: 1731682351)
  Status: EXPIRADO ⚠️
  Ação: EXCLUÍDO ✓

[2/5] Processando certificado:
  ID: exemplo_com_abc_123_1760000000_hash123
  Domínio: exemplo.com
  Data de validade: 2025-12-31 23:59:59 (timestamp: 1735689599)
  Status: VÁLIDO ✓
  Ação: MANTIDO

...

================================================================================
RESUMO DA OPERAÇÃO
================================================================================
Total de certificados analisados: 5
Certificados válidos: 3
Certificados expirados encontrados: 2
Certificados excluídos com sucesso: 2
Falhas na exclusão: 0
================================================================================
```

## 📝 Arquivo de Log

Quando a opção `--log` é ativada, o script cria um arquivo de log com o formato:
```
log-<dominio>-<aaaa-mm-dd-hh-mm-ss>.txt
```

Exemplo:
```
log-meudominio.com-2025-12-16-10-30-45.txt
```

O arquivo contém todas as mesmas informações exibidas no terminal.

## ⚙️ Critério de Exclusão

O script exclui **APENAS** certificados que atendem ao seguinte critério:

```
data_validade < data_atual
```

Ou seja, certificados são excluídos SOMENTE se a data de validade for **estritamente menor** que a data atual. Certificados com data de validade igual ou maior que a data atual são mantidos.

## ⚠️ Tratamento de Erros

O script possui tratamento robusto de erros:

1. **Erros de conexão**: Registra no log e finaliza graciosamente
2. **Erros de exclusão**: Registra no log e continua com próximos certificados
3. **Certificados com formato inválido**: Registra aviso e marca como válido (não exclui)
4. **Interrupção pelo usuário (Ctrl+C)**: Finaliza graciosamente

## 🔒 Segurança

- ⚠️ **NUNCA** compartilhe sua API key
- ⚠️ **NUNCA** commite API keys em repositórios Git
- ⚠️ Mantenha os logs em local seguro (podem conter informações sensíveis)
- ✅ Recomenda-se criar uma API key específica para este script
- ✅ Revogue a API key após o uso se for temporário
- ✅ Use variáveis de ambiente para armazenar credenciais

## 🐛 Troubleshooting

### Erro: "Module 'requests' not found"
**Solução:** Instale o módulo requests
```bash
pip install requests
```

### Erro: "Authentication failed" ou "401 Unauthorized"
**Possíveis causas:**
- API key incorreta ou expirada
- Username incorreto
- Formato incorreto (o script concatena username:api-key automaticamente)

**Solução:** 
1. Verifique se o username está correto
2. Gere uma nova API key no cPanel
3. Teste a conexão com as novas credenciais

### Erro: "You must specify either the 'id' or 'friendly_name'"
**Possível causa:**
- Versão antiga do script

**Solução:** 
- Use a versão 2.0 do script (este arquivo)
- O parâmetro 'id' agora é passado corretamente na requisição UAPI

### Erro: "Connection timeout"
**Possíveis causas:**
- Hostname incorreto
- Firewall bloqueando a porta 2083
- Servidor fora do ar

**Solução:** 
1. Verifique conectividade: `ping <hostname>`
2. Verifique se a porta 2083 está acessível: `telnet <hostname> 2083`
3. Verifique configurações de firewall

### Certificados válidos aparecem como expirados
**Solução:**
- Use a versão 2.0 do script
- A lógica de comparação de datas foi corrigida
- O script agora interpreta corretamente timestamps Unix

### Nenhum certificado expirado encontrado
Isso é normal! Significa que todos os certificados estão válidos.

## 📄 Códigos de Saída

- `0`: Sucesso (certificados excluídos ou nenhum expirado encontrado)
- `1`: Erro durante execução ou falhas na exclusão
- `130`: Operação cancelada pelo usuário (Ctrl+C)

## 🔄 Changelog

**Versão 2.0** (2025-12-16)
- ✨ **BREAKING CHANGE**: Parâmetros separados `--username` e `--api-key` (ambos obrigatórios)
- 🗑️ Removido completamente suporte à API2 (apenas UAPI)
- 🐛 Corrigido parâmetro 'id' na exclusão de certificados
- 🐛 Corrigida lógica de verificação de expiração (timestamp)
- ✨ Adicionada exibição de data de validade em formato legível + timestamp
- ✨ Critério correto: exclui APENAS certificados com data < data_atual
- 📝 Melhorias no logging verboso

**Versão 1.0** (2025-12-15)
- Versão inicial
- Suporte a UAPI e API2
- Logging dual (stdout + arquivo)
- Tratamento robusto de erros

## 🤝 Suporte

Para problemas ou dúvidas:
1. Verifique a seção de Troubleshooting
2. Consulte a documentação da UAPI do cPanel
3. Execute o script com `--log` para análise detalhada

## 📜 Licença

Este script é fornecido "como está", sem garantias de qualquer tipo.

---

**Nota**: Este script utiliza UAPI (Universal API) do cPanel, que é a API moderna e recomendada. API2 foi removida completamente na versão 2.0.
