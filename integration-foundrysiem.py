import requests
import json
from datetime import datetime

# -----------------------------------------------------------------------------------------------------

# Configurações do Foundry
foundry_endpoint = "https://aif-foundry-azure-girls-challenge3.cognitiveservices.azure.com/openai/deployments/gpt-4.1-mini/chat/completions?api-version=2025-01-01-preview"
foundry_api_key = "3CfbxSNLC4y57EeYaIZSFnVJ3JAvGtmLYeCaHoS2f1NbpslaCRAUJQQJ99BKACHYHv6XJ3w3AAAAACOG8Xhn"
headers_foundry = {
    "Content-Type": "application/json",
    "api-key": foundry_api_key
}

# -----------------------------------------------------------------------------------------------------

# Configurações do Azure Sentinel
workspace_id = "11fefee5-1da7-481e-9cc2-30f49a4a1700"  # Customer ID
shared_key = "SODkLCbVoaomkffAcGyOWIDbZj6pYMSX4v9yj/QihuMvUO5fmH2zMi+Jcq3BpRL5R/tgr7Tv6FfAzL1N8LFjsQ=="  # Primary Key
log_type = "VulnerabilityLog"  # Tipo de log

sentinel_url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
headers_sentinel = {
    "Content-Type": "application/json",
    "Authorization": f"SharedKey {workspace_id}:{shared_key}",
    "Log-Type": log_type
}

# -----------------------------------------------------------------------------------------------------

# Código Python que o usuário quer analisar
codigo_usuario = """
def login(user, password):
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{password}'"
    execute(query)
"""

# -----------------------------------------------------------------------------------------------------

# Prompt do agente (instruções completas)
prompt = f"""
Você é um assistente especializado em segurança de código Python. Seu objetivo é analisar trechos de código e identificar vulnerabilidades de acordo com a documentação OWASP Top 10. Você deve fornecer respostas claras, detalhadas e práticas, explicando exatamente quais problemas existem e como corrigí-los, e também enviar o código vulnerável em formato JSON como um Alerta para o Azure Sentinel.
Você não responde perguntas sobre nenhum outro assunto, somente informa vulnerabilidades que estão na OWASP Top 10 e envia o alerta.
Modo de análise:
- Faz a análise do código Python enviado (Informe inicialmente que o código Python enviado não deve ultrapassar 5.000 caracteres. Se o usuário enviar mais que isso, informe que o código é muito grande e peça para enviar em partes menores.)
- Retorne o código em JSON no campo 'analysis_target_code' do código da Action.
Modelo de resposta:
- Identifique potenciais vulnerabilidades que se encaixem na OWASP Top 10 (A01 a A10).
- Para cada vulnerabilidade detectada, indique:
  1. O tipo da vulnerabilidade que está no OWASP Top 10 (por exemplo: SQL Injection, Insecure Deserialization, etc.).
  2. Onde no código ela ocorre (linha ou trecho relevante).
  3. Um resumo do risco associado.
  4. Sugestões práticas e resumidas para mitigação ou correção.
  5. Envio de um alerta JSON para o Azure Sentinel com a vulnerabilidade encontrada.
- Se não houver vulnerabilidades, diga claramente que o código parece seguro segundo a OWASP Top 10.
- Sempre use linguagem clara, precisa e objetiva.

Código a ser analisado:
{codigo_usuario}
"""

# -----------------------------------------------------------------------------------------------------

# Enviar prompt + código para o Foundry
payload_foundry = {
    "messages": [{"role": "user", "content": prompt}]
}

response_foundry = requests.post(foundry_endpoint, headers=headers_foundry, json=payload_foundry)

if response_foundry.status_code != 200:
    print("Erro ao chamar o AgenteOWASP:", response_foundry.status_code, response_foundry.text)
    exit(1)

# -----------------------------------------------------------------------------------------------------

# Extrair código e vulnerabilidades automaticamente
agent_output = response_foundry.json()
model_content = agent_output["choices"][0]["message"]["content"]

try:
    parsed_json = json.loads(model_content)
    codigo_python = parsed_json.get("analysis_target_code", "")
    vulnerabilities = parsed_json.get("vulnerabilities", [])
except json.JSONDecodeError:
    print("O Foundry não retornou JSON válido. Conteúdo recebido:")
    print(model_content)
    codigo_python = ""
    vulnerabilities = []

print("Código Python extraído automaticamente:")
print(codigo_python)

print("\nVulnerabilidades detectadas:")
print(json.dumps(vulnerabilities, indent=2))

# -----------------------------------------------------------------------------------------------------

# Preparar payload para o Sentinel
payload_sentinel = {
    "timestamp": datetime.utcnow().isoformat(),
    "source": "FoundryAgent",
    "analysis_target_code": codigo_python,
    "vulnerabilities": vulnerabilities
}

# -----------------------------------------------------------------------------------------------------

# Enviar para o Azure Sentinel
response_sentinel = requests.post(sentinel_url, headers=headers_sentinel, data=json.dumps(payload_sentinel))

if response_sentinel.status_code in [200, 202]:
    print("\n Log enviado com sucesso para o Azure Sentinel!")
else:
    print("\n Erro ao enviar para o Sentinel:", response_sentinel.status_code, response_sentinel.text)
