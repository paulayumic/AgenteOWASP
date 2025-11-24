import requests
import json
import hmac
import hashlib
import base64
from datetime import datetime

# -----------------------------------------------------------------------------------------------------
# Infos do Foundry

foundry_endpoint = "https://aif-foundry-azure-girls-challenge3.cognitiveservices.azure.com/openai/deployments/gpt-4.1-mini/chat/completions?api-version=2025-01-01-preview"
foundry_api_key = "3CfbxSNLC4y57EeYaIZSFnVJ3JAvGtmLYeCaHoS2f1NbpslaCRAUJQQJ99BKACHYHv6XJ3w3AAAAACOG8Xhn"

headers_foundry = {
    "Content-Type": "application/json",
    "api-key": foundry_api_key
}

# -----------------------------------------------------------------------------------------------------
# Infos do Azure Sentinel

workspace_id = "11fefee5-1da7-481e-9cc2-30f49a4a1700"  # CustomerID
shared_key = "SODkLCbVoaomkffAcGyOWIDbZj6pYMSX4v9yj/QihuMvUO5fmH2zMi+Jcq3BpRL5R/tgr7Tv6FfAzL1N8LFjsQ==" # PrimaryKey do workspace
log_type = "VulnerabilityLog"

sentinel_url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

# -----------------------------------------------------------------------------------------------------
# Função para gerar o HMAC para o Azure Sentinel, para uma autenticação segura.
# Para mais informações: https://learn.microsoft.com/pt-br/azure/azure-app-configuration/rest-api-authentication-hmac

def build_signature(workspace_id, shared_key, date, content_length):
    string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = hmac.new(decoded_key, string_to_sign.encode('utf-8'), hashlib.sha256).digest()
    return f"SharedKey {workspace_id}:{base64.b64encode(encoded_hash).decode()}"

# -----------------------------------------------------------------------------------------------------
# INPUT: Código Python a ser analisado.
# Foi inserido esse código_python diretamente no script para testes, mas pode ser alterado por um arquivo python.

codigo_python = """
def login(user, password):
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{password}'"
    execute(query)
"""

# -----------------------------------------------------------------------------------------------------
# Envio o código para o AgentOWASP

payload_foundry = {
    "messages": [
        {
            "role": "system",
            "content": """
Você é um analisador de segurança especializado em código Python.
Sua tarefa é analisar o código fornecido e identificar **todas as vulnerabilidades possíveis**, seguindo a referência do **OWASP Top 10**.

Retorne SOMENTE um JSON com o seguinte formato:

{
  "arquivo": "<nome_arquivo_se_existir>",
  "total_vulnerabilidades": <numero>,
  "vulnerabilidades": [
    {
      "titulo": "",
      "descricao": "",
      "tipo_owasp": "",
      "trecho_codigo": "",
      "linha": "",
      "impacto": "",
      "severidade": "",
      "como_explorar": "",
      "como_mitigar": ""
    }
  ]
}

Regras:
- Não adicionar texto fora do JSON.
- Se não encontrar o arquivo no código, defina "arquivo": null.
- Cada vulnerabilidade deve ter seu tipo OWASP Top 10.
- Severidade deve ser: Baixa, Média, Alta ou Crítica.
- O trecho do código deve ser exatamente como aparece no input.
- A mitigação deve ser objetiva e prática.
"""
        },
        {
            "role": "user",
            "content": codigo_python
        }
    ],
    "max_tokens": 2000,
    "temperature": 0
}

response_foundry = requests.post(foundry_endpoint, headers=headers_foundry, json=payload_foundry)

if response_foundry.status_code != 200:
    print("Erro ao chamar o Foundry:", response_foundry.status_code, response_foundry.text)
    #exit(1)

agent_json = response_foundry.json()


# -----------------------------------------------------------------------------------------------------
# Envio o alerta para o Azure Sentinel

# Prepara o payload
payload_sentinel = {
    "timestamp": datetime.utcnow().isoformat(),
    "source": "FoundryAgent",
    "code_snippet": codigo_python,
    "vulnerabilities": agent_json.get("vulnerabilities", [])
}

body = json.dumps(payload_sentinel)
date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
content_length = len(body.encode('utf-8'))
signature = build_signature(workspace_id, shared_key, date, content_length)

headers_sentinel = {
    "Content-Type": "application/json",
    "Authorization": signature,
    "Log-Type": log_type,
    "x-ms-date": date
}

response_sentinel = requests.post(sentinel_url, headers=headers_sentinel, data=body)

if response_sentinel.status_code in [200, 202]:
    print("Alerta enviado com sucesso para o Azure Sentinel!")
else:
    print("Erro ao enviar para o Sentinel:", response_sentinel.status_code, response_sentinel.text)
