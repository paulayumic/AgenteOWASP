# AgenteOWASP
Foi realizado a tentativa da criação de um agente que trata e analisa códigos do tipo python e encontra vulnerabilidades de segurança através da documentação do OWASP Top 10, que informa as vulnerabilidades mais importantes de segurança e envia alertas automaticamente para o Sentinel.
O AgentOWASP é um assistente especializado em segurança de código Python, cujo objetivo principal é analisar trechos de código e identificar vulnerabilidades conforme a documentação OWASP Top 10. Ele funciona de forma automatizada: você envia o código Python pelo script, que faz a requisição para o Foundry Agent; o agente processa o código e retorna um JSON contendo o próprio código analisado e uma lista de vulnerabilidades detectadas, cada uma com tipo, linha, risco e sugestão de mitigação. O script então captura automaticamente esse JSON e envia os dados para o Azure Sentinel, criando logs estruturados que incluem timestamp, código analisado e vulnerabilidades. O agente tem limite de caracteres no código analisado (5.000), detecta vulnerabilidades como SQL Injection, XSS e Insecure Deserialization, gera alertas JSON prontos para o Sentinel e elimina a necessidade de inserção manual de vulnerabilidades ou uso do chat do Foundry. Ele permite segurança automatizada, centralização de alertas, análise escalável de múltiplos códigos e redução de erros manuais, integrando de forma prática e eficiente a análise de segurança de código Python com monitoramento no Azure Sentinel.

## Primeiro, foi criado o Resource Group do projeto

<img width="1920" height="904" alt="1" src="https://github.com/user-attachments/assets/10eb11d8-b68a-4887-b426-d2c47436e5b3" />

## Criação do Recurso Microsoft Froundry

<img width="1916" height="869" alt="2 1" src="https://github.com/user-attachments/assets/42fe357b-b1ce-40d6-a2a6-1267766c3e69" />

Após ter dado alguns erros na criação do recurso (por problema da região e incompatibilidade do GPT com ela), refiz os passos através de bash no CLI, que tem menor erro de sincronização:

<img width="602" height="117" alt="2 4" src="https://github.com/user-attachments/assets/4f00e7c5-71bf-4327-ba43-16c5bc5c1c59" />
Após o sucesso da criação, fui para o Foundry.
##Deploy do Chat GPT-4.1 Mini
Por ser o único que funcionava na instância Global Standart e que havia personalização de token, utilizei-o.

<img width="667" height="895" alt="5 1" src="https://github.com/user-attachments/assets/bdeb25f4-092e-458c-8d1c-fc0a6a5a7698" />
##Criando um agente no Microsoft Foundry
###Criação do agente
Através da página ~Agents~, fiz a criação do Agente OWASP:

<img width="1920" height="912" alt="6" src="https://github.com/user-attachments/assets/83db7380-5d7d-4acd-b854-653bc86e2b37" />

As suas instruções são as seguintes:
```python
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
```
<img width="722" height="793" alt="7" src="https://github.com/user-attachments/assets/08b6a92b-be72-4564-b5c3-09e760c73527" />

Como eu gostaria que ele criasse um objeto JSON para a integração com o Azure Sentinel, foi necessário criar um Script via Python para fazer a integração com a API do Microsoft Sentinel, que está no arquivo *integration-foundry-siem.py*

## Extra: Criação do ambiente SIEM

Foi feito a criação do ambiente no Azure Sentinel para vermos os alertas do SIEM através dos seguintes comandos:

<img width="1602" height="390" alt="sentinel-1" src="https://github.com/user-attachments/assets/2ecab14c-3aad-4275-87af-1a376c50b971" />


