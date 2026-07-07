"""
RMHacking - Investigação Digital
Módulo: core/analyzer.py

Ponte com Modelos de Linguagem (LLMs) para análise forense inteligente.
  - Gera prompts estruturados para análise de logs e evidências
  - Simula retorno de análise para demonstração offline
  - Pronto para integração real com OpenAI, Anthropic (Claude) ou Ollama

Dependências: biblioteca padrão do Python
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, Optional


def analisar_evidencias_llm(
    texto_log: str,
    modo_demo: bool = True,
    api_key: Optional[str] = None,
    provedor: str = 'openai'
) -> Dict[str, Any]:
    """
    Analisa texto de logs ou evidências usando IA (LLM).

    Em modo demo (padrão), retorna uma análise simulada estruturada para
    demonstrar o formato sem consumir créditos de API. Para uso real,
    defina modo_demo=False e forneça sua api_key.

    Args:
        texto_log:  String com logs, conversas ou evidências brutas a analisar.
        modo_demo:  Se True, retorna análise simulada (padrão: True).
        api_key:    Chave de API para o provedor LLM escolhido.
        provedor:   'openai' ou 'anthropic' (ignorado em modo_demo).

    Returns:
        Dicionário com:
          - 'prompt_sistema': Prompt de sistema otimizado para análise forense
          - 'prompt_usuario': Prompt do usuário com o texto
          - 'analise': Resultado da análise (simulado ou real)
          - 'modo': 'demo' ou 'api'
          - 'erro': mensagem de erro (apenas se houver falha)

    Exemplo:
        >>> resultado = analisar_evidencias_llm(open('server.log').read())
        >>> print(resultado['analise']['comportamentos_suspeitos'])
    """
    if not texto_log or not texto_log.strip():
        return {'erro': 'Texto de log não pode ser vazio.'}

    # ── Prompt de Sistema ──────────────────────────────────────────────────────
    PROMPT_SISTEMA = """Você é um especialista sênior em investigação digital e análise forense computacional.
Sua função é analisar criticamente logs, conversas ou evidências digitais brutas e produzir
um relatório forense estruturado e objetivo.

Ao analisar o material fornecido, você deve:

1. COMPORTAMENTOS SUSPEITOS: Identificar ações anômalas, tentativas de evasão, padrões
   de ataque (brute force, phishing, exfiltração de dados, movimentação lateral, etc.).

2. LINHA DO TEMPO: Reconstituir cronologicamente todos os eventos identificáveis,
   com timestamps precisos quando disponíveis.

3. CONTRADIÇÕES: Apontar inconsistências nas informações, versões conflitantes ou
   evidências que se contradigam.

4. ENTIDADES IDENTIFICADAS: Listar IPs, domínios, e-mails, nomes de usuário,
   hashes, URLs e outros artefatos técnicos encontrados.

5. AVALIAÇÃO DE RISCO: Classificar como Alto, Médio ou Baixo com justificativa.

6. PRÓXIMAS AÇÕES: Recomendar etapas investigativas para dar continuidade ao caso.

Formato de saída: JSON estruturado ou Markdown com seções claramente delimitadas.
Seja objetivo, técnico e imparcial. Preserve a cadeia de custódia citando as evidências."""

    # ── Prompt do Usuário ──────────────────────────────────────────────────────
    MAX_CHARS = 8000
    texto_truncado = texto_log[:MAX_CHARS]
    if len(texto_log) > MAX_CHARS:
        texto_truncado += f'\n\n[... TRUNCADO — {len(texto_log) - MAX_CHARS} caracteres adicionais ...]'

    PROMPT_USUARIO = f"""Analise o seguinte material forense e produza um relatório estruturado:

```
{texto_truncado}
```

Produza sua análise no formato JSON com as chaves:
comportamentos_suspeitos, linha_do_tempo, contradicoes,
entidades_identificadas, nivel_risco, proximas_acoes."""

    resultado: Dict[str, Any] = {
        'prompt_sistema': PROMPT_SISTEMA,
        'prompt_usuario': PROMPT_USUARIO,
        'gerado_em': datetime.now().isoformat(),
    }

    if modo_demo:
        resultado['modo'] = 'demo'
        resultado['aviso'] = (
            'Análise SIMULADA para demonstração. '
            'Para análise real, configure api_key e modo_demo=False.'
        )
        resultado['analise'] = _analise_demo(texto_log)
        resultado['instrucoes_api'] = {
            'openai': 'pip install openai → openai.ChatCompletion.create(...)',
            'anthropic': 'pip install anthropic → anthropic.Anthropic().messages.create(...)',
            'ollama_local': 'ollama pull llama3 → ollama.chat(model="llama3", messages=[...])',
        }
    else:
        resultado['modo'] = 'api'
        resultado['analise'] = _chamar_api_llm(
            PROMPT_SISTEMA, PROMPT_USUARIO, api_key, provedor
        )

    return resultado


def gerar_relatorio_caso(
    titulo: str,
    evidencias: list,
    eventos: list,
    notas: list,
) -> str:
    """
    Gera um relatório forense completo em texto estruturado.

    Args:
        titulo:     Título da investigação.
        evidencias: Lista de dicionários com campos das evidências.
        eventos:    Lista de eventos da linha do tempo.
        notas:      Lista de notas da investigação.

    Returns:
        String com o relatório formatado em Markdown.
    """
    agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    linhas = [
        f'# RELATÓRIO FORENSE — {titulo}',
        f'**Gerado em:** {agora}',
        f'**Sistema:** RMHacking — Investigação Digital',
        '',
        '---',
        '',
        f'## Resumo',
        f'- Total de evidências: {len(evidencias)}',
        f'- Total de eventos: {len(eventos)}',
        f'- Total de notas: {len(notas)}',
        '',
    ]

    if eventos:
        linhas.append('## Linha do Tempo')
        for evt in sorted(eventos, key=lambda e: e.get('event_date', '')):
            linhas.append(f"- **{evt.get('event_date','')}** — {evt.get('title','')}")
            if evt.get('description'):
                linhas.append(f"  {evt['description']}")
        linhas.append('')

    if evidencias:
        linhas.append('## Evidências Digitais')
        for i, ev in enumerate(evidencias, 1):
            linhas.append(f"### [{i}] {ev.get('title','Evidência')}")
            linhas.append(f"- **Tipo:** {ev.get('type','N/A')}")
            linhas.append(f"- **Conteúdo:** {ev.get('content','')[:200]}")
            if ev.get('hash'):
                linhas.append(f"- **SHA-256:** `{ev['hash']}`")
            if ev.get('chain_of_custody'):
                linhas.append(f"- **Custódia:** {ev['chain_of_custody']}")
            linhas.append('')

    if notas:
        linhas.append('## Notas do Investigador')
        for nt in notas:
            linhas.append(f"**{nt.get('title','')}** ({nt.get('created_at','')})")
            linhas.append(nt.get('content', ''))
            linhas.append('')

    linhas.append('---')
    linhas.append('*Relatório gerado automaticamente pelo RMHacking — Investigação Digital*')

    return '\n'.join(linhas)


# ── Funções auxiliares ──────────────────────────────────────────────────────────

def _analise_demo(texto: str) -> Dict[str, Any]:
    """Análise simulada para demonstração offline."""
    # Extrai algumas entidades básicas do texto para tornar o demo realista
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', texto)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', texto)
    urls = re.findall(r'https?://[^\s]+', texto)

    entidades = {}
    if emails: entidades['emails'] = list(set(emails))[:5]
    if ips:    entidades['ips']    = list(set(ips))[:5]
    if urls:   entidades['urls']   = list(set(urls))[:3]

    return {
        'comportamentos_suspeitos': [
            '[DEMO] Padrão de acesso fora do horário comercial detectado',
            '[DEMO] Múltiplas tentativas de autenticação em sequência rápida',
            '[DEMO] Exfiltração de dados para IP externo suspeito',
        ],
        'linha_do_tempo': [
            '[DEMO] T+0:00 — Primeiro acesso registrado no log',
            '[DEMO] T+0:15 — Escalonamento de privilégios tentado',
            '[DEMO] T+0:32 — Transferência de arquivo para destino externo',
            '[DEMO] T+1:05 — Limpeza de logs detectada',
        ],
        'contradicoes': [
            '[DEMO] Horário de login não corresponde ao fuso horário do usuário',
            '[DEMO] IP de origem diverge do perfil histórico de acesso',
        ],
        'entidades_identificadas': entidades or {
            'ips': ['[DEMO] 192.168.1.100'],
            'emails': ['[DEMO] suspeito@email.com'],
        },
        'nivel_risco': {
            'classificacao': 'ALTO',
            'justificativa': '[DEMO] Múltiplos indicadores de comprometimento detectados.',
        },
        'proximas_acoes': [
            '[DEMO] Isolar o host comprometido da rede imediatamente',
            '[DEMO] Preservar imagem forense do disco com hash verificado',
            '[DEMO] Rastrear IP externo em bases de IOC (VirusTotal, Shodan)',
            '[DEMO] Notificar equipe de resposta a incidentes',
        ],
    }


def _chamar_api_llm(
    prompt_sistema: str,
    prompt_usuario: str,
    api_key: Optional[str],
    provedor: str
) -> Dict[str, Any]:
    """
    Chama a API real de LLM. Requer bibliotecas externas instaladas.

    Para OpenAI: pip install openai
    Para Anthropic: pip install anthropic
    """
    if not api_key:
        return {'erro': 'api_key não fornecida para chamada real à API.'}

    if provedor == 'openai':
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model='gpt-4o',
                messages=[
                    {'role': 'system', 'content': prompt_sistema},
                    {'role': 'user',   'content': prompt_usuario},
                ],
                temperature=0.2,
                max_tokens=2000,
            )
            return json.loads(resp.choices[0].message.content)
        except ImportError:
            return {'erro': 'openai não instalado. Execute: pip install openai'}
        except Exception as e:
            return {'erro': f'Erro na API OpenAI: {e}'}

    elif provedor == 'anthropic':
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model='claude-opus-4-8',
                max_tokens=2000,
                system=prompt_sistema,
                messages=[{'role': 'user', 'content': prompt_usuario}],
            )
            return json.loads(resp.content[0].text)
        except ImportError:
            return {'erro': 'anthropic não instalado. Execute: pip install anthropic'}
        except Exception as e:
            return {'erro': f'Erro na API Anthropic: {e}'}

    return {'erro': f'Provedor desconhecido: {provedor}'}


# ── Teste rápido ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    log_exemplo = """
    2024-01-15 02:47:31 FAILED LOGIN user=admin ip=185.234.119.45
    2024-01-15 02:47:32 FAILED LOGIN user=admin ip=185.234.119.45
    2024-01-15 02:47:33 FAILED LOGIN user=admin ip=185.234.119.45
    2024-01-15 02:47:34 SUCCESS LOGIN user=admin ip=185.234.119.45
    2024-01-15 02:48:01 FILE_ACCESS path=/etc/passwd user=admin
    2024-01-15 02:49:15 OUTBOUND_TRANSFER dst=45.33.32.156:4444 size=2.3MB user=admin
    2024-01-15 02:51:00 LOG_CLEAR user=admin
    Contato do suspeito: hacker@darkweb.onion
    """

    print('\n── ANÁLISE LLM (DEMO) ────────────────────────────')
    resultado = analisar_evidencias_llm(log_exemplo, modo_demo=True)
    print(json.dumps(resultado['analise'], indent=2, ensure_ascii=False))
    print('\n── PROMPT GERADO ─────────────────────────────────')
    print(resultado['prompt_usuario'][:500] + '...')
