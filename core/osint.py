"""
RMHacking - Investigação Digital
Módulo: core/osint.py

Ferramentas de OSINT (Open Source Intelligence):
  - Rastreamento geográfico de endereços IP
  - Varredura de texto/logs por padrões sensíveis (Regex)
  - Geração de links de busca para ferramentas OSINT externas

Dependências: apenas biblioteca padrão do Python (urllib, re, json)
"""

import re
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List


def rastrear_ip(endereco_ip: str) -> Dict[str, Any]:
    """
    Rastreia a localização geográfica e informações técnicas de um IP.

    Utiliza a API pública ip-api.com (gratuita, sem chave necessária).
    Suporta IPv4 e IPv6.

    Args:
        endereco_ip: Endereço IP no formato '8.8.8.8' ou '2001:db8::1'.

    Returns:
        Dicionário com:
          - 'ip': IP consultado
          - 'pais': País
          - 'regiao': Estado/Região
          - 'cidade': Cidade
          - 'cep': CEP/Zip
          - 'provedor_isp': Nome do provedor de internet
          - 'organizacao': Organização responsável
          - 'as': Sistema Autônomo (ASN)
          - 'latitude': Coordenada geográfica
          - 'longitude': Coordenada geográfica
          - 'proxy': True se VPN/Proxy detectado
          - 'mobile': True se rede móvel
          - 'hosting': True se datacenter/hosting
          - 'maps_url': Link para Google Maps
          - 'erro': mensagem de erro (apenas se houver falha)

    Exemplo:
        >>> info = rastrear_ip('8.8.8.8')
        >>> print(f"{info['cidade']}, {info['pais']}")
        'Mountain View, United States'
    """
    resultado: Dict[str, Any] = {}

    # Sanitiza o input para evitar injeção de path
    ip_limpo = endereco_ip.strip()
    if not ip_limpo:
        return {'erro': 'Endereço IP não pode ser vazio.'}

    # Caracteres válidos para IP (IPv4, IPv6)
    if not re.match(r'^[0-9a-fA-F.:]+$', ip_limpo):
        return {'erro': f'Endereço IP inválido: {ip_limpo}'}

    url = (
        f'http://ip-api.com/json/{ip_limpo}'
        f'?lang=pt-BR&fields=status,message,country,regionName,city,zip,'
        f'lat,lon,isp,org,as,mobile,proxy,hosting,query'
    )

    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'RMHacking-InvestigacaoDigital/1.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as resposta:
            dados = json.loads(resposta.read().decode('utf-8'))

        if dados.get('status') == 'success':
            resultado['ip']           = dados.get('query', ip_limpo)
            resultado['pais']         = dados.get('country', 'N/A')
            resultado['regiao']       = dados.get('regionName', 'N/A')
            resultado['cidade']       = dados.get('city', 'N/A')
            resultado['cep']          = dados.get('zip', 'N/A')
            resultado['provedor_isp'] = dados.get('isp', 'N/A')
            resultado['organizacao']  = dados.get('org', 'N/A')
            resultado['as']           = dados.get('as', 'N/A')
            resultado['latitude']     = dados.get('lat')
            resultado['longitude']    = dados.get('lon')
            resultado['proxy']        = dados.get('proxy', False)
            resultado['mobile']       = dados.get('mobile', False)
            resultado['hosting']      = dados.get('hosting', False)

            lat, lon = dados.get('lat'), dados.get('lon')
            if lat and lon:
                resultado['maps_url'] = f'https://www.google.com/maps?q={lat},{lon}'
                resultado['localizacao_completa'] = (
                    f"{resultado['cidade']}, {resultado['regiao']}, {resultado['pais']}"
                )
        else:
            resultado['erro'] = dados.get('message', 'Resposta inválida da API.')

    except urllib.error.URLError as e:
        resultado['erro'] = f'Erro de rede: {e.reason}'
    except urllib.error.HTTPError as e:
        resultado['erro'] = f'Erro HTTP {e.code}: {e.reason}'
    except json.JSONDecodeError:
        resultado['erro'] = 'Resposta inválida da API (não é JSON).'
    except Exception as e:
        resultado['erro'] = f'Erro inesperado: {e}'

    return resultado


def buscar_padroes_texto(
    caminho_arquivo: str = '',
    texto_direto: str = ''
) -> Dict[str, Any]:
    """
    Varre um arquivo de texto ou string em busca de padrões de dados sensíveis.

    Detecta: e-mails, CPFs, IPs IPv4, URLs, telefones brasileiros,
    hashes MD5/SHA-256, cartões de crédito e tokens/chaves de API.

    Args:
        caminho_arquivo: Caminho para o arquivo de texto/log a ser analisado.
                         Se vazio, usa `texto_direto`.
        texto_direto:    String de texto para analisar diretamente.
                         Usado se `caminho_arquivo` não for fornecido.

    Returns:
        Dicionário com:
          - 'total_achados': número total de matches únicos
          - Por categoria: lista de strings únicas encontradas
          - 'erro': mensagem de erro (apenas se houver falha)

    Exemplo:
        >>> resultado = buscar_padroes_texto(texto_direto="contato@email.com 192.168.1.1")
        >>> print(resultado['emails'])
        ['contato@email.com']
    """
    resultado: Dict[str, Any] = {
        'emails': [],
        'cpfs': [],
        'ips_ipv4': [],
        'urls': [],
        'telefones_br': [],
        'hashes_md5': [],
        'hashes_sha256': [],
        'cartoes_credito': [],
        'chaves_api': [],
        'total_achados': 0,
    }

    # Carrega o texto
    texto = ''
    if caminho_arquivo:
        try:
            from pathlib import Path
            texto = Path(caminho_arquivo).read_text(encoding='utf-8', errors='replace')
            resultado['arquivo_analisado'] = caminho_arquivo
        except FileNotFoundError:
            return {'erro': f'Arquivo não encontrado: {caminho_arquivo}'}
        except OSError as e:
            return {'erro': f'Erro ao ler arquivo: {e}'}
    elif texto_direto:
        texto = texto_direto
    else:
        return {'erro': 'Forneça caminho_arquivo ou texto_direto.'}

    resultado['total_caracteres'] = len(texto)

    # ── Padrões Regex ─────────────────────────────────────────────────────────
    padroes: Dict[str, str] = {
        'emails': (
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
        ),
        'cpfs': (
            r'\b\d{3}[.\- ]?\d{3}[.\- ]?\d{3}[.\- ]?\d{2}\b'
        ),
        'ips_ipv4': (
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        'urls': (
            r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        ),
        'telefones_br': (
            r'(?:\+55[\s\-]?)?(?:\(?\d{2}\)?[\s\-]?)'
            r'(?:9\d{4}|\d{4})[\s\-]?\d{4}'
        ),
        'hashes_md5': (
            r'\b[a-fA-F0-9]{32}\b'
        ),
        'hashes_sha256': (
            r'\b[a-fA-F0-9]{64}\b'
        ),
        'cartoes_credito': (
            r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'
        ),
        'chaves_api': (
            r'(?:api[_\-]?key|token|secret|password|passwd|pwd)'
            r'\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?'
        ),
    }

    total = 0
    for categoria, padrao in padroes.items():
        matches = re.findall(padrao, texto, re.IGNORECASE)
        # Remove duplicatas preservando ordem
        unicos = list(dict.fromkeys(
            m.strip() if isinstance(m, str) else m[0].strip()
            for m in matches
        ))
        resultado[categoria] = unicos
        total += len(unicos)

    resultado['total_achados'] = total

    return resultado


def gerar_links_osint(alvo: str, tipo: str = 'geral') -> Dict[str, List[str]]:
    """
    Gera links úteis para pesquisa OSINT com base no alvo e tipo.

    Args:
        alvo: O alvo da pesquisa (nome, IP, e-mail, usuário, domínio...).
        tipo: 'ip', 'email', 'username', 'domain', 'person', ou 'geral'.

    Returns:
        Dicionário com listas de URLs categorizadas por ferramenta.

    Exemplo:
        >>> links = gerar_links_osint('usuario123', 'username')
        >>> for cat, urls in links.items():
        ...     print(cat, urls)
    """
    alvo_enc = urllib.parse.quote(alvo, safe='') if hasattr(urllib, 'parse') else alvo

    try:
        from urllib.parse import quote
        alvo_enc = quote(alvo, safe='')
    except Exception:
        alvo_enc = alvo

    links: Dict[str, List[str]] = {}

    # Links comuns a todos os tipos
    links['buscadores'] = [
        f'https://www.google.com/search?q="{alvo_enc}"',
        f'https://www.bing.com/search?q="{alvo_enc}"',
        f'https://duckduckgo.com/?q="{alvo_enc}"',
    ]
    links['arquivos_historicos'] = [
        f'https://web.archive.org/web/*/{alvo_enc}',
        f'https://cached.google.com/search?q=cache:{alvo_enc}',
    ]

    if tipo in ('ip',):
        links['analise_ip'] = [
            f'https://ipinfo.io/{alvo}',
            f'https://www.shodan.io/host/{alvo}',
            f'https://www.virustotal.com/gui/ip-address/{alvo}',
            f'https://bgp.he.net/ip/{alvo}',
            f'http://ip-api.com/json/{alvo}',
        ]
    elif tipo in ('email',):
        links['analise_email'] = [
            f'https://haveibeenpwned.com/account/{alvo_enc}',
            f'https://hunter.io/email-verifier/{alvo_enc}',
            f'https://www.google.com/search?q="{alvo_enc}"',
        ]
    elif tipo in ('username',):
        links['redes_sociais'] = [
            f'https://www.instagram.com/{alvo}/',
            f'https://twitter.com/{alvo}',
            f'https://www.tiktok.com/@{alvo}',
            f'https://github.com/{alvo}',
            f'https://www.linkedin.com/in/{alvo}',
            f'https://www.facebook.com/{alvo}',
            f'https://whatsmyname.app/?q={alvo_enc}',
        ]
    elif tipo in ('domain',):
        links['analise_dominio'] = [
            f'https://www.virustotal.com/gui/domain/{alvo}',
            f'https://www.shodan.io/domain/{alvo}',
            f'https://whois.domaintools.com/{alvo}',
            f'https://www.ssllabs.com/ssltest/analyze.html?d={alvo}',
            f'https://dnsdumpster.com/',
        ]

    return links


# ── Teste rápido ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('\n── RASTREAMENTO DE IP ────────────────────────────')
    resultado_ip = rastrear_ip('8.8.8.8')
    print(json.dumps(resultado_ip, indent=2, ensure_ascii=False, default=str))

    texto_teste = """
    Olá, enviei para fulano@email.com e também para teste@gmail.com.
    O servidor em 192.168.1.100 foi acessado via https://malware.evil.com/download
    CPF do suspeito: 123.456.789-09
    Telefone: +55 (11) 98765-4321
    Hash do arquivo: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
    """

    print('\n── SCANNER DE PADRÕES ────────────────────────────')
    resultado_scan = buscar_padroes_texto(texto_direto=texto_teste)
    print(json.dumps(resultado_scan, indent=2, ensure_ascii=False, default=str))
