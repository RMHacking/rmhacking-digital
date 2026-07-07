#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          RMHacking — Investigação Digital                    ║
║          Orquestrador CLI de Ferramentas Forenses            ║
╚══════════════════════════════════════════════════════════════╝

Interface de linha de comando para acesso rápido às ferramentas
forenses e OSINT sem necessidade de abrir o navegador.

Uso: python app.py

Dependências:
  - core/forensics.py  (Pillow: pip install Pillow)
  - core/osint.py      (apenas stdlib)
  - core/analyzer.py   (apenas stdlib; openai/anthropic opcionais)
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Adiciona o diretório raiz ao path para importar 'core'
sys.path.insert(0, str(Path(__file__).parent))

from core.forensics import calcular_hash_sha256, extrair_metadados_exif
from core.osint import rastrear_ip, buscar_padroes_texto, gerar_links_osint
from core.analyzer import analisar_evidencias_llm, gerar_relatorio_caso


# ── Cores ANSI ────────────────────────────────────────────────────────────────
class Cor:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    VERDE   = '\033[92m'
    AMARELO = '\033[93m'
    VERMELHO= '\033[91m'
    AZUL    = '\033[94m'
    CIANO   = '\033[96m'
    CINZA   = '\033[90m'


def c(texto: str, cor: str) -> str:
    """Aplica cor ANSI ao texto."""
    return f'{cor}{texto}{Cor.RESET}'


def cabecalho() -> None:
    """Exibe o banner do sistema."""
    print()
    print(c('╔══════════════════════════════════════════════════════════╗', Cor.AZUL))
    print(c('║  🔍  RMHacking — Investigação Digital                    ║', Cor.AZUL))
    print(c('║      Ferramentas Forenses & OSINT                        ║', Cor.CINZA))
    print(c('╚══════════════════════════════════════════════════════════╝', Cor.AZUL))
    print()


def menu_principal() -> str:
    """Exibe o menu principal e retorna a opção escolhida."""
    print(c('═══ MENU PRINCIPAL ═══', Cor.CIANO))
    opcoes = [
        ('1', '🔐', 'Verificar integridade de arquivo (SHA-256)'),
        ('2', '📸', 'Analisar metadados EXIF de imagem'),
        ('3', '🌐', 'Rastrear localização geográfica de IP'),
        ('4', '🔍', 'Escanear arquivo/texto por dados sensíveis (Regex)'),
        ('5', '🤖', 'Analisar evidências com IA (LLM)'),
        ('6', '🔗', 'Gerar links OSINT para um alvo'),
        ('7', '📊', 'Gerar relatório forense (texto)'),
        ('0', '🚪', 'Sair'),
    ]
    for num, emoji, desc in opcoes:
        print(f'  {c(f"[{num}]", Cor.AMARELO)} {emoji}  {desc}')
    print()
    return input(c('▶ Escolha uma opção: ', Cor.VERDE)).strip()


def pausar() -> None:
    input(c('\n[Enter para continuar...]', Cor.CINZA))


def separador() -> None:
    print(c('─' * 60, Cor.CINZA))


def imprimir_json(dados: dict) -> None:
    """Imprime dicionário formatado com cores básicas."""
    texto = json.dumps(dados, indent=2, ensure_ascii=False, default=str)
    print(c(texto, Cor.CIANO))


# ── Ações ─────────────────────────────────────────────────────────────────────

def opcao_hash() -> None:
    """[1] Calcula hash SHA-256 de um arquivo."""
    print(c('\n─── Hash SHA-256 / Integridade de Arquivo ───', Cor.AZUL))
    caminho = input('Caminho do arquivo: ').strip().strip('"\'')
    if not caminho:
        print(c('Cancelado.', Cor.CINZA))
        return
    print(c('Calculando...', Cor.AMARELO))
    resultado = calcular_hash_sha256(caminho)
    separador()
    if 'erro' in resultado:
        print(c(f'✗ Erro: {resultado["erro"]}', Cor.VERMELHO))
    else:
        print(c(f'✓ Arquivo: {resultado["arquivo"]}', Cor.VERDE))
        print(c(f'  Tamanho: {resultado["tamanho_legivel"]}', Cor.CINZA))
        print()
        print(c('  SHA-256:', Cor.AMARELO))
        print(c(f'  {resultado["hash_sha256"]}', Cor.VERDE + Cor.BOLD))

        # Opção de salvar
        salvar = input('\nSalvar hash em arquivo .txt? (s/N): ').strip().lower()
        if salvar == 's':
            saida = Path(caminho).stem + '_hash.txt'
            Path(saida).write_text(
                f'Arquivo: {resultado["caminho_completo"]}\n'
                f'Tamanho: {resultado["tamanho_legivel"]}\n'
                f'SHA-256: {resultado["hash_sha256"]}\n'
                f'Verificado em: {datetime.now().isoformat()}\n',
                encoding='utf-8'
            )
            print(c(f'Hash salvo em: {saida}', Cor.VERDE))
    pausar()


def opcao_exif() -> None:
    """[2] Extrai metadados EXIF de uma imagem."""
    print(c('\n─── Análise de Metadados EXIF ───', Cor.AZUL))
    caminho = input('Caminho da imagem (JPEG/PNG/TIFF): ').strip().strip('"\'')
    if not caminho:
        print(c('Cancelado.', Cor.CINZA))
        return
    print(c('Extraindo metadados...', Cor.AMARELO))
    resultado = extrair_metadados_exif(caminho)
    separador()
    if 'erro' in resultado:
        print(c(f'✗ Erro: {resultado["erro"]}', Cor.VERMELHO))
    else:
        campos_relevantes = [
            'arquivo', 'formato', 'dimensoes', 'Make', 'Model',
            'DateTime', 'DateTimeOriginal', 'Software',
            'GPS_Latitude', 'GPS_Longitude', 'GPS_Maps_URL',
        ]
        for campo in campos_relevantes:
            if campo in resultado:
                label = campo.replace('_', ' ')
                print(f'  {c(label+":", Cor.AMARELO)} {resultado[campo]}')

        if resultado.get('aviso'):
            print(c(f'\n⚠ {resultado["aviso"]}', Cor.AMARELO))
        if resultado.get('GPS_Maps_URL'):
            print(c(f'\n🗺 Google Maps: {resultado["GPS_Maps_URL"]}', Cor.VERDE))
    pausar()


def opcao_ip() -> None:
    """[3] Rastreia IP geograficamente."""
    print(c('\n─── Rastreamento de IP ───', Cor.AZUL))
    ip = input('Endereço IP (ex: 8.8.8.8): ').strip()
    if not ip:
        print(c('Cancelado.', Cor.CINZA))
        return
    print(c('Consultando ip-api.com...', Cor.AMARELO))
    resultado = rastrear_ip(ip)
    separador()
    if 'erro' in resultado:
        print(c(f'✗ Erro: {resultado["erro"]}', Cor.VERMELHO))
    else:
        campos = [
            ('ip',           '🌐 IP'),
            ('pais',         '🏳 País'),
            ('regiao',       '📍 Estado'),
            ('cidade',       '🏙 Cidade'),
            ('cep',          '📮 CEP'),
            ('provedor_isp', '📡 ISP'),
            ('organizacao',  '🏢 Organização'),
            ('as',           '🔢 ASN'),
            ('latitude',     '📐 Latitude'),
            ('longitude',    '📐 Longitude'),
        ]
        for chave, rotulo in campos:
            if resultado.get(chave):
                print(f'  {c(rotulo+":", Cor.AMARELO)} {resultado[chave]}')

        alertas = []
        if resultado.get('proxy'):  alertas.append('⚠️  PROXY/VPN detectado!')
        if resultado.get('hosting'): alertas.append('🖥  Datacenter/Hosting')
        if resultado.get('mobile'):  alertas.append('📱 Rede móvel')

        if alertas:
            print()
            for a in alertas: print(c(f'  {a}', Cor.VERMELHO))

        if resultado.get('maps_url'):
            print(c(f'\n  🗺 Google Maps: {resultado["maps_url"]}', Cor.VERDE))
    pausar()


def opcao_regex() -> None:
    """[4] Escaneia arquivo ou texto por padrões sensíveis."""
    print(c('\n─── Scanner de Padrões (Regex) ───', Cor.AZUL))
    print('  [1] Analisar um arquivo')
    print('  [2] Colar texto diretamente')
    modo = input('Escolha: ').strip()

    texto = ''
    caminho = ''

    if modo == '1':
        caminho = input('Caminho do arquivo: ').strip().strip('"\'')
    elif modo == '2':
        print(c('Cole o texto (CTRL+D ou linha vazia para terminar):', Cor.CINZA))
        linhas = []
        try:
            while True:
                linha = input()
                linhas.append(linha)
        except (EOFError, KeyboardInterrupt):
            pass
        texto = '\n'.join(linhas)
    else:
        print(c('Opção inválida.', Cor.VERMELHO))
        return

    if not texto and not caminho:
        print(c('Cancelado.', Cor.CINZA))
        return

    print(c('\nEscaneando...', Cor.AMARELO))
    resultado = buscar_padroes_texto(
        caminho_arquivo=caminho,
        texto_direto=texto
    )
    separador()

    if 'erro' in resultado:
        print(c(f'✗ Erro: {resultado["erro"]}', Cor.VERMELHO))
    else:
        total = resultado.get('total_achados', 0)
        if total == 0:
            print(c('✓ Nenhum padrão sensível detectado.', Cor.VERDE))
        else:
            print(c(f'⚠ {total} padrão(ões) encontrado(s):\n', Cor.AMARELO))
            categorias = {
                'emails': '📧 E-mails',
                'cpfs': '🇧🇷 CPFs',
                'ips_ipv4': '🌐 IPs IPv4',
                'urls': '🔗 URLs',
                'telefones_br': '📱 Telefones BR',
                'hashes_md5': '🔑 Hashes MD5',
                'hashes_sha256': '🔐 Hashes SHA-256',
                'cartoes_credito': '💳 Cartões',
                'chaves_api': '🗝 Chaves/Tokens',
            }
            for chave, rotulo in categorias.items():
                items = resultado.get(chave, [])
                if items:
                    print(c(f'  {rotulo} ({len(items)}):', Cor.CIANO))
                    for item in items[:5]:
                        print(f'    • {item}')
                    if len(items) > 5:
                        print(c(f'    ... e mais {len(items)-5} itens', Cor.CINZA))
    pausar()


def opcao_llm() -> None:
    """[5] Análise de evidências por IA."""
    print(c('\n─── Análise por Inteligência Artificial ───', Cor.AZUL))
    print('  [1] Colar log/texto manualmente')
    print('  [2] Carregar de arquivo')
    modo = input('Escolha: ').strip()

    texto = ''
    if modo == '1':
        print(c('Cole o texto (CTRL+D para terminar):', Cor.CINZA))
        linhas = []
        try:
            while True:
                linhas.append(input())
        except (EOFError, KeyboardInterrupt):
            pass
        texto = '\n'.join(linhas)
    elif modo == '2':
        caminho = input('Caminho do arquivo: ').strip().strip('"\'')
        try:
            texto = Path(caminho).read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            print(c(f'✗ Erro: {e}', Cor.VERMELHO))
            pausar()
            return

    if not texto.strip():
        print(c('Texto vazio. Cancelado.', Cor.CINZA))
        return

    usar_api = input('\nUsar API real? (s/N — padrão: modo demo): ').strip().lower()
    api_key = None
    provedor = 'openai'

    if usar_api == 's':
        provedor = input('Provedor (openai/anthropic) [openai]: ').strip() or 'openai'
        api_key  = input('Chave de API: ').strip()
        modo_demo = False
    else:
        modo_demo = True

    print(c('\nAnalisando...', Cor.AMARELO))
    resultado = analisar_evidencias_llm(texto, modo_demo=modo_demo, api_key=api_key, provedor=provedor)
    separador()

    if 'erro' in resultado:
        print(c(f'✗ Erro: {resultado["erro"]}', Cor.VERMELHO))
    else:
        analise = resultado.get('analise', {})
        if 'erro' in analise:
            print(c(f'✗ Erro na análise: {analise["erro"]}', Cor.VERMELHO))
        else:
            print(c('ANÁLISE FORENSE:', Cor.VERDE + Cor.BOLD))
            imprimir_json(analise)

            salvar = input('\nSalvar prompt completo em arquivo? (s/N): ').strip().lower()
            if salvar == 's':
                saida = f'analise_llm_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                with open(saida, 'w', encoding='utf-8') as f:
                    f.write('=== PROMPT SISTEMA ===\n')
                    f.write(resultado['prompt_sistema'])
                    f.write('\n\n=== PROMPT USUARIO ===\n')
                    f.write(resultado['prompt_usuario'])
                    f.write('\n\n=== ANÁLISE ===\n')
                    f.write(json.dumps(analise, indent=2, ensure_ascii=False, default=str))
                print(c(f'Salvo em: {saida}', Cor.VERDE))
    pausar()


def opcao_links_osint() -> None:
    """[6] Gera links OSINT para um alvo."""
    print(c('\n─── Links OSINT para Alvo ───', Cor.AZUL))
    alvo = input('Alvo (IP, e-mail, usuário, domínio, nome): ').strip()
    if not alvo:
        return

    tipos = ['ip','email','username','domain','person','geral']
    print('Tipos: ' + ' | '.join(f'[{t}]' for t in tipos))
    tipo = input('Tipo [geral]: ').strip() or 'geral'

    links = gerar_links_osint(alvo, tipo)
    separador()
    for categoria, urls in links.items():
        print(c(f'\n  {categoria.upper()}:', Cor.CIANO))
        for url in urls:
            print(f'    {url}')
    pausar()


def opcao_relatorio() -> None:
    """[7] Gera relatório forense em texto."""
    print(c('\n─── Gerador de Relatório Forense ───', Cor.AZUL))
    titulo = input('Título da investigação: ').strip()
    if not titulo:
        return

    saida = f'relatorio_{titulo[:20].replace(" ","_")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
    # Relatório básico (sem dados reais do BD em modo CLI)
    relatorio = gerar_relatorio_caso(titulo, [], [], [])
    Path(saida).write_text(relatorio, encoding='utf-8')
    print(c(f'\n✓ Relatório salvo em: {saida}', Cor.VERDE))
    print(c('  Para relatório completo com todos os dados, use a interface web.', Cor.CINZA))
    pausar()


# ── Loop Principal ────────────────────────────────────────────────────────────

def main() -> None:
    """Ponto de entrada do orquestrador CLI."""
    cabecalho()

    acoes = {
        '1': opcao_hash,
        '2': opcao_exif,
        '3': opcao_ip,
        '4': opcao_regex,
        '5': opcao_llm,
        '6': opcao_links_osint,
        '7': opcao_relatorio,
    }

    while True:
        try:
            opcao = menu_principal()
            if opcao == '0':
                print(c('\n👋 Encerrando. Bons investigações!\n', Cor.VERDE))
                break
            elif opcao in acoes:
                acoes[opcao]()
            else:
                print(c('Opção inválida.', Cor.VERMELHO))
        except KeyboardInterrupt:
            print(c('\n\n👋 Interrompido pelo usuário.\n', Cor.AMARELO))
            break


if __name__ == '__main__':
    main()
