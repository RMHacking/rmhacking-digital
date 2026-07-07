"""
RMHacking - Investigação Digital
Módulo: core/forensics.py

Ferramentas de Forense Digital:
  - Cálculo de hash SHA-256 para integridade de evidências
  - Extração de metadados EXIF de imagens (GPS, câmera, datas)

Dependências: Pillow (`pip install Pillow`)
"""

import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any


def calcular_hash_sha256(caminho_arquivo: str) -> Dict[str, Any]:
    """
    Calcula o hash SHA-256 de um arquivo para garantir integridade forense.

    Lê o arquivo em blocos de 64 KB para suportar arquivos grandes sem
    consumir toda a memória RAM.

    Args:
        caminho_arquivo: Caminho absoluto ou relativo para o arquivo.

    Returns:
        Dicionário com:
          - 'hash_sha256': string hexadecimal do hash
          - 'arquivo': nome do arquivo
          - 'tamanho_bytes': tamanho do arquivo em bytes
          - 'erro': mensagem de erro (apenas se houver falha)

    Exemplo:
        >>> resultado = calcular_hash_sha256("/evidencias/foto.jpg")
        >>> print(resultado['hash_sha256'])
        'a1b2c3d4...'
    """
    resultado: Dict[str, Any] = {}
    caminho = Path(caminho_arquivo)

    if not caminho.exists():
        return {'erro': f'Arquivo não encontrado: {caminho_arquivo}'}
    if not caminho.is_file():
        return {'erro': f'O caminho não aponta para um arquivo: {caminho_arquivo}'}

    try:
        sha256 = hashlib.sha256()
        tamanho = 0
        BLOCO = 65536  # 64 KB por bloco

        with open(caminho, 'rb') as f:
            while True:
                bloco = f.read(BLOCO)
                if not bloco:
                    break
                sha256.update(bloco)
                tamanho += len(bloco)

        resultado['hash_sha256'] = sha256.hexdigest()
        resultado['arquivo'] = caminho.name
        resultado['caminho_completo'] = str(caminho.resolve())
        resultado['tamanho_bytes'] = tamanho
        resultado['tamanho_legivel'] = _formatar_tamanho(tamanho)

    except PermissionError:
        resultado['erro'] = 'Sem permissão de leitura para o arquivo.'
    except OSError as e:
        resultado['erro'] = f'Erro de sistema ao ler arquivo: {e}'

    return resultado


def extrair_metadados_exif(caminho_imagem: str) -> Dict[str, Any]:
    """
    Extrai metadados EXIF de uma imagem JPEG/TIFF.

    Se a imagem contiver dados de GPS, converte as coordenadas DMS
    (graus, minutos, segundos) para graus decimais legíveis.

    Args:
        caminho_imagem: Caminho para o arquivo de imagem.

    Returns:
        Dicionário com metadados EXIF. Campos principais:
          - 'Make': Fabricante da câmera
          - 'Model': Modelo da câmera
          - 'DateTime': Data/hora da captura
          - 'GPS_Latitude': Latitude em graus decimais (se disponível)
          - 'GPS_Longitude': Longitude em graus decimais (se disponível)
          - 'GPS_Maps_URL': Link direto para Google Maps (se GPS disponível)
          - 'todos_os_campos': dicionário com todos os dados EXIF brutos
          - 'erro': mensagem de erro (apenas se houver falha)

    Exemplo:
        >>> meta = extrair_metadados_exif("/evidencias/suspeito.jpg")
        >>> print(meta.get('GPS_Maps_URL'))
        'https://www.google.com/maps?q=-23.5489,-46.6388'
    """
    resultado: Dict[str, Any] = {}
    caminho = Path(caminho_imagem)

    if not caminho.exists():
        return {'erro': f'Imagem não encontrada: {caminho_imagem}'}

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        return {'erro': 'Biblioteca Pillow não instalada. Execute: pip install Pillow'}

    try:
        with Image.open(caminho) as img:
            resultado['arquivo'] = caminho.name
            resultado['formato'] = img.format
            resultado['modo_cor'] = img.mode
            resultado['dimensoes'] = f'{img.width}x{img.height} pixels'

            exif_raw = img._getexif()

            if exif_raw is None:
                resultado['aviso'] = 'Esta imagem não possui dados EXIF.'
                return resultado

            exif_decodificado: Dict[str, Any] = {}
            gps_info: Dict[str, Any] = {}

            for tag_id, valor in exif_raw.items():
                nome_tag = TAGS.get(tag_id, str(tag_id))

                if nome_tag == 'GPSInfo':
                    # Decodifica sub-tags de GPS
                    for gps_tag_id, gps_valor in valor.items():
                        nome_gps = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                        gps_info[nome_gps] = gps_valor
                elif isinstance(valor, bytes):
                    try:
                        exif_decodificado[nome_tag] = valor.decode('utf-8', errors='replace').strip()
                    except Exception:
                        exif_decodificado[nome_tag] = repr(valor)
                else:
                    exif_decodificado[nome_tag] = valor

            # Campos mais relevantes para investigação
            for campo in ['Make', 'Model', 'DateTime', 'DateTimeOriginal',
                          'Software', 'Artist', 'Copyright', 'ImageDescription',
                          'ExifImageWidth', 'ExifImageHeight', 'Flash',
                          'FocalLength', 'ExposureTime', 'FNumber',
                          'ISOSpeedRatings', 'MakerNote']:
                if campo in exif_decodificado:
                    resultado[campo] = exif_decodificado[campo]

            resultado['todos_os_campos'] = exif_decodificado

            # Processar GPS
            if gps_info:
                resultado['GPS_bruto'] = str(gps_info)
                try:
                    lat = _dms_para_decimal(
                        gps_info.get('GPSLatitude'),
                        gps_info.get('GPSLatitudeRef', 'N')
                    )
                    lon = _dms_para_decimal(
                        gps_info.get('GPSLongitude'),
                        gps_info.get('GPSLongitudeRef', 'E')
                    )
                    if lat is not None and lon is not None:
                        resultado['GPS_Latitude'] = lat
                        resultado['GPS_Longitude'] = lon
                        resultado['GPS_Maps_URL'] = (
                            f'https://www.google.com/maps?q={lat},{lon}'
                        )
                        resultado['GPS_Altitude'] = gps_info.get('GPSAltitude')
                except Exception as e:
                    resultado['GPS_erro'] = f'Falha ao converter GPS: {e}'

    except Exception as e:
        resultado['erro'] = f'Erro ao processar imagem: {e}'

    return resultado


# ── Funções auxiliares ──────────────────────────────────────────────────────────

def _dms_para_decimal(
    dms: Optional[tuple],
    referencia: str
) -> Optional[float]:
    """
    Converte coordenadas GPS de DMS (graus, minutos, segundos IFDRational)
    para graus decimais.

    Args:
        dms: Tupla com (graus, minutos, segundos) como objetos IFDRational.
        referencia: 'N', 'S', 'E' ou 'W'.

    Returns:
        Float em graus decimais, ou None se a conversão falhar.
    """
    if not dms or len(dms) < 3:
        return None
    try:
        graus   = float(dms[0])
        minutos = float(dms[1])
        segundos = float(dms[2])
        decimal = graus + (minutos / 60.0) + (segundos / 3600.0)
        if referencia in ('S', 'W'):
            decimal = -decimal
        return round(decimal, 7)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _formatar_tamanho(bytes_: int) -> str:
    """Formata um tamanho em bytes para string legível (KB, MB, GB)."""
    for unidade in ['B', 'KB', 'MB', 'GB']:
        if bytes_ < 1024.0:
            return f'{bytes_:.1f} {unidade}'
        bytes_ /= 1024.0
    return f'{bytes_:.1f} TB'


# ── Teste rápido ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Uso: python forensics.py <caminho_do_arquivo>')
        sys.exit(1)

    arquivo = sys.argv[1]
    print('\n── HASH SHA-256 ──────────────────────────────────')
    print(json.dumps(calcular_hash_sha256(arquivo), indent=2, ensure_ascii=False, default=str))

    print('\n── METADADOS EXIF ────────────────────────────────')
    print(json.dumps(extrair_metadados_exif(arquivo), indent=2, ensure_ascii=False, default=str))
