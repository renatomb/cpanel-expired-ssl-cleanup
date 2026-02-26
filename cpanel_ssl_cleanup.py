#!/usr/bin/env python3
"""
cpanel_ssl_cleanup.py - Script para limpeza automática de certificados SSL expirados no cPanel

DESCRIÇÃO:
    Este script conecta ao cPanel via UAPI, obtém a lista de todos os certificados SSL
    da conta e remove automaticamente aqueles que estão expirados.

USO:
    python3 cpanel_ssl_cleanup.py --username SEU_USERNAME --api-key SUA_API_KEY --hostname seu.host.com --domain seudominio.com [--log]

PARÂMETROS OBRIGATÓRIOS:
    --username      Username do cPanel
    --api-key       API key do cPanel (obtida em cPanel -> Segurança -> Tokens de API)
    --hostname      Hostname do servidor cPanel (ex: servidor.seuhost.com)
    --domain        Nome do domínio (usado para nomear o arquivo de log)

PARÂMETROS OPCIONAIS:
    --log           Ativa a gravação de log em arquivo (formato: log-dominio-aaaa-mm-dd-hh-mm-ss.txt)

EXEMPLOS:
    # Executar sem gravar log em arquivo
    python3 cpanel_ssl_cleanup.py --username meuuser --api-key abc123xyz --hostname server.host.com --domain exemplo.com

    # Executar com gravação de log em arquivo
    python3 cpanel_ssl_cleanup.py --username meuuser --api-key abc123xyz --hostname server.host.com --domain exemplo.com --log

REQUISITOS:
    - Python 3.6+
    - Módulo requests: pip install requests

AUTOR: Renato Monteiro Batista https://github.com/renatomb/cpanel-expired-ssl-cleanup
VERSÃO: 1.0
"""

import argparse
import sys
import requests
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
import logging


class CPanelSSLManager:
    """Classe para gerenciar certificados SSL no cPanel via UAPI"""

    def __init__(self, username: str, api_key: str, hostname: str):
        """
        Inicializa o gerenciador de SSL do cPanel
        
        Args:
            username: Username do cPanel
            api_key: API key do cPanel
            hostname: Hostname do servidor cPanel
        """
        self.username = username
        self.api_key = api_key
        self.hostname = hostname.rstrip('/')
        self.session = requests.Session()
        
        # Concatenar username:api_key para autenticação
        auth_token = f"{username}:{api_key}"
        self.session.headers.update({
            'Authorization': f'cpanel {auth_token}'
        })
        
        # URL base para a UAPI
        self.uapi_base = f"https://{self.hostname}:2083/execute"
        
        self.logger = logging.getLogger(__name__)

    def _make_uapi_request(self, module: str, function: str, params: Optional[Dict] = None, method: str = 'GET') -> Dict[str, Any]:
        """
        Faz uma requisição à UAPI do cPanel
        
        Args:
            module: Módulo da API (ex: SSL)
            function: Função a ser chamada
            params: Parâmetros da função
            method: Método HTTP (GET ou POST)
            
        Returns:
            Resposta da API em formato dict
        """
        url = f"{self.uapi_base}/{module}/{function}"
        
        try:
            if method.upper() == 'POST':
                response = self.session.post(url, params=params, verify=False, timeout=30)
            else:
                if params:
                    response = self.session.get(url, params=params, verify=False, timeout=30)
                else:
                    response = self.session.get(url, verify=False, timeout=30)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erro na requisição UAPI: {e}")
            raise

    def get_ssl_certificates(self) -> List[Dict[str, Any]]:
        """
        Obtém lista de todos os certificados SSL da conta via UAPI
        
        Returns:
            Lista de dicionários contendo informações dos certificados
        """
        self.logger.info("Obtendo lista de certificados SSL via UAPI...")
        
        try:
            response = self._make_uapi_request('SSL', 'list_certs')
            
            if response.get('status') == 1 and 'data' in response:
                certs = response['data']
                self.logger.info(f"✓ Obtidos {len(certs)} certificados via UAPI")
                return certs
            else:
                error_msg = response.get('errors', ['Erro desconhecido'])[0] if 'errors' in response else 'Erro desconhecido'
                self.logger.error(f"UAPI não retornou dados esperados: {error_msg}")
                return []
                
        except Exception as e:
            self.logger.error(f"Falha ao obter certificados via UAPI: {e}")
            return []

    def is_certificate_expired(self, cert_data: Dict[str, Any]) -> tuple[bool, Optional[datetime], Optional[str]]:
        """
        Verifica se um certificado está expirado
        
        Args:
            cert_data: Dados do certificado
            
        Returns:
            Tupla (is_expired, expiry_datetime, expiry_timestamp_str)
        """
        # Possíveis campos de data de expiração
        expiry_fields = ['not_after', 'notafter', 'expiry_date', 'expiration']
        
        expiry_value = None
        for field in expiry_fields:
            if field in cert_data:
                expiry_value = cert_data[field]
                break
        
        if not expiry_value:
            self.logger.warning(f"Não foi possível encontrar data de expiração para certificado: {cert_data.get('id', 'unknown')}")
            return False, None, None
        
        try:
            # Tentar interpretar como timestamp primeiro (formato comum do cPanel)
            expiry_date = None
            expiry_timestamp_str = str(expiry_value)
            
            try:
                # Tentar como timestamp Unix
                expiry_date = datetime.fromtimestamp(int(expiry_value))
                self.logger.debug(f"Data de expiração interpretada como timestamp: {expiry_value}")
            except (ValueError, TypeError, OSError):
                # Se não for timestamp, tentar diferentes formatos de data
                date_formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%d',
                    '%b %d %H:%M:%S %Y %Z',
                    '%Y%m%d%H%M%S'
                ]
                
                for fmt in date_formats:
                    try:
                        expiry_date = datetime.strptime(str(expiry_value), fmt)
                        self.logger.debug(f"Data de expiração interpretada com formato {fmt}: {expiry_value}")
                        break
                    except ValueError:
                        continue
            
            if expiry_date is None:
                self.logger.warning(f"Formato de data não reconhecido: {expiry_value}")
                return False, None, None
            
            now = datetime.now()
            # Certificado expirado APENAS se data_validade < data_atual (estritamente menor)
            is_expired = expiry_date < now
            
            days_diff = (expiry_date - now).days
            if is_expired:
                self.logger.debug(f"Certificado expirado há {abs(days_diff)} dias")
            else:
                self.logger.debug(f"Certificado válido por mais {days_diff} dias")
            
            return is_expired, expiry_date, expiry_timestamp_str
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar data de expiração: {e}")
            return False, None, None

    def delete_certificate(self, cert_id: str) -> bool:
        """
        Exclui um certificado SSL via UAPI
        
        Args:
            cert_id: ID do certificado a ser excluído
            
        Returns:
            True se o certificado foi excluído com sucesso, False caso contrário
        """
        self.logger.info(f"Excluindo certificado ID: {cert_id}")
        
        try:
            # Fazer requisição UAPI com o parâmetro 'id' usando POST
            response = self._make_uapi_request('SSL', 'delete_cert', {'id': cert_id}, method='POST')
            
            if response.get('status') == 1:
                self.logger.info(f"✓ Certificado {cert_id} excluído com sucesso via UAPI")
                return True
            else:
                error_msg = response.get('errors', ['Erro desconhecido'])[0] if 'errors' in response else 'Erro desconhecido'
                self.logger.error(f"✗ Falha ao excluir certificado via UAPI: {error_msg}")
                return False
                
        except Exception as e:
            self.logger.error(f"Falha ao excluir certificado via UAPI: {e}")
            return False

    def cleanup_expired_certificates(self) -> Dict[str, int]:
        """
        Remove todos os certificados expirados
        
        Returns:
            Dicionário com estatísticas da operação
        """
        stats = {
            'total': 0,
            'expired': 0,
            'deleted': 0,
            'failed': 0,
            'valid': 0
        }
        
        self.logger.info("=" * 80)
        self.logger.info("INICIANDO LIMPEZA DE CERTIFICADOS SSL EXPIRADOS")
        self.logger.info("=" * 80)
        
        # Obter lista de certificados
        certificates = self.get_ssl_certificates()
        stats['total'] = len(certificates)
        
        if not certificates:
            self.logger.warning("Nenhum certificado encontrado na conta")
            return stats
        
        self.logger.info(f"\nTotal de certificados encontrados: {stats['total']}")
        self.logger.info("-" * 80)
        
        # Processar cada certificado
        for i, cert in enumerate(certificates, 1):
            cert_id = cert.get('id', cert.get('cert_id', 'unknown'))
            domain = cert.get('domain', cert.get('domains', 'N/A'))
            
            self.logger.info(f"\n[{i}/{stats['total']}] Processando certificado:")
            self.logger.info(f"  ID: {cert_id}")
            self.logger.info(f"  Domínio: {domain}")
            
            # Verificar se está expirado
            is_expired, expiry_date, expiry_timestamp = self.is_certificate_expired(cert)
            
            # Exibir data de validade em formato legível
            if expiry_date:
                expiry_readable = expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                self.logger.info(f"  Data de validade: {expiry_readable} (timestamp: {expiry_timestamp})")
            else:
                self.logger.info(f"  Data de validade: Não disponível")
            
            if is_expired:
                stats['expired'] += 1
                self.logger.warning(f"  Status: EXPIRADO ⚠️")
                
                # Tentar excluir
                if self.delete_certificate(cert_id):
                    stats['deleted'] += 1
                    self.logger.info(f"  Ação: EXCLUÍDO ✓")
                else:
                    stats['failed'] += 1
                    self.logger.error(f"  Ação: FALHA NA EXCLUSÃO ✗")
            else:
                stats['valid'] += 1
                self.logger.info(f"  Status: VÁLIDO ✓")
                self.logger.info(f"  Ação: MANTIDO")
        
        # Resumo final
        self.logger.info("\n" + "=" * 80)
        self.logger.info("RESUMO DA OPERAÇÃO")
        self.logger.info("=" * 80)
        self.logger.info(f"Total de certificados analisados: {stats['total']}")
        self.logger.info(f"Certificados válidos: {stats['valid']}")
        self.logger.info(f"Certificados expirados encontrados: {stats['expired']}")
        self.logger.info(f"Certificados excluídos com sucesso: {stats['deleted']}")
        self.logger.info(f"Falhas na exclusão: {stats['failed']}")
        self.logger.info("=" * 80)
        
        return stats


class DualLogger:
    """Classe para logging simultâneo em stdout e arquivo"""
    
    def __init__(self, log_to_file: bool, domain: str):
        """
        Inicializa o logger dual
        
        Args:
            log_to_file: Se True, grava logs em arquivo
            domain: Nome do domínio para o arquivo de log
        """
        self.log_to_file = log_to_file
        self.log_file = None
        
        # Configurar logging básico
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        
        # Se logging em arquivo estiver ativado, adicionar handler de arquivo
        if self.log_to_file:
            timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
            log_filename = f"log-{domain}-{timestamp}.txt"
            
            file_handler = logging.FileHandler(log_filename, encoding='utf-8')
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(logging.Formatter('%(message)s'))
            
            logging.getLogger().addHandler(file_handler)
            
            self.log_file = log_filename
            logging.info(f"Arquivo de log criado: {log_filename}")
            logging.info("")


def parse_arguments():
    """
    Processa argumentos da linha de comando
    
    Returns:
        Namespace com os argumentos processados
    """
    parser = argparse.ArgumentParser(
        description='Script para limpeza automática de certificados SSL expirados no cPanel via UAPI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --username meuuser --api-key abc123xyz --hostname server.host.com --domain exemplo.com
  %(prog)s --username meuuser --api-key abc123xyz --hostname server.host.com --domain exemplo.com --log
        """
    )
    
    parser.add_argument(
        '--username',
        required=True,
        help='Username do cPanel (obrigatório)'
    )
    
    parser.add_argument(
        '--api-key',
        required=True,
        help='API key do cPanel (obrigatório)'
    )
    
    parser.add_argument(
        '--hostname',
        required=True,
        help='Hostname do servidor cPanel (obrigatório)'
    )
    
    parser.add_argument(
        '--domain',
        required=True,
        help='Nome do domínio - usado para nomear o arquivo de log (obrigatório)'
    )
    
    parser.add_argument(
        '--log',
        action='store_true',
        help='Ativa a gravação de log em arquivo'
    )
    
    return parser.parse_args()


def main():
    """Função principal do script"""
    
    # Desabilitar warnings de SSL (certificados auto-assinados)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Processar argumentos
    args = parse_arguments()
    
    # Configurar logging
    dual_logger = DualLogger(args.log, args.domain)
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 80)
    logger.info("CPANEL SSL CERTIFICATE CLEANUP SCRIPT v1.0")
    logger.info("=" * 80)
    logger.info(f"Username: {args.username}")
    logger.info(f"Hostname: {args.hostname}")
    logger.info(f"Domínio: {args.domain}")
    logger.info(f"Logging em arquivo: {'Ativado' if args.log else 'Desativado'}")
    logger.info(f"Data/Hora de início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 80)
    logger.info("")
    
    try:
        # Criar instância do gerenciador SSL
        manager = CPanelSSLManager(
            username=args.username,
            api_key=args.api_key,
            hostname=args.hostname
        )
        
        # Executar limpeza
        stats = manager.cleanup_expired_certificates()
        
        # Finalizar
        logger.info("")
        logger.info(f"Data/Hora de término: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if dual_logger.log_file:
            logger.info(f"\nLog gravado em: {dual_logger.log_file}")
        
        # Código de saída baseado no resultado
        if stats['failed'] > 0:
            logger.warning("\n⚠️  Operação concluída com falhas")
            sys.exit(1)
        elif stats['deleted'] > 0:
            logger.info("\n✓ Operação concluída com sucesso")
            sys.exit(0)
        else:
            logger.info("\n✓ Nenhum certificado expirado encontrado")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.error("\n\n✗ Operação cancelada pelo usuário")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\n\n✗ Erro fatal: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
