#!/usr/bin/env python3
"""
Programa principal para iniciar el monitor DNS
"""

import argparse
import sys
import signal
import logging
from dns_sniffer import DNSSniffer
from redis_client import DNSRedisClient
from config import get_config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def signal_handler(sig, frame):
    """Maneja señales de interrupción"""
    logger.info("\nDeteniendo captura DNS...")
    sys.exit(0)


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description='Monitor DNS pasivo - Captura y almacena consultas DNS'
    )
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default=None,
        help='Interfaz de red a escuchar (default: todas)'
    )
    parser.add_argument(
        '-f', '--filter',
        type=str,
        default=None,
        help='Filtro BPF para captura (default: desde config.yaml)'
    )
    parser.add_argument(
        '--redis-host',
        type=str,
        default=None,
        help='Host de Redis (default: desde config.yaml)'
    )
    parser.add_argument(
        '--redis-port',
        type=int,
        default=None,
        help='Puerto de Redis (default: desde config.yaml)'
    )
    parser.add_argument(
        '--redis-db',
        type=int,
        default=None,
        help='Base de datos Redis (default: desde config.yaml)'
    )
    parser.add_argument(
        '--redis-password',
        type=str,
        default=None,
        help='Contraseña de Redis (opcional)'
    )
    parser.add_argument(
        '--no-redis',
        action='store_true',
        help='Ejecutar sin Redis (solo mostrar en consola)'
    )
    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='Ruta al archivo de configuración (default: config.yaml)'
    )
    
    args = parser.parse_args()
    
    # Cargar configuración desde archivo
    config = get_config(args.config)
    redis_config = config.get_redis_config()
    sniffer_config = config.get_sniffer_config()
    
    # Los argumentos de línea de comandos tienen prioridad sobre la configuración del archivo
    # Si se proporcionan argumentos explícitos, usarlos; sino usar la configuración del archivo
    redis_host = args.redis_host if args.redis_host is not None else redis_config['host']
    redis_port = args.redis_port if args.redis_port is not None else redis_config['port']
    redis_db = args.redis_db if args.redis_db is not None else redis_config['db']
    redis_password = args.redis_password if args.redis_password is not None else redis_config['password']
    
    interface = args.interface if args.interface is not None else sniffer_config['interface']
    filter_str = args.filter if args.filter is not None else sniffer_config['filter']
    
    # Registrar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Inicializar cliente Redis si es necesario
    redis_client = None
    if not args.no_redis:
        try:
            redis_client = DNSRedisClient(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password
            )
            logger.info(f"Redis conectado exitosamente a {redis_host}:{redis_port} (DB: {redis_db})")
        except Exception as e:
            logger.error(f"Error conectando a Redis: {e}")
            logger.error("Ejecutando sin almacenamiento en Redis...")
            redis_client = None
    
    # Inicializar y iniciar capturador DNS
    sniffer = DNSSniffer(interface=interface)
    
    try:
        logger.info("Iniciando captura DNS...")
        logger.info("Presiona Ctrl+C para detener")
        sniffer.start(redis_client=redis_client, filter_str=filter_str)
    except KeyboardInterrupt:
        logger.info("Captura interrumpida")
    except Exception as e:
        logger.error(f"Error durante la captura: {e}")
        sys.exit(1)
    finally:
        # Mostrar estadísticas finales
        stats = sniffer.get_stats()
        logger.info("\n=== Estadísticas Finales ===")
        logger.info(f"Total de paquetes capturados: {stats['total_packets']}")
        logger.info(f"Paquetes DNS: {stats['dns_packets']}")
        logger.info(f"TCP: {stats['tcp_count']}")
        logger.info(f"UDP: {stats['udp_count']}")
        logger.info(f"Errores: {stats['errors']}")


if __name__ == '__main__':
    main()

