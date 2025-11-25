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
        default='port 53',
        help='Filtro BPF para captura (default: port 53)'
    )
    parser.add_argument(
        '--redis-host',
        type=str,
        default='localhost',
        help='Host de Redis (default: localhost)'
    )
    parser.add_argument(
        '--redis-port',
        type=int,
        default=6379,
        help='Puerto de Redis (default: 6379)'
    )
    parser.add_argument(
        '--redis-db',
        type=int,
        default=0,
        help='Base de datos Redis (default: 0)'
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
    
    args = parser.parse_args()
    
    # Registrar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Inicializar cliente Redis si es necesario
    redis_client = None
    if not args.no_redis:
        try:
            redis_client = DNSRedisClient(
                host=args.redis_host,
                port=args.redis_port,
                db=args.redis_db,
                password=args.redis_password
            )
            logger.info("Redis conectado exitosamente")
        except Exception as e:
            logger.error(f"Error conectando a Redis: {e}")
            logger.error("Ejecutando sin almacenamiento en Redis...")
            redis_client = None
    
    # Inicializar y iniciar capturador DNS
    sniffer = DNSSniffer(interface=args.interface)
    
    try:
        logger.info("Iniciando captura DNS...")
        logger.info("Presiona Ctrl+C para detener")
        sniffer.start(redis_client=redis_client, filter_str=args.filter)
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

