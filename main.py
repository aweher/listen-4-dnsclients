#!/usr/bin/env python3
"""
Programa principal para iniciar el monitor DNS
"""

import argparse
import sys
import signal
import logging
from dns_sniffer import DNSSniffer
from sqlite_client import DNSSQLiteClient

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
        '--db-path',
        type=str,
        default='dns_monitor.db',
        help='Ruta al archivo de base de datos SQLite (default: dns_monitor.db)'
    )
    parser.add_argument(
        '--no-db',
        action='store_true',
        help='Ejecutar sin base de datos (solo mostrar en consola)'
    )
    
    args = parser.parse_args()
    
    # Registrar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Inicializar cliente SQLite si es necesario
    db_client = None
    if not args.no_db:
        try:
            db_client = DNSSQLiteClient(db_path=args.db_path)
            logger.info(f"SQLite conectado exitosamente: {args.db_path}")
        except Exception as e:
            logger.error(f"Error conectando a SQLite: {e}")
            logger.error("Ejecutando sin almacenamiento en base de datos...")
            db_client = None
    
    # Inicializar y iniciar capturador DNS
    sniffer = DNSSniffer(interface=args.interface)
    
    try:
        logger.info("Iniciando captura DNS...")
        logger.info("Presiona Ctrl+C para detener")
        sniffer.start(db_client=db_client, filter_str=args.filter)
    except KeyboardInterrupt:
        logger.info("Captura interrumpida")
    except Exception as e:
        logger.error(f"Error durante la captura: {e}")
        sys.exit(1)
    finally:
        # Cerrar conexión a la base de datos
        if db_client:
            db_client.close()
        
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

