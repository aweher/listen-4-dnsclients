#!/usr/bin/env python3
"""
Copyright (c) 2025 Ariel S. Weher <ariel@ayuda.la>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Programa principal para iniciar el monitor DNS
"""

import argparse
import sys
import signal
import logging
from dns_sniffer import DNSSniffer
from redis_client import DNSRedisClient
from clickhouse_client import DNSClickHouseClient
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
    parser.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Número de paquetes a acumular antes de escribir a Redis (default: 50)'
    )
    parser.add_argument(
        '--flush-interval',
        type=float,
        default=1.0,
        help='Intervalo en segundos para forzar escritura a Redis (default: 1.0)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mostrar cada paquete DNS capturado en consola'
    )
    
    args = parser.parse_args()
    
    # Cargar configuración desde archivo
    config = get_config(args.config)
    redis_config = config.get_redis_config()
    clickhouse_config = config.get_clickhouse_config()
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
    
    # Inicializar cliente ClickHouse si está configurado
    clickhouse_client = None
    try:
        clickhouse_client = DNSClickHouseClient(
            host=clickhouse_config['host'],
            port=clickhouse_config['port'],
            database=clickhouse_config['database'],
            user=clickhouse_config['user'],
            password=clickhouse_config['password']
        )
        logger.info(f"ClickHouse conectado exitosamente a {clickhouse_config['host']}:{clickhouse_config['port']} (DB: {clickhouse_config['database']})")
    except Exception as e:
        logger.warning(f"Error conectando a ClickHouse: {e}")
        logger.warning("Ejecutando sin almacenamiento en ClickHouse...")
        clickhouse_client = None
    
    # Inicializar y iniciar capturador DNS
    sniffer = DNSSniffer(
        interface=interface,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        verbose=args.verbose
    )
    
    try:
        logger.info("Iniciando captura DNS...")
        logger.info("Presiona Ctrl+C para detener")
        if redis_client or clickhouse_client:
            stores = []
            if redis_client:
                stores.append("Redis")
            if clickhouse_client:
                stores.append("ClickHouse")
            logger.info(f"Almacenes de datos: {', '.join(stores)}")
            logger.info(f"Optimización activada: batch_size={args.batch_size}, flush_interval={args.flush_interval}s")
        sniffer.start(redis_client=redis_client, clickhouse_client=clickhouse_client, filter_str=filter_str)
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
        if 'batches_written' in stats:
            logger.info(f"Batches escritos: {stats['batches_written']}")
            logger.info(f"Paquetes en buffer: {stats.get('packets_buffered', 0)}")


if __name__ == '__main__':
    main()

