#!/usr/bin/env python3
"""
Cliente SQLite para almacenar y consultar datos DNS
"""

import sqlite3
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DNSSQLiteClient:
    """Cliente para interactuar con SQLite y obtener estadísticas DNS"""
    
    def __init__(self, db_path: str = 'dns_monitor.db'):
        """
        Inicializa el cliente SQLite
        
        Args:
            db_path: Ruta al archivo de base de datos SQLite
        """
        self.db_path = db_path
        self.conn = None
        self._init_database()
        logger.info("Conectado a SQLite en %s", db_path)
    
    def _init_database(self):
        """Inicializa la base de datos y crea las tablas si no existen"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # Permite acceso por nombre de columna
        
        cursor = self.conn.cursor()
        
        # Tabla principal de paquetes DNS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                is_query INTEGER NOT NULL,
                is_response INTEGER NOT NULL,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                record_type_code INTEGER NOT NULL,
                dns_id INTEGER,
                opcode INTEGER,
                rcode INTEGER,
                data_json TEXT,
                created_at REAL DEFAULT (julianday('now'))
            )
        ''')
        
        # Índices para mejorar el rendimiento de consultas
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_packets(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON dns_packets(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON dns_packets(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_record_type ON dns_packets(record_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON dns_packets(protocol)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON dns_packets(created_at)')
        
        self.conn.commit()
    
    def store_packet(self, dns_data: Dict[str, Any]):
        """
        Almacena un paquete DNS en la base de datos
        
        Args:
            dns_data: Diccionario con datos del paquete DNS
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO dns_packets 
                (timestamp, src_ip, dst_ip, protocol, is_query, is_response,
                 domain, record_type, record_type_code, dns_id, opcode, rcode, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                dns_data.get('timestamp'),
                dns_data.get('src_ip'),
                dns_data.get('dst_ip'),
                dns_data.get('protocol'),
                1 if dns_data.get('is_query', False) else 0,
                1 if dns_data.get('is_response', False) else 0,
                dns_data.get('domain'),
                dns_data.get('record_type'),
                dns_data.get('record_type_code', 0),
                dns_data.get('dns_id'),
                dns_data.get('opcode'),
                dns_data.get('rcode'),
                json.dumps(dns_data)
            ))
            self.conn.commit()
        except Exception as e:
            logger.error("Error almacenando paquete DNS: %s", e)
            self.conn.rollback()
    
    def get_top_clients(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Obtiene los clientes (IPs) que más consultas han realizado
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de diccionarios con IP y cantidad de consultas
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT src_ip as ip, COUNT(*) as count
            FROM dns_packets
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))
        
        return [{'ip': row['ip'], 'count': row['count']} for row in cursor.fetchall()]
    
    def get_top_domains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Obtiene los dominios más consultados
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de diccionarios con dominio y cantidad de consultas
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT domain, COUNT(*) as count
            FROM dns_packets
            GROUP BY domain
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))
        
        return [{'domain': row['domain'], 'count': row['count']} for row in cursor.fetchall()]
    
    def get_record_type_stats(self) -> Dict[str, int]:
        """
        Obtiene estadísticas por tipo de registro DNS
        
        Returns:
            Diccionario con tipo de registro y cantidad
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT record_type, COUNT(*) as count
            FROM dns_packets
            GROUP BY record_type
            ORDER BY count DESC
        ''')
        
        return {row['record_type']: row['count'] for row in cursor.fetchall()}
    
    def get_protocol_stats(self) -> Dict[str, int]:
        """
        Obtiene estadísticas TCP vs UDP
        
        Returns:
            Diccionario con protocolo y cantidad
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT protocol, COUNT(*) as count
            FROM dns_packets
            GROUP BY protocol
        ''')
        
        return {row['protocol']: row['count'] for row in cursor.fetchall()}
    
    def get_unique_clients_count(self) -> int:
        """Retorna el número de clientes únicos"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(DISTINCT src_ip) as count FROM dns_packets')
        result = cursor.fetchone()
        return result['count'] if result else 0
    
    def get_unique_domains_count(self) -> int:
        """Retorna el número de dominios únicos"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(DISTINCT domain) as count FROM dns_packets')
        result = cursor.fetchone()
        return result['count'] if result else 0
    
    def get_recent_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Obtiene las consultas más recientes
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de consultas DNS recientes
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT data_json
            FROM dns_packets
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        queries = []
        for row in cursor.fetchall():
            try:
                query_data = json.loads(row['data_json'])
                queries.append(query_data)
            except json.JSONDecodeError:
                continue
        
        return queries
    
    def get_time_range_stats(self, hours: int = 24) -> Dict[str, Any]:
        """
        Obtiene estadísticas del último período de tiempo
        
        Args:
            hours: Número de horas hacia atrás
            
        Returns:
            Diccionario con estadísticas del período
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Convertir timestamp a formato SQLite datetime
        cutoff_datetime = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor = self.conn.cursor()
        
        # Obtener total de consultas
        cursor.execute('''
            SELECT COUNT(*) as total_queries
            FROM dns_packets
            WHERE datetime(timestamp) >= datetime(?)
        ''', (cutoff_datetime,))
        total_queries = cursor.fetchone()['total_queries']
        
        # Obtener clientes únicos
        cursor.execute('''
            SELECT COUNT(DISTINCT src_ip) as unique_clients
            FROM dns_packets
            WHERE datetime(timestamp) >= datetime(?)
        ''', (cutoff_datetime,))
        unique_clients = cursor.fetchone()['unique_clients']
        
        # Obtener dominios únicos
        cursor.execute('''
            SELECT COUNT(DISTINCT domain) as unique_domains
            FROM dns_packets
            WHERE datetime(timestamp) >= datetime(?)
        ''', (cutoff_datetime,))
        unique_domains = cursor.fetchone()['unique_domains']
        
        # Obtener estadísticas TCP vs UDP
        cursor.execute('''
            SELECT protocol, COUNT(*) as count
            FROM dns_packets
            WHERE datetime(timestamp) >= datetime(?)
            GROUP BY protocol
        ''', (cutoff_datetime,))
        protocol_counts = {row['protocol']: row['count'] for row in cursor.fetchall()}
        
        # Obtener estadísticas por tipo de registro
        cursor.execute('''
            SELECT record_type, COUNT(*) as count
            FROM dns_packets
            WHERE datetime(timestamp) >= datetime(?)
            GROUP BY record_type
        ''', (cutoff_datetime,))
        record_types = {row['record_type']: row['count'] for row in cursor.fetchall()}
        
        return {
            'total_queries': total_queries,
            'unique_clients': unique_clients,
            'unique_domains': unique_domains,
            'tcp_count': protocol_counts.get('TCP', 0),
            'udp_count': protocol_counts.get('UDP', 0),
            'record_types': record_types
        }
    
    def clear_all_data(self):
        """Elimina todos los datos DNS almacenados (¡CUIDADO!)"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM dns_packets')
            self.conn.commit()
            logger.info("Todos los datos DNS han sido eliminados")
        except Exception as e:
            logger.error(f"Error eliminando datos: {e}")
            self.conn.rollback()
    
    def cleanup_old_data(self, days: int = 30):
        """
        Elimina datos más antiguos que el número de días especificado
        
        Args:
            days: Número de días de retención
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            cutoff_datetime = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
            
            cursor = self.conn.cursor()
            cursor.execute('''
                DELETE FROM dns_packets
                WHERE datetime(timestamp) < datetime(?)
            ''', (cutoff_datetime,))
            deleted = cursor.rowcount
            self.conn.commit()
            logger.info("Eliminados %d registros antiguos (más de %d días)", deleted, days)
        except Exception as e:
            logger.error("Error limpiando datos antiguos: %s", e)
            self.conn.rollback()
    
    def close(self):
        """Cierra la conexión a la base de datos"""
        if self.conn:
            self.conn.close()
            logger.info("Conexión a SQLite cerrada")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

