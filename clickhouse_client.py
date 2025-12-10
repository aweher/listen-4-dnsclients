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

Cliente ClickHouse para almacenar y consultar datos DNS
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
from clickhouse_driver import Client
from clickhouse_driver.errors import Error as ClickHouseError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DNSClickHouseClient:
    """Cliente para interactuar con ClickHouse y almacenar datos DNS"""
    
    def __init__(self, host: str = 'localhost', port: int = 9000, database: str = 'dns_monitor',
                 user: str = 'default', password: Optional[str] = None):
        """
        Inicializa el cliente ClickHouse
        
        Args:
            host: Host de ClickHouse
            port: Puerto de ClickHouse (puerto nativo, default: 9000)
            database: Nombre de la base de datos
            user: Usuario de ClickHouse
            password: Contraseña de ClickHouse (opcional)
        """
        try:
            # Guardar el nombre de la base de datos como atributo de la clase
            self.database = database
            self.client = Client(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password or '',
                connect_timeout=10,
                send_receive_timeout=30
            )
            # Test de conexión
            self.client.execute('SELECT 1')
            logger.info(f"Conectado a ClickHouse en {host}:{port} (database: {database})")
            
            # Crear base de datos y tabla si no existen
            self._initialize_database()
        except ClickHouseError as e:
            logger.error(f"Error conectando a ClickHouse: {e}")
            raise
    
    def _initialize_database(self):
        """Crea la base de datos y tabla si no existen"""
        try:
            # Crear base de datos si no existe
            # Usar el atributo database de la clase, no del cliente
            self.client.execute(f'CREATE DATABASE IF NOT EXISTS `{self.database}`')
            
            # Crear tabla para almacenar paquetes DNS
            create_table_query = """
            CREATE TABLE IF NOT EXISTS dns_queries (
                timestamp DateTime,
                src_ip String,
                dst_ip String,
                protocol String,
                is_query UInt8,
                is_response UInt8,
                domain String,
                record_type String,
                record_type_code UInt16,
                dns_id UInt16,
                opcode UInt8,
                rcode Nullable(UInt8),
                queries String,
                answers String
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, src_ip, domain)
            TTL timestamp + INTERVAL 90 DAY
            SETTINGS index_granularity = 8192
            """
            
            self.client.execute(create_table_query)
            logger.info("Tabla dns_queries inicializada correctamente")
            
        except ClickHouseError as e:
            logger.error(f"Error inicializando base de datos: {e}")
            raise
    
    def insert_dns_query(self, dns_data: Dict[str, Any]):
        """
        Inserta un paquete DNS en ClickHouse
        
        Args:
            dns_data: Diccionario con información del paquete DNS
        """
        try:
            # Convertir timestamp ISO a DateTime
            timestamp = datetime.fromisoformat(dns_data['timestamp'].replace('Z', '+00:00'))
            
            # Serializar queries y answers a JSON strings
            import json
            queries_str = json.dumps(dns_data.get('queries', []))
            answers_str = json.dumps(dns_data.get('answers', []))
            
            insert_query = """
            INSERT INTO dns_queries (
                timestamp, src_ip, dst_ip, protocol, is_query, is_response,
                domain, record_type, record_type_code, dns_id, opcode, rcode,
                queries, answers
            ) VALUES
            """
            
            self.client.execute(
                insert_query,
                [(
                    timestamp,
                    dns_data['src_ip'],
                    dns_data['dst_ip'],
                    dns_data['protocol'],
                    1 if dns_data.get('is_query', False) else 0,
                    1 if dns_data.get('is_response', False) else 0,
                    dns_data['domain'],
                    dns_data['record_type'],
                    dns_data.get('record_type_code', 0),
                    dns_data.get('dns_id', 0),
                    dns_data.get('opcode', 0),
                    dns_data.get('rcode'),
                    queries_str,
                    answers_str
                )]
            )
            
        except ClickHouseError as e:
            logger.error(f"Error insertando datos en ClickHouse: {e}")
            raise
        except Exception as e:
            logger.error(f"Error procesando datos para ClickHouse: {e}")
            raise
    
    def insert_batch(self, dns_data_list: List[Dict[str, Any]]):
        """
        Inserta múltiples paquetes DNS en ClickHouse en un solo batch
        
        Args:
            dns_data_list: Lista de diccionarios con información de paquetes DNS
        """
        if not dns_data_list:
            return
        
        try:
            import json
            
            # Preparar datos para inserción batch
            data_to_insert = []
            for dns_data in dns_data_list:
                timestamp = datetime.fromisoformat(dns_data['timestamp'].replace('Z', '+00:00'))
                queries_str = json.dumps(dns_data.get('queries', []))
                answers_str = json.dumps(dns_data.get('answers', []))
                
                data_to_insert.append((
                    timestamp,
                    dns_data['src_ip'],
                    dns_data['dst_ip'],
                    dns_data['protocol'],
                    1 if dns_data.get('is_query', False) else 0,
                    1 if dns_data.get('is_response', False) else 0,
                    dns_data['domain'],
                    dns_data['record_type'],
                    dns_data.get('record_type_code', 0),
                    dns_data.get('dns_id', 0),
                    dns_data.get('opcode', 0),
                    dns_data.get('rcode'),
                    queries_str,
                    answers_str
                ))
            
            insert_query = """
            INSERT INTO dns_queries (
                timestamp, src_ip, dst_ip, protocol, is_query, is_response,
                domain, record_type, record_type_code, dns_id, opcode, rcode,
                queries, answers
            ) VALUES
            """
            
            self.client.execute(insert_query, data_to_insert)
            logger.debug(f"Insertados {len(dns_data_list)} registros en ClickHouse")
            
        except ClickHouseError as e:
            logger.error(f"Error insertando batch en ClickHouse: {e}")
            raise
        except Exception as e:
            logger.error(f"Error procesando batch para ClickHouse: {e}")
            raise
    
    def get_top_clients(self, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Obtiene los clientes (IPs) que más consultas han realizado
        
        Args:
            limit: Número máximo de resultados
            hours: Número de horas hacia atrás para filtrar
            
        Returns:
            Lista de diccionarios con IP y cantidad de consultas
        """
        try:
            query = """
            SELECT 
                src_ip as ip,
                count() as count
            FROM dns_queries
            WHERE timestamp >= now() - INTERVAL ? HOUR
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT ?
            """
            
            result = self.client.execute(query, [hours, limit])
            return [{'ip': row[0], 'count': row[1]} for row in result]
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo top clientes: {e}")
            return []
    
    def get_top_domains(self, limit: int = 10, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Obtiene los dominios más consultados
        
        Args:
            limit: Número máximo de resultados
            hours: Número de horas hacia atrás para filtrar
            
        Returns:
            Lista de diccionarios con dominio y cantidad de consultas
        """
        try:
            query = """
            SELECT 
                domain,
                count() as count
            FROM dns_queries
            WHERE timestamp >= now() - INTERVAL ? HOUR
            GROUP BY domain
            ORDER BY count DESC
            LIMIT ?
            """
            
            result = self.client.execute(query, [hours, limit])
            return [{'domain': row[0], 'count': row[1]} for row in result]
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo top dominios: {e}")
            return []
    
    def get_protocol_stats(self, hours: int = 24) -> Dict[str, int]:
        """
        Obtiene estadísticas TCP vs UDP
        
        Args:
            hours: Número de horas hacia atrás para filtrar
            
        Returns:
            Diccionario con protocolo y cantidad
        """
        try:
            query = """
            SELECT 
                protocol,
                count() as count
            FROM dns_queries
            WHERE timestamp >= now() - INTERVAL ? HOUR
            GROUP BY protocol
            """
            
            result = self.client.execute(query, [hours])
            return {row[0]: row[1] for row in result}
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo estadísticas de protocolo: {e}")
            return {}
    
    def get_record_type_stats(self, hours: int = 24) -> Dict[str, int]:
        """
        Obtiene estadísticas por tipo de registro DNS
        
        Args:
            hours: Número de horas hacia atrás para filtrar
            
        Returns:
            Diccionario con tipo de registro y cantidad
        """
        try:
            query = """
            SELECT 
                record_type,
                count() as count
            FROM dns_queries
            WHERE timestamp >= now() - INTERVAL ? HOUR
            GROUP BY record_type
            ORDER BY count DESC
            """
            
            result = self.client.execute(query, [hours])
            return {row[0]: row[1] for row in result}
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo estadísticas de tipos de registro: {e}")
            return {}
    
    def get_unique_clients_count(self, hours: int = 24) -> int:
        """
        Retorna el número de clientes únicos
        
        Args:
            hours: Número de horas hacia atrás para filtrar
        """
        try:
            query = """
            SELECT uniqExact(src_ip)
            FROM dns_queries
            WHERE timestamp >= now() - INTERVAL ? HOUR
            """
            
            result = self.client.execute(query, [hours])
            return result[0][0] if result else 0
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo conteo de clientes únicos: {e}")
            return 0
    
    def get_unique_domains_count(self, hours: int = 24) -> int:
        """
        Retorna el número de dominios únicos
        
        Args:
            hours: Número de horas hacia atrás para filtrar
        """
        try:
            query = """
            SELECT uniqExact(domain)
            FROM dns_queries
            WHERE timestamp >= now() - INTERVAL ? HOUR
            """
            
            result = self.client.execute(query, [hours])
            return result[0][0] if result else 0
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo conteo de dominios únicos: {e}")
            return 0
    
    def get_recent_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Obtiene las consultas más recientes
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de consultas DNS recientes
        """
        try:
            import json
            
            query = """
            SELECT 
                timestamp,
                src_ip,
                domain,
                record_type,
                protocol,
                is_query
            FROM dns_queries
            ORDER BY timestamp DESC
            LIMIT ?
            """
            
            result = self.client.execute(query, [limit])
            queries = []
            for row in result:
                queries.append({
                    'timestamp': row[0].isoformat(),
                    'src_ip': row[1],
                    'domain': row[2],
                    'record_type': row[3],
                    'protocol': row[4],
                    'is_query': bool(row[5])
                })
            
            return queries
            
        except ClickHouseError as e:
            logger.error(f"Error obteniendo consultas recientes: {e}")
            return []
    
    def close(self):
        """Cierra la conexión con ClickHouse"""
        if hasattr(self, 'client'):
            self.client.disconnect()
            logger.info("Conexión con ClickHouse cerrada")