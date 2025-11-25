#!/usr/bin/env python3
"""
Cliente Redis para almacenar y consultar datos DNS
"""

import redis
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DNSRedisClient:
    """Cliente para interactuar con Redis y obtener estadísticas DNS"""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0, password: Optional[str] = None):
        """
        Inicializa el cliente Redis
        
        Args:
            host: Host de Redis
            port: Puerto de Redis
            db: Base de datos Redis
            password: Contraseña de Redis (opcional)
        """
        try:
            self.client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True
            )
            # Test de conexión
            self.client.ping()
            logger.info(f"Conectado a Redis en {host}:{port}")
        except redis.ConnectionError as e:
            logger.error(f"Error conectando a Redis: {e}")
            raise
    
    def get_top_clients(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Obtiene los clientes (IPs) que más consultas han realizado
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de diccionarios con IP y cantidad de consultas
        """
        clients = []
        pattern = "dns:client:*:count"
        
        for key in self.client.scan_iter(match=pattern):
            count = int(self.client.get(key) or 0)
            ip = key.replace("dns:client:", "").replace(":count", "")
            clients.append({'ip': ip, 'count': count})
        
        # Ordenar por cantidad descendente
        clients.sort(key=lambda x: x['count'], reverse=True)
        return clients[:limit]
    
    def get_top_domains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Obtiene los dominios más consultados
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de diccionarios con dominio y cantidad de consultas
        """
        domains = []
        pattern = "dns:domain:*:count"
        
        for key in self.client.scan_iter(match=pattern):
            count = int(self.client.get(key) or 0)
            domain = key.replace("dns:domain:", "").replace(":count", "")
            domains.append({'domain': domain, 'count': count})
        
        # Ordenar por cantidad descendente
        domains.sort(key=lambda x: x['count'], reverse=True)
        return domains[:limit]
    
    def get_record_type_stats(self) -> Dict[str, int]:
        """
        Obtiene estadísticas por tipo de registro DNS
        
        Returns:
            Diccionario con tipo de registro y cantidad
        """
        stats = {}
        pattern = "dns:type:*:count"
        
        for key in self.client.scan_iter(match=pattern):
            count = int(self.client.get(key) or 0)
            record_type = key.replace("dns:type:", "").replace(":count", "")
            stats[record_type] = count
        
        return stats
    
    def get_protocol_stats(self) -> Dict[str, int]:
        """
        Obtiene estadísticas TCP vs UDP
        
        Returns:
            Diccionario con protocolo y cantidad
        """
        stats = {}
        pattern = "dns:protocol:*:count"
        
        for key in self.client.scan_iter(match=pattern):
            count = int(self.client.get(key) or 0)
            protocol = key.replace("dns:protocol:", "").replace(":count", "")
            stats[protocol] = count
        
        return stats
    
    def get_unique_clients_count(self) -> int:
        """Retorna el número de clientes únicos"""
        return self.client.scard("dns:clients:unique")
    
    def get_unique_domains_count(self) -> int:
        """Retorna el número de dominios únicos"""
        return self.client.scard("dns:domains:unique")
    
    def get_recent_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Obtiene las consultas más recientes
        
        Args:
            limit: Número máximo de resultados
            
        Returns:
            Lista de consultas DNS recientes
        """
        queries = []
        
        # Obtener las claves más recientes
        recent_keys = self.client.zrevrange("dns:recent", 0, limit - 1)
        
        for key in recent_keys:
            data = self.client.get(key)
            if data:
                try:
                    query_data = json.loads(data)
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
        cutoff_timestamp = cutoff_time.timestamp()
        
        # Obtener consultas del período
        recent_keys = self.client.zrangebyscore(
            "dns:recent",
            cutoff_timestamp,
            '+inf'
        )
        
        stats = {
            'total_queries': len(recent_keys),
            'clients': set(),
            'domains': set(),
            'tcp_count': 0,
            'udp_count': 0,
            'record_types': {}
        }
        
        for key in recent_keys:
            data = self.client.get(key)
            if data:
                try:
                    query_data = json.loads(data)
                    stats['clients'].add(query_data['src_ip'])
                    stats['domains'].add(query_data['domain'])
                    
                    if query_data['protocol'] == 'TCP':
                        stats['tcp_count'] += 1
                    else:
                        stats['udp_count'] += 1
                    
                    record_type = query_data['record_type']
                    stats['record_types'][record_type] = stats['record_types'].get(record_type, 0) + 1
                except (json.JSONDecodeError, KeyError):
                    continue
        
        stats['unique_clients'] = len(stats['clients'])
        stats['unique_domains'] = len(stats['domains'])
        
        return stats
    
    def clear_all_data(self):
        """Elimina todos los datos DNS almacenados (¡CUIDADO!)"""
        pattern = "dns:*"
        keys = list(self.client.scan_iter(match=pattern))
        if keys:
            self.client.delete(*keys)
            logger.info(f"Eliminados {len(keys)} registros DNS")
        else:
            logger.info("No hay datos para eliminar")

