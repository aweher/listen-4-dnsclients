#!/usr/bin/env python3
"""
DNS Sniffer - Captura pasiva de paquetes DNS
Escucha tráfico DNS en la interfaz de red y extrae información de las consultas
"""

import socket
import struct
from datetime import datetime
from typing import Optional, Dict, Any
from scapy.all import sniff, IP, UDP, TCP, DNS, Raw
from scapy.layers.dns import DNSQR, DNSRR
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DNSSniffer:
    """Captura y procesa paquetes DNS de forma pasiva"""
    
    # Tipos de registro DNS comunes
    DNS_TYPES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        255: 'ANY'
    }
    
    def __init__(self, interface: Optional[str] = None):
        """
        Inicializa el capturador DNS
        
        Args:
            interface: Interfaz de red a escuchar (None = todas las interfaces)
        """
        self.interface = interface
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'errors': 0
        }
    
    def _parse_dns_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Parsea un paquete DNS y extrae información relevante
        
        Args:
            packet: Paquete capturado por Scapy
            
        Returns:
            Diccionario con información del paquete DNS o None si no es válido
        """
        try:
            # Verificar que tenga capa IP
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Verificar si es TCP o UDP
            is_tcp = packet.haslayer(TCP)
            is_udp = packet.haslayer(UDP)
            
            if not (is_tcp or is_udp):
                return None
            
            # Verificar si tiene capa DNS
            if not packet.haslayer(DNS):
                return None
            
            dns_layer = packet[DNS]
            
            # Solo procesar queries (QR=0) o respuestas (QR=1)
            # QR=0: Query, QR=1: Response
            is_query = dns_layer.qr == 0
            is_response = dns_layer.qr == 1
            
            # Extraer información de las queries
            queries = []
            if dns_layer.qr == 0 and dns_layer.qd:  # Es una query
                query = dns_layer.qd
                if query:
                    domain = query.qname.decode('utf-8').rstrip('.')
                    qtype = query.qtype
                    qtype_name = self.DNS_TYPES.get(qtype, f'UNKNOWN({qtype})')
                    queries.append({
                        'domain': domain,
                        'type': qtype_name,
                        'type_code': qtype
                    })
            
            # Extraer información de las respuestas
            answers = []
            if dns_layer.qr == 1 and dns_layer.an:  # Es una respuesta
                for i in range(dns_layer.ancount):
                    if i < len(dns_layer.an):
                        answer = dns_layer.an[i]
                        domain = answer.rrname.decode('utf-8').rstrip('.') if hasattr(answer, 'rrname') else ''
                        rtype = answer.type
                        rtype_name = self.DNS_TYPES.get(rtype, f'UNKNOWN({rtype})')
                        rdata = ''
                        if hasattr(answer, 'rdata'):
                            if isinstance(answer.rdata, bytes):
                                try:
                                    rdata = answer.rdata.decode('utf-8')
                                except:
                                    rdata = str(answer.rdata)
                            else:
                                rdata = str(answer.rdata)
                        answers.append({
                            'domain': domain,
                            'type': rtype_name,
                            'type_code': rtype,
                            'data': rdata
                        })
            
            # Si no hay queries ni respuestas relevantes, ignorar
            if not queries and not answers:
                return None
            
            # Determinar el dominio principal (de la query o de la primera respuesta)
            main_domain = ''
            if queries:
                main_domain = queries[0]['domain']
            elif answers:
                main_domain = answers[0]['domain']
            
            # Determinar el tipo de registro principal
            main_type = ''
            if queries:
                main_type = queries[0]['type']
            elif answers:
                main_type = answers[0]['type']
            
            protocol = 'TCP' if is_tcp else 'UDP'
            port = packet[TCP].dport if is_tcp else packet[UDP].dport
            
            # Solo procesar si es tráfico DNS (puerto 53)
            if port != 53:
                return None
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'is_query': is_query,
                'is_response': is_response,
                'domain': main_domain,
                'record_type': main_type,
                'record_type_code': queries[0]['type_code'] if queries else (answers[0]['type_code'] if answers else 0),
                'queries': queries,
                'answers': answers,
                'dns_id': dns_layer.id,
                'opcode': dns_layer.opcode,
                'rcode': dns_layer.rcode if is_response else None
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error parseando paquete DNS: {e}")
            self.stats['errors'] += 1
            return None
    
    def packet_handler(self, packet, db_client=None):
        """
        Maneja cada paquete capturado
        
        Args:
            packet: Paquete capturado
            db_client: Cliente SQLite para almacenar datos
        """
        self.stats['total_packets'] += 1
        
        dns_data = self._parse_dns_packet(packet)
        
        if dns_data:
            self.stats['dns_packets'] += 1
            if dns_data['protocol'] == 'TCP':
                self.stats['tcp_count'] += 1
            else:
                self.stats['udp_count'] += 1
            
            # Almacenar en SQLite si está disponible
            if db_client:
                try:
                    db_client.store_packet(dns_data)
                except Exception as e:
                    logger.error(f"Error almacenando en SQLite: {e}")
            
            logger.debug(f"DNS Packet: {dns_data['src_ip']} -> {dns_data['domain']} ({dns_data['record_type']}) via {dns_data['protocol']}")
    
    def start(self, db_client=None, filter_str: str = "port 53"):
        """
        Inicia la captura de paquetes DNS
        
        Args:
            db_client: Cliente SQLite para almacenar datos
            filter_str: Filtro BPF para captura (default: port 53)
        """
        logger.info(f"Iniciando captura DNS en interfaz: {self.interface or 'todas'}")
        logger.info(f"Filtro: {filter_str}")
        
        try:
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=lambda p: self.packet_handler(p, db_client),
                store=False  # No almacenar paquetes en memoria
            )
        except KeyboardInterrupt:
            logger.info("Captura interrumpida por el usuario")
        except Exception as e:
            logger.error(f"Error en captura: {e}")
            raise
    
    def get_stats(self) -> Dict[str, int]:
        """Retorna estadísticas de captura"""
        return self.stats.copy()

