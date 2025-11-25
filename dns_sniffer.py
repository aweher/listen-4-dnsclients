#!/usr/bin/env python3
"""
DNS Sniffer - Captura pasiva de paquetes DNS
Escucha tráfico DNS en la interfaz de red y extrae información de las consultas
"""

import json
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional, Dict, Any
from scapy.all import sniff, IP, UDP, TCP, DNS
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
    
    def __init__(self, interface: Optional[str] = None, batch_size: int = 50, flush_interval: float = 1.0, verbose: bool = False):
        """
        Inicializa el capturador DNS
        
        Args:
            interface: Interfaz de red a escuchar (None = todas las interfaces)
            batch_size: Número de paquetes a acumular antes de escribir a Redis (default: 50)
            flush_interval: Intervalo en segundos para forzar escritura a Redis (default: 1.0)
            verbose: Si es True, muestra cada paquete capturado en consola
        """
        self.interface = interface
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.verbose = verbose
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'errors': 0,
            'batches_written': 0,
            'packets_buffered': 0
        }
        # Buffer thread-safe para acumular paquetes
        self.buffer = deque()
        self.buffer_lock = threading.Lock()
        self.last_flush = time.time()
        self.redis_client = None
        self.flush_thread = None
        self.stats_thread = None
        self.running = False
    
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
                    try:
                        # Decodificar nombre DNS de forma segura
                        if isinstance(query.qname, bytes):
                            domain = query.qname.decode('utf-8', errors='replace').rstrip('.')
                        else:
                            domain = str(query.qname).rstrip('.')
                    except Exception:
                        domain = str(query.qname).rstrip('.')
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
                        # Decodificar nombre DNS de forma segura
                        domain = ''
                        if hasattr(answer, 'rrname'):
                            try:
                                if isinstance(answer.rrname, bytes):
                                    domain = answer.rrname.decode('utf-8', errors='replace').rstrip('.')
                                else:
                                    domain = str(answer.rrname).rstrip('.')
                            except Exception:
                                domain = str(answer.rrname).rstrip('.')
                        rtype = answer.type
                        rtype_name = self.DNS_TYPES.get(rtype, f'UNKNOWN({rtype})')
                        rdata = ''
                        if hasattr(answer, 'rdata'):
                            if isinstance(answer.rdata, bytes):
                                try:
                                    rdata = answer.rdata.decode('utf-8', errors='replace')
                                except Exception:
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
            
            # Obtener puerto de forma segura
            try:
                if is_tcp and packet.haslayer(TCP):
                    port = packet[TCP].dport
                elif is_udp and packet.haslayer(UDP):
                    port = packet[UDP].dport
                else:
                    return None
            except (AttributeError, IndexError):
                return None
            
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
    
    def packet_handler(self, packet, redis_client=None):
        """
        Maneja cada paquete capturado
        
        Args:
            packet: Paquete capturado
            redis_client: Cliente Redis para almacenar datos (se usa para inicialización)
        """
        self.stats['total_packets'] += 1
        
        dns_data = self._parse_dns_packet(packet)
        
        if dns_data:
            self.stats['dns_packets'] += 1
            if dns_data['protocol'] == 'TCP':
                self.stats['tcp_count'] += 1
            else:
                self.stats['udp_count'] += 1
            
            # Mostrar paquete en consola si verbose está activado
            if self.verbose:
                logger.info(f"DNS: {dns_data['src_ip']} -> {dns_data['domain']} ({dns_data['record_type']}) via {dns_data['protocol']}")
            
            # Almacenar en buffer si Redis está disponible
            if self.redis_client:
                try:
                    with self.buffer_lock:
                        self.buffer.append(dns_data)
                        self.stats['packets_buffered'] += 1
                        
                        # Flush si el buffer alcanza el tamaño máximo
                        if len(self.buffer) >= self.batch_size:
                            self._flush_buffer()
                except Exception as e:
                    logger.error(f"Error agregando a buffer: {e}")
                    self.stats['errors'] += 1
            elif redis_client:
                # Modo sin buffer (compatibilidad hacia atrás)
                try:
                    self._store_in_redis(redis_client, dns_data)
                except Exception as e:
                    logger.error(f"Error almacenando en Redis: {e}")
                    self.stats['errors'] += 1
            
            logger.debug(f"DNS Packet: {dns_data['src_ip']} -> {dns_data['domain']} ({dns_data['record_type']}) via {dns_data['protocol']}")
    
    def _store_in_redis(self, redis_client, dns_data: Dict[str, Any]):
        """
        Almacena datos DNS en Redis (método individual, para compatibilidad)
        
        Args:
            redis_client: Cliente Redis (DNSRedisClient o redis.Redis)
            dns_data: Datos del paquete DNS
        """
        # Obtener el cliente Redis real (puede ser DNSRedisClient o redis.Redis)
        if hasattr(redis_client, 'client'):
            # Es un DNSRedisClient, usar el cliente interno
            client = redis_client.client
        else:
            # Es un redis.Redis directo
            client = redis_client
        
        timestamp = datetime.now()
        timestamp_str = timestamp.strftime('%Y%m%d%H%M%S%f')
        
        # Almacenar el paquete completo
        key = f"dns:packet:{timestamp_str}"
        client.setex(key, 86400 * 7, json.dumps(dns_data))  # Retener 7 días
        
        # Estadísticas por IP de origen
        src_ip_key = f"dns:client:{dns_data['src_ip']}"
        client.incr(f"{src_ip_key}:count")
        client.expire(f"{src_ip_key}:count", 86400 * 30)  # 30 días
        
        # Dominios más consultados
        domain_key = f"dns:domain:{dns_data['domain']}"
        client.incr(f"{domain_key}:count")
        client.expire(f"{domain_key}:count", 86400 * 30)
        
        # Estadísticas por tipo de registro
        record_type_key = f"dns:type:{dns_data['record_type']}"
        client.incr(f"{record_type_key}:count")
        client.expire(f"{record_type_key}:count", 86400 * 30)
        
        # Estadísticas TCP vs UDP
        protocol_key = f"dns:protocol:{dns_data['protocol']}"
        client.incr(f"{protocol_key}:count")
        client.expire(f"{protocol_key}:count", 86400 * 30)
        
        # Timestamp para consultas recientes
        client.zadd("dns:recent", {key: timestamp.timestamp()})
        client.expire("dns:recent", 86400 * 7)  # Mantener últimos 7 días
        
        # IPs de origen únicas
        client.sadd("dns:clients:unique", dns_data['src_ip'])
        client.expire("dns:clients:unique", 86400 * 30)
        
        # Dominios únicos
        client.sadd("dns:domains:unique", dns_data['domain'])
        client.expire("dns:domains:unique", 86400 * 30)
    
    def _flush_buffer(self):
        """
        Escribe todos los paquetes del buffer a Redis usando pipeline para optimizar
        """
        if not self.redis_client:
            return
        
        # Extraer todos los paquetes del buffer (thread-safe)
        packets_to_write = []
        with self.buffer_lock:
            if len(self.buffer) == 0:
                return
            while self.buffer:
                packets_to_write.append(self.buffer.popleft())
        
        if not packets_to_write:
            return
        
        try:
            # Usar pipeline de Redis para agrupar todas las operaciones
            # Esto reduce significativamente los round-trips, especialmente importante con AOF
            # Acceder al cliente Redis interno del DNSRedisClient
            pipe = self.redis_client.client.pipeline()
            
            current_time = datetime.now()
            timestamp_base = current_time.timestamp()
            
            for i, dns_data in enumerate(packets_to_write):
                # Usar microsegundos para asegurar unicidad
                timestamp_str = f"{current_time.strftime('%Y%m%d%H%M%S')}{i:06d}"
                key = f"dns:packet:{timestamp_str}"
                timestamp_val = timestamp_base + (i * 0.000001)  # Asegurar orden
                
                # Almacenar el paquete completo
                pipe.setex(key, 86400 * 7, json.dumps(dns_data))
                
                # Estadísticas por IP de origen
                src_ip_key = f"dns:client:{dns_data['src_ip']}"
                pipe.incr(f"{src_ip_key}:count")
                pipe.expire(f"{src_ip_key}:count", 86400 * 30)
                
                # Dominios más consultados
                domain_key = f"dns:domain:{dns_data['domain']}"
                pipe.incr(f"{domain_key}:count")
                pipe.expire(f"{domain_key}:count", 86400 * 30)
                
                # Estadísticas por tipo de registro
                record_type_key = f"dns:type:{dns_data['record_type']}"
                pipe.incr(f"{record_type_key}:count")
                pipe.expire(f"{record_type_key}:count", 86400 * 30)
                
                # Estadísticas TCP vs UDP
                protocol_key = f"dns:protocol:{dns_data['protocol']}"
                pipe.incr(f"{protocol_key}:count")
                pipe.expire(f"{protocol_key}:count", 86400 * 30)
                
                # Timestamp para consultas recientes
                pipe.zadd("dns:recent", {key: timestamp_val})
                
                # IPs de origen únicas
                pipe.sadd("dns:clients:unique", dns_data['src_ip'])
                
                # Dominios únicos
                pipe.sadd("dns:domains:unique", dns_data['domain'])
            
            # Expirar sets una sola vez por batch (más eficiente)
            pipe.expire("dns:recent", 86400 * 7)
            pipe.expire("dns:clients:unique", 86400 * 30)
            pipe.expire("dns:domains:unique", 86400 * 30)
            
            # Ejecutar todas las operaciones en un solo round-trip
            pipe.execute()
            
            self.stats['batches_written'] += 1
            self.last_flush = time.time()
            logger.info(f"✅ Escritos {len(packets_to_write)} paquetes a Redis en batch (Total batches: {self.stats['batches_written']})")
            
        except Exception as e:
            logger.error(f"Error escribiendo batch a Redis: {e}")
            self.stats['errors'] += 1
            # Re-agregar los paquetes al buffer para reintentar
            with self.buffer_lock:
                self.buffer.extendleft(reversed(packets_to_write))
    
    def _flush_thread_worker(self):
        """
        Worker thread que fuerza el flush periódico del buffer
        """
        while self.running:
            time.sleep(self.flush_interval)
            current_time = time.time()
            
            # Flush si ha pasado el intervalo y hay datos
            if (current_time - self.last_flush) >= self.flush_interval:
                # Verificar tamaño del buffer sin lock (no crítico, solo para logging)
                buffer_size = len(self.buffer) if hasattr(self, 'buffer') else 0
                if buffer_size > 0:
                    logger.debug(f"Flush periódico: {buffer_size} paquetes en buffer")
                # _flush_buffer() maneja el locking internamente
                self._flush_buffer()
    
    def _stats_thread_worker(self, interval: float = 10.0):
        """
        Worker thread que muestra estadísticas periódicas
        
        Args:
            interval: Intervalo en segundos para mostrar estadísticas (default: 10.0)
        """
        last_stats_time = time.time()
        last_packets = 0
        
        while self.running:
            time.sleep(interval)
            current_time = time.time()
            
            # Calcular estadísticas
            stats = self.get_stats()
            elapsed = current_time - last_stats_time
            packets_diff = stats['dns_packets'] - last_packets
            rate = packets_diff / elapsed if elapsed > 0 else 0
            
            with self.buffer_lock:
                buffer_size = len(self.buffer)
            
            logger.info(
                f"📊 Estadísticas: {stats['dns_packets']} paquetes DNS capturados | "
                f"Rate: {rate:.1f} pkt/s | "
                f"Buffer: {buffer_size} | "
                f"Batches escritos: {stats.get('batches_written', 0)} | "
                f"TCP: {stats['tcp_count']} UDP: {stats['udp_count']}"
            )
            
            last_stats_time = current_time
            last_packets = stats['dns_packets']
    
    def start(self, redis_client=None, filter_str: str = "port 53"):
        """
        Inicia la captura de paquetes DNS
        
        Args:
            redis_client: Cliente Redis para almacenar datos
            filter_str: Filtro BPF para captura (default: port 53)
        """
        logger.info(f"Iniciando captura DNS en interfaz: {self.interface or 'todas'}")
        logger.info(f"Filtro: {filter_str}")
        
        # Configurar Redis y buffer si está disponible
        if redis_client:
            self.redis_client = redis_client
            self.running = True
            # Iniciar thread para flush periódico
            self.flush_thread = threading.Thread(target=self._flush_thread_worker, daemon=True)
            self.flush_thread.start()
            # Iniciar thread para estadísticas periódicas
            self.stats_thread = threading.Thread(target=self._stats_thread_worker, args=(10.0,), daemon=True)
            self.stats_thread.start()
            logger.info(f"Modo optimizado activado: batch_size={self.batch_size}, flush_interval={self.flush_interval}s")
        
        try:
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=lambda p: self.packet_handler(p, redis_client),
                store=False  # No almacenar paquetes en memoria
            )
        except KeyboardInterrupt:
            logger.info("Captura interrumpida por el usuario")
        except Exception as e:
            logger.error(f"Error en captura: {e}")
            raise
        finally:
            # Asegurar que el buffer se vacíe antes de terminar
            self.running = False
            if self.redis_client:
                # Flush final del buffer
                with self.buffer_lock:
                    if len(self.buffer) > 0:
                        logger.info(f"Realizando flush final de {len(self.buffer)} paquetes...")
                        self._flush_buffer()
                # Esperar a que los threads terminen
                if self.flush_thread and self.flush_thread.is_alive():
                    self.flush_thread.join(timeout=2.0)
                if self.stats_thread and self.stats_thread.is_alive():
                    self.stats_thread.join(timeout=2.0)
    
    def get_stats(self) -> Dict[str, int]:
        """Retorna estadísticas de captura"""
        return self.stats.copy()

