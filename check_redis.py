#!/usr/bin/env python3
"""
Script para verificar datos DNS en Redis
"""

import sys
from redis_client import DNSRedisClient
from config import get_config

def main():
    """Verifica los datos DNS almacenados en Redis"""
    try:
        # Cargar configuración
        config = get_config()
        redis_config = config.get_redis_config()
        
        print(f"Conectando a Redis: {redis_config['host']}:{redis_config['port']} (DB: {redis_config['db']})")
        
        # Conectar a Redis
        client = DNSRedisClient(
            host=redis_config['host'],
            port=redis_config['port'],
            db=redis_config['db'],
            password=redis_config['password']
        )
        
        # Obtener información de diagnóstico
        diag_info = client.get_diagnostic_info()
        
        print("\n=== Información de Redis ===")
        if 'error' in diag_info:
            print(f"❌ Error: {diag_info['error']}")
            return 1
        
        print(f"✅ Conexión: OK")
        print(f"📊 Total de claves DNS: {diag_info['total_keys']}")
        
        if diag_info['has_data']:
            print(f"\n✅ HAY DATOS EN REDIS:")
            print(f"  - Clientes: {diag_info['client_keys']}")
            print(f"  - Dominios: {diag_info['domain_keys']}")
            print(f"  - Paquetes: {diag_info['packet_keys']}")
            print(f"  - Tipos: {diag_info['type_keys']}")
            print(f"  - Protocolos: {diag_info['protocol_keys']}")
            print(f"  - Consultas recientes: {diag_info['recent_queries']}")
            print(f"  - Clientes únicos: {diag_info['unique_clients']}")
            print(f"  - Dominios únicos: {diag_info['unique_domains']}")
            
            # Mostrar algunos ejemplos
            print("\n=== Top 5 Clientes ===")
            top_clients = client.get_top_clients(limit=5)
            for i, client_info in enumerate(top_clients, 1):
                print(f"  {i}. {client_info['ip']}: {client_info['count']} consultas")
            
            print("\n=== Top 5 Dominios ===")
            top_domains = client.get_top_domains(limit=5)
            for i, domain_info in enumerate(top_domains, 1):
                print(f"  {i}. {domain_info['domain']}: {domain_info['count']} consultas")
            
            print("\n=== Estadísticas por Protocolo ===")
            protocol_stats = client.get_protocol_stats()
            for protocol, count in protocol_stats.items():
                print(f"  {protocol}: {count}")
            
            print("\n=== Tipos de Registro ===")
            record_stats = client.get_record_type_stats()
            for record_type, count in sorted(record_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {record_type}: {count}")
        else:
            print("\n⚠️  NO HAY DATOS EN REDIS")
            print("Posibles causas:")
            print("  - El capturador no está escribiendo a Redis")
            print("  - El buffer no se ha vaciado aún (espera hasta 1 segundo)")
            print("  - El capturador está usando otra base de datos Redis")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

