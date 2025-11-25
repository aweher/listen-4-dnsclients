# DNS Monitor - Monitor Pasivo de Consultas DNS

> Hecho por Ariel S. Weher <ariel@ayuda.la>

Sistema de monitoreo pasivo de consultas DNS que captura tráfico DNS en tiempo real, almacena estadísticas en una base de datos SQLite local y proporciona un dashboard interactivo para visualización.

## Características

- 🔍 **Captura pasiva** de paquetes DNS (TCP y UDP)
- 📊 **Almacenamiento en SQLite** con estadísticas agregadas
- 📈 **Dashboard interactivo** con visualizaciones en tiempo real
- 🌐 **Estadísticas detalladas**:
  - IPs de origen de clientes
  - Dominios más consultados
  - Tipos de registro DNS (A, AAAA, MX, etc.)
  - Distribución TCP vs UDP
  - Consultas recientes
  - Estadísticas por período de tiempo

## Requisitos

- Python 3.8 o superior
- Permisos de administrador para capturar paquetes de red (en Linux/Mac)
- SQLite3 (incluido en Python por defecto)

## Instalación

1. Clonar o descargar el proyecto

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

No se requiere configuración adicional de base de datos. SQLite creará automáticamente el archivo `dns_monitor.db` cuando se ejecute el capturador por primera vez.

## Uso

### 1. Iniciar el capturador DNS

El capturador debe ejecutarse con permisos de administrador para poder capturar paquetes de red:

```bash
# En Linux/Mac
sudo python3 main.py

# Con opciones personalizadas
sudo python3 main.py -i eth0 --db-path /ruta/personalizada/dns_monitor.db

# Ver todas las opciones
python3 main.py --help
```

**Opciones disponibles:**
- `-i, --interface`: Interfaz de red específica (por defecto: todas)
- `-f, --filter`: Filtro BPF personalizado (por defecto: `port 53`)
- `--db-path`: Ruta al archivo de base de datos SQLite (por defecto: `dns_monitor.db`)
- `--no-db`: Ejecutar sin base de datos (solo mostrar en consola)

### 2. Iniciar el Dashboard

En otra terminal, ejecutar:

```bash
streamlit run dashboard.py
```

El dashboard estará disponible en `http://localhost:8501`

En el sidebar del dashboard puedes configurar la ruta a la base de datos si usaste una diferente a la predeterminada.

## Estructura del Proyecto

```
detectar-clientes-dns/
├── main.py              # Programa principal del capturador
├── dns_sniffer.py       # Módulo de captura de paquetes DNS
├── sqlite_client.py     # Cliente SQLite para almacenamiento y consultas
├── dashboard.py         # Dashboard Streamlit
├── requirements.txt     # Dependencias Python
├── dns_monitor.db       # Base de datos SQLite (se crea automáticamente)
└── README.md           # Este archivo
```

## Funcionalidades del Dashboard

### Estadísticas Generales
- Número de clientes únicos
- Número de dominios únicos
- Total de consultas
- Porcentaje de consultas TCP

### Visualizaciones
- **Gráfico de protocolos**: Distribución TCP vs UDP (gráfico de pastel)
- **Tipos de registro**: Frecuencia de cada tipo de registro DNS (A, AAAA, MX, etc.)
- **Top clientes**: IPs de origen que más consultas realizan
- **Top dominios**: Dominios más consultados
- **Consultas recientes**: Tabla con las últimas consultas capturadas

### Estadísticas por Período
- Consultas en las últimas horas (1h, 6h, 24h, 48h)
- Análisis de tipos de registro por período

## Notas Importantes

### Permisos de Red
En sistemas Unix (Linux/Mac), necesitas permisos de administrador para capturar paquetes de red. Por eso el capturador debe ejecutarse con `sudo`.

### Interfaz de Red
Si no especificas una interfaz con `-i`, el capturador escuchará en todas las interfaces. Para ver las interfaces disponibles:

```bash
# En Linux
ip addr show

# En Mac
ifconfig
```

### Filtros BPF
Puedes usar filtros BPF personalizados para capturar solo el tráfico que te interese. Ejemplos:

```bash
# Solo UDP en puerto 53
sudo python3 main.py -f "udp port 53"

# Solo TCP en puerto 53
sudo python3 main.py -f "tcp port 53"

# Tráfico desde una IP específica
sudo python3 main.py -f "port 53 and host 192.168.1.100"
```

### Base de Datos SQLite
- La base de datos se crea automáticamente en la primera ejecución
- Por defecto se crea como `dns_monitor.db` en el directorio actual
- Puedes especificar una ruta personalizada con `--db-path`
- Los datos se almacenan de forma persistente en el archivo
- Puedes hacer backup simplemente copiando el archivo `.db`

## Solución de Problemas

### Error: "Permission denied" al capturar paquetes
- Asegúrate de ejecutar con `sudo`
- En algunos sistemas, puede ser necesario configurar capacidades específicas

### Error: "No module named 'scapy'"
- Instala las dependencias: `pip install -r requirements.txt`

### Error: "No such file or directory" al acceder a la base de datos
- Verifica que la ruta especificada con `--db-path` sea correcta
- Asegúrate de que el directorio existe y tienes permisos de escritura

### No se capturan paquetes
- Verifica que haya tráfico DNS en la interfaz seleccionada
- Prueba con `tcpdump -i <interface> port 53` para verificar que hay tráfico
- Asegúrate de que el filtro BPF sea correcto

### El dashboard no muestra datos
- Verifica que el capturador esté ejecutándose y capturando datos
- Asegúrate de que la ruta de la base de datos en el dashboard coincida con la del capturador
- Verifica que el archivo `dns_monitor.db` existe y tiene datos

## Desarrollo

### Estructura de la Base de Datos SQLite

El sistema utiliza una tabla principal `dns_packets` con los siguientes campos:

- `id`: ID único del registro
- `timestamp`: Timestamp de la consulta
- `src_ip`: IP de origen
- `dst_ip`: IP de destino
- `protocol`: Protocolo (TCP/UDP)
- `is_query`: Si es una query (1) o respuesta (0)
- `is_response`: Si es una respuesta (1) o query (0)
- `domain`: Dominio consultado
- `record_type`: Tipo de registro DNS (A, AAAA, MX, etc.)
- `record_type_code`: Código numérico del tipo de registro
- `dns_id`: ID de la consulta DNS
- `opcode`: Opcode DNS
- `rcode`: Código de respuesta (si es respuesta)
- `data_json`: Datos completos del paquete en formato JSON
- `created_at`: Timestamp de creación del registro

La base de datos incluye índices en los campos más consultados para optimizar el rendimiento.

### Limpieza de Datos Antiguos

El cliente SQLite incluye un método `cleanup_old_data(days)` que puedes usar para eliminar datos más antiguos que un número de días especificado. Esto ayuda a mantener el tamaño de la base de datos bajo control.

## Licencia

Este proyecto es de código abierto y está disponible para uso libre.
