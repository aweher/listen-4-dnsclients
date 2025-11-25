# DNS Monitor - Monitor Pasivo de Consultas DNS

> Hecho por Ariel S. Weher <ariel@ayuda.la>

Sistema de monitoreo pasivo de consultas DNS que captura tráfico DNS en tiempo real, almacena estadísticas en Redis y proporciona un dashboard interactivo para visualización.

## Características

- 🔍 **Captura pasiva** de paquetes DNS (TCP y UDP)
- 📊 **Almacenamiento en Redis** con estadísticas agregadas
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
- Redis (instalado y ejecutándose)
- Permisos de administrador para capturar paquetes de red (en Linux/Mac)

## Instalación

1. Clonar o descargar el proyecto

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Asegurarse de que Redis esté ejecutándose:

**Opción A: Usando Docker Compose (recomendado)**
```bash
docker-compose up -d
```

**Opción B: Instalación local**
```bash
# En macOS con Homebrew
brew services start redis

# En Linux
sudo systemctl start redis

# O ejecutar manualmente
redis-server
```

## Uso

### 0. Iniciar Redis con Docker Compose

Si prefieres usar Docker para Redis (recomendado para facilitar el despliegue):

```bash
# Iniciar Redis en segundo plano
docker-compose up -d

# Verificar que Redis está corriendo
docker-compose ps

# Ver logs de Redis
docker-compose logs -f redis

# Detener Redis
docker-compose down

# Detener y eliminar volúmenes (¡elimina todos los datos!)
docker-compose down -v
```

El contenedor de Redis estará disponible en `localhost:6379` y los datos se persisten en un volumen Docker.

### 1. Iniciar el capturador DNS

El capturador debe ejecutarse con permisos de administrador para poder capturar paquetes de red:

```bash
# En Linux/Mac
sudo python3 main.py

# Con opciones personalizadas
sudo python3 main.py -i eth0 --redis-host localhost --redis-port 6379

# Ver todas las opciones
python3 main.py --help
```

**Opciones disponibles:**
- `-i, --interface`: Interfaz de red específica (por defecto: todas)
- `-f, --filter`: Filtro BPF personalizado (por defecto: `port 53`)
- `--redis-host`: Host de Redis (por defecto: `localhost`)
- `--redis-port`: Puerto de Redis (por defecto: `6379`)
- `--redis-db`: Base de datos Redis (por defecto: `0`)
- `--redis-password`: Contraseña de Redis (opcional)
- `--no-redis`: Ejecutar sin Redis (solo mostrar en consola)

### 2. Iniciar el Dashboard

En otra terminal, ejecutar:

```bash
streamlit run dashboard.py
```

El dashboard estará disponible en `http://localhost:8501`

## Estructura del Proyecto

```
detectar-clientes-dns/
├── main.py              # Programa principal del capturador
├── dns_sniffer.py       # Módulo de captura de paquetes DNS
├── redis_client.py      # Cliente Redis para almacenamiento y consultas
├── dashboard.py         # Dashboard Streamlit
├── requirements.txt     # Dependencias Python
├── docker-compose.yml   # Configuración Docker para Redis
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

## Solución de Problemas

### Error: "Permission denied" al capturar paquetes
- Asegúrate de ejecutar con `sudo`
- En algunos sistemas, puede ser necesario configurar capacidades específicas

### Error: "No module named 'scapy'"
- Instala las dependencias: `pip install -r requirements.txt`

### Error: "Connection refused" a Redis
- Verifica que Redis esté ejecutándose: `redis-cli ping`
- Debe responder con `PONG`
- Si usas Docker Compose, verifica que el contenedor esté corriendo: `docker-compose ps`
- Para ver los logs de Redis: `docker-compose logs redis`

### No se capturan paquetes
- Verifica que haya tráfico DNS en la interfaz seleccionada
- Prueba con `tcpdump -i <interface> port 53` para verificar que hay tráfico
- Asegúrate de que el filtro BPF sea correcto

## Desarrollo

### Estructura de Datos en Redis

El sistema almacena datos en Redis con las siguientes claves:

- `dns:packet:<timestamp>`: Paquetes DNS individuales (JSON)
- `dns:client:<ip>:count`: Contador de consultas por IP
- `dns:domain:<domain>:count`: Contador de consultas por dominio
- `dns:type:<type>:count`: Contador por tipo de registro
- `dns:protocol:<protocol>:count`: Contador por protocolo
- `dns:recent`: Sorted set con timestamps de consultas recientes
- `dns:clients:unique`: Set de IPs únicas
- `dns:domains:unique`: Set de dominios únicos
