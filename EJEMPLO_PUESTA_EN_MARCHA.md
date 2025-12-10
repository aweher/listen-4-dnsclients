# Ejemplo de Puesta en Marcha

Este documento muestra cómo poner en marcha el sistema DNS Monitor paso a paso.

## Escenario: Sniffer fuera de Docker, Redis y ClickHouse en Docker

### 1. Iniciar servicios Docker (Redis y ClickHouse)

```bash
# Opción 1: Usar deploy.sh (recomendado)
sudo ./deploy.sh redis
sudo ./deploy.sh clickhouse

# Opción 2: Usar docker-compose directamente
docker-compose -f docker-compose.redis.yml up -d
docker-compose -f docker-compose.clickhouse.yml up -d
```

### 2. Verificar que los servicios están corriendo

```bash
docker ps
```

Deberías ver:
- `dns-monitor-redis` en el puerto 6379
- `dns-monitor-clickhouse` en los puertos 8123 y 9000

### 3. Configurar config.yaml

**IMPORTANTE:** Cuando el sniffer corre **fuera de Docker** (como servicio systemd), debe usar `localhost` para conectarse a Redis y ClickHouse, no los nombres de los servicios Docker.

Crea o edita `config.yaml`:

```yaml
# Configuración del servidor Redis
redis:
  host: localhost    # ⚠️ IMPORTANTE: usar "localhost" cuando el sniffer corre fuera de Docker
  port: 6379
  db: 0
  password: null

# Configuración del servidor ClickHouse
clickhouse:
  host: localhost    # ⚠️ IMPORTANTE: usar "localhost" cuando el sniffer corre fuera de Docker
  port: 9000         # Puerto nativo de ClickHouse
  database: dns_monitor
  user: default
  password: null

# Configuración del sniffer DNS
sniffer:
  interface: eth1    # Cambiar por tu interfaz de red
  filter: "port 53"

# Configuración de autenticación del dashboard
auth:
  users:
    - username: admin
      password: admin123  # ⚠️ Cambiar en producción
```

### 4. Instalar el sniffer

```bash
sudo ./deploy.sh sniffer
```

Esto:
- Crea un virtualenv en `venv/`
- Instala las dependencias
- Crea el servicio systemd `dns-sniffer.service`
- **NO** habilita el servicio automáticamente

### 5. Habilitar y iniciar el servicio del sniffer

```bash
# Habilitar para que arranque automáticamente al reiniciar
sudo systemctl enable dns-sniffer.service

# Iniciar el servicio
sudo systemctl start dns-sniffer.service

# Verificar el estado
sudo systemctl status dns-sniffer.service
```

### 6. Verificar que funciona correctamente

```bash
# Ver logs del sniffer
sudo journalctl -u dns-sniffer -f

# Deberías ver mensajes como:
# - "Redis conectado exitosamente a localhost:6379"
# - "Conectado a ClickHouse en localhost:9000"
# - "Iniciando captura DNS..."
```

### 7. Iniciar el Dashboard

```bash
# Opción 1: Usar Docker (recomendado)
sudo ./deploy.sh dashboard

# Opción 2: Usar servicio systemd (sin Docker)
sudo ./deploy.sh dashboard  # Genera el servicio
sudo systemctl enable dns-dashboard.service
sudo systemctl start dns-dashboard.service
```

### 8. Acceder al Dashboard

Abre tu navegador en: `http://localhost:8501`

## Solución de Problemas

### Error: "Error -2 connecting to redis:6379. Name or service not known"

**Causa:** El `config.yaml` tiene `host: redis` en lugar de `host: localhost`

**Solución:** Cambiar en `config.yaml`:
```yaml
redis:
  host: localhost  # Cambiar de "redis" a "localhost"
```

### Error: "'Client' object has no attribute 'database'"

**Causa:** Bug en el código (ya corregido en la versión actual)

**Solución:** Asegúrate de tener la última versión del código. Si persiste, reinicia el servicio:
```bash
sudo systemctl restart dns-sniffer.service
```

### El sniffer no captura paquetes

**Verificaciones:**
1. ¿Tienes permisos? El sniffer necesita permisos de root para capturar paquetes
2. ¿La interfaz es correcta? Verifica con `ip addr` o `ifconfig`
3. ¿Hay tráfico DNS? Verifica con `tcpdump -i eth1 port 53`

### ClickHouse no se conecta

**Verificaciones:**
1. ¿ClickHouse está corriendo? `docker ps | grep clickhouse`
2. ¿El puerto es correcto? Debe ser 9000 (nativo), no 8123 (HTTP)
3. ¿Puedes conectarte manualmente?
   ```bash
   docker exec -it dns-monitor-clickhouse clickhouse-client
   ```

## Configuración para Diferentes Escenarios

### Escenario A: Todo en Docker
- Sniffer, Redis, ClickHouse y Dashboard en Docker
- `config.yaml` puede usar nombres de servicios: `host: redis`, `host: clickhouse`

### Escenario B: Sniffer fuera, resto en Docker (Recomendado)
- Sniffer como servicio systemd (mejor rendimiento)
- Redis, ClickHouse y Dashboard en Docker
- `config.yaml` debe usar `host: localhost` para Redis y ClickHouse

### Escenario C: Todo fuera de Docker
- Todo como servicios systemd
- `config.yaml` usa `host: localhost` para todo

## Comandos Útiles

```bash
# Ver estado de todos los servicios
./deploy.sh status

# Ver logs de un servicio específico
./deploy.sh logs sniffer
./deploy.sh logs dashboard

# Detener todos los servicios
./deploy.sh stop

# Reiniciar el sniffer
sudo systemctl restart dns-sniffer.service

# Ver estadísticas del sniffer
sudo journalctl -u dns-sniffer | grep "Total"
```
