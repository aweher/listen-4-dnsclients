# Docker para Dashboard DNS Monitor

> Copyright (c) 2025 Ariel S. Weher <ariel@ayuda.la>
> 
> Licensed under the MIT License. See [LICENSE](LICENSE) for details.

Este documento explica cómo ejecutar el dashboard DNS Monitor en un host externo usando Docker.

## Requisitos

- Docker
- Docker Compose (opcional, pero recomendado)

## Opción 1: Usando Docker Compose (Recomendado)

### Configuración inicial

1. **Crear archivo de configuración** (si no existe):
   ```bash
   cp config.yaml.example config.yaml
   ```

2. **Editar `config.yaml`** para configurar:
   - Host de Redis (usar `redis` si Redis está en el mismo docker-compose)
   - Puerto de Redis (6379 por defecto)
   - Contraseña de Redis (si aplica)
   - Usuarios y contraseñas para autenticación del dashboard

   Ejemplo para usar con docker-compose:
   ```yaml
   redis:
     host: redis  # Nombre del servicio en docker-compose
     port: 6379
     db: 0
     password: null
   ```

3. **Construir y ejecutar**:
   ```bash
   docker-compose up -d
   ```

   Esto iniciará tanto Redis como el Dashboard.

4. **Acceder al dashboard**:
   Abre tu navegador en: `http://localhost:8501`

### Configuración con variables de entorno

También puedes configurar Redis usando variables de entorno en `docker-compose.yml`:

```yaml
dashboard:
  environment:
    - REDIS_HOST=redis
    - REDIS_PORT=6379
    - REDIS_PASSWORD=tu_password  # Opcional
```

El script de entrada actualizará automáticamente el `config.yaml` con estos valores.

## Opción 2: Usando Docker directamente

### Construir la imagen

```bash
docker build -f Dockerfile.dashboard -t dns-monitor-dashboard .
```

### Ejecutar el contenedor

```bash
docker run -d \
  --name dns-monitor-dashboard \
  -p 8501:8501 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e REDIS_HOST=tu_servidor_redis \
  -e REDIS_PORT=6379 \
  -e REDIS_PASSWORD=tu_password \
  --restart unless-stopped \
  dns-monitor-dashboard
```

**Nota**: Asegúrate de que el contenedor pueda conectarse al servidor Redis. Si Redis está en otro contenedor, usa `--network` o el nombre del contenedor de Redis.

### Conectar a Redis en otro contenedor

Si Redis está en otro contenedor Docker:

```bash
docker run -d \
  --name dns-monitor-dashboard \
  --network nombre_de_la_red \
  -p 8501:8501 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e REDIS_HOST=nombre_contenedor_redis \
  -e REDIS_PORT=6379 \
  --restart unless-stopped \
  dns-monitor-dashboard
```

## Configuración para host externo

Para ejecutar en un host externo y acceder desde fuera:

1. **Asegúrate de que el puerto 8501 esté abierto** en el firewall del host.

2. **Configura Redis** para que sea accesible:
   - Si Redis está en el mismo host: usa la IP del host o `host.docker.internal` (en Docker Desktop)
   - Si Redis está en otro servidor: usa la IP o hostname del servidor Redis

3. **Ejecuta el contenedor**:
   ```bash
   docker run -d \
     --name dns-monitor-dashboard \
     -p 0.0.0.0:8501:8501 \
     -v $(pwd)/config.yaml:/app/config.yaml \
     -e REDIS_HOST=IP_O_HOSTNAME_REDIS \
     -e REDIS_PORT=6379 \
     --restart unless-stopped \
     dns-monitor-dashboard
   ```

4. **Accede desde cualquier máquina**:
   `http://IP_DEL_HOST:8501`

## Verificar que funciona

```bash
# Ver logs del contenedor
docker logs dns-monitor-dashboard

# Verificar salud del contenedor
docker ps  # Debe mostrar "healthy" en STATUS

# Probar conexión
curl http://localhost:8501/_stcore/health
```

## Detener y eliminar

```bash
# Detener
docker-compose down

# O si usaste docker run directamente
docker stop dns-monitor-dashboard
docker rm dns-monitor-dashboard
```

## Solución de problemas

### El dashboard no se conecta a Redis

1. Verifica que Redis esté ejecutándose y accesible
2. Revisa la configuración en `config.yaml` o variables de entorno
3. Verifica los logs: `docker logs dns-monitor-dashboard`

### Error de permisos en config.yaml

Si montas `config.yaml` como volumen y hay problemas de permisos:
```bash
chmod 644 config.yaml
```

### Puerto ya en uso

Si el puerto 8501 está ocupado, cambia el mapeo:
```yaml
ports:
  - "8502:8501"  # Usa 8502 en el host
```

## Seguridad

⚠️ **Importante para producción**:

1. Cambia las contraseñas por defecto en `config.yaml`
2. Usa HTTPS con un proxy reverso (nginx, traefik, etc.)
3. Configura un firewall adecuado
4. No expongas Redis directamente a internet sin autenticación

