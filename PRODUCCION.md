# Guía de Despliegue en Producción

> Copyright (c) 2025 Ariel S. Weher <ariel@ayuda.la>
> 
> Licensed under the MIT License. See [LICENSE](LICENSE) for details.

Esta guía explica cómo ejecutar el DNS Monitor Dashboard en modo producción.

## Opciones de Ejecución

### 1. Script de Inicio Rápido

El proyecto incluye un script `run_dashboard.sh` que configura automáticamente Streamlit para producción:

```bash
./run_dashboard.sh
```

### 2. Comando Directo

```bash
streamlit run dashboard.py \
    --server.headless=true \
    --server.address=0.0.0.0 \
    --server.port=8501 \
    --browser.gatherUsageStats=false \
    --server.enableXsrfProtection=true
```

### 3. Usando el Archivo de Configuración

El archivo `.streamlit/config.toml` contiene todas las configuraciones de producción. Simplemente ejecuta:

```bash
streamlit run dashboard.py
```

## Configuración del Archivo .streamlit/config.toml

El archivo ya está configurado con valores de producción:

- **headless = true**: No abre el navegador automáticamente
- **address = "0.0.0.0"**: Escucha en todas las interfaces de red
- **enableXsrfProtection = true**: Protección contra ataques XSRF
- **gatherUsageStats = false**: No envía estadísticas de uso

## Ejecutar como Servicio (Linux con systemd)

### 1. Crear el archivo de servicio

Copia `dashboard.service` a `/etc/systemd/system/`:

```bash
sudo cp dashboard.service /etc/systemd/system/dns-dashboard.service
```

### 2. Editar el archivo de servicio

Ajusta las siguientes líneas según tu entorno:

```ini
User=tu_usuario          # Usuario que ejecutará el servicio
Group=tu_grupo           # Grupo del usuario
WorkingDirectory=/ruta/completa/a/detectar-clientes-dns
ExecStart=/ruta/a/streamlit run dashboard.py --server.headless=true --server.address=0.0.0.0 --server.port=8501
```

### 3. Habilitar y iniciar el servicio

```bash
# Recargar systemd
sudo systemctl daemon-reload

# Habilitar el servicio para que inicie automáticamente
sudo systemctl enable dns-dashboard

# Iniciar el servicio
sudo systemctl start dns-dashboard

# Verificar el estado
sudo systemctl status dns-dashboard

# Ver logs
sudo journalctl -u dns-dashboard -f
```

## Usar con Nginx como Proxy Reverso (Recomendado)

### 1. Instalar Nginx

```bash
# Ubuntu/Debian
sudo apt-get install nginx

# CentOS/RHEL
sudo yum install nginx
```

### 2. Configurar Nginx

Crea un archivo de configuración `/etc/nginx/sites-available/dns-dashboard`:

```nginx
server {
    listen 80;
    server_name tu-dominio.com;  # Cambiar por tu dominio

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

### 3. Habilitar el sitio

```bash
# Crear enlace simbólico
sudo ln -s /etc/nginx/sites-available/dns-dashboard /etc/nginx/sites-enabled/

# Verificar configuración
sudo nginx -t

# Recargar Nginx
sudo systemctl reload nginx
```

### 4. Configurar SSL con Let's Encrypt (Opcional pero Recomendado)

```bash
# Instalar Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtener certificado SSL
sudo certbot --nginx -d tu-dominio.com

# El certificado se renovará automáticamente
```

## Variables de Entorno

Puedes configurar variables de entorno para personalizar el comportamiento:

```bash
export STREAMLIT_SERVER_PORT=8501
export STREAMLIT_SERVER_ADDRESS=0.0.0.0
export STREAMLIT_SERVER_HEADLESS=true
export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
export STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true
```

## Seguridad en Producción

### 1. Autenticación

El dashboard ya incluye autenticación básica. Asegúrate de:

- Cambiar las contraseñas por defecto en `config.yaml`
- Usar contraseñas fuertes
- Limitar el acceso por IP si es posible

### 2. Firewall

Configura el firewall para permitir solo el puerto necesario:

```bash
# UFW (Ubuntu)
sudo ufw allow 8501/tcp

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=8501/tcp
sudo firewall-cmd --reload
```

### 3. Usar HTTPS

Siempre usa HTTPS en producción. Configura SSL/TLS con:
- Nginx + Let's Encrypt (gratis)
- O un certificado SSL comercial

### 4. Limitar Acceso por IP

Puedes limitar el acceso en Nginx:

```nginx
location / {
    allow 192.168.1.0/24;  # Permitir solo esta red
    deny all;
    proxy_pass http://127.0.0.1:8501;
    # ... resto de configuración
}
```

## Monitoreo

### Ver logs de Streamlit

```bash
# Si usas systemd
sudo journalctl -u dns-dashboard -f

# Si ejecutas manualmente
# Los logs aparecen en la consola
```

### Verificar que el servicio está corriendo

```bash
# Verificar proceso
ps aux | grep streamlit

# Verificar puerto
netstat -tlnp | grep 8501
# o
ss -tlnp | grep 8501
```

## Solución de Problemas

### El dashboard no inicia

1. Verifica que Redis esté corriendo:
   ```bash
   redis-cli ping
   ```

2. Verifica que el archivo `config.yaml` exista y esté configurado correctamente

3. Verifica los logs:
   ```bash
   sudo journalctl -u dns-dashboard -n 50
   ```

### Error de permisos

Asegúrate de que el usuario que ejecuta el servicio tenga permisos para:
- Leer `config.yaml`
- Acceder a Redis
- Ejecutar Python y Streamlit

### El dashboard no es accesible desde otras máquinas

1. Verifica que `address = "0.0.0.0"` en `.streamlit/config.toml`
2. Verifica el firewall
3. Verifica que no haya otro proceso usando el puerto 8501


