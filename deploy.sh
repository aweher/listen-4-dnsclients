#!/bin/bash
# Copyright (c) 2025 Ariel S. Weher <ariel@ayuda.la>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Script de despliegue modular para DNS Monitor
# Permite instalar componentes por separado o todos juntos

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Función para mostrar ayuda
show_help() {
    cat << EOF
Uso: $0 [OPCIÓN]

Script de despliegue modular para DNS Monitor

OPCIONES:
    redis          Instalar solo Redis
    clickhouse     Instalar solo ClickHouse
    dashboard      Instalar solo Dashboard (requiere Redis y ClickHouse)
    sniffer        Instalar solo Sniffer (crea virtualenv e instala dependencias)
    all            Instalar todos los componentes (Redis, ClickHouse, Dashboard y Sniffer)
    stop           Detener todos los servicios
    restart        Reiniciar todos los servicios
    status         Mostrar estado de los servicios
    logs           Mostrar logs de los servicios
    clean          Eliminar contenedores y volúmenes (¡CUIDADO: elimina datos!)
    help           Mostrar esta ayuda

EJEMPLOS:
    $0 redis              # Instalar solo Redis
    $0 clickhouse         # Instalar solo ClickHouse
    $0 sniffer            # Instalar solo Sniffer
    $0 all                # Instalar todos los componentes
    $0 stop               # Detener todos los servicios
    $0 logs               # Ver logs de todos los servicios

EOF
}

# Función para verificar dependencias
check_dependencies() {
    info "Verificando dependencias..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker no está instalado. Por favor, instala Docker primero."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error "Docker Compose no está instalado. Por favor, instala Docker Compose primero."
        exit 1
    fi
    
    # Detectar si usar docker-compose o docker compose
    if docker compose version &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
    else
        DOCKER_COMPOSE_CMD="docker-compose"
    fi
    
    success "Dependencias verificadas"
}

# Función para verificar dependencias de Python
check_python_dependencies() {
    info "Verificando dependencias de Python..."
    
    if ! command -v python3 &> /dev/null; then
        error "Python 3 no está instalado. Por favor, instala Python 3 primero."
        exit 1
    fi
    
    local python_version=$(python3 --version 2>&1 | awk '{print $2}')
    info "Python versión: $python_version"
    
    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        error "pip3 no está instalado. Por favor, instala pip3 primero."
        exit 1
    fi
    
    success "Dependencias de Python verificadas"
}

# Función para crear directorios de datos
create_data_directories() {
    info "Creando directorios para persistencia de datos..."
    
    mkdir -p data/redis
    mkdir -p data/clickhouse
    mkdir -p data/clickhouse-logs
    
    success "Directorios creados"
}

# Función para verificar y crear config.yaml si es necesario
check_and_create_config() {
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local config_file="$project_dir/config.yaml"
    local config_example="$project_dir/config.yaml.example"
    
    if [ ! -f "$config_file" ]; then
        warning "El archivo config.yaml no existe."
        
        if [ -f "$config_example" ]; then
            echo ""
            info "Se encontró config.yaml.example. Puedes crear config.yaml desde este archivo."
            read -p "¿Deseas crear config.yaml desde config.yaml.example? (s/n): " create_config
            echo ""
            
            # Normalizar respuesta (aceptar s, S, si, Si, SI, y, Y, yes, Yes, YES)
            create_config=$(echo "$create_config" | tr '[:upper:]' '[:lower:]')
            if [ "$create_config" = "s" ] || [ "$create_config" = "si" ] || [ "$create_config" = "y" ] || [ "$create_config" = "yes" ]; then
                info "Copiando config.yaml.example a config.yaml..."
                cp "$config_example" "$config_file"
                success "Archivo config.yaml creado"
                warning "Por favor, edita config.yaml con tus configuraciones antes de continuar."
                info "Puedes editarlo con: nano $config_file"
                return 0
            else
                warning "No se creó config.yaml."
                info "Debes crear config.yaml manualmente antes de continuar."
                info "Puedes copiarlo manualmente con: cp $config_example $config_file"
                return 1
            fi
        else
            error "No se encontró config.yaml ni config.yaml.example"
            error "No se puede continuar sin un archivo de configuración."
            return 1
        fi
    fi
    
    return 0
}

# Función para instalar Redis
install_redis() {
    info "Instalando Redis..."
    check_dependencies
    create_data_directories
    
    $DOCKER_COMPOSE_CMD -f docker-compose.redis.yml up -d
    
    info "Esperando a que Redis esté listo..."
    sleep 5
    
    if docker exec dns-monitor-redis redis-cli ping &> /dev/null; then
        success "Redis instalado y funcionando correctamente"
        info "Redis está disponible en localhost:6379"
    else
        warning "Redis se inició pero no responde aún. Puede tardar unos segundos más."
    fi
}

# Función para instalar ClickHouse
install_clickhouse() {
    info "Instalando ClickHouse..."
    check_dependencies
    create_data_directories
    
    $DOCKER_COMPOSE_CMD -f docker-compose.clickhouse.yml up -d
    
    info "Esperando a que ClickHouse esté listo..."
    sleep 10
    
    # Verificar que ClickHouse esté respondiendo
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:8123/ping &> /dev/null; then
            success "ClickHouse instalado y funcionando correctamente"
            info "ClickHouse HTTP está disponible en localhost:8123"
            info "ClickHouse Native está disponible en localhost:9000"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    warning "ClickHouse se inició pero no responde aún. Puede tardar más tiempo."
    info "Verifica los logs con: $0 logs clickhouse"
}

# Función para instalar Dashboard
install_dashboard() {
    info "Instalando Dashboard..."
    check_dependencies
    
    # Verificar que config.yaml existe (necesario para el dashboard)
    if ! check_and_create_config; then
        error "No se puede continuar sin config.yaml"
        exit 1
    fi
    
    # Verificar que Redis y ClickHouse estén corriendo
    if ! docker ps | grep -q dns-monitor-redis; then
        error "Redis no está corriendo. Ejecuta '$0 redis' primero."
        exit 1
    fi
    
    if ! docker ps | grep -q dns-monitor-clickhouse; then
        error "ClickHouse no está corriendo. Ejecuta '$0 clickhouse' primero."
        exit 1
    fi
    
    $DOCKER_COMPOSE_CMD -f docker-compose.yml up -d dashboard
    
    info "Esperando a que Dashboard esté listo..."
    sleep 5
    
    success "Dashboard instalado y funcionando correctamente (Docker)"
    info "Dashboard está disponible en http://localhost:8501"
    
    # Generar también el servicio systemd para ejecución sin Docker
    info "Generando servicio systemd para dashboard..."
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local service_file="$project_dir/dashboard.service"
    local systemd_service="/etc/systemd/system/dns-dashboard.service"
    
    # Detectar ruta de streamlit
    local streamlit_path
    if command -v streamlit &> /dev/null; then
        streamlit_path=$(command -v streamlit)
    elif command -v python3 &> /dev/null && python3 -c "import streamlit" 2>/dev/null; then
        # Si streamlit está instalado pero no en PATH, usar python3 -m streamlit
        streamlit_path="python3 -m streamlit"
    else
        # Si no se encuentra, usar el comando genérico (se intentará instalar o dará error)
        streamlit_path="streamlit"
        warning "Streamlit no encontrado. Asegúrate de tener Streamlit instalado."
        warning "Puedes instalarlo con: pip3 install streamlit"
    fi
    
    # Detectar usuario y grupo actual
    local current_user="${SUDO_USER:-$USER}"
    local current_group=$(id -gn "$current_user" 2>/dev/null || echo "$current_user")
    
    # Si no se puede determinar el grupo, usar el mismo que el usuario
    if [ -z "$current_group" ]; then
        current_group="$current_user"
    fi
    
    # Determinar PATH para el servicio (incluir venv si existe)
    local service_path="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
    if [ -d "$project_dir/venv/bin" ]; then
        service_path="$project_dir/venv/bin:$service_path"
    fi
    
    # Crear el archivo de servicio
    cat > "$service_file" << EOF
[Unit]
Description=DNS Monitor Dashboard (Streamlit)
After=network.target redis.service
Wants=network-online.target

[Service]
Type=simple
User=$current_user
Group=$current_group
WorkingDirectory=$project_dir
Environment="PATH=$service_path"
ExecStart=$streamlit_path run $project_dir/dashboard.py --server.headless=true --server.address=0.0.0.0 --server.port=8501 --browser.gatherUsageStats=false --server.enableXsrfProtection=true
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dns-dashboard

[Install]
WantedBy=multi-user.target
EOF
    
    success "Archivo de servicio creado: $service_file"
    
    # Copiar a systemd (requiere sudo)
    if [ "$EUID" -eq 0 ]; then
        info "Copiando servicio a systemd..."
        if [ -f "$systemd_service" ]; then
            warning "El servicio ya existe en systemd. Actualizándolo..."
        fi
        cp "$service_file" "$systemd_service"
        chmod 644 "$systemd_service"
        success "Servicio copiado a $systemd_service"
        
        info "Recargando systemd..."
        systemctl daemon-reload
        success "Systemd recargado"
    else
        if [ -f "$systemd_service" ]; then
            info "El servicio ya está instalado en systemd."
        else
            warning "Se requieren permisos de administrador para instalar el servicio systemd."
            info "Ejecuta los siguientes comandos con sudo:"
            echo ""
            echo "  sudo cp $service_file $systemd_service"
            echo "  sudo chmod 644 $systemd_service"
            echo "  sudo systemctl daemon-reload"
            echo ""
        fi
    fi
    
    if [ -f "$systemd_service" ]; then
        info "Servicio systemd instalado: dns-dashboard.service"
        info ""
        warning "El servicio NO está habilitado para arrancar automáticamente."
        info "Para habilitar el arranque automático, ejecuta:"
        info "  sudo systemctl enable dns-dashboard.service"
        info ""
        info "Comandos útiles del servicio:"
        info "  sudo systemctl start dns-dashboard    # Iniciar el servicio"
        info "  sudo systemctl stop dns-dashboard     # Detener el servicio"
        info "  sudo systemctl status dns-dashboard   # Ver estado"
        info "  sudo journalctl -u dns-dashboard -f   # Ver logs en tiempo real"
        info ""
        info "NOTA: El servicio systemd ejecuta el dashboard directamente (sin Docker)."
        info "      Asegúrate de tener Python y Streamlit instalados en el sistema."
    else
        info "Servicio systemd preparado en: $service_file"
        info ""
        info "Para instalar el servicio systemd, ejecuta:"
        echo ""
        echo "  sudo cp $service_file $systemd_service"
        echo "  sudo chmod 644 $systemd_service"
        echo "  sudo systemctl daemon-reload"
        echo ""
        info "Después de instalarlo, para habilitar el arranque automático:"
        info "  sudo systemctl enable dns-dashboard.service"
    fi
}

# Función para instalar Sniffer
install_sniffer() {
    info "Instalando Sniffer..."
    check_python_dependencies
    
    # Obtener el directorio del script (directorio del proyecto)
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local venv_dir="$project_dir/venv"
    
    # Verificar que main.py existe
    if [ ! -f "$project_dir/main.py" ]; then
        error "El archivo main.py no existe en el directorio del proyecto."
        exit 1
    fi
    
    # Verificar que requirements.txt existe
    if [ ! -f "$project_dir/requirements.txt" ]; then
        error "El archivo requirements.txt no existe en el directorio del proyecto."
        exit 1
    fi
    
    # Crear directorio venv si no existe
    if [ ! -d "$venv_dir" ]; then
        info "Creando virtualenv en $venv_dir..."
        if command -v python3 &> /dev/null; then
            python3 -m venv "$venv_dir"
        else
            error "No se pudo crear el virtualenv. Python3 no está disponible."
            exit 1
        fi
        
        if [ $? -eq 0 ]; then
            success "Virtualenv creado en $venv_dir"
        else
            error "Error al crear el virtualenv"
            exit 1
        fi
    else
        info "Virtualenv ya existe en $venv_dir"
    fi
    
    # Activar virtualenv e instalar dependencias
    info "Instalando dependencias de Python en el virtualenv..."
    
    # Verificar que el virtualenv tenga pip
    if [ ! -f "$venv_dir/bin/pip" ] && [ ! -f "$venv_dir/bin/pip3" ]; then
        info "Actualizando pip en el virtualenv..."
        if [ -f "$venv_dir/bin/python3" ]; then
            "$venv_dir/bin/python3" -m ensurepip --upgrade || "$venv_dir/bin/python3" -m pip install --upgrade pip
        fi
    fi
    
    # Determinar el comando pip del virtualenv
    local venv_pip
    if [ -f "$venv_dir/bin/pip3" ]; then
        venv_pip="$venv_dir/bin/pip3"
    elif [ -f "$venv_dir/bin/pip" ]; then
        venv_pip="$venv_dir/bin/pip"
    else
        error "No se encontró pip en el virtualenv"
        exit 1
    fi
    
    # Instalar requerimientos
    "$venv_pip" install --upgrade pip
    "$venv_pip" install -r "$project_dir/requirements.txt"
    
    if [ $? -eq 0 ]; then
        success "Dependencias de Python instaladas correctamente en el virtualenv"
    else
        error "Error al instalar dependencias de Python"
        exit 1
    fi
    
    # Verificar que config.yaml existe
    if ! check_and_create_config; then
        error "No se puede continuar sin config.yaml"
        exit 1
    fi
    
    # Verificar que el virtualenv funciona correctamente
    info "Verificando que el virtualenv funciona..."
    local venv_python="$venv_dir/bin/python3"
    
    if [ ! -f "$venv_python" ]; then
        error "Python del virtualenv no encontrado en $venv_python"
        exit 1
    fi
    
    # Verificar que puede importar los módulos principales
    info "Verificando que los módulos se pueden importar..."
    if ! "$venv_python" -c "import sys; sys.path.insert(0, '$project_dir'); from dns_sniffer import DNSSniffer; from redis_client import DNSRedisClient; from clickhouse_client import DNSClickHouseClient; print('OK')" 2>/dev/null; then
        warning "No se pudieron importar todos los módulos. Esto puede ser normal si faltan dependencias del sistema."
        warning "Continuando con la instalación del servicio systemd..."
    else
        success "Módulos verificados correctamente"
    fi
    
    # Verificar que el script se puede ejecutar (al menos verificar sintaxis)
    info "Verificando sintaxis del script principal..."
    if ! "$venv_python" -m py_compile "$project_dir/main.py" 2>/dev/null; then
        warning "Advertencia al verificar sintaxis de main.py, pero continuando..."
    else
        success "Sintaxis del script verificada"
    fi
    
    # Crear script wrapper para ejecutar el sniffer fácilmente
    local sniffer_script="$project_dir/run_sniffer.sh"
    if [ ! -f "$sniffer_script" ]; then
        info "Creando script wrapper run_sniffer.sh..."
        cat > "$sniffer_script" << 'EOFWRAPPER'
#!/bin/bash
# Script wrapper para ejecutar el sniffer usando el virtualenv

# Obtener el directorio del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python3"

# Verificar que el virtualenv existe
if [ ! -f "$PYTHON_BIN" ]; then
    echo "Error: Virtualenv no encontrado. Ejecuta './deploy.sh sniffer' primero."
    exit 1
fi

# Ejecutar el sniffer con el Python del virtualenv
cd "$SCRIPT_DIR"
exec "$PYTHON_BIN" main.py "$@"
EOFWRAPPER
        chmod +x "$sniffer_script"
        success "Script wrapper creado: $sniffer_script"
    fi
    
    # Crear servicio systemd
    info "Creando servicio systemd..."
    local service_file="$project_dir/dns-sniffer.service"
    local systemd_service="/etc/systemd/system/dns-sniffer.service"
    
    # Obtener el usuario actual (para el servicio, aunque necesitará root para capturar paquetes)
    local current_user="${SUDO_USER:-$USER}"
    local current_group=$(id -gn "$current_user" 2>/dev/null || echo "$current_user")
    
    # Crear el archivo de servicio
    cat > "$service_file" << EOF
[Unit]
Description=DNS Monitor Sniffer
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$project_dir
Environment="PATH=$venv_dir/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$venv_python $project_dir/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dns-sniffer

# Seguridad: limitar capacidades
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    
    success "Archivo de servicio creado: $service_file"
    
    # Copiar a systemd (requiere sudo)
    if [ "$EUID" -eq 0 ]; then
        info "Copiando servicio a systemd..."
        if [ -f "$systemd_service" ]; then
            warning "El servicio ya existe en systemd. Actualizándolo..."
        fi
        cp "$service_file" "$systemd_service"
        chmod 644 "$systemd_service"
        success "Servicio copiado a $systemd_service"
        
        info "Recargando systemd..."
        systemctl daemon-reload
        success "Systemd recargado"
    else
        if [ -f "$systemd_service" ]; then
            info "El servicio ya está instalado en systemd."
        else
            warning "Se requieren permisos de administrador para instalar el servicio systemd."
            info "Ejecuta los siguientes comandos con sudo:"
            echo ""
            echo "  sudo cp $service_file $systemd_service"
            echo "  sudo chmod 644 $systemd_service"
            echo "  sudo systemctl daemon-reload"
            echo ""
        fi
    fi
    
    success "Sniffer instalado correctamente"
    info "Virtualenv ubicado en: $venv_dir"
    info ""
    info "Para ejecutar el sniffer, usa una de estas opciones:"
    info "  1. Script wrapper: sudo ./run_sniffer.sh"
    info "  2. Directamente:   sudo $venv_dir/bin/python3 main.py"
    info "  3. Activar venv:   source $venv_dir/bin/activate && sudo python3 main.py"
    info ""
    
    if [ -f "$systemd_service" ]; then
        info "Servicio systemd instalado: dns-sniffer.service"
        info ""
        warning "El servicio NO está habilitado para arrancar automáticamente."
        info "Para habilitar el arranque automático, ejecuta:"
        info "  sudo systemctl enable dns-sniffer.service"
        info ""
        info "Comandos útiles del servicio:"
        info "  sudo systemctl start dns-sniffer    # Iniciar el servicio"
        info "  sudo systemctl stop dns-sniffer     # Detener el servicio"
        info "  sudo systemctl status dns-sniffer   # Ver estado"
        info "  sudo journalctl -u dns-sniffer -f   # Ver logs en tiempo real"
    else
        info "Servicio systemd preparado en: $service_file"
        info ""
        info "Para instalar el servicio systemd, ejecuta:"
        echo ""
        echo "  sudo cp $service_file $systemd_service"
        echo "  sudo chmod 644 $systemd_service"
        echo "  sudo systemctl daemon-reload"
        echo ""
        info "Después de instalarlo, para habilitar el arranque automático:"
        info "  sudo systemctl enable dns-sniffer.service"
    fi
    
    info ""
    info "NOTA: El sniffer requiere permisos de administrador para capturar paquetes de red."
}

# Función para instalar todos los componentes
install_all() {
    info "Instalando todos los componentes..."
    check_dependencies
    create_data_directories
    
    # Verificar que config.yaml existe (necesario para dashboard y sniffer)
    if ! check_and_create_config; then
        error "No se puede continuar sin config.yaml"
        exit 1
    fi
    
    # Instalar servicios Docker (Redis, ClickHouse, Dashboard)
    $DOCKER_COMPOSE_CMD -f docker-compose.yml up -d
    
    info "Esperando a que los servicios estén listos..."
    sleep 10
    
    # Verificar servicios Docker
    local redis_ok=false
    local clickhouse_ok=false
    
    if docker exec dns-monitor-redis redis-cli ping &> /dev/null; then
        redis_ok=true
        success "Redis está funcionando"
    else
        warning "Redis puede tardar más en estar listo"
    fi
    
    if curl -s http://localhost:8123/ping &> /dev/null; then
        clickhouse_ok=true
        success "ClickHouse está funcionando"
    else
        warning "ClickHouse puede tardar más en estar listo"
    fi
    
    # Instalar sniffer (fuera de Docker)
    info ""
    info "Instalando sniffer..."
    check_python_dependencies
    
    # Obtener el directorio del script (directorio del proyecto)
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local venv_dir="$project_dir/venv"
    
    # Verificar que main.py existe
    if [ ! -f "$project_dir/main.py" ]; then
        error "El archivo main.py no existe en el directorio del proyecto."
        exit 1
    fi
    
    # Verificar que requirements.txt existe
    if [ ! -f "$project_dir/requirements.txt" ]; then
        error "El archivo requirements.txt no existe en el directorio del proyecto."
        exit 1
    fi
    
    # Crear directorio venv si no existe
    if [ ! -d "$venv_dir" ]; then
        info "Creando virtualenv en $venv_dir..."
        if command -v python3 &> /dev/null; then
            python3 -m venv "$venv_dir"
        else
            error "No se pudo crear el virtualenv. Python3 no está disponible."
            exit 1
        fi
        
        if [ $? -eq 0 ]; then
            success "Virtualenv creado en $venv_dir"
        else
            error "Error al crear el virtualenv"
            exit 1
        fi
    else
        info "Virtualenv ya existe en $venv_dir"
    fi
    
    # Instalar dependencias en el virtualenv
    info "Instalando dependencias de Python en el virtualenv..."
    
    # Verificar que el virtualenv tenga pip
    if [ ! -f "$venv_dir/bin/pip" ] && [ ! -f "$venv_dir/bin/pip3" ]; then
        info "Actualizando pip en el virtualenv..."
        if [ -f "$venv_dir/bin/python3" ]; then
            "$venv_dir/bin/python3" -m ensurepip --upgrade || "$venv_dir/bin/python3" -m pip install --upgrade pip
        fi
    fi
    
    # Determinar el comando pip del virtualenv
    local venv_pip
    if [ -f "$venv_dir/bin/pip3" ]; then
        venv_pip="$venv_dir/bin/pip3"
    elif [ -f "$venv_dir/bin/pip" ]; then
        venv_pip="$venv_dir/bin/pip"
    else
        error "No se encontró pip en el virtualenv"
        exit 1
    fi
    
    # Instalar requerimientos
    "$venv_pip" install --upgrade pip
    "$venv_pip" install -r "$project_dir/requirements.txt"
    
    if [ $? -eq 0 ]; then
        success "Dependencias de Python instaladas correctamente en el virtualenv"
    else
        error "Error al instalar dependencias de Python"
        exit 1
    fi
    
    # Verificar que el virtualenv funciona correctamente
    info "Verificando que el virtualenv funciona..."
    local venv_python="$venv_dir/bin/python3"
    
    if [ ! -f "$venv_python" ]; then
        error "Python del virtualenv no encontrado en $venv_python"
        exit 1
    fi
    
    # Verificar que puede importar los módulos principales
    info "Verificando que los módulos se pueden importar..."
    if ! "$venv_python" -c "import sys; sys.path.insert(0, '$project_dir'); from dns_sniffer import DNSSniffer; from redis_client import DNSRedisClient; from clickhouse_client import DNSClickHouseClient; print('OK')" 2>/dev/null; then
        warning "No se pudieron importar todos los módulos. Esto puede ser normal si faltan dependencias del sistema."
        warning "Continuando con la instalación del servicio systemd..."
    else
        success "Módulos verificados correctamente"
    fi
    
    # Verificar que el script se puede ejecutar (al menos verificar sintaxis)
    info "Verificando sintaxis del script principal..."
    if ! "$venv_python" -m py_compile "$project_dir/main.py" 2>/dev/null; then
        warning "Advertencia al verificar sintaxis de main.py, pero continuando..."
    else
        success "Sintaxis del script verificada"
    fi
    
    # Crear script wrapper para ejecutar el sniffer fácilmente
    local sniffer_script="$project_dir/run_sniffer.sh"
    if [ ! -f "$sniffer_script" ]; then
        info "Creando script wrapper run_sniffer.sh..."
        cat > "$sniffer_script" << 'EOFWRAPPER'
#!/bin/bash
# Script wrapper para ejecutar el sniffer usando el virtualenv

# Obtener el directorio del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python3"

# Verificar que el virtualenv existe
if [ ! -f "$PYTHON_BIN" ]; then
    echo "Error: Virtualenv no encontrado. Ejecuta './deploy.sh sniffer' primero."
    exit 1
fi

# Ejecutar el sniffer con el Python del virtualenv
cd "$SCRIPT_DIR"
exec "$PYTHON_BIN" main.py "$@"
EOFWRAPPER
        chmod +x "$sniffer_script"
        success "Script wrapper creado: $sniffer_script"
    fi
    
    # Crear servicio systemd para el sniffer
    info "Creando servicio systemd para sniffer..."
    local service_file="$project_dir/dns-sniffer.service"
    local systemd_service="/etc/systemd/system/dns-sniffer.service"
    
    # Crear el archivo de servicio
    cat > "$service_file" << EOF
[Unit]
Description=DNS Monitor Sniffer
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$project_dir
Environment="PATH=$venv_dir/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$venv_python $project_dir/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dns-sniffer

# Seguridad: limitar capacidades
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    
    success "Archivo de servicio creado: $service_file"
    
    # Copiar a systemd (requiere sudo)
    if [ "$EUID" -eq 0 ]; then
        info "Copiando servicio a systemd..."
        if [ -f "$systemd_service" ]; then
            warning "El servicio ya existe en systemd. Actualizándolo..."
        fi
        cp "$service_file" "$systemd_service"
        chmod 644 "$systemd_service"
        success "Servicio copiado a $systemd_service"
        
        info "Recargando systemd..."
        systemctl daemon-reload
        success "Systemd recargado"
    else
        if [ -f "$systemd_service" ]; then
            info "El servicio ya está instalado en systemd."
        else
            warning "Se requieren permisos de administrador para instalar el servicio systemd."
            info "Ejecuta los siguientes comandos con sudo:"
            echo ""
            echo "  sudo cp $service_file $systemd_service"
            echo "  sudo chmod 644 $systemd_service"
            echo "  sudo systemctl daemon-reload"
            echo ""
        fi
    fi
    
    success "Todos los componentes han sido iniciados"
    info ""
    info "Servicios Docker:"
    info "  Redis está disponible en localhost:6379"
    info "  ClickHouse HTTP está disponible en localhost:8123"
    info "  ClickHouse Native está disponible en localhost:9000"
    info "  Dashboard está disponible en http://localhost:8501"
    info ""
    info "Sniffer:"
    info "  Virtualenv ubicado en: $venv_dir"
    if [ -f "$systemd_service" ]; then
        info "  Servicio systemd instalado: dns-sniffer.service"
        warning "  El servicio NO está habilitado para arrancar automáticamente."
        info "  Para habilitar: sudo systemctl enable dns-sniffer.service"
        info "  Para iniciar: sudo systemctl start dns-sniffer"
    else
        info "  Servicio systemd preparado en: $service_file"
        info "  Para instalar: sudo cp $service_file $systemd_service && sudo systemctl daemon-reload"
    fi
}

# Función para detener servicios
stop_services() {
    info "Deteniendo servicios..."
    
    # Detener servicios Docker
    if [ -f docker-compose.yml ]; then
        $DOCKER_COMPOSE_CMD -f docker-compose.yml down 2>/dev/null || true
    fi
    if [ -f docker-compose.redis.yml ]; then
        $DOCKER_COMPOSE_CMD -f docker-compose.redis.yml down 2>/dev/null || true
    fi
    if [ -f docker-compose.clickhouse.yml ]; then
        $DOCKER_COMPOSE_CMD -f docker-compose.clickhouse.yml down 2>/dev/null || true
    fi
    
    # Detener servicio systemd del dashboard si existe y está corriendo
    if systemctl is-active --quiet dns-dashboard.service 2>/dev/null; then
        info "Deteniendo servicio systemd dns-dashboard..."
        if [ "$EUID" -eq 0 ]; then
            systemctl stop dns-dashboard.service
            success "Servicio systemd del dashboard detenido"
        else
            warning "Se requieren permisos de administrador para detener el servicio systemd."
            info "Ejecuta: sudo systemctl stop dns-dashboard.service"
        fi
    fi
    
    # Detener sniffer si está corriendo
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Detener servicio systemd si existe y está corriendo
    if systemctl is-active --quiet dns-sniffer.service 2>/dev/null; then
        info "Deteniendo servicio systemd dns-sniffer..."
        if [ "$EUID" -eq 0 ]; then
            systemctl stop dns-sniffer.service
            success "Servicio systemd detenido"
        else
            warning "Se requieren permisos de administrador para detener el servicio systemd."
            info "Ejecuta: sudo systemctl stop dns-sniffer.service"
        fi
    fi
    
    # Detener procesos manuales del sniffer
    if pgrep -f "python3.*main.py" > /dev/null || pgrep -f "$project_dir/venv/bin/python3.*main.py" > /dev/null || pgrep -f "run_sniffer.sh" > /dev/null; then
        info "Deteniendo procesos del sniffer..."
        pkill -f "python3.*main.py" || true
        pkill -f "$project_dir/venv/bin/python3.*main.py" || true
        pkill -f "run_sniffer.sh" || true
        sleep 2
        if pgrep -f "python3.*main.py" > /dev/null || pgrep -f "$project_dir/venv/bin/python3.*main.py" > /dev/null || pgrep -f "run_sniffer.sh" > /dev/null; then
            warning "Algunos procesos del sniffer no se detuvieron automáticamente. Puede requerir permisos de administrador."
        else
            success "Procesos del sniffer detenidos"
        fi
    fi
    
    success "Servicios detenidos"
}

# Función para reiniciar servicios
restart_services() {
    info "Reiniciando servicios..."
    stop_services
    sleep 2
    install_all
}

# Función para mostrar estado
show_status() {
    info "Estado de los servicios:"
    echo ""
    
    # Mostrar servicios Docker
    if docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "dns-monitor|NAMES"; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "dns-monitor|NAMES"
    else
        warning "No hay servicios Docker DNS Monitor corriendo"
    fi
    
    echo ""
    # Mostrar estado del dashboard (systemd)
    if systemctl list-unit-files | grep -q "dns-dashboard.service"; then
        if systemctl is-active --quiet dns-dashboard.service 2>/dev/null; then
            success "Dashboard (systemd): ACTIVO"
            if [ "$EUID" -eq 0 ]; then
                systemctl status dns-dashboard.service --no-pager -l | head -n 5
            else
                info "  Ejecuta 'sudo systemctl status dns-dashboard' para más detalles"
            fi
        elif systemctl is-enabled --quiet dns-dashboard.service 2>/dev/null; then
            warning "Dashboard (systemd): HABILITADO pero no corriendo"
            info "  Ejecuta 'sudo systemctl start dns-dashboard' para iniciarlo"
        else
            info "Dashboard (systemd): Servicio disponible pero no habilitado"
            info "  Ejecuta 'sudo systemctl enable dns-dashboard' para habilitar arranque automático"
        fi
    fi
    
    echo ""
    # Mostrar estado del sniffer
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Verificar servicio systemd
    if systemctl list-unit-files | grep -q "dns-sniffer.service"; then
        if systemctl is-active --quiet dns-sniffer.service 2>/dev/null; then
            success "Sniffer (systemd): ACTIVO"
            if [ "$EUID" -eq 0 ]; then
                systemctl status dns-sniffer.service --no-pager -l | head -n 5
            else
                info "  Ejecuta 'sudo systemctl status dns-sniffer' para más detalles"
            fi
        elif systemctl is-enabled --quiet dns-sniffer.service 2>/dev/null; then
            warning "Sniffer (systemd): HABILITADO pero no corriendo"
            info "  Ejecuta 'sudo systemctl start dns-sniffer' para iniciarlo"
        else
            info "Sniffer (systemd): Servicio disponible pero no habilitado"
            info "  Ejecuta 'sudo systemctl enable dns-sniffer' para habilitar arranque automático"
        fi
    fi
    
    # Verificar procesos manuales
    local sniffer_pid=$(pgrep -f "python3.*main.py" | head -n1)
    if [ -z "$sniffer_pid" ]; then
        sniffer_pid=$(pgrep -f "$project_dir/venv/bin/python3.*main.py" | head -n1)
    fi
    if [ -z "$sniffer_pid" ]; then
        sniffer_pid=$(pgrep -f "run_sniffer.sh" | head -n1)
    fi
    
    if [ -n "$sniffer_pid" ]; then
        success "Sniffer (proceso manual) está corriendo (PID: $sniffer_pid)"
    elif ! systemctl is-active --quiet dns-sniffer.service 2>/dev/null; then
        warning "Sniffer no está corriendo"
    fi
    
    if [ -d "$project_dir/venv" ]; then
        info "  Virtualenv: $project_dir/venv"
    fi
}

# Función para mostrar logs
show_logs() {
    local service=${1:-""}
    
    if [ -z "$service" ]; then
        info "Mostrando logs de todos los servicios (Ctrl+C para salir)..."
        $DOCKER_COMPOSE_CMD -f docker-compose.yml logs -f 2>/dev/null || \
        (docker logs -f dns-monitor-redis & docker logs -f dns-monitor-clickhouse & docker logs -f dns-monitor-dashboard & wait)
    else
        case $service in
            redis)
                docker logs -f dns-monitor-redis
                ;;
            clickhouse)
                docker logs -f dns-monitor-clickhouse
                ;;
            dashboard)
                # Si está corriendo como servicio systemd, mostrar logs del journal
                if systemctl is-active --quiet dns-dashboard.service 2>/dev/null; then
                    info "Mostrando logs del servicio systemd dns-dashboard (Ctrl+C para salir)..."
                    if [ "$EUID" -eq 0 ]; then
                        journalctl -u dns-dashboard.service -f
                    else
                        warning "Se requieren permisos de administrador para ver logs del servicio systemd."
                        info "Ejecuta: sudo journalctl -u dns-dashboard.service -f"
                    fi
                elif docker ps | grep -q dns-monitor-dashboard; then
                    # Si está corriendo en Docker, mostrar logs de Docker
                    docker logs -f dns-monitor-dashboard
                else
                    warning "El dashboard no está corriendo"
                    if systemctl list-unit-files | grep -q "dns-dashboard.service"; then
                        info "Para iniciar el servicio: sudo systemctl start dns-dashboard"
                    elif docker ps -a | grep -q dns-monitor-dashboard; then
                        info "Para iniciar en Docker: docker start dns-monitor-dashboard"
                    else
                        info "Para iniciar: ./deploy.sh dashboard"
                    fi
                fi
                ;;
            sniffer)
                local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
                
                # Si está corriendo como servicio systemd, mostrar logs del journal
                if systemctl is-active --quiet dns-sniffer.service 2>/dev/null; then
                    info "Mostrando logs del servicio systemd dns-sniffer (Ctrl+C para salir)..."
                    if [ "$EUID" -eq 0 ]; then
                        journalctl -u dns-sniffer.service -f
                    else
                        warning "Se requieren permisos de administrador para ver logs del servicio systemd."
                        info "Ejecuta: sudo journalctl -u dns-sniffer.service -f"
                    fi
                elif pgrep -f "python3.*main.py" > /dev/null || pgrep -f "$project_dir/venv/bin/python3.*main.py" > /dev/null || pgrep -f "run_sniffer.sh" > /dev/null; then
                    info "El sniffer está corriendo como proceso manual."
                    warning "Los logs están en la terminal donde se ejecutó."
                    info "Para ver logs del servicio systemd (si está instalado):"
                    info "  sudo journalctl -u dns-sniffer.service -f"
                    info "Para ejecutar en foreground y ver logs: sudo ./run_sniffer.sh"
                else
                    warning "El sniffer no está corriendo"
                    if systemctl list-unit-files | grep -q "dns-sniffer.service"; then
                        info "Para iniciar el servicio: sudo systemctl start dns-sniffer"
                    else
                        info "Para ejecutarlo: sudo ./run_sniffer.sh"
                    fi
                fi
                ;;
            *)
                error "Servicio desconocido: $service"
                info "Servicios disponibles: redis, clickhouse, dashboard, sniffer"
                exit 1
                ;;
        esac
    fi
}

# Función para limpiar (eliminar contenedores y volúmenes)
clean_all() {
    warning "¡ATENCIÓN! Esta operación eliminará todos los contenedores y volúmenes."
    warning "Esto incluye TODOS LOS DATOS almacenados en Redis y ClickHouse."
    read -p "¿Estás seguro de que quieres continuar? (escribe 'si' para confirmar): " confirm
    
    if [ "$confirm" != "si" ]; then
        info "Operación cancelada"
        exit 0
    fi
    
    info "Eliminando contenedores y volúmenes..."
    
    stop_services
    
    # Asegurar que los contenedores estén completamente detenidos y eliminados
    info "Verificando y eliminando contenedores..."
    local containers_to_remove=("dns-monitor-redis" "dns-monitor-clickhouse" "dns-monitor-dashboard")
    local containers_running=false
    
    for container in "${containers_to_remove[@]}"; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
            containers_running=true
            info "Eliminando contenedor ${container}..."
            docker stop "${container}" 2>/dev/null || true
            docker rm -f "${container}" 2>/dev/null || true
        fi
    done
    
    # Esperar un momento para que los procesos se liberen completamente
    if [ "$containers_running" = true ]; then
        info "Esperando a que los procesos se liberen..."
        sleep 2
    fi
    
    # Verificar que ningún contenedor esté corriendo antes de eliminar datos
    info "Verificando que los contenedores estén detenidos..."
    local running_containers=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E "dns-monitor-(redis|clickhouse|dashboard)" || true)
    
    if [ -n "$running_containers" ]; then
        error "Los siguientes contenedores aún están corriendo:"
        echo "$running_containers"
        error "No se pueden eliminar los datos mientras los contenedores estén activos."
        error "Intenta detenerlos manualmente con: docker stop <nombre_contenedor>"
        exit 1
    fi
    
    # Verificar que los contenedores estén eliminados (no solo detenidos)
    local existing_containers=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E "dns-monitor-(redis|clickhouse|dashboard)" || true)
    if [ -n "$existing_containers" ]; then
        warning "Algunos contenedores aún existen (aunque detenidos):"
        echo "$existing_containers"
        info "Forzando eliminación..."
        echo "$existing_containers" | while read -r container; do
            docker rm -f "$container" 2>/dev/null || true
        done
        sleep 1
    fi
    
    # Eliminar volúmenes
    info "Eliminando volúmenes Docker..."
    docker volume rm dns-monitor-redis-data 2>/dev/null || true
    docker volume rm dns-monitor-clickhouse-data 2>/dev/null || true
    docker volume rm dns-monitor-clickhouse-logs 2>/dev/null || true
    
    # Eliminar directorios de datos locales (si existen)
    # Solo después de verificar que los contenedores están detenidos
    if [ -d "data" ]; then
        warning "Eliminando directorio data/..."
        # Intentar eliminar con rm -rf primero
        if ! rm -rf data/ 2>/dev/null; then
            # Si falla, intentar con find para eliminar archivos problemáticos
            info "Algunos archivos requieren eliminación forzada..."
            find data/ -type f -exec chmod 644 {} \; 2>/dev/null || true
            find data/ -type d -exec chmod 755 {} \; 2>/dev/null || true
            # Intentar eliminar de nuevo
            if ! rm -rf data/ 2>/dev/null; then
                # Último recurso: usar find para eliminar todo
                find data/ -delete 2>/dev/null || true
                # Si aún existe, intentar rmdir
                rmdir data/ 2>/dev/null || true
            fi
        fi
        # Verificar que se eliminó
        if [ -d "data" ]; then
            warning "Algunos archivos en data/ no se pudieron eliminar automáticamente."
            warning "Puede ser necesario eliminarlos manualmente con permisos de administrador."
            warning "Intenta: sudo rm -rf data/"
        else
            success "Directorio data/ eliminado"
        fi
    fi
    
    # Preguntar si también eliminar el virtualenv
    local project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -d "$project_dir/venv" ]; then
        read -p "¿También eliminar el virtualenv? (escribe 'si' para confirmar): " clean_venv
        if [ "$clean_venv" == "si" ]; then
            warning "Eliminando virtualenv..."
            rm -rf "$project_dir/venv"
            success "Virtualenv eliminado"
            
            # También eliminar el script wrapper si existe
            if [ -f "$project_dir/run_sniffer.sh" ]; then
                rm -f "$project_dir/run_sniffer.sh"
                info "Script wrapper eliminado"
            fi
        fi
    fi
    
    success "Limpieza completada"
}

# Main
case "${1:-help}" in
    redis)
        install_redis
        ;;
    clickhouse)
        install_clickhouse
        ;;
    dashboard)
        install_dashboard
        ;;
    sniffer)
        install_sniffer
        ;;
    all)
        install_all
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "${2:-}"
        ;;
    clean)
        clean_all
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        error "Opción desconocida: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
