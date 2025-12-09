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
    all            Instalar todos los componentes (Redis, ClickHouse y Dashboard)
    stop           Detener todos los servicios
    restart        Reiniciar todos los servicios
    status         Mostrar estado de los servicios
    logs           Mostrar logs de los servicios
    clean          Eliminar contenedores y volúmenes (¡CUIDADO: elimina datos!)
    help           Mostrar esta ayuda

EJEMPLOS:
    $0 redis              # Instalar solo Redis
    $0 clickhouse         # Instalar solo ClickHouse
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

# Función para crear directorios de datos
create_data_directories() {
    info "Creando directorios para persistencia de datos..."
    
    mkdir -p data/redis
    mkdir -p data/clickhouse
    mkdir -p data/clickhouse-logs
    
    success "Directorios creados"
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
    
    success "Dashboard instalado y funcionando correctamente"
    info "Dashboard está disponible en http://localhost:8501"
}

# Función para instalar todos los componentes
install_all() {
    info "Instalando todos los componentes..."
    check_dependencies
    create_data_directories
    
    $DOCKER_COMPOSE_CMD -f docker-compose.yml up -d
    
    info "Esperando a que los servicios estén listos..."
    sleep 10
    
    # Verificar servicios
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
    
    success "Todos los componentes han sido iniciados"
    info "Redis está disponible en localhost:6379"
    info "ClickHouse HTTP está disponible en localhost:8123"
    info "ClickHouse Native está disponible en localhost:9000"
    info "Dashboard está disponible en http://localhost:8501"
}

# Función para detener servicios
stop_services() {
    info "Deteniendo servicios..."
    
    if [ -f docker-compose.yml ]; then
        $DOCKER_COMPOSE_CMD -f docker-compose.yml down 2>/dev/null || true
    fi
    if [ -f docker-compose.redis.yml ]; then
        $DOCKER_COMPOSE_CMD -f docker-compose.redis.yml down 2>/dev/null || true
    fi
    if [ -f docker-compose.clickhouse.yml ]; then
        $DOCKER_COMPOSE_CMD -f docker-compose.clickhouse.yml down 2>/dev/null || true
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
    
    if docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "dns-monitor|NAMES"; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "dns-monitor|NAMES"
    else
        warning "No hay servicios DNS Monitor corriendo"
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
                docker logs -f dns-monitor-dashboard
                ;;
            *)
                error "Servicio desconocido: $service"
                info "Servicios disponibles: redis, clickhouse, dashboard"
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
    
    # Eliminar volúmenes
    docker volume rm dns-monitor-redis-data 2>/dev/null || true
    docker volume rm dns-monitor-clickhouse-data 2>/dev/null || true
    docker volume rm dns-monitor-clickhouse-logs 2>/dev/null || true
    
    # Eliminar directorios de datos locales (si existen)
    if [ -d "data" ]; then
        warning "Eliminando directorio data/..."
        rm -rf data/
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
