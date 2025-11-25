#!/bin/bash
# Script para ejecutar el dashboard en modo producción

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Iniciando DNS Monitor Dashboard en modo producción...${NC}"

# Verificar que existe el archivo de configuración
if [ ! -f "config.yaml" ]; then
    echo -e "${YELLOW}⚠️  Advertencia: config.yaml no encontrado. Usando config.yaml.example como base.${NC}"
    if [ -f "config.yaml.example" ]; then
        cp config.yaml.example config.yaml
        echo -e "${YELLOW}Por favor, edita config.yaml con tus configuraciones antes de continuar.${NC}"
    fi
fi

# Verificar que las dependencias estén instaladas
if ! python3 -c "import streamlit" 2>/dev/null; then
    echo -e "${YELLOW}Instalando dependencias...${NC}"
    pip3 install -r requirements.txt
fi

# Ejecutar Streamlit en modo producción
echo -e "${GREEN}Iniciando servidor en http://0.0.0.0:8501${NC}"
echo -e "${YELLOW}Presiona Ctrl+C para detener el servidor${NC}"
echo ""

# Opciones de producción:
# --server.headless=true: No abrir navegador automáticamente
# --server.address=0.0.0.0: Escuchar en todas las interfaces
# --server.port=8501: Puerto del servidor
# --browser.gatherUsageStats=false: No enviar estadísticas de uso
streamlit run dashboard.py \
    --server.headless=true \
    --server.address=0.0.0.0 \
    --server.port=8501 \
    --browser.gatherUsageStats=false \
    --server.enableXsrfProtection=true

