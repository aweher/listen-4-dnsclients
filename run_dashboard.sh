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
#
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

