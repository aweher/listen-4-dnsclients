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
# Script de entrada para el contenedor del dashboard

set -e

# Si no existe config.yaml, crear uno desde el ejemplo
if [ ! -f /app/config.yaml ]; then
    echo "Config.yaml no encontrado, creando desde ejemplo..."
    cp /app/config.yaml.example /app/config.yaml 2>/dev/null || true
fi

# Actualizar configuración de Redis desde variables de entorno si están disponibles
if [ -n "$REDIS_HOST" ] || [ -n "$REDIS_PORT" ] || [ -n "$REDIS_PASSWORD" ]; then
    echo "Actualizando configuración de Redis desde variables de entorno..."
    python3 << EOF
import yaml
import os

config_path = '/app/config.yaml'
with open(config_path, 'r') as f:
    config = yaml.safe_load(f) or {}

if 'redis' not in config:
    config['redis'] = {}

if os.getenv('REDIS_HOST'):
    config['redis']['host'] = os.getenv('REDIS_HOST')
if os.getenv('REDIS_PORT'):
    config['redis']['port'] = int(os.getenv('REDIS_PORT'))
if os.getenv('REDIS_PASSWORD'):
    config['redis']['password'] = os.getenv('REDIS_PASSWORD')
elif 'REDIS_PASSWORD' in os.environ and os.getenv('REDIS_PASSWORD') == '':
    config['redis']['password'] = None

with open(config_path, 'w') as f:
    yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

print(f"Configuración actualizada: Redis en {config['redis'].get('host', 'localhost')}:{config['redis'].get('port', 6379)}")
EOF
fi

# Ejecutar Streamlit
exec python -m streamlit run dashboard.py \
    --server.headless=true \
    --server.address=0.0.0.0 \
    --server.port=8501 \
    --browser.gatherUsageStats=false \
    --server.enableXsrfProtection=true

