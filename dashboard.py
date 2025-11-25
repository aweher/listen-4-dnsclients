#!/usr/bin/env python3
"""
Dashboard Streamlit para visualizar estadísticas DNS
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
from redis_client import DNSRedisClient

# Configuración de la página
st.set_page_config(
    page_title="DNS Monitor Dashboard",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Título principal
st.title("🌐 DNS Monitor Dashboard")
st.markdown("---")

# Inicializar cliente Redis
@st.cache_resource
def get_redis_client():
    """Obtiene el cliente Redis (con caché)"""
    return DNSRedisClient(
        host=st.sidebar.text_input("Redis Host", value="localhost"),
        port=st.sidebar.number_input("Redis Port", value=6379, min_value=1, max_value=65535),
        db=st.sidebar.number_input("Redis DB", value=0, min_value=0, max_value=15)
    )

# Sidebar
st.sidebar.title("⚙️ Configuración")
auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
refresh_interval = st.sidebar.slider("Intervalo (segundos)", 1, 60, 5)

try:
    redis_client = get_redis_client()
except Exception as e:
    st.error(f"Error conectando a Redis: {e}")
    st.stop()

# Botón de actualización manual
if st.sidebar.button("🔄 Actualizar Datos"):
    st.rerun()

# Estadísticas generales
st.header("📊 Estadísticas Generales")

col1, col2, col3, col4 = st.columns(4)

try:
    unique_clients = redis_client.get_unique_clients_count()
    unique_domains = redis_client.get_unique_domains_count()
    protocol_stats = redis_client.get_protocol_stats()
    total_queries = sum(protocol_stats.values())
    
    with col1:
        st.metric("Clientes Únicos", unique_clients)
    
    with col2:
        st.metric("Dominios Únicos", unique_domains)
    
    with col3:
        st.metric("Total Consultas", total_queries)
    
    with col4:
        tcp_count = protocol_stats.get('TCP', 0)
        udp_count = protocol_stats.get('UDP', 0)
        if total_queries > 0:
            tcp_percent = (tcp_count / total_queries) * 100
            st.metric("TCP %", f"{tcp_percent:.1f}%")
        else:
            st.metric("TCP %", "0%")
    
except Exception as e:
    st.error(f"Error obteniendo estadísticas: {e}")

st.markdown("---")

# Gráficos principales
col1, col2 = st.columns(2)

# Gráfico TCP vs UDP
with col1:
    st.subheader("📡 Protocolo: TCP vs UDP")
    try:
        protocol_stats = redis_client.get_protocol_stats()
        if protocol_stats:
            df_protocol = pd.DataFrame([
                {'Protocolo': 'TCP', 'Cantidad': protocol_stats.get('TCP', 0)},
                {'Protocolo': 'UDP', 'Cantidad': protocol_stats.get('UDP', 0)}
            ])
            
            fig = px.pie(
                df_protocol,
                values='Cantidad',
                names='Protocolo',
                color_discrete_map={'TCP': '#1f77b4', 'UDP': '#ff7f0e'}
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay datos de protocolos disponibles")
    except Exception as e:
        st.error(f"Error: {e}")

# Gráfico de tipos de registro
with col2:
    st.subheader("📋 Tipos de Registro DNS")
    try:
        record_stats = redis_client.get_record_type_stats()
        if record_stats:
            df_records = pd.DataFrame([
                {'Tipo': k, 'Cantidad': v}
                for k, v in record_stats.items()
            ])
            df_records = df_records.sort_values('Cantidad', ascending=False)
            
            fig = px.bar(
                df_records,
                x='Tipo',
                y='Cantidad',
                color='Cantidad',
                color_continuous_scale='Blues'
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay datos de tipos de registro disponibles")
    except Exception as e:
        st.error(f"Error: {e}")

st.markdown("---")

# Top clientes y dominios
col1, col2 = st.columns(2)

# Top clientes
with col1:
    st.subheader("👥 Top Clientes (IPs de Origen)")
    try:
        top_clients = redis_client.get_top_clients(limit=10)
        if top_clients:
            df_clients = pd.DataFrame(top_clients)
            
            fig = px.bar(
                df_clients,
                x='count',
                y='ip',
                orientation='h',
                labels={'count': 'Consultas', 'ip': 'IP de Origen'},
                color='count',
                color_continuous_scale='Reds'
            )
            fig.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
            
            # Tabla detallada
            with st.expander("Ver tabla detallada"):
                st.dataframe(df_clients, use_container_width=True)
        else:
            st.info("No hay datos de clientes disponibles")
    except Exception as e:
        st.error(f"Error: {e}")

# Top dominios
with col2:
    st.subheader("🌍 Dominios Más Consultados")
    try:
        top_domains = redis_client.get_top_domains(limit=10)
        if top_domains:
            df_domains = pd.DataFrame(top_domains)
            
            fig = px.bar(
                df_domains,
                x='count',
                y='domain',
                orientation='h',
                labels={'count': 'Consultas', 'domain': 'Dominio'},
                color='count',
                color_continuous_scale='Greens'
            )
            fig.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
            
            # Tabla detallada
            with st.expander("Ver tabla detallada"):
                st.dataframe(df_domains, use_container_width=True)
        else:
            st.info("No hay datos de dominios disponibles")
    except Exception as e:
        st.error(f"Error: {e}")

st.markdown("---")

# Consultas recientes
st.subheader("🕐 Consultas Recientes")
try:
    num_recent = st.slider("Número de consultas recientes a mostrar", 10, 100, 50)
    recent_queries = redis_client.get_recent_queries(limit=num_recent)
    
    if recent_queries:
        # Preparar datos para la tabla
        table_data = []
        for q in recent_queries:
            table_data.append({
                'Timestamp': q.get('timestamp', 'N/A'),
                'IP Origen': q.get('src_ip', 'N/A'),
                'Dominio': q.get('domain', 'N/A'),
                'Tipo': q.get('record_type', 'N/A'),
                'Protocolo': q.get('protocol', 'N/A'),
                'Es Query': 'Sí' if q.get('is_query', False) else 'No'
            })
        
        df_recent = pd.DataFrame(table_data)
        st.dataframe(df_recent, use_container_width=True, height=400)
    else:
        st.info("No hay consultas recientes disponibles")
except Exception as e:
    st.error(f"Error: {e}")

st.markdown("---")

# Estadísticas por período
st.subheader("📈 Estadísticas por Período")
time_range = st.selectbox(
    "Seleccionar período",
    ["Última hora", "Últimas 6 horas", "Últimas 24 horas", "Últimas 48 horas"]
)

try:
    hours_map = {
        "Última hora": 1,
        "Últimas 6 horas": 6,
        "Últimas 24 horas": 24,
        "Últimas 48 horas": 48
    }
    hours = hours_map[time_range]
    time_stats = redis_client.get_time_range_stats(hours=hours)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Consultas", time_stats['total_queries'])
    
    with col2:
        st.metric("Clientes Únicos", time_stats['unique_clients'])
    
    with col3:
        st.metric("Dominios Únicos", time_stats['unique_domains'])
    
    with col4:
        total_protocol = time_stats['tcp_count'] + time_stats['udp_count']
        if total_protocol > 0:
            tcp_percent = (time_stats['tcp_count'] / total_protocol) * 100
            st.metric("TCP %", f"{tcp_percent:.1f}%")
        else:
            st.metric("TCP %", "0%")
    
    # Gráfico de tipos de registro en el período
    if time_stats['record_types']:
        st.subheader(f"Tipos de Registro ({time_range.lower()})")
        df_time_records = pd.DataFrame([
            {'Tipo': k, 'Cantidad': v}
            for k, v in time_stats['record_types'].items()
        ])
        df_time_records = df_time_records.sort_values('Cantidad', ascending=False)
        
        fig = px.pie(
            df_time_records,
            values='Cantidad',
            names='Tipo'
        )
        st.plotly_chart(fig, use_container_width=True)
    
except Exception as e:
    st.error(f"Error: {e}")

# Footer
st.markdown("---")
st.markdown(f"*Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

# Auto-refresh
if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()

