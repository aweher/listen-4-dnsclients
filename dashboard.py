#!/usr/bin/env python3
"""
Copyright (c) 2025 Ariel S. Weher <ariel@ayuda.la>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Dashboard Streamlit para visualizar estadísticas DNS
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import time
import hashlib
from redis_client import DNSRedisClient
from config import get_config

# Configuración de la página
st.set_page_config(
    page_title="DNS Monitor Dashboard",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Cargar configuración de autenticación
config = get_config()
auth_config = config.get_auth_config()

# Inicializar sesión
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'auth_token' not in st.session_state:
    st.session_state.auth_token = None

# Función para generar un token de autenticación simple
def generate_auth_token(username):
    """Genera un token simple basado en el usuario y timestamp"""
    timestamp = str(int(time.time()))
    token_string = f"{username}:{timestamp}"
    return hashlib.sha256(token_string.encode()).hexdigest()[:32]

# Función para verificar token (simplificada - en producción usar JWT o similar)
def verify_auth_token(token, username):
    """Verifica que el token sea válido para el usuario"""
    # En una implementación real, esto debería verificar contra una base de datos
    # o usar JWT. Por ahora, simplemente verificamos que el usuario existe
    return username in auth_config

# JavaScript para manejar cookies
cookie_script = """
<script>
function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
    document.cookie = name + '=' + value + ';expires=' + expires.toUTCString() + ';path=/';
}

function getCookie(name) {
    const nameEQ = name + '=';
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

function deleteCookie(name) {
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
}
</script>
"""


# Función para establecer cookie de autenticación
def set_auth_cookie(username, token):
    """Establece la cookie de autenticación usando JavaScript"""
    days = 7  # Cookie válida por 7 días
    st.components.v1.html(
        f"""
        {cookie_script}
        <script>
        setCookie('dns_dashboard_auth', '{token}', {days});
        setCookie('dns_dashboard_user', '{username}', {days});
        </script>
        """,
        height=0,
        key=f"set_cookie_{int(time.time())}"
    )

# Función para eliminar cookie de autenticación
def clear_auth_cookie():
    """Elimina la cookie de autenticación"""
    st.components.v1.html(
        f"""
        {cookie_script}
        <script>
        deleteCookie('dns_dashboard_auth');
        deleteCookie('dns_dashboard_user');
        </script>
        """,
        height=0,
        key=f"clear_cookie_{int(time.time())}"
    )

# Función de autenticación
def check_password(user, pwd):
    """Verifica las credenciales contra la configuración"""
    if user in auth_config:
        return auth_config[user] == pwd
    return False

# Verificar cookies al inicio usando JavaScript
# Si hay una cookie de autenticación válida, establecer el estado automáticamente
if not st.session_state.authenticated and 'auth_checked' not in st.session_state:
    st.session_state.auth_checked = True
    
    # Componente que lee cookies y establece autenticación mediante query params
    # Solo se ejecuta si no estamos ya autenticados y no hay parámetros de cookie en la URL
    query_params = st.query_params
    if 'from_cookie' not in query_params:
        st.components.v1.html(
            f"""
            {cookie_script}
            <script>
            (function() {{
                const authToken = getCookie('dns_dashboard_auth');
                const username = getCookie('dns_dashboard_user');
                
                if (authToken && username) {{
                    // Si hay cookie válida, redirigir con parámetros para establecer autenticación
                    const url = new URL(window.location);
                    if (!url.searchParams.has('from_cookie')) {{
                        url.searchParams.set('auth_token', authToken);
                        url.searchParams.set('username', username);
                        url.searchParams.set('from_cookie', 'true');
                        window.location.href = url.toString();
                    }}
                }}
            }})();
            </script>
            """,
            height=0,
            key="check_auth_cookie"
        )

# Verificar parámetros de autenticación de cookies
query_params = st.query_params
if 'from_cookie' in query_params and 'auth_token' in query_params and 'username' in query_params:
    if not st.session_state.authenticated:
        username = query_params['username']
        token = query_params['auth_token']
        # Verificar que el usuario existe (validación básica)
        if username in auth_config:
            st.session_state.authenticated = True
            st.session_state.auth_token = token
            st.session_state.username = username
            # Limpiar parámetros de la URL
            for key in list(query_params.keys()):
                del query_params[key]
            st.rerun()

# Pantalla de login
if not st.session_state.authenticated:
    st.title("🔐 Autenticación Requerida")
    st.markdown("Por favor, ingresa tus credenciales para acceder al dashboard.")
    
    with st.form("login_form"):
        input_username = st.text_input("Usuario", placeholder="Ingresa tu usuario")
        input_password = st.text_input("Contraseña", type="password", placeholder="Ingresa tu contraseña")
        submit_button = st.form_submit_button("Iniciar Sesión")
        
        if submit_button:
            if check_password(input_username, input_password):
                # Generar token de autenticación
                token = generate_auth_token(input_username)
                st.session_state.authenticated = True
                st.session_state.auth_token = token
                st.session_state.username = input_username
                # Establecer cookies para persistencia
                set_auth_cookie(input_username, token)
                st.rerun()
            else:
                st.error("❌ Usuario o contraseña incorrectos")
    
    st.stop()

# Cargar configuración de Redis (solo después de autenticación)
redis_config = config.get_redis_config()

# Usar configuración del archivo sin mostrarla
redis_host = redis_config['host']
redis_port = redis_config['port']
redis_db = redis_config['db']
redis_password = redis_config['password']

# Sidebar - Configuración
st.sidebar.title("⚙️ Configuración")
auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
refresh_interval = st.sidebar.slider("Intervalo (segundos)", 1, 600, 180)

# Botón de cierre de sesión
st.sidebar.markdown("---")
if st.sidebar.button("🚪 Cerrar Sesión"):
    st.session_state.authenticated = False
    st.session_state.auth_token = None
    if 'username' in st.session_state:
        del st.session_state.username
    # Eliminar cookies
    clear_auth_cookie()
    st.rerun()

# Título principal con indicador de estado
col_title1, col_title2 = st.columns([3, 1])
with col_title1:
    st.title("🌐 DNS Monitor Dashboard")
with col_title2:
    if auto_refresh:
        st.markdown(f"<div style='text-align: right; padding-top: 1rem;'><span style='color: green; font-weight: bold;'>🟢 EN VIVO</span><br><small>{refresh_interval}s</small></div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div style='text-align: right; padding-top: 1rem;'><span style='color: gray;'>⚪ PAUSADO</span></div>", unsafe_allow_html=True)
st.markdown("---")

# Inicializar cliente de datos
@st.cache_resource
def get_redis_client(host, port, db, password):
    """Obtiene el cliente de datos (con caché)"""
    # Crear una clave única basada en los parámetros para invalidar el caché cuando cambien
    return DNSRedisClient(
        host=host,
        port=port,
        db=db,
        password=password
    )

try:
    redis_client = get_redis_client(redis_host, redis_port, redis_db, redis_password)
except Exception as e:
    st.error(f"Error conectando al sistema: {e}")
    st.stop()

# Botón de actualización manual y estado de auto-refresh
col_btn1, col_btn2 = st.sidebar.columns(2)
with col_btn1:
    if st.button("🔄 Actualizar"):
        st.cache_resource.clear()  # Limpiar caché al actualizar
        st.rerun()

with col_btn2:
    if auto_refresh:
        st.success(f"🟢 Auto-refresh: {refresh_interval}s")
    else:
        st.info("⚪ Auto-refresh: OFF")

# Sección de diagnóstico
with st.sidebar.expander("🔍 Diagnóstico"):
    try:
        # Verificar conexión
        redis_client.client.ping()
        st.success("✅ Conexión: OK")
        
        # Obtener información de diagnóstico
        diag_info = redis_client.get_diagnostic_info()
        
        if 'error' in diag_info:
            st.error(f"❌ Error: {diag_info['error']}")
        else:
            st.info(f"📊 Total de registros: {diag_info['total_keys']}")
            
            if diag_info['has_data']:
                st.success("✅ Hay datos disponibles")
                st.info(f"  - Clientes: {diag_info['client_keys']}")
                st.info(f"  - Dominios: {diag_info['domain_keys']}")
                st.info(f"  - Paquetes: {diag_info['packet_keys']}")
                st.info(f"  - Tipos: {diag_info['type_keys']}")
                st.info(f"  - Protocolos: {diag_info['protocol_keys']}")
                st.info(f"  - Consultas recientes: {diag_info['recent_queries']}")
                st.info(f"  - Clientes únicos: {diag_info['unique_clients']}")
                st.info(f"  - Dominios únicos: {diag_info['unique_domains']}")
            else:
                st.warning("⚠️ No hay datos disponibles")
                st.markdown("""
                **Posibles causas:**
                - El capturador DNS no está ejecutándose
                - No hay tráfico DNS en la red
                """)
    except Exception as e:
        st.error(f"❌ Error en diagnóstico: {e}")
        import traceback
        with st.expander("Detalles"):
            st.code(traceback.format_exc())

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
    
    # Mostrar advertencia si no hay datos
    if total_queries == 0 and unique_clients == 0 and unique_domains == 0:
        st.warning("⚠️ No se encontraron datos. Asegúrate de que:")
        st.markdown("""
        1. El capturador DNS esté ejecutándose
        2. Haya tráfico DNS en la red
        """)
    
except Exception as e:
    st.error(f"Error obteniendo estadísticas: {e}")
    import traceback
    with st.expander("Detalles del error"):
        st.code(traceback.format_exc())

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
            st.plotly_chart(fig, width='stretch')
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
            st.plotly_chart(fig, width='stretch')
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
            st.plotly_chart(fig, width='stretch')
            
            # Tabla detallada
            with st.expander("Ver tabla detallada"):
                st.dataframe(df_clients, width='stretch')
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
            st.plotly_chart(fig, width='stretch')
            
            # Tabla detallada
            with st.expander("Ver tabla detallada"):
                st.dataframe(df_domains, width='stretch')
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
        st.dataframe(df_recent, width='stretch', height=400)
    else:
        st.info("No hay consultas recientes disponibles")
except Exception as e:
    st.error(f"Error: {e}")

st.markdown("---")

# Tablas detalladas completas
st.header("📋 Tablas Detalladas Completas")

# Tabla de todos los clientes
st.subheader("👥 Totalidad de Clientes")
try:
    all_clients = redis_client.get_all_clients()
    if all_clients:
        df_all_clients = pd.DataFrame(all_clients)
        df_all_clients.index = range(1, len(df_all_clients) + 1)  # Índice empezando en 1
        
        # Mostrar métricas rápidas
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Clientes", len(all_clients))
        with col2:
            total_client_queries = df_all_clients['count'].sum()
            st.metric("Total Consultas", total_client_queries)
        with col3:
            avg_queries = df_all_clients['count'].mean() if len(all_clients) > 0 else 0
            st.metric("Promedio Consultas/Cliente", f"{avg_queries:.1f}")
        
        # Mostrar tabla con opciones de búsqueda y ordenamiento
        st.dataframe(
            df_all_clients,
            use_container_width=True,
            height=600,
            column_config={
                "ip": st.column_config.TextColumn(
                    "IP de Origen",
                    help="Dirección IP del cliente que realizó las consultas DNS"
                ),
                "count": st.column_config.NumberColumn(
                    "Consultas",
                    help="Número total de consultas DNS realizadas por este cliente",
                    format="%d"
                )
            }
        )
        
        # Opción para descargar CSV
        csv_clients = df_all_clients.to_csv(index=False)
        st.download_button(
            label="📥 Descargar CSV de Clientes",
            data=csv_clients,
            file_name=f"clientes_dns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No hay datos de clientes disponibles")
except Exception as e:
    st.error(f"Error obteniendo todos los clientes: {e}")
    import traceback
    with st.expander("Detalles del error"):
        st.code(traceback.format_exc())

st.markdown("---")

# Tabla de todos los dominios
st.subheader("🌍 Totalidad de Dominios Consultados")
try:
    all_domains = redis_client.get_all_domains()
    if all_domains:
        df_all_domains = pd.DataFrame(all_domains)
        df_all_domains.index = range(1, len(df_all_domains) + 1)  # Índice empezando en 1
        
        # Mostrar métricas rápidas
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Dominios", len(all_domains))
        with col2:
            total_domain_queries = df_all_domains['count'].sum()
            st.metric("Total Consultas", total_domain_queries)
        with col3:
            avg_queries = df_all_domains['count'].mean() if len(all_domains) > 0 else 0
            st.metric("Promedio Consultas/Dominio", f"{avg_queries:.1f}")
        
        # Mostrar tabla con opciones de búsqueda y ordenamiento
        st.dataframe(
            df_all_domains,
            use_container_width=True,
            height=600,
            column_config={
                "domain": st.column_config.TextColumn(
                    "Dominio",
                    help="Nombre del dominio consultado"
                ),
                "count": st.column_config.NumberColumn(
                    "Consultas",
                    help="Número total de consultas DNS realizadas para este dominio",
                    format="%d"
                )
            }
        )
        
        # Opción para descargar CSV
        csv_domains = df_all_domains.to_csv(index=False)
        st.download_button(
            label="📥 Descargar CSV de Dominios",
            data=csv_domains,
            file_name=f"dominios_dns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No hay datos de dominios disponibles")
except Exception as e:
    st.error(f"Error obteniendo todos los dominios: {e}")
    import traceback
    with st.expander("Detalles del error"):
        st.code(traceback.format_exc())

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
        st.plotly_chart(fig, width='stretch')
    
except Exception as e:
    st.error(f"Error: {e}")

# Footer con indicador de actualización
st.markdown("---")
current_time = datetime.now()
if auto_refresh:
    st.markdown(f"*🔄 Actualización automática cada {refresh_interval}s - Última actualización: {current_time.strftime('%Y-%m-%d %H:%M:%S')}*")
else:
    st.markdown(f"*Última actualización: {current_time.strftime('%Y-%m-%d %H:%M:%S')}*")

# Auto-refresh - debe estar al final del script
if auto_refresh:
    # Mostrar un spinner mientras espera
    with st.spinner(f"Esperando {refresh_interval} segundos para próxima actualización..."):
        time.sleep(refresh_interval)
    st.rerun()

