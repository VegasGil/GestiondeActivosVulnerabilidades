import streamlit as st
import pandas as pd
import duckdb
import subprocess
import glob
import os
from datetime import datetime

# 1. Configuración de la página
st.set_page_config(page_title="Gestión de Activos y Vulnerabilidades", page_icon="🛡️", layout="wide")

# 2. Diseño Moderno (CSS - Purple Team)
st.markdown("""
    <style>
        .main { background-color: #0e1117; }
        .stButton>button { 
            width: 100%; border-radius: 6px; background-color: #5E35B1; color: white; border: none; 
            font-weight: bold; margin-bottom: 5px; min-height: 60px; white-space: normal; 
            display: flex; align-items: center; justify-content: center; transition: 0.3s;
        }
        .stButton>button:hover { background-color: #4527A0; border: 1px solid #B39DDB; box-shadow: 0 0 10px #7E57C2; }
        .btn-global>button { background-color: #311B92 !important; border: 1px solid #7E57C2 !important; text-transform: uppercase; letter-spacing: 1px;}
        .btn-global>button:hover { background-color: #4527A0 !important; box-shadow: 0 0 15px #B39DDB !important;}
        .stDownloadButton>button { min-height: 45px; background-color: #4CAF50; width: 100%;}
        .stDownloadButton>button:hover { background-color: #388E3C; border: 1px solid #81C784; }
        
        .metric-card { 
            background-color: #1e1e1e; padding: 15px; border-radius: 8px; border-left: 5px solid #5E35B1; 
            text-align: center; margin-bottom: 20px; height: 120px; display: flex; flex-direction: column; 
            justify-content: center; align-items: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .metric-card h3 { margin: 0; font-size: 1rem; color: #BDBDBD; padding-bottom: 5px;}
        .metric-card h2 { margin: 0; font-size: 2rem; color: #FFFFFF; font-weight: bold;}
        .metric-card h4 { margin: 0; font-size: 1.1rem; color: #FFFFFF; word-break: break-word;}
        
        .kpi-critico { border-left: 5px solid #FF1744 !important; }
        .kpi-mitigado { border-left: 5px solid #00C853 !important; }
        .kpi-activo { border-left: 5px solid #FF9100 !important; }
        .kpi-top { border-left: 5px solid #E91E63 !important; height: 100px !important; }
        .kpi-falso-seguro { border-left: 5px solid #FFC107 !important; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Gestión de Activos y Vulnerabilidades")
st.markdown("---")

# 3. FUNCIONES DE LECTURA Y CORRELACIÓN PESADA
@st.cache_data(ttl=10)
def obtener_tipos_reportes():
    archivos = glob.glob('historico_csv/**/*.csv', recursive=True)
    return list(set([os.path.basename(f).split('_')[0] if '_' in os.path.basename(f) and os.path.basename(f).split('_')[-1].replace('.csv','').isdigit() else os.path.basename(f).replace('.csv','') for f in archivos]))

def cargar_tabla_especifica(nombre_base):
    try:
        con = duckdb.connect(':memory:')
        query = f"SELECT DISTINCT * FROM read_csv_auto('historico_csv/**/*{nombre_base}*.csv', union_by_name=True, ignore_errors=True)"
        return con.execute(query).df().drop_duplicates()
    except Exception:
        return pd.DataFrame()

def actualizar_base_maestra():
    nombres_archivos = obtener_tipos_reportes()
    dfs_to_merge = []
    
    for name in nombres_archivos:
        df = cargar_tabla_especifica(name)
        if not df.empty:
            col_mapping = {col: 'DeviceName' for col in df.columns if str(col).lower().replace(' ', '').replace('_', '') in ['devicename', 'nombreequipo', 'hostname', 'equipo', 'dispositivo']}
            df.rename(columns=col_mapping, inplace=True)
            
            if 'AreaInfraestructura' not in df.columns:
                df['AreaInfraestructura'] = name
            else:
                df['AreaInfraestructura'] = df['AreaInfraestructura'].fillna(name)
                
            dfs_to_merge.append(df)

    if not dfs_to_merge: return
    
    df_nueva = dfs_to_merge[0]
    for i in range(1, len(dfs_to_merge)):
        if 'DeviceName' in df_nueva.columns and 'DeviceName' in dfs_to_merge[i].columns:
            df_nueva = pd.merge(df_nueva, dfs_to_merge[i], on='DeviceName', how='outer', suffixes=('', '_dup'))
            for col in list(df_nueva.columns):
                if col.endswith('_dup'):
                    orig_col = col.replace('_dup', '')
                    df_nueva[orig_col] = df_nueva[orig_col].combine_first(df_nueva[col])
                    df_nueva.drop(columns=[col], inplace=True)
        else:
            df_nueva = pd.concat([df_nueva, dfs_to_merge[i]], ignore_index=True)

    columnas_deseadas = ['DeviceName', 'compliance', 'AreaInfraestructura', 'sistemaOperativo', 'ComponenteNoConforme', 'SoftwareVersion', 'CveId', 'VulnerabilitySeverityLevel', 'RecommendedSecurityUpdate']
    df_nueva = df_nueva[[col for col in columnas_deseadas if col in df_nueva.columns]].drop_duplicates()
    df_nueva.reset_index(drop=True, inplace=True)

    os.makedirs('datos_correlacionados', exist_ok=True)
    ruta_maestra = 'datos_correlacionados/base_global_maestra.csv'
    
    if os.path.exists(ruta_maestra):
        df_vieja = pd.read_csv(ruta_maestra)
        if 'Estado' in df_vieja.columns and 'DeviceName' in df_vieja.columns:
            df_vieja['Key'] = df_vieja['DeviceName'].astype(str) + "-" + df_vieja.get('CveId', '').astype(str)
            df_nueva['Key'] = df_nueva['DeviceName'].astype(str) + "-" + df_nueva.get('CveId', '').astype(str)
            
            estado_map = dict(zip(df_vieja['Key'], df_vieja['Estado']))
            df_nueva['Estado'] = df_nueva['Key'].map(estado_map).fillna('🔴 Activo')
            df_nueva.drop(columns=['Key'], inplace=True)
        else:
            df_nueva.insert(0, 'Estado', '🔴 Activo')
    else:
        df_nueva.insert(0, 'Estado', '🔴 Activo')

    df_nueva.to_csv(ruta_maestra, index=False)

# ================= MENU LATERAL =================
st.sidebar.header("⚙️ Administración")

if st.sidebar.button("🔄 Procesar Nuevos CSVs"):
    with st.spinner("1. Convirtiendo archivos y 2. Calculando Correlación Maestra..."):
        try:
            subprocess.run(["python", "src/data/data_processor.py"], capture_output=True, text=True)
            actualizar_base_maestra()
            st.sidebar.success("¡Datos procesados y Base Maestra actualizada!")
            st.cache_data.clear()
            st.rerun()
        except Exception as e:
            st.sidebar.error("Error al procesar.")

st.sidebar.markdown("---")
st.sidebar.header("🌐 Análisis Principal")

st.markdown('<div class="btn-global">', unsafe_allow_html=True)
if st.sidebar.button("🌟 Vista Global Correlacionada"):
    st.session_state.vista_actual = "GLOBAL"
st.markdown('</div>', unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.header("📁 Vistas Individuales (Crudas)")

tipos_disponibles = obtener_tipos_reportes()
if 'vista_actual' not in st.session_state:
    st.session_state.vista_actual = "GLOBAL"

for tipo in tipos_disponibles:
    if st.sidebar.button(f"📄 {tipo}"):
        st.session_state.vista_actual = tipo

# ================= PANTALLA PRINCIPAL =================
if st.session_state.vista_actual == "GLOBAL":
    titulo_vista = "Vista Global Correlacionada (Carga Rápida)"
    ruta_maestra = 'datos_correlacionados/base_global_maestra.csv'
    if os.path.exists(ruta_maestra):
        df_actual = pd.read_csv(ruta_maestra)
    else:
        st.warning("No existe la base maestra. Haz clic en 'Procesar Nuevos CSVs' para generarla.")
        df_actual = pd.DataFrame()
else:
    df_actual = cargar_tabla_especifica(st.session_state.vista_actual)
    if 'Estado' not in df_actual.columns and not df_actual.empty:
        df_actual.insert(0, 'Estado', '🔴 Activo')
    if not df_actual.empty:
        df_actual.reset_index(drop=True, inplace=True)
    titulo_vista = f"Reporte Individual: {st.session_state.vista_actual}"

if not df_actual.empty:
    df_filtrado = df_actual.copy()
    
    st.subheader(f"📊 {titulo_vista}")

    # --- SECCIÓN DE FILTROS ---
    st.markdown("#### 🎛️ Panel de Filtros y Búsqueda")
    
    # BUSCADOR GLOBAL OPTIMIZADO (Vectorizado)
    busqueda_global = st.text_input("🔎 Buscador Global Rápido (CVE, Software, Nombre de Equipo, etc.):")
    if busqueda_global:
        mascara_busqueda = pd.Series(False, index=df_filtrado.index)
        for col in df_filtrado.columns:
            mascara_busqueda = mascara_busqueda | df_filtrado[col].astype(str).str.contains(busqueda_global, case=False, na=False)
        df_filtrado = df_filtrado[mascara_busqueda]
    
    col_filtro1, col_filtro2 = st.columns(2)
    with col_filtro1:
        if 'Estado' in df_filtrado.columns:
            filtro_estado = st.radio("🛡️ Estado de Vulnerabilidad:", ["Mostrar Todos", "🔴 Solo Activas", "✅ Solo Mitigadas"], horizontal=True)
            if filtro_estado == "🔴 Solo Activas":
                df_filtrado = df_filtrado[df_filtrado['Estado'] == '🔴 Activo']
            elif filtro_estado == "✅ Solo Mitigadas":
                df_filtrado = df_filtrado[df_filtrado['Estado'] == '✅ Mitigado']

    with col_filtro2:
        sev_col = 'VulnerabilitySeverityLevel' if 'VulnerabilitySeverityLevel' in df_filtrado.columns else ('Severity' if 'Severity' in df_filtrado.columns else None)
        if sev_col:
            filtro_sev = st.radio("🚦 Nivel de Severidad:", ["Mostrar Todas", "🚨 Solo Críticas", "🟠 Solo Altas"], horizontal=True)
            if filtro_sev == "🚨 Solo Críticas":
                df_filtrado = df_filtrado[df_filtrado[sev_col].astype(str).str.contains('Critical', case=False, na=False)]
            elif filtro_sev == "🟠 Solo Altas":
                df_filtrado = df_filtrado[df_filtrado[sev_col].astype(str).str.contains('High', case=False, na=False)]

    if 'AreaInfraestructura' in df_filtrado.columns:
        opciones_area = ["Todas las Categorías"] + [str(x) for x in df_actual['AreaInfraestructura'].dropna().unique()]
        filtro_area = st.radio("🏢 Categoría de Equipo:", opciones_area, horizontal=True)
        if filtro_area != "Todas las Categorías":
            df_filtrado = df_filtrado[df_filtrado['AreaInfraestructura'].astype(str) == filtro_area]

    col_filtro3, col_filtro4 = st.columns(2)
    with col_filtro3:
        if 'ComponenteNoConforme' in df_filtrado.columns:
            opciones_comp = [str(x) for x in df_filtrado['ComponenteNoConforme'].dropna().unique()]
            filtro_comp = st.multiselect("⚙️ Filtrar por Componente (Software):", opciones_comp, placeholder="Selecciona componentes...")
            if filtro_comp:
                df_filtrado = df_filtrado[df_filtrado['ComponenteNoConforme'].astype(str).isin(filtro_comp)]
                
    with col_filtro4:
        if 'sistemaOperativo' in df_filtrado.columns:
            opciones_os = [str(x) for x in df_filtrado['sistemaOperativo'].dropna().unique()]
            filtro_os = st.multiselect("🖥️ Filtrar por Sistema Operativo:", opciones_os, placeholder="Selecciona SO...")
            if filtro_os:
                df_filtrado = df_filtrado[df_filtrado['sistemaOperativo'].astype(str).isin(filtro_os)]

    # --- CÁLCULO DE KPIs PRINCIPALES ---
    activos_afectados = df_filtrado['DeviceName'].nunique() if 'DeviceName' in df_filtrado.columns else len(df_filtrado)
    total_mitigados = len(df_filtrado[df_filtrado['Estado'] == '✅ Mitigado']) if 'Estado' in df_filtrado.columns else 0
    total_activos = len(df_filtrado[df_filtrado['Estado'] == '🔴 Activo']) if 'Estado' in df_filtrado.columns else 0
    
    criticas_activas = 0
    if sev_col and 'Estado' in df_filtrado.columns:
        criticas_activas = len(df_filtrado[(df_filtrado[sev_col].astype(str).str.contains('Critical', case=False, na=False)) & (df_filtrado['Estado'] == '🔴 Activo')])

    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f'<div class="metric-card"><h3 title="Equipos físicos/virtuales únicos en esta vista">Equipos Afectados</h3><h2>{activos_afectados}</h2></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card kpi-activo"><h3>Vulnerabilidades Activas</h3><h2>{total_activos}</h2></div>', unsafe_allow_html=True)
    with col3:
        st.markdown(f'<div class="metric-card kpi-mitigado"><h3>Vulnerabilidades Mitigadas</h3><h2>{total_mitigados}</h2></div>', unsafe_allow_html=True)
    with col4:
        st.markdown(f'<div class="metric-card kpi-critico"><h3>Críticas SIN Mitigar</h3><h2>{criticas_activas}</h2></div>', unsafe_allow_html=True)

    # --- KPIs DE CUMPLIMIENTO (COMPLIANCE VS REALIDAD) ---
    if 'compliance' in df_filtrado.columns:
        st.markdown("#### 🛡️ Brecha de Cumplimiento (Falsa Sensación de Seguridad)")
        
        equipos_compliant_vuln = df_filtrado[df_filtrado['compliance'].astype(str).str.contains('Compliant|Cumple', case=False, na=False)]['DeviceName'].nunique()
        equipos_non_compliant = df_filtrado[df_filtrado['compliance'].astype(str).str.contains('Non|No Cumple|Not', case=False, na=False)]['DeviceName'].nunique()
        
        c_col1, c_col2, c_col3 = st.columns(3)
        with c_col1:
            st.markdown(f'<div class="metric-card"><h3 title="Total de equipos únicos en la vista actual">Total Equipos Vulnerables</h3><h2>{activos_afectados}</h2></div>', unsafe_allow_html=True)
        with c_col2:
            st.markdown(f'<div class="metric-card kpi-falso-seguro"><h3 title="Intune los marca conformes, pero tienen componentes vulnerables">"Compliant" PERO Vulnerables</h3><h2>{equipos_compliant_vuln}</h2></div>', unsafe_allow_html=True)
        with c_col3:
            st.markdown(f'<div class="metric-card kpi-critico"><h3 title="Equipos marcados como No Conformes en Intune">Equipos Non-Compliant</h3><h2>{equipos_non_compliant}</h2></div>', unsafe_allow_html=True)

    # --- KPIs DE TOP 3 COMPONENTES ---
    if 'ComponenteNoConforme' in df_filtrado.columns and not df_filtrado.empty:
        st.markdown("#### 🔥 Top 3 Componentes Vulnerables (Para Parcheo Prioritario)")
        top_comps = df_filtrado['ComponenteNoConforme'].value_counts().head(3)
        
        if not top_comps.empty:
            cols_top = st.columns(3)
            for i, (comp, count) in enumerate(top_comps.items()):
                with cols_top[i]:
                    st.markdown(f'<div class="metric-card kpi-top">'
                                f'<h3 style="font-size: 1rem; color: #E91E63;">#{i+1} | {comp}</h3>'
                                f'<h2 style="font-size: 1.8rem;">{count} <span style="font-size: 1rem; color: #BDBDBD; font-weight: normal;">alertas</span></h2>'
                                f'</div>', unsafe_allow_html=True)

    # --- TABLA EDITABLE ---
    st.markdown("*(Cambia el estado haciendo doble clic en la columna **Estado**)*")
    df_editado = st.data_editor(
        df_filtrado,
        use_container_width=True,
        num_rows="dynamic",
        key=f"editor_{st.session_state.vista_actual}",
        column_config={
            "Estado": st.column_config.SelectboxColumn("Estado", options=["🔴 Activo", "✅ Mitigado"], required=True)
        }
    )

    # --- GUARDAR MITIGACIONES ---
    st.markdown("---")
    col_btn1, col_btn2, col_btn3 = st.columns([2, 2, 4])
    
    with col_btn1:
        if st.button("💾 Guardar Mitigaciones"):
            try:
                if st.session_state.vista_actual == "GLOBAL":
                    df_maestro = pd.read_csv('datos_correlacionados/base_global_maestra.csv')
                    df_maestro.loc[df_editado.index, 'Estado'] = df_editado['Estado']
                    df_maestro.to_csv('datos_correlacionados/base_global_maestra.csv', index=False)
                    st.success("¡Base Maestra Actualizada Exitosamente!")
                else:
                    os.makedirs('datos_editados/individuales', exist_ok=True)
                    df_editado.to_csv(f"datos_editados/individuales/{st.session_state.vista_actual}_estado.csv", index=False)
                    st.success("Guardado en vistas individuales.")
            except Exception as e:
                st.error(f"⚠️ Error al guardar: {e}")
                
    with col_btn2:
        csv_export = df_editado.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Descargar Tabla Actual",
            data=csv_export,
            file_name=f"Reporte_{st.session_state.vista_actual}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )