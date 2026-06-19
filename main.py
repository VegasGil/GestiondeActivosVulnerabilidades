import streamlit as st
import pandas as pd
import duckdb
import subprocess
import glob
import os
from datetime import datetime
import plotly.express as px

# 1. Page Configuration
st.set_page_config(page_title="Cloud Posture & Vulnerability Dashboard", layout="wide")

# Safe state initialization
if 'current_view' not in st.session_state:
    st.session_state.current_view = "GLOBAL"
if 'screen_mode' not in st.session_state:
    st.session_state.screen_mode = "Executive Dashboard"

# 2. Ultra-Dark Enterprise Design
st.markdown("""
    <style>
        .main { background-color: #12141A; }
        .stButton>button { 
            width: 100%; border-radius: 4px; background-color: #2D313A; color: #E0E0E0; border: 1px solid #424651; 
            font-weight: 500; margin-bottom: 5px; min-height: 45px; transition: 0.2s;
        }
        .stButton>button:hover { background-color: #3F4452; border-color: #5C6270; color: white;}
        .btn-nav>button { background-color: #1E3A8A !important; border: 1px solid #2563EB !important; color: white; font-size: 1.05rem;}
        .btn-nav>button:hover { background-color: #2563EB !important; box-shadow: 0 0 15px #3B82F6 !important;}
        .cs-card {
            background-color: #1F2128; padding: 15px 20px; border-radius: 4px; margin-bottom: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3); border: 1px solid #2D313A; height: 110px;
        }
        .cs-card-title { font-size: 0.90rem; color: #9CA3AF; margin-bottom: 2px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;}
        .cs-card-value { font-size: 2.6rem; color: #F9FAFB; font-weight: 400; line-height: 1.1; margin-bottom: 5px;}
        .cs-card-footer { font-size: 0.70rem; color: #6B7280; }
        .border-crit { border-bottom: 4px solid #E53935; }
        .border-high { border-bottom: 4px solid #F57C00; }
        .border-med  { border-bottom: 4px solid #FFB300; }
        .border-cve  { border-bottom: 4px solid #8B5CF6; }
        .border-ok   { border-bottom: 4px solid #10B981; }
        .border-info { border-bottom: 4px solid #2563EB; }
        [data-testid="stVerticalBlockBorderWrapper"] > div {
            background-color: #1F2128 !important; border-color: #2D313A !important; border-radius: 6px !important; padding: 1rem !important;
        }
        .grid-title { font-size: 1.05rem; color: #E5E7EB; margin-bottom: 15px; font-weight: 600;}
        .empty-state { color: #6B7280; text-align: center; padding: 30px 0; font-style: italic; font-size: 0.9rem;}
        h1, h2, h3, h4, h5, h6 { color: #F3F4F6 !important; }
        hr { border-color: #2D313A; }
        .filter-panel { background-color: #1F2128; padding: 20px; border-radius: 4px; border: 1px solid #374151; margin-bottom: 20px;}
        [data-testid="stDataFrame"] { background-color: transparent !important;}
        .streamlit-expanderHeader { color: #9CA3AF !important; font-size: 0.85rem !important; }
    </style>
""", unsafe_allow_html=True)

# 3. DATA PROCESSING & STANDARDIZATION FUNCTIONS
def standardize_columns(df):
    if df.empty: return df
    
    df = df.loc[:, ~df.columns.duplicated()].copy()
    col_mapping = {}
    assigned_targets = set()
    
    for col in df.columns:
        col_lower = str(col).lower().strip().replace(' ', '').replace('_', '')
        target = None
        
        if col_lower in ['devicename', 'nombreequipo', 'hostname', 'equipo', 'dispositivo', 'name', 'device', 'host', 'computername']:
            target = 'DeviceName'
        elif 'compliance' in col_lower or 'cumplimiento' in col_lower:
            target = 'Compliance'
        elif 'sistemaoperativo' in col_lower or col_lower in ['os', 'operatingsystem']:
            target = 'OperatingSystem'
        elif col_lower in ['estado', 'status']:
            target = 'Status'
        elif col_lower in ['areainfraestructura', 'environment', 'provider']:
            target = 'Environment'
        elif col_lower in ['componentenoconforme', 'vulnerablesoftware', 'software']:
            target = 'VulnerableSoftware'
        elif col_lower in ['vulnerabilityseveritylevel', 'severity']:
            target = 'Severity'
            
        if target and target not in assigned_targets and target != col:
            col_mapping[col] = target
            assigned_targets.add(target)
        elif target == col:
            assigned_targets.add(target)
            
    df.rename(columns=col_mapping, inplace=True)
    df = df.loc[:, ~df.columns.duplicated()].copy()
    
    if 'DeviceName' in df.columns:
        df['DeviceName'] = df['DeviceName'].fillna('Unknown')
        df['DeviceName'] = df['DeviceName'].astype(str).str.lower().str.strip()
        df['DeviceName'] = df['DeviceName'].apply(lambda x: x.split('.')[0] if '.' in x else x)
        
    if 'Status' in df.columns:
        status_map = {
            '🔴 Activo': '🔴 Active', '✅ Mitigado Manual': '✅ Manual Mitigation', '✅ Auto-Mitigado': '✅ Auto-Mitigated', 
            'Activo': '🔴 Active', 'Active': '🔴 Active', '🔴 Active': '🔴 Active',
            'Manual Mitigation': '✅ Manual Mitigation', 'Auto-Mitigated': '✅ Auto-Mitigated'
        }
        df['Status'] = df['Status'].replace(status_map)
        
    return df

def update_trend_history(df_master):
    if df_master.empty or 'Status' not in df_master.columns: return
    os.makedirs('datos_correlacionados', exist_ok=True)
    trend_file = 'datos_correlacionados/trend_history.csv'
    
    active_count = len(df_master[df_master['Status'] == '🔴 Active'])
    mitigated_count = len(df_master[df_master['Status'].astype(str).str.contains('Mitigat', case=False, na=False)])
    
    new_row = pd.DataFrame({'Date': [datetime.now().strftime('%Y-%m-%d %H:%M')], 'Active': [active_count], 'Mitigated': [mitigated_count]})
    
    if os.path.exists(trend_file):
        history_df = pd.read_csv(trend_file)
        history_df = pd.concat([history_df, new_row], ignore_index=True)
    else:
        history_df = new_row
        
    history_df.drop_duplicates(subset=['Date'], keep='last').to_csv(trend_file, index=False)

def get_recent_files():
    files = glob.glob('historico_csv/**/*.csv', recursive=True)
    if not files: return []
    files_by_type = {}
    for f in files:
        base_name = os.path.basename(f)
        parts = base_name.split('_')
        name_only = '_'.join(parts[:-1]) if len(parts) > 1 and parts[-1].replace('.csv', '').isdigit() else base_name.replace('.csv', '')
        mod_time = os.path.getmtime(f)
        if name_only not in files_by_type or mod_time > files_by_type[name_only]['time']:
            files_by_type[name_only] = {'path': f, 'time': mod_time, 'base_name': name_only}
    return list(files_by_type.values())

def load_specific_table(file_path):
    try:
        con = duckdb.connect(':memory:')
        query = f"SELECT DISTINCT * FROM read_csv_auto('{file_path}', ignore_errors=True)"
        return con.execute(query).df().drop_duplicates()
    except Exception:
        return pd.DataFrame()

def process_master_database():
    recent_files = get_recent_files()
    if not recent_files: return

    dfs_to_concat = []
    for info in recent_files:
        df = load_specific_table(info['path'])
        df = standardize_columns(df)
        if not df.empty:
            if 'Environment' not in df.columns:
                df['Environment'] = info['base_name']
            dfs_to_concat.append(df)

    if not dfs_to_concat: return
    
    df_all = pd.concat(dfs_to_concat, ignore_index=True)
    
    enrichment_cols = ['Compliance', 'OperatingSystem', 'Environment']
    for col in enrichment_cols:
        if col in df_all.columns:
            mapping = df_all.dropna(subset=[col]).drop_duplicates(subset=['DeviceName'], keep='last').set_index('DeviceName')[col]
            df_all[col] = df_all['DeviceName'].map(mapping)
            
    if 'CveId' in df_all.columns or 'VulnerableSoftware' in df_all.columns:
        cols_to_check = [c for c in ['CveId', 'VulnerableSoftware'] if c in df_all.columns]
        df_all = df_all.dropna(subset=cols_to_check, how='all')

    df_today = df_all.drop_duplicates()
    df_today = standardize_columns(df_today)
    
    df_today['Key'] = df_today['DeviceName'].astype(str) + "-" + df_today.get('CveId', pd.Series(['']*len(df_today))).astype(str) + "-" + df_today.get('VulnerableSoftware', pd.Series(['']*len(df_today))).astype(str)

    os.makedirs('datos_correlacionados', exist_ok=True)
    master_path = 'datos_correlacionados/base_global_maestra.csv'
    
    if os.path.exists(master_path):
        df_master = pd.read_csv(master_path)
        df_master = standardize_columns(df_master)
        
        if 'Key' not in df_master.columns:
            df_master['Key'] = df_master['DeviceName'].astype(str) + "-" + df_master.get('CveId', pd.Series(['']*len(df_master))).astype(str) + "-" + df_master.get('VulnerableSoftware', pd.Series(['']*len(df_master))).astype(str)
        
        df_master = df_master.drop_duplicates(subset=['Key'])
        
        if 'Status' in df_master.columns:
            status_memory = df_master.set_index('Key')['Status'].to_dict()
            df_today['Status'] = df_today['Key'].map(status_memory).fillna('🔴 Active')
        else:
            df_today['Status'] = '🔴 Active'
            
        keys_today = set(df_today['Key'])
        keys_old = set(df_master['Key'])
        keys_missing = keys_old - keys_today
        
        df_missing = df_master[df_master['Key'].isin(keys_missing)].copy()
        df_missing['Status'] = '✅ Auto-Mitigated'
        
        df_new = pd.concat([df_today, df_missing], ignore_index=True)
    else:
        df_today['Status'] = '🔴 Active'
        df_new = df_today

    df_new = df_new.drop_duplicates(subset=['Key']) 
    df_new.to_csv(master_path, index=False)
    update_trend_history(df_new)

@st.cache_data(ttl=300)
def fetch_cached_data(view_name):
    if view_name == "GLOBAL":
        path = 'datos_correlacionados/base_global_maestra.csv'
        df = pd.read_csv(path) if os.path.exists(path) else pd.DataFrame()
    else:
        files_info = get_recent_files()
        spec_path = next((info['path'] for info in files_info if info['base_name'] == view_name), None)
        df = load_specific_table(spec_path) if spec_path else pd.DataFrame()
        
    if not df.empty:
        df = standardize_columns(df)
        if 'Status' not in df.columns: df.insert(0, 'Status', '🔴 Active')
        
        if 'Key' not in df.columns:
            df['Key'] = df['DeviceName'].astype(str) + "-" + df.get('CveId', pd.Series(['']*len(df))).astype(str) + "-" + df.get('VulnerableSoftware', pd.Series(['']*len(df))).astype(str)
            
    return df

# ================= SIDEBAR MENU =================
st.sidebar.header("Operations")
if st.sidebar.button("Refresh Data (ETL)"):
    with st.spinner("Building Correlated Master Database..."):
        try:
            subprocess.run(["python", "src/data/data_processor.py"], capture_output=True, text=True)
            process_master_database()
            st.cache_data.clear() 
            st.sidebar.success("Correlation and Synchronization successful!")
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Error processing data: {e}")

st.sidebar.markdown("---")
st.sidebar.header("Navigation")
st.markdown('<div class="btn-nav">', unsafe_allow_html=True)
if st.sidebar.button("Executive Dashboard"): st.session_state.screen_mode = "Executive Dashboard"
if st.sidebar.button("Search & Mitigation"): st.session_state.screen_mode = "Search & Mitigation"
if st.sidebar.button("Patch Management"): st.session_state.screen_mode = "Patch Management"
st.markdown('</div>', unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.header("Data Source")
available_files = get_recent_files()
file_names = [info['base_name'] for info in available_files]

if not file_names:
    st.sidebar.warning("No historical data available.")
else:
    source_options = ["Global Correlated View"] + [t.replace('_', ' ').title() for t in file_names]
    selected_source = st.sidebar.selectbox("Select data view:", source_options, label_visibility="collapsed")
    st.session_state.current_view = "GLOBAL" if selected_source == "Global Correlated View" else file_names[source_options.index(selected_source) - 1]

df_actual = fetch_cached_data(st.session_state.current_view)

# =====================================================================
# PAGE 1: EXECUTIVE DASHBOARD
# =====================================================================
if st.session_state.screen_mode == "Executive Dashboard":
    st.title("Cloud Posture & Vulnerability Dashboard")
    
    if df_actual.empty:
        st.info("Master database is empty or not found. Process new CSVs to begin.")
    else:
        df_dash = df_actual.copy()
        sev_col = 'Severity' if 'Severity' in df_dash.columns else None
        df_active = df_dash[df_dash['Status'] == '🔴 Active'].copy()
        
        hora_actual = datetime.now().strftime('%H:%M:%S')
        total_equipos = df_dash['DeviceName'].nunique() if 'DeviceName' in df_dash.columns else 0
        criticas = len(df_active[df_active[sev_col].astype(str).str.contains('Critical', case=False, na=False)]) if sev_col else 0
        altas = len(df_active[df_active[sev_col].astype(str).str.contains('High', case=False, na=False)]) if sev_col else 0
        medias = len(df_active[df_active[sev_col].astype(str).str.contains('Medium|Mod', case=False, na=False)]) if sev_col else 0
        total_cves = df_active['CveId'].nunique() if 'CveId' in df_active.columns else 0

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1: st.markdown(f'<div class="cs-card border-crit"><div class="cs-card-title">Critical IOMs</div><div class="cs-card-value">{criticas}</div><div class="cs-card-footer">Last refreshed: {hora_actual}</div></div>', unsafe_allow_html=True)
        with col2: st.markdown(f'<div class="cs-card border-high"><div class="cs-card-title">High IOMs</div><div class="cs-card-value">{altas}</div><div class="cs-card-footer">Last refreshed: {hora_actual}</div></div>', unsafe_allow_html=True)
        with col3: st.markdown(f'<div class="cs-card border-med"><div class="cs-card-title">Medium IOMs</div><div class="cs-card-value">{medias}</div><div class="cs-card-footer">Last refreshed: {hora_actual}</div></div>', unsafe_allow_html=True)
        with col4: st.markdown(f'<div class="cs-card border-cve"><div class="cs-card-title">Total Active CVEs</div><div class="cs-card-value">{total_cves}</div><div class="cs-card-footer">Unique vulnerabilities</div></div>', unsafe_allow_html=True)
        with col5: st.markdown(f'<div class="cs-card border-info"><div class="cs-card-title">Impacted Assets</div><div class="cs-card-value">{total_equipos}</div><div class="cs-card-footer">Unique Devices</div></div>', unsafe_allow_html=True)

        col_c1, col_c2 = st.columns([7, 3])
        with col_c1:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Top Services with Vulnerabilities (Count by Severity)</div>', unsafe_allow_html=True)
                if 'VulnerableSoftware' in df_active.columns and sev_col and not df_active['VulnerableSoftware'].dropna().empty:
                    df_active['VulnerableSoftware'] = df_active['VulnerableSoftware'].fillna('Unknown')
                    df_active[sev_col] = df_active[sev_col].fillna('Unrated')
                    df_bar = df_active.groupby(['VulnerableSoftware', sev_col]).size().reset_index(name='Count')
                    top_comps = df_active['VulnerableSoftware'].value_counts().head(12).index
                    df_bar = df_bar[df_bar['VulnerableSoftware'].isin(top_comps)]
                    fig_bar = px.bar(df_bar, x='VulnerableSoftware', y='Count', color=sev_col, color_discrete_map={'Critical':'#E53935', 'High':'#F57C00', 'Medium':'#FFB300', 'Low':'#03A9F4', 'Unrated': '#9E9E9E'}, barmode='stack', template="plotly_dark")
                    fig_bar.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#B0B3BC', size=11), xaxis_title="", yaxis_title="Findings", legend_title="Severity", margin=dict(t=10, b=0, l=0, r=0))
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.markdown('<div class="empty-state">No Component data available in this view.</div>', unsafe_allow_html=True)
            
        with col_c2:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Top 10 Active CVEs</div>', unsafe_allow_html=True)
                if 'CveId' in df_active.columns and not df_active['CveId'].dropna().empty:
                    df_cve = df_active['CveId'].fillna('No CVE assigned').value_counts().head(10).reset_index()
                    df_cve.columns = ['CVE', 'Count']
                    fig_cve = px.pie(df_cve, names='CVE', values='Count', hole=0.6, template="plotly_dark", color_discrete_sequence=px.colors.qualitative.Pastel)
                    fig_cve.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#B0B3BC'), margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation='h', yanchor='top', y=-0.05, xanchor='center', x=0.5, font=dict(size=10)))
                    fig_cve.update_traces(textposition='inside', textinfo='percent', insidetextorientation='radial')
                    st.plotly_chart(fig_cve, use_container_width=True)
                    
                    with st.expander("📋 View & Copy Data"):
                        st.dataframe(df_cve, hide_index=True, use_container_width=True)
                else: 
                    st.markdown('<div class="empty-state">No CVE data available in this view.</div>', unsafe_allow_html=True)

        col_t1, col_t2 = st.columns(2)
        with col_t1:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Top 10 Most Vulnerable Devices</div>', unsafe_allow_html=True)
                if 'DeviceName' in df_active.columns and sev_col:
                    top_dev = df_active.groupby(['DeviceName', sev_col]).size().unstack(fill_value=0)
                    if 'Critical' in top_dev.columns: top_dev['SortScore'] = top_dev['Critical'] * 10
                    else: top_dev['SortScore'] = 0
                    if 'High' in top_dev.columns: top_dev['SortScore'] += top_dev['High']
                    top_dev = top_dev.sort_values('SortScore', ascending=False).head(10).drop(columns=['SortScore'], errors='ignore').reset_index()
                    st.dataframe(top_dev, use_container_width=True, hide_index=True)
                else:
                    st.markdown('<div class="empty-state">No Device data available in this view.</div>', unsafe_allow_html=True)

        with col_t2:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Configuration Assessments by Provider</div>', unsafe_allow_html=True)
                if 'Environment' in df_active.columns and not df_active['Environment'].dropna().empty:
                    top_area = df_active['Environment'].value_counts().reset_index()
                    top_area.columns = ['Cloud Provider / Environment', 'Findings']
                    st.dataframe(top_area, use_container_width=True, hide_index=True)
                else:
                    st.markdown('<div class="empty-state">No Environment data available in this view.</div>', unsafe_allow_html=True)

        col_d1, col_d2, col_d3 = st.columns(3)
        with col_d1:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Findings by Severity</div>', unsafe_allow_html=True)
                if sev_col and sev_col in df_active.columns and not df_active[sev_col].dropna().empty:
                    df_sev = df_active[sev_col].value_counts().reset_index()
                    df_sev.columns = ['Severity', 'Count']
                    fig_sev = px.pie(df_sev, names='Severity', values='Count', hole=0.6, template="plotly_dark", color='Severity', color_discrete_map={'Critical':'#E53935', 'High':'#F57C00', 'Medium':'#FFB300', 'Low':'#03A9F4'})
                    fig_sev.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#B0B3BC'), margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation='h', yanchor='top', y=-0.05, xanchor='center', x=0.5, font=dict(size=10)))
                    fig_sev.update_traces(textposition='inside', textinfo='percent', insidetextorientation='radial')
                    st.plotly_chart(fig_sev, use_container_width=True)
                    
                    with st.expander("📋 View & Copy Data"):
                        st.dataframe(df_sev, hide_index=True, use_container_width=True)
                else: 
                    st.markdown('<div class="empty-state">No Severity data available.</div>', unsafe_allow_html=True)

        with col_d2:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Top Actionable Patches / Updates</div>', unsafe_allow_html=True)
                if 'RecommendedSecurityUpdate' in df_active.columns and not df_active['RecommendedSecurityUpdate'].dropna().empty:
                    df_patch = df_active[df_active['RecommendedSecurityUpdate'].astype(str).str.lower() != 'none']
                    if not df_patch.empty:
                        df_patch = df_patch['RecommendedSecurityUpdate'].fillna('Unknown').value_counts().head(10).reset_index()
                        df_patch.columns = ['Security Update', 'Count']
                        
                        fig_patch = px.bar(df_patch, y='Security Update', x='Count', orientation='h', template="plotly_dark", color_discrete_sequence=['#3B82F6'])
                        fig_patch.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#B0B3BC', size=11), yaxis={'categoryorder':'total ascending'}, xaxis_title="", yaxis_title="", margin=dict(t=10, b=0, l=0, r=0))
                        st.plotly_chart(fig_patch, use_container_width=True)
                        
                        with st.expander("📋 View & Copy Data"):
                            st.dataframe(df_patch, hide_index=True, use_container_width=True)
                    else:
                        st.markdown('<div class="empty-state">No Specific Patches recommended in this view.</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="empty-state">No Patch Recommendation data available.</div>', unsafe_allow_html=True)
            
        with col_d3:
            with st.container(border=True):
                st.markdown('<div class="grid-title">Top 5 Devices with Findings</div>', unsafe_allow_html=True)
                if 'DeviceName' in df_active.columns and not df_active['DeviceName'].dropna().empty:
                    df_dev = df_active['DeviceName'].value_counts().head(5).reset_index()
                    df_dev.columns = ['Device Name', 'Count']
                    fig_dev = px.pie(df_dev, names='Device Name', values='Count', hole=0.6, template="plotly_dark", color_discrete_sequence=px.colors.sequential.Blues_r)
                    fig_dev.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#B0B3BC'), margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation='h', yanchor='top', y=-0.05, xanchor='center', x=0.5, font=dict(size=10)))
                    fig_dev.update_traces(textposition='inside', textinfo='percent', insidetextorientation='radial')
                    st.plotly_chart(fig_dev, use_container_width=True)
                    
                    with st.expander("📋 View & Copy Data"):
                        st.dataframe(df_dev, hide_index=True, use_container_width=True)
                else: 
                    st.markdown('<div class="empty-state">No Device data available in this view.</div>', unsafe_allow_html=True)

# =====================================================================
# PAGE 2: SEARCH, FILTERS & MITIGATION
# =====================================================================
elif st.session_state.screen_mode == "Search & Mitigation":
    st.title("Advanced Search and Mitigation")
    
    if df_actual.empty:
        st.info("Upload and process data to use the tool.")
    else:
        df_filtered = df_actual.copy()
        sev_col = 'Severity' if 'Severity' in df_filtered.columns else None
        
        st.markdown('<div class="filter-panel">', unsafe_allow_html=True)
        st.markdown("##### Global Search & Filters")
        
        busqueda_global = st.text_input("Global Search:", placeholder="Account ID, CVE, Component, Hostname...")
        if busqueda_global:
            mascara_busqueda = pd.Series(False, index=df_filtered.index)
            for col in df_filtered.columns:
                mascara_busqueda = mascara_busqueda | df_filtered[col].astype(str).str.contains(busqueda_global, case=False, na=False)
            df_filtered = df_filtered[mascara_busqueda]
        
        st.markdown("<hr style='margin: 10px 0;'>", unsafe_allow_html=True)
        
        col_f1, col_f2, col_f3, col_f4 = st.columns(4)
        with col_f1:
            if 'Status' in df_filtered.columns:
                filtro_estado = st.selectbox("Status", ["🔴 Active", "All", "✅ Mitigated"])
                if filtro_estado == "🔴 Active": df_filtered = df_filtered[df_filtered['Status'] == '🔴 Active']
                elif filtro_estado == "✅ Mitigated": df_filtered = df_filtered[df_filtered['Status'].astype(str).str.contains('Mitigat', case=False, na=False)]
        with col_f2:
            if sev_col:
                filtro_sev = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
                if filtro_sev != "All": df_filtered = df_filtered[df_filtered[sev_col].astype(str).str.contains(filtro_sev, case=False, na=False)]
        with col_f3:
            if 'Environment' in df_filtered.columns:
                filtro_area = st.multiselect("Cloud Provider / Region", [str(x) for x in df_actual['Environment'].dropna().unique()])
                if filtro_area: df_filtered = df_filtered[df_filtered['Environment'].astype(str).isin(filtro_area)]
        with col_f4:
            if 'Compliance' in df_filtered.columns:
                filtro_compliance = st.multiselect("Intune Compliance", [str(x) for x in df_actual['Compliance'].dropna().unique()])
                if filtro_compliance: df_filtered = df_filtered[df_filtered['Compliance'].astype(str).isin(filtro_compliance)]

        col_f5, col_f6 = st.columns(2)
        with col_f5:
            if 'OperatingSystem' in df_filtered.columns:
                filtro_os = st.multiselect("Operating System", [str(x) for x in df_actual['OperatingSystem'].dropna().unique()])
                if filtro_os: df_filtered = df_filtered[df_filtered['OperatingSystem'].astype(str).isin(filtro_os)]
        with col_f6:
            if 'VulnerableSoftware' in df_filtered.columns:
                filtro_comp = st.multiselect("Vulnerable Software", [str(x) for x in df_actual['VulnerableSoftware'].dropna().unique()])
                if filtro_comp: df_filtered = df_filtered[df_filtered['VulnerableSoftware'].astype(str).isin(filtro_comp)]
        
        st.markdown('</div>', unsafe_allow_html=True)

        activos_afectados = df_filtered['DeviceName'].nunique() if 'DeviceName' in df_filtered.columns else len(df_filtered)
        alertas_filtradas = len(df_filtered)
        st.markdown(f"**Search Results:** {alertas_filtradas} vulnerabilities across {activos_afectados} unique assets.")

        if 'Status' in df_filtered.columns:
            cols = ['Status'] + [col for col in df_filtered.columns if col not in ['Status', 'Key']]
            cols.append('Key') 
            df_filtered = df_filtered[cols]

        df_editado = st.data_editor(
            df_filtered,
            use_container_width=True,
            num_rows="dynamic",
            key=f"editor_{st.session_state.current_view}",
            column_config={
                "Status": st.column_config.SelectboxColumn("Status", options=["🔴 Active", "✅ Manual Mitigation", "✅ Auto-Mitigated"], required=True),
                "Key": None 
            }
        )

        st.markdown("---")
        col_btn1, col_btn2, col_btn3 = st.columns([2, 2, 4])
        with col_btn1:
            if st.button("Save Mitigations"):
                try:
                    if st.session_state.current_view == "GLOBAL":
                        df_maestro = pd.read_csv('datos_correlacionados/base_global_maestra.csv')
                        df_maestro = standardize_columns(df_maestro)
                        df_maestro = df_maestro.drop_duplicates(subset=['Key'])
                        
                        df_maestro.set_index('Key', inplace=True)
                        df_editado_seguro = df_editado.drop_duplicates(subset=['Key']).copy()
                        df_editado_seguro.set_index('Key', inplace=True)
                        
                        df_maestro.update(df_editado_seguro[['Status']])
                        df_maestro.reset_index(inplace=True)
                        
                        df_maestro.to_csv('datos_correlacionados/base_global_maestra.csv', index=False)
                        st.cache_data.clear() 
                        st.success("Mitigations successfully saved to Master Database.")
                    else:
                        os.makedirs('datos_editados/individuales', exist_ok=True)
                        df_editado.to_csv(f"datos_editados/individuales/{st.session_state.current_view}_status.csv", index=False)
                        st.cache_data.clear()
                        st.success("Mitigations saved in individual view.")
                except Exception as e:
                    st.error(f"Error saving data: {e}")
        with col_btn2:
            export_name = f"Vulnerability_Report_{st.session_state.current_view}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            df_export = df_editado.drop(columns=['Key'], errors='ignore')
            st.download_button("Export to CSV", data=df_export.to_csv(index=False).encode('utf-8'), file_name=export_name)


# =====================================================================
# PAGE 3: PATCH MANAGEMENT (Con Filtro CVE y KPIs en estilo cs-card)
# =====================================================================
elif st.session_state.screen_mode == "Patch Management":
    st.title("🛠️ Patch Management & Prioritization")
    
    if df_actual.empty:
        st.info("Upload and process data to use the tool.")
    else:
        # Patch Management se enfoca SOLO en las vulnerabilidades Activas
        df_patching = df_actual[df_actual['Status'] == '🔴 Active'].copy()
        sev_col = 'Severity' if 'Severity' in df_patching.columns else None
        
        st.markdown('<div class="filter-panel">', unsafe_allow_html=True)
        st.markdown("##### Filter by Target Architecture")
        col_p1, col_p2, col_p3, col_p4 = st.columns(4)
        
        with col_p1:
            if 'OperatingSystem' in df_patching.columns:
                filtro_os_p = st.multiselect("Target OS", [str(x) for x in df_patching['OperatingSystem'].dropna().unique()])
                if filtro_os_p: df_patching = df_patching[df_patching['OperatingSystem'].astype(str).isin(filtro_os_p)]
        
        with col_p2:
            if 'RecommendedSecurityUpdate' in df_patching.columns:
                filtro_patch = st.multiselect("Specific Patch/KB", [str(x) for x in df_patching['RecommendedSecurityUpdate'].dropna().unique() if str(x).lower() != 'none'])
                if filtro_patch: df_patching = df_patching[df_patching['RecommendedSecurityUpdate'].astype(str).isin(filtro_patch)]
        
        # NUEVO FILTRO POR CVE AQUÍ
        with col_p3:
            if 'CveId' in df_patching.columns:
                filtro_cve_p = st.multiselect("Specific CVE", [str(x) for x in df_actual['CveId'].dropna().unique()])
                if filtro_cve_p: df_patching = df_patching[df_patching['CveId'].astype(str).isin(filtro_cve_p)]

        with col_p4:
             if sev_col:
                filtro_sev_p = st.multiselect("Severity Filter", ["Critical", "High", "Medium", "Low"])
                if filtro_sev_p: df_patching = df_patching[df_patching[sev_col].astype(str).isin(filtro_sev_p)]
                
        st.markdown('</div>', unsafe_allow_html=True)

        # FORZAR a que las Críticas siempre salgan primero
        if sev_col and sev_col in df_patching.columns:
            sort_map = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Unrated': 5}
            df_patching['_sort_rank'] = df_patching[sev_col].map(sort_map).fillna(6)
            df_patching = df_patching.sort_values(by=['_sort_rank', 'DeviceName']).drop(columns=['_sort_rank'])

        # CÁLCULO DE KPIs
        crit_count = len(df_patching[df_patching[sev_col].astype(str).str.contains('Critical', case=False, na=False)]) if sev_col else 0
        high_count = len(df_patching[df_patching[sev_col].astype(str).str.contains('High', case=False, na=False)]) if sev_col else 0
        activos_afectados = df_patching['DeviceName'].nunique() if 'DeviceName' in df_patching.columns else len(df_patching)
        
        # NUEVO DISEÑO DE KPIs (Estilo Dashboard Principal)
        col_pk1, col_pk2, col_pk3, col_pk4 = st.columns(4)
        with col_pk1: st.markdown(f'<div class="cs-card border-info"><div class="cs-card-title">Assets to Patch</div><div class="cs-card-value">{activos_afectados}</div><div class="cs-card-footer">Unique Devices</div></div>', unsafe_allow_html=True)
        with col_pk2: st.markdown(f'<div class="cs-card border-crit"><div class="cs-card-title">Critical Vulnerabilities</div><div class="cs-card-value">{crit_count}</div><div class="cs-card-footer">Needs immediate action</div></div>', unsafe_allow_html=True)
        with col_pk3: st.markdown(f'<div class="cs-card border-high"><div class="cs-card-title">High Vulnerabilities</div><div class="cs-card-value">{high_count}</div><div class="cs-card-footer">Needs scheduled action</div></div>', unsafe_allow_html=True)
        with col_pk4: st.markdown(f'<div class="cs-card border-cve"><div class="cs-card-title">Total Pending Findings</div><div class="cs-card-value">{len(df_patching)}</div><div class="cs-card-footer">In current filter</div></div>', unsafe_allow_html=True)
        
        # Gráfico Interactivo de Parches
        if 'RecommendedSecurityUpdate' in df_patching.columns and not df_patching['RecommendedSecurityUpdate'].dropna().empty:
            df_graph = df_patching[df_patching['RecommendedSecurityUpdate'].astype(str).str.lower() != 'none']
            if not df_graph.empty:
                df_top = df_graph['RecommendedSecurityUpdate'].value_counts().head(10).reset_index()
                df_top.columns = ['Security Update', 'Count']
                fig_p = px.bar(df_top, y='Security Update', x='Count', orientation='h', template="plotly_dark", color_discrete_sequence=['#10B981'], title="Top Actionable Patches Needed")
                fig_p.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', yaxis={'categoryorder':'total ascending'}, margin=dict(t=30, b=0, l=0, r=0))
                st.plotly_chart(fig_p, use_container_width=True)

        # Editor de datos ordenado
        if 'Status' in df_patching.columns:
            cols = ['Status'] + [col for col in df_patching.columns if col not in ['Status', 'Key']]
            cols.append('Key') 
            df_patching = df_patching[cols]

        st.markdown("##### Prioritized Patching List")
        df_editado_p = st.data_editor(
            df_patching,
            use_container_width=True,
            num_rows="dynamic",
            key=f"editor_patch_{st.session_state.current_view}",
            column_config={"Status": st.column_config.SelectboxColumn("Status", options=["🔴 Active", "✅ Manual Mitigation", "✅ Auto-Mitigated"], required=True), "Key": None}
        )

        st.markdown("---")
        col_bp1, col_bp2 = st.columns([2, 6])
        with col_bp1:
            if st.button("Save Mitigations", key="btn_save_patch"):
                try:
                    if st.session_state.current_view == "GLOBAL":
                        df_maestro = pd.read_csv('datos_correlacionados/base_global_maestra.csv')
                        df_maestro = standardize_columns(df_maestro)
                        df_maestro = df_maestro.drop_duplicates(subset=['Key'])
                        
                        df_maestro.set_index('Key', inplace=True)
                        df_editado_seguro = df_editado_p.drop_duplicates(subset=['Key']).copy()
                        df_editado_seguro.set_index('Key', inplace=True)
                        
                        df_maestro.update(df_editado_seguro[['Status']])
                        df_maestro.reset_index(inplace=True)
                        
                        df_maestro.to_csv('datos_correlacionados/base_global_maestra.csv', index=False)
                        st.cache_data.clear() 
                        st.success("Mitigations successfully saved to Master Database.")
                    else:
                        os.makedirs('datos_editados/individuales', exist_ok=True)
                        df_editado_p.to_csv(f"datos_editados/individuales/{st.session_state.current_view}_status.csv", index=False)
                        st.cache_data.clear()
                        st.success("Mitigations saved in individual view.")
                except Exception as e:
                    st.error(f"Error saving data: {e}")
        with col_bp2:
            export_name = f"Patch_Plan_{st.session_state.current_view}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            df_export = df_editado_p.drop(columns=['Key'], errors='ignore')
            st.download_button("Export Prioritized List", data=df_export.to_csv(index=False).encode('utf-8'), file_name=export_name)