# 🛡️ Gestión de Activos y Vulnerabilidades (Asset Management)

Dashboard interno para automatizar el triage diario de vulnerabilidades exportadas
desde **Microsoft Defender for Endpoint** (consultas KQL de Servidores Linux y
Workstations/Móviles), eliminando el trabajo manual de comparar reportes CSV día a
día para saber qué es nuevo, qué sigue abierto y qué ya se mitigó.

---

## 1. ¿Qué resuelve este proyecto?

Hoy el flujo es manual: descargar el CSV de Defender, abrirlo, y comparar a ojo
contra el del día anterior para ver qué cambió. Esto no escala y es fácil pasar
por alto una vulnerabilidad crítica recurrente.

`Gestión de Activos y Vulnerabilidades (Asset Management)` automatiza ese trabajo:

1. Tú solo creas una carpeta con la fecha del día y dejas ahí los CSV exportados de Defender.
2. La app (o un script de línea de comandos) convierte cada CSV a **Parquet**
   (mucho más liviano y rápido de consultar) y lo registra en una base **DuckDB**.
3. Un motor determinista (no depende de un LLM para esto, así no hay alucinaciones)
   compara automáticamente el snapshot del día contra el histórico acumulado y
   clasifica cada hallazgo como **Nueva**, **Recurrente** o **Mitigada**.
4. Un dashboard en **Streamlit** muestra KPIs, tablas filtrables por consulta,
   gráficos de criticidad y, opcionalmente, un resumen ejecutivo generado por un
   LLM (Anthropic Claude u OpenAI) que **interpreta** los números ya calculados,
# GestiondeActivosVulnerabilidades
Proyecto para la gestión de activos y vulnerabilidades. La interfaz se construirá con **Streamlit** y el almacenamiento y consulta de datos se realizará con **DuckDB**.
