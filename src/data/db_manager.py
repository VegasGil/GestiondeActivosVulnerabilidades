"""
Gestor de base de datos DuckDB para Gestión de Activos y Vulnerabilidades.

Centraliza la carga histórica de Parquet y el análisis comparativo de alertas.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATOS_PROCESADOS = PROJECT_ROOT / "datos_procesados"
DB_PATH = PROJECT_ROOT / "asset_management.db"

# Columnas que identifican de forma única una vulnerabilidad entre cargas diarias.
COLUMNAS_VULNERABILIDAD = ("DeviceName", "ComponenteNoConforme")
PATRON_ARCHIVO_ALERTAS = "%alertas%"


def get_connection() -> duckdb.DuckDBPyConnection:
    """Abre (o crea) la base de datos local asset_management.db."""
    return duckdb.connect(str(DB_PATH))


def _patron_parquet() -> str:
    """Devuelve el patrón glob de Parquet en formato compatible con DuckDB."""
    return (DATOS_PROCESADOS / "**" / "*.parquet").as_posix()


def _existen_parquet() -> bool:
    """Comprueba si hay al menos un archivo Parquet procesado."""
    return any(DATOS_PROCESADOS.rglob("*.parquet"))


def cargar_datos(conexion: duckdb.DuckDBPyConnection | None = None) -> int:
    """
    Lee recursivamente todos los Parquet en datos_procesados/**/*.parquet
    y crea/actualiza las vistas históricas en DuckDB.

    Returns:
        Número de archivos Parquet detectados.
    """
    cerrar_al_finalizar = conexion is None
    con = conexion or get_connection()

    try:
        if not _existen_parquet():
            print("Aviso: no se encontraron archivos .parquet en 'datos_procesados'.")
            return 0

        patron = _patron_parquet()

        # Vista general con metadatos extraídos de la ruta del archivo.
        con.execute(
            f"""
            CREATE OR REPLACE VIEW historico_datos AS
            SELECT
                regexp_extract(
                    filename,
                    '[\\\\/]([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})[\\\\/]',
                    1
                ) AS fecha_carga,
                regexp_extract(filename, '([^/\\\\]+)\\.parquet$', 1) AS nombre_archivo,
                filename AS ruta_archivo,
                *
            FROM read_parquet('{patron}', filename=true, union_by_name=true)
            """
        )

        # Vista filtrada para análisis de vulnerabilidades (archivos de alertas).
        con.execute(
            f"""
            CREATE OR REPLACE VIEW historico_vulnerabilidades AS
            SELECT *
            FROM historico_datos
            WHERE lower(nombre_archivo) LIKE '{PATRON_ARCHIVO_ALERTAS}'
              AND DeviceName IS NOT NULL
              AND ComponenteNoConforme IS NOT NULL
            """
        )

        total = con.execute(
            f"""
            SELECT COUNT(DISTINCT filename)
            FROM read_parquet('{patron}', filename=true)
            """
        ).fetchone()[0]

        print(f"Datos cargados: {total} archivo(s) Parquet indexados en DuckDB.")
        return total

    finally:
        if cerrar_al_finalizar:
            con.close()


def _obtener_fecha_anterior(con: duckdb.DuckDBPyConnection, fecha_actual: str) -> str | None:
    """Obtiene la fecha de carga inmediatamente anterior a fecha_actual."""
    resultado = con.execute(
        """
        SELECT MAX(fecha_carga) AS fecha_anterior
        FROM historico_vulnerabilidades
        WHERE fecha_carga < ?
        """,
        [fecha_actual],
    ).fetchone()

    return resultado[0] if resultado else None


def _vulnerabilidades_por_fecha(con: duckdb.DuckDBPyConnection, fecha: str) -> pd.DataFrame:
    """
    Devuelve vulnerabilidades únicas para una fecha, consolidando varias cargas del mismo día.
    """
    return con.execute(
        """
        SELECT DISTINCT
            DeviceName,
            ComponenteNoConforme,
            Severity,
            TotalAtaquesFrenados
        FROM historico_vulnerabilidades
        WHERE fecha_carga = ?
        ORDER BY DeviceName, ComponenteNoConforme
        """,
        [fecha],
    ).df()


def analizar_vulnerabilidades(
    fecha_actual: str,
    conexion: duckdb.DuckDBPyConnection | None = None,
) -> dict[str, Any]:
    """
    Compara vulnerabilidades de fecha_actual contra la fecha anterior disponible.

    Clasificación:
        - nuevas: presentes hoy y ausentes ayer.
        - repetidas: presentes en ambos días.
        - mitigadas: presentes ayer y ausentes hoy.

    Args:
        fecha_actual: Fecha en formato YYYY-MM-DD.
        conexion: Conexión DuckDB opcional (útil para pruebas o Streamlit).

    Returns:
        Diccionario con DataFrames clasificados y metadatos del análisis.
    """
    cerrar_al_finalizar = conexion is None
    con = conexion or get_connection()

    try:
        cargar_datos(con)

        total_hoy = con.execute(
            """
            SELECT COUNT(DISTINCT (DeviceName, ComponenteNoConforme))
            FROM historico_vulnerabilidades
            WHERE fecha_carga = ?
            """,
            [fecha_actual],
        ).fetchone()[0]

        if total_hoy == 0:
            raise ValueError(
                f"No hay vulnerabilidades registradas para la fecha '{fecha_actual}'."
            )

        fecha_anterior = _obtener_fecha_anterior(con, fecha_actual)

        if fecha_anterior is None:
            nuevas = _vulnerabilidades_por_fecha(con, fecha_actual)
            return {
                "fecha_actual": fecha_actual,
                "fecha_anterior": None,
                "nuevas": nuevas,
                "repetidas": pd.DataFrame(columns=list(COLUMNAS_VULNERABILIDAD) + ["Severity", "TotalAtaquesFrenados"]),
                "mitigadas": pd.DataFrame(columns=list(COLUMNAS_VULNERABILIDAD) + ["Severity", "TotalAtaquesFrenados"]),
            }

        nuevas = con.execute(
            """
            SELECT DISTINCT h.DeviceName, h.ComponenteNoConforme, h.Severity, h.TotalAtaquesFrenados
            FROM historico_vulnerabilidades h
            WHERE h.fecha_carga = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM historico_vulnerabilidades a
                  WHERE a.fecha_carga = ?
                    AND a.DeviceName = h.DeviceName
                    AND a.ComponenteNoConforme = h.ComponenteNoConforme
              )
            ORDER BY h.DeviceName, h.ComponenteNoConforme
            """,
            [fecha_actual, fecha_anterior],
        ).df()

        repetidas = con.execute(
            """
            SELECT DISTINCT h.DeviceName, h.ComponenteNoConforme, h.Severity, h.TotalAtaquesFrenados
            FROM historico_vulnerabilidades h
            INNER JOIN historico_vulnerabilidades a
                ON a.DeviceName = h.DeviceName
               AND a.ComponenteNoConforme = h.ComponenteNoConforme
            WHERE h.fecha_carga = ?
              AND a.fecha_carga = ?
            ORDER BY h.DeviceName, h.ComponenteNoConforme
            """,
            [fecha_actual, fecha_anterior],
        ).df()

        mitigadas = con.execute(
            """
            SELECT DISTINCT a.DeviceName, a.ComponenteNoConforme, a.Severity, a.TotalAtaquesFrenados
            FROM historico_vulnerabilidades a
            WHERE a.fecha_carga = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM historico_vulnerabilidades h
                  WHERE h.fecha_carga = ?
                    AND h.DeviceName = a.DeviceName
                    AND h.ComponenteNoConforme = a.ComponenteNoConforme
              )
            ORDER BY a.DeviceName, a.ComponenteNoConforme
            """,
            [fecha_anterior, fecha_actual],
        ).df()

        return {
            "fecha_actual": fecha_actual,
            "fecha_anterior": fecha_anterior,
            "nuevas": nuevas,
            "repetidas": repetidas,
            "mitigadas": mitigadas,
        }

    finally:
        if cerrar_al_finalizar:
            con.close()


if __name__ == "__main__":
    from datetime import date

    cargar_datos()

    hoy = date.today().isoformat()
    try:
        resultado = analizar_vulnerabilidades(hoy)
        print(f"\nAnálisis de vulnerabilidades ({resultado['fecha_actual']}):")
        if resultado["fecha_anterior"]:
            print(f"Comparado contra: {resultado['fecha_anterior']}")
        else:
            print("Sin fecha anterior disponible (primera carga).")

        for categoria in ("nuevas", "repetidas", "mitigadas"):
            total = len(resultado[categoria])
            print(f"  {categoria.capitalize()}: {total}")
    except ValueError as error:
        print(f"Aviso: {error}")
