import shutil
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATOS_DIARIOS = PROJECT_ROOT / "datos_diarios"
DATOS_PROCESADOS = PROJECT_ROOT / "datos_procesados"
HISTORICO_CSV = PROJECT_ROOT / "historico_csv"

INT64_MAX = np.iinfo(np.int64).max
INT64_MIN = np.iinfo(np.int64).min


def preparar_para_parquet(df: pd.DataFrame) -> pd.DataFrame:
    """Normaliza tipos incompatibles con PyArrow (p. ej. enteros fuera de rango int64)."""
    df = df.copy()

    for col in df.columns:
        dtype = df[col].dtype

        if pd.api.types.is_integer_dtype(dtype):
            col_max = df[col].max(skipna=True)
            col_min = df[col].min(skipna=True)
            if pd.notna(col_max) and (col_max > INT64_MAX or col_min < INT64_MIN):
                df[col] = df[col].astype(str)
        elif dtype == object:
            df[col] = df[col].astype(str)

    return df


def procesar_csvs() -> None:
    """
    Convierte CSV diarios a Parquet particionados por fecha y archiva los originales.

    Cada ejecución usa una marca de tiempo (HHMMSS) para evitar sobrescrituras
    si se procesan varias cargas el mismo día.
    """
    ahora = datetime.now()
    fecha_actual = ahora.strftime("%Y-%m-%d")
    marca_tiempo = ahora.strftime("%H%M%S")

    carpeta_parquet = DATOS_PROCESADOS / fecha_actual
    carpeta_historico = HISTORICO_CSV / fecha_actual
    carpeta_parquet.mkdir(parents=True, exist_ok=True)
    carpeta_historico.mkdir(parents=True, exist_ok=True)

    archivos_csv = sorted(DATOS_DIARIOS.glob("*.csv"))

    if not archivos_csv:
        print("Aviso: la carpeta 'datos_diarios' está vacía o no contiene archivos .csv.")
        return

    for archivo_csv in archivos_csv:
        df = pd.read_csv(archivo_csv)
        df = preparar_para_parquet(df)

        nombre_parquet = f"{archivo_csv.stem}_{marca_tiempo}.parquet"
        archivo_parquet = carpeta_parquet / nombre_parquet
        df.to_parquet(archivo_parquet, index=False, engine="pyarrow")
        print(f"Convertido: {archivo_csv.name} -> {fecha_actual}/{nombre_parquet}")

        nombre_csv_historico = f"{archivo_csv.stem}_{marca_tiempo}.csv"
        destino_csv = carpeta_historico / nombre_csv_historico
        shutil.move(str(archivo_csv), str(destino_csv))
        print(f"Archivado: {archivo_csv.name} -> historico_csv/{fecha_actual}/{nombre_csv_historico}")

    print(
        f"\nÉxito: {len(archivos_csv)} archivo(s) procesado(s) en "
        f"'{DATOS_PROCESADOS.name}/{fecha_actual}'."
    )


if __name__ == "__main__":
    procesar_csvs()
