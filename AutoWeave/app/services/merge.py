import io
import pandas as pd
from fastapi import UploadFile

def _read_csv(upload: UploadFile) -> pd.DataFrame:
    # Read bytes -> text -> pandas
    raw = upload.file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return pd.read_csv(io.StringIO(text))

def _clean_headers(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df

def _trim_strings(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        if pd.api.types.is_object_dtype(df[col]):
            df[col] = df[col].astype(str).str.strip()
            # turn "nan" back into actual NaN if it came from astype(str)
            df.loc[df[col].str.lower().isin(["nan", "none", ""]), col] = pd.NA
    return df

def _preview_csv(df: pd.DataFrame, n: int = 25) -> str:
    return df.head(n).to_csv(index=False)

async def merge_autotrac_exports(
    projects_csv: UploadFile,
    incomes_csv: UploadFile,
    time_entries_csv: UploadFile,
):
    # UploadFile.file is a stream; ensure pointer is at start
    projects_csv.file.seek(0)
    incomes_csv.file.seek(0)
    time_entries_csv.file.seek(0)

    projects = _trim_strings(_clean_headers(_read_csv(projects_csv)))
    incomes = _trim_strings(_clean_headers(_read_csv(incomes_csv)))
    entries = _trim_strings(_clean_headers(_read_csv(time_entries_csv)))

    # MVP: we don't assume exact schema yet.
    # We'll attempt to find a join key, otherwise return cleaned trio stats and previews.
    candidate_keys = ["project_id", "projectId", "project", "project_name", "Project ID", "Project"]
    join_key = next((k for k in candidate_keys if k in projects.columns and k in incomes.columns and k in entries.columns), None)

    stats = {
        "projects": {"rows": int(len(projects)), "cols": int(projects.shape[1])},
        "incomes": {"rows": int(len(incomes)), "cols": int(incomes.shape[1])},
        "time_entries": {"rows": int(len(entries)), "cols": int(entries.shape[1])},
        "join_key_used": join_key,
    }

    if join_key:
        merged = entries.merge(projects, on=join_key, how="left", suffixes=("", "_project"))
        merged = merged.merge(incomes, on=join_key, how="left", suffixes=("", "_income"))
        stats["merged"] = {"rows": int(len(merged)), "cols": int(merged.shape[1])}
        return {
            "mode": "merged",
            "stats": stats,
            "preview_csv": _preview_csv(merged, 25),
            "download_csv": merged.to_csv(index=False),  # simplest MVP (can switch to streaming later)
        }

    return {
        "mode": "cleaned_only",
        "stats": stats,
        "message": "No common join key detected across all three files. Returning cleaned previews only.",
        "previews": {
            "projects_csv": _preview_csv(projects, 15),
            "incomes_csv": _preview_csv(incomes, 15),
            "time_entries_csv": _preview_csv(entries, 15),
        },
    }
