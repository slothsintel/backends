import io
import pandas as pd
from fastapi import UploadFile, HTTPException

MAX_BYTES = 10 * 1024 * 1024  # 10MB per file (safe default for Render free)

def _read_upload_csv(upload: UploadFile) -> pd.DataFrame:
    upload.file.seek(0)
    raw = upload.file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"{upload.filename} exceeds {MAX_BYTES//1024//1024}MB limit")

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    df = pd.read_csv(io.StringIO(text))
    df.columns = [str(c).strip() for c in df.columns]
    return df

def _trim_strings(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.columns:
        if pd.api.types.is_object_dtype(df[col]):
            s = df[col].astype(str).str.strip()
            s = s.mask(s.str.lower().isin(["nan", "none", ""]), pd.NA)
            df[col] = s
    return df

def _preview(df: pd.DataFrame, n: int = 25) -> str:
    return df.head(n).to_csv(index=False)

def _detect_join_key(projects: pd.DataFrame, incomes: pd.DataFrame, entries: pd.DataFrame) -> str | None:
    candidates = [
        "project_id", "projectId", "Project ID", "ProjectID",
        "project", "Project", "project_name", "Project Name",
    ]
    for k in candidates:
        if k in projects.columns and k in incomes.columns and k in entries.columns:
            return k
    return None

async def merge_autotrac_exports(
    projects_csv: UploadFile,
    incomes_csv: UploadFile,
    time_entries_csv: UploadFile,
):
    projects = _trim_strings(_read_upload_csv(projects_csv))
    incomes  = _trim_strings(_read_upload_csv(incomes_csv))
    entries  = _trim_strings(_read_upload_csv(time_entries_csv))

    join_key = _detect_join_key(projects, incomes, entries)

    stats = {
        "projects": {"rows": int(len(projects)), "cols": int(projects.shape[1])},
        "incomes": {"rows": int(len(incomes)), "cols": int(incomes.shape[1])},
        "time_entries": {"rows": int(len(entries)), "cols": int(entries.shape[1])},
        "join_key_used": join_key,
    }

    if not join_key:
        return {
            "mode": "cleaned_only",
            "stats": stats,
            "message": "No common join key detected across all three files yet.",
            "previews": {
                "projects_csv": _preview(projects, 15),
                "incomes_csv": _preview(incomes, 15),
                "time_entries_csv": _preview(entries, 15),
            },
        }

    merged = entries.merge(projects, on=join_key, how="left", suffixes=("", "_project"))
    merged = merged.merge(incomes, on=join_key, how="left", suffixes=("", "_income"))

    stats["merged"] = {"rows": int(len(merged)), "cols": int(merged.shape[1])}

    return {
        "mode": "merged",
        "stats": stats,
        "preview_csv": _preview(merged, 25),
        "download_csv": merged.to_csv(index=False),
    }
