import io
import pandas as pd
from fastapi import UploadFile, HTTPException

MAX_BYTES = 10 * 1024 * 1024  # 10MB per file

JOIN_KEYS = ["project_id", "project_name"]
KEEP_COLS = [
    "project_id", "project_name",
    "start_time", "end_time", "duration_hours",
    "income_date", "amount", "currency", "amount_gbp",
]

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

def _strip_obj_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for c in df.columns:
        if pd.api.types.is_object_dtype(df[c]):
            df[c] = df[c].astype(str).str.strip()
            df.loc[df[c].str.lower().isin(["", "nan", "none"]), c] = pd.NA
    return df

def _drop_if_empty(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    df = df.copy()
    # treat empty strings/whitespace as NA already via _strip_obj_cols
    return df.dropna(subset=cols, how="any")

def _ensure_cols_exist(df: pd.DataFrame, cols: list[str], label: str):
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise HTTPException(status_code=400, detail=f"{label} missing required columns: {missing}")

def _preview(df: pd.DataFrame, n: int = 25) -> str:
    return df.head(n).to_csv(index=False)

def _select_keep_cols(df: pd.DataFrame) -> pd.DataFrame:
    # ensure all KEEP_COLS exist (as columns) so final selection is stable
    df = df.copy()
    for c in KEEP_COLS:
        if c not in df.columns:
            df[c] = pd.NA
    return df[KEEP_COLS]

async def trim_and_full_join(
    time_entries_csv: UploadFile,
    incomes_csv: UploadFile,
    projects_csv: UploadFile | None,
):
    # ---------- Read ----------
    entries_raw = _strip_obj_cols(_read_upload_csv(time_entries_csv))
    incomes_raw = _strip_obj_cols(_read_upload_csv(incomes_csv))

    projects_raw = None
    if projects_csv is not None:
        projects_raw = _strip_obj_cols(_read_upload_csv(projects_csv))

    stats = {
        "before": {
            "time_entries": {"rows": int(len(entries_raw)), "cols": int(entries_raw.shape[1])},
            "incomes": {"rows": int(len(incomes_raw)), "cols": int(incomes_raw.shape[1])},
            "projects": None if projects_raw is None else {"rows": int(len(projects_raw)), "cols": int(projects_raw.shape[1])},
        }
    }

    # ---------- Trim & normalize ----------
    # 1) entries trim
    _ensure_cols_exist(entries_raw, ["project_id", "project_name", "duration_hours"], "time_entries_csv")
    entries = entries_raw.copy()

    # duration_hours: if numeric NaN or empty -> drop
    # coerce duration_hours to numeric (invalid -> NaN)
    entries["duration_hours"] = pd.to_numeric(entries["duration_hours"], errors="coerce")
    entries = _drop_if_empty(entries, ["project_id", "project_name", "duration_hours"])

    # keep only needed cols from entries (plus join keys)
    needed_entries = JOIN_KEYS + ["start_time", "end_time", "duration_hours"]
    for c in needed_entries:
        if c not in entries.columns:
            entries[c] = pd.NA
    entries = entries[needed_entries]

    # 2) incomes trim + rename date -> income_date
    _ensure_cols_exist(incomes_raw, ["project_id", "project_name", "amount"], "incomes_csv")
    incomes = incomes_raw.copy()
    if "date" in incomes.columns and "income_date" not in incomes.columns:
        incomes = incomes.rename(columns={"date": "income_date"})

    # amount: treat empty as NA already; keep as text (don’t force numeric yet)
    incomes = _drop_if_empty(incomes, ["project_id", "project_name", "amount"])

    needed_incomes = JOIN_KEYS + ["income_date", "amount", "currency", "amount_gbp"]
    for c in needed_incomes:
        if c not in incomes.columns:
            incomes[c] = pd.NA
    incomes = incomes[needed_incomes]

    # 3) projects optional: rename id->project_id, name->project_name
    projects = None
    if projects_raw is not None:
        projects = projects_raw.copy()
        # rename only if the old names exist
        ren = {}
        if "id" in projects.columns: ren["id"] = "project_id"
        if "name" in projects.columns: ren["name"] = "project_name"
        projects = projects.rename(columns=ren)

        _ensure_cols_exist(projects, ["project_id", "project_name"], "projects_csv")
        projects = _drop_if_empty(projects, ["project_id", "project_name"])

        # keep only join keys (per your spec)
        projects = projects[JOIN_KEYS].drop_duplicates()

    stats["after_trim"] = {
        "time_entries": {"rows": int(len(entries)), "cols": int(entries.shape[1])},
        "incomes": {"rows": int(len(incomes)), "cols": int(incomes.shape[1])},
        "projects": None if projects is None else {"rows": int(len(projects)), "cols": int(projects.shape[1])},
    }

    # ---------- FULL OUTER JOIN ----------
    # Note: outer join on (project_id, project_name)
    merged = pd.merge(entries, incomes, on=JOIN_KEYS, how="outer")

    if projects is not None:
        merged = pd.merge(merged, projects, on=JOIN_KEYS, how="outer")

    merged = _select_keep_cols(merged)

    stats["merged"] = {"rows": int(len(merged)), "cols": int(merged.shape[1])}

    return {
        "mode": "merged",
        "stats": stats,
        "preview_csv": _preview(merged, 25),
        "download_csv": merged.to_csv(index=False),
    }
