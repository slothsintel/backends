import io
import pandas as pd
from fastapi import UploadFile, HTTPException

MAX_BYTES = 10 * 1024 * 1024  # 10MB per file

JOIN_KEYS = ["project_id", "project_name", "date"]
FINAL_COLS = [
    "project_id",
    "project_name",
    "date",
    "duration_hours",
    "amount",
    "currency",
    "amount_gbp",
]


def _read_upload_csv(upload: UploadFile) -> pd.DataFrame:
    upload.file.seek(0)
    raw = upload.file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"{upload.filename} exceeds {MAX_BYTES//1024//1024}MB limit",
        )

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
            s = df[c].astype(str).str.strip()
            s = s.mask(s.str.lower().isin(["", "nan", "none"]), pd.NA)
            df[c] = s
    return df


def _ensure_cols_exist(df: pd.DataFrame, cols: list[str], label: str):
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise HTTPException(status_code=400, detail=f"{label} missing required columns: {missing}")


def _drop_if_empty(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    return df.dropna(subset=cols, how="any")


def _to_date(series: pd.Series) -> pd.Series:
    dt = pd.to_datetime(series, errors="coerce", utc=True)
    return dt.dt.date


def _preview(df: pd.DataFrame, n: int = 25) -> str:
    return df.head(n).to_csv(index=False)


def _ensure_final_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for c in FINAL_COLS:
        if c not in df.columns:
            df[c] = pd.NA
    return df[FINAL_COLS]


async def trim_aggregate_and_join(
    time_entries_csv: UploadFile,
    incomes_csv: UploadFile,
    projects_csv: UploadFile | None,
):
    # --------------------
    # READ
    # --------------------
    entries_raw = _strip_obj_cols(_read_upload_csv(time_entries_csv))
    incomes_raw = _strip_obj_cols(_read_upload_csv(incomes_csv))

    projects_raw = None
    if projects_csv is not None:
        projects_raw = _strip_obj_cols(_read_upload_csv(projects_csv))

    stats = {
        "before": {
            "time_entries": {"rows": int(len(entries_raw)), "cols": int(entries_raw.shape[1])},
            "incomes": {"rows": int(len(incomes_raw)), "cols": int(incomes_raw.shape[1])},
            "projects": None if projects_raw is None else {
                "rows": int(len(projects_raw)),
                "cols": int(projects_raw.shape[1]),
            },
        }
    }

    # ============================================================
    # 1) TIME ENTRIES
    # ============================================================
    _ensure_cols_exist(entries_raw, ["project_id", "project_name", "duration_hours"], "time_entries_csv")
    entries = entries_raw.copy()

    entries["duration_hours"] = pd.to_numeric(entries["duration_hours"], errors="coerce")
    entries = _drop_if_empty(entries, ["project_id", "project_name", "duration_hours"])

    # Derive date from start_time fallback end_time
    start_d = _to_date(entries["start_time"]) if "start_time" in entries.columns else pd.Series([pd.NA]*len(entries))
    end_d = _to_date(entries["end_time"]) if "end_time" in entries.columns else pd.Series([pd.NA]*len(entries))

    entries["date"] = start_d
    entries.loc[entries["date"].isna(), "date"] = end_d
    # Aggregate duration_hours by project_id, project_name, date
    time_agg = (
        entries
        .groupby(["project_id", "project_name", "date"], as_index=False, dropna=False)
        .agg(duration_hours=("duration_hours", "sum"))
    )

    stats["after_time_trim_agg"] = {
        "rows": int(len(time_agg)),
        "cols": int(time_agg.shape[1]),
    }

    # ============================================================
    # 2) INCOMES
    # ============================================================
    _ensure_cols_exist(incomes_raw, ["project_id", "project_name", "amount"], "incomes_csv")
    incomes = incomes_raw.copy()

    if "date" not in incomes.columns and "income_date" in incomes.columns:
        incomes = incomes.rename(columns={"income_date": "date"})

    _ensure_cols_exist(incomes, ["date"], "incomes_csv")

    incomes["amount"] = pd.to_numeric(incomes["amount"], errors="coerce")
    incomes = _drop_if_empty(incomes, ["project_id", "project_name", "amount"])

    incomes["date"] = _to_date(incomes["date"])

    if "amount_gbp" in incomes.columns:
        incomes["amount_gbp"] = pd.to_numeric(incomes["amount_gbp"], errors="coerce")
    else:
        incomes["amount_gbp"] = pd.NA

    income_agg = (
        incomes
        .groupby(["project_id", "project_name", "date"], as_index=False, dropna=False)
        .agg(
            amount=("amount", "sum"),
            amount_gbp=("amount_gbp", "sum"),
            currency=("currency", lambda s: s.dropna().iloc[0] if len(s.dropna()) else pd.NA),
        )
    )

    stats["after_income_trim_agg"] = {
        "rows": int(len(income_agg)),
        "cols": int(income_agg.shape[1]),
    }

    # ============================================================
    # 3) PROJECTS (OPTIONAL)
    # ============================================================
    proj = None
    if projects_raw is not None:
        proj = projects_raw.copy()
        ren = {}
        if "id" in proj.columns:
            ren["id"] = "project_id"
        if "name" in proj.columns:
            ren["name"] = "project_name"
        proj = proj.rename(columns=ren)

        _ensure_cols_exist(proj, ["project_id", "project_name"], "projects_csv")
        proj = _drop_if_empty(proj, ["project_id", "project_name"])
        proj = proj[["project_id", "project_name"]].drop_duplicates()

    # ============================================================
    # 4) FULL OUTER JOIN BY project_id + project_name + date
    # ============================================================
    merged = pd.merge(time_agg, income_agg,
                      on=["project_id", "project_name", "date"],
                      how="outer")

    if proj is not None:
        merged = pd.merge(merged, proj,
                          on=["project_id", "project_name"],
                          how="outer")

    # NEW RULE: Deduplicate final rows
    merged_out = merged.drop_duplicates()

    merged_out = _ensure_final_cols(merged_out)
    stats["final_joined"] = {
        "rows": int(len(merged_out)),
        "cols": int(merged_out.shape[1]),
    }
    return {
        "mode": "trim_agg_full_join_dedup",
        "stats": stats,
        "preview_csv": _preview(merged_out, 10),
        "download_csv": merged_out.to_csv(index=False),
    }
