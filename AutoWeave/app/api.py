from fastapi import APIRouter, UploadFile, File, HTTPException
from .services.merge import trim_aggregate_and_join

router = APIRouter()

@router.post("/merge/autotrac")
async def merge_autotrac(
    time_entries_csv: UploadFile = File(...),
    incomes_csv: UploadFile = File(...),
    projects_csv: UploadFile | None = File(None),
):
    files = [time_entries_csv, incomes_csv] + ([projects_csv] if projects_csv else [])
    for f in files:
        if not f.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail=f"Expected .csv file, got: {f.filename}")

    return await trim_aggregate_and_join(time_entries_csv, incomes_csv, projects_csv)
