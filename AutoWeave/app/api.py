from fastapi import APIRouter, UploadFile, File, HTTPException
from .services.merge import merge_autotrac_exports

router = APIRouter()

@router.post("/merge/autotrac")
async def merge_autotrac(
    projects_csv: UploadFile = File(...),
    incomes_csv: UploadFile = File(...),
    time_entries_csv: UploadFile = File(...),
):
    for f in (projects_csv, incomes_csv, time_entries_csv):
        if not f.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail=f"Expected .csv file, got: {f.filename}")

    return await merge_autotrac_exports(projects_csv, incomes_csv, time_entries_csv)
