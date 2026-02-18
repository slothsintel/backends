from fastapi import APIRouter, UploadFile, File, HTTPException
from .services.merge import merge_autotrac_exports

router = APIRouter()

@router.post("/merge/autotrac")
async def merge_autotrac(
    projects_csv: UploadFile = File(...),
    incomes_csv: UploadFile = File(...),
    time_entries_csv: UploadFile = File(...),
):
    # Basic content-type sanity (browsers may send application/vnd.ms-excel for csv)
    for f in (projects_csv, incomes_csv, time_entries_csv):
        if not f.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail=f"Expected CSV file, got: {f.filename}")

    result = await merge_autotrac_exports(
        projects_csv=projects_csv,
        incomes_csv=incomes_csv,
        time_entries_csv=time_entries_csv,
    )
    return result
