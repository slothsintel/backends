from fastapi import APIRouter, UploadFile, File, HTTPException
from .services.merge import trim_and_full_join

router = APIRouter()

@router.post("/merge/autotrac")
async def merge_autotrac(
    time_entries_csv: UploadFile = File(...),
    incomes_csv: UploadFile = File(...),
    projects_csv: UploadFile | None = File(None),
):
    # basic extension check
    required = [time_entries_csv, incomes_csv]
    if projects_csv is not None:
        required.append(projects_csv)

    for f in required:
        if not f.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail=f"Expected .csv file, got: {f.filename}")

    return await trim_and_full_join(
        time_entries_csv=time_entries_csv,
        incomes_csv=incomes_csv,
        projects_csv=projects_csv,
    )
