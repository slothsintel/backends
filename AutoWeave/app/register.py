@router.post("/auth/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.execute(
        select(OwUser).where(OwUser.email == data.email.lower())
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = OwUser(
        email=data.email.lower(),
        password_hash=hash_password(data.password),
        is_email_verified=False,
    )
    db.add(user)
    db.commit()

    return {"ok": True}
