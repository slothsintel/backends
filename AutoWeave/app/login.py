@router.post("/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.execute(
        select(OwUser).where(OwUser.email == data.email.lower())
    ).scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(str(user.id))

    return {
        "access_token": token,
        "token_type": "bearer",
    }
