@router.post("/auth/forgot")
def forgot(data: ForgotRequest, db: Session = Depends(get_db)):
    user = db.execute(
        select(OwUser).where(OwUser.email == data.email.lower())
    ).scalar_one_or_none()

    if user:
        token = secrets.token_urlsafe(32)

        reset = OwPasswordReset(
            user_id=user.id,
            token_hash=hash_password(token),
            expires_at=datetime.utcnow() + timedelta(minutes=30),
        )
        db.add(reset)
        db.commit()

        # TODO: send email with token link

    return {"ok": True}
