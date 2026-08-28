"""Create the first account without putting its password in source code or shell history."""

from getpass import getpass

from app.main import Base, PASSWORD_HASHER, SessionLocal, User, engine, normalize_username, utc_now


def main() -> None:
    username = input("Initial username [D2N1K]: ").strip() or "D2N1K"
    try:
        username = normalize_username(username)
    except ValueError as error:
        raise SystemExit(str(error))

    password = getpass("Password: ")
    confirmation = getpass("Repeat password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as database:
        existing = database.query(User).filter(User.username_normalized == username.casefold()).first()
        if existing:
            raise SystemExit("This username already exists.")
        now = utc_now()
        database.add(
            User(
                username=username,
                username_normalized=username.casefold(),
                password_hash=PASSWORD_HASHER.hash(password),
                created_at=now,
                updated_at=now,
            )
        )
        database.commit()
    print("Initial account created.")


if __name__ == "__main__":
    main()
