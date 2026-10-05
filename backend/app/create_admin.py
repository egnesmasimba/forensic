"""Run from backend: python -m app.create_admin"""
from getpass import getpass

from app.auth import AccountCreate, hash_password
from app.main import app, ensure_database_schema
from app.models import User


def main():
    ensure_database_schema(app.state.engine)
    with app.state.session_factory() as db:
        if db.query(User).filter_by(role="administrator").first():
            raise SystemExit("An administrator already exists. Use account management after signing in.")
        username = input("Administrator username: ")
        password = getpass("Password (at least 12 characters): ")
        if password != getpass("Repeat password: "):
            raise SystemExit("Passwords do not match.")
        account = AccountCreate(username=username, password=password, role="administrator")
        db.add(User(username=account.username, password_hash=hash_password(account.password), role=account.role))
        db.commit()
        print("Administrator created. Sign in through ZANAQ Forensic smart.")


if __name__ == "__main__":
    main()
