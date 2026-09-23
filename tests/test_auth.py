import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — ensure models are registered with Base
from app.database import Base, get_db
from app.main import app


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def register_user(client: TestClient, email: str, password: str):
    return client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )


def login_user(client: TestClient, email: str, password: str):
    return client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )


def test_register_creates_user(client: TestClient):
    response = register_user(client, "alice@example.com", "StrongPass123!")

    assert response.status_code in (200, 201)
    assert response.json()["email"] == "alice@example.com"
    assert "password" not in response.json()


def test_register_rejects_duplicate_email(client: TestClient):
    payload = {"email": "alice@example.com", "password": "StrongPass123!"}
    first_response = client.post("/auth/register", json=payload)
    second_response = client.post("/auth/register", json=payload)

    assert first_response.status_code in (200, 201)
    assert second_response.status_code in (400, 409, 422)


def test_login_returns_bearer_token_for_valid_credentials(client: TestClient):
    register_user(client, "alice@example.com", "StrongPass123!")

    response = login_user(client, "alice@example.com", "StrongPass123!")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body.get("access_token"), str)
    assert body["access_token"]
    assert body.get("token_type", "bearer").lower() == "bearer"


def test_login_rejects_incorrect_password(client: TestClient):
    register_user(client, "alice@example.com", "StrongPass123!")

    response = login_user(client, "alice@example.com", "WrongPassword123!")

    assert response.status_code == 401


def test_login_rejects_unknown_user(client: TestClient):
    response = login_user(client, "missing@example.com", "StrongPass123!")

    assert response.status_code == 401


def test_current_user_requires_authentication(client: TestClient):
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_current_user_accepts_valid_access_token(client: TestClient):
    register_user(client, "alice@example.com", "StrongPass123!")
    login_response = login_user(client, "alice@example.com", "StrongPass123!")
    token = login_response.json()["access_token"]

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_current_user_rejects_invalid_token(client: TestClient):
    response = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 401
