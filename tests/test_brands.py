"""Tests for Stage 1 brand intelligence endpoints."""

from fastapi.testclient import TestClient

from risk_radar.db.models import AssetType


def test_create_brand_and_list_assets(client: TestClient) -> None:
    """Acceptance: a brand profile can be created and its assets listed."""
    brand_response = client.post("/api/v1/brands", json={"name": "Acme"})
    assert brand_response.status_code == 201
    brand = brand_response.json()

    domain = client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "domain", "value": "acme.example", "verified": True},
    )
    assert domain.status_code == 201

    account = client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "account", "value": "@acme"},
    )
    assert account.status_code == 201

    listing = client.get(f"/api/v1/brands/{brand['id']}/assets")
    assert listing.status_code == 200
    assets = listing.json()
    assert len(assets) == 2

    by_type = {asset["asset_type"]: asset for asset in assets}
    assert by_type["domain"]["value"] == "acme.example"
    assert by_type["domain"]["verified"] is True
    assert by_type["account"]["value"] == "@acme"
    assert by_type["account"]["verified"] is False


def test_read_brand_profile(client: TestClient) -> None:
    """A created brand profile can be read back by its identifier."""
    created = client.post("/api/v1/brands", json={"name": "Acme"}).json()

    response = client.get(f"/api/v1/brands/{created['id']}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["name"] == "Acme"


def test_duplicate_brand_name_rejected(client: TestClient) -> None:
    """The official brand name uniquely identifies a profile."""
    assert client.post("/api/v1/brands", json={"name": "Acme"}).status_code == 201

    duplicate = client.post("/api/v1/brands", json={"name": "Acme"})

    assert duplicate.status_code == 409


def test_asset_requires_existing_brand(client: TestClient) -> None:
    """Assets cannot be attached to a brand that does not exist."""
    response = client.post(
        "/api/v1/brands/999/assets",
        json={"asset_type": AssetType.DOMAIN.value, "value": "ghost.example"},
    )

    assert response.status_code == 404


def test_unknown_brand_returns_404(client: TestClient) -> None:
    """Reading a missing brand profile returns a not-found error."""
    assert client.get("/api/v1/brands/999").status_code == 404


def test_invalid_asset_type_rejected(client: TestClient) -> None:
    """Only the five official asset kinds are accepted."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()

    response = client.post(
        f"/api/v1/brands/{brand['id']}/assets",
        json={"asset_type": "hologram", "value": "x"},
    )

    assert response.status_code == 422


def test_blank_brand_name_rejected(client: TestClient) -> None:
    """An empty brand name cannot create a profile."""
    response = client.post("/api/v1/brands", json={"name": ""})

    assert response.status_code == 422
