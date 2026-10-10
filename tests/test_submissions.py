"""Tests for Stage 2 user submission endpoints."""

import base64
import hashlib

from fastapi.testclient import TestClient

PNG_DATA_URI = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\nfake-image").decode()


def _expected_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_url_submission_becomes_stored_candidate(client: TestClient) -> None:
    """A URL submission is persisted and readable with a matching content hash."""
    content = "http://evil.example/login"

    created = client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": content, "source": "analyst"},
    )

    assert created.status_code == 201
    body = created.json()
    assert body["submission_type"] == "url"
    assert body["content"] == content
    assert body["content"] != ""
    assert body["content_hash"] == _expected_hash(content)
    assert body["source"] == "analyst"
    assert body["brand_id"] is None
    assert body["created_at"]

    fetched = client.get(f"/api/v1/submissions/{body['id']}")
    assert fetched.status_code == 200
    assert fetched.json() == body


def test_message_submission_stored(client: TestClient) -> None:
    """A text message submission is stored as raw evidence."""
    content = "Your account is suspended, click http://bit.example/x now"

    response = client.post(
        "/api/v1/submissions", json={"submission_type": "message", "content": content}
    )

    assert response.status_code == 201
    body = response.json()
    assert body["content"] == content
    assert body["content_hash"] == _expected_hash(content)
    assert body["source"] == "user"


def test_screenshot_data_uri_submission_stored(client: TestClient) -> None:
    """An image supplied as a base64 data URI is stored with its hash."""
    response = client.post(
        "/api/v1/submissions",
        json={"submission_type": "screenshot", "content": PNG_DATA_URI},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["content"] == PNG_DATA_URI
    assert body["content_hash"] == _expected_hash(PNG_DATA_URI)


def test_screenshot_url_submission_stored(client: TestClient) -> None:
    """A screenshot referenced by URL is accepted as evidence."""
    content = "https://cdn.example/shot.png"

    response = client.post(
        "/api/v1/submissions", json={"submission_type": "screenshot", "content": content}
    )

    assert response.status_code == 201
    assert response.json()["content_hash"] == _expected_hash(content)


def test_social_profile_handle_and_url_stored(client: TestClient) -> None:
    """Social profiles are accepted as @handles or URLs and persisted."""
    handle = "@acme_support"
    handle_response = client.post(
        "/api/v1/submissions",
        json={"submission_type": "social_profile", "content": handle},
    )
    assert handle_response.status_code == 201
    assert handle_response.json()["content_hash"] == _expected_hash(handle)

    url = "https://social.example/acme_support"
    url_response = client.post(
        "/api/v1/submissions",
        json={"submission_type": "social_profile", "content": url},
    )
    assert url_response.status_code == 201
    assert url_response.json()["content_hash"] == _expected_hash(url)


def test_app_listing_submission_stored(client: TestClient) -> None:
    """An app store listing URL is accepted as evidence."""
    content = "https://play.example/store/apps/details?id=com.fake.acme"

    response = client.post(
        "/api/v1/submissions", json={"submission_type": "app_listing", "content": content}
    )

    assert response.status_code == 201
    assert response.json()["submission_type"] == "app_listing"
    assert response.json()["content_hash"] == _expected_hash(content)


def test_submission_associates_with_brand_when_provided(client: TestClient) -> None:
    """Submissions can reference a brand but do not require one."""
    brand = client.post("/api/v1/brands", json={"name": "Acme"}).json()

    linked = client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": "http://a.example/", "brand_id": brand["id"]},
    )
    assert linked.status_code == 201
    assert linked.json()["brand_id"] == brand["id"]

    unlinked = client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": "http://b.example/"},
    )
    assert unlinked.status_code == 201
    assert unlinked.json()["brand_id"] is None


def test_submission_with_unknown_brand_rejected(client: TestClient) -> None:
    """A submission naming a missing brand fails with a clear error."""
    response = client.post(
        "/api/v1/submissions",
        json={"submission_type": "url", "content": "http://a.example/", "brand_id": 999},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Brand not found"


def test_invalid_submission_type_rejected(client: TestClient) -> None:
    """Only the five supported submission types are accepted."""
    response = client.post(
        "/api/v1/submissions", json={"submission_type": "hologram", "content": "x"}
    )

    assert response.status_code == 422


def test_url_type_requires_http_url(client: TestClient) -> None:
    """The url type rejects non-URL content with a clear message."""
    response = client.post(
        "/api/v1/submissions", json={"submission_type": "url", "content": "not a url"}
    )

    assert response.status_code == 422
    assert "http(s) URL" in str(response.json())


def test_screenshot_type_requires_image_data(client: TestClient) -> None:
    """The screenshot type rejects plain text and broken base64."""
    bad_values = (
        "just words",
        "data:image/png;base64,@@not-base64@@",
        "data:text/plain;base64,aGk=",
    )
    for bad in bad_values:
        response = client.post(
            "/api/v1/submissions", json={"submission_type": "screenshot", "content": bad}
        )
        assert response.status_code == 422


def test_social_profile_rejects_plain_text(client: TestClient) -> None:
    """The social_profile type requires a URL or an @handle."""
    response = client.post(
        "/api/v1/submissions", json={"submission_type": "social_profile", "content": "acme"}
    )

    assert response.status_code == 422


def test_blank_content_rejected(client: TestClient) -> None:
    """Empty or whitespace-only content never becomes a stored candidate."""
    empty = client.post("/api/v1/submissions", json={"submission_type": "message", "content": ""})
    assert empty.status_code == 422

    blank = client.post(
        "/api/v1/submissions", json={"submission_type": "message", "content": "   "}
    )
    assert blank.status_code == 422


def test_unknown_submission_returns_404(client: TestClient) -> None:
    """Reading a submission that was never stored returns not-found."""
    assert client.get("/api/v1/submissions/999").status_code == 404


def test_identical_content_stored_twice_with_same_hash(client: TestClient) -> None:
    """Hashes identify content; they do not block storing equal evidence twice."""
    content = "http://duplicate.example/"
    first = client.post("/api/v1/submissions", json={"submission_type": "url", "content": content})
    second = client.post("/api/v1/submissions", json={"submission_type": "url", "content": content})

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
    assert first.json()["content_hash"] == second.json()["content_hash"] == _expected_hash(content)
