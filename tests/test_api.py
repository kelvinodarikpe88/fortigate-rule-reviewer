from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
KEY = {"x-api-key": "test-key"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_review_needs_a_key(client):
    assert client.post("/v1/review", json={"config": "x" * 40}).status_code == 401


def test_review_returns_findings_with_change_requests(client):
    response = client.post(
        "/v1/review",
        headers=KEY,
        json={"config": (FIXTURES / "planted.conf").read_text()},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["findings"] == 9
    assert all("change_request" in f for f in body["findings"])
    assert body["findings"][0]["change_request_source"] == "template"


def test_config_without_policy_block_is_422(client):
    response = client.post("/v1/review", headers=KEY, json={"config": "hostname fw\n" * 5})
    assert response.status_code == 422


def test_clean_config_returns_no_findings(client):
    response = client.post(
        "/v1/review", headers=KEY, json={"config": (FIXTURES / "clean.conf").read_text()}
    )
    assert response.json()["summary"]["findings"] == 0
