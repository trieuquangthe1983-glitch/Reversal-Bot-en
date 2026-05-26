"""End-to-end tests for the license server FastAPI app.

BSC verification is mocked — we test the orchestration, signing, and
anti-fraud logic without hitting real RPC.
"""
from __future__ import annotations
import os
from unittest.mock import patch

import pytest


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "test-admin-token-secret")
    from fastapi.testclient import TestClient
    import importlib, app as app_mod
    importlib.reload(app_mod)
    return TestClient(app_mod.app)


def _mock_proof(tier="monthly", tx="0x" + "a" * 64, amount=None):
    from blockchain import PaymentProof
    from tiers import TIERS
    return PaymentProof(
        tx_hash=tx,
        from_address="0x" + "b" * 40,
        to_address="0xfde5be00ba5db63a93abf7922ee831db62257550",
        amount_usdt=amount if amount is not None else TIERS[tier].price_usdt,
        block_number=10_000_000,
        confirmations=20,
        matched_tier=tier,
        raw_receipt={"logs": [{}]},
    )


class TestPublicEndpoints:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_pricing(self, client):
        r = client.get("/pricing")
        assert r.status_code == 200
        j = r.json()
        assert len(j["tiers"]) == 5
        assert j["payment"]["wallet"].lower().startswith("0xfde5be00")
        assert j["support_email"] == "dht.io.vn@gmail.com"

    def test_public_key(self, client):
        r = client.get("/public-key")
        assert r.status_code == 200
        pem = r.json()["public_key_pem"]
        assert "BEGIN PUBLIC KEY" in pem


class TestBuyerFlow:
    def test_full_happy_path(self, client):
        with patch("app.verify_bsc_payment", return_value=_mock_proof("monthly")):
            r = client.post("/verify-payment", json={
                "tx_hash": "0x" + "a" * 64,
                "tier": "monthly",
                "machine_id": "abc123def456" + "0" * 12,
            })
            assert r.status_code == 200, r.text
            j = r.json()
            assert "token" in j
            assert j["tier"] == "monthly"
            token = j["token"]
        # Activate
        r = client.post("/activate", json={
            "token": token,
            "machine_id": "abc123def456" + "0" * 12,
        })
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["ok"] is True
        assert j["tier"] == "monthly"
        # Heartbeat
        r = client.post("/heartbeat", json={"token": token})
        assert r.status_code == 200
        j = r.json()
        assert j["is_active"] is True
        assert j["tier"] == "monthly"

    def test_unknown_tier_rejected(self, client):
        r = client.post("/verify-payment", json={
            "tx_hash": "0x" + "a" * 64,
            "tier": "platinum",        # bogus
            "machine_id": "abc123def456" + "0" * 12,
        })
        assert r.status_code == 400

    def test_tx_reuse_rejected(self, client):
        tx = "0x" + "c" * 64
        with patch("app.verify_bsc_payment", return_value=_mock_proof("monthly", tx=tx)):
            r1 = client.post("/verify-payment", json={
                "tx_hash": tx, "tier": "monthly",
                "machine_id": "abc123def456" + "0" * 12,
            })
            assert r1.status_code == 200
            # Second attempt with same tx
            r2 = client.post("/verify-payment", json={
                "tx_hash": tx, "tier": "monthly",
                "machine_id": "abc123def456" + "0" * 12,
            })
            assert r2.status_code == 400
            assert "already been used" in r2.json()["detail"]

    def test_trial_one_shot_per_machine(self, client):
        mid = "abc123def456" + "0" * 12
        with patch("app.verify_bsc_payment",
                   return_value=_mock_proof("trial", tx="0x" + "1" * 64)):
            r1 = client.post("/verify-payment", json={
                "tx_hash": "0x" + "1" * 64, "tier": "trial",
                "machine_id": mid,
            })
            assert r1.status_code == 200
        with patch("app.verify_bsc_payment",
                   return_value=_mock_proof("trial", tx="0x" + "2" * 64)):
            r2 = client.post("/verify-payment", json={
                "tx_hash": "0x" + "2" * 64, "tier": "trial",
                "machine_id": mid,
            })
            assert r2.status_code == 400
            assert "no longer available" in r2.json()["detail"].lower() \
                or "first license" in r2.json()["detail"].lower()

    def test_trial_locked_after_paid_license(self, client):
        """Trial must be the FIRST license. Once a paid tier is activated,
        trial is permanently locked on that machine."""
        mid = "abc123def456" + "0" * 12
        # First: buy monthly
        with patch("app.verify_bsc_payment",
                   return_value=_mock_proof("monthly", tx="0x" + "f" * 64)):
            r = client.post("/verify-payment", json={
                "tx_hash": "0x" + "f" * 64, "tier": "monthly", "machine_id": mid,
            })
            assert r.status_code == 200
        # Now try trial on same machine
        with patch("app.verify_bsc_payment",
                   return_value=_mock_proof("trial", tx="0x" + "e" * 64)):
            r = client.post("/verify-payment", json={
                "tx_hash": "0x" + "e" * 64, "tier": "trial", "machine_id": mid,
            })
            assert r.status_code == 400
            assert "first license" in r.json()["detail"].lower() \
                or "no longer available" in r.json()["detail"].lower()

    def test_trial_eligible_endpoint(self, client):
        """/trial-eligible/<mid> reports True for fresh machine."""
        mid = "fresh" + "0" * 19
        r = client.get(f"/trial-eligible/{mid}")
        assert r.status_code == 200
        assert r.json()["trial_eligible"] is True

    def test_trial_eligible_false_after_any_license(self, client):
        mid = "abc123def456" + "0" * 12
        with patch("app.verify_bsc_payment",
                   return_value=_mock_proof("annual", tx="0x" + "d" * 64)):
            client.post("/verify-payment", json={
                "tx_hash": "0x" + "d" * 64, "tier": "annual", "machine_id": mid,
            })
        r = client.get(f"/trial-eligible/{mid}")
        assert r.status_code == 200
        assert r.json()["trial_eligible"] is False
        assert "active annual" in r.json()["reason"].lower() \
            or "prior license" in r.json()["reason"].lower()

    def test_activate_wrong_machine_rejected(self, client):
        with patch("app.verify_bsc_payment", return_value=_mock_proof("monthly")):
            r = client.post("/verify-payment", json={
                "tx_hash": "0x" + "a" * 64, "tier": "monthly",
                "machine_id": "machineA" + "0" * 16,
            })
            token = r.json()["token"]
        # Try to activate on machine B
        r = client.post("/activate", json={
            "token": token,
            "machine_id": "machineB" + "0" * 16,
        })
        assert r.status_code == 400
        assert "different machine" in r.json()["detail"]

    def test_heartbeat_after_revoke(self, client):
        # Issue + activate
        with patch("app.verify_bsc_payment", return_value=_mock_proof("monthly")):
            r = client.post("/verify-payment", json={
                "tx_hash": "0x" + "d" * 64, "tier": "monthly",
                "machine_id": "abc123def456" + "0" * 12,
            })
            j = r.json()
            token, license_id = j["token"], j["license_id"]
        client.post("/activate", json={
            "token": token, "machine_id": "abc123def456" + "0" * 12})
        # Revoke
        r = client.post(f"/admin/revoke/{license_id}",
                        params={"reason": "test"},
                        headers={"x-admin-token": "test-admin-token-secret"})
        assert r.status_code == 200
        # Heartbeat now shows revoked
        r = client.post("/heartbeat", json={"token": token})
        assert r.status_code == 200
        j = r.json()
        assert j["is_active"] is False
        assert j.get("revoked") is True

    def test_invalid_token_rejected_on_activate(self, client):
        r = client.post("/activate", json={
            "token": "not-a-real-token.bogus-sig",
            "machine_id": "abc123def456" + "0" * 12,
        })
        assert r.status_code == 400


class TestRateLimit:
    def test_rate_limit_blocks_after_5_failures(self, client):
        from blockchain import PaymentVerifyError
        with patch("app.verify_bsc_payment",
                   side_effect=PaymentVerifyError("invalid")):
            for _ in range(5):
                client.post("/verify-payment", json={
                    "tx_hash": "0x" + "9" * 64, "tier": "monthly",
                    "machine_id": "abc123def456" + "0" * 12,
                })
            # 6th
            r = client.post("/verify-payment", json={
                "tx_hash": "0x" + "9" * 64, "tier": "monthly",
                "machine_id": "abc123def456" + "0" * 12,
            })
            assert r.status_code == 429


class TestAdmin:
    def test_admin_requires_token(self, client):
        r = client.get("/admin/list")
        assert r.status_code == 401

    def test_admin_with_token(self, client):
        r = client.get("/admin/list",
                       headers={"x-admin-token": "test-admin-token-secret"})
        assert r.status_code == 200
        assert r.json() == []   # nothing yet

    def test_admin_list_shows_issued_licenses(self, client):
        with patch("app.verify_bsc_payment", return_value=_mock_proof("monthly")):
            client.post("/verify-payment", json={
                "tx_hash": "0x" + "e" * 64, "tier": "monthly",
                "machine_id": "abc123def456" + "0" * 12,
            })
        r = client.get("/admin/list",
                       headers={"x-admin-token": "test-admin-token-secret"})
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["tier"] == "monthly"
