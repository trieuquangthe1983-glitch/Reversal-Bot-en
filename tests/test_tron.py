"""Tests for Tron (TRC20) USDT verification."""
from __future__ import annotations
from unittest.mock import patch

import pytest


class TestBase58:
    def test_payment_wallet_roundtrip(self):
        from tron import b58_to_hex, hex_to_b58, PAYMENT_WALLET_TRON
        h = b58_to_hex(PAYMENT_WALLET_TRON)
        assert h.startswith("41")     # Tron mainnet prefix
        assert hex_to_b58(h) == PAYMENT_WALLET_TRON

    def test_usdt_contract_roundtrip(self):
        from tron import b58_to_hex, hex_to_b58, USDT_TRC20_BASE58
        h = b58_to_hex(USDT_TRC20_BASE58)
        assert hex_to_b58(h) == USDT_TRC20_BASE58

    def test_bad_address_rejected(self):
        from tron import b58_to_hex
        with pytest.raises(ValueError, match="checksum"):
            b58_to_hex("T" + "X" * 33)


def _mock_tron_tx_info(tier_amount=29.0, to_padded_hex=None, valid=True):
    """Build a fake TronGrid getTransactionInfo response."""
    from tron import (PAYMENT_WALLET_HEX, USDT_TRC20_HEX,
                     TRANSFER_EVENT_TOPIC, USDT_TRC20_DECIMALS)
    raw_amount = int(tier_amount * (10 ** USDT_TRC20_DECIMALS))
    if to_padded_hex is None:
        to_padded_hex = "0" * 24 + PAYMENT_WALLET_HEX[2:]
    return {
        "id": "a" * 64,
        "blockNumber": 1_000_000,
        "receipt": {"result": "SUCCESS" if valid else "FAILED"},
        "log": [{
            "address": USDT_TRC20_HEX[2:],   # without 0x41 prefix
            "topics": [
                TRANSFER_EVENT_TOPIC,
                "0" * 24 + "b" * 40,           # from
                to_padded_hex,                  # to
            ],
            "data": f"{raw_amount:064x}",
        }],
    }


class TestVerifyTronPayment:
    def test_happy_path_monthly(self):
        from tron import verify_tron_payment
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(tier_amount=39.0)), \
             patch("tron._get_current_block", return_value=1_000_100):
            proof = verify_tron_payment("a" * 64, expected_tier="monthly")
            assert proof.matched_tier == "monthly"
            assert proof.amount_usdt == 39.0
            assert proof.confirmations >= 20

    def test_lifetime(self):
        from tron import verify_tron_payment
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(tier_amount=569.0)), \
             patch("tron._get_current_block", return_value=1_000_100):
            proof = verify_tron_payment("a" * 64, expected_tier="lifetime")
            assert proof.matched_tier == "lifetime"

    def test_failed_tx_rejected(self):
        from tron import verify_tron_payment, TronPaymentVerifyError
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(tier_amount=39.0, valid=False)), \
             patch("tron._get_current_block", return_value=1_000_100):
            with pytest.raises(TronPaymentVerifyError, match="execution failed"):
                verify_tron_payment("a" * 64, expected_tier="monthly")

    def test_wrong_recipient_rejected(self):
        from tron import verify_tron_payment, TronPaymentVerifyError
        # Different "to" address
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(
                       tier_amount=29.0,
                       to_padded_hex="0" * 24 + "deadbeef" * 5)), \
             patch("tron._get_current_block", return_value=1_000_100):
            with pytest.raises(TronPaymentVerifyError, match="no USDT-TRC20 transfer"):
                verify_tron_payment("a" * 64, expected_tier="trial")

    def test_amount_mismatch_rejected(self):
        from tron import verify_tron_payment, TronPaymentVerifyError
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(tier_amount=50.0)), \
             patch("tron._get_current_block", return_value=1_000_100):
            with pytest.raises(TronPaymentVerifyError, match="does not match any tier"):
                verify_tron_payment("a" * 64, expected_tier="monthly")

    def test_insufficient_confirmations(self):
        from tron import verify_tron_payment, TronPaymentVerifyError
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(tier_amount=29.0)), \
             patch("tron._get_current_block", return_value=1_000_005):   # only 5
            with pytest.raises(TronPaymentVerifyError, match="confirmations"):
                verify_tron_payment("a" * 64, expected_tier="trial")

    def test_bad_tx_hash_format(self):
        from tron import verify_tron_payment, TronPaymentVerifyError
        with pytest.raises(TronPaymentVerifyError, match="invalid Tron tx hash"):
            verify_tron_payment("notahash", expected_tier="trial")

    def test_wrong_tier_requested(self):
        """Tx sent 29 USDT but customer claims they paid for monthly (39)."""
        from tron import verify_tron_payment, TronPaymentVerifyError
        with patch("tron._get_tx_info",
                   return_value=_mock_tron_tx_info(tier_amount=29.0)), \
             patch("tron._get_current_block", return_value=1_000_100):
            with pytest.raises(TronPaymentVerifyError, match="matches the trial tier"):
                verify_tron_payment("a" * 64, expected_tier="monthly")


class TestPricingExposesBothNetworks:
    def test_pricing_includes_networks(self, monkeypatch):
        monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "x")
        from fastapi.testclient import TestClient
        import importlib, app as app_mod
        importlib.reload(app_mod)
        c = TestClient(app_mod.app)
        r = c.get("/pricing")
        assert r.status_code == 200
        j = r.json()
        assert "networks" in j
        nets = {n["id"]: n for n in j["networks"]}
        assert "bsc" in nets
        assert "tron" in nets
        assert nets["bsc"]["wallet"].lower().startswith("0xfde5")
        assert nets["tron"]["wallet"].startswith("TCXQ")
        assert "buyer pays" in j["fee_policy"].lower()


class TestVerifyPaymentDispatch:
    def test_network_tron_dispatches_to_tron_verifier(self, monkeypatch):
        monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "x")
        from fastapi.testclient import TestClient
        import importlib, app as app_mod
        importlib.reload(app_mod)
        from tron import TronPaymentProof
        c = TestClient(app_mod.app)

        tron_proof = TronPaymentProof(
            tx_hash="a" * 64,
            from_address="TX" + "x" * 32,
            to_address="TCXQjLBqE79ALwzMSXneQXUHtyymDTXapt",
            amount_usdt=29.0,
            block_number=1_000_000,
            confirmations=25,
            matched_tier="trial",
            raw_info={},
        )
        with patch("app.verify_tron_payment", return_value=tron_proof):
            r = c.post("/verify-payment", json={
                "tx_hash": "a" * 64,
                "tier": "trial",
                "machine_id": "abc123def456" + "0" * 12,
                "network": "tron",
            })
            assert r.status_code == 200, r.text
            j = r.json()
            assert j["tier"] == "trial"
            assert "token" in j

    def test_unknown_network_rejected(self, monkeypatch):
        monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "x")
        from fastapi.testclient import TestClient
        import importlib, app as app_mod
        importlib.reload(app_mod)
        c = TestClient(app_mod.app)
        r = c.post("/verify-payment", json={
            "tx_hash": "a" * 64,
            "tier": "trial",
            "machine_id": "abc123def456" + "0" * 12,
            "network": "ethereum",
        })
        assert r.status_code == 400
        assert "unsupported network" in r.json()["detail"].lower()


class TestTolerance:
    def test_strict_tolerance_05_cents(self):
        from tiers import match_tier_by_amount
        assert match_tier_by_amount(29.0).name == "trial"
        assert match_tier_by_amount(29.03).name == "trial"   # within 0.05
        assert match_tier_by_amount(28.94) is None           # outside 0.05
        assert match_tier_by_amount(38.50) is None           # way off monthly (39)
