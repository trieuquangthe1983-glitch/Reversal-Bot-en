"""Shared pytest fixtures: isolated DB per test + generated keypair."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    """Each test gets its own state dir + DB + freshly generated keypair."""
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("LICENSE_STATE_DIR", str(state))
    monkeypatch.setenv("LICENSE_DB_PATH", str(state / "licenses.db"))
    # Generate a fresh keypair for this test
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (state / "master_private.pem").write_bytes(pem)
    # Reset module caches
    import importlib
    import db, crypto, blockchain, tiers, app as app_mod
    importlib.reload(db)
    importlib.reload(crypto)
    importlib.reload(blockchain)
    importlib.reload(tiers)
    importlib.reload(app_mod)
    db.init_db()
    yield
    db.close_thread_connection()
