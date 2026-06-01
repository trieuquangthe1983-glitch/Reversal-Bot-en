# Reversal Bot License Server

Standalone FastAPI service that signs license tokens for the Reversal Bot.

**Architecture**: Customer's bot has only the public Ed25519 key. This server has the private key. Customer pays USDT-BEP20 → submits tx_hash → server verifies on BSC → server signs token → returns to customer. Tokens can be verified offline by any bot using the embedded public key, so bots run without internet 99% of the time (heartbeat once per 7 days max).

See [DEPLOY.md](DEPLOY.md) for full setup walkthrough.

## Quick start (local)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Generate keypair (once)
python scripts/generate_master_keys.py

# Set admin token
export LICENSE_ADMIN_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")

# Run server
uvicorn app:app --reload --port 8000
```

Test:
```bash
curl http://localhost:8000/health
curl http://localhost:8000/pricing
curl http://localhost:8000/public-key
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | /health | none | Liveness probe |
| GET | /pricing | none | Tier list + payment wallet info |
| GET | /public-key | none | Ed25519 public key (PEM) |
| POST | /verify-payment | none | Verify BSC tx + mint signed token |
| POST | /activate | none | Re-verify signature + register activation |
| POST | /heartbeat | none | Bot reports in, server returns revocation/expiry |
| GET | /admin/list | admin | List all issued licenses |
| POST | /admin/revoke/{id} | admin | Revoke a license |
| POST | /admin/peek-token | admin | Debug a token without verifying |

## Deployment options

- **Fly.io**: free tier, persistent volume, auto-SSL → see `fly.toml`
- **Railway.app**: free tier, easy GitHub-based deploy → see `railway.json`
- **VPS + Docker**: full control → see `docker-compose.yml`

All deployment paths are covered step-by-step in [DEPLOY.md](DEPLOY.md).

## Security model

- **Private key** lives ONLY on the server (`MASTER_PRIVATE_KEY` env var)
- **Public key** ships embedded in the bot binary; safe to be extracted
- **Admin token** gates `/admin/*` endpoints; rotate periodically
- **Rate limiting**: 5 failed attempts per IP per hour
- **tx_hash uniqueness**: each on-chain payment can only mint one license
- **Trial gate**: machine_id checked so trials can't be re-redeemed
- **Audit log**: every attempt persisted to `activation_attempts` table

## Tests

```bash
pytest tests/ -v
# 22/22 passing
```

## Support

dht.io.vn@gmail.com
