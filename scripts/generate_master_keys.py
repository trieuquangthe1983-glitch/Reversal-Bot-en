"""Generate the Ed25519 keypair used to sign license tokens.

Run ONCE at server setup. Outputs:

    state/master_private.pem     <- KEEP SECRET. Lives only on the server.
    state/master_public.pem      <- copy this into the bot's licensing/codes.py

The private key NEVER leaves your machine (or the server you deploy to).
The public key ships with every customer's bot.

If you ever lose the private key, every existing license becomes
unverifiable -- you must regenerate, re-issue codes to all paying
customers, and rebuild the bot with the new public key.

Idempotency: refuses to overwrite an existing private key unless
--force is passed. This prevents accidentally invalidating all licenses.
"""
import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Allow running from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main(force: bool = False, state_dir: str = "state") -> None:
    sd = Path(state_dir)
    sd.mkdir(parents=True, exist_ok=True)
    priv_path = sd / "master_private.pem"
    pub_path = sd / "master_public.pem"

    if priv_path.exists() and not force:
        print(f"[ABORT] {priv_path} already exists.")
        print(f"        Pass --force to overwrite (DANGER: invalidates all licenses).")
        sys.exit(1)

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    priv_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    # Try to restrict permissions (POSIX only)
    try:
        import os
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    print("=" * 64)
    print("Ed25519 keypair generated successfully.")
    print("=" * 64)
    print(f"  Private key: {priv_path.resolve()}  (KEEP SECRET)")
    print(f"  Public key:  {pub_path.resolve()}")
    print()
    print("Next steps:")
    print("  1. Copy the contents of master_public.pem and paste into your bot's")
    print("     src/licensing/codes.py  ->  PUBLIC_KEY_PEM constant.")
    print()
    print("  2. For local dev, the server will read the private key from")
    print(f"     {priv_path}")
    print()
    print("  3. For production deploy (Railway / Fly.io / etc), set the env var:")
    print('       MASTER_PRIVATE_KEY="<paste the full PEM contents here>"')
    print()
    print("  4. Set the admin token for revocation endpoints:")
    print("       LICENSE_ADMIN_TOKEN=<a long random string>")
    print()
    print("Public key (paste into bot):")
    print("-" * 64)
    print(pub_pem.decode("ascii"))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing private key (DANGER)")
    p.add_argument("--state-dir", default="state",
                   help="output directory (default: state)")
    args = p.parse_args()
    main(force=args.force, state_dir=args.state_dir)
