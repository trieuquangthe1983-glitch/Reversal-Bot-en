# Triển khai License Server — Hướng dẫn từng bước

Mục tiêu: Có một license server chạy 24/7 trên Internet để khi khách thanh toán USDT-BEP20, server tự verify on-chain và mint signed token cho họ.

---

## 📋 Tổng quan kiến trúc

```
   ┌─────────────┐     1. send USDT             ┌─────────────┐
   │  Customer   │  ───────────────────────────▶│  BSC chain  │
   │  (mua bot)  │                              │  (BEP20)    │
   └─────────────┘                              └─────────────┘
         │
         │ 2. nhập tx_hash + tier vào dashboard
         ▼
   ┌─────────────┐     3. POST /verify-payment   ┌─────────────────────┐
   │  Customer   │  ──────────────────────────▶ │ License Server      │
   │  bot UI     │  ◀────── 4. signed token ─── │ (anh deploy ở đây)  │
   └─────────────┘                              │                     │
         │                                      │  - PRIVATE Ed25519  │
         │ 5. activate locally                  │  - SQLite licenses  │
         ▼                                      │  - BSC verify       │
   bot starts running                           └─────────────────────┘
                                                          ▲
                                          6. heartbeat khi bot khởi động
                                                          │
   ┌─────────────┐                                        │
   │  Customer   │  ──────────────────────────────────────┘
   │  bot loop   │
   └─────────────┘
```

---

## 🛠️ Bước 1 — Sinh keypair Ed25519 (local, 1 lần)

Trên máy laptop của anh:

```bash
cd /c/Users/Administrator/license-server
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/generate_master_keys.py
```

Output sẽ in ra:
- `state/master_private.pem` — **giữ tuyệt mật**, backup vào USB hoặc 1Password
- `state/master_public.pem` — copy nội dung file này

**⚠️ Backup ngay private key.** Mất file = mất khả năng verify TOÀN BỘ license đã bán.

## 🔑 Bước 2 — Paste public key vào bot

Mở file:
```
C:\Users\Administrator\crypto-reversal-bot-en\src\licensing\codes.py
```

Tìm constant `PUBLIC_KEY_PEM` và thay bằng nội dung `master_public.pem`:

```python
PUBLIC_KEY_PEM = """\
-----BEGIN PUBLIC KEY-----
<paste nội dung master_public.pem ở đây>
-----END PUBLIC KEY-----
"""
```

Đây là key duy nhất ship trong bot binary tới mọi customer. Lộ public key không sao — chỉ private key mới mint được token.

## 🌐 Bước 3 — Chọn nơi deploy

Anh có 3 lựa chọn miễn phí/giá rẻ:

### A) **Fly.io** (Recommended — free $5/tháng quota, persistent volume)

```bash
# Cài fly CLI: https://fly.io/docs/hands-on/install-flyctl/
fly auth login

cd license-server
fly launch --copy-config --no-deploy
# Khi hỏi tên app, dùng tên unique như "your-name-license"
# Khi hỏi region, chọn "sin" (Singapore) cho latency thấp từ VN

# Tạo volume cho SQLite persistent
fly volumes create license_data --region sin --size 1

# Set secrets (PEM dạng inline)
fly secrets set MASTER_PRIVATE_KEY="$(cat state/master_private.pem)"
fly secrets set LICENSE_ADMIN_TOKEN="$(openssl rand -hex 32)"
# Lưu admin token ở 1Password — dùng để gọi /admin/* endpoints

# Deploy!
fly deploy

# Lấy URL của app
fly status   # → https://your-name-license.fly.dev
```

### B) **Railway.app** (cũng free tier, dễ hơn fly.io)

1. Đăng ký https://railway.app
2. Connect GitHub repo `license-server` (push code lên GitHub trước)
3. Railway tự detect Dockerfile + deploy
4. Vào Settings → Variables → set:
   - `MASTER_PRIVATE_KEY` = nội dung `master_private.pem`
   - `LICENSE_ADMIN_TOKEN` = random 32-char hex (sinh bằng `python -c "import secrets; print(secrets.token_hex(32))"`)
5. Add a **Volume** mounted at `/data` để SQLite persistent
6. Railway sẽ assign 1 domain free dạng `your-app-production.up.railway.app`

### C) **VPS rẻ ($5/tháng)** — Vultr/Linode/DigitalOcean

```bash
ssh root@your-vps-ip
apt update && apt install -y docker.io docker-compose

git clone https://github.com/yourname/license-server.git
cd license-server

# Copy private key qua SCP
scp state/master_private.pem root@your-vps-ip:/root/license-server/state/

# Tạo .env
cat > .env <<EOF
LICENSE_ADMIN_TOKEN=$(openssl rand -hex 32)
EOF

docker compose up -d

# Cài nginx + Let's Encrypt cho HTTPS (quan trọng!)
apt install -y nginx certbot python3-certbot-nginx
# Edit /etc/nginx/sites-available/license với reverse proxy đến :8090
certbot --nginx -d license.your-domain.com
```

## 🔗 Bước 4 — Trỏ bot đến server

Trên máy mỗi customer (anh hardcode hoặc cho user customize):

```python
# Trong .env của bot:
LICENSE_SERVER_URL=https://your-name-license.fly.dev
LICENSE_OFFLINE_GRACE_DAYS=7
```

Hoặc hardcode default trong `src/licensing/client.py`:

```python
DEFAULT_SERVER_URL = os.getenv("LICENSE_SERVER_URL",
                               "https://your-name-license.fly.dev")
```

## ✅ Bước 5 — Test end-to-end (sandbox)

Trên máy anh, làm 1 lần để chắc chắn flow chạy:

```bash
# Terminal 1: chạy server local
cd license-server
python -m uvicorn app:app --reload

# Terminal 2: chạy bot
cd crypto-reversal-bot-en
set LICENSE_SERVER_URL=http://localhost:8090
# Bot UI sẽ chạy ở:
python scripts/run_web.py
```

Sau đó:
1. Mở `http://localhost:8788` (bot UI)
2. Click **💎 Pricing** → phải load tiers từ server local
3. Click **🔑 Activate** → paste 1 tx_hash thật của anh (nếu có) hoặc skip để test phần khác
4. Server log sẽ show request + tx verify

Để test full flow mà không cần gửi USDT thật, anh có thể tạm thời mock `verify_bsc_payment` trong `app.py` để return success.

## 💰 Bước 6 — Customer flow (workflow thật)

1. Customer download bot, chạy `python scripts/run_web.py`
2. Họ click 💎 Pricing → thấy 5 tier
3. Chuyển USDT-BEP20 đúng số tới ví `0xFdE5bE00bA5db63a93abf7922ee831dB62257550`
4. Đợi ~30 giây (12 confirmations)
5. Copy tx hash từ bscscan.com
6. Click 🔑 Activate trên bot UI
7. Paste tx_hash + chọn tier → bấm Verify
8. Bot gọi server → server verify on-chain → mint signed token → trả về
9. Token tự fill vào Step 2 → bấm Activate
10. Bot start được, license badge hiện ✅

## 🛠️ Bước 7 — Admin operations

### List tất cả license đã issue:
```bash
curl -H "x-admin-token: <your-admin-token>" \
     https://your-server.fly.dev/admin/list
```

### Revoke 1 license (refund, chargeback...):
```bash
curl -X POST \
     -H "x-admin-token: <your-admin-token>" \
     "https://your-server.fly.dev/admin/revoke/42?reason=refund"
```

### Manual support — chuyển license sang máy mới:
Khi customer email anh xin transfer:
1. Nhận từ customer: machine_id cũ + machine_id mới + tx_hash gốc (làm bằng chứng)
2. Revoke license cũ qua `/admin/revoke/{old_id}` với reason "transfer"
3. Trên server, query SQLite trực tiếp:
   ```bash
   fly ssh console  # vào server
   sqlite3 /data/state/licenses.db
   sqlite> SELECT id, tier, machine_id, expires_at FROM licenses
           WHERE payment_tx_hash = '<original tx>' AND revoked_at IS NULL;
   sqlite> -- copy tier + expires_at
   ```
4. Mint code mới bằng cách insert hoặc gọi script helper:
   ```python
   # Trên server hoặc local nếu anh có private key:
   from crypto import sign_license
   from db import LicenseRepo
   lid = LicenseRepo.insert(tier='annual', machine_id='<new_mid>',
                            expires_at='<copied>', payment_tx_hash=None,
                            customer_email='customer@example.com')
   token = sign_license('annual', '<new_mid>', lid, duration_days=365)
   print(token)
   # Email token này cho customer
   ```

## 🔐 Bước 8 — Bảo mật vận hành

### Backup
- **Private key**: copy `master_private.pem` ra USB + cloud (encrypted) + 1Password. **Không có backup = không thể issue code mới hoặc transfer license**.
- **DB licenses.db**: backup hàng tuần. Fly.io có snapshot tự động cho volume; trên VPS thì cron `sqlite3 .backup`.

### Monitoring
- Set up uptime ping tới `/health` (free: Uptime Robot, Better Stack)
- Nếu server down quá `LICENSE_OFFLINE_GRACE_DAYS` (default 7), tất cả bot dừng → anh sẽ nhận khiếu nại

### Rotation
- Đổi `LICENSE_ADMIN_TOKEN` mỗi 6 tháng (revoke cũ + issue mới)
- Private key Ed25519 **không cần rotate** trừ khi nghi ngờ leak. Nếu rotate phải re-issue tất cả license đang chạy.

### Logs
Server log mọi attempt vào bảng `activation_attempts`. Định kỳ query:
```sql
SELECT ip_address, COUNT(*) AS fails, MAX(ts) AS latest
FROM activation_attempts
WHERE success = 0 AND ts >= datetime('now', '-1 day')
GROUP BY ip_address
ORDER BY fails DESC;
```
Để phát hiện brute force / abuse.

---

## 📞 Support email

Tất cả error message trong bot + server đã chứa `dht.io.vn@gmail.com`. Anh chỉ cần monitor inbox này.

## 🎯 Checklist trước khi mở bán

- [ ] Sinh keypair, backup private key 2 nơi
- [ ] Paste public key vào `crypto-reversal-bot-en/src/licensing/codes.py`
- [ ] Deploy server lên Fly.io / Railway / VPS
- [ ] Set `MASTER_PRIVATE_KEY` + `LICENSE_ADMIN_TOKEN` secrets
- [ ] Test với tx_hash thật của chính anh ($29 trial — anh tự gửi cho ví của mình)
- [ ] Verify token sign + activate + heartbeat hoạt động
- [ ] Cập nhật `LICENSE_SERVER_URL` trong bot config trỏ tới production server
- [ ] Set up uptime monitoring
- [ ] Sẵn sàng trả lời email từ `dht.io.vn@gmail.com`
- [ ] Pack bot thành `.zip` (bỏ `state/`, `__pycache__/`, `.venv/`, `.pytest_cache/`)
- [ ] Bán!
