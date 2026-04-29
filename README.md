# TGPars License Server

Minimal FastAPI service for managing TGPars license keys.

## Deploy on Railway (free tier)

1. Create new project → Deploy from GitHub
2. Set environment variables:
   - `ADMIN_TOKEN` — secret token for admin API calls (change from default!)
   - `DATABASE_URL` — Railway provides PostgreSQL URL automatically
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

## Local development

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 9000
```

## API

### Public
- `GET /health` — health check
- `POST /validate` — validate key + machine_id
- `POST /activate` — bind machine to key (first time or re-activation)
- `POST /deactivate` — free up a machine slot

### Admin (requires `X-Admin-Token` header)
- `GET /admin/licenses` — list all licenses
- `POST /admin/generate` — create a new license key
- `DELETE /admin/licenses/{key}` — revoke a key

## Generate a key (example)

```bash
curl -X POST https://your-server/admin/generate \
  -H "X-Admin-Token: YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plan": "pro", "max_machines": 2, "notes": "Customer John"}'
```

## Plans

| Plan       | Accounts | Messages/day | Instagram | Twitter | Video |
|------------|----------|--------------|-----------|---------|-------|
| trial      | 50       | 1500         | No        | No      | No    |
| starter    | 50       | 1500         | No        | No      | No    |
| pro        | 200      | Unlimited    | Yes       | No      | Yes   |
| enterprise | Unlimited| Unlimited    | Yes       | Yes     | Yes   |
