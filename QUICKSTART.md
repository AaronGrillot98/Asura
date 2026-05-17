# Quickstart

## Local Demo

```bash
cd asura
cp .env.example .env
docker compose up -d
```

Open:

- Dashboard: http://localhost:3000
- API docs: http://localhost:8000/docs

## Developer Mode

Backend:

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

## Demo Scope

The seeded demo project is `Acme FlightOps Demo` (project id `demo`). Active scans are only allowed for the configured demo targets and require explicit authorization. By default the runner is `DemoRunner`; set `ASURA_ENABLE_REAL_SCANNERS=1` to enable `SubprocessRunner`.

