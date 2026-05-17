# Install

## Requirements

- Docker and Docker Compose for the easiest path.
- Node.js 22+ for frontend development.
- Python 3.12+ for backend development.

## Docker Compose

```bash
cp .env.example .env
docker compose up -d
```

## Scanner Tools

Asura can run only tools that are installed in the runtime or available through future scanner containers. Missing tools are reported as not installed rather than faking results.

Check registry health:

```bash
curl http://localhost:8000/api/arsenal/contract
```

