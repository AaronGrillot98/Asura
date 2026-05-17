# Adding A Tool

1. Add the tool to `backend/registry/tools.yaml`.
2. Choose an execution class.
3. Declare modes, executable, input types, output formats, parser, and command templates.
4. Add a risk warning if the tool touches a target.
5. Run:

```bash
cd backend
python -m pytest
```

Rules:

- Runner tools need command templates for every declared mode.
- Active/lab tools must be safe by default or require authorized scope.
- Reference tools cannot define commands.
- Blocked tools cannot define commands, modes, or executables.

