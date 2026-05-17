# Tool Registry Contract

All tools shown in Asura must be declared in `backend/registry/tools.yaml`.

## Execution Classes

- `core_runner`: default engine tools that Asura can execute as first-class scanner jobs.
- `optional_pack`: installable or guarded integrations that are not part of the default engine.
- `reference`: catalog entries for knowledge-base depth, imports, or external services. Asura does not execute them.
- `blocked`: tools Asura explicitly refuses to install or run.

## Required Fields

Every registry entry must declare:

- `id`
- `name`
- `pack`
- `category`
- `execution`
- `modes`
- `install_status`
- `integration_status`
- `license`
- `official_url`
- `input_types`
- `output_formats`
- `parser`
- `safe_default`
- `requires_authorized_scope`
- `docker_available`
- `supported_os`
- `commands`
- `recommended_use`
- `risk_warning`

Executable tools must also declare:

- `executable`
- at least one command template
- at least one parser
- at least one input type
- at least one output format
- at least one supported OS

## Safety Rules

- Blocked tools cannot define commands, modes, or executables.
- Reference tools cannot define commands.
- Runner tools must define a command template for every declared mode.
- Non-safe active or lab tools must require authorized scope.
- Command modes must be listed in the tool's `modes`.
- The blocked-tools policy must not be empty.

The backend enforces these rules through `/api/arsenal/contract` and the test suite.

