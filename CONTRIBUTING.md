# Contributing to PortRegistry

Thanks for helping. This page explains how to set up, what a good change looks like and the rules that keep PortRegistry safe.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) first. For security problems, do **not** open an issue; follow [SECURITY.md](SECURITY.md).

## Ways to help

- Report a bug or ask for a feature using the issue templates.
- Improve the docs, especially platform notes for Linux and macOS.
- Fix an issue or add tests. For anything larger than a small fix, please open an issue first so we can agree on the approach before you spend time on it.

## Set up

You need Python 3.12 or newer.

```bash
git clone https://github.com/AndyFerns/PortRegistry.git
cd PortRegistry
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[docker,dev]"
```

Use a throwaway home and port while developing, so you never touch your real data:

```bash
export PORTREGISTRY_HOME="$PWD/.portregistry"   # PowerShell: $env:PORTREGISTRY_HOME = "$PWD\.portregistry"
export PORTREGISTRY_PORT=18765
portregistry daemon start
```

## Before you open a pull request

CI runs all of these; run them locally first:

```bash
ruff check src tests
ruff format --check src tests
mypy
python -m django makemigrations --check --dry-run --settings=portregistry.django_app.settings
pytest
```

- Add or update tests with your change. Tests for process control use fake OS adapters (see `tests/control_fakes.py`); do not write tests that stop real, non-disposable processes.
- mypy runs on Linux, Windows and macOS in CI. Wrap platform-specific modules (such as `winreg`) in a `sys.platform` check so type checking works everywhere (for example `mypy --platform linux`).
- Keep changes focused. Unrelated clean-ups belong in a separate pull request.
- Update the [README](README.md) when behaviour, settings or commands change.
- Commit messages follow the style already in the history: `feat(scope): ...`, `fix(scope): ...`, `docs: ...`, `test: ...`.

## Ground rules (please do not break these)

PortRegistry is local-first and deliberately cautious. Changes that weaken these will not be merged:

1. **One daemon owns discovery, scheduling and database writes.** The GUI, TUI and CLI are clients only.
2. **Never execute discovered command lines**, and never collect process environment variables.
3. **Never elevate privileges automatically** (no sudo, no UAC prompts).
4. **Never expose the Docker socket** through the HTTP API.
5. **Escape untrusted values** (process names, command lines, labels) in every interface.
6. **Process control stays opt-in, guarded and audited.** Own-user processes only, protected processes never, a two-step confirmation with a single-use code, no `--yes` flag, and every attempt recorded.
7. **No telemetry or network calls** to anything except the local daemon and Docker.

## Reviews

A maintainer will review your pull request when they can; this is a small project, so please be patient. Expect questions and requests for changes; they are about the code, not about you.

## Licence of contributions

PortRegistry is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution you agree that it is released under that licence, as described in section 5 of the licence.
