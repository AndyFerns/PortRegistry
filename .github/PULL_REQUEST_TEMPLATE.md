## What and why

<!-- What does this change do, and why? Link the issue it closes, e.g. "Closes #123". -->

## How it was tested

<!-- Commands you ran and what you saw. Mention your OS and Python version. -->

## Checklist

- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] `mypy` passes (and `mypy --platform linux` if I touched platform-specific code)
- [ ] `pytest` passes, and I added or updated tests
- [ ] No migration drift (`python -m django makemigrations --check --dry-run --settings=portregistry.django_app.settings`)
- [ ] README or docs updated if behaviour, settings or commands changed
- [ ] I read the ground rules in [CONTRIBUTING.md](../CONTRIBUTING.md), and this change does not weaken them (no executing command lines, no environment variables, no automatic elevation, no Docker socket exposure, untrusted values escaped)
- [ ] If this touches process control: safeguards, two-step confirmation and audit events are unchanged or strengthened

## Notes for the reviewer

<!-- Anything risky, surprising or left out on purpose. Screenshots for GUI or TUI changes help. -->
