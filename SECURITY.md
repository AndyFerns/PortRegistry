# Security policy

PortRegistry is a local tool. It reads information about the processes and ports on your machine and, only when you turn it on, can stop processes you own. Security reports are taken seriously.

## Supported versions

PortRegistry is pre-1.0. Only the latest released version receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest release (0.2.x and newer) | yes |
| anything older | no, please upgrade |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). If that option is not available, contact the maintainer, [@AndyFerns](https://github.com/AndyFerns), through the contact details on their GitHub profile and ask for a private channel before sending details.

Please include:

- the PortRegistry version (`portregistry version`) and your operating system;
- what you did, what you expected and what happened;
- the smallest steps or proof of concept that reproduces it;
- the impact as you understand it.

You can expect an acknowledgement within about 7 days. After that we will confirm the problem, work on a fix, and agree a disclosure date with you. Reporters are credited in the release notes unless they prefer not to be.

## What is in scope

- Any way for a **web page or another local user** to call the daemon API without the token or session (for example DNS rebinding, cross-site requests or a weak Host check).
- Bypassing the **process-control safeguards**: stopping a process that is protected, belongs to another user, or has changed since it was reviewed; reusing or forging a confirmation code; or skipping the two-step flow.
- Leaking **secrets**: the API token, process environment variables (which PortRegistry never collects) or command lines in places they should not appear.
- **Injection** in the GUI, TUI or CLI from untrusted values such as process names, command lines or container labels.
- Exposure of the **Docker socket** through the HTTP API (it must never be exposed).
- Anything that makes PortRegistry **execute** a discovered command line, or elevate privileges on its own.

## Out of scope

- Problems that need an attacker who already has your account's full control on the same machine (they can already read your files and kill your processes).
- Running the daemon bound to a non-loopback address against the documented warnings. Process control is disabled in that case.
- Findings in third-party dependencies that do not affect PortRegistry (report those upstream).
- Denial of service by a user who is allowed to run the CLI.

## Design notes for researchers

- The daemon listens on `127.0.0.1` by default, authenticates with a local token (or a one-time login link for the browser), and checks the `Host` header.
- Stopping processes is **off by default** (`[control] enabled = false`). When on, it only acts on processes owned by the daemon's own user, never on protected processes, and always needs a two-step confirmation with a single-use code valid for 30 seconds. Every attempt, allowed or refused, is recorded in History.
- See the "Stopping processes (opt-in)" and "Permissions and visibility" sections of the [README](README.md).
