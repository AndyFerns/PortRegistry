"""Best-effort project detection from a process working directory.

Walks up from the directory looking for well-known project markers. Only
``stat`` calls are made (no file contents are read, nothing is executed), the
walk is bounded, and results are cached per scan. Runs during collection, never
inside a database transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

MARKERS = (
    ".git",
    "pyproject.toml",
    "package.json",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "manage.py",
)
MAX_DEPTH = 12


@dataclass(frozen=True)
class ProjectInfo:
    name: str
    root: str
    marker: str


def _stop_dirs() -> set[Path]:
    """Directories that are never a project root (the walk stops there)."""
    try:
        return {Path.home()}
    except RuntimeError:
        return set()


class ProjectDetector:
    def __init__(self) -> None:
        self._cache: dict[str, ProjectInfo | None] = {}
        self._stops = _stop_dirs()

    def detect(self, cwd: str | None) -> ProjectInfo | None:
        if not cwd:
            return None
        if cwd in self._cache:
            return self._cache[cwd]
        result = self._walk(cwd)
        self._cache[cwd] = result
        return result

    def _walk(self, cwd: str) -> ProjectInfo | None:
        try:
            current = Path(cwd)
            if not current.is_absolute():
                return None
        except (OSError, ValueError):
            return None
        for _ in range(MAX_DEPTH):
            if current in self._stops or current.parent == current:
                return None
            # Never treat system/program directories as projects.
            lowered = str(current).replace("\\", "/").lower()
            if lowered.startswith(
                ("c:/windows", "/usr", "/bin", "/sbin", "/system", "/opt/homebrew/cellar")
            ):
                return None
            for marker in MARKERS:
                try:
                    if (current / marker).exists():
                        return ProjectInfo(name=current.name, root=str(current), marker=marker)
                except OSError:
                    continue
            current = current.parent
        return None


def detect_project(cwd: str | None) -> ProjectInfo | None:
    return ProjectDetector().detect(cwd)
