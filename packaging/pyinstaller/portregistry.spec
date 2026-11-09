# PyInstaller spec for a one-folder PortRegistry bundle.
#
# Build (from the repository root, in a venv with `pip install -e ".[docker,binary]"`,
# plus `[tray]` where a tray backend is available):
#
#     pyinstaller --noconfirm --clean packaging/pyinstaller/portregistry.spec
#
# Output: dist/portregistry/portregistry(.exe). The bundle runs every CLI
# command, including `daemon start` (which re-invokes the bundle executable).
# ruff: noqa
import importlib.util
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "portregistry.django_app.settings")

hiddenimports = []
datas = []

# PortRegistry itself: all modules (migrations are discovered by Django at runtime),
# templates, static files (vendored htmx) and the migration sources.
hiddenimports += collect_submodules("portregistry", filter=lambda name: ".tray" not in name or importlib.util.find_spec("pystray") is not None)
datas += collect_data_files("portregistry", include_py_files=True)

# Frameworks loaded by dotted path (settings, URLconf, middleware, backends).
for package in ("django", "rest_framework", "uvicorn", "textual", "rich", "typer", "httpx", "platformdirs"):
    hiddenimports += collect_submodules(package, filter=lambda name: ".tests" not in name and ".test." not in name)
for package in ("django", "rest_framework", "textual"):
    datas += collect_data_files(package)

# Optional extras: bundled only if installed in the build environment.
if importlib.util.find_spec("docker") is not None:
    hiddenimports += collect_submodules("docker")
if importlib.util.find_spec("pystray") is not None:
    hiddenimports += ["pystray", "PIL.Image", "PIL.ImageDraw"]

a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "mypy", "ruff", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="portregistry",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="portregistry")
