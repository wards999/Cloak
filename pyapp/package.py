"""Package the cloak app (cloak_app.py) as a standalone app with the engine inside.

    python pyapp/package.py <dir with the built engine binaries> <output dir>

Windows: <output>/Cloak/Cloak.exe, with the engine (cloak.exe,
cloak-winmount.exe) in <output>/Cloak/bin.
macOS:   <output>/Cloak.app, with the engine (cloak, cloak-mount) in
Contents/MacOS/bin, ad-hoc signed so Apple Silicon will run it.

Needs PyInstaller plus pyapp/requirements.txt installed.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import PyInstaller.__main__

HERE = Path(__file__).resolve().parent
IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    engine, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    work = out / "_build"
    # The app shows its release number in Settings (see `app_version`).
    cargo = (HERE.parent / "Cargo.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', cargo, re.M)[1]
    (HERE / "_version.py").write_text(f'VERSION = "{version}"\n', encoding="utf-8")
    PyInstaller.__main__.run([
        str(HERE / "cloak_app.py"),
        "--name", "Cloak",
        "--windowed",
        # The file's own icon (Explorer, Finder, Dock), and the PNG the app
        # sets on its windows at runtime.
        "--icon", str(HERE / "assets" / ("icon.icns" if IS_MAC else "icon.ico")),
        "--add-data", f"{HERE / 'assets' / 'icon.png'}{os.pathsep}assets",
        "--noconfirm",
        "--clean",
        # The widget library's stylesheets and icons are data files.
        "--collect-data", "qfluentwidgets",
        "--distpath", str(out),
        "--workpath", str(work / "work"),
        "--specpath", str(work),
        # Parts of Qt the app never uses.
        *[a for m in ("QtWebEngineCore", "QtWebEngineWidgets", "QtQuick", "QtQml", "QtPdf", "Qt3DCore")
          for a in ("--exclude-module", f"PySide6.{m}")],
    ])
    shutil.rmtree(work, ignore_errors=True)

    names = ["cloak.exe", "cloak-winmount.exe"] if IS_WIN else ["cloak", "cloak-mount"]
    bin_dir = (out / "Cloak.app" / "Contents" / "MacOS" / "bin") if IS_MAC else (out / "Cloak" / "bin")
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(engine / name, bin_dir / name)
    if IS_MAC:
        # Adding files invalidates PyInstaller's signature; Apple Silicon
        # refuses to run unsigned code, so sign the whole bundle again (ad hoc).
        subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(out / "Cloak.app")], check=True)
    print(f"packaged into {out}")


if __name__ == "__main__":
    main()
