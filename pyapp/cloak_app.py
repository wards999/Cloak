"""cloak — a Fluent-design drive manager (PySide6 + QFluentWidgets).

Minimal by design: create drives, and lock / unlock them. Unlocking mounts the
drive and opens it in your file manager; all file work happens there. The crypto
and storage are the Rust `cloak` engine, reached through the `cloak` CLI (to
verify the password) and the `cloak-winmount` / `cloak-mount` adapter (to mount).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import date, datetime
from pathlib import Path

from PySide6.QtCore import QRect, Qt, QTimer
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QFileDialog, QHBoxLayout, QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    FluentWindow, FluentIcon as FIF, NavigationItemPosition, setTheme, setThemeColor,
    Theme, TitleLabel, SubtitleLabel, BodyLabel, StrongBodyLabel, CaptionLabel,
    PrimaryPushButton, PushButton, TransparentPushButton, LineEdit, PasswordLineEdit,
    ComboBox, CardWidget, MessageBoxBase, FlowLayout, InfoBar, InfoBarPosition,
    RadioButton, SwitchButton, TransparentToolButton, ToolTipFilter, ProgressBar,
)

APP_DIR = Path(__file__).resolve().parent
# A packaged app (PyInstaller) keeps the engine in `bin` next to its executable.
FROZEN = getattr(sys, "frozen", False)
EXE_DIR = Path(sys.executable).resolve().parent if FROZEN else APP_DIR
ICON = APP_DIR / "assets" / "icon.png"
IS_WIN = sys.platform.startswith("win")
# Engine calls from a windowed app would each flash a console window.
NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}


# ---- where the app keeps its data ------------------------------------------
#
# Cloak is portable: its drive list and settings live in a `cloak-data` folder
# next to the app (beside Cloak.exe, or beside Cloak.app on macOS, since writing
# inside a signed app bundle would break its signature), so the whole thing can
# travel on a USB stick. An app installed the usual macOS way, in Applications,
# keeps them in ~/.cloak instead, as does one whose folder can't be written
# (Program Files, or a read-only quarantine copy); that's also where earlier
# versions kept them.

LEGACY_DIR = Path.home() / ".cloak"


def _app_home():
    """The folder the app lives in (for a macOS bundle, the one holding it)."""
    if FROZEN and sys.platform == "darwin":
        return EXE_DIR.parents[2]  # Cloak.app/Contents/MacOS -> beside Cloak.app
    return EXE_DIR


def _writable(d):
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".write-test"
        probe.write_text("")
        probe.unlink()
        return True
    except OSError:
        return False


def _installed():
    """Is this a macOS app installed in an Applications folder?"""
    if not (FROZEN and sys.platform == "darwin"):
        return False
    home = _app_home()
    return home in (Path("/Applications"), Path.home() / "Applications")


def _data_dir():
    """(folder, portable?) for the drive list and settings."""
    if _installed():
        return LEGACY_DIR, False
    d = _app_home() / "cloak-data"
    if not _writable(d):
        return LEGACY_DIR, False
    # First portable run: bring over the drive list and settings from ~/.cloak.
    for name in ("drives.json", "settings.json"):
        src, dst = LEGACY_DIR / name, d / name
        if src.exists() and not dst.exists():
            try:
                shutil.copy2(src, dst)
            except OSError:
                pass
    return d, True


DATA_DIR, PORTABLE = _data_dir()
CONFIG = DATA_DIR / "drives.json"
SETTINGS = DATA_DIR / "settings.json"


# ---- engine bridge ---------------------------------------------------------

def _find(exe_base):
    env = os.environ.get("CLOAK_BIN") if exe_base == "cloak" else None
    if env and Path(env).exists():
        return env
    exe = exe_base + (".exe" if IS_WIN else "")
    candidates = [EXE_DIR / "bin" / exe, EXE_DIR / exe]
    candidates += [APP_DIR / rel / exe for rel in ("../target/release", "../target/debug")]
    for p in candidates:
        if p.exists():
            return str(p)
    return exe


CLI = _find("cloak")


def engine(args, **env_vars):
    """Run the `cloak` command line and return its JSON reply; raises
    RuntimeError with its message on failure."""
    env = os.environ.copy()
    env.update(env_vars)
    try:
        proc = subprocess.run([CLI, *args], capture_output=True, text=True, env=env, **NO_WINDOW)
    except OSError as e:
        raise RuntimeError(f"the engine wasn't found ({e})")
    out = (proc.stdout or "").strip()
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        data = {}
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(data["error"])
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "the engine failed").strip())
    return data


def engine_with_progress(args, on_progress, **env_vars):
    """Like `engine`, for a command that also prints progress lines
    (`{"progress": n, "total": t}`): `on_progress(n, t)` is called for each,
    with the window kept responsive."""
    env = os.environ.copy()
    env.update(env_vars)
    try:
        proc = subprocess.Popen([CLI, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, **NO_WINDOW)
    except OSError as e:
        raise RuntimeError(f"the engine wasn't found ({e})")
    data = {}
    for line in proc.stdout:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and "progress" in msg:
            on_progress(msg["progress"], msg["total"])
            QApplication.processEvents()
        elif isinstance(msg, dict):
            data = msg
    err = proc.stderr.read()
    proc.wait()
    if "error" in data:
        raise RuntimeError(data["error"])
    if proc.returncode != 0:
        raise RuntimeError((err or "the engine failed").strip())
    return data


def conversion_state(path):
    """"converting" or "unconverting" if a run in `path` was interrupted."""
    p = Path(path)
    if (p / "converting.idx").exists():
        return "converting"
    if (p / "unconverting.idx").exists():
        return "unconverting"
    return None


def _size(n):
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1000


def _duration(seconds):
    if seconds < 60:
        return "under a minute"
    minutes = round(seconds / 60)
    if minutes < 90:
        return f"about {minutes} minute{'s' if minutes != 1 else ''}"
    return f"about {round(minutes / 60)} hours"


def verify(path, password):
    """Open the drive to check the password; raise RuntimeError on failure."""
    env = os.environ.copy()
    env["CLOAK_PASSPHRASE"] = password
    try:
        proc = subprocess.run([CLI, "open", path], capture_output=True, text=True, env=env, **NO_WINDOW)
    except OSError as e:
        raise RuntimeError(f"engine not found ({e})")
    out = (proc.stdout or "").strip()
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        data = {}
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(data["error"])
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "could not open drive").strip())


def create_store(path, password):
    env = os.environ.copy()
    env["CLOAK_PASSPHRASE"] = password
    try:
        proc = subprocess.run([CLI, "create", path], capture_output=True, text=True, env=env, **NO_WINDOW)
    except OSError as e:
        raise RuntimeError(f"engine not found ({e})")
    out = (proc.stdout or "").strip()
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        data = {}
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(data["error"])
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "could not create drive").strip())


def used_drive_letters():
    """Authoritative set of in-use drive letters (Windows), via GetLogicalDrives
    — catches reserved and disconnected-network letters that Path.exists misses."""
    if not IS_WIN:
        return set()
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        return {f"{chr(ord('A') + i)}:" for i in range(26) if mask & (1 << i)}
    except Exception:
        # Fall back to a filesystem probe.
        return {f"{c}:" for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{c}\\").exists()}


def free_drive_letters():
    if not IS_WIN:
        return []
    used = used_drive_letters()
    return [f"{c}:" for c in "DEFGHIJKLMNOPQRSTUVWXYZ" if f"{c}:" not in used]


def winfsp_bin():
    """Directory holding winfsp-x64.dll. It isn't on PATH by default, so the
    mount adapter fails to load it with STATUS_DLL_NOT_FOUND; we add it to the
    adapter's environment. Returns None if not found (non-Windows, or no WinFsp)."""
    if not IS_WIN:
        return None
    try:
        import winreg
        for key in (r"SOFTWARE\WOW6432Node\WinFsp", r"SOFTWARE\WinFsp"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                    inst, _ = winreg.QueryValueEx(k, "InstallDir")
                    p = os.path.join(inst, "bin")
                    if os.path.isdir(p):
                        return p
            except OSError:
                continue
    except Exception:
        pass
    default = r"C:\Program Files (x86)\WinFsp\bin"
    return default if os.path.isdir(default) else None


# Drive paths are saved twice: as last seen, and relative to the data folder
# when the drive is on the same disk as the app. On a USB stick that's the
# one that keeps working when the stick gets another drive letter (or mount
# point) on another computer.

def _same_volume(a, b):
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


def _resolve(entry):
    """A drive entry's folder now: the relative path if it still leads to a
    folder, else the path as last seen."""
    rel = entry.get("rel")
    if rel:
        p = os.path.normpath(os.path.join(DATA_DIR, rel))
        if os.path.isdir(p):
            return p
    return os.path.normpath(entry.get("path", ""))


def load_drives():
    try:
        drives = json.loads(CONFIG.read_text())
    except Exception:
        return []
    return [{"name": d.get("name", ""), "path": _resolve(d)} for d in drives if isinstance(d, dict)]


def save_drives(drives):
    out = []
    for d in drives:
        entry = {"name": d["name"], "path": os.path.normpath(d["path"])}
        if PORTABLE and _same_volume(d["path"], DATA_DIR):
            try:
                entry["rel"] = os.path.relpath(d["path"], DATA_DIR)
            except ValueError:
                pass  # different drive letters after all
        out.append(entry)
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(json.dumps(out, indent=2))
    except Exception:
        pass


# Remembered preferences. Earlier versions wrote the theme capitalised
# ("System"), so names are matched without regard to case.
THEMES = {"system": Theme.AUTO, "light": Theme.LIGHT, "dark": Theme.DARK}


def load_settings():
    """{"theme": "system" | "light" | "dark", "auto_lock": bool}, with
    defaults for anything missing or unreadable."""
    try:
        data = json.loads(SETTINGS.read_text())
    except Exception:
        data = {}
    theme = str(data.get("theme", "system")).lower()
    auto_lock = data.get("auto_lock", True)
    return {
        "theme": theme if theme in THEMES else "system",
        "auto_lock": auto_lock if isinstance(auto_lock, bool) else True,
    }


def save_setting(key, value):
    """Change one preference, keeping the others (and any this version
    doesn't know about)."""
    try:
        data = json.loads(SETTINGS.read_text())
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    data[key] = value
    try:
        SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def open_in_file_manager(mountpoint):
    try:
        if IS_WIN:
            os.startfile(mountpoint if mountpoint.endswith("\\") else mountpoint + "\\")
        elif sys.platform == "darwin":
            subprocess.Popen(["open", mountpoint])
        else:
            subprocess.Popen(["xdg-open", mountpoint])
    except Exception:
        pass


# ---- sleep / shutdown safety ----------------------------------------------
#
# Mounted drives are decrypted and live, so we unmount them when the machine
# sleeps (security) and when it shuts down or logs off (clean teardown). Kept in
# a module global so the filter/observer isn't garbage-collected.

_POWER_HOOK = None


def install_power_hook(app, on_power):
    """Call on_power("sleep") on suspend and on_power("shutdown") on logoff/
    shutdown. Best-effort and silent if the platform hook is unavailable."""
    global _POWER_HOOK
    if IS_WIN:
        import ctypes
        import ctypes.wintypes
        from PySide6.QtCore import QAbstractNativeEventFilter

        WM_POWERBROADCAST, PBT_APMSUSPEND = 0x0218, 0x0004
        WM_QUERYENDSESSION, WM_ENDSESSION = 0x0011, 0x0016

        class _Filter(QAbstractNativeEventFilter):
            def nativeEventFilter(self, _etype, message):
                try:
                    msg = ctypes.wintypes.MSG.from_address(int(message))
                    if msg.message == WM_POWERBROADCAST and msg.wParam == PBT_APMSUSPEND:
                        on_power("sleep")
                    elif msg.message in (WM_QUERYENDSESSION, WM_ENDSESSION):
                        on_power("shutdown")
                except Exception:
                    pass
                return (False, 0)

        _POWER_HOOK = _Filter()
        app.installNativeEventFilter(_POWER_HOOK)
    elif sys.platform == "darwin":
        try:
            from Foundation import NSObject
            from AppKit import NSWorkspace

            class _Sleep(NSObject):
                def onSleep_(self, _note):
                    on_power("sleep")

            obs = _Sleep.new()
            nc = NSWorkspace.sharedWorkspace().notificationCenter()
            nc.addObserver_selector_name_object_(
                obs, "onSleep:", "NSWorkspaceWillSleepNotification", None
            )
            _POWER_HOOK = obs
        except Exception:
            pass


# ---- dialogs ---------------------------------------------------------------

class FocusedDialog(MessageBoxBase):
    """A dialog that puts the cursor in `self.first` when it appears, and that
    checks its fields before closing: the main button (and Enter) call
    `validate`, and a problem is shown inside the dialog, keeping what was
    typed, instead of closing it.

    Focus is set once the dialog is on screen; setting it while it's being
    built doesn't stick, as the opening animation moves focus after that."""

    first = None

    def __init__(self, parent):
        super().__init__(parent)
        self.error = CaptionLabel("", self)
        self.error.setStyleSheet("color: #d13438;")
        self.error.setWordWrap(True)
        # Selectable, so a message can be copied into a bug report.
        self.error.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.error.hide()
        # Route the main button through validate() rather than straight to
        # accept(), which is all the library's own handler does.
        self.yesButton.clicked.disconnect()
        self.yesButton.clicked.connect(self._on_yes)

    def finish_layout(self):
        """Call after adding the fields: puts the error line below them."""
        self.viewLayout.addWidget(self.error)

    def showEvent(self, e):
        super().showEvent(e)
        if self.first is not None:
            QTimer.singleShot(0, self.first.setFocus)

    def validate(self):
        """True to close the dialog; otherwise call `problem` and return False."""
        return True

    def problem(self, message, field=None):
        """Show `message` in the dialog and put the cursor in `field`."""
        self.error.setText(message)
        self.error.show()
        if field is not None:
            field.setFocus()
            if hasattr(field, "selectAll"):
                field.selectAll()
        return False

    busy_text = None  # the main button's label while validate() works

    def _on_yes(self):
        self.error.hide()
        label = self.yesButton.text()
        if self.busy_text:
            self.yesButton.setText(self.busy_text)
        self.yesButton.setEnabled(False)
        self.cancelButton.setEnabled(False)
        QApplication.processEvents()
        try:
            ok = self.validate()
        finally:
            self.yesButton.setText(label)
            self.yesButton.setEnabled(True)
            self.cancelButton.setEnabled(True)
        if ok:
            self.accept()
            signal = getattr(self, "yesSignal", None)  # not in every version
            if signal is not None:
                signal.emit()


class CreateDialog(FocusedDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.titleLabel = SubtitleLabel("Create a new drive", self)
        self.name = LineEdit(self); self.name.setPlaceholderText("Name  (e.g. Personal)")
        self.loc = LineEdit(self); self.loc.setPlaceholderText("Location — an empty folder")
        self.pick = PushButton("Choose folder…", self)
        self.pw = PasswordLineEdit(self); self.pw.setPlaceholderText("Password")
        self.pw2 = PasswordLineEdit(self); self.pw2.setPlaceholderText("Confirm password")
        row = QHBoxLayout(); row.addWidget(self.loc); row.addWidget(self.pick)
        self.viewLayout.addWidget(self.titleLabel)
        self.viewLayout.addWidget(self.name)
        self.viewLayout.addLayout(row)
        self.viewLayout.addWidget(self.pw)
        self.viewLayout.addWidget(self.pw2)
        self.finish_layout()
        self.created = None  # (name, folder) once the drive exists
        self.busy_text = "Creating…"
        self.pw2.returnPressed.connect(self.yesButton.click)
        self.yesButton.setText("Create drive")
        self.first = self.name
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(430)
        self.pick.clicked.connect(self._choose)

    def _choose(self):
        d = QFileDialog.getExistingDirectory(self, "Choose an empty folder for the drive", str(Path.home()))
        if d:
            self.loc.setText(os.path.normpath(d))

    def validate(self):
        name, loc = self.name.text().strip(), self.loc.text().strip()
        if not name:
            return self.problem("Give the drive a name.", self.name)
        if not loc:
            return self.problem("Choose a folder for the drive.", self.loc)
        if not self.pw.text():
            return self.problem("Enter a password.", self.pw)
        if self.pw.text() != self.pw2.text():
            return self.problem("The passwords don't match.", self.pw2)
        loc = os.path.normpath(loc)
        folder = Path(loc)
        if (folder / "meta.json").exists():
            return self.problem(
                "That folder is already a cloak drive. Choose an empty folder, or use "
                "Add existing to add this drive to your list.", self.loc)
        if folder.is_file():
            return self.problem("That's a file. Choose a folder for the drive.", self.loc)
        if folder.is_dir() and any(folder.iterdir()):
            return self.problem("That folder isn't empty. Choose an empty folder, or a new one.", self.loc)
        try:
            create_store(loc, self.pw.text())
        except RuntimeError as e:
            return self.problem(f"Couldn't create the drive there: {e}", self.loc)
        self.created = (name, loc)
        return True


class UnlockDialog(FocusedDialog):
    """Password and drive letter, then the mount itself, all checked before
    closing: `mount(password, mountpoint)` returns an error message, or None
    once the drive is up."""

    def __init__(self, parent, name, path, letters, mount):
        super().__init__(parent)
        self.path = path
        self.mount = mount
        self.busy_text = "Unlocking…"
        self.titleLabel = SubtitleLabel(f"Unlock “{name}”", self)
        self.sub = CaptionLabel(path, self)
        self.pw = PasswordLineEdit(self); self.pw.setPlaceholderText("Password")
        self.viewLayout.addWidget(self.titleLabel)
        self.viewLayout.addWidget(self.sub)
        self.viewLayout.addWidget(self.pw)
        self.combo = None
        if letters:
            row = QHBoxLayout()
            row.addWidget(BodyLabel("Mount at", self))
            self.combo = ComboBox(self)
            self.combo.addItems(letters)
            row.addWidget(self.combo); row.addStretch(1)
            self.viewLayout.addLayout(row)
        self.yesButton.setText("Unlock")
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(390)
        self.pw.returnPressed.connect(self.yesButton.click)
        self.first = self.pw
        self.finish_layout()

    def validate(self):
        if not self.pw.text():
            return self.problem("Enter the password.", self.pw)
        if IS_WIN:
            mp = self.combo.currentText() if self.combo else ""
            if not mp:
                return self.problem("Choose a drive letter.", self.combo)
            # It may have been taken since the dialog opened.
            if mp in used_drive_letters():
                return self.problem(f"{mp} is no longer free. Pick another letter.", self.combo)
        try:
            verify(self.path, self.pw.text())
        except RuntimeError as e:
            return self.problem(str(e)[:1].upper() + str(e)[1:] + ".", self.pw)
        mp = self.combo.currentText() if (IS_WIN and self.combo) else None
        failure = self.mount(self.pw.text(), mp)
        if failure:
            return self.problem(failure, self.combo if IS_WIN else self.pw)
        return True


class AddExistingDialog(FocusedDialog):
    """Pick a drive's folder and name it, checked before closing."""

    def __init__(self, parent, known_paths):
        super().__init__(parent)
        self.known = known_paths
        self.titleLabel = SubtitleLabel("Add an existing drive", self)
        self.loc = LineEdit(self); self.loc.setPlaceholderText("The drive's folder")
        self.pick = PushButton("Choose folder…", self)
        self.name = LineEdit(self); self.name.setPlaceholderText("Name for this drive")
        row = QHBoxLayout(); row.addWidget(self.loc); row.addWidget(self.pick)
        self.viewLayout.addWidget(self.titleLabel)
        self.viewLayout.addLayout(row)
        self.viewLayout.addWidget(self.name)
        self.finish_layout()
        self.yesButton.setText("Add drive")
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(430)
        self.pick.clicked.connect(self._choose)
        self.name.returnPressed.connect(self.yesButton.click)
        self.loc.returnPressed.connect(self.yesButton.click)
        self.first = self.pick
        self.added = None  # (name, folder) once checked

    def _choose(self):
        d = QFileDialog.getExistingDirectory(self, "Select an existing cloak drive folder", str(Path.home()))
        if d:
            d = os.path.normpath(d)
            self.loc.setText(d)
            if not self.name.text().strip():
                self.name.setText(Path(d).name)
            self.name.setFocus()
            self.name.selectAll()

    def validate(self):
        loc = self.loc.text().strip()
        if not loc:
            return self.problem("Choose the drive's folder.", self.pick)
        loc = os.path.normpath(loc)
        if not os.path.isdir(loc):
            return self.problem("That folder doesn't exist.", self.loc)
        if not (Path(loc) / "meta.json").exists():
            return self.problem(
                "That folder isn't a cloak drive. Choose the folder you created the drive in.", self.loc)
        if loc in self.known:
            return self.problem("That drive is already in your list.", self.loc)
        self.added = (self.name.text().strip() or Path(loc).name, loc)
        return True


class ConvertDialog(FocusedDialog):
    """Make an existing folder into a drive in place: check it first (the
    dry run), then convert with a progress bar. Also finishes a conversion
    that was interrupted (`resume`: the drive's name and folder)."""

    def __init__(self, parent, known_paths, resume=None):
        super().__init__(parent)
        self.known = known_paths
        self.checked = None  # the folder the shown report is for
        self.titleLabel = SubtitleLabel("Finish converting" if resume else "Convert a folder into a drive", self)
        self.intro = CaptionLabel(
            "The folder's files stay where they are: cloak renames them and encrypts the start "
            "and end of each, so even a large folder takes minutes, not hours.", self)
        self.intro.setWordWrap(True)
        self.name = LineEdit(self); self.name.setPlaceholderText("Name  (e.g. Personal)")
        self.loc = LineEdit(self); self.loc.setPlaceholderText("The folder to convert")
        self.pick = PushButton("Choose folder…", self)
        self.pw = PasswordLineEdit(self); self.pw.setPlaceholderText("Password")
        self.pw2 = PasswordLineEdit(self); self.pw2.setPlaceholderText("Confirm password")
        self.report = BodyLabel("", self); self.report.setWordWrap(True); self.report.hide()
        self.bar = ProgressBar(self); self.bar.hide()
        row = QHBoxLayout(); row.addWidget(self.loc); row.addWidget(self.pick)
        for w in (self.titleLabel, self.intro, self.name):
            self.viewLayout.addWidget(w)
        self.viewLayout.addLayout(row)
        for w in (self.pw, self.pw2, self.report, self.bar):
            self.viewLayout.addWidget(w)
        self.finish_layout()
        self.converted = None  # (name, folder) once done
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(470)
        self.pick.clicked.connect(self._choose)
        self.loc.textChanged.connect(self._unchecked)
        self.pw2.returnPressed.connect(self.yesButton.click)
        self.first = self.name
        self.resume = bool(resume)
        if resume:
            self.name.setText(resume["name"]); self.loc.setText(resume["path"])
            for w in (self.name, self.loc, self.pick):
                w.setEnabled(False)
            self.pw2.hide()
            self.intro.setText("Converting this folder was interrupted. Enter the password you chose "
                               "for it, and cloak carries on where it stopped.")
            self.pw.returnPressed.connect(self.yesButton.click)
            self.first = self.pw
        self._unchecked()

    def _choose(self):
        d = QFileDialog.getExistingDirectory(self, "Choose the folder to convert", str(Path.home()))
        if d:
            d = os.path.normpath(d)
            self.loc.setText(d)
            if not self.name.text().strip():
                self.name.setText(Path(d).name)

    def _unchecked(self):
        self.checked = None
        self.report.hide()
        self.yesButton.setText("Finish converting" if self.resume else "Check folder")
        self.busy_text = "Converting…" if self.resume else "Checking…"

    def validate(self):
        name, loc = self.name.text().strip(), os.path.normpath(self.loc.text().strip() or ".")
        if not name:
            return self.problem("Give the drive a name.", self.name)
        if not self.loc.text().strip() or not os.path.isdir(loc):
            return self.problem("Choose the folder to convert.", self.pick)
        if not self.resume and loc in self.known:
            return self.problem("That folder is already in your list of drives.", self.loc)
        if not self.pw.text():
            return self.problem("Enter a password.", self.pw)
        if not self.resume and self.pw.text() != self.pw2.text():
            return self.problem("The passwords don't match.", self.pw2)
        if self.resume or self.checked == loc:
            return self._convert(name, loc)
        return self._check(loc)

    def _check(self, loc):
        """The dry run: show what converting would do; stays open either way."""
        try:
            r = engine(["convert-scan", loc])
        except RuntimeError as e:
            return self.problem(f"Couldn't check that folder: {e}", self.loc)
        if r.get("resume"):
            return self.problem("Converting this folder was interrupted. Add it with Add existing, "
                                "then use Resume on its card.", self.loc)
        problems = r.get("problems", [])
        if problems:
            lines = [f"• {p['path'] or 'The folder'}: {p['problem']}" for p in problems[:8]]
            more = f"\n…and {len(problems) - 8} more." if len(problems) > 8 else ""
            return self.problem("Fix these first, then check again:\n" + "\n".join(lines) + more, self.loc)
        files, folders = r["files"], r["folders"]
        # Each file costs a few small writes plus its ends, whatever its size.
        estimate = files * 0.01 + r["encrypt_bytes"] / 100e6
        text = (f"{files:,} file{'s' if files != 1 else ''} in {folders + 1:,} folder{'s' if folders else ''}, "
                f"{_size(r['bytes'])}. Converting should take {_duration(estimate)}.")
        if r.get("litter"):
            text += f"\n{len(r['litter'])} system clutter file(s) (.DS_Store, Thumbs.db…) will be deleted."
        for w in r.get("warnings", []):
            text += f"\n⚠ {w[:1].upper() + w[1:]}."
        text += "\nKeep a backup of anything irreplaceable until you've checked the drive."
        self.report.setText(text)
        self.report.show()
        self.checked = loc
        self.yesButton.setText("Convert")
        self.busy_text = "Converting…"
        return False  # stay open: the next press converts

    def _convert(self, name, loc):
        self.bar.setValue(0); self.bar.show()

        def progress(done, total):
            self.bar.setValue(int(100 * done / total) if total else 100)

        try:
            engine_with_progress(["convert", loc], progress, CLOAK_PASSPHRASE=self.pw.text())
        except RuntimeError as e:
            self.bar.hide()
            msg = str(e)
            if conversion_state(loc) == "converting":
                msg += "\nNothing is lost: what's done so far is kept, and converting again carries on from there."
            return self.problem(f"Converting stopped: {msg}", self.pw)
        self.converted = (name, loc)
        return True


class UnconvertDialog(FocusedDialog):
    """Turn a drive back into a plain folder, in place."""

    def __init__(self, parent, drive):
        super().__init__(parent)
        self.path = drive["path"]
        self.titleLabel = SubtitleLabel(f"Turn “{drive['name']}” back into a plain folder", self)
        resuming = conversion_state(self.path) == "unconverting"
        text = ("This was interrupted. Enter the drive's password and cloak carries on where it stopped."
                if resuming else
                "Its files get their real names back and are decrypted where they lie, so its folder "
                "becomes an ordinary, unprotected folder. Anyone with access to it can then read everything.")
        self.intro = CaptionLabel(text, self); self.intro.setWordWrap(True)
        self.pw = PasswordLineEdit(self); self.pw.setPlaceholderText("The drive's password")
        self.bar = ProgressBar(self); self.bar.hide()
        for w in (self.titleLabel, self.intro, self.pw, self.bar):
            self.viewLayout.addWidget(w)
        self.finish_layout()
        self.yesButton.setText("Turn back into a folder")
        self.busy_text = "Working…"
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(450)
        self.pw.returnPressed.connect(self.yesButton.click)
        self.first = self.pw
        self.done = False

    def validate(self):
        if not self.pw.text():
            return self.problem("Enter the drive's password.", self.pw)
        self.bar.setValue(0); self.bar.show()

        def progress(done, total):
            self.bar.setValue(int(100 * done / total) if total else 100)

        try:
            engine_with_progress(["unconvert", self.path], progress, CLOAK_PASSPHRASE=self.pw.text())
        except RuntimeError as e:
            self.bar.hide()
            msg = str(e)
            msg = msg[:1].upper() + msg[1:]
            if conversion_state(self.path) == "unconverting":
                msg += ". Nothing is lost: run this again to carry on from where it stopped"
            return self.problem(msg + ".", self.pw)
        self.done = True
        return True


def _documents():
    d = Path.home() / "Documents"
    return d if d.is_dir() else Path.home()


class BackupDialog(FocusedDialog):
    """Back up the recovery files (drive header and folder lists) of
    `drives` into one password-protected file."""

    def __init__(self, parent, drives):
        super().__init__(parent)
        self.drives = drives
        one = len(drives) == 1
        title = f"Back up “{drives[0]['name']}”" if one else f"Back up all {len(drives)} drives"
        self.titleLabel = SubtitleLabel(title, self)
        what = CaptionLabel(
            "Saves the files needed to open " + ("this drive" if one else "these drives")
            + " if they're lost or damaged: the drive header and every folder list. "
            "Not your files themselves; keep a normal backup of the drive's folder for "
            "those. Store this somewhere other than the drive's own disk.", self)
        what.setWordWrap(True)
        stem = drives[0]["name"] if one else "cloak-drives"
        self.out = LineEdit(self)
        self.out.setText(str(_documents() / f"{stem} recovery {date.today().isoformat()}.cloakbak"))
        self.pick = PushButton("Save as…", self)
        self.pw = PasswordLineEdit(self); self.pw.setPlaceholderText("Password for this backup")
        self.pw2 = PasswordLineEdit(self); self.pw2.setPlaceholderText("Confirm password")
        row = QHBoxLayout(); row.addWidget(self.out); row.addWidget(self.pick)
        self.viewLayout.addWidget(self.titleLabel)
        self.viewLayout.addWidget(what)
        self.viewLayout.addLayout(row)
        self.viewLayout.addWidget(self.pw)
        self.viewLayout.addWidget(self.pw2)
        self.finish_layout()
        self.yesButton.setText("Back up")
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(470)
        self.pick.clicked.connect(self._choose)
        self.pw2.returnPressed.connect(self.yesButton.click)
        self.first = self.pw
        self.busy_text = "Backing up…"
        self.result = None

    def _choose(self):
        f, _ = QFileDialog.getSaveFileName(self, "Save the backup as", self.out.text(), "cloak backup (*.cloakbak)")
        if f:
            self.out.setText(os.path.normpath(f))

    def validate(self):
        out = self.out.text().strip()
        if not out:
            return self.problem("Choose where to save the backup.", self.out)
        if not out.lower().endswith(".cloakbak"):
            out += ".cloakbak"
        if not os.path.isdir(os.path.dirname(os.path.abspath(out))):
            return self.problem("That folder doesn't exist.", self.out)
        if not self.pw.text():
            return self.problem("Choose a password for the backup.", self.pw)
        if self.pw.text() != self.pw2.text():
            return self.problem("The passwords don't match.", self.pw2)
        args = ["backup", out]
        for d in self.drives:
            args += [d["name"], d["path"]]
        try:
            self.result = engine(args, CLOAK_BACKUP_PASSPHRASE=self.pw.text())
        except RuntimeError as e:
            return self.problem(f"Couldn't make the backup: {e}", self.out)
        self.result["file"] = out
        return True


class RestoreDialog(FocusedDialog):
    """Put a drive's recovery files back from a backup. Only what's missing or
    can't be read is replaced."""

    def __init__(self, parent, known_drives, mounted):
        super().__init__(parent)
        self.known = known_drives
        self.mounted = mounted
        self.backup = None  # the backup's listing, once opened
        self.titleLabel = SubtitleLabel("Restore from a backup", self)
        what = CaptionLabel(
            "Puts back a drive's header and folder lists where they're missing or "
            "damaged. Anything still readable is left as it is.", self)
        what.setWordWrap(True)
        self.file = LineEdit(self); self.file.setPlaceholderText("Backup file (.cloakbak)")
        self.pick = PushButton("Choose…", self)
        self.bpw = PasswordLineEdit(self); self.bpw.setPlaceholderText("The backup's password")
        self.combo = ComboBox(self)
        self.target = LineEdit(self); self.target.setPlaceholderText("The drive's folder")
        self.pick_target = PushButton("Choose folder…", self)
        self.dpw = PasswordLineEdit(self); self.dpw.setPlaceholderText("The drive's password")
        row = QHBoxLayout(); row.addWidget(self.file); row.addWidget(self.pick)
        row2 = QHBoxLayout(); row2.addWidget(self.target); row2.addWidget(self.pick_target)
        self.viewLayout.addWidget(self.titleLabel)
        self.viewLayout.addWidget(what)
        self.viewLayout.addLayout(row)
        self.viewLayout.addWidget(self.bpw)
        self.second = [self.combo, self.target, self.pick_target, self.dpw]
        self.viewLayout.addWidget(self.combo)
        self.viewLayout.addLayout(row2)
        self.viewLayout.addWidget(self.dpw)
        self.finish_layout()
        for w in self.second:
            w.hide()
        self.yesButton.setText("Open backup")
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(470)
        self.pick.clicked.connect(self._choose)
        self.pick_target.clicked.connect(self._choose_target)
        self.combo.currentIndexChanged.connect(self._drive_chosen)
        self.bpw.returnPressed.connect(self.yesButton.click)
        self.dpw.returnPressed.connect(self.yesButton.click)
        self.first = self.pick
        self.busy_text = "Working…"
        self.result = None

    def _choose(self):
        f, _ = QFileDialog.getOpenFileName(self, "Choose a backup", str(_documents()), "cloak backup (*.cloakbak)")
        if f:
            self.file.setText(os.path.normpath(f))
            self.bpw.setFocus()

    def _choose_target(self):
        d = QFileDialog.getExistingDirectory(self, "The drive's folder", self.target.text() or str(Path.home()))
        if d:
            self.target.setText(os.path.normpath(d))

    def _drive_chosen(self, i):
        if self.backup and 0 <= i < len(self.backup["drives"]):
            d = self.backup["drives"][i]
            # Where it is now, if it's in the list under that name; else where it was.
            here = next((k["path"] for k in self.known if k["name"] == d["name"]), d["path"])
            self.target.setText(os.path.normpath(here))

    def validate(self):
        if self.backup is None:
            return self._open()
        return self._restore()

    def _open(self):
        f = self.file.text().strip()
        if not f:
            return self.problem("Choose the backup file.", self.pick)
        if not os.path.isfile(f):
            return self.problem("That file doesn't exist.", self.file)
        if not self.bpw.text():
            return self.problem("Enter the backup's password.", self.bpw)
        try:
            self.backup = engine(["backup-list", f], CLOAK_BACKUP_PASSPHRASE=self.bpw.text())
        except RuntimeError as e:
            return self.problem(str(e)[:1].upper() + str(e)[1:] + ".", self.bpw)
        if not self.backup.get("drives"):
            self.backup = None
            return self.problem("That backup has no drives in it.", self.file)
        made = datetime.fromtimestamp(self.backup.get("created", 0)).strftime("%d %b %Y, %H:%M")
        self.combo.clear()
        self.combo.addItems([f"{d['name']}  (backed up {made})" for d in self.backup["drives"]])
        for w in (self.file, self.pick, self.bpw):
            w.setEnabled(False)
        for w in self.second:
            w.show()
        self._drive_chosen(0)
        self.yesButton.setText("Restore")
        self.busy_text = "Restoring…"
        self.dpw.setFocus()
        return False  # stay open for step two

    def _restore(self):
        d = self.backup["drives"][self.combo.currentIndex()]
        target = os.path.normpath(self.target.text().strip()) if self.target.text().strip() else ""
        if not target:
            return self.problem("Choose the drive's folder.", self.target)
        if not os.path.isdir(target):
            return self.problem("That folder doesn't exist.", self.target)
        if target in self.mounted:
            return self.problem("That drive is unlocked. Lock it first, then restore.", self.target)
        if not self.dpw.text():
            return self.problem("Enter the drive's password.", self.dpw)
        try:
            r = engine(["restore", self.file.text().strip(), d["name"], target],
                       CLOAK_BACKUP_PASSPHRASE=self.bpw.text(), CLOAK_PASSPHRASE=self.dpw.text())
        except RuntimeError as e:
            field = self.dpw if "password" in str(e) else self.target
            return self.problem(str(e)[:1].upper() + str(e)[1:] + ".", field)
        self.result = {"name": d["name"], "path": target, **r}
        return True


# ---- drive card ------------------------------------------------------------

class DriveCard(CardWidget):
    def __init__(self, drive, mount, callbacks):
        super().__init__()
        self.setFixedSize(260, 158)
        lay = QVBoxLayout(self); lay.setContentsMargins(18, 16, 18, 16); lay.setSpacing(5)

        lay.addWidget(StrongBodyLabel(drive["name"], self))
        path = CaptionLabel(drive["path"], self); path.setWordWrap(True); path.setStyleSheet("color: gray;")
        lay.addWidget(path)
        lay.addStretch(1)

        unlocked = mount is not None
        state = None if unlocked else conversion_state(drive["path"])
        if unlocked:
            status = CaptionLabel(f"● Unlocked · {mount['mp']}", self)
            status.setStyleSheet("color: #13b3a4;")
        elif state:
            what = "Converting" if state == "converting" else "Turning back into a folder"
            status = CaptionLabel(f"◐ {what} wasn't finished", self)
            status.setStyleSheet("color: #ca5010;")
        else:
            status = CaptionLabel("○ Locked", self)
            status.setStyleSheet("color: gray;")
        lay.addWidget(status)

        row = QHBoxLayout()
        if state:
            resumeb = PrimaryPushButton("Resume", self)
            resumeb.clicked.connect(lambda: callbacks["resume"](drive, state))
            removeb = TransparentPushButton("Remove", self)
            removeb.clicked.connect(lambda: callbacks["remove"](drive))
            row.addWidget(resumeb); row.addStretch(1); row.addWidget(removeb)
            lay.addLayout(row)
            return
        if unlocked:
            openb = PushButton("Open", self)
            openb.clicked.connect(lambda: callbacks["open"](drive))
            lockb = PrimaryPushButton("Lock", self)
            lockb.clicked.connect(lambda: callbacks["lock"](drive))
            row.addWidget(openb); row.addStretch(1); row.addWidget(lockb)
        else:
            unlockb = PrimaryPushButton("Unlock", self)
            unlockb.clicked.connect(lambda: callbacks["unlock"](drive))
            removeb = TransparentPushButton("Remove", self)
            removeb.clicked.connect(lambda: callbacks["remove"](drive))
            row.addWidget(unlockb); row.addStretch(1); row.addWidget(removeb)
        backupb = TransparentToolButton(FIF.SAVE, self)
        backupb.setToolTip("Back up this drive's recovery files")
        backupb.installEventFilter(ToolTipFilter(backupb))
        backupb.clicked.connect(lambda: callbacks["backup"](drive))
        row.insertWidget(1, backupb)
        if not unlocked:
            plainb = TransparentToolButton(FIF.RETURN, self)
            plainb.setToolTip("Turn back into a plain folder")
            plainb.installEventFilter(ToolTipFilter(plainb))
            plainb.clicked.connect(lambda: callbacks["unconvert"](drive))
            row.insertWidget(2, plainb)
        lay.addLayout(row)


# ---- drives interface ------------------------------------------------------

class DrivesInterface(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.setObjectName("drivesInterface")
        self.drives = load_drives()
        self.mounts = {}  # path -> {"proc": Popen, "mp": mountpoint}

        lay = QVBoxLayout(self); lay.setContentsMargins(36, 28, 36, 28); lay.setSpacing(16)
        head = QHBoxLayout()
        head.addWidget(TitleLabel("Your drives", self)); head.addStretch(1)
        addbtn = PushButton(FIF.FOLDER, "Add existing", self)
        addbtn.clicked.connect(self.import_existing)
        convbtn = PushButton(FIF.SYNC, "Convert folder", self)
        convbtn.setToolTip("Make a folder you already have into a drive, without copying it")
        convbtn.installEventFilter(ToolTipFilter(convbtn))
        convbtn.clicked.connect(lambda: self.convert_folder())
        newbtn = PrimaryPushButton(FIF.ADD, "New drive", self)
        newbtn.clicked.connect(self.create_drive)
        head.addWidget(addbtn)
        head.addWidget(convbtn)
        head.addWidget(newbtn)
        lay.addLayout(head)
        lay.addWidget(CaptionLabel("Unlock a drive to mount it — then work with your files in Explorer.", self))

        self.host = QWidget(self)
        self.cards = FlowLayout(self.host, needAni=True)
        self.cards.setHorizontalSpacing(16); self.cards.setVerticalSpacing(16)
        lay.addWidget(self.host)
        lay.addStretch(1)
        self.refresh()

    def refresh(self):
        while self.cards.count():
            item = self.cards.takeAt(0)
            if item is None:
                continue
            # FlowLayout.takeAt may return the widget directly or a QLayoutItem.
            w = item.widget() if hasattr(item, "widget") else item
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        cbs = {"unlock": self.unlock, "lock": self.lock, "open": self.open_drive, "remove": self.remove,
               "backup": lambda d: self.back_up([d]), "resume": self.resume_conversion,
               "unconvert": self.unconvert}
        for d in self.drives:
            self.cards.addWidget(DriveCard(d, self.mounts.get(d["path"]), cbs))

    def err(self, msg):
        InfoBar.error("Error", msg, duration=4500, position=InfoBarPosition.TOP, parent=self.win)

    def ok(self, msg):
        InfoBar.success("Done", msg, duration=2500, position=InfoBarPosition.TOP, parent=self.win)

    def create_drive(self):
        dlg = CreateDialog(self.win)
        if not dlg.exec() or not dlg.created:
            return
        name, loc = dlg.created
        self.drives = [d for d in self.drives if d["path"] != loc]
        self.drives.insert(0, {"name": name, "path": loc})
        save_drives(self.drives)
        self.refresh()
        self.ok(f"Created “{name}”. Unlock it to mount.")

    def import_existing(self):
        dlg = AddExistingDialog(self.win, {os.path.normpath(d["path"]) for d in self.drives})
        if not dlg.exec() or not dlg.added:
            return
        name, folder = dlg.added
        self.drives.insert(0, {"name": name, "path": folder})
        save_drives(self.drives)
        self.refresh()
        self.ok(f"Added “{name}”. Unlock it to mount.")

    def convert_folder(self, resume=None):
        known = {os.path.normpath(d["path"]) for d in self.drives}
        dlg = ConvertDialog(self.win, known, resume)
        if not dlg.exec() or not dlg.converted:
            self.refresh()  # an interrupted run shows as such on its card
            return
        name, loc = dlg.converted
        if not any(os.path.normpath(d["path"]) == loc for d in self.drives):
            self.drives.insert(0, {"name": name, "path": loc})
            save_drives(self.drives)
        self.refresh()
        self.ok(f"“{name}” is now a drive. Unlock it to mount.")

    def resume_conversion(self, drive, state):
        if state == "converting":
            self.convert_folder(resume=drive)
        else:
            self.unconvert(drive)

    def unconvert(self, drive):
        if drive["path"] in self.mounts:
            return self.err("Lock the drive first.")
        dlg = UnconvertDialog(self.win, drive)
        dlg.exec()
        if dlg.done:
            self.drives = [d for d in self.drives if d["path"] != drive["path"]]
            save_drives(self.drives)
            self.ok(f"“{drive['name']}” is a plain folder again: {drive['path']}")
        self.refresh()

    def unlock(self, drive):
        letters = free_drive_letters()
        if IS_WIN and not letters:
            return self.err("No free drive letters available. Free one and try again.")
        mounted = {}

        def mount(pw, letter):
            mp = letter if IS_WIN else str(Path.home() / "cloak-mnt" / drive["name"])
            failure = self._mount(drive, pw, mp)
            if not failure:
                mounted["mp"] = mp
            return failure

        dlg = UnlockDialog(self.win, drive["name"], drive["path"], letters, mount)
        if not dlg.exec() or "mp" not in mounted:
            return
        mp = mounted["mp"]
        self.refresh()
        self.ok(f"Unlocked at {mp}")
        QTimer.singleShot(300, lambda: open_in_file_manager(mp))

    def _mount(self, drive, pw, mp):
        """Mount `drive` at `mp`. Returns an error message for the user, or
        None once the drive is up (and recorded in self.mounts)."""
        if not IS_WIN:
            Path(mp).mkdir(parents=True, exist_ok=True)
        adapter = _find("cloak-winmount" if IS_WIN else "cloak-mount")
        env = os.environ.copy(); env["CLOAK_PASSPHRASE"] = pw
        wb = winfsp_bin()
        if IS_WIN and not wb:
            return "WinFsp isn't installed. Install it (winget install WinFsp.WinFsp) and try again."
        if wb:
            env["PATH"] = wb + os.pathsep + env.get("PATH", "")
        # Give the adapter real places to write: started from Explorer or
        # Finder, the app has no console, and an adapter left with a dead
        # output handle can fail on its first message. Its errors go to a
        # file so they can be shown if the mount doesn't come up.
        errors = tempfile.TemporaryFile()
        try:
            proc = subprocess.Popen(
                [adapter, drive["path"], mp],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=errors, env=env, **NO_WINDOW,
            )
        except FileNotFoundError:
            return (
                f"The mount driver ({Path(adapter).name}) is missing. Keep the app's "
                f"folder together, including bin, or download Cloak again."
            )
        except OSError as e:
            return f"Couldn't start the mount driver: {e.strerror or e}."
        if not self._wait_for_mount(proc, mp):
            try:
                proc.kill()
            except Exception:
                pass
            errors.seek(0)
            # Everything the driver said: the system's own reason (from macFUSE
            # or WinFsp) usually comes before the driver's summary line.
            lines = [l.strip() for l in errors.read().decode(errors="replace").splitlines() if l.strip()]
            detail = "\n".join(lines)[-1500:] if lines else "the mount driver stopped without saying why"
            return f"Couldn't mount the drive:\n{detail}"
        self.mounts[drive["path"]] = {"proc": proc, "mp": mp}
        return None

    def _wait_for_mount(self, proc, mp, timeout=15.0):
        """True once `mp` is mounted; False if the adapter exits first or the
        mount doesn't appear in time. Keeps the window responsive meanwhile."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            if (os.path.exists(mp + "\\") if IS_WIN else os.path.ismount(mp)):
                return True
            QApplication.processEvents()
            time.sleep(0.1)
        return False

    def back_up(self, drives):
        if not drives:
            return self.err("There are no drives to back up yet.")
        dlg = BackupDialog(self.win, drives)
        if not dlg.exec() or not dlg.result:
            return
        n = len(drives)
        self.ok(f"Backed up {'the drive' if n == 1 else f'{n} drives'} to {dlg.result['file']}")

    def restore(self):
        dlg = RestoreDialog(self.win, self.drives, {os.path.normpath(p) for p in self.mounts})
        if not dlg.exec() or not dlg.result:
            return
        r = dlg.result
        if not any(os.path.normpath(d["path"]) == r["path"] for d in self.drives):
            self.drives.insert(0, {"name": r["name"], "path": r["path"]})
            save_drives(self.drives)
            self.refresh()
        if r["restored"]:
            n = len(r["restored"])
            msg = f"Restored {n} file{'s' if n != 1 else ''} to “{r['name']}”."
        else:
            msg = f"Nothing needed restoring: everything in “{r['name']}” is readable."
        if r["skipped"]:
            msg += f" {len(r['skipped'])} folder list(s) were skipped because those folders are gone."
        self.ok(msg)

    def lock(self, drive):
        self._unmount(drive["path"])
        self.refresh()

    def _unmount(self, path):
        m = self.mounts.pop(path, None)
        if not m:
            return
        proc = m["proc"]
        # Closing stdin tells the adapter to unmount cleanly and save its last
        # changes (folder lists are saved half a second after they change);
        # give it time, then force-terminate as a fallback.
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

    def open_drive(self, drive):
        m = self.mounts.get(drive["path"])
        if m:
            open_in_file_manager(m["mp"])

    def remove(self, drive):
        self.drives = [d for d in self.drives if d["path"] != drive["path"]]
        save_drives(self.drives)
        self.refresh()

    def lock_all(self):
        for path in list(self.mounts.keys()):
            self._unmount(path)


# ---- settings --------------------------------------------------------------

class SettingsInterface(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.setObjectName("settingsInterface")
        lay = QVBoxLayout(self); lay.setContentsMargins(36, 28, 36, 28); lay.setSpacing(12)
        lay.addWidget(TitleLabel("Settings", self))

        lay.addWidget(StrongBodyLabel("Appearance", self))
        lay.addWidget(CaptionLabel("Choose a theme.", self))
        group = QButtonGroup(self)
        current = load_settings()["theme"]
        for label, name in (("System", "system"), ("Light", "light"), ("Dark", "dark")):
            rb = RadioButton(label, self)
            rb.clicked.connect(lambda _=False, n=name: self.set_theme(n))
            rb.setChecked(name == current)
            group.addButton(rb)
            lay.addWidget(rb)

        lay.addSpacing(10)
        lay.addWidget(StrongBodyLabel("Security", self))
        row = QHBoxLayout()
        row.addWidget(BodyLabel("Auto-lock drives when the computer sleeps", self))
        row.addStretch(1)
        sw = SwitchButton(self)
        sw.setChecked(win.auto_lock)
        sw.checkedChanged.connect(self.set_auto_lock)
        row.addWidget(sw)
        lay.addLayout(row)
        lay.addWidget(CaptionLabel("Drives always unmount on shutdown and when you quit.", self))

        lay.addSpacing(10)
        lay.addWidget(StrongBodyLabel("Storage", self))
        if PORTABLE:
            where = f"Your drive list and settings are kept with the app, in {DATA_DIR}."
        elif _installed():
            where = (
                f"Cloak is installed in Applications, so your drive list and settings are "
                f"kept in {DATA_DIR}. To keep them with the app instead (on a USB stick, "
                f"say), run Cloak from any other folder."
            )
        else:
            where = (
                f"The app's folder can't be written to, so your drive list and settings are "
                f"kept in {DATA_DIR}. Move the app to a folder you can write to (such as a "
                f"USB stick) to keep them with the app instead."
            )
        note = CaptionLabel(where, self)
        note.setWordWrap(True)
        lay.addWidget(note)

        lay.addSpacing(10)
        lay.addWidget(StrongBodyLabel("Recovery", self))
        rec = CaptionLabel(
            "If a drive's header or a folder list is lost or damaged, the drive (or that "
            "folder) can't be opened. Back them up into a password-protected file and "
            "restore from it if that happens. Each drive also has its own Back up button.",
            self)
        rec.setWordWrap(True)
        lay.addWidget(rec)
        brow = QHBoxLayout()
        allb = PushButton(FIF.SAVE, "Back up all drives…", self)
        allb.clicked.connect(lambda: win.drives.back_up(list(win.drives.drives)))
        restb = PushButton(FIF.HISTORY, "Restore from a backup…", self)
        restb.clicked.connect(win.drives.restore)
        brow.addWidget(allb); brow.addWidget(restb); brow.addStretch(1)
        lay.addLayout(brow)

        lay.addStretch(1)

    def set_theme(self, name):
        setTheme(THEMES[name])
        save_setting("theme", name)

    def set_auto_lock(self, on):
        self.win.auto_lock = on
        save_setting("auto_lock", on)


# ---- window ----------------------------------------------------------------

class Cloak(FluentWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("cloak")
        self.resize(820, 560)
        self.navigationInterface.setReturnButtonVisible(False)
        if sys.platform == "darwin":
            # The traffic lights take the top-left corner (systemTitleBarRect):
            # the sidebar's menu button and items start below them, and the
            # title bar (which the library puts at x=46) starts its contents,
            # the app name, after them.
            panel = self.navigationInterface.panel.vBoxLayout
            m = panel.contentsMargins()
            panel.setContentsMargins(m.left(), self.LIGHTS_BOTTOM, m.right(), m.bottom())
            m = self.titleBar.hBoxLayout.contentsMargins()
            left = self.LIGHTS_W + 12 - 46
            self.titleBar.hBoxLayout.setContentsMargins(left, m.top(), m.right(), m.bottom())
        self.auto_lock = load_settings()["auto_lock"]
        self.drives = DrivesInterface(self)
        self.settings = SettingsInterface(self)
        self.addSubInterface(self.drives, FIF.FOLDER, "Drives")
        self.addSubInterface(self.settings, FIF.SETTING, "Settings", NavigationItemPosition.BOTTOM)

    def on_power(self, kind):
        # Shutdown/logoff always locks (clean teardown); sleep respects the setting.
        if kind == "shutdown" or self.auto_lock:
            self.drives.lock_all()
            self.drives.refresh()

    def closeEvent(self, e):
        self.drives.lock_all()
        super().closeEvent(e)

    # The traffic lights' strip on macOS: its width, and where the sidebar
    # starts below it.
    LIGHTS_W, LIGHTS_BOTTOM = 75, 38

    def systemTitleBarRect(self, size):
        # Where macOS's traffic lights go. The widget library puts them top
        # right, clear of its back and menu buttons; Mac windows have them in
        # the top-left corner, with the sidebar below (the back button is
        # hidden: two pages need no history).
        return QRect(0, 0 if self.isFullScreen() else 8, self.LIGHTS_W, size.height())


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    if IS_WIN:
        # Our own taskbar identity, so the taskbar shows cloak's icon rather
        # than that of the Python running it (when run from source).
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("cloak.app")
        except Exception:
            pass
    app = QApplication(sys.argv)
    # On macOS the window icon also replaces the Dock icon, and this PNG is
    # cropped edge to edge for Windows; the app bundle's .icns has the
    # margin macOS icons are drawn with, so a packaged Mac app keeps that.
    if not (FROZEN and sys.platform == "darwin"):
        app.setWindowIcon(QIcon(str(ICON)))
    setTheme(THEMES[load_settings()["theme"]])
    setThemeColor(QColor("#13b3a4"))
    w = Cloak()
    install_power_hook(app, w.on_power)
    app.aboutToQuit.connect(w.drives.lock_all)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
