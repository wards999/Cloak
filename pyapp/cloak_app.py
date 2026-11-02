"""cloak — a Fluent-design drive manager (PySide6 + QFluentWidgets).

Minimal by design: create drives, and lock / unlock them. Unlocking mounts the
drive and opens it in your file manager; all file work happens there. The crypto
and storage are the Rust `cloak` engine, reached through the `cloak` CLI (to
verify the password) and the `cloak-winmount` / `cloak-mount` adapter (to mount).
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QFileDialog, QHBoxLayout, QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    FluentWindow, FluentIcon as FIF, NavigationItemPosition, setTheme, setThemeColor,
    Theme, TitleLabel, SubtitleLabel, BodyLabel, StrongBodyLabel, CaptionLabel,
    PrimaryPushButton, PushButton, TransparentPushButton, LineEdit, PasswordLineEdit,
    ComboBox, CardWidget, MessageBoxBase, FlowLayout, InfoBar, InfoBarPosition,
    RadioButton, SwitchButton,
)

APP_DIR = Path(__file__).resolve().parent
# A packaged app (PyInstaller) keeps the engine in `bin` next to its executable.
FROZEN = getattr(sys, "frozen", False)
EXE_DIR = Path(sys.executable).resolve().parent if FROZEN else APP_DIR
CONFIG = Path.home() / ".cloak" / "drives.json"
SETTINGS = Path.home() / ".cloak" / "settings.json"
ICON = APP_DIR / "assets" / "icon.png"
IS_WIN = sys.platform.startswith("win")
# Engine calls from a windowed app would each flash a console window.
NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}


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


def load_drives():
    try:
        return json.loads(CONFIG.read_text())
    except Exception:
        return []


def save_drives(drives):
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(json.dumps(drives, indent=2))
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

class CreateDialog(MessageBoxBase):
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
        self.yesButton.setText("Create drive")
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(430)
        self.pick.clicked.connect(self._choose)

    def _choose(self):
        d = QFileDialog.getExistingDirectory(self, "Choose an empty folder for the drive")
        if d:
            self.loc.setText(d)


class UnlockDialog(MessageBoxBase):
    def __init__(self, parent, name, path, letters):
        super().__init__(parent)
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


class NameDialog(MessageBoxBase):
    def __init__(self, parent, title, placeholder):
        super().__init__(parent)
        self.titleLabel = SubtitleLabel(title, self)
        self.edit = LineEdit(self); self.edit.setPlaceholderText(placeholder)
        self.viewLayout.addWidget(self.titleLabel)
        self.viewLayout.addWidget(self.edit)
        self.yesButton.setText("OK")
        self.cancelButton.setText("Cancel")
        self.widget.setMinimumWidth(360)
        self.edit.returnPressed.connect(self.yesButton.click)


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
        status = CaptionLabel(
            f"● Unlocked · {mount['mp']}" if unlocked else "○ Locked", self
        )
        status.setStyleSheet("color: #13b3a4;" if unlocked else "color: gray;")
        lay.addWidget(status)

        row = QHBoxLayout()
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
        newbtn = PrimaryPushButton(FIF.ADD, "New drive", self)
        newbtn.clicked.connect(self.create_drive)
        head.addWidget(addbtn)
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
        cbs = {"unlock": self.unlock, "lock": self.lock, "open": self.open_drive, "remove": self.remove}
        for d in self.drives:
            self.cards.addWidget(DriveCard(d, self.mounts.get(d["path"]), cbs))

    def err(self, msg):
        InfoBar.error("Error", msg, duration=4500, position=InfoBarPosition.TOP, parent=self.win)

    def ok(self, msg):
        InfoBar.success("Done", msg, duration=2500, position=InfoBarPosition.TOP, parent=self.win)

    def create_drive(self):
        dlg = CreateDialog(self.win)
        if not dlg.exec():
            return
        name, loc, pw, pw2 = dlg.name.text().strip(), dlg.loc.text().strip(), dlg.pw.text(), dlg.pw2.text()
        if not name or not loc or not pw:
            return self.err("Name, location and password are required.")
        if pw != pw2:
            return self.err("Passwords don't match.")
        try:
            create_store(loc, pw)
        except RuntimeError as e:
            return self.err(str(e))
        self.drives = [d for d in self.drives if d["path"] != loc]
        self.drives.insert(0, {"name": name, "path": loc})
        save_drives(self.drives)
        self.refresh()
        self.ok(f"Created “{name}”. Unlock it to mount.")

    def import_existing(self):
        folder = QFileDialog.getExistingDirectory(self, "Select an existing cloak drive folder")
        if not folder:
            return
        if not (Path(folder) / "meta.json").exists():
            return self.err("That folder isn't a cloak drive (no drive metadata found).")
        if any(d["path"] == folder for d in self.drives):
            return self.err("That drive is already in your list.")
        dlg = NameDialog(self.win, "Add existing drive", "Name for this drive")
        dlg.edit.setText(Path(folder).name)
        if not dlg.exec():
            return
        name = dlg.edit.text().strip() or Path(folder).name
        self.drives.insert(0, {"name": name, "path": folder})
        save_drives(self.drives)
        self.refresh()
        self.ok(f"Added “{name}”. Unlock it to mount.")

    def unlock(self, drive):
        letters = free_drive_letters()
        if IS_WIN and not letters:
            return self.err("No free drive letters available. Free one and try again.")
        dlg = UnlockDialog(self.win, drive["name"], drive["path"], letters)
        if not dlg.exec():
            return
        pw = dlg.pw.text()
        try:
            verify(drive["path"], pw)
        except RuntimeError as e:
            return self.err(str(e))

        if IS_WIN:
            mp = dlg.combo.currentText() if dlg.combo else ""
            if not mp:
                return self.err("Choose a drive letter.")
            # Re-check right before mounting — it may have been taken meanwhile.
            if mp in used_drive_letters():
                return self.err(f"{mp} is no longer free — pick another and try again.")
        else:
            mp = str(Path.home() / "cloak-mnt" / drive["name"])
            Path(mp).mkdir(parents=True, exist_ok=True)

        adapter = _find("cloak-winmount" if IS_WIN else "cloak-mount")
        env = os.environ.copy(); env["CLOAK_PASSPHRASE"] = pw
        wb = winfsp_bin()
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
        except OSError as e:
            return self.err(f"Couldn't start the mount driver ({e}). Is it installed?")
        if not self._wait_for_mount(proc, mp):
            try:
                proc.kill()
            except Exception:
                pass
            errors.seek(0)
            lines = [l for l in errors.read().decode(errors="replace").splitlines() if l.strip()]
            detail = lines[-1].strip() if lines else "it stopped without saying why"
            return self.err(f"The drive couldn't be mounted: {detail}")
        self.mounts[drive["path"]] = {"proc": proc, "mp": mp}
        self.refresh()
        self.ok(f"Unlocked at {mp}")
        QTimer.singleShot(300, lambda: open_in_file_manager(mp))

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
