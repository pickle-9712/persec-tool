"""
settings.py - window for changing what the live overlay hides and how it looks.

Saving writes config.json; the running overlay picks the changes up within a
second (no restart needed). Also starts/stops the overlay and can make it start
with Windows.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on high-DPI screens
APP_ID = "opsec-tool.settings"
# own taskbar identity (matches the Start menu shortcut) instead of "Python"
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)

import tkinter as tk  # noqa: E402
from tkinter import colorchooser, messagebox, ttk  # noqa: E402
from tkinter import font as tkfont  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import redact  # noqa: E402

CONFIG = HERE / "config.json"
PIDFILE = HERE / "live.pid"
PYTHONW = HERE / ".venv" / "Scripts" / "pythonw.exe"
STARTUP_LNK = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
               / "Startup" / "opsec-tool live redaction.lnk")

k32 = ctypes.windll.kernel32
u32 = ctypes.windll.user32

PROTON_DARK = (30, 28, 36)  # the old VpnPrivacy tool's colour: blends into Proton's background
PRESETS = [("Grey", (128, 128, 128)), ("Black", (0, 0, 0)), ("Charcoal", (40, 42, 48)),
           ("White", (245, 245, 245)), ("Purple", (124, 92, 255)), ("Pink", (255, 105, 180))]


# --------------------------------------------------------------------------- #
# Overlay process control
# --------------------------------------------------------------------------- #
def process_name(pid: int) -> str:
    h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(512)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return Path(buf.value).name
        return ""
    finally:
        k32.CloseHandle(h)


def overlay_pid() -> int | None:
    try:
        pid = int(PIDFILE.read_text().strip())
    except (OSError, ValueError):
        return None
    h = k32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(h, ctypes.byref(code))
        alive = code.value == 259  # STILL_ACTIVE
    finally:
        k32.CloseHandle(h)
    return pid if alive and "python" in process_name(pid).lower() else None


def start_overlay():
    subprocess.Popen([str(PYTHONW), str(HERE / "live.py")], cwd=str(HERE),
                     creationflags=0x00000008 | 0x00000200)  # detached, own process group


def stop_overlay():
    pid = overlay_pid()
    if pid:
        h = k32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
        if h:
            k32.TerminateProcess(h, 0)
            k32.CloseHandle(h)


def set_startup(on: bool):
    if on:
        ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{STARTUP_LNK}');"
              f"$s.TargetPath='{PYTHONW}';$s.Arguments='\"{HERE / 'live.py'}\"';"
              f"$s.WorkingDirectory='{HERE}';$s.Save()")
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], creationflags=0x08000000)
    else:
        STARTUP_LNK.unlink(missing_ok=True)


def create_shortcut(path: Path):
    """Shortcut that opens this window, with the app's icon and taskbar identity
    (so a pinned icon and the open window share one taskbar button)."""
    import comtypes
    import comtypes.client
    from comtypes import COMMETHOD, GUID, HRESULT, IUnknown
    from comtypes.persist import IPersistFile
    from comtypes.shelllink import IShellLinkW, ShellLink

    class PROPERTYKEY(ctypes.Structure):
        _fields_ = [("fmtid", GUID), ("pid", wintypes.DWORD)]

    class PROPVARIANT(ctypes.Structure):
        _fields_ = [("vt", ctypes.c_ushort), ("r1", ctypes.c_ushort), ("r2", ctypes.c_ushort),
                    ("r3", ctypes.c_ushort), ("pwszVal", ctypes.c_wchar_p), ("pad", ctypes.c_void_p)]

    class IPropertyStore(IUnknown):
        _iid_ = GUID("{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}")
        _methods_ = [
            COMMETHOD([], HRESULT, "GetCount", (["out"], ctypes.POINTER(wintypes.DWORD), "c")),
            COMMETHOD([], HRESULT, "GetAt", (["in"], wintypes.DWORD, "i"),
                      (["out"], ctypes.POINTER(PROPERTYKEY), "k")),
            COMMETHOD([], HRESULT, "GetValue", (["in"], ctypes.POINTER(PROPERTYKEY), "k"),
                      (["out"], ctypes.POINTER(PROPVARIANT), "v")),
            COMMETHOD([], HRESULT, "SetValue", (["in"], ctypes.POINTER(PROPERTYKEY), "k"),
                      (["in"], ctypes.POINTER(PROPVARIANT), "v")),
            COMMETHOD([], HRESULT, "Commit"),
        ]

    link = comtypes.client.CreateObject(ShellLink, interface=IShellLinkW)
    link.SetPath(str(PYTHONW))
    link.SetArguments(f'"{HERE / "settings.py"}"')
    link.SetWorkingDirectory(str(HERE))
    link.SetIconLocation(str(HERE / "icon.ico"), 0)
    link.SetDescription("Covers your personal info on screen")
    store = link.QueryInterface(IPropertyStore)
    key = PROPERTYKEY(GUID("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}"), 5)  # PKEY_AppUserModel_ID
    store.SetValue(ctypes.byref(key), ctypes.byref(PROPVARIANT(vt=31, pwszVal=APP_ID)))  # VT_LPWSTR
    store.Commit()
    path.parent.mkdir(parents=True, exist_ok=True)
    link.QueryInterface(IPersistFile).Save(str(path), True)


def running_apps() -> list[str]:
    """Process names of apps that currently have a visible window."""
    names = set()
    proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def cb(h, _):
        if u32.IsWindowVisible(h) and u32.GetWindowTextLengthW(h) > 0:
            pid = wintypes.DWORD()
            u32.GetWindowThreadProcessId(h, ctypes.byref(pid))
            n = process_name(pid.value)
            if n:
                names.add(n.removesuffix(".exe"))
        return True

    u32.EnumWindows(proc(cb), 0)
    return sorted(names, key=str.lower)


# --------------------------------------------------------------------------- #
# Window
# --------------------------------------------------------------------------- #
class Settings:
    def __init__(self):
        self.cfg = self.load()
        self.root = tk.Tk()
        self.root.title("settings")
        try:
            self.root.iconbitmap(default=str(HERE / "icon.ico"))
        except tk.TclError:
            pass
        self.root.minsize(760, 640)
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Sub.TLabel", foreground="#666")
        style.configure("Hint.TLabel", foreground="#777")
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10))
        self.root.option_add("*Font", ("Segoe UI", 10))

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)
        self.build_header(outer)
        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True, pady=(12, 12))
        self.build_hide_tab(nb)
        self.build_detect_tab(nb)
        self.build_look_tab(nb)
        self.build_apps_tab(nb)
        self.build_proton_tab(nb)
        self.build_footer(outer)

        self.saved = self.collect()
        self.refresh_status()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- config ----------
    @staticmethod
    def load() -> dict:
        cfg = json.loads(json.dumps(redact.DEFAULT_CONFIG))
        try:
            user = json.loads(CONFIG.read_text(encoding="utf-8-sig"))
            cfg["detect"].update(user.pop("detect", {}))
            cfg.update(user)
        except (OSError, ValueError):
            pass
        return cfg

    def collect(self) -> dict:
        cfg = json.loads(json.dumps(self.cfg))  # keeps any settings this window doesn't show
        for key, box in self.lists.items():
            cfg[key] = [ln.strip() for ln in box.get("1.0", "end").splitlines() if ln.strip()]
        for key, var in self.checks.items():
            cfg["detect"][key] = bool(var.get())
        cfg["box_color"] = list(self.color)
        cfg["padding"] = int(self.padding.get())
        cfg["corner_radius"] = int(self.radius.get())
        cfg["animation"] = bool(self.animate.get())
        cfg["animation_ms"] = int(self.anim_ms.get())
        cfg["live_ignore_processes"] = list(self.ignored.get(0, "end"))
        cfg["docs_ocr"] = bool(self.docs_ocr.get())
        cfg["scan_cover"] = bool(self.scan_cover.get())
        cfg["scan_cover_match_app"] = bool(self.cover_match.get())
        cfg["scan_cover_apps"] = [a.strip().removesuffix(".exe") for a in self.cover_apps.get().split(",") if a.strip()]
        pv = dict(cfg.get("proton_vpn") or {})
        pv["enabled"] = bool(self.pv_enabled.get())
        for key, var in self.pv_parts.items():
            pv[key] = bool(var.get())
        mode = self.pv_color_mode.get()
        pv["color"] = (list(PROTON_DARK) if mode == "blend"
                       else None if mode == "same" else list(self.pv_custom))
        cfg["proton_vpn"] = pv
        return cfg

    def save(self):
        cfg = self.collect()
        tmp = CONFIG.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        os.replace(tmp, CONFIG)  # atomic: the overlay never reads a half-written file
        self.cfg, self.saved = cfg, cfg
        running = overlay_pid() is not None
        self.message.set("Saved. Applied to the running overlay." if running
                         else "Saved. The overlay isn't running - press Start.")

    # ---------- header / footer ----------
    def build_header(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x")
        left = ttk.Frame(top)
        left.pack(side="left")
        ttk.Label(left, text="opsec-tool", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text="Covers your personal info on screen with boxes.",
                  style="Sub.TLabel").pack(anchor="w")
        right = ttk.Frame(top)
        right.pack(side="right")
        self.dot = tk.Canvas(right, width=14, height=14, highlightthickness=0, bg=self.root.cget("bg"))
        self.dot.pack(side="left", padx=(0, 6))
        self.status = tk.StringVar()
        ttk.Label(right, textvariable=self.status, width=9).pack(side="left")
        self.start_btn = ttk.Button(right, text="Start", command=self.on_start)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(right, text="Stop", command=self.on_stop)
        self.stop_btn.pack(side="left")

    def build_footer(self, parent):
        bottom = ttk.Frame(parent)
        bottom.pack(fill="x")
        self.autostart = tk.BooleanVar(value=STARTUP_LNK.exists())
        ttk.Checkbutton(bottom, text="Start automatically when I log in to Windows",
                        variable=self.autostart, command=lambda: set_startup(self.autostart.get())
                        ).pack(side="left")
        ttk.Button(bottom, text="Save", style="Accent.TButton", command=self.save).pack(side="right")
        ttk.Button(bottom, text="Undo changes", command=self.revert).pack(side="right", padx=8)
        self.message = tk.StringVar()
        ttk.Label(parent, textvariable=self.message, style="Hint.TLabel").pack(anchor="e", pady=(6, 0))

    # ---------- tab: what to hide ----------
    def build_hide_tab(self, nb):
        tab = ttk.Frame(nb, padding=14)
        nb.add(tab, text="  What to hide  ")
        ttk.Label(tab, text="One per line. Capitals don't matter. Names and places match whole words; "
                            "usernames also match inside longer words.",
                  style="Hint.TLabel", wraplength="6.5i").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        fields = [("first_name", "First names / nicknames"), ("last_name", "Last names"),
                  ("locations", "Places (city, town, school, street...)"), ("emails", "Email addresses"),
                  ("extra_terms", "Usernames and anything else")]
        self.lists = {}
        for i, (key, label) in enumerate(fields):
            r, c = 1 + (i // 2) * 2, i % 2
            span = 2 if key == "extra_terms" else 1
            ttk.Label(tab, text=label).grid(row=r, column=c, columnspan=span, sticky="w", padx=(0 if c == 0 else 10, 0))
            box = tk.Text(tab, height=5, width=36, wrap="none", relief="solid", borderwidth=1,
                          font=("Segoe UI", 10), padx=6, pady=4)
            box.grid(row=r + 1, column=c, columnspan=span, sticky="nsew",
                     padx=(0 if c == 0 else 10, 0), pady=(2, 10))
            box.insert("1.0", "\n".join(redact.as_list(self.cfg.get(key))))
            box.bind("<<Modified>>", lambda e: (e.widget.edit_modified(False), self.update_preview()))
            self.lists[key] = box
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)

    # ---------- tab: detection ----------
    def build_detect_tab(self, nb):
        tab = ttk.Frame(nb, padding=14)
        nb.add(tab, text="  Detection  ")
        d = self.cfg["detect"]
        self.checks = {}
        rows = [
            ("my_name", "Your names and everything in your lists", "Matches the lists on the first tab."),
            ("ip_addresses", "IP addresses", "IPv4 and IPv6, found automatically. Version numbers are ignored."),
            ("emails", "Any email address", "Not just the ones in your list. Off = only your listed emails."),
            ("street_addresses", "Street addresses", "Things like \"123 Main St\"."),
            ("locations_ml", "Place names (AI)", "Finds cities/countries that aren't in your list. "
                                                  "Uses ~400 MB memory and some CPU; can mis-flag words."),
        ]
        for i, (key, label, hint) in enumerate(rows):
            var = tk.BooleanVar(value=bool(d.get(key)))
            self.checks[key] = var
            ttk.Checkbutton(tab, text=label, variable=var).grid(row=i * 2, column=0, sticky="w", pady=(8, 0))
            ttk.Label(tab, text=hint, style="Hint.TLabel").grid(row=i * 2 + 1, column=0, sticky="w", padx=(24, 0))

        r = len(rows) * 2
        self.docs_ocr = tk.BooleanVar(value=bool(self.cfg.get("docs_ocr", True)))
        ttk.Checkbutton(tab, text="Google Docs (reads the page with OCR)", variable=self.docs_ocr
                        ).grid(row=r, column=0, sticky="w", pady=(8, 0))
        ttk.Label(tab, text="Docs draws text as an image, so it's read from pixels, only while a Docs tab "
                            "is showing. Boxes there update a little slower than elsewhere.",
                  style="Hint.TLabel", wraplength="6.3i").grid(row=r + 1, column=0, sticky="w", padx=(24, 0))
        r += 2
        ttk.Separator(tab).grid(row=r, column=0, sticky="ew", pady=(16, 4))
        self.scan_cover = tk.BooleanVar(value=bool(self.cfg.get("scan_cover", True)))
        ttk.Checkbutton(tab, text="Black out a window while it's being scanned", variable=self.scan_cover
                        ).grid(row=r + 1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(tab, text="When you switch tabs, load a site or switch channels, the window goes black "
                            "until its boxes are placed (usually under half a second).",
                  style="Hint.TLabel", wraplength="6.3i").grid(row=r + 2, column=0, sticky="w", padx=(24, 0))
        self.cover_match = tk.BooleanVar(value=bool(self.cfg.get("scan_cover_match_app", True)))
        ttk.Checkbutton(tab, text="Use each app's main color instead of black (learned while you use it)",
                        variable=self.cover_match).grid(row=r + 5, column=0, sticky="w", padx=(24, 0), pady=(8, 0))
        ttk.Label(tab, text="In these apps (comma-separated):").grid(row=r + 3, column=0, sticky="w",
                                                                     padx=(24, 0), pady=(6, 2))
        apps = self.cfg.get("scan_cover_apps") or ["brave", "chrome", "msedge", "firefox", "opera",
                                                    "vivaldi", "Discord", "Signal"]
        self.cover_apps = tk.StringVar(value=", ".join(apps))
        ttk.Entry(tab, textvariable=self.cover_apps, width=70).grid(row=r + 4, column=0, sticky="w", padx=(24, 0))

    # ---------- tab: appearance ----------
    def build_look_tab(self, nb):
        tab = ttk.Frame(nb, padding=14)
        nb.add(tab, text="  Appearance  ")
        self.color = tuple(self.cfg.get("box_color", [128, 128, 128]))

        ttk.Label(tab, text="Box color").grid(row=0, column=0, sticky="w")
        row = ttk.Frame(tab)
        row.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 12))
        self.swatch = tk.Canvas(row, width="0.4i", height="0.26i", highlightthickness=1, highlightbackground="#999")
        self.swatch.pack(side="left")
        ttk.Button(row, text="Choose...", command=self.pick_color).pack(side="left", padx=(8, 12))
        for name, rgb in PRESETS:
            c = tk.Canvas(row, width="0.24i", height="0.24i", highlightthickness=1, highlightbackground="#bbb",
                          bg="#%02x%02x%02x" % rgb, cursor="hand2")
            c.pack(side="left", padx=3)
            c.bind("<Button-1>", lambda e, v=rgb: self.set_color(v))
            c.bind("<Enter>", lambda e, n=name: self.message.set(n))

        def slider(r, label, var, lo, hi, unit):
            ttk.Label(tab, text=label).grid(row=r, column=0, sticky="w", pady=6)
            ttk.Scale(tab, from_=lo, to=hi, variable=var, length="3i",
                      command=lambda v: (var.set(round(float(v))), self.update_preview())
                      ).grid(row=r, column=1, sticky="w", padx=10)
            ttk.Label(tab, textvariable=var, width=4).grid(row=r, column=2, sticky="w")
            ttk.Label(tab, text=unit, style="Hint.TLabel").grid(row=r, column=3, sticky="w")

        self.padding = tk.IntVar(value=int(self.cfg.get("padding", 4)))
        self.radius = tk.IntVar(value=int(self.cfg.get("corner_radius", 0)))
        self.anim_ms = tk.IntVar(value=int(self.cfg.get("animation_ms", 120)))
        self.animate = tk.BooleanVar(value=bool(self.cfg.get("animation", True)))
        slider(2, "Extra space around text", self.padding, 0, 20, "px")
        slider(3, "Rounded corners", self.radius, 0, 20, "px")
        ttk.Checkbutton(tab, text="Smooth animation", variable=self.animate,
                        command=self.update_preview).grid(row=4, column=0, sticky="w", pady=(10, 0))
        slider(5, "Animation length", self.anim_ms, 0, 400, "ms")
        ttk.Label(tab, text="Boxes still jump instantly when they need to grow to cover text; "
                            "only shrinking and moving away is animated.",
                  style="Hint.TLabel", wraplength="6.5i").grid(row=6, column=0, columnspan=4, sticky="w")

        ttk.Label(tab, text="Preview").grid(row=7, column=0, sticky="w", pady=(16, 4))
        self.preview = tk.Canvas(tab, width="6.5i", height="0.8i", bg="#ffffff", highlightthickness=1,
                                 highlightbackground="#ccc")
        self.preview.grid(row=8, column=0, columnspan=4, sticky="w")
        self.update_preview()

    def set_color(self, rgb):
        self.color = tuple(int(v) for v in rgb)
        self.update_preview()

    def pick_color(self):
        rgb, _ = colorchooser.askcolor(color="#%02x%02x%02x" % self.color, title="Box color")
        if rgb:
            self.set_color(rgb)

    def update_preview(self):
        if not hasattr(self, "preview"):
            return
        hexc = "#%02x%02x%02x" % self.color
        self.swatch.delete("all")
        self.swatch.create_rectangle(0, 0, 400, 400, fill=hexc, outline="")
        cv = self.preview
        cv.delete("all")
        first = (redact.as_list(self.collect_list("first_name")) or ["Sam"])[0]
        place = (redact.as_list(self.collect_list("locations")) or ["Springfield"])[0]
        f = tkfont.Font(family="Segoe UI", size=13)
        parts = ["hey it's ", first.title(), ", I'm in ", place.title(), " today"]
        x, y = 16, int(cv.winfo_reqheight()) // 2
        cv.create_text(x, y, anchor="w", font=f, fill="#222", text="".join(parts))
        h = f.metrics("linespace")
        scale = self.root.winfo_fpixels("1i") / 96  # overlay padding is in px at 100%
        pad = self.padding.get() * scale
        r = self.radius.get() * scale
        boxes = []
        for i, part in enumerate(parts):
            if i in (1, 3):
                boxes.append((x, f.measure(part)))
            x += f.measure(part)
        for bx, w in boxes:
            x0, y0, x1, y1 = bx - pad, y - h / 2 - pad, bx + w + pad, y + h / 2 + pad
            if r > 0:
                rr = min(r, (x1 - x0) / 2, (y1 - y0) / 2)
                pts = [x0 + rr, y0, x1 - rr, y0, x1, y0, x1, y0 + rr, x1, y1 - rr, x1, y1,
                       x1 - rr, y1, x0 + rr, y1, x0, y1, x0, y1 - rr, x0, y0 + rr, x0, y0]
                cv.create_polygon(*pts, fill=hexc, outline="", smooth=True)
            else:
                cv.create_rectangle(x0, y0, x1, y1, fill=hexc, outline="")

    def collect_list(self, key):
        box = getattr(self, "lists", {}).get(key)
        if box is None:
            return []
        return [ln.strip() for ln in box.get("1.0", "end").splitlines() if ln.strip()]

    # ---------- tab: apps ----------
    def build_apps_tab(self, nb):
        tab = ttk.Frame(nb, padding=14)
        nb.add(tab, text="  Ignored apps  ")
        ttk.Label(tab, text="The overlay never covers anything in these apps.",
                  style="Hint.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self.ignored = tk.Listbox(tab, height=10, width=40, relief="solid", borderwidth=1,
                                  activestyle="none", font=("Segoe UI", 10))
        self.ignored.grid(row=1, column=0, rowspan=4, sticky="nsew")
        for name in self.cfg.get("live_ignore_processes", []):
            self.ignored.insert("end", name)
        ttk.Button(tab, text="Remove selected", command=self.remove_app).grid(row=1, column=1, sticky="nw", padx=12)

        ttk.Label(tab, text="Add an app that's open now:").grid(row=5, column=0, sticky="w", pady=(14, 2))
        row = ttk.Frame(tab)
        row.grid(row=6, column=0, columnspan=3, sticky="w")
        self.app_pick = ttk.Combobox(row, width=32, values=running_apps())
        self.app_pick.pack(side="left")
        ttk.Button(row, text="Refresh", command=lambda: self.app_pick.configure(values=running_apps())
                   ).pack(side="left", padx=6)
        ttk.Button(row, text="Add", command=self.add_app).pack(side="left")
        ttk.Label(tab, text="You can also type a program name, e.g. \"Discord\" or \"brave\".",
                  style="Hint.TLabel").grid(row=7, column=0, columnspan=3, sticky="w", pady=(4, 0))
        tab.columnconfigure(0, weight=1)

    # ---------- tab: Proton VPN ----------
    def build_proton_tab(self, nb):
        tab = ttk.Frame(nb, padding=14)
        nb.add(tab, text="  Proton VPN  ")
        pv = {"enabled": True, "location": True, "ip": True, "server_load": True,
              "traffic": True, "speed": True, "color": list(PROTON_DARK)}
        pv.update(self.cfg.get("proton_vpn") or {})
        ttk.Label(tab, text="Covers the connection details in Proton VPN's window, found from the labels "
                            "next to them. The boxes follow the window, scrolling and animation like all others. "
                            "Ctrl+Alt+H shows/hides them.",
                  style="Hint.TLabel", wraplength="6.5i").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        self.pv_enabled = tk.BooleanVar(value=bool(pv["enabled"]))
        ttk.Checkbutton(tab, text="Cover Proton VPN's connection details", variable=self.pv_enabled
                        ).grid(row=1, column=0, columnspan=3, sticky="w")
        parts = [("location", "Location (country and city / server)"), ("ip", "VPN IP"),
                 ("server_load", "Server load"), ("traffic", "Total traffic"),
                 ("speed", "Current traffic speed and graph")]
        self.pv_parts = {}
        for i, (key, label) in enumerate(parts):
            var = tk.BooleanVar(value=bool(pv.get(key, True)))
            self.pv_parts[key] = var
            ttk.Checkbutton(tab, text=label, variable=var).grid(row=2 + i, column=0, sticky="w", padx=(24, 0), pady=2)

        ttk.Label(tab, text="Box color").grid(row=8, column=0, sticky="w", pady=(16, 4))
        col = pv.get("color")
        self.pv_custom = tuple(col) if col else PROTON_DARK
        self.pv_color_mode = tk.StringVar(
            value="same" if not col else "blend" if tuple(col) == PROTON_DARK else "custom")
        ttk.Radiobutton(tab, text="Blend in with Proton's dark background", value="blend",
                        variable=self.pv_color_mode).grid(row=9, column=0, sticky="w", padx=(24, 0))
        ttk.Radiobutton(tab, text="Same as the other boxes (Appearance tab)", value="same",
                        variable=self.pv_color_mode).grid(row=10, column=0, sticky="w", padx=(24, 0))
        row = ttk.Frame(tab)
        row.grid(row=11, column=0, sticky="w", padx=(24, 0))
        ttk.Radiobutton(row, text="Custom:", value="custom", variable=self.pv_color_mode).pack(side="left")
        self.pv_swatch = tk.Canvas(row, width="0.4i", height="0.26i", highlightthickness=1, highlightbackground="#999")
        self.pv_swatch.pack(side="left", padx=8)
        ttk.Button(row, text="Choose...", command=self.pick_pv_color).pack(side="left")
        self.draw_pv_swatch()

    def draw_pv_swatch(self):
        self.pv_swatch.delete("all")
        self.pv_swatch.create_rectangle(0, 0, 400, 400, fill="#%02x%02x%02x" % self.pv_custom, outline="")

    def pick_pv_color(self):
        rgb, _ = colorchooser.askcolor(color="#%02x%02x%02x" % self.pv_custom, title="Proton VPN box color")
        if rgb:
            self.pv_custom = tuple(int(v) for v in rgb)
            self.pv_color_mode.set("custom")
            self.draw_pv_swatch()

    def add_app(self):
        name = self.app_pick.get().strip().removesuffix(".exe")
        if name and name.lower() not in [n.lower() for n in self.ignored.get(0, "end")]:
            self.ignored.insert("end", name)
        self.app_pick.set("")

    def remove_app(self):
        for i in reversed(self.ignored.curselection()):
            self.ignored.delete(i)

    # ---------- overlay control ----------
    def refresh_status(self):
        running = overlay_pid() is not None
        self.status.set("Running" if running else "Stopped")
        self.dot.delete("all")
        self.dot.create_oval(2, 2, 12, 12, fill="#2fb36d" if running else "#c0392b", outline="")
        self.start_btn.state(["disabled"] if running else ["!disabled"])
        self.stop_btn.state(["!disabled"] if running else ["disabled"])
        self.root.after(1000, self.refresh_status)

    def on_start(self):
        if self.collect() != self.saved:
            self.save()
        start_overlay()
        self.message.set("Starting... (takes a few seconds)")

    def on_stop(self):
        stop_overlay()
        self.message.set("Stopped.")

    def revert(self):
        self.root.destroy()
        Settings().root.mainloop()

    def on_close(self):
        if self.collect() != self.saved:
            ans = messagebox.askyesnocancel("opsec-tool", "Save your changes before closing?")
            if ans is None:
                return
            if ans:
                self.save()
        self.root.destroy()


START_MENU_LNK = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
                  / "opsec-tool.lnk")

if __name__ == "__main__":
    if "--install-shortcut" in sys.argv:
        create_shortcut(START_MENU_LNK)
        print(f"Created {START_MENU_LNK}")
    else:
        Settings().root.mainloop()
