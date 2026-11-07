"""
live.py - always-on screen redaction overlay (text-based, no OCR).

Reads the *actual text* of visible apps through Windows UI Automation - the
accessibility API screen readers use. That covers web pages in browsers (the
rendered HTML text), Discord/Electron apps, text fields, editors, Explorer, etc.
Text runs through the same detectors as redact.py (IPs, your name, your
locations, emails, street addresses, BERT location model) in strict mode, and
matches get grey boxes in a transparent, click-through, always-on-top window
(visible to screen-share / OBS captures too).

Designed to stay light on other apps (like a screen reader):
  - apps *notify* us when their text/structure changes; we re-read only the
    part that changed instead of polling whole windows
  - each window gets a full read when first seen and a slow background refresh,
    within a per-app time budget
  - only already-found matches are re-positioned frequently (cheap calls)
  - occlusion is computed from window z-order (no messages sent to apps)

Text that is only pixels (inside images, videos, games) is NOT seen.

Quit: Ctrl+Alt+F12   (or end "pythonw.exe" in Task Manager)
Log:  live.log next to this file  (--debug logs detected text; don't share it)
"""

from __future__ import annotations

import ctypes
import json
import logging
import math
import os
import queue
import sys
import threading
import time
from collections import defaultdict, deque
from ctypes import wintypes
from pathlib import Path

ctypes.windll.shcore.SetProcessDpiAwareness(2)  # physical pixels everywhere
os.environ.setdefault("OMP_NUM_THREADS", "2")  # keep PyTorch from grabbing every core
os.environ.setdefault("MKL_NUM_THREADS", "2")

import comtypes
import comtypes.client
import mss
import tkinter as tk

comtypes.client.GetModule("UIAutomationCore.dll")
from comtypes.gen import UIAutomationClient as U  # noqa: E402

import redact  # noqa: E402

HERE = Path(__file__).resolve().parent
log = logging.getLogger("live")

TRANSPARENT = "#ff00fe"  # color key that Windows renders as see-through
WEB_FRAMEWORKS = {"chrome", "gecko"}  # browsers, Electron apps (Discord, VS Code...)


def is_editor(control_type: int, framework: str | None) -> bool:
    """Text boxes / editors whose whole content we read via TextPattern.
    A web page is also a 'Document' but is read element by element instead."""
    if control_type == U.UIA_EditControlTypeId:
        return True
    return control_type == U.UIA_DocumentControlTypeId and (framework or "").lower() not in WEB_FRAMEWORKS

TICK = 0.1                # s between position refreshes / event processing
FAST_TICK = 0.015         # while scrolling / dragging: re-read positions this often
ACTIVITY_HOLD = 0.6       # s that scroll/drag "fast mode" lasts after the last input
WHEEL_GUESS_PX = 80      # for ~0.1 s after a wheel turn (before the first real
                          #   measurement) stretch the box ~1 notch (px at 100%) that way
RENDER_LAG = 0.03         # s between measuring text and the box reaching the screen
MOTION_MARGIN = 0.02      # s of movement added as safety margin while text moves
MAX_LEAD = 0.08           # never predict further ahead than this (s)
SCROLLER_REFRESH = 1.0    # s between re-reading where a scrollable area is
COVER_MIN = 0.3           # s a scan cover stays at least (late-loading content gets read)
COVER_MAX = 3.0           # s a scan cover stays at most (never leaves a window stuck black)
COVER_APPS = ["brave", "chrome", "msedge", "firefox", "opera", "vivaldi", "Discord", "Signal"]
DOCS_MARK = " - Google Docs"  # in a browser window's title while a Docs tab is showing
DOCS_INTERVAL = 0.5       # s between checks of a Docs page for changes
DOCS_BUDGET = 0.4         # max fraction of time spent on Docs OCR
PROTON_RELAYOUT = 5.0     # s between full re-reads of Proton VPN's layout (also on changes)
PROTON_DEFAULTS = {"enabled": True, "process": "ProtonVPN.Client", "location": True, "ip": True,
                   "server_load": True, "traffic": True, "speed": True, "color": [30, 28, 36]}
HOLD_MISSING = 0.25       # keep a box this long if its text briefly reports no position
MIN_CHAR_PX = 3           # narrowest plausible on-screen character (px at 100% scaling)
LINE_PX = 32              # generous single text line height (px at 100% scaling)
CONTAINER_TYPES = {       # elements whose name is a label for an area, not visible text
    U.UIA_DocumentControlTypeId, U.UIA_PaneControlTypeId, U.UIA_GroupControlTypeId,
    U.UIA_WindowControlTypeId, U.UIA_CustomControlTypeId, U.UIA_ListControlTypeId,
    U.UIA_TableControlTypeId, U.UIA_TreeControlTypeId, U.UIA_ToolBarControlTypeId,
    U.UIA_TabControlTypeId, U.UIA_MenuBarControlTypeId, U.UIA_MenuControlTypeId,
    U.UIA_StatusBarControlTypeId, U.UIA_DataGridControlTypeId,
}
FULL_RESCAN_EVERY = 30.0  # s between background full reads of a window
APP_BUDGET = 0.10         # max fraction of an app's time we may spend reading it
MAX_EVENTS_PER_TICK = 40
NER_BUDGET = 0.15         # max seconds of ML-model time per second (5 s average)
ML_THREADS = 2            # CPU threads the ML model may use
DIGITS = str.maketrans("0123456789", "0000000000")
BROWSERS = {"brave", "chrome", "msedge", "vivaldi", "opera", "firefox", "arc"}

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
dwmapi = ctypes.windll.dwmapi
user32.GetDpiForWindow.argtypes = [wintypes.HWND]
user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

GWL_EXSTYLE = -20
WS_EX_LAYERED, WS_EX_TRANSPARENT = 0x80000, 0x20
WS_EX_TOOLWINDOW, WS_EX_NOACTIVATE, WS_EX_APPWINDOW = 0x80, 0x08000000, 0x40000


def com_init():
    try:
        comtypes.CoInitializeEx(comtypes.COINIT_MULTITHREADED)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Window z-order snapshot (no messages are sent to other apps)
# --------------------------------------------------------------------------- #
class Win:
    __slots__ = ("hwnd", "pid", "rect", "scale")

    def __init__(self, hwnd, pid, rect, scale):
        self.hwnd, self.pid, self.rect, self.scale = hwnd, pid, rect, scale


def snapshot_windows(my_pid: int) -> list[Win]:
    """Visible top-level windows, topmost first."""
    out = []

    def cb(h, _):
        if not user32.IsWindowVisible(h) or user32.IsIconic(h):
            return True
        if user32.GetWindowLongPtrW(h, GWL_EXSTYLE) & WS_EX_TRANSPARENT:
            return True  # click-through overlays don't hide anything
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(h, ctypes.byref(pid))
        if pid.value == my_pid:
            return True
        cloaked = ctypes.c_int(0)
        dwmapi.DwmGetWindowAttribute(h, 14, ctypes.byref(cloaked), 4)  # DWMWA_CLOAKED
        if cloaked.value:
            return True
        r = wintypes.RECT()
        if dwmapi.DwmGetWindowAttribute(h, 9, ctypes.byref(r), ctypes.sizeof(r)) != 0:  # frame bounds
            user32.GetWindowRect(h, ctypes.byref(r))
        if r.right - r.left > 1 and r.bottom - r.top > 1:
            out.append(Win(h, pid.value, (r.left, r.top, r.right, r.bottom),
                           (user32.GetDpiForWindow(h) or 96) / 96))
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return out


def subtract(a, b) -> list[tuple]:
    """Rectangle a minus rectangle b, as up to 4 rectangles."""
    al, at, ar, ab = a
    bl, bt, br, bb = b
    if bl >= ar or br <= al or bt >= ab or bb <= at:
        return [a]
    out = []
    if bt > at:
        out.append((al, at, ar, bt))
    if bb < ab:
        out.append((al, bb, ar, ab))
    top, bot = max(at, bt), min(ab, bb)
    if bl > al:
        out.append((al, top, bl, bot))
    if br < ar:
        out.append((br, top, ar, bot))
    return [r for r in out if r[2] - r[0] > 1 and r[3] - r[1] > 1]


def visible_fraction(hwnd, wins) -> float:
    """How much of a window isn't covered by windows on top of it (0..1)."""
    for i, w in enumerate(wins):
        if w.hwnd == hwnd:
            l, t, r, b = w.rect
            total = max(1, (r - l) * (b - t))
            pieces = [w.rect]
            for above in wins[:i]:
                pieces = [q for pc in pieces for q in subtract(pc, above.rect)]
                if not pieces:
                    return 0.0
            return sum((q[2] - q[0]) * (q[3] - q[1]) for q in pieces) / total
    return 0.0


def window_at(wins: list[Win], x: float, y: float) -> Win | None:
    for w in wins:
        l, t, r, b = w.rect
        if l <= x < r and t <= y < b:
            return w
    return None


# --------------------------------------------------------------------------- #
# Text-range helpers
# --------------------------------------------------------------------------- #
def text_pattern(el):
    try:
        p = el.GetCurrentPattern(U.UIA_TextPatternId)
        return p.QueryInterface(U.IUIAutomationTextPattern) if p else None
    except (comtypes.COMError, ValueError):
        return None


def find_ranges(rng, needles, limit: int = 10) -> list:
    """Text ranges of every occurrence of each needle (searched once, then kept)."""
    out = []
    for needle in needles:
        search = rng.Clone()
        for _ in range(limit):
            found = search.FindText(needle, 0, 1)  # forward, ignore case
            if not found:
                break
            out.append(found)
            search.MoveEndpointByRange(U.TextPatternRangeEndpoint_Start, found, U.TextPatternRangeEndpoint_End)
    return out


def ranges_rects(ranges) -> list[tuple]:
    out = []
    for rg in ranges:
        r = rg.GetBoundingRectangles() or ()  # only visible parts are returned
        out += [(r[i], r[i + 1], r[i] + r[i + 2], r[i + 1] + r[i + 3]) for i in range(0, len(r), 4)]
    return [r for r in out if r[2] > r[0] and r[3] > r[1]]


class Track:
    """An element whose text contains something sensitive."""
    __slots__ = ("el", "pid", "text", "hits", "needles", "tp", "ranges", "misses", "doc", "ctype",
                 "scroller", "scroller_t", "scroller_rel", "offset", "color")

    def __init__(self, el, pid, text, hits):
        self.el, self.pid, self.text, self.hits = el, pid, text, hits
        self.needles = {text[a:b] for a, b in hits}
        self.tp = None      # element's own text pattern (editors), if any
        self.ranges = None  # None = not resolved yet; [] = estimate from element box
        self.misses = 0
        self.doc = None     # browsers: the page this text belongs to (tab check)
        self.ctype = None   # UI Automation control type
        self.scroller = None      # element of the scrollable area it's in; False = none
        self.scroller_t = 0.0     # when that area's rectangle was last read
        self.scroller_rel = None  # that area relative to its window: (l, t, r, b)
        self.offset = None  # Proton boxes: area = anchor element's box + this offset
        self.color = None   # box colour override (None = the normal box colour)


# --------------------------------------------------------------------------- #
# UI Automation event handlers -> queue of changed elements
# --------------------------------------------------------------------------- #
class StructureHandler(comtypes.COMObject):
    _com_interfaces_ = [U.IUIAutomationStructureChangedEventHandler]

    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def HandleStructureChangedEvent(self, sender, changeType, runtimeId):
        self.sink(sender)


class PropertyHandler(comtypes.COMObject):
    _com_interfaces_ = [U.IUIAutomationPropertyChangedEventHandler]

    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def HandlePropertyChangedEvent(self, sender, propertyId, newValue):
        self.sink(sender)


class EventHandler(comtypes.COMObject):
    _com_interfaces_ = [U.IUIAutomationEventHandler]

    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def HandleAutomationEvent(self, sender, eventId):
        self.sink(sender)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #
class Scanner(threading.Thread):
    def __init__(self, cfg: dict, out: queue.Queue):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.out = out
        self.my_pid = os.getpid()
        self.heartbeat = time.monotonic() + 60  # grace period for model loading
        self.activity_until = 0.0  # set by the input watcher while you scroll / drag
        self.sys_scale = (user32.GetDpiForSystem() or 96) / 96  # display scaling (e.g. 2.25 = 225%)
        self.ml_ready = False
        self.cfg_mtime = None
        self.cover_requests = {}     # hwnd -> time: windows blacked out until scanned
        self.guards = {}             # hwnd -> cover state for windows of black-out apps
        self.docs = {}               # browser hwnd -> Google Docs OCR state
        self.docs_spent = deque()
        self.ocr_engine = None
        self.ocr_loop = None
        self.new_windows = set()     # windows that just appeared (cover them at once)
        self.app_colors = load_app_colors()  # app name -> its main (background) colour
        self.color_sampled = 0.0
        self.proton_hidden = False   # Ctrl+Alt+H
        self.proton_dirty = True     # re-read Proton's layout soon
        self.proton_last = 0.0
        self.proton_size = None
        self.line_cache: dict[str, list] = {}
        self.ner_cache: dict[str, list] = {}
        self.ner_spent: deque = deque()
        self.ner_queue: deque = deque()          # masked lines awaiting the ML model
        self.ner_queued: set = set()
        self.pending: dict[tuple, tuple] = {}    # rid -> (pid, el, texts, tp) awaiting ML
        self.waiting: dict[str, set] = defaultdict(set)  # ML key -> rids waiting on it
        ignore = cfg.get("live_ignore_processes", [])
        self.ignore = {p.lower().removesuffix(".exe") for p in ignore}
        self.proc_names: dict[int, str] = {}
        self.tracks: dict[tuple, Track] = {}
        self.events: deque = deque(maxlen=5000)
        self.last_full: dict[int, float] = {}            # hwnd -> time of last full read
        self.spent: dict[int, deque] = defaultdict(deque)  # pid -> (time, seconds spent)

    # ---- detection ----
    def detect(self, text: str) -> tuple[list[tuple[int, int]], set]:
        """Hits in text, line by line (so editing one line of a big document
        doesn't re-check the rest). Second value: ML keys still waiting."""
        hits, missing, pos = [], set(), 0
        for line in text.splitlines(keepends=True) or [text]:
            r, key = self.detect_line(line)
            hits += [(a + pos, b + pos) for a, b in r]
            if key is not None:
                missing.add(key)
            pos += len(line)
        return hits, missing

    def detect_line(self, line: str) -> tuple[list, str | None]:
        r = self.line_cache.get(line)
        if r is not None:
            return r, None
        # instant checks: your name / locations / IPs / emails / addresses
        hits = [(h.start, h.end) for h in redact.find_sensitive(line, self.cfg, strict=True, use_ner=False)]
        if redact.ner_wanted(line, self.cfg, strict=True):
            # ML model, cached with digits masked so ticking timers/counters
            # don't count as new text (digits -> '0' keeps all positions)
            key = line.translate(DIGITS)
            ner = self.ner_cache.get(key)
            if ner is None:
                if key not in self.ner_queued:
                    self.ner_queued.add(key)
                    self.ner_queue.append(key)
                return hits, key  # instant hits now, ML result later
            hits = hits + ner
        if len(self.line_cache) > 50000:
            self.line_cache.clear()
        self.line_cache[line] = hits
        if hits:
            log.debug("hit %r", [line[a:b] for a, b in hits])
        return hits, None

    def process_ner(self):
        """Run queued ML checks in batches, newest text first, within budget."""
        while self.ner_queue and self.ner_budget_ok():
            batch = [self.ner_queue.pop() for _ in range(min(8, len(self.ner_queue)))]
            t0 = time.perf_counter()
            results = redact.ner_batch(batch, self.cfg, strict=True)
            self.ner_spent.append((time.monotonic(), time.perf_counter() - t0))
            if len(self.ner_cache) > 50000:
                self.ner_cache.clear()
            for key, hs in zip(batch, results):
                self.ner_queued.discard(key)
                self.ner_cache[key] = [(h.start, h.end) for h in hs]
                for rid in self.waiting.pop(key, ()):
                    if rid in self.pending:
                        self.evaluate(rid, *self.pending[rid])
        while len(self.ner_queue) > 5000:  # very old backlog: drop
            self.ner_queued.discard(self.ner_queue.popleft())

    def ner_budget_ok(self) -> bool:
        now = time.monotonic()
        d = self.ner_spent
        while d and d[0][0] < now - 5.0:
            d.popleft()
        return sum(s for _, s in d) < NER_BUDGET * 5.0

    # ---- per-app time budget ----
    def budget_ok(self, pid: int) -> bool:
        now = time.monotonic()
        d = self.spent[pid]
        while d and d[0][0] < now - 2.0:
            d.popleft()
        return sum(s for _, s in d) < APP_BUDGET * 2.0

    def charge(self, pid: int, seconds: float):
        self.spent[pid].append((time.monotonic(), seconds))

    # ---- setup ----
    def setup(self):
        com_init()
        u = self.uia = comtypes.client.CreateObject(U.CUIAutomation8, interface=U.IUIAutomation2)
        u.ConnectionTimeout = 1000
        u.TransactionTimeout = 1000
        self.cache_req = u.CreateCacheRequest()
        for p in (
            U.UIA_NamePropertyId, U.UIA_BoundingRectanglePropertyId, U.UIA_ValueValuePropertyId,
            U.UIA_IsTextPatternAvailablePropertyId, U.UIA_ControlTypePropertyId,
            U.UIA_RuntimeIdPropertyId, U.UIA_ProcessIdPropertyId, U.UIA_FrameworkIdPropertyId,
        ):
            self.cache_req.AddProperty(p)
        self.cond = u.CreateOrCondition(
            u.CreateNotCondition(u.CreatePropertyCondition(U.UIA_NamePropertyId, "")),
            u.CreateOrCondition(
                u.CreatePropertyCondition(U.UIA_IsValuePatternAvailablePropertyId, True),
                u.CreatePropertyCondition(U.UIA_IsTextPatternAvailablePropertyId, True),
            ),
        )
        ev_cache = u.CreateCacheRequest()
        ev_cache.AddProperty(U.UIA_ProcessIdPropertyId)
        ev_cache.AddProperty(U.UIA_RuntimeIdPropertyId)
        root = u.GetRootElement()
        sink = self.events.append
        self.handlers = [StructureHandler(sink), PropertyHandler(sink), EventHandler(sink)]
        u.AddStructureChangedEventHandler(root, U.TreeScope_Subtree, ev_cache, self.handlers[0])
        props = (ctypes.c_int * 2)(U.UIA_NamePropertyId, U.UIA_ValueValuePropertyId)
        u.AddPropertyChangedEventHandlerNativeArray(
            root, U.TreeScope_Subtree, ev_cache, self.handlers[1], props, 2)
        for ev in (U.UIA_Text_TextChangedEventId, U.UIA_LiveRegionChangedEventId):
            u.AddAutomationEventHandler(ev, root, U.TreeScope_Subtree, ev_cache, self.handlers[2])

    def ensure_ml(self):
        """Load the place-name model if the config asks for it (once)."""
        if self.ml_ready or not redact.ner_wanted("Warm up the models", self.cfg, strict=True):
            return
        self.ml_ready = True
        import torch
        import warnings
        torch.set_num_threads(ML_THREADS)
        redact.find_ner("warm up the models in Paris today", self.cfg)  # load model now
        try:  # 8-bit weights: ~2x faster on CPU, same results in testing
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ner = redact.get_ner()
                ner.model = torch.quantization.quantize_dynamic(ner.model, {torch.nn.Linear}, dtype=torch.qint8)
        except Exception:
            log.warning("model quantization unavailable; using full precision")

    def check_config(self):
        """Apply edits to config.json (e.g. from the settings window) live."""
        try:
            mtime = redact.CONFIG_PATH.stat().st_mtime
        except OSError:
            return
        if self.cfg_mtime is None or mtime == self.cfg_mtime:
            self.cfg_mtime = mtime
            return
        self.cfg_mtime = mtime
        try:
            cfg = redact.load_config(redact.CONFIG_PATH)
        except Exception as ex:  # e.g. half-saved / invalid JSON: keep the old settings
            log.warning("config.json not applied: %s", ex)
            return
        self.cfg = cfg
        self.ignore = {p.lower().removesuffix(".exe") for p in cfg.get("live_ignore_processes", [])}
        self.line_cache.clear()
        self.ner_cache.clear()
        self.ner_queue.clear()
        self.ner_queued.clear()
        self.pending.clear()
        self.waiting.clear()
        for rid in [r for r, tr in self.tracks.items() if self.is_ignored(tr.pid)]:
            del self.tracks[rid]
        self.last_full.clear()  # re-read every window with the new settings
        self.ensure_ml()
        self.out.put(("config", cfg))
        log.info("config reloaded")

    def run(self):
        self.setup()
        self.ensure_ml()
        self.out.put(("geometry", tuple(user32.GetSystemMetrics(i) for i in (76, 77, 78, 79))))
        log.info("scanner running")
        last_full_tick = last_cfg_check = 0.0
        while True:
            t0 = time.perf_counter()
            now = self.heartbeat = time.monotonic()
            fast = now < self.activity_until
            if now - last_cfg_check > 1.0:
                last_cfg_check = now
                self.check_config()
            try:
                wins = self.last_wins = snapshot_windows(self.my_pid)
                scanned = self.scan_covered(wins, now)
                self.sample_app_color(wins, now)
                self.process_events()  # new text (e.g. messages scrolling into view)
                if not fast or now - last_full_tick >= TICK:
                    last_full_tick = now
                    self.process_ner()
                    self.background_rescan(wins)
                self.proton_update(wins, now)
                self.docs_update(wins, now)
                if scanned:  # a window was just restored / switched to: use its *current* stacking
                    wins = self.last_wins = snapshot_windows(self.my_pid)
                self.out.put(("boxes", self.positions(wins, force=scanned) + self.docs_items(wins, now)))
                self.finish_scans(scanned)       # after the boxes, so they're there when it uncovers
                self.update_guards(wins, now)
                self.out.put(("guards", self.guard_state()))
            except Exception:
                log.exception("tick failed")
            time.sleep(max(0.0, (FAST_TICK if fast else TICK) - (time.perf_counter() - t0)))

    # ---- reading text ----
    def read_subtree(self, el, pid_hint=None, scope=U.TreeScope_Subtree):
        """Read every text element under el; update tracked matches."""
        # phase 1: talk to the app (this is what costs the app time)
        t0 = time.perf_counter()
        try:
            arr = el.FindAllBuildCache(scope, self.cond, self.cache_req)
            n = arr.Length if arr else 0
        except (comtypes.COMError, ValueError):
            return
        pid = pid_hint
        items = []
        for i in range(n):
            e = arr.GetElement(i)
            try:
                rid = tuple(e.GetCachedPropertyValue(U.UIA_RuntimeIdPropertyId) or ())
                pid = e.GetCachedPropertyValue(U.UIA_ProcessIdPropertyId)
                val = e.GetCachedPropertyValue(U.UIA_ValueValuePropertyId)
                texts = [t for t in (e.CachedName or "", val if isinstance(val, str) else "") if t]
                tp = None
                ctype, fw = e.CachedControlType, (e.CachedFrameworkId or "").lower()
                rc = e.CachedBoundingRectangle
                rect = (rc.left, rc.top, rc.right, rc.bottom)
                if (e.GetCachedPropertyValue(U.UIA_IsTextPatternAvailablePropertyId)
                        and is_editor(ctype, fw)):
                    tp = text_pattern(e)
                    if tp is not None:
                        texts.append(tp.DocumentRange.GetText(100_000))
            except comtypes.COMError:
                continue
            items.append((rid, pid, e, texts, tp, rect, ctype))
        if pid is not None:
            self.charge(pid, time.perf_counter() - t0)

        # phase 2: our own detection work
        for item in items:
            self.evaluate(*item)

    def evaluate(self, rid, pid, e, texts, tp, rect, ctype):
        """Decide whether an element's text is sensitive; (re)track it."""
        if self.is_ignored(pid):
            return
        found, missing = None, set()
        for text in texts:
            hits, miss = self.detect(text)
            missing |= miss
            if hits and found is None:
                found = Track(e, pid, text, hits)
                found.ctype = ctype
                found.tp = tp
        if found:
            old = self.tracks.get(rid)
            if old is not None and old.text == found.text and old.hits == found.hits:
                old.el = e  # unchanged text: keep the already-resolved ranges
            else:
                self.tracks[rid] = found
        else:
            self.tracks.pop(rid, None)
        self.pending.pop(rid, None)
        if missing:  # re-evaluated from stored text once the ML model gets to it
            self.pending[rid] = (pid, e, texts, tp, rect, ctype)
            for k in missing:
                self.waiting[k].add(rid)

    def proc_name(self, pid) -> str:
        name = self.proc_names.get(pid)
        if name is None:
            name = ""
            h = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
            if h:
                buf = ctypes.create_unicode_buffer(512)
                size = wintypes.DWORD(512)
                if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    name = Path(buf.value).stem.lower()
                kernel32.CloseHandle(h)
            self.proc_names[pid] = name
        return name

    def is_ignored(self, pid) -> bool:
        return bool(self.ignore) and pid is not None and self.proc_name(pid) in self.ignore

    def process_events(self):
        seen, deferred, n = set(), [], 0
        while self.events and n < MAX_EVENTS_PER_TICK:
            el = self.events.popleft()
            try:
                rid = tuple(el.GetCachedPropertyValue(U.UIA_RuntimeIdPropertyId) or ())
                pid = el.GetCachedPropertyValue(U.UIA_ProcessIdPropertyId)
            except comtypes.COMError:
                continue
            if pid is not None and self.proc_name(pid) == self.proton_cfg()["process"].lower():
                self.proton_dirty = True  # Proton changed: re-read its layout (throttled)
            if pid == self.my_pid or rid in seen or self.is_ignored(pid):
                continue
            seen.add(rid)
            if not self.budget_ok(pid):
                deferred.append(el)  # app is busy-ish: read it a bit later
                continue
            self.read_subtree(el, pid)
            n += 1
        self.events.extendleft(reversed(deferred))

    def background_rescan(self, wins: list[Win]):
        """Full read of windows never read / not read for a while (one per tick)."""
        now = time.monotonic()
        visible = {w.hwnd: w for w in wins}
        for h in [h for h in self.last_full if h not in visible]:
            del self.last_full[h]
        for w in wins:
            if now - self.last_full.get(w.hwnd, -1e9) < FULL_RESCAN_EVERY or self.is_ignored(w.pid):
                continue
            if not self.budget_ok(w.pid):
                continue
            self.last_full[w.hwnd] = now
            try:
                self.read_subtree(self.uia.ElementFromHandle(w.hwnd), w.pid)
            except comtypes.COMError:
                pass
            return

    # ---- positions of tracked matches ----
    def positions(self, wins: list[Win], force=()) -> list[tuple]:
        boxes, resolved, titles = [], 0, {}
        urgent = {pid for _h, _r, pid in force if pid}  # apps being uncovered: resolve all now
        for rid, tr in list(self.tracks.items()):
            if tr.ranges is None and (resolved < 5 or tr.pid in urgent):
                # exact-position lookups are spread over ticks; until then the
                # element's outline is used (locate falls back to it) - no gap
                resolved += 1
                self.resolve(tr)
            try:
                if tr.doc is not None and not self.tab_visible(tr, wins, titles):
                    continue  # text in a background browser tab
                rects = self.locate(tr)
            except (comtypes.COMError, ValueError):
                rects = None
            if rects is None:
                tr.misses += 1
                if tr.misses > 20:  # element gone
                    del self.tracks[rid]
                continue
            tr.misses = 0
            t_meas = time.monotonic()
            parts = self.visible_parts(rects, tr.pid, wins, pad=0 if tr.offset is not None else None)
            if parts and tr.scroller and t_meas - tr.scroller_t > SCROLLER_REFRESH:
                tr.scroller_t = t_meas
                try:  # the scroll area's position, relative to its window
                    rc = tr.scroller.CurrentBoundingRectangle
                    wl, wt = parts[0][2][0], parts[0][2][1]
                    tr.scroller_rel = (rc.left - wl, rc.top - wt, rc.right - wl, rc.bottom - wt)
                except (comtypes.COMError, ValueError):
                    tr.scroller, tr.scroller_rel = False, None
            area = tr.scroller_rel if tr.scroller else (False if tr.scroller is False else None)
            for i, (box, hwnd, wrect) in enumerate(parts):
                boxes.append((box, hwnd, wrect, (rid, i), t_meas, area, tr.color))
        return boxes

    # ---- Proton VPN: same label-based detection as the old VpnPrivacy tool ----
    # ---- covers for black-out apps ----
    # Every window of a black-out app has a cover window attached right above it.
    # The cover is solid ("armed") while the window is minimized / hidden, or the
    # moment its content switches (tab, page, channel). When the window is in
    # view again it's scanned, its boxes are placed, then the cover fades away.
    def cover_apps(self) -> set:
        return {a.lower().removesuffix(".exe") for a in self.cfg.get("scan_cover_apps", COVER_APPS)}

    def update_guards(self, wins, now):
        if not self.cfg.get("scan_cover", True):
            self.guards.clear()
            return
        apps = self.cover_apps()
        for w in wins:  # new windows of black-out apps
            if w.hwnd in self.guards or self.proc_name(w.pid) not in apps or self.is_ignored(w.pid):
                continue
            if w.rect[2] - w.rect[0] < 200 or w.rect[3] - w.rect[1] < 150:
                continue
            if user32.GetWindowLongPtrW(w.hwnd, GWL_EXSTYLE) & (WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT):
                continue  # menus, tooltips, overlays
            if not user32.GetWindowTextLengthW(w.hwnd) or user32.GetWindow(w.hwnd, 4):
                continue  # untitled / owned popups
            fresh = w.hwnd in self.new_windows
            hidden = visible_fraction(w.hwnd, wins) < 0.1
            self.guards[w.hwnd] = {"name": self.proc_name(w.pid), "armed": fresh or hidden,
                                   "scan_req": now if fresh else None, "cleared": 0.0}
            if fresh:
                self.cover_requests[w.hwnd] = now
        self.new_windows.clear()
        for hwnd, g in list(self.guards.items()):
            if not user32.IsWindow(hwnd) or not user32.IsWindowVisible(hwnd):
                del self.guards[hwnd]
                continue
            minimized = bool(user32.IsIconic(hwnd))
            frac = 0.0 if minimized else visible_fraction(hwnd, wins)
            if not g["armed"]:
                if minimized or frac < 0.1:  # out of sight: arm it for next time
                    g["armed"], g["scan_req"] = True, None
            elif not minimized and frac >= 0.1:  # back in view: scan, then clear
                if g["scan_req"] is None:
                    g["scan_req"] = now
                    self.cover_requests[hwnd] = now
                    self.activity_until = max(self.activity_until, now + 0.3)
                elif now - g["scan_req"] > COVER_MAX:
                    g["armed"], g["cleared"] = False, now  # never leave it stuck

    def arm(self, hwnd):
        """Content of the window you're using just switched (called from the
        input thread): cover it now and scan it right away."""
        g = self.guards.get(hwnd)
        if g is None:
            return False
        now = time.monotonic()
        g["armed"], g["scan_req"] = True, now
        self.cover_requests[hwnd] = now
        self.activity_until = max(self.activity_until, now + 0.3)
        return True

    def finish_scans(self, scanned):
        now = time.monotonic()
        for hwnd, req, _pid in scanned:
            g = self.guards.get(hwnd)
            if g and g["armed"] and g["scan_req"] is not None and g["scan_req"] <= req:
                g["armed"], g["scan_req"], g["cleared"] = False, None, now

    def guard_color(self, name):
        if self.cfg.get("scan_cover_match_app", True) and name in self.app_colors:
            return self.app_colors[name]
        return self.cfg.get("scan_cover_color", [0, 0, 0])

    def guard_state(self) -> dict:
        return {h: (g["armed"], tuple(self.guard_color(g["name"]))) for h, g in self.guards.items()}

    def sample_app_color(self, wins, now):
        """Every few seconds, note the main colour of the window you're using
        (if it's a black-out app), so its cover can match it."""
        if now - self.color_sampled < 3.0:
            return
        self.color_sampled = now
        fg = user32.GetForegroundWindow()
        g = self.guards.get(fg)
        if g is None or g["armed"] or now - g["cleared"] < 2.0:
            return  # only when its cover is fully gone
        rc = client_rect(fg)
        if rc is None or visible_fraction(fg, wins) < 0.9:
            return
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab(bbox=rc, all_screens=True).convert("RGB").resize((48, 48))
        except Exception:
            return
        counts = {}
        for r, gg, b in img.getdata():  # most common colour, in small buckets
            k = (r // 8, gg // 8, b // 8)
            counts[k] = counts.get(k, 0) + 1
        (r, gg, b), n = max(counts.items(), key=lambda kv: kv[1])
        if n < 48 * 48 * 0.2:
            return  # no clear main colour (e.g. a photo filling the window)
        color = [min(255, r * 8 + 4), min(255, gg * 8 + 4), min(255, b * 8 + 4)]
        if self.app_colors.get(g["name"]) != color:
            self.app_colors[g["name"]] = color
            save_app_colors(self.app_colors)

    def scan_covered(self, wins, now) -> list:
        """Windows blacked out because their content just changed: read them
        right away (no waiting for the background schedule)."""
        done = []
        for hwnd, req in list(self.cover_requests.items()):
            if self.cover_requests.get(hwnd) == req:
                self.cover_requests.pop(hwnd, None)
            w = next((w for w in wins if w.hwnd == hwnd), None)
            if w is not None:
                try:
                    self.read_subtree(self.uia.ElementFromHandle(hwnd), w.pid)
                except (comtypes.COMError, ValueError):
                    pass
                self.last_full[hwnd] = now
                if DOCS_MARK in window_title(hwnd):
                    self.docs_update(wins, now, force=hwnd)  # OCR it before the cover lifts
            done.append((hwnd, req, w.pid if w else None))
        return done

    # ---- Google Docs: drawn as an image, so read with OCR (Docs tabs only) ----
    def docs_update(self, wins, now, force=None):
        if not self.cfg.get("docs_ocr", True):
            self.docs.clear()
            return
        seen = set()
        for w in wins:
            if self.proc_name(w.pid) not in BROWSERS or self.is_ignored(w.pid):
                continue
            title = window_title(w.hwnd)
            if DOCS_MARK not in title:
                continue
            seen.add(w.hwnd)
            st = self.docs.get(w.hwnd)
            if st is None or st["title"] != title:  # new doc / tab: start fresh
                st = self.docs[w.hwnd] = {"title": title, "sig": None, "boxes": [], "t": -1e9, "pid": w.pid}
            if force is not None and force != w.hwnd:
                continue
            if force is None:
                if now - st["t"] < DOCS_INTERVAL or not self.docs_budget_ok():
                    continue
                if visible_fraction(w.hwnd, wins) < 0.05:
                    continue  # hidden: nothing to cover right now
            st["t"] = now
            sig = self.docs_signature(w)
            if force is None and st["sig"] is not None and sig is not None and self.same_sig(sig, st["sig"]):
                continue  # page unchanged since last OCR
            st["sig"] = sig
            t0 = time.perf_counter()
            boxes = self.docs_ocr(w.hwnd)
            self.docs_spent.append((time.monotonic(), time.perf_counter() - t0))
            if boxes is not None:
                st["boxes"] = boxes
        for h in [h for h in self.docs if h not in seen]:
            del self.docs[h]

    def docs_budget_ok(self) -> bool:
        now = time.monotonic()
        while self.docs_spent and self.docs_spent[0][0] < now - 5.0:
            self.docs_spent.popleft()
        return sum(x for _, x in self.docs_spent) < DOCS_BUDGET * 5.0

    @staticmethod
    def docs_signature(w):
        """Tiny greyscale thumbnail of the window on screen, to notice changes cheaply."""
        try:
            grab_cls = getattr(mss, "MSS", None) or mss.mss
            with grab_cls() as m:
                l, t, r, b = w.rect
                g = m.grab({"left": l, "top": t, "width": r - l, "height": b - t})
            from PIL import Image
            return Image.frombytes("RGB", g.size, g.rgb).convert("L").resize((96, 54)).tobytes()
        except Exception:
            return None

    @staticmethod
    def same_sig(a, b) -> bool:
        return sum(abs(x - y) for x, y in zip(a, b)) / max(1, len(a)) < 1.5

    def docs_ocr(self, hwnd):
        """OCR the browser window's own pixels; boxes relative to its top-left."""
        cap = print_window(hwnd)
        if cap is None:
            return None
        data, w, h, _wl, _wt = cap
        if self.ocr_engine is None:
            import asyncio
            from winrt.windows.media.ocr import OcrEngine
            self.ocr_engine = OcrEngine.try_create_from_user_profile_languages()
            self.ocr_loop = asyncio.new_event_loop()
            if self.ocr_engine is None:
                log.warning("Windows OCR unavailable; Google Docs can't be covered")
                return None
        from winrt.windows.graphics.imaging import BitmapAlphaMode, BitmapPixelFormat, SoftwareBitmap
        from winrt.windows.storage.streams import DataWriter
        dw = DataWriter()
        dw.write_bytes(data)
        bmp = SoftwareBitmap.create_copy_from_buffer(dw.detach_buffer(), BitmapPixelFormat.BGRA8, w, h,
                                                     BitmapAlphaMode.PREMULTIPLIED)
        result = self.ocr_loop.run_until_complete(self.ocr_engine.recognize_async(bmp))
        boxes = []
        for line in result.lines:
            words = list(line.words)
            if not words:
                continue
            spans, pos = [], 0
            for wd in words:
                spans.append((pos, pos + len(wd.text)))
                pos += len(wd.text) + 1
            text = " ".join(wd.text for wd in words)
            # OCR text can have small errors: use the OCR-tolerant matching here
            hits = [(hh.start, hh.end) for hh in redact.find_sensitive(text, self.cfg, strict=False, use_ner=False)]
            if not hits:
                continue
            flagged = [any(a < e and s_ < b for s_, e in hits) for a, b in spans]
            i = 0
            while i < len(words):
                if not flagged[i]:
                    i += 1
                    continue
                j = i
                while j + 1 < len(words) and flagged[j + 1]:
                    j += 1
                rs = [words[k].bounding_rect for k in range(i, j + 1)]
                boxes.append((min(r.x for r in rs), min(r.y for r in rs),
                              max(r.x + r.width for r in rs), max(r.y + r.height for r in rs)))
                i = j + 1
        return boxes

    def docs_items(self, wins, now) -> list:
        items = []
        for hwnd, st in self.docs.items():
            if not st["boxes"]:
                continue
            r = wintypes.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(r))
            rects = [(r.left + a, r.top + b, r.left + c, r.top + d) for a, b, c, d in st["boxes"]]
            for i, (box, h, wrect) in enumerate(self.visible_parts(rects, st["pid"], wins)):
                items.append((box, h, wrect, ("docs", hwnd, i), now, None, None))
        return items

    def proton_cfg(self) -> dict:
        c = dict(PROTON_DEFAULTS)
        c.update(self.cfg.get("proton_vpn") or {})
        c["process"] = str(c.get("process") or "ProtonVPN.Client").removesuffix(".exe")
        return c

    def proton_update(self, wins, now):
        """Find the connection-detail areas in Proton VPN's window (re-read only
        when it changes, is resized, or every few seconds). Each area becomes a
        tracked box anchored to an element, so it follows scrolling and moves."""
        pc = self.proton_cfg()
        name = pc["process"].lower()
        if not pc["enabled"] or self.proton_hidden:
            self.drop_proton()
            return
        mine = [w for w in wins if self.proc_name(w.pid) == name and w.rect[2] - w.rect[0] > 200]
        if not mine:
            self.drop_proton()
            return
        w = max(mine, key=lambda w: (w.rect[2] - w.rect[0]) * (w.rect[3] - w.rect[1]))
        size = (w.rect[2] - w.rect[0], w.rect[3] - w.rect[1])
        due = self.proton_dirty and now - self.proton_last > 1.0
        if not (due or size != self.proton_size or now - self.proton_last > PROTON_RELAYOUT):
            return
        if not self.budget_ok(w.pid):
            return
        self.proton_last, self.proton_size, self.proton_dirty = now, size, False
        t0 = time.perf_counter()
        try:
            areas = self.proton_areas(w.hwnd, pc)
        except (comtypes.COMError, ValueError):
            return
        finally:
            self.charge(w.pid, time.perf_counter() - t0)
        if not areas and any(k[0] == "proton" for k in self.tracks if isinstance(k, tuple)):
            return  # briefly unreadable: keep the last good layout (like the old tool)
        color = pc.get("color")
        keep = set()
        for kind, n, rect, anchor, arect in areas:
            key = ("proton", kind, n)
            keep.add(key)
            tr = self.tracks.get(key)
            if tr is None:
                tr = Track(anchor, w.pid, "", [])
                self.tracks[key] = tr
            tr.el, tr.pid = anchor, w.pid
            tr.offset = (rect[0] - arect[0], rect[1] - arect[1], rect[2] - arect[2], rect[3] - arect[3])
            tr.color = tuple(color) if color else None
        for k in [k for k in self.tracks if isinstance(k, tuple) and k[:1] == ("proton",) and k not in keep]:
            del self.tracks[k]

    def drop_proton(self):
        for k in [k for k in self.tracks if isinstance(k, tuple) and k[:1] == ("proton",)]:
            del self.tracks[k]
        self.proton_size = None

    def proton_areas(self, hwnd, pc) -> list:
        """Port of the VpnPrivacy tool's FindDetailAreas: screen areas holding the
        connection details, found from the labels next to them.
        Returns [(kind, n, area rect, anchor element, anchor rect)]."""
        u = self.uia
        cr = u.CreateCacheRequest()
        for prop in (U.UIA_NamePropertyId, U.UIA_AutomationIdPropertyId, U.UIA_BoundingRectanglePropertyId):
            cr.AddProperty(prop)
        cond = u.CreatePropertyCondition(U.UIA_ControlTypePropertyId, U.UIA_TextControlTypeId)
        arr = u.ElementFromHandle(hwnd).FindAllBuildCache(U.TreeScope_Descendants, cond, cr)
        texts = []
        for i in range(arr.Length if arr else 0):
            e = arr.GetElement(i)
            rc = e.CachedBoundingRectangle
            if rc.right - rc.left > 0:
                texts.append((e.CachedName or "", e.CachedAutomationId or "", (rc.left, rc.top, rc.right, rc.bottom), e))

        def index_of(label):
            return next((i for i, t in enumerate(texts) if t[0].lower().startswith(label.lower())), -1)

        ip, load, total, current = (index_of(x) for x in ("VPN IP", "Server load", "Total traffic", "Current traffic"))
        cur_label = texts[current][2] if current >= 0 else None
        pad = 6
        out = []

        # Location: the connection card's country and its city / server line
        loc = [t for t in texts if t[1] in ("ConnectionCardTitle", "ConnectionCardDescription")]
        if loc and pc["location"]:
            r = (min(t[2][0] for t in loc) - pad, min(t[2][1] for t in loc) - pad,
                 max(t[2][2] for t in loc) + pad, max(t[2][3] for t in loc) + pad)
            out.append(("location", 0, r, loc[0][3], loc[0][2]))

        # A value under its label, widened up to the next column so bars and long values are covered
        def value_box(kind, idx, right_edge):
            if idx < 0 or idx + 1 >= len(texts) or not pc[kind]:
                return
            v = texts[idx + 1][2]
            right = right_edge if right_edge is not None and right_edge > v[2] else v[2] + pad
            out.append((kind, 0, (v[0] - pad, v[1] - pad, right, v[3] + pad), texts[idx + 1][3], v))

        before_current = cur_label[0] - 16 if cur_label else None
        before_load = texts[load][2][0] - 16 if load >= 0 else None
        value_box("ip", ip, before_load)
        value_box("server_load", load, before_current)
        value_box("traffic", total, before_current)

        if cur_label and pc["speed"]:
            label_el = texts[current][3]
            after = [t for t in texts[current + 1: current + 7]
                     if t[0].endswith("/s") or all(c.isdigit() or c in ".," for c in t[0])]
            speeds = [t for t in after if t[0].endswith("/s")]
            right = max(t[2][2] for t in speeds) + pad if speeds else cur_label[2] + 400
            if speeds:
                out.append(("speed", 0, (min(t[2][0] for t in speeds) - 40, cur_label[1] - pad, right,
                                         cur_label[3] + pad), label_el, cur_label))
            bottom = max(t[2][3] for t in after) + 14 if after else cur_label[3] + 150
            out.append(("speed", 1, (cur_label[0] - pad, cur_label[3] + 2, right, bottom), label_el, cur_label))
        return out

    def find_scroller(self, el):
        """Nearest ancestor that scrolls vertically (e.g. Discord's message list).
        Returns the element, or False if the text isn't inside anything scrollable."""
        walker = self.uia.RawViewWalker
        cur = el
        for _ in range(40):
            if cur.GetCurrentPropertyValue(U.UIA_ScrollVerticallyScrollablePropertyId):
                return cur
            if cur.CurrentControlType == U.UIA_WindowControlTypeId:
                return False
            cur = walker.GetParentElement(cur)
            if not cur:
                return False
        return False

    def resolve(self, tr: Track):
        """One-time search for the exact text ranges of a match."""
        t0 = time.perf_counter()
        tr.ranges = []
        if tr.offset is not None:  # Proton area: only need its scroll area
            try:
                tr.scroller = self.find_scroller(tr.el)
            except (comtypes.COMError, ValueError):
                tr.scroller = None
            return
        try:
            if tr.tp is not None:  # editor: search its own document
                tr.ranges = find_ranges(tr.tp.DocumentRange, tr.needles)
            browser = self.proc_name(tr.pid) in BROWSERS
            doc = self.find_document(tr.el) if (browser or not tr.ranges) else None
            if browser:
                tr.doc = doc
            if not tr.ranges and doc is not None:  # web/Electron text: its range in the page
                tp = text_pattern(doc)
                if tp is not None:
                    tr.ranges = find_ranges(tp.RangeFromChild(tr.el), tr.needles)
        except (comtypes.COMError, ValueError):
            tr.ranges = []
        try:
            tr.scroller = self.find_scroller(tr.el)
        except (comtypes.COMError, ValueError):
            tr.scroller = None  # unknown: overlay falls back to what it has seen move
        self.charge(tr.pid, time.perf_counter() - t0)

    def locate(self, tr: Track):
        if tr.offset is not None:  # Proton area: anchor element's box + fixed offset
            rc = tr.el.CurrentBoundingRectangle
            if rc.right <= rc.left or rc.bottom <= rc.top:
                return None
            o = tr.offset
            return [(rc.left + o[0], rc.top + o[1], rc.right + o[2], rc.bottom + o[3])]
        if tr.el.CurrentIsOffscreen:
            return []  # e.g. inside a background browser tab / collapsed panel
        if tr.ranges:
            return ranges_rects(tr.ranges)  # one cheap call per range
        rc = tr.el.CurrentBoundingRectangle
        l, t, r, b = rc.left, rc.top, rc.right, rc.bottom
        if r <= l or b <= t:
            return None
        longest_line = max((len(ln) for ln in tr.text.splitlines()), default=0)
        if (r - l) < longest_line * MIN_CHAR_PX * self.sys_scale:
            # far too small to show this text: it's a hidden description
            # (e.g. tray icon tooltip with your Wi-Fi name), not visible text
            return []
        if tr.ctype == U.UIA_EditControlTypeId:
            # a text box always shows its text; without exact positions,
            # cover the whole box (never treat it as a hidden label)
            return [(l, t, r, b)]
        if tr.ctype in CONTAINER_TYPES:
            # a page / panel / list's *label* (e.g. Gmail's page title with your
            # email in it) - shown in the tab or not at all, never across the area
            return []
        if "\n" not in tr.text and (b - t) > 3 * LINE_PX * self.sys_scale:
            return []  # one line of text can't fill a tall area: it's a label
        if "\n" in tr.text or (b - t) > 50:
            return [(l, t, r, b)]
        cw = (r - l) / max(len(tr.text), 1)
        return [(max(l, l + cw * (a - 0.5)), t, min(r, l + cw * (e + 0.5)), b) for a, e in tr.hits]

    def find_document(self, el):
        """Nearest ancestor with a TextPattern (e.g. the web page document)."""
        walker = self.uia.RawViewWalker
        cur = el
        for _ in range(25):
            cur = walker.GetParentElement(cur)
            if not cur:
                return None
            if cur.CurrentControlType == U.UIA_DocumentControlTypeId:
                return cur
        return None

    def tab_visible(self, tr: Track, wins, titles: dict) -> bool:
        """Browsers keep background tabs' text 'on screen' as far as accessibility
        is concerned; the active tab is the one whose title is the window title."""
        name = (tr.doc.CurrentName or "").strip()
        if not name:
            return True  # can't tell: better to cover
        if tr.pid not in titles:
            buf = ctypes.create_unicode_buffer(512)
            titles[tr.pid] = []
            for w in wins:
                if w.pid == tr.pid and user32.GetWindowTextW(w.hwnd, buf, 512):
                    titles[tr.pid].append(buf.value)
        return any(t.startswith(name) for t in titles[tr.pid])

    def visible_parts(self, rects, pid, wins, pad=None) -> list[tuple]:
        """The parts of each rectangle you can actually see: inside its window
        and not under any window that's on top of it."""
        out = []
        for l, t, r, b in rects:
            cx, cy = (l + r) / 2, (t + b) / 2
            owner = window_at(wins, cx, cy)
            pts = [(cx, cy), (l + 1, t + 1), (r - 1, t + 1), (l + 1, b - 1), (r - 1, b - 1)]
            if owner is None or owner.pid != pid:
                owner = next((w for x, y in pts if (w := window_at(wins, x, y)) and w.pid == pid), None)
                if owner is None:
                    continue  # completely covered by another app
            p = max(int(self.cfg["padding"]), round(2 * owner.scale)) if pad is None else pad
            # window position measured right now (not at tick start), so a move
            # mid-tick can't be applied twice by the overlay
            wrect = frame_rect(owner.hwnd) or owner.rect
            wl, wt, wr, wb = wrect
            l, t, r, b = max(l - p, wl), max(t - p, wt), min(r + p, wr), min(b + p, wb)
            if r <= l or b <= t:
                continue
            pieces = [(l, t, r, b)]
            for w in wins:  # topmost first: everything before the owner is on top of it
                if w is owner:
                    break
                pieces = [q for pc in pieces for q in subtract(pc, w.rect)]
                if not pieces:
                    break
            for q in pieces:
                out.append(((int(q[0]), int(q[1]), int(q[2]) + 1, int(q[3]) + 1), owner.hwnd, wrect))
        return out


# --------------------------------------------------------------------------- #
# Overlay window
# --------------------------------------------------------------------------- #
HWND_TOPMOST = wintypes.HWND(-1)
SWP_FLAGS = 0x0001 | 0x0002 | 0x0010  # NOSIZE | NOMOVE | NOACTIVATE
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetAncestor.restype = wintypes.HWND
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND] + [ctypes.c_int] * 4 + [wintypes.UINT]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]


gdi32 = ctypes.windll.gdi32
gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
gdi32.CreateCompatibleDC.restype = wintypes.HDC
gdi32.SelectObject.restype = wintypes.HGDIOBJ
gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wintypes.HDC]
gdi32.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT, ctypes.c_void_p,
                            ctypes.c_void_p, wintypes.UINT]
user32.GetDC.restype = wintypes.HDC
user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]


def print_window(hwnd):
    """The window's own pixels (as the app draws them - none of our boxes or
    covers on top). Returns (BGRA bytes, width, height, window left, window top)."""
    r = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    if w <= 0 or h <= 0:
        return None
    screen = user32.GetDC(None)
    mem = gdi32.CreateCompatibleDC(screen)
    bmp = gdi32.CreateCompatibleBitmap(screen, w, h)
    old = gdi32.SelectObject(mem, bmp)
    try:
        if not user32.PrintWindow(hwnd, mem, 2):  # PW_RENDERFULLCONTENT
            return None
        bi = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), w, -h, 1, 32, 0, 0, 0, 0, 0, 0)
        buf = (ctypes.c_ubyte * (w * h * 4))()
        if not gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0):
            return None
        return bytes(buf), w, h, r.left, r.top
    finally:
        gdi32.SelectObject(mem, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(None, screen)


def window_title(hwnd) -> str:
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    return buf.value


APP_COLORS_FILE = HERE / "app_colors.json"


def load_app_colors() -> dict:
    try:
        return json.loads(APP_COLORS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_app_colors(colors: dict):
    try:
        tmp = APP_COLORS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(colors, indent=1), encoding="utf-8")
        os.replace(tmp, APP_COLORS_FILE)
    except OSError:
        pass


def client_rect(hwnd):
    """A window's content area on screen (everything inside its border)."""
    if not user32.IsWindowVisible(hwnd) or user32.IsIconic(hwnd):
        return None
    r = wintypes.RECT()
    pt = wintypes.POINT(0, 0)
    if not user32.GetClientRect(hwnd, ctypes.byref(r)) or not user32.ClientToScreen(hwnd, ctypes.byref(pt)):
        return None
    if r.right < 50 or r.bottom < 50:
        return None
    return (pt.x, pt.y, pt.x + r.right, pt.y + r.bottom)


def frame_rect(hwnd):
    """Window rectangle (same measurement the scanner uses); None if gone/minimized."""
    if not user32.IsWindow(hwnd) or user32.IsIconic(hwnd) or not user32.IsWindowVisible(hwnd):
        return None
    r = wintypes.RECT()
    if dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(r), ctypes.sizeof(r)) != 0:
        user32.GetWindowRect(hwnd, ctypes.byref(r))
    return (r.left, r.top, r.right, r.bottom)


def rounded_points(x0, y0, x1, y1, r):
    """Polygon points that, drawn with smooth=True, make a rounded rectangle."""
    r = max(0.0, min(r, (x1 - x0) / 2, (y1 - y0) / 2))
    return [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1,
            x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]


class Overlay:
    """Draws the boxes. Between scanner updates it keeps them glued to their
    window, follows scrolling, and animates smoothly. Safety rule for the
    animation: an edge that has to *grow* to cover text jumps there at once;
    only edges that pull back (and boxes going away) are animated."""

    def __init__(self, cfg: dict, inbox: queue.Queue):
        self.inbox = inbox
        self.origin = (0, 0)
        self.items = []    # [(box, hwnd, window rect, id, time measured)]
        self.scroll = {}   # box id -> (direction: +1 down/-1 up/0 drag, time, recent notches)
        self.movers = set()  # box ids seen moving while you scrolled (for apps that
                             # don't report their scrollable areas)
        self.track = {}    # id -> (time measured, top relative to window, velocity px/s, last moved)
        self.seen = {}     # id -> (item, time last reported) for HOLD_MISSING
        self.disp = {}     # id -> [l, t, r, b] as currently drawn (animated)
        self.shapes = {}   # id -> canvas polygon
        self.drawn = {}
        self.last_frame = time.monotonic()
        self.input_until = 0.0
        self.guard_wins = {}  # app window -> its attached cover window
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.overrideredirect(True)
        self.root.config(bg=TRANSPARENT)
        self.root.attributes("-transparentcolor", TRANSPARENT)
        self.root.attributes("-topmost", True)
        self.canvas = tk.Canvas(self.root, bg=TRANSPARENT, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)
        self.hwnd = None
        self.apply_config(cfg)
        self.root.after(16, self.poll)
        self.root.after(1500, self.keep_on_top)

    def apply_config(self, cfg: dict):
        r, g, b = cfg.get("box_color", [128, 128, 128])
        self.color = f"#{int(r):02x}{int(g):02x}{int(b):02x}"
        if self.color.lower() == TRANSPARENT:
            self.color = "#ff00fd"  # the see-through key color itself can't be used
        self.radius = max(0.0, float(cfg.get("corner_radius", 0)))

        self.animate = bool(cfg.get("animation", True))
        self.anim_s = max(0.0, float(cfg.get("animation_ms", 120))) / 1000
        for key, shape in self.shapes.items():
            self.canvas.itemconfig(shape, fill=getattr(self, "colors", {}).get(key, self.color),
                                   smooth=self.radius > 0)
        self.drawn = {}  # force a redraw with the new look

    def place(self, geo):
        x, y, w, h = geo
        self.origin = (x, y)
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.deiconify()
        self.root.update_idletasks()
        self.hwnd = user32.GetAncestor(self.root.winfo_id(), 2)  # GA_ROOT
        style = user32.GetWindowLongPtrW(self.hwnd, GWL_EXSTYLE)
        style = (style | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE) & ~WS_EX_APPWINDOW
        user32.SetWindowLongPtrW(self.hwnd, GWL_EXSTYLE, style)
        self.keep_on_top(reschedule=False)

    def keep_on_top(self, reschedule=True):
        if self.hwnd:
            user32.SetWindowPos(self.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_FLAGS)
        if reschedule:
            self.root.after(1500, self.keep_on_top)

    def on_wheel(self, x, y, delta):
        """delta > 0 wheel up (content moves down), < 0 wheel down, 0 = click-drag.
        Only boxes inside the scrollable area under the mouse get the head start."""
        now = time.monotonic()
        d = (delta > 0) - (delta < 0)
        rects = {}
        for box, hwnd, wrect, key, tm, area, _c in self.items:
            if hwnd not in rects:
                rects[hwnd] = frame_rect(hwnd)
            cur = rects[hwnd]
            if not cur or not (cur[0] <= x < cur[2] and cur[1] <= y < cur[3]):
                continue  # not the window being scrolled
            if area:  # known scrollable area: is the mouse over it?
                al, at, ar, ab = area[0] + cur[0], area[1] + cur[1], area[2] + cur[0], area[3] + cur[1]
                if not (al <= x < ar and at <= y < ab):
                    continue
            elif key not in self.movers:
                continue  # not in a known scroll area, and never seen it scroll
            prev = self.scroll.get(key)
            n = 1
            if delta and prev and prev[0] == d and now - prev[1] < 0.1:
                n = min(prev[2] + 1, 3)  # several quick notches = bigger scroll
            self.scroll[key] = (d, now, n)

    def update_motion(self, items):
        """Speed of each covered piece of text, from consecutive measurements."""
        new = {}
        scrolling = time.monotonic() < self.input_until
        for (l, t, r, b), hwnd, wrect, key, tm, area, _c in items:
            rel = t - wrect[1]  # relative to its window, so window moves don't count
            prev = self.track.get(key)
            v = 0.0
            if prev and tm == prev[0]:
                v = prev[2]
            elif prev and 0 < tm - prev[0] < 0.3:
                moved = rel - prev[1]
                v = 0.0 if abs(moved) <= 1 else max(-20000.0, min(20000.0, moved / (tm - prev[0])))
            last_move = tm if v else (prev[3] if prev else -1.0)
            new[key] = (tm, rel, v, last_move)
            if v and scrolling:
                self.movers.add(key)
        self.track = new
        if len(self.movers) > 5000:
            self.movers.clear()

    def receive(self, items):
        """New boxes from the scanner; briefly keep ones that went missing."""
        now = time.monotonic()
        keys = {it[3] for it in items}
        held = [it for k, (it, seen) in self.seen.items() if k not in keys and now - seen < HOLD_MISSING]
        for it in items:
            self.seen[it[3]] = (it, now)
        self.seen = {k: v for k, v in self.seen.items() if now - v[1] < HOLD_MISSING or k in keys}
        self.items = items + held
        self.update_motion(items)

    def poll(self):
        try:
            while True:
                msg = self.inbox.get_nowait()
                if msg == "quit":
                    self.root.destroy()
                    return
                if msg[0] == "geometry":
                    self.place(msg[1])
                elif msg[0] == "boxes":
                    self.receive(msg[1])
                elif msg[0] == "wheel":
                    self.input_until = time.monotonic() + ACTIVITY_HOLD
                    self.on_wheel(*msg[1:])
                elif msg[0] == "config":
                    self.apply_config(msg[1])
                elif msg[0] == "guards":
                    self.sync_guards(msg[1])
                elif msg[0] == "arm":
                    gw = self.guard_wins.get(msg[1])
                    if gw:
                        gw["target"] = 1.0
                        self.set_alpha(gw, 1.0)  # instantly
        except queue.Empty:
            pass
        self.redraw()
        self.update_guard_windows()
        self.root.after(16, self.poll)

    def targets(self, now) -> dict:
        """Where each box should be right now (window moves + scroll prediction)."""
        rects, shown = {}, {}
        colors = self.colors = {}
        for (l, t, r, b), hwnd, (wl, wt, wr, wb), key, tm, area, col in self.items:
            if col:
                colors[key] = "#%02x%02x%02x" % tuple(int(v) for v in col)
            if hwnd not in rects:
                rects[hwnd] = frame_rect(hwnd)
            cur = rects[hwnd]
            if cur is None:
                continue  # window minimized / closed
            dx, dy = cur[0] - wl, cur[1] - wt  # window moved since the box was measured
            l, t, r, b = l + dx, t + dy, r + dx, b + dy
            if dx or dy:
                m = max(8, (b - t) * 0.6)  # predicted position: safety margin
                l, t, r, b = l - m, t - m, r + m, b + m
            motion = self.track.get(key)
            v = motion[2] if motion else 0.0
            if motion and now - motion[3] < 0.3:
                m = 6 * (user32.GetDpiForWindow(hwnd) or 96) / 96  # slow tail of a scroll
                t, b = t - m, b + m
            if v and now - tm < 0.25:
                # moving text: cover from where it was measured to where it
                # should be when this frame shows, plus a speed-based margin
                off = v * min(now - tm + RENDER_LAG, MAX_LEAD)
                m = abs(v) * MOTION_MARGIN + 3
                t, b = min(t, t + off) - m, max(b, b + off) + m
            else:
                st = self.scroll.get(key)
                if st and now - st[1] < 0.1:
                    # scroll just started, nothing measured yet: stretch that way
                    g = WHEEL_GUESS_PX * st[2] * (user32.GetDpiForWindow(hwnd) or 96) / 96
                    if st[0] >= 0:
                        b += g
                    if st[0] <= 0:
                        t -= g
            l, t, r, b = max(l, cur[0]), max(t, cur[1]), min(r, cur[2]), min(b, cur[3])
            if r > l and b > t:
                old = shown.get(key)  # same id twice (held + live): keep the union
                shown[key] = (l, t, r, b) if old is None else (
                    min(old[0], l), min(old[1], t), max(old[2], r), max(old[3], b))
        return shown

    # ---- cover windows attached to black-out apps ----
    def sync_guards(self, state: dict):
        for app, (armed, color) in state.items():
            hexc = "#%02x%02x%02x" % tuple(int(v) for v in color)
            if hexc.lower() == TRANSPARENT:
                hexc = "#ff00fd"
            gw = self.guard_wins.get(app)
            if gw is None:
                gw = self.make_guard(app, hexc, armed)
                if gw is None:
                    continue
                self.guard_wins[app] = gw
            if gw["color"] != hexc:
                gw["color"] = hexc
                try:
                    gw["top"].config(bg=hexc)
                except tk.TclError:
                    pass
            gw["target"] = 1.0 if armed else 0.0
            if armed:
                self.set_alpha(gw, 1.0)
        for app in [a for a in self.guard_wins if a not in state]:
            self.drop_guard(app)

    def make_guard(self, app, color, armed):
        rc = client_rect(app) or frame_rect(app) or (0, 0, 2, 2)
        try:
            top = tk.Toplevel(self.root)
            top.withdraw()
            top.overrideredirect(True)
            top.config(bg=color)
            top.attributes("-alpha", 1.0 if armed else 0.0)
            top.geometry(f"{rc[2] - rc[0]}x{rc[3] - rc[1]}+{rc[0]}+{rc[1]}")
            top.deiconify()
            top.update_idletasks()
        except tk.TclError:
            return None
        gh = user32.GetAncestor(top.winfo_id(), 2)
        style = user32.GetWindowLongPtrW(gh, GWL_EXSTYLE)
        style = (style | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE) & ~WS_EX_APPWINDOW
        user32.SetWindowLongPtrW(gh, GWL_EXSTYLE, style)
        user32.SetWindowLongPtrW(gh, -8, app)  # owned by the app: Windows keeps it right above it
        gw = {"top": top, "hwnd": gh, "app": app, "alpha": 1.0 if armed else 0.0,
              "target": 1.0 if armed else 0.0, "color": color, "rect": rc, "z_checked": 0.0}
        self.restack(gw)
        return gw

    def restack(self, gw):
        """Directly above its app window: under whatever is on top of the app."""
        above = user32.GetWindow(gw["app"], 3)  # GW_HWNDPREV
        while above and above == gw["hwnd"]:
            above = user32.GetWindow(above, 3)
        user32.SetWindowPos(gw["hwnd"], above or 0, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0010)

    def drop_guard(self, app):
        gw = self.guard_wins.pop(app, None)
        if gw:
            try:
                gw["top"].destroy()
            except tk.TclError:
                pass

    def set_alpha(self, gw, a):
        a = max(0.0, min(1.0, a))
        if abs(a - gw["alpha"]) > 0.001 or a in (0.0, 1.0):
            gw["alpha"] = a
            try:
                gw["top"].attributes("-alpha", a)
            except tk.TclError:
                pass

    def update_guard_windows(self):
        now = time.monotonic()
        fade = max(0.12, self.anim_s) if self.animate else 0.0
        dt = getattr(self, "_guard_dt", now)
        self._guard_dt = now
        for app, gw in list(self.guard_wins.items()):
            if not user32.IsWindow(gw["hwnd"]):  # destroyed together with its app
                self.guard_wins.pop(app, None)
                continue
            rc = client_rect(app)
            if rc and rc != gw["rect"]:
                gw["rect"] = rc
                gw["top"].geometry(f"{rc[2] - rc[0]}x{rc[3] - rc[1]}+{rc[0]}+{rc[1]}")
            if now - gw["z_checked"] > 0.5:
                gw["z_checked"] = now
                if user32.GetWindow(gw["hwnd"], 2) != app:  # GW_HWNDNEXT: not right above it
                    self.restack(gw)
            if gw["target"] == 0.0 and gw["alpha"] > 0.0:
                # the "swap": boxes are already drawn on top; the cover fades out under them
                self.set_alpha(gw, gw["alpha"] - (now - dt) / fade if fade else 0.0)

    def redraw(self):
        now = time.monotonic()
        dt, self.last_frame = now - self.last_frame, now
        goal = self.targets(now)
        smooth = self.animate and self.anim_s > 0
        k = 1 - math.exp(-dt / (self.anim_s / 3)) if smooth else 1.0  # ~done after anim_s
        frame = {}
        for key in set(self.disp) | set(goal):
            tgt, cur = goal.get(key), self.disp.get(key)
            if tgt is None:
                if not smooth or cur is None or key[0] == "cover":
                    continue  # gone (a scan cover lifts at once)
                cx, cy = (cur[0] + cur[2]) / 2, (cur[1] + cur[3]) / 2
                tgt = (cx, cy, cx, cy)  # text went away: shrink out
            if cur is None:
                cur = list(tgt)  # new box: appears instantly (safety first)
            else:
                nxt = []
                for i, (c, g) in enumerate(zip(cur, tgt)):
                    grows = (g < c) if i < 2 else (g > c)
                    nxt.append(g if (grows and key in goal) else c + (g - c) * k)
                cur = nxt
            if key not in goal and (cur[2] - cur[0] < 2 or cur[3] - cur[1] < 2):
                continue  # finished shrinking out
            frame[key] = cur
        self.disp = frame
        ox, oy = self.origin
        rounded = {k: tuple(int(round(v)) for v in box) for k, box in frame.items()}
        if rounded == self.drawn:
            return
        for key in [k for k in self.shapes if k not in rounded]:
            self.canvas.delete(self.shapes.pop(key))
        for key, (x0, y0, x1, y1) in rounded.items():
            if self.drawn.get(key) == (x0, y0, x1, y1) and key in self.shapes:
                continue
            pts = rounded_points(x0 - ox, y0 - oy, x1 - ox, y1 - oy, self.radius * self.scale_for(key))
            if key in self.shapes:
                self.canvas.coords(self.shapes[key], *pts)
            else:
                self.shapes[key] = self.canvas.create_polygon(
                    *pts, fill=self.colors.get(key, self.color), outline="", smooth=self.radius > 0)
        self.drawn = rounded

    def scale_for(self, key) -> float:
        return (user32.GetDpiForSystem() or 96) / 96


# --------------------------------------------------------------------------- #
# Input watcher: notices scrolling / dragging. Raw input is a read-only copy
# of input events: nothing is hooked, blocked or delayed.
# --------------------------------------------------------------------------- #
class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [("dwType", wintypes.DWORD), ("dwSize", wintypes.DWORD),
                ("hDevice", wintypes.HANDLE), ("wParam", wintypes.WPARAM)]


class RAWMOUSE(ctypes.Structure):
    _fields_ = [("usFlags", ctypes.c_ushort), ("_pad", ctypes.c_ushort),
                ("usButtonFlags", ctypes.c_ushort), ("usButtonData", ctypes.c_short),
                ("ulRawButtons", ctypes.c_ulong), ("lLastX", ctypes.c_long),
                ("lLastY", ctypes.c_long), ("ulExtraInformation", ctypes.c_ulong)]


class RAWKEYBOARD(ctypes.Structure):
    _fields_ = [("MakeCode", ctypes.c_ushort), ("Flags", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort), ("VKey", ctypes.c_ushort),
                ("Message", ctypes.c_uint), ("ExtraInformation", ctypes.c_ulong)]


class _RAWDATA(ctypes.Union):
    _fields_ = [("mouse", RAWMOUSE), ("keyboard", RAWKEYBOARD)]


class RAWINPUT(ctypes.Structure):
    _fields_ = [("header", RAWINPUTHEADER), ("data", _RAWDATA)]


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [("usUsagePage", ctypes.c_ushort), ("usUsage", ctypes.c_ushort),
                ("dwFlags", wintypes.DWORD), ("hwndTarget", wintypes.HWND)]


WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]


SCROLL_KEYS = {0x21, 0x22, 0x23, 0x24, 0x26, 0x28, 0x20}  # PgUp PgDn End Home Up Down Space


def input_thread(scanner: Scanner, overlay_q: queue.Queue):
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.GetRawInputData.argtypes = [wintypes.HANDLE, wintypes.UINT, ctypes.c_void_p,
                                       ctypes.POINTER(wintypes.UINT), wintypes.UINT]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                       wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    WM_INPUT, RID_INPUT = 0x00FF, 0x10000003
    RI_MOUSE_WHEEL = 0x0400
    BUTTON_DOWN, BUTTON_UP = 0x0001, 0x0002  # left button
    state = {"dragging": False}
    raw = RAWINPUT()
    size_hdr = ctypes.sizeof(RAWINPUTHEADER)

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == WM_INPUT:
            size = wintypes.UINT(ctypes.sizeof(raw))
            if user32.GetRawInputData(lparam, RID_INPUT, ctypes.byref(raw), ctypes.byref(size), size_hdr) > 0:
                now = time.monotonic()
                if raw.header.dwType == 0:  # mouse
                    m = raw.data.mouse
                    flags = m.usButtonFlags
                    if flags & BUTTON_DOWN:
                        state["dragging"] = True
                    if flags & BUTTON_UP:
                        state["dragging"] = False
                        scanner.activity_until = now + ACTIVITY_HOLD
                    if flags & RI_MOUSE_WHEEL:
                        pt = wintypes.POINT()
                        user32.GetCursorPos(ctypes.byref(pt))
                        overlay_q.put(("wheel", pt.x, pt.y, m.usButtonData))
                        scanner.activity_until = now + ACTIVITY_HOLD
                    elif state["dragging"] and (m.lLastX or m.lLastY):
                        scanner.activity_until = now + ACTIVITY_HOLD  # dragging a window / scrollbar
                        if now - state.get("drag_sent", 0) > 0.05:
                            state["drag_sent"] = now
                            pt = wintypes.POINT()
                            user32.GetCursorPos(ctypes.byref(pt))
                            overlay_q.put(("wheel", pt.x, pt.y, 0))
                elif raw.header.dwType == 1 and raw.data.keyboard.VKey in SCROLL_KEYS:
                    scanner.activity_until = now + ACTIVITY_HOLD
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    proc = WNDPROC(wndproc)  # keep a reference for the lifetime of the thread
    wc = WNDCLASSW()
    wc.lpfnWndProc = proc
    wc.lpszClassName = "opsecToolInputWatcher"
    wc.hInstance = kernel32.GetModuleHandleW(None)
    user32.RegisterClassW(ctypes.byref(wc))
    hwnd = user32.CreateWindowExW(0, wc.lpszClassName, None, 0, 0, 0, 0, 0,
                                  wintypes.HWND(-3), None, wc.hInstance, None)  # message-only
    RIDEV_INPUTSINK = 0x00000100  # receive input even when we're not focused
    devs = (RAWINPUTDEVICE * 2)(RAWINPUTDEVICE(1, 2, RIDEV_INPUTSINK, hwnd),   # mouse
                                RAWINPUTDEVICE(1, 6, RIDEV_INPUTSINK, hwnd))   # keyboard
    if not user32.RegisterRawInputDevices(devs, 2, ctypes.sizeof(RAWINPUTDEVICE)):
        log.warning("scroll/drag detection unavailable")
        return
    log.info("scroll/drag detection active")

    # Content changes: tab switches, page loads and channel switches change the
    # window title; new windows are "shown". Windows tells us at once, so the
    # window can be blacked out before its new content can be seen.
    titles = {}
    buf = ctypes.create_unicode_buffer(512)

    def title_key(hwnd) -> str:
        """A window title, minus things that change without the content changing:
        counters ("(3) Inbox") and unsaved-file markers ("*notes.txt - Notepad")."""
        user32.GetWindowTextW(hwnd, buf, 512)
        return buf.value.lstrip("*●• ").translate(DIGITS)

    # remember what's already open, so the first tab/channel switch counts too
    seed = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)(
        lambda h, _: (titles.__setitem__(h, title_key(h)) if user32.IsWindowVisible(h) else None) or True)
    user32.EnumWindows(seed, 0)
    WINEVENTPROC = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD, wintypes.HWND,
                                      wintypes.LONG, wintypes.LONG, wintypes.DWORD, wintypes.DWORD)
    EVENT_OBJECT_SHOW, EVENT_OBJECT_NAMECHANGE = 0x8002, 0x800C
    EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_MINIMIZEEND = 0x0003, 0x0017

    def on_event(hook, event, hwnd, id_obj, id_child, thread, ms):
        try:
            if id_obj != 0 or id_child != 0 or not hwnd:
                return
            if event in (EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_MINIMIZEEND):
                # Alt+Tab / taskbar / restore: its cover is already up if it was
                # hidden - scan it right away so the cover can clear quickly
                g = scanner.guards.get(hwnd)
                if g and g["armed"]:
                    now = time.monotonic()
                    g["scan_req"] = now
                    scanner.cover_requests[hwnd] = now
                    scanner.activity_until = max(scanner.activity_until, now + 0.3)
                return
            if user32.GetAncestor(hwnd, 2) != hwnd or not user32.IsWindowVisible(hwnd):
                return
            title = title_key(hwnd)
            prev = titles.get(hwnd)
            titles[hwnd] = title
            if not scanner.cfg.get("scan_cover", True):
                return
            if event == EVENT_OBJECT_SHOW and prev is None:
                scanner.new_windows.add(hwnd)  # brand-new window: cover it once it's tracked
            elif (event == EVENT_OBJECT_NAMECHANGE and prev is not None and title and prev != title
                  and user32.GetForegroundWindow() == hwnd and scanner.arm(hwnd)):
                overlay_q.put(("arm", hwnd))  # tab / page / channel switched: cover now
        except Exception:
            log.exception("window event")

    event_proc = WINEVENTPROC(on_event)  # keep a reference
    user32.SetWinEventHook.restype = wintypes.HANDLE
    user32.SetWinEventHook.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.HMODULE, WINEVENTPROC,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    for ev in (EVENT_OBJECT_SHOW, EVENT_OBJECT_NAMECHANGE, EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_MINIMIZEEND):
        user32.SetWinEventHook(ev, ev, None, event_proc, 0, 0, 0x0002)  # out of context, skip own process
    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


def hotkey_thread(out: queue.Queue, scanner=None):
    """Ctrl+Alt+F12 quits. Ctrl+Alt+H shows/hides the Proton VPN boxes."""
    MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, VK_F12, VK_H, WM_HOTKEY = 0x1, 0x2, 0x4000, 0x7B, 0x48, 0x312
    if not user32.RegisterHotKey(None, 1, MOD_ALT | MOD_CONTROL | MOD_NOREPEAT, VK_F12):
        log.warning("could not register Ctrl+Alt+F12 hotkey")
    if not user32.RegisterHotKey(None, 2, MOD_ALT | MOD_CONTROL | MOD_NOREPEAT, VK_H):
        log.warning("could not register Ctrl+Alt+H hotkey (another program is using it)")
    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        if msg.message == WM_HOTKEY and msg.wParam == 1:
            log.info("quit hotkey pressed")
            out.put("quit")
            return
        if msg.message == WM_HOTKEY and msg.wParam == 2 and scanner is not None:
            scanner.proton_hidden = not scanner.proton_hidden
            log.info("Proton VPN boxes %s", "hidden" if scanner.proton_hidden else "shown")


def watchdog(scanner: Scanner):
    """If some app hangs a call and the scanner stops ticking, restart cleanly
    (otherwise protection would silently stop)."""
    import subprocess

    while True:
        time.sleep(5)
        if time.monotonic() - scanner.heartbeat > 20:
            log.error("scanner stuck for 20s; restarting")
            args = [a for a in sys.argv[1:] if a != "--restarted"] + ["--restarted"]
            subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *args], cwd=str(HERE))
            os._exit(3)


def main() -> int:
    debug = "--debug" in sys.argv
    logging.basicConfig(
        filename=HERE / "live.log", level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if sys.stdout is not None:  # running with a console: also log there
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
    for noisy in ("httpx", "httpcore", "urllib3", "huggingface_hub", "filelock", "comtypes", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    for attempt in range(20):  # a restarting copy may still be shutting down
        mutex = kernel32.CreateMutexW(None, False, "Local\\opsec-tool-live")
        if kernel32.GetLastError() != 183:  # not ERROR_ALREADY_EXISTS
            break
        kernel32.CloseHandle(mutex)
        if "--restarted" not in sys.argv:
            log.info("already running; exiting")
            return 0
        time.sleep(0.5)
    else:
        return 0
    # never compete with the apps you're actually using
    kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), 0x4000)  # BELOW_NORMAL

    (HERE / "live.pid").write_text(str(os.getpid()))  # lets the settings window find us
    cfg = redact.load_config()
    q: queue.Queue = queue.Queue()
    overlay = Overlay(cfg, q)
    scanner = Scanner(cfg, q)
    scanner.start()
    threading.Thread(target=hotkey_thread, args=(q, scanner), daemon=True).start()
    threading.Thread(target=watchdog, args=(scanner,), daemon=True).start()
    threading.Thread(target=input_thread, args=(scanner, q), daemon=True).start()
    log.info("live redaction started (Ctrl+Alt+F12 to quit)")
    overlay.root.mainloop()
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
