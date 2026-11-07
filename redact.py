"""
opsec-tool: automatically grey-box IPs, your name, and locations in images.

Pipeline:
  1. EasyOCR (deep-learning text detector + recognizer) finds every piece of
     text in the image and where it is.
  2. Detectors run over the recognized text:
       - regex + validation for IPv4 / IPv6 addresses (and emails)
       - fuzzy matching for your first / last / full name and any extra terms
         from config.json (tolerates OCR typos, catches usernames like "jsmith99")
       - a BERT named-entity-recognition model (dslim/bert-base-NER) for
         locations (and optionally any person / organization name)
       - a street-address regex
  3. Every hit is mapped back to pixel coordinates and painted over with a
     solid grey box.

Usage:
  python redact.py screenshot.png              -> screenshot_redacted.png
  python redact.py folder_of_images/           -> each image gets _redacted copy
  python redact.py --clipboard                 -> redact image on clipboard in place
  python redact.py img.png -o out.png --report -> also print what was found
"""

from __future__ import annotations

import argparse
import difflib
import io
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageGrab

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}

DEFAULT_CONFIG = {
    "first_name": [],
    "last_name": [],
    "emails": [],
    "locations": [],
    "extra_terms": [],
    "live_ignore_processes": [],
    "detect": {
        "ip_addresses": True,
        "emails": False,
        "my_name": True,
        "locations_ml": False,
        "street_addresses": False,
        "all_person_names_ml": False,
        "organizations_ml": False,
    },
    "fuzzy_threshold": 0.8,
    "ner_min_score": 0.6,
    "box_color": [128, 128, 128],
    "padding": 4,
    "corner_radius": 0,
    "animation": True,
    "animation_ms": 120,
}


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_config(path: Path = CONFIG_PATH) -> dict:
    global CONFIG_PATH
    CONFIG_PATH = path
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if CONFIG_PATH.exists():
        user = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))  # -sig: Notepad may add a BOM
        detect = {**cfg["detect"], **user.get("detect", {})}
        cfg.update(user)
        cfg["detect"] = detect
    else:
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        print(f"Created {CONFIG_PATH} - fill in your name/locations there.")
    return cfg


# --------------------------------------------------------------------------- #
# OCR -> text layout with character offsets
# --------------------------------------------------------------------------- #
@dataclass
class Segment:
    text: str
    box: tuple[float, float, float, float]  # x0, y0, x1, y1 in original pixels
    start: int = 0  # offset into the full document text
    end: int = 0


@dataclass
class Hit:
    start: int
    end: int
    kind: str


_reader = None
_ner = None


def get_reader():
    global _reader
    if _reader is None:
        import easyocr
        import torch

        print("Loading OCR model...", file=sys.stderr)
        _reader = easyocr.Reader(["en"], gpu=torch.cuda.is_available(), verbose=False)
    return _reader


def get_ner():
    global _ner
    if _ner is None:
        import os

        cache = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface"))
        if (cache / "hub" / "models--dslim--bert-base-NER").exists():
            os.environ.setdefault("HF_HUB_OFFLINE", "1")  # already downloaded: stay offline
        from transformers import pipeline

        print("Loading NER model...", file=sys.stderr)
        _ner = pipeline(
            "token-classification",
            model="dslim/bert-base-NER",
            aggregation_strategy="simple",
        )
    return _ner


def ocr(img: Image.Image) -> list[Segment]:
    import numpy as np

    # Small screenshots OCR much better when upscaled.
    scale = 2 if max(img.size) < 1600 else 1
    work = img.convert("RGB")
    if scale != 1:
        work = work.resize((work.width * scale, work.height * scale), Image.LANCZOS)

    results = get_reader().readtext(np.array(work), paragraph=False, width_ths=0.3)
    segs = []
    for pts, text, _conf in results:
        text = text.strip()
        if not text:
            continue
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        segs.append(
            Segment(text, (min(xs) / scale, min(ys) / scale, max(xs) / scale, max(ys) / scale))
        )
    return segs


def build_document(segs: list[Segment]) -> str:
    """Group segments into visual lines so the NER model sees real context,
    and record each segment's character offsets in the joined text."""
    segs = sorted(segs, key=lambda s: (s.box[1] + s.box[3]) / 2)
    lines: list[list[Segment]] = []
    for s in segs:
        cy = (s.box[1] + s.box[3]) / 2
        h = s.box[3] - s.box[1]
        if lines:
            last = lines[-1]
            lcy = sum((t.box[1] + t.box[3]) / 2 for t in last) / len(last)
            if abs(cy - lcy) < 0.5 * h:
                last.append(s)
                continue
        lines.append([s])

    parts = []
    pos = 0
    for line in lines:
        line.sort(key=lambda s: s.box[0])
        for i, s in enumerate(line):
            if i:
                parts.append(" ")
                pos += 1
            s.start = pos
            parts.append(s.text)
            pos += len(s.text)
            s.end = pos
        parts.append("\n")
        pos += 1
    return "".join(parts)


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #
IPV4_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\s?[.,]\s?\d{1,3}){3}(?![\w])")
IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
EMAIL_RE = re.compile(r"[\w.+-]+\s?@\s?[\w-]+(?:\.[\w-]+)+")  # OCR: tolerates stray spaces
# exact text: no spaces, preceded by nothing word-like, ends in an alphabetic TLD
EMAIL_STRICT_RE = re.compile(r"(?<![\w.+@-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,24}(?![\w-])")
STREET_RE = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z][\w'.-]*\s+){1,4}"
    r"(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Way|Ct|Court|"
    r"Pl|Place|Ter|Terrace|Pkwy|Parkway|Cir|Circle|Hwy|Highway)\b\.?",
    re.I,
)
WORD_RE = re.compile(r"[\w'@.-]+")


VERSION_CONTEXT_RE = re.compile(r"(?:\bv|\bver|version|build|release)\s*[:#]?\s*$", re.I)


def detect_ips(text: str, strict: bool = False) -> list[Hit]:
    hits = []
    for m in IPV4_RE.finditer(text):
        if strict and re.search(r"\s|,", m.group()):
            continue  # exact text: real IPs never contain spaces/commas
        if VERSION_CONTEXT_RE.search(text[max(0, m.start() - 12) : m.start()]):
            continue  # "version 1.2.3.4" / "build 4.5.6.7"
        candidate = re.sub(r"\s", "", m.group()).replace(",", ".")
        try:
            ipaddress.IPv4Address(candidate)
            hits.append(Hit(m.start(), m.end(), "ip"))
        except ValueError:
            pass
    for m in IPV6_RE.finditer(text):
        try:
            ipaddress.IPv6Address(m.group())
            hits.append(Hit(m.start(), m.end(), "ip"))
        except ValueError:
            pass
    if strict:
        return hits
    # OCR often mangles IPv6 ("2001:db8::8a2e" -> "2001:db88a2e.370"), so also
    # flag hex-looking tokens with several :/./; separators and at least one ':'.
    for m in re.finditer(r"[0-9A-Fa-f:.;]{10,}", text):
        tok = m.group()
        if (
            ":" in tok
            and len(re.findall(r"[:.;]", tok)) >= 3
            and re.search(r"[A-Fa-f]", tok)
        ):
            hits.append(Hit(m.start(), m.end(), "ip"))
    return hits


def detect_regex(text: str, pattern: re.Pattern, kind: str) -> list[Hit]:
    return [Hit(m.start(), m.end(), kind) for m in pattern.finditer(text)]


def detect_terms_strict(text: str, terms: list[tuple[str, str]]) -> list[Hit]:
    """Matching for exact (non-OCR) text: whole words only, no fuzziness.
    - names/locations: whole-word, case-insensitive ("john" won't hit "johnny")
    - custom terms (usernames etc.): anywhere, even inside a longer word
    - full name also caught when written as one word ("johnwick99")"""
    hits = []
    for term, kind in terms:
        tl = term.strip().lower()
        if not tl:
            continue
        pat = r"\s+".join(re.escape(p) for p in tl.split())
        if kind != "custom term":
            pat = rf"(?<!\w){pat}(?!\w)"
        hits += [Hit(m.start(), m.end(), kind) for m in re.finditer(pat, text, re.I)]
        compact = tl.replace(" ", "")
        if " " in tl and len(compact) >= 6:
            hits += [Hit(m.start(), m.end(), kind) for m in re.finditer(re.escape(compact), text, re.I)]
    return hits


def detect_terms(text: str, terms: list[tuple[str, str]], threshold: float) -> list[Hit]:
    """Exact + fuzzy matching of user-supplied terms (name, city, username...)."""
    hits = []
    words = [(m.start(), m.end(), m.group().lower().strip(".'-")) for m in WORD_RE.finditer(text)]

    for term, kind in terms:
        term = term.strip()
        if not term:
            continue
        tl = term.lower()
        # 1) exact, case-insensitive, flexible whitespace
        pat = r"\s+".join(re.escape(p) for p in tl.split())
        for m in re.finditer(pat, text, re.I):
            hits.append(Hit(m.start(), m.end(), kind))

        k = len(tl.split())
        compact = tl.replace(" ", "")
        for i in range(len(words) - k + 1):
            window = words[i : i + k]
            joined = " ".join(w[2] for w in window)
            s, e = window[0][0], window[-1][1]
            if len(compact) >= 4:
                # 2) term embedded in a word, e.g. username "johnsmith99"
                if k == 1 and compact in joined:
                    hits.append(Hit(s, e, kind))
                    continue
                # 3) fuzzy, to survive OCR errors ("Srnith" for "Smith")
                if abs(len(joined) - len(tl)) <= max(2, len(tl) // 4):
                    if difflib.SequenceMatcher(None, joined, tl).ratio() >= threshold:
                        hits.append(Hit(s, e, kind))
        # 4) multi-word term written as one word: "johnsmith" for "John Smith"
        if k > 1 and len(compact) >= 6:
            for ws, we, w in words:
                if compact in w:
                    hits.append(Hit(ws, we, kind))
    return hits


def detect_ner(text: str, cfg: dict, strict: bool = False) -> list[Hit]:
    if strict and len(text.split()) < 3:
        return []  # UI labels / buttons: too little context, mostly false positives
    min_score = cfg.get("live_ner_min_score", 0.9) if strict else cfg["ner_min_score"]
    want = {}
    d = cfg["detect"]
    if d.get("locations_ml"):
        want["LOC"] = "location"
    if d.get("all_person_names_ml"):
        want["PER"] = "person"
    if d.get("organizations_ml"):
        want["ORG"] = "organization"
    if not want:
        return []

    ner = get_ner()
    hits = []
    # Chunk by lines to stay under BERT's 512-token limit.
    chunks, buf, buf_start, pos = [], "", 0, 0
    for line in text.splitlines(keepends=True):
        if len(buf) + len(line) > 1000 and buf:
            chunks.append((buf_start, buf))
            buf, buf_start = "", pos
        buf += line
        pos += len(line)
    if buf:
        chunks.append((buf_start, buf))

    for offset, chunk in chunks:
        if not chunk.strip():
            continue
        for ent in ner(chunk):
            label = ent["entity_group"]
            if label not in want or ent["score"] < min_score:
                continue
            word = chunk[ent["start"] : ent["end"]]
            if strict and (len(word) < 3 or word.isupper() or not word[0].isupper()):
                continue  # "NEW", "DESC", lowercase fragments
            hits.append(Hit(offset + ent["start"], offset + ent["end"], want[label]))
    return hits


def ner_batch(texts: list[str], cfg: dict, strict: bool = True) -> list[list[Hit]]:
    """Run the ML model on many short texts at once (much faster than one by one).
    Texts over 1000 chars fall back to detect_ner (which chunks them)."""
    min_score = cfg.get("live_ner_min_score", 0.9) if strict else cfg["ner_min_score"]
    d = cfg["detect"]
    want = {k: v for k, v, on in (
        ("LOC", "location", d.get("locations_ml")),
        ("PER", "person", d.get("all_person_names_ml")),
        ("ORG", "organization", d.get("organizations_ml")),
    ) if on}
    out: list[list[Hit]] = [[] for _ in texts]
    short = [i for i, t in enumerate(texts) if len(t) <= 1000 and t.strip()]
    for i, t in enumerate(texts):
        if i not in short and t.strip():
            out[i] = find_ner(t, cfg, strict)
    if not want or not short:
        return out
    short.sort(key=lambda i: len(texts[i]))  # similar lengths together = less padding
    results = get_ner()([texts[i] for i in short], batch_size=8)
    for i, ents in zip(short, results):
        t = texts[i]
        for ent in ents:
            if ent["entity_group"] not in want or ent["score"] < min_score:
                continue
            word = t[ent["start"] : ent["end"]]
            if strict and (len(word) < 3 or word.isupper() or not word[0].isupper()):
                continue
            out[i].append(expand_to_word(t, Hit(ent["start"], ent["end"], want[ent["entity_group"]])))
    return out


def expand_to_word(text: str, h: Hit) -> Hit:
    s, e = h.start, h.end
    while s > 0 and (text[s - 1].isalnum() or text[s - 1] in "_-'"):
        s -= 1
    while e < len(text) and (text[e].isalnum() or text[e] in "_-'"):
        e += 1
    return Hit(s, e, h.kind)


def ner_wanted(text: str, cfg: dict, strict: bool = False) -> bool:
    d = cfg["detect"]
    if not (d.get("locations_ml") or d.get("all_person_names_ml") or d.get("organizations_ml")):
        return False
    if strict:
        # strict mode only accepts capitalised entities, so a line without any
        # Capitalised word can't produce a hit: skip the expensive model
        return len(text.split()) >= 3 and re.search(r"[A-Z][a-z]", text) is not None
    return True


def find_ner(text: str, cfg: dict, strict: bool = False) -> list[Hit]:
    return [expand_to_word(text, h) for h in detect_ner(text, cfg, strict)]


def as_list(v) -> list[str]:
    """Config values may be a single string or a list of strings."""
    if v is None:
        return []
    return [v] if isinstance(v, str) else [str(x) for x in v]


def find_sensitive(text: str, cfg: dict, strict: bool = False, use_ner: bool = True) -> list[Hit]:
    """strict=True is for exact text (live mode via UI Automation): no OCR-error
    tolerance, whole-word name matching, pickier ML model.
    use_ner=False skips the (slow) ML model; call find_ner() separately."""
    d = cfg["detect"]
    hits: list[Hit] = []
    if d.get("ip_addresses"):
        hits += detect_ips(text, strict)
    if d.get("emails"):
        hits += detect_regex(text, EMAIL_STRICT_RE if strict else EMAIL_RE, "email")
    if d.get("street_addresses"):
        hits += detect_regex(text, STREET_RE, "address")

    terms = []
    if d.get("my_name"):
        # each may be a single name or a list of names (nicknames, aliases...)
        firsts = [n.strip() for n in as_list(cfg.get("first_name")) if n.strip()]
        lasts = [n.strip() for n in as_list(cfg.get("last_name")) if n.strip()]
        terms += [(n, "my name") for n in firsts + lasts]
        terms += [(f"{f} {l}", "my name") for f in firsts for l in lasts]  # every full-name combo
    terms += [(t, "custom term") for t in as_list(cfg.get("extra_terms"))]
    terms += [(t, "my email") for t in as_list(cfg.get("emails"))]
    terms += [(t, "my location") for t in as_list(cfg.get("locations"))]
    if strict:
        hits += detect_terms_strict(text, terms)
    else:
        hits += detect_terms(text, terms, cfg["fuzzy_threshold"])

    if use_ner:
        hits += detect_ner(text, cfg, strict)
    return [expand_to_word(text, h) for h in hits]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def ink_words(gray, box) -> list[tuple[float, float]]:
    """Find the horizontal extents of each visually separate word inside a
    segment box by looking for columns with no 'ink' (pixels that differ from
    the background). Works for light and dark themes."""
    import numpy as np

    x0, y0, x1, y1 = (int(round(v)) for v in box)
    x0, y0 = max(x0, 0), max(y0, 0)
    region = gray[y0:y1, x0:x1]
    if region.size == 0 or region.shape[1] < 2:
        return [(box[0], box[2])]
    border = np.concatenate([region[0], region[-1], region[:, 0], region[:, -1]])
    bg = np.median(border)
    has_ink = (np.abs(region.astype(int) - bg) > 40).any(axis=0)

    min_gap = max(2, int(0.15 * (y1 - y0)))  # narrower gaps are inside a word
    words, start, gap = [], None, 0
    for i, ink in enumerate(has_ink):
        if ink:
            if start is None:
                start = i
            gap = 0
        elif start is not None:
            gap += 1
            if gap >= min_gap:
                words.append((x0 + start, x0 + i - gap + 1))
                start, gap = None, 0
    if start is not None:
        words.append((x0 + start, x0 + len(has_ink) - gap))
    return words or [(box[0], box[2])]


def hits_to_boxes(hits: list[Hit], segs: list[Segment], img: Image.Image, pad: int) -> list[tuple]:
    import numpy as np

    gray = np.array(img.convert("L"))
    word_cache: dict[int, list] = {}
    boxes = []
    for h in hits:
        for idx, s in enumerate(segs):
            a, b = max(h.start, s.start), min(h.end, s.end)
            if a >= b:
                continue
            x0, y0, x1, y1 = s.box
            n = max(len(s.text), 1)
            cw = (x1 - x0) / n  # approx char width (proportional estimate)
            bx0 = max(x0, x0 + cw * (a - s.start - 0.3))
            bx1 = min(x1, x0 + cw * (b - s.start + 0.3))
            # Snap outward to whole visual words so a partial word never leaks.
            if idx not in word_cache:
                word_cache[idx] = ink_words(gray, s.box)
            for wx0, wx1 in word_cache[idx]:
                if wx0 <= bx0 <= wx1:
                    bx0 = wx0
                if wx0 <= bx1 <= wx1:
                    bx1 = wx1
            boxes.append((bx0 - pad, y0 - pad, bx1 + pad, y1 + pad))
    return boxes


def redact_image(img: Image.Image, cfg: dict, report: bool = False) -> tuple[Image.Image, int]:
    segs = ocr(img)
    text = build_document(segs)
    hits = find_sensitive(text, cfg)

    if report:
        seen = set()
        for h in sorted(hits, key=lambda h: h.start):
            key = (h.kind, text[h.start : h.end])
            if key not in seen:
                seen.add(key)
                print(f"  [{h.kind}] {key[1]!r}")

    boxes = hits_to_boxes(hits, segs, img, cfg["padding"])
    out = img.convert("RGB").copy()
    draw = ImageDraw.Draw(out)
    color = tuple(cfg["box_color"])
    for b in boxes:
        draw.rectangle(b, fill=color)
    return out, len(boxes)


# --------------------------------------------------------------------------- #
# Clipboard (Windows)
# --------------------------------------------------------------------------- #
def set_clipboard_image(img: Image.Image) -> None:
    import ctypes
    from ctypes import wintypes

    buf = io.BytesIO()
    img.convert("RGB").save(buf, "BMP")
    data = buf.getvalue()[14:]  # strip BMP file header -> DIB

    k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
    k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    k32.GlobalAlloc.restype = wintypes.HGLOBAL
    k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    k32.GlobalLock.restype = wintypes.LPVOID
    k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    u32.OpenClipboard.argtypes = [wintypes.HWND]
    u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    u32.SetClipboardData.restype = wintypes.HANDLE

    h = k32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
    p = k32.GlobalLock(h)
    ctypes.memmove(p, data, len(data))
    k32.GlobalUnlock(h)
    if not u32.OpenClipboard(None):
        raise RuntimeError("Could not open clipboard")
    try:
        u32.EmptyClipboard()
        if not u32.SetClipboardData(8, h):  # CF_DIB
            raise RuntimeError("Could not set clipboard data")
    finally:
        u32.CloseClipboard()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def collect_inputs(paths: list[str]) -> list[Path]:
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(
                f for f in p.iterdir()
                if f.suffix.lower() in IMAGE_EXTS and not f.stem.endswith("_redacted")
            )
        elif p.is_file():
            files.append(p)
        else:
            print(f"Not found: {p}", file=sys.stderr)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description="Grey-box IPs, your name and locations in images.")
    ap.add_argument("inputs", nargs="*", help="image files or folders")
    ap.add_argument("-o", "--output", help="output file (single input) or folder")
    ap.add_argument("--clipboard", action="store_true", help="redact the image on the clipboard")
    ap.add_argument("--report", action="store_true", help="print what was detected")
    ap.add_argument("--config", default=str(CONFIG_PATH), help="path to config.json")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    if not (as_list(cfg["first_name"]) or as_list(cfg["last_name"])) and cfg["detect"].get("my_name"):
        print("Note: first_name/last_name are empty in config.json.", file=sys.stderr)

    if args.clipboard:
        img = ImageGrab.grabclipboard()
        if not isinstance(img, Image.Image):
            print("No image on the clipboard.", file=sys.stderr)
            return 1
        out, n = redact_image(img, cfg, args.report)
        set_clipboard_image(out)
        print(f"Clipboard image redacted ({n} boxes).")
        return 0

    files = collect_inputs(args.inputs)
    if not files:
        ap.print_help()
        return 1

    out_arg = Path(args.output) if args.output else None
    for f in files:
        if out_arg and len(files) == 1 and out_arg.suffix:
            dest = out_arg
        else:
            folder = out_arg or f.parent
            folder.mkdir(parents=True, exist_ok=True)
            dest = folder / f"{f.stem}_redacted.png"
        print(f"{f.name}:")
        with Image.open(f) as img:
            out, n = redact_image(img, cfg, args.report)
        out.save(dest)  # PNG/fresh save -> original EXIF/GPS metadata is not copied
        print(f"  -> {dest}  ({n} boxes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
