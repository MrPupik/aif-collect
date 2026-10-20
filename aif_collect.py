#!/usr/bin/env python3
"""aif_collect: bundle Claude Code sessions into one redacted, anonymized zip.

Local only: no network calls. Originals are only ever read. Python 3.8+, stdlib only.
"""
import argparse
import contextlib
import datetime
import fnmatch
import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"

EXCLUDED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", "target"}
EXCLUDED_FILE_GLOBS = [".env*", "*.pem", "*.key", "id_rsa*"]
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_GIT_BYTES = 15 * 1024 * 1024
WARN_ZIP_BYTES = 100 * 1024 * 1024
GIT_TIMEOUT = 120
HEAD_LINES = 50
MIN_ZIP_MTIME = 315619200  # 1980-01-02; zip cannot store anything older

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=\-]{16,}", re.I),
]


BANNER = r"""
   _=/    |\_/|    \=_
  /XX/    |XXX|    \XX\
  |XXXXX_XXXXXXX_XXXXX|
  XXXXXXXXXXXXXXXXXXXXX
  |XXXXX/ XXXXX \XXXXX|
  \XX/    |/ \|    \XX/
   ~=\    i   i    /=~

  AI-fluent collect
  -----------------
  Made by AI-fluent. Collects your Claude Code
  sessions into one zip, on your machine only.
"""


class UserError(Exception):
    """A problem the user can act on; main() prints the message without a traceback."""


# ---------------------------------------------------------------- helpers

def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024


def ask(prompt):
    try:
        return input(prompt)
    except EOFError:
        raise UserError("No interactive input available. Run this from a terminal (not a pipe).")


def open_folder(path):
    """Best effort: show a folder in the OS file browser."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # noqa
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print("  (could not open the folder automatically: %s)" % path)


def parse_selection(text, n):
    """'1,3,5-7' or 'all' -> sorted list of 0-based indexes. Raises ValueError with a readable message."""
    text = text.strip().lower()
    if text == "all":
        return list(range(n))
    picked = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            raise ValueError("'%s' is not a number or range" % part)
        lo = int(m.group(1))
        hi = int(m.group(2) or lo)
        if lo > hi:
            raise ValueError("range '%s' is backwards" % part)
        if lo < 1 or hi > n:
            raise ValueError("'%s' is outside 1-%d" % (part, n))
        picked.update(range(lo - 1, hi))
    if not picked:
        raise ValueError("nothing selected")
    return sorted(picked)


def is_excluded_file(name):
    low = name.lower()
    return any(fnmatch.fnmatchcase(low, g) for g in EXCLUDED_FILE_GLOBS)


def walk_files(root):
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


# ---------------------------------------------------------------- redaction

class Redactor:
    def __init__(self, home, usernames, names):
        self.counts = Counter()
        variants = {str(home), str(home).replace("\\", "/"), str(home).replace("/", "\\")}
        variants = sorted((v for v in variants if len(v) > 3), key=len, reverse=True)
        self.home_pat = re.compile("|".join(re.escape(v) for v in variants)) if variants else None
        self.user_pats = [
            re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(u), re.I)
            for u in sorted(set(usernames)) if len(u) >= 3
        ]
        self.name_pats = [
            (re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(n), re.I), "name-%d" % (i + 1))
            for i, n in enumerate(names)
        ]
        self.name_pats.sort(key=lambda p: -len(p[0].pattern))

    def redact_text(self, s):
        for pat in SECRET_PATTERNS:
            s, n = pat.subn("[REDACTED]", s)
            self.counts["secrets"] += n
        pats = ([self.home_pat] if self.home_pat else []) + self.user_pats
        for pat in pats:
            s, n = pat.subn("<USER>", s)
            self.counts["user"] += n
        for pat, placeholder in self.name_pats:
            s, n = pat.subn(placeholder, s)
            self.counts["names"] += n
        return s

    def redact_path(self, s):
        # <, > and [ ] are awkward or illegal in Windows file names
        return self.redact_text(s).replace("<USER>", "USER").replace("[REDACTED]", "REDACTED")

    def redact_obj(self, o):
        if isinstance(o, str):
            return self.redact_text(o)
        if isinstance(o, list):
            return [self.redact_obj(v) for v in o]
        if isinstance(o, dict):
            return {(self.redact_text(k) if isinstance(k, str) else k): self.redact_obj(v) for k, v in o.items()}
        return o


# ---------------------------------------------------------------- discovery

def find_claude_dir(override=None):
    if override:
        p = Path(override).expanduser()
        if (p / "projects").is_dir():
            return p
        raise UserError("--claude-dir %s has no 'projects' folder inside it." % p)
    cands = []
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        cands.append(Path(os.environ["CLAUDE_CONFIG_DIR"]).expanduser())
    cands += [Path.home() / ".claude", Path.home() / ".config" / "claude"]
    if os.environ.get("USERPROFILE"):
        cands.append(Path(os.environ["USERPROFILE"]) / ".claude")
    for c in cands:
        if (c / "projects").is_dir():
            return c
    raise UserError(
        "Could not find your Claude Code data. Looked in:\n  %s\n"
        "If it lives elsewhere, run again with --claude-dir <folder> (the one containing 'projects')."
        % "\n  ".join(str(c) for c in cands)
    )


def scan_head(path):
    """Return (cwd, sessionId, version) from the first lines of a jsonl; any may be None."""
    found = {"cwd": None, "sessionId": None, "version": None}
    try:
        with open(str(path), "rb") as f:
            for i, line in enumerate(f):
                if i >= HEAD_LINES or all(found.values()):
                    break
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    for k in found:
                        if not found[k] and isinstance(rec.get(k), str):
                            found[k] = rec[k]
    except OSError:
        pass
    return found["cwd"], found["sessionId"], found["version"]


def discover_projects(claude_dir, since=None):
    projects, warnings = [], []
    for d in sorted((claude_dir / "projects").iterdir()):
        if not d.is_dir():
            continue
        files = []
        try:
            for f in d.rglob("*.jsonl"):
                try:
                    st = f.stat()
                except OSError:
                    continue
                if since and datetime.datetime.fromtimestamp(st.st_mtime) < since:
                    continue
                files.append((f, st.st_mtime, st.st_size))
        except OSError as e:
            warnings.append("Skipped %s (%s)" % (d.name, e.strerror or e))
            continue
        if not files:
            continue
        files.sort(key=lambda t: t[1], reverse=True)
        cwd, sids, versions = None, set(), set()
        for f, _, _ in files:
            c, sid, ver = scan_head(f)
            cwd = cwd or c
            if sid:
                sids.add(sid)
            if ver:
                versions.add(ver)
            if "subagents" not in f.parts:
                sids.add(f.stem)
        top = [t for t in files if "subagents" not in t[0].parts] or files
        projects.append({
            "dir": d,
            "cwd": cwd,
            "name": Path(cwd.replace("\\", "/")).name if cwd else d.name,
            "files": [f for f, _, _ in files],
            "sessions": len(top),
            "sids": sorted(sids),
            "versions": sorted(versions),
            "last": files[0][1],
            "size": sum(s for _, _, s in files),
        })
    projects.sort(key=lambda p: p["last"], reverse=True)
    return projects, warnings


def find_side_data(claude_dir, sids):
    """Allowlisted per-session locations only. Returns (found: [(kind, path)], missing: [kind])."""
    import glob
    found, kinds = [], Counter()
    specs = [("file-history", "file-history/{}", True), ("todos", "todos/{}*", False),
             ("images", "image-cache/{}*", False), ("images", "images/{}*", False)]
    for sid in sids:
        esc = glob.escape(sid)
        for kind, pattern, _ in specs:
            for m in glob.glob(str(claude_dir / pattern.format(esc))):
                found.append((kind, Path(m)))
                kinds[kind] += 1
    missing = [k for k in ("file-history", "todos", "images") if not kinds[k]]
    return found, missing


# ---------------------------------------------------------------- picker

class KeyboardUnavailable(Exception):
    """Raw key input could not be set up; the caller falls back to the typed menu."""


HEADER_ROW = "%3s  %-30s %8s  %-10s %9s" % ("#", "Project", "Sessions", "Last used", "Size")


def project_row(i, p):
    return "%3d  %-30s %8d  %-10s %9s" % (
        i, p["name"][:30], p["sessions"], datetime.date.fromtimestamp(p["last"]).isoformat(), human(p["size"]))


def arrows_available():
    if not (sys.stdin.isatty() and sys.stdout.isatty()) or os.environ.get("TERM") == "dumb":
        return False
    if os.name == "nt":
        return True
    try:
        import termios  # noqa: F401
    except ImportError:
        return False
    return True


@contextlib.contextmanager
def keyboard_mode():
    """Unbuffered single-key input for the duration of the block."""
    if os.name == "nt":
        os.system("")  # turns on ANSI escape handling in the Windows console
        yield
        return
    try:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)
    except Exception as e:
        raise KeyboardUnavailable(str(e))
    try:
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _plain_key(ch):
    if ch in ("\r", "\n"):
        return "enter"
    if ch == " ":
        return "space"
    if ch == "\x03":
        raise KeyboardInterrupt
    return ch.lower()


def read_key():
    """One of: up, down, space, enter, esc, or a lowercase character ('' for unknown sequences)."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
        return _plain_key(ch)
    import select
    fd = sys.stdin.fileno()
    ch = os.read(fd, 1).decode("utf-8", "ignore")
    if ch == "":
        raise UserError("Input closed.")
    if ch == "\x1b":
        if select.select([fd], [], [], 0.05)[0]:
            seq = os.read(fd, 2).decode("utf-8", "ignore")
            return {"[A": "up", "[B": "down", "OA": "up", "OB": "down"}.get(seq, "")
        return "esc"
    return _plain_key(ch)


def pick_interactive(projects, key_reader=None, out=None):
    """Arrow-key multi-select. Returns the chosen projects in list order."""
    key_reader = key_reader or read_key
    out = out or sys.stdout
    n = len(projects)
    cols, lines = shutil.get_terminal_size((80, 24))
    view = max(3, min(n, lines - 8))
    cur, top, drawn, chosen = 0, 0, 0, set()

    def draw():
        nonlocal top, drawn
        if cur < top:
            top = cur
        elif cur >= top + view:
            top = cur - view + 1
        rows = ["Projects found (most recent first) - %d selected" % len(chosen), "      " + HEADER_ROW]
        for i in range(top, min(n, top + view)):
            text = "%s[%s] %s" % ("> " if i == cur else "  ", "x" if i in chosen else " ", project_row(i + 1, projects[i]))
            text = text[:cols - 1]
            rows.append("\x1b[7m%s\x1b[0m" % text if i == cur else text)
        rows.append("  (%d-%d of %d)" % (top + 1, min(n, top + view), n) if n > view else "")
        rows.append("Up/Down move   Space select   a all/none   Enter confirm   q quit")
        if drawn:
            out.write("\x1b[%dA" % drawn)
        for r in rows:
            out.write("\r\x1b[2K%s\n" % r)
        out.flush()
        drawn = len(rows)

    out.write("\n\x1b[?25l")  # hide the cursor while navigating
    try:
        while True:
            draw()
            key = key_reader()
            if key == "up":
                cur = (cur - 1) % n
            elif key == "down":
                cur = (cur + 1) % n
            elif key == "space":
                chosen.symmetric_difference_update({cur})
            elif key == "a":
                chosen = set() if len(chosen) == n else set(range(n))
            elif key == "enter":
                break
            elif key in ("q", "esc"):
                raise UserError("Cancelled.")
    finally:
        out.write("\x1b[?25h")
        out.flush()
    return [projects[i] for i in sorted(chosen or {cur})]


def pick_projects(projects):
    if arrows_available():
        try:
            with keyboard_mode():
                return pick_interactive(projects)
        except KeyboardUnavailable:
            pass  # fall through to the typed menu
    print("\nProjects found (most recent first):\n")
    print("  " + HEADER_ROW)
    for i, p in enumerate(projects, 1):
        print("  " + project_row(i, p))
    while True:
        text = ask("\nWhich projects? (e.g. 1,3,5-7 or all, q to quit): ")
        if text.strip().lower() in ("q", "quit"):
            raise UserError("Cancelled.")
        try:
            return [projects[i] for i in parse_selection(text, len(projects))]
        except ValueError as e:
            print("  Sorry, %s. Try again." % e)


# ---------------------------------------------------------------- git

class Git:
    def __init__(self):
        self.env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
        self.available = shutil.which("git") is not None

    def run(self, cwd, *args, **kw):
        """Returns (ok, stdout_bytes, error_text). Never raises for the usual git failures."""
        if not self.available:
            return False, b"", "git is not installed"
        try:
            r = subprocess.run(["git", "-C", str(cwd)] + list(args), env=self.env, timeout=GIT_TIMEOUT,
                               stdout=kw.get("stdout", subprocess.PIPE), stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            return False, b"", "git timed out"
        except OSError as e:
            return False, b"", str(e)
        err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return r.returncode == 0, r.stdout or b"", (err[-1] if err else "git failed")


# ---------------------------------------------------------------- staging

class Report:
    def __init__(self, alias):
        self.alias = alias
        self.files = 0
        self.bytes = 0
        self.sessions = 0
        self.skipped = []   # (path, reason)
        self.notes = []
        self.redactions = {}
        self.git = {}


class Stager:
    def __init__(self, redactor, claude_dir, no_git):
        self.red = redactor
        self.claude_dir = claude_dir
        self.no_git = no_git
        self.git = Git()

    def stage_file(self, src, root, rel, rep, cap=None):
        """Copy src to root/<redacted rel>, redacting text. Returns True if staged."""
        label = rel.as_posix()
        if is_excluded_file(src.name):
            rep.skipped.append((label, "excluded file type"))
            return False
        if src.is_symlink():
            rep.skipped.append((label, "symlink"))
            return False
        try:
            st = src.stat()
            if cap and st.st_size > cap:
                rep.skipped.append((label, "over %s" % human(cap)))
                return False
            dest = root / self.red.redact_path(label)
            dest.parent.mkdir(parents=True, exist_ok=True)
            suffix = src.suffix.lower()
            if suffix == ".jsonl":
                self._jsonl(src, dest, rep, label)
            else:
                data = src.read_bytes()
                text = None
                if b"\0" not in data[:8192]:
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
                if text is None:
                    dest.write_bytes(data)
                    rep.notes.append("binary, not scanned: %s" % label)
                elif suffix == ".json":
                    try:
                        text = json.dumps(self.red.redact_obj(json.loads(text)), ensure_ascii=False, indent=2)
                    except ValueError:
                        text = self.red.redact_text(text)
                    dest.write_text(text, encoding="utf-8", newline="\n")
                else:
                    dest.write_text(self.red.redact_text(text), encoding="utf-8", newline="\n")
            mtime = max(st.st_mtime, MIN_ZIP_MTIME)
            os.utime(str(dest), (mtime, mtime))
            rep.files += 1
            rep.bytes += dest.stat().st_size
            return True
        except FileNotFoundError:
            return False  # vanished mid-run, e.g. a tracked file that was deleted
        except PermissionError as e:
            rep.skipped.append((label, "no permission to read (%s)" % (e.strerror or "denied")))
            return False

    def _jsonl(self, src, dest, rep, label):
        bad = 0
        with open(str(src), "rb") as fin, open(str(dest), "w", encoding="utf-8", newline="\n") as fout:
            for raw in fin:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    out = json.dumps(self.red.redact_obj(json.loads(line)), ensure_ascii=False)
                except ValueError:
                    bad += 1
                    out = self.red.redact_text(line)
                fout.write(out + "\n")
        if bad:
            rep.notes.append("%d unparseable line(s) in %s were text-redacted" % (bad, label))

    def stage_project(self, proj, meta, stage):
        rep = Report(meta["alias"])
        base = stage / "projects" / meta["alias"]
        self.red.counts = Counter()
        pdir = proj["dir"]
        cwd = Path(proj["cwd"]) if proj["cwd"] else None

        for f in proj["files"]:
            self.stage_file(f, base / "transcripts", f.relative_to(pdir), rep)
        rep.sessions = proj["sessions"]

        found, missing = find_side_data(self.claude_dir, proj["sids"])
        for kind, path in found:
            rels = [path] if path.is_file() else list(walk_files(path))
            for f in rels:
                rel = f.relative_to(path.parent) if path.is_file() else Path(path.name) / f.relative_to(path)
                self.stage_file(f, base / "session-data" / kind, rel, rep)
        if missing:
            rep.notes.append("no %s found for these sessions" % ", ".join(missing))

        if cwd and cwd.is_dir():
            self._code(cwd, base, rep)
            if not self.no_git:
                self._git(cwd, base, rep)
            for rel in ("CLAUDE.md", ".claude/CLAUDE.md"):
                if (cwd / rel).is_file():
                    self.stage_file(cwd / rel, base / "instructions", Path(rel), rep)
            for f in sorted((cwd / ".claude").glob("settings*.json")) if (cwd / ".claude").is_dir() else []:
                self.stage_file(f, base / "instructions", Path(".claude") / f.name, rep)
        else:
            rep.notes.append("project folder no longer exists (%s): no code snapshot or git history"
                             % (self.red.redact_path(proj["cwd"]) if proj["cwd"] else "unknown"))

        for extra in meta["extras"]:
            if extra.is_dir():
                for f in walk_files(extra):
                    self.stage_file(f, base / "extras", Path(extra.name) / f.relative_to(extra), rep, MAX_FILE_BYTES)
            else:
                self.stage_file(extra, base / "extras", Path(extra.name), rep, MAX_FILE_BYTES)

        rep.redactions = dict(self.red.counts)
        return rep

    def _code(self, cwd, base, rep):
        ok, out, err = self.git.run(cwd, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        if ok:
            names = sorted(set(p for p in out.decode("utf-8", "surrogateescape").split("\0") if p))
            files = [cwd / n for n in names
                     if not EXCLUDED_DIRS.intersection(Path(n).parts[:-1]) and (cwd / n).is_file()]
        else:
            if (cwd / ".git").exists():
                rep.notes.append("git could not list files (%s); copied the folder instead" % err)
            files = walk_files(cwd)
        for f in files:
            self.stage_file(f, base / "code", f.relative_to(cwd), rep, MAX_FILE_BYTES)

    def _git(self, cwd, base, rep):
        if not (cwd / ".git").exists():
            return
        info = rep.git
        ok, out, err = self.git.run(cwd, "rev-list", "--branches", "--tags", "-n", "1")
        if not ok:
            info["skipped"] = "git unavailable or failed: %s" % err
            return
        if not out.strip():
            info["skipped"] = "repository has no commits"
            return
        ok, out, _ = self.git.run(cwd, "rev-list", "--branches", "--tags", "--count")
        info["commits"] = int(out.strip() or 0) if ok else None
        ok, out, _ = self.git.run(cwd, "log", "--branches", "--tags", "--format=%ae")
        info["authors"] = len(set(out.decode("utf-8", "replace").split())) if ok else None

        base.mkdir(parents=True, exist_ok=True)
        log_path = base / "git-log.txt"
        with open(str(log_path), "wb") as fh:
            ok, _, err = self.git.run(cwd, "log", "-p", "--branches", "--tags", stdout=fh)
        if not ok:
            log_path.unlink()
            info["skipped"] = "git log failed: %s" % err
            return
        if log_path.stat().st_size > MAX_GIT_BYTES:
            log_path.unlink()
            info["skipped"] = "history over %s; skipped (use the code snapshot)" % human(MAX_GIT_BYTES)
            return
        before = self.red.counts["secrets"]
        text = self.red.redact_text(log_path.read_text(encoding="utf-8", errors="replace"))
        log_path.write_text(text, encoding="utf-8", newline="\n")
        leaked = self.red.counts["secrets"] - before
        rep.files += 1
        rep.bytes += log_path.stat().st_size

        bundle = base / "git.bundle"
        ok, _, err = self.git.run(cwd, "bundle", "create", str(bundle), "--branches", "--tags")
        if not ok:
            info["bundle_skipped"] = "bundle failed: %s" % err
        elif leaked:
            bundle.unlink()
            info["bundle_skipped"] = "history contains %d secret(s); only the redacted git-log.txt is kept" % leaked
        elif bundle.stat().st_size > MAX_GIT_BYTES:
            bundle.unlink()
            info["bundle_skipped"] = "bundle over %s" % human(MAX_GIT_BYTES)
        else:
            info["bundle"] = bundle.stat().st_size
            rep.files += 1
            rep.bytes += info["bundle"]


# ---------------------------------------------------------------- prompts

def clean_dropped_path(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1]
    elif os.name != "nt":
        s = re.sub(r"\\(.)", r"\1", s)  # terminals escape spaces when dragging files in
    return Path(s).expanduser()


def prompt_project_meta(proj, index, taken):
    print("\n--- %s ---" % proj["name"])
    alias = ask("Anonymous alias [candidate-%d]: " % index).strip() or "candidate-%d" % index
    alias = re.sub(r"[^A-Za-z0-9._-]", "-", alias)
    while alias in taken:
        alias += "-x"
    outcome = ask("Outcome (e.g. hired, rejected, unsure): ").strip()
    reason = ask("One-line reason or rubric score: ").strip()
    extras = []
    while True:
        text = ask("Add any other files or folders (drag in, or press Enter to skip): ")
        if not text.strip():
            break
        p = clean_dropped_path(text)
        if p.exists():
            extras.append(p)
            print("  added %s" % p.name)
        else:
            print("  not found: %s" % p)
    return {"alias": alias, "outcome": outcome, "reason": reason, "extras": extras}


# ---------------------------------------------------------------- output

README = """ai-fluent-collect export (tool v{version})

manifest.json     what was collected, counts, redactions, skipped files
labels.json       alias, outcome and reason per project
projects/<alias>/
  transcripts/    Claude Code sessions (.jsonl), secrets and names redacted
  session-data/   file-history, todos, images for those sessions
  code/           final state of the project folder
  git-log.txt     redacted `git log -p`
  git.bundle      full git history; read it with: git clone git.bundle repo
  instructions/   project CLAUDE.md and .claude/settings*.json
  extras/         files added by the person who ran the tool

Redaction was applied to copies only; the originals were never modified.
Secrets became [REDACTED], the home path and username became <USER>.
"""


def write_meta_files(stage, metas, reports, args, versions, redactor):
    (stage / "README.txt").write_text(README.format(version=VERSION), encoding="utf-8")
    labels = {m["alias"]: {"outcome": m["outcome"], "reason": m["reason"]} for m in metas}
    (stage / "labels.json").write_text(json.dumps(labels, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest = {
        "tool_version": VERSION,
        "os": platform.platform(),
        "python": platform.python_version(),
        "claude_code_versions": sorted(versions),
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "since": args.since.date().isoformat() if args.since else None,
        "projects": [{
            "alias": r.alias, "sessions": r.sessions, "files": r.files, "bytes": r.bytes,
            "redactions": r.redactions, "git": r.git, "notes": r.notes,
            "skipped": [{"path": redactor.redact_path(p), "reason": why} for p, why in r.skipped],
        } for r in reports],
    }
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")


def staged_files(stage):
    return sorted(p for p in stage.rglob("*") if p.is_file())


def show_review(reports):
    print("\n================ Review ================")
    for r in reports:
        print("\n%s: %d sessions, %d files, %s" % (r.alias, r.sessions, r.files, human(r.bytes)))
        red = ", ".join("%s: %d" % kv for kv in sorted(r.redactions.items())) or "none"
        print("  redactions: %s" % red)
        g = r.git
        if g.get("skipped"):
            print("  git: skipped (%s)" % g["skipped"])
        elif g:
            print("  git: %s commits, %s author(s) (emails are inside git history), bundle %s" % (
                g.get("commits"), g.get("authors"), human(g["bundle"]) if "bundle" in g else "not included"))
            if g.get("bundle_skipped"):
                print("       bundle not included: %s" % g["bundle_skipped"])
        for p, why in r.skipped[:15]:
            print("  skipped %s: %s" % (p, why))
        if len(r.skipped) > 15:
            print("  ... and %d more skipped (see manifest.json)" % (len(r.skipped) - 15))
        for n in r.notes:
            print("  note: %s" % n)


def default_out_dir():
    home = Path.home()
    for d in (home / "Desktop", home / "OneDrive" / "Desktop"):
        if d.is_dir():
            return d
    return home


def write_zip(stage, dest):
    tmp = dest.with_name(dest.name + ".part")
    try:
        with zipfile.ZipFile(str(tmp), "w", zipfile.ZIP_DEFLATED) as zf:
            for p in staged_files(stage):
                zf.write(str(p), p.relative_to(stage).as_posix())
        os.replace(str(tmp), str(dest))
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def make_zip(stage, out):
    name = "aif-export-%s.zip" % datetime.datetime.now().strftime("%Y%m%d-%H%M")
    if out and out.suffix.lower() == ".zip":
        targets = [out]
    else:
        targets = [(out or default_out_dir()) / name]
    if targets[0].parent != Path.home():
        targets.append(Path.home() / name)
    last = None
    for t in targets:
        try:
            t.parent.mkdir(parents=True, exist_ok=True)
            write_zip(stage, t)
            return t
        except OSError as e:
            last = e
            print("Could not write %s (%s)." % (t, e.strerror or e))
            if t is not targets[-1]:
                print("Trying your home folder instead...")
    raise UserError("Could not write the zip anywhere (%s). Free some disk space or pass --out <folder>." % last)


# ---------------------------------------------------------------- main

def parse_args(argv):
    def date(s):
        try:
            return datetime.datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            raise argparse.ArgumentTypeError("expected YYYY-MM-DD, got '%s'" % s)

    ap = argparse.ArgumentParser(description="Bundle Claude Code sessions into one redacted zip.")
    ap.add_argument("--claude-dir", help="Claude data folder (the one containing 'projects')")
    ap.add_argument("--since", type=date, help="only sessions modified on/after this date (YYYY-MM-DD)")
    ap.add_argument("--dry-run", action="store_true", help="print the files that would be zipped, write nothing")
    ap.add_argument("--out", help="output folder, or a .zip file path (default: Desktop)")
    ap.add_argument("--no-git", action="store_true", help="skip git history")
    return ap.parse_args(argv)


def run(args):
    print(BANNER)
    print("Version %s. No network access. Nothing is sent. Originals are never modified.\n" % VERSION)

    claude_dir = find_claude_dir(args.claude_dir)
    projects, warnings = discover_projects(claude_dir, args.since)
    for w in warnings:
        print("Warning: %s" % w)
    if not projects:
        raise UserError("No Claude Code sessions found in %s%s." % (
            claude_dir / "projects", " since %s" % args.since.date() if args.since else ""))
    selected = pick_projects(projects)

    names = []
    if not args.dry_run:
        raw = ask("\nNames to anonymize (comma-separated, e.g. candidate names, company; Enter to skip): ")
        names = [n.strip() for n in raw.split(",") if n.strip()]

    metas, taken = [], set()
    for i, proj in enumerate(selected, 1):
        if args.dry_run:
            meta = {"alias": "candidate-%d" % i, "outcome": "", "reason": "", "extras": []}
        else:
            meta = prompt_project_meta(proj, i, taken)
        taken.add(meta["alias"])
        metas.append(meta)

    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    home = Path.home()
    redactor = Redactor(home, [u for u in (user, home.name) if u], names)

    try:
        stage = Path(tempfile.mkdtemp(prefix="aif-collect-"))
    except OSError as e:
        raise UserError("Could not create a temporary folder (%s). Check free disk space." % e)
    try:
        print("\nCollecting and redacting (this can take a minute)...")
        stager = Stager(redactor, claude_dir, args.no_git)
        reports = [stager.stage_project(p, m, stage) for p, m in zip(selected, metas)]
        versions = {v for p in selected for v in p["versions"]}
        write_meta_files(stage, metas, reports, args, versions, redactor)

        if args.dry_run:
            print("\nFiles that would be in the zip:")
            for p in staged_files(stage):
                print("  " + p.relative_to(stage).as_posix())
            show_review(reports)
            return 0

        show_review(reports)
        while True:
            ans = ask("\nCreate the zip? [y = yes, o = open the staging folder to inspect, anything else = cancel]: ")
            ans = ans.strip().lower()
            if ans == "o":
                open_folder(stage)
            elif ans == "y":
                break
            else:
                print("Cancelled. Nothing was written.")
                return 0
        zip_path = make_zip(stage, Path(args.out).expanduser() if args.out else None)
        size = zip_path.stat().st_size
        print("\nDone: %s (%s)" % (zip_path, human(size)))
        if size > WARN_ZIP_BYTES:
            print("Warning: this is over %s; it may be too large to email. Try --since or fewer projects." % human(WARN_ZIP_BYTES))
        print("Nothing was sent anywhere. Please send this file yourself.")
        open_folder(zip_path.parent)
        return 0
    finally:
        shutil.rmtree(str(stage), ignore_errors=True)


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    args = parse_args(argv)
    try:
        return run(args)
    except UserError as e:
        print(str(e))
        return 1
    except KeyboardInterrupt:
        print("\nCancelled. Nothing was written.")
        return 130
    except OSError as e:
        print("\nFile system error: %s\nCheck free disk space and permissions, then try again." % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
