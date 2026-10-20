import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import aif_collect as aif  # noqa: E402

FAKE_KEY = "sk-ant-FAKEKEY1234567890abcdefghij"
FAKE_USER = "fakeuser"


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
    subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def hash_tree(root):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(root).rglob("*")) if p.is_file()}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(str(self.tmp), ignore_errors=True))
        self.home = self.tmp / "home" / FAKE_USER
        self.claude = self.home / ".claude"
        self.proj = self.home / "work" / "exercise"
        (self.home / "Desktop").mkdir(parents=True)
        self.proj.mkdir(parents=True)
        (self.proj / "app.py").write_text("print('hi')\n")
        (self.proj / ".env").write_text("SECRET=1\n")
        (self.proj / "node_modules").mkdir()
        (self.proj / "node_modules" / "x.js").write_text("x")
        (self.proj / "CLAUDE.md").write_text("be nice\n")
        git(self.proj, "init", "-q")
        git(self.proj, "add", "app.py", "CLAUDE.md")
        git(self.proj, "commit", "-qm", "one")
        (self.proj / "app.py").write_text("print('two')\n")
        git(self.proj, "commit", "-qam", "two")

        enc = self.claude / "projects" / "-home-fakeuser-work-exercise"
        (enc / "s1" / "subagents").mkdir(parents=True)
        rec = {"cwd": str(self.proj), "sessionId": "s1", "version": "2.0.1",
               "message": {"content": "key %s in %s/work by %s" % (FAKE_KEY, self.home, FAKE_USER)}}
        (enc / "s1.jsonl").write_text(json.dumps(rec) + "\n" + json.dumps({"x": FAKE_KEY}) + "\n")
        (enc / "s2.jsonl").write_text(json.dumps(dict(rec, sessionId="s2")) + "\n")
        (enc / "s1" / "subagents" / "agent-a.jsonl").write_text(json.dumps(dict(rec)) + "\n")
        (self.claude / "file-history" / "s1").mkdir(parents=True)
        (self.claude / "file-history" / "s1" / "snap.txt").write_text("owner %s\n" % FAKE_USER)
        (self.claude / "todos").mkdir()
        (self.claude / "todos" / "s1-agent.json").write_text(json.dumps([{"t": FAKE_KEY}]))
        (self.claude / "shell-snapshots").mkdir()
        (self.claude / "shell-snapshots" / "snap.sh").write_text("export TOKEN=1\n")

    def run_main(self, args, inputs):
        out = io.StringIO()
        with mock.patch("pathlib.Path.home", return_value=self.home), \
                mock.patch("getpass.getuser", return_value=FAKE_USER), \
                mock.patch("builtins.input", side_effect=inputs if inputs is EOFError else list(inputs)), \
                mock.patch.object(aif, "open_folder"), \
                contextlib.redirect_stdout(out):
            code = aif.main(["--claude-dir", str(self.claude)] + args)
        return code, out.getvalue()

    # answers: pick, names, alias, outcome, reason, extras(skip), consent
    FULL = ["all", "", "", "hired", "good", "", "y"]

    def zips(self):
        return sorted((self.home / "Desktop").glob("aif-export-*.zip"))


class UnitTests(unittest.TestCase):
    def test_parse_selection(self):
        self.assertEqual(aif.parse_selection("1,3,5-7", 8), [0, 2, 4, 5, 6])
        self.assertEqual(aif.parse_selection("all", 3), [0, 1, 2])
        for bad in ("0", "9", "x", "3-1", ""):
            with self.assertRaises(ValueError):
                aif.parse_selection(bad, 8)

    def test_redactor(self):
        r = aif.Redactor(Path("/home/bob"), ["bob"], ["Acme Corp"])
        out = r.redact_obj({"k bob": ["/home/bob/x", "Bearer abcdefghijklmnop1234", "at acme corp", "bobby"]})
        self.assertEqual(out, {"k <USER>": ["<USER>/x", "[REDACTED]", "at name-1", "bobby"]})

    def test_private_key_block(self):
        r = aif.Redactor(Path("/home/bob"), [], [])
        s = "a -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- b"
        self.assertEqual(r.redact_text(s), "a [REDACTED] b")

    def test_excluded(self):
        for n in (".env", ".env.local", "a.pem", "id_rsa.pub", "x.KEY"):
            self.assertTrue(aif.is_excluded_file(n), n)
        self.assertFalse(aif.is_excluded_file("environment.py"))


class InteractivePickerTests(unittest.TestCase):
    PROJECTS = [{"name": "p%d" % i, "sessions": 1, "last": 1.0, "size": 10} for i in range(3)]

    def pick(self, keys):
        it = iter(keys)
        out = io.StringIO()
        return aif.pick_interactive(self.PROJECTS, key_reader=lambda: next(it), out=out), out.getvalue()

    def names(self, keys):
        return [p["name"] for p in self.pick(keys)[0]]

    def test_toggle_and_confirm(self):
        self.assertEqual(self.names(["down", "space", "down", "space", "enter"]), ["p1", "p2"])

    def test_all_none_and_default_to_highlighted(self):
        self.assertEqual(self.names(["a", "enter"]), ["p0", "p1", "p2"])
        self.assertEqual(self.names(["a", "a", "down", "enter"]), ["p1"])
        self.assertEqual(self.names(["enter"]), ["p0"])

    def test_wraps_around(self):
        self.assertEqual(self.names(["up", "enter"]), ["p2"])

    def test_quit_and_cursor_restored(self):
        with self.assertRaises(aif.UserError):
            self.pick(["q"])
        out = io.StringIO()
        with self.assertRaises(aif.UserError):
            aif.pick_interactive(self.PROJECTS, key_reader=iter(["esc"]).__next__, out=out)
        self.assertTrue(out.getvalue().endswith("\x1b[?25h"))

    def test_typed_menu_used_when_not_a_terminal(self):
        self.assertFalse(aif.arrows_available())


class DiscoveryTests(Fixture):
    def test_cwd_from_file_not_folder_name(self):
        projects, _ = aif.discover_projects(self.claude)
        self.assertEqual(len(projects), 1)
        p = projects[0]
        self.assertEqual(p["cwd"], str(self.proj))
        self.assertEqual(p["name"], "exercise")
        self.assertEqual(p["sessions"], 2)
        self.assertEqual(len(p["files"]), 3)
        self.assertIn("s1", p["sids"])

    def test_since_filters(self):
        import datetime
        projects, _ = aif.discover_projects(self.claude, datetime.datetime(2999, 1, 1))
        self.assertEqual(projects, [])

    def test_missing_claude_dir_lists_paths(self):
        with mock.patch("pathlib.Path.home", return_value=self.tmp / "nowhere"), \
                mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(aif.UserError) as cm:
                aif.find_claude_dir()
        self.assertIn("--claude-dir", str(cm.exception))
        self.assertIn(".claude", str(cm.exception))


class EndToEnd(Fixture):
    def test_zip_is_clean_and_originals_untouched(self):
        before = hash_tree(self.home)
        code, out = self.run_main([], self.FULL)
        self.assertEqual(code, 0, out)
        self.assertEqual(hash_tree(self.home / ".claude"), {k: v for k, v in before.items() if ".claude" in k})
        after = hash_tree(self.home)
        zips = self.zips()
        self.assertEqual(len(zips), 1)
        self.assertEqual({k: v for k, v in after.items() if not k.endswith(".zip")}, before)

        with zipfile.ZipFile(str(zips[0])) as zf:
            names = zf.namelist()
            for n in names:
                if n.endswith(".bundle"):
                    continue
                data = zf.read(n).decode("utf-8", "replace")
                self.assertNotIn(FAKE_KEY, data, n)
                self.assertNotIn(FAKE_USER, data + n, n)
                self.assertNotIn(str(self.home), data, n)
                if n.endswith(".jsonl"):
                    for line in data.splitlines():
                        json.loads(line)
            joined = "\n".join(names)
            self.assertNotIn(".env", joined)
            self.assertNotIn("node_modules", joined)
            self.assertNotIn("shell-snapshots", joined)
            for needed in ("manifest.json", "README.txt", "labels.json",
                           "projects/candidate-1/code/app.py",
                           "projects/candidate-1/git.bundle", "projects/candidate-1/git-log.txt",
                           "projects/candidate-1/instructions/CLAUDE.md",
                           "projects/candidate-1/transcripts/s1/subagents/agent-a.jsonl",
                           "projects/candidate-1/session-data/file-history/s1/snap.txt"):
                self.assertIn(needed, names)
            self.assertEqual(json.loads(zf.read("labels.json"))["candidate-1"]["outcome"], "hired")

            clone = self.tmp / "clone"
            (self.tmp / "b").mkdir()
            (self.tmp / "b" / "git.bundle").write_bytes(zf.read("projects/candidate-1/git.bundle"))
            subprocess.run(["git", "clone", "-q", str(self.tmp / "b" / "git.bundle"), str(clone)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_dry_run_tree_matches_zip(self):
        code, out = self.run_main(["--dry-run"], ["all"])
        self.assertEqual(code, 0)
        self.assertEqual(self.zips(), [])
        listing = out.split("Files that would be in the zip:\n")[1].split("\n\n")[0]
        tree = {l[2:] for l in listing.splitlines()}
        # same aliases as a real run with all defaults
        self.run_main([], ["all", "", "", "", "", "", "y"])
        with zipfile.ZipFile(str(self.zips()[0])) as zf:
            self.assertEqual({n for n in zf.namelist()}, tree)

    def test_no_git(self):
        code, _ = self.run_main(["--no-git"], self.FULL)
        self.assertEqual(code, 0)
        with zipfile.ZipFile(str(self.zips()[0])) as zf:
            self.assertFalse([n for n in zf.namelist() if "git.bundle" in n or "git-log" in n])

    def test_bundle_dropped_when_history_has_secret(self):
        (self.proj / "app.py").write_text("KEY = '%s'\n" % FAKE_KEY)
        git(self.proj, "commit", "-qam", "oops")
        (self.proj / "app.py").write_text("print('clean')\n")
        git(self.proj, "commit", "-qam", "fix")
        code, out = self.run_main([], self.FULL)
        self.assertEqual(code, 0)
        self.assertIn("secret", out)
        with zipfile.ZipFile(str(self.zips()[0])) as zf:
            names = zf.namelist()
            self.assertNotIn("projects/candidate-1/git.bundle", names)
            self.assertNotIn(FAKE_KEY, zf.read("projects/candidate-1/git-log.txt").decode())

    def test_names_extras_and_cancel(self):
        extra = self.tmp / "task.md"
        extra.write_text("Task for Acme Corp\n")
        code, _ = self.run_main([], ["all", "Acme Corp", "alice", "o", "r", "'%s'" % extra, "", "y"])
        self.assertEqual(code, 0)
        with zipfile.ZipFile(str(self.zips()[0])) as zf:
            self.assertEqual(zf.read("projects/alice/extras/task.md").decode(), "Task for name-1\n")
        for z in self.zips():
            z.unlink()
        code, out = self.run_main([], ["all", "", "", "", "", "", "n"])
        self.assertEqual(code, 0)
        self.assertEqual(self.zips(), [])

    def test_missing_project_dir_and_no_git_binary(self):
        import shutil
        shutil.rmtree(str(self.proj))
        code, out = self.run_main([], self.FULL)
        self.assertEqual(code, 0, out)
        self.assertIn("no longer exists", out)

    def test_git_not_installed_falls_back_to_walk(self):
        with mock.patch("shutil.which", return_value=None):
            code, out = self.run_main([], self.FULL)
        self.assertEqual(code, 0, out)
        with zipfile.ZipFile(str(self.zips()[0])) as zf:
            names = zf.namelist()
            self.assertIn("projects/candidate-1/code/app.py", names)
            self.assertFalse([n for n in names if "node_modules" in n or ".env" in n])

    def test_unwritable_out_falls_back_to_home(self):
        blocker = self.tmp / "file"
        blocker.write_text("x")
        code, out = self.run_main(["--out", str(blocker / "sub")], self.FULL)
        self.assertEqual(code, 0, out)
        self.assertIn("home folder", out)
        self.assertEqual(len(list(self.home.glob("aif-export-*.zip"))), 1)

    def test_eof_on_input_is_a_clean_error(self):
        code, out = self.run_main([], EOFError)
        self.assertEqual(code, 1)
        self.assertIn("interactive", out)


if __name__ == "__main__":
    unittest.main()
