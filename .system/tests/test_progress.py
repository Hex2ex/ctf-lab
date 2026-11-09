"""progress.py tests.  Run: python3 -I -m unittest discover -s .system/tests -v   (never touches real data)"""
import glob, hashlib, json, os, stat, sys, tempfile, threading, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
import progress as pg  # noqa: E402


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


LABS = """# test
vmlab|vm|linux|1|Test VM|-||A VM
webgoat|docker|web|1|Test Web|-|port=1|A web lab
multi|vm|linux|2|Multi Flag|-||A VM with three flags
winbox|vm|windows|2|Win|-||A Windows VM
"""
GENERATED = """chal-a|local|crypto|1|Challenge A|-||A challenge
"""
LEARN_EN = {
    "webgoat": {"learn": ["Learn SQLi"], "vulns": [{"id": "sql-injection", "name": "SQL Injection", "desc": "x"},
                                                   {"id": "xss-reflected", "name": "XSS (Reflected)", "desc": "y"}]},
    "multi": {"tasks": [{"id": "k1", "name": "First"}, {"id": "k2", "name": "Second"}, {"id": "k3", "name": "Third"}]},
}
LEARN_TR = {
    "webgoat": {"learn": ["SQLi öğren"], "vulns": [{"id": "sql-injection", "name": "SQL Enjeksiyonu", "desc": "x"},
                                                   {"id": "xss-reflected", "name": "XSS (Yansıyan)", "desc": "y"}]},
    "multi": {"tasks": [{"id": "k1", "name": "Birinci"}, {"id": "k2", "name": "İkinci"}, {"id": "k3", "name": "Üçüncü"}]},
}
TR_LABS = {"vmlab": {"name": "Deneme VM", "desc": "Bir VM"}}
HASHES = f"{sha('CTFLAB{right}')}  chal-a\n{sha('F1')}  multi#k1\n{sha('F2')}  multi#k2\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pg.SYS = self.tmp.name
        c = os.path.join(pg.SYS, "catalog")
        for lang, data in (("en", LEARN_EN), ("tr", LEARN_TR)):
            os.makedirs(os.path.join(c, "learn", lang))
            with open(os.path.join(c, "learn", lang, "t.json"), "w", encoding="utf-8") as f:
                json.dump(data, f)
        os.makedirs(os.path.join(c, "i18n"))
        with open(os.path.join(c, "i18n", "tr-labs.json"), "w", encoding="utf-8") as f:
            json.dump(TR_LABS, f)
        for name, content in (("labs.psv", LABS), ("generated.psv", GENERATED), ("flags.sha256", HASHES)):
            with open(os.path.join(c, name), "w", encoding="utf-8") as f:
                f.write(content)

    def tearDown(self):
        self.tmp.cleanup()

    def record(self):
        with open(os.path.join(pg.SYS, "progress.json"), encoding="utf-8") as f:
            return json.load(f)["labs"]

    def no_record(self):
        return not os.path.exists(os.path.join(pg.SYS, "progress.json"))


class Verify(Base):
    def test_right_flag_verifies_and_completes_the_lab(self):
        r = pg.submit("chal-a", "CTFLAB{right}")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["state"], "verified")
        self.assertTrue(r["lab"]["done"])
        self.assertEqual(r["lab"]["badge"], "verified")
        self.assertEqual(self.record()["chal-a"]["flag"]["state"], "verified")

    def test_wrong_flag_is_rejected_and_nothing_is_written(self):
        self.assertFalse(pg.submit("chal-a", "CTFLAB{wrong}")["ok"])
        self.assertTrue(self.no_record())

    def test_surrounding_whitespace_is_ignored(self):
        self.assertTrue(pg.submit("chal-a", "  CTFLAB{right}\n")["ok"])

    def test_case_sensitive(self):
        self.assertFalse(pg.submit("chal-a", "ctflab{right}")["ok"])

    def test_empty_and_too_long_flags(self):
        self.assertFalse(pg.submit("chal-a", "   ")["ok"])
        self.assertFalse(pg.submit("chal-a", "A" * 501)["ok"])

    def test_resubmitting_keeps_the_original_time(self):
        pg.submit("chal-a", "CTFLAB{right}")
        t = self.record()["chal-a"]["flag"]["t"]
        r = pg.submit("chal-a", "CTFLAB{right}")
        self.assertTrue(r["ok"])
        self.assertIn("already", r["message"])
        self.assertEqual(self.record()["chal-a"]["flag"]["t"], t)

    def test_the_flag_itself_is_never_stored(self):
        pg.submit("chal-a", "CTFLAB{right}")
        with open(os.path.join(pg.SYS, "progress.json"), encoding="utf-8") as f:
            self.assertNotIn("CTFLAB{right}", f.read())

    def test_multi_flag_lab_finds_the_matching_task(self):
        self.assertTrue(pg.submit("multi", "F2")["ok"])
        k = self.record()["multi"]
        self.assertEqual(k["k2"]["state"], "verified")
        self.assertNotIn("k1", k)

    def test_explicit_task_rejects_another_tasks_flag(self):
        self.assertFalse(pg.submit("multi", "F2", "k1")["ok"])

    def test_messages_follow_the_language(self):
        self.assertIn("Yanlış", pg.submit("chal-a", "x", lang="tr")["message"])
        self.assertIn("Wrong", pg.submit("chal-a", "x")["message"])


class Claim(Base):
    def test_hash_task_cannot_be_claimed(self):
        self.assertFalse(pg.done("chal-a", "flag")["ok"])
        self.assertTrue(self.no_record())

    def test_claim_tasks_mark_and_badge(self):
        pg.done("vmlab", "user", "got a shell")
        r = pg.done("vmlab", "root")
        self.assertTrue(r["ok"])
        self.assertTrue(r["lab"]["done"])
        self.assertEqual(r["lab"]["badge"], "claimed")
        self.assertEqual(self.record()["vmlab"]["user"]["note"], "got a shell")

    def test_flag_on_claim_task_is_saved_as_note(self):
        r = pg.submit("vmlab", "flag{abc}", "user")
        self.assertEqual((r["ok"], r["state"]), (True, "claimed"))
        self.assertEqual(self.record()["vmlab"]["user"]["note"], "flag{abc}")

    def test_taskless_flag_on_unverifiable_lab_is_rejected(self):
        r = pg.submit("vmlab", "flag{abc}")
        self.assertFalse(r["ok"])
        self.assertIn("ctf done", r["message"])

    def test_mixed_lab_badge_is_claimed(self):
        pg.submit("multi", "F1"); pg.submit("multi", "F2"); r = pg.done("multi", "k3")
        self.assertEqual((r["lab"]["verified"], r["lab"]["claimed"], r["lab"]["badge"]), (2, 1, "claimed"))

    def test_missing_task_does_not_complete(self):
        r = pg.done("vmlab", "user")
        self.assertFalse(r["lab"]["done"])
        self.assertIsNone(r["lab"]["badge"])

    def test_undo(self):
        pg.done("vmlab", "user")
        self.assertTrue(pg.undo("vmlab", "user")["ok"])
        self.assertNotIn("vmlab", self.record())
        self.assertFalse(pg.undo("vmlab", "user")["ok"])

    def test_verified_task_can_be_undone_and_verified_again(self):
        pg.submit("chal-a", "CTFLAB{right}")
        self.assertTrue(pg.undo("chal-a", "flag")["ok"])
        self.assertTrue(pg.submit("chal-a", "CTFLAB{right}")["ok"])


class Tasks(Base):
    def test_default_vm_tasks(self):
        d = pg.detail("vmlab")
        self.assertEqual([t["id"] for t in d["tasks"]], ["user", "root"])
        self.assertTrue(all(t["kind"] == "claim" for t in d["tasks"]))

    def test_default_windows_tasks(self):
        self.assertEqual([t["id"] for t in pg.detail("winbox")["tasks"]], ["access", "admin"])

    def test_vuln_tasks_have_stable_ids(self):
        self.assertEqual([t["id"] for t in pg.detail("webgoat")["tasks"]], ["sql-injection", "xss-reflected"])

    def test_task_ids_do_not_depend_on_the_language(self):
        en, tr = pg.detail("webgoat"), pg.detail("webgoat", "tr")
        self.assertEqual([t["id"] for t in en["tasks"]], [t["id"] for t in tr["tasks"]])
        self.assertEqual(tr["tasks"][0]["name"], "Sömür: SQL Enjeksiyonu")
        self.assertEqual(en["tasks"][0]["name"], "Exploit: SQL Injection")
        self.assertEqual(pg.detail("multi", "tr")["tasks"][1]["name"], "İkinci")

    def test_turkish_detail_uses_turkish_texts(self):
        d = pg.detail("vmlab", "tr")
        self.assertEqual((d["name"], d["level_name"], d["category_name"]), ("Deneme VM", "Başlangıç", "Linux Sunucu"))
        self.assertEqual(pg.detail("webgoat", "tr")["learn"], ["SQLi öğren"])

    def test_claim_made_in_one_language_shows_in_the_other(self):
        pg.done("webgoat", "sql-injection", lang="tr")
        self.assertEqual(pg.detail("webgoat")["tasks"][0]["state"], "claimed")

    def test_generated_challenge_has_one_hash_task(self):
        self.assertEqual([(x["id"], x["kind"]) for x in pg.detail("chal-a")["tasks"]], [("flag", "hash")])

    def test_explicit_tasks_and_kinds(self):
        self.assertEqual({x["id"]: x["kind"] for x in pg.detail("multi")["tasks"]}, {"k1": "hash", "k2": "hash", "k3": "claim"})

    def test_unknown_lab_and_bad_ids(self):
        for bad in ("nope", "../etc/passwd", "", "A", "a b"):
            self.assertIsNone(pg.detail(bad))
            self.assertFalse(pg.submit(bad, "x")["ok"])
        self.assertFalse(pg.done("vmlab", "../x")["ok"])


class Overview(Base):
    def test_overall_and_category_counters(self):
        pg.submit("chal-a", "CTFLAB{right}")
        pg.done("vmlab", "user"); pg.done("vmlab", "root")
        o = pg.overview()
        self.assertEqual(o["overall"]["labs"], 5)
        self.assertEqual((o["overall"]["done"], o["overall"]["verified"], o["overall"]["claimed"]), (2, 1, 1))
        self.assertEqual(o["categories"]["crypto"], {"labs": 1, "done": 1})
        self.assertEqual(o["categories"]["linux"], {"labs": 2, "done": 1})

    def test_search_text_covers_both_languages(self):
        s = pg.search_text()["webgoat"]
        self.assertIn("SQL Injection", s); self.assertIn("SQL Enjeksiyonu", s)


class Robustness(Base):
    def test_file_is_private(self):
        pg.done("vmlab", "user")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(pg.SYS, "progress.json")).st_mode), 0o600)

    def test_corrupt_file_is_moved_aside_not_overwritten(self):
        p = os.path.join(pg.SYS, "progress.json")
        with open(p, "w") as f:
            f.write("{corrupt")
        self.assertTrue(pg.done("vmlab", "user")["ok"])
        saved = glob.glob(p + ".corrupt-*")
        self.assertEqual(len(saved), 1)
        with open(saved[0]) as f:
            self.assertEqual(f.read(), "{corrupt")

    def test_concurrent_writes_lose_nothing(self):
        work = [lambda t=t: pg.done("webgoat", t) for t in ("sql-injection", "xss-reflected")] \
            + [lambda: pg.submit("chal-a", "CTFLAB{right}")] * 3 + [lambda: pg.done("vmlab", "user"), lambda: pg.done("vmlab", "root")]
        ts = [threading.Thread(target=w) for w in work]
        [t.start() for t in ts]; [t.join() for t in ts]
        k = self.record()
        self.assertEqual(set(k["webgoat"]), {"sql-injection", "xss-reflected"})
        self.assertEqual(set(k["vmlab"]), {"user", "root"})

    def test_no_temp_files_left(self):
        pg.done("vmlab", "user")
        self.assertEqual(glob.glob(os.path.join(pg.SYS, ".progress-*")), [])


class CommandLine(Base):
    def test_exit_codes(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pg.main(["flag", "chal-a", "CTFLAB{wrong}"]), 1)
            self.assertEqual(pg.main(["flag", "chal-a", "CTFLAB{right}"]), 0)
            self.assertEqual(pg.main(["done", "vmlab", "user", "a", "note"]), 0)
            self.assertEqual(pg.main(["info", "webgoat"]), 0)
            self.assertEqual(pg.main(["info", "nope"]), 1)
            self.assertEqual(pg.main(["progress"]), 0)
            self.assertEqual(pg.main([]), 1)
        self.assertEqual(self.record()["vmlab"]["user"]["note"], "a note")


if __name__ == "__main__":
    unittest.main()
