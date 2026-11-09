"""Catalog consistency: every lab row is well-formed and every lab has English + Turkish content."""
import json, os, re, unittest

SYS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TYPES = {"vm", "iso", "docker", "repo", "files", "local", "vulhub"}
CATS = {"web", "linux", "windows", "pwn", "crypto", "forensics", "api", "archives", "custom"}


def rows():
    out = []
    for name in ("labs.psv", "generated.psv"):
        path = os.path.join(SYS, "catalog", name)
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8").read().splitlines():
            if line.strip() and not line.startswith("#"):
                out.append(line.split("|", 7))
    return out


def learn(lang):
    d = {}
    base = os.path.join(SYS, "catalog", "learn", lang)
    for f in sorted(os.listdir(base)):
        d.update(json.load(open(os.path.join(base, f), encoding="utf-8")))
    return d


class Catalog(unittest.TestCase):
    def test_rows_are_well_formed(self):
        ids = set()
        for r in rows():
            self.assertEqual(len(r), 8, r)
            i, typ, cat, level = r[0], r[1], r[2], r[3]
            self.assertRegex(i, r"^[a-z0-9][a-z0-9-]{0,40}$")
            self.assertNotIn(i, ids, f"duplicate id {i}")
            ids.add(i)
            self.assertIn(typ, TYPES, r)
            self.assertIn(cat, CATS, r)
            self.assertIn(level, {"0", "1", "2", "3"}, r)
            self.assertTrue(r[4] and r[7], f"{i}: name/description missing")

    def test_docker_labs_have_ports_and_compose_or_script(self):
        for r in rows():
            if r[1] != "docker":
                continue
            self.assertRegex(r[6], r"port=\d+", r[0])
            d = os.path.join(SYS, "labs", r[0])
            self.assertTrue(os.path.exists(os.path.join(d, "docker-compose.yml")) or os.path.exists(os.path.join(d, "start.sh")), f"{r[0]}: no compose file or start.sh")

    def test_turkish_names_cover_every_lab(self):
        tr = json.load(open(os.path.join(SYS, "catalog", "i18n", "tr-labs.json"), encoding="utf-8"))
        missing = [r[0] for r in rows() if r[0] not in tr]
        self.assertEqual(missing, [])

    def test_learning_content_is_aligned_between_languages(self):
        en, tr = learn("en"), learn("tr")
        self.assertEqual(set(en), set(tr))
        for i in en:
            self.assertEqual(len(en[i]["learn"]), len(tr[i]["learn"]), i)
            self.assertEqual([v["id"] for v in en[i]["vulns"]], [v["id"] for v in tr[i]["vulns"]], i)
            self.assertEqual([t["id"] for t in en[i].get("tasks", [])], [t["id"] for t in tr[i].get("tasks", [])], i)

    def test_learning_content_belongs_to_known_labs(self):
        known = {r[0] for r in rows()}
        self.assertEqual(set(learn("en")) - known, set())

    def test_ui_strings_exist_in_both_languages(self):
        en = json.load(open(os.path.join(SYS, "catalog", "i18n", "en.json"), encoding="utf-8"))
        tr = json.load(open(os.path.join(SYS, "catalog", "i18n", "tr.json"), encoding="utf-8"))
        self.assertEqual(set(en), set(tr))


if __name__ == "__main__":
    unittest.main()
