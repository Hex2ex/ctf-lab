"""Panel HTTP tests: a real server on a free port with temporary data (never touches the running panel or real progress)."""
import http.client, importlib.util, json, os, tempfile, threading, unittest
from http.server import ThreadingHTTPServer

from test_progress import Base, pg

PANEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "panel.py")
spec = importlib.util.spec_from_file_location("panel", PANEL)
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)
SECRET = "S3cretS3cretS3cretS3cret"


class PanelTest(Base):
    def setUp(self):
        super().setUp()
        self.root = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self.root.name, "05-crypto", "1-easy", "chal-a"))
        with open(os.path.join(self.root.name, "05-crypto", "1-easy", "chal-a", "message.txt"), "w") as f:
            f.write("hello")
        with open(os.path.join(self.root.name, "secret.txt"), "w") as f:
            f.write("outside")
        panel.ROOT = self.root.name
        panel.REMOTE = os.path.join(pg.SYS, "remote"); os.makedirs(panel.REMOTE)
        panel.status = lambda: {"kali": {"state": "shut off", "ip": ""}, "targets": {"state": "shut off", "ip": ""},
                                "labs": [{"id": "vmlab", "name": "Test VM", "desc": "A VM", "category": "linux", "level": 1, "type": "vm", "state": "stopped", "port": "", "dir": ""}]}
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
        panel.PORT = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); self.root.cleanup()
        super().tearDown()

    def enable_remote(self):
        with open(os.path.join(panel.REMOTE, "remote.env"), "w") as f:
            f.write(f"CTF_PASS_HASH='$2a$x'\nCTF_PROXY_SECRET='{SECRET}'\n")
        open(os.path.join(panel.REMOTE, "enabled"), "w").close()

    def req(self, method, path, body=None, token=True, host=None, raw=None, headers=None, full=False):
        c = http.client.HTTPConnection("127.0.0.1", panel.PORT, timeout=5)
        h = {"Host": host or f"127.0.0.1:{panel.PORT}", "Content-Type": "application/json"}
        if token:
            h["X-Token"] = panel.TOKEN
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body) if body is not None else None)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse(); b = r.read().decode("utf-8", "replace"); c.close()
        if full:
            return r
        try:
            return r.status, json.loads(b)
        except ValueError:
            return r.status, b


class Access(PanelTest):
    def test_home_page_embeds_progress_and_both_languages(self):
        code, s = self.req("GET", "/", token=False)
        self.assertEqual(code, 200)
        self.assertIn('"overall"', s)
        self.assertIn("Bu labda neler öğreneceksin", s)
        self.assertIn("What you will learn", s)

    def test_wrong_host_is_rejected(self):
        self.assertEqual(self.req("GET", "/", token=False, host="evil.example")[0], 403)
        self.assertEqual(self.req("GET", "/api/status", host="evil.example")[0], 403)

    def test_api_without_token_is_rejected(self):
        for m, p, b in (("GET", "/api/status", None), ("GET", "/api/detail/chal-a", None), ("GET", "/api/search", None),
                        ("POST", "/api/flag", {"lab": "chal-a", "flag": "x"})):
            self.assertEqual(self.req(m, p, b, token=False)[0], 403, p)
        self.assertTrue(self.no_record())

    def test_proxy_header_is_useless_while_remote_access_is_off(self):
        code, s = self.req("GET", "/", token=False, host="evil.example", headers={"X-CTF-Proxy": SECRET})
        self.assertEqual(code, 403)

    def test_proxied_page_gets_the_token_and_wrong_secret_does_not(self):
        self.enable_remote()
        code, s = self.req("GET", "/", token=False, host="lab.example", headers={"X-CTF-Proxy": SECRET})
        self.assertEqual(code, 200)
        self.assertIn(json.dumps(panel.TOKEN), s)
        self.assertEqual(self.req("GET", "/", token=False, host="lab.example", headers={"X-CTF-Proxy": "nope" * 6})[0], 403)

    def test_proxied_api_still_needs_the_token(self):
        self.enable_remote()
        self.assertEqual(self.req("GET", "/api/status", token=False, host="lab.example", headers={"X-CTF-Proxy": SECRET})[0], 403)
        self.assertEqual(self.req("GET", "/api/status", host="lab.example", headers={"X-CTF-Proxy": SECRET})[0], 200)


class Files(PanelTest):
    def cookie(self):
        r = self.req("GET", f"/?t={panel.TOKEN}", token=False, full=True)
        return r.getheader("Set-Cookie").split(";")[0]

    def test_files_need_the_panel_cookie(self):
        self.assertEqual(self.req("GET", "/files/05-crypto/", token=False)[0], 403)
        self.assertNotIn("Set-Cookie", dict(self.req("GET", "/", token=False, full=True).getheaders()))

    def test_listing_and_download(self):
        c = {"Cookie": self.cookie()}
        code, s = self.req("GET", "/files/05-crypto/1-easy/chal-a/", token=False, headers=c)
        self.assertEqual(code, 200); self.assertIn("message.txt", s)
        self.assertEqual(self.req("GET", "/files/05-crypto/1-easy/chal-a/message.txt", token=False, headers=c), (200, "hello"))

    def test_traversal_is_blocked(self):
        c = {"Cookie": self.cookie()}
        for p in ("/files/../secret.txt", "/files/05-crypto/../secret.txt", "/files/05-crypto/%2e%2e/secret.txt", "/files/.system/x", "/files/secret.txt"):
            self.assertEqual(self.req("GET", p, token=False, headers=c)[0], 404, p)

    def test_symlink_out_of_the_tree_is_blocked(self):
        os.symlink(os.path.join(self.root.name, "secret.txt"), os.path.join(self.root.name, "05-crypto", "link.txt"))
        self.assertEqual(self.req("GET", "/files/05-crypto/link.txt", token=False, headers={"Cookie": self.cookie()})[0], 404)


class Progress(PanelTest):
    def test_status_contains_progress_and_turkish_names(self):
        code, v = self.req("GET", "/api/status")
        self.assertEqual((code, v["progress"]["overall"]["labs"]), (200, 5))
        self.assertEqual(self.req("GET", "/api/status?lang=tr")[1]["labs"][0]["name"], "Deneme VM")

    def test_detail_in_both_languages(self):
        code, v = self.req("GET", "/api/detail/webgoat")
        self.assertEqual((code, v["learn"], len(v["tasks"])), (200, ["Learn SQLi"], 2))
        self.assertEqual(self.req("GET", "/api/detail/webgoat?lang=tr")[1]["learn"], ["SQLi öğren"])
        self.assertEqual(self.req("GET", "/api/detail/nope")[0], 404)
        self.assertEqual(self.req("GET", "/api/detail/..%2Fetc")[0], 404)

    def test_wrong_and_right_flag(self):
        code, r = self.req("POST", "/api/flag", {"lab": "chal-a", "flag": "CTFLAB{wrong}", "lang": "tr"})
        self.assertEqual((code, r["ok"]), (200, False)); self.assertIn("Yanlış", r["message"])
        code, r = self.req("POST", "/api/flag", {"lab": "chal-a", "flag": "CTFLAB{right}"})
        self.assertEqual((code, r["ok"], r["lab"]["done"]), (200, True, True))
        self.assertEqual(self.req("GET", "/api/status")[1]["progress"]["labs"]["chal-a"]["badge"], "verified")

    def test_done_and_undo(self):
        self.assertTrue(self.req("POST", "/api/done", {"lab": "vmlab", "task": "user", "note": "shell"})[1]["ok"])
        self.assertEqual(self.req("GET", "/api/detail/vmlab")[1]["tasks"][0]["note"], "shell")
        self.assertTrue(self.req("POST", "/api/undo", {"lab": "vmlab", "task": "user"})[1]["ok"])
        self.assertIsNone(self.req("GET", "/api/detail/vmlab")[1]["tasks"][0]["state"])


class BadInput(PanelTest):
    def test_invalid_fields(self):
        for p, b in (("/api/flag", {"lab": "../x", "flag": "a"}), ("/api/flag", {"lab": 5, "flag": "a"}),
                     ("/api/flag", {"lab": "chal-a", "flag": 5}), ("/api/flag", {"flag": "a"}),
                     ("/api/flag", {"lab": "chal-a", "task": "../x", "flag": "a"}),
                     ("/api/done", {"lab": "vmlab"}), ("/api/undo", {"lab": "vmlab", "task": ["user"]}),
                     ("/api/action", {"action": "vpn-add", "id": "../../x"}), ("/api/action", {"action": "start", "id": "a;b"}),
                     ("/api/action", {"action": "rm -rf", "id": "x"})):
            self.assertEqual(self.req("POST", p, b)[0], 400, (p, b))
        self.assertTrue(self.no_record())

    def test_bad_and_huge_bodies(self):
        self.assertEqual(self.req("POST", "/api/flag", raw="{bad")[0], 400)
        self.assertEqual(self.req("POST", "/api/flag", raw="[1,2]")[0], 400)
        self.assertEqual(self.req("POST", "/api/flag", raw=json.dumps({"lab": "chal-a", "flag": "A" * 20000}))[0], 413)

    def test_vpn_config_needs_token_and_valid_name(self):
        os.makedirs(os.path.join(panel.REMOTE, "wg"))
        with open(os.path.join(panel.REMOTE, "wg", "laptop.conf"), "w") as f:
            f.write("[Interface]\n")
        self.assertEqual(self.req("GET", "/api/vpn/laptop.conf", token=False)[0], 403)
        self.assertEqual(self.req("GET", "/api/vpn/laptop.conf")[0], 200)
        self.assertEqual(self.req("GET", "/api/vpn/..%2Fx.conf")[0], 404)


class PageScript(unittest.TestCase):
    def test_no_global_declaration_collides_with_a_window_property(self):
        """`function top(){}` made the whole script fail in real browsers (window.top is not redefinable)."""
        import re
        js = panel.PAGE
        declared = set(re.findall(r"(?:^|[;}\n])\s*(?:function|let|const|var)\s+([A-Za-z_$][\w$]*)", js))
        reserved = {"top", "name", "status", "open", "close", "focus", "print", "stop", "length", "parent", "self", "event", "history",
                    "location", "screen", "origin", "find", "blur", "scroll", "external", "frames", "opener", "closed", "menubar", "toolbar"}
        self.assertEqual(declared & reserved, set())


if __name__ == "__main__":
    unittest.main()
