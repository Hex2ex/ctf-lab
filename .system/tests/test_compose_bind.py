"""compose_bind.py tests: docker-mode port binding."""
import os, sys, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
import compose_bind as cb  # noqa: E402

IP = "127.0.0.1"


class Rebind(unittest.TestCase):
    def test_forms(self):
        for spec, want in (("8081:80", '"127.0.0.1:8081:80"'), ("8081:80/tcp", '"127.0.0.1:8081:80/tcp"'),
                           ("80", '"127.0.0.1::80"'), ("0.0.0.0:8081:80", '"127.0.0.1:8081:80"'),
                           ("[::]:8081:80", '"127.0.0.1:8081:80"'), ("8000-8010:80", '"127.0.0.1:8000-8010:80"'),
                           ("5353:53/udp", '"127.0.0.1:5353:53/udp"')):
            self.assertEqual(cb.rebind(spec, IP), want, spec)

    def test_variables_are_left_alone(self):
        self.assertIsNone(cb.rebind("${LISTEN_IP:-127.0.0.1}:8888:80", IP))
        self.assertIsNone(cb.rebind("${PORT}:80", IP))


class Text(unittest.TestCase):
    def test_compose_file(self):
        src = """services:
  web:
    image: x
    ports:
      - "8081:80"   # http
      - 8443:443
    environment:
      - A=1
  db:
    image: y
    ports:
    - "0.0.0.0:3306:3306"
    expose:
      - "3306"
"""
        out, n = cb.bind_ports(src, IP)
        self.assertEqual(n, 3)
        self.assertIn('- "127.0.0.1:8081:80"   # http', out)
        self.assertIn('- "127.0.0.1:8443:443"', out)
        self.assertIn('- "127.0.0.1:3306:3306"', out)
        self.assertIn("- A=1", out)            # not under ports:
        self.assertIn('- "3306"', out)         # expose: is not touched

    def test_idempotent(self):
        once, _ = cb.bind_ports('ports:\n  - "8081:80"\n', IP)
        twice, _ = cb.bind_ports(once, IP)
        self.assertEqual(once, twice)

    def test_inline_list(self):
        out, n = cb.bind_ports('services:\n  a:\n    ports: ["8088:8000", 9000:90]  # x\n    restart: "no"\n', IP)
        self.assertEqual(n, 2)
        self.assertIn('ports: ["127.0.0.1:8088:8000", "127.0.0.1:9000:90"]  # x', out)
        self.assertIn('restart: "no"', out)

    def test_long_syntax_is_untouched(self):
        src = "ports:\n  - target: 80\n    published: 8080\n"
        self.assertEqual(cb.bind_ports(src, IP), (src, 0))


if __name__ == "__main__":
    unittest.main()
