#!/usr/bin/env python3
"""Rewrite the published ports of docker-compose files so that they bind to ONE address.

Used in 'docker mode' (web labs run on the host's Docker instead of the targets VM): vulnerable apps must
never listen on 0.0.0.0, so every `ports:` entry becomes `<ip>:<host>:<container>`.

    compose_bind.py <ip> <compose-file>...

Handled (block and inline `[...]` lists): "8081:80", 8081:80/tcp, "80" (random host port), "0.0.0.0:8081:80", "[::]:8081:80".
Left alone: entries with ${VARS} and the long `target:/published:` syntax; `ctf` double-checks the running
containers afterwards (docker_exposure_check) and stops any lab that is still reachable on all interfaces.
"""
import re, sys

KEY = re.compile(r"^(\s*)ports\s*:\s*(#.*)?$")
INLINE = re.compile(r"^(\s*ports\s*:\s*)\[(.*)\](\s*(#.*)?)$")   # ports: ["8088:8000", 9000]
ITEM = re.compile(r"""^(\s*)-\s*(["']?)([^"'#\s]+)\2(\s*(#.*)?)$""")


def rebind(spec, ip):
    if "$" in spec or "{" in spec:
        return None
    proto = ""
    if "/" in spec:
        spec, proto = spec.rsplit("/", 1)
        proto = "/" + proto
    if spec.startswith("["):  # [::1]:8081:80
        end = spec.find("]")
        if end < 0 or spec[end + 1:end + 2] != ":":
            return None
        parts = spec[end + 2:].split(":")
    else:
        parts = spec.split(":")
        if len(parts) == 3:
            parts = parts[1:]
        elif len(parts) == 1:
            parts = ["", parts[0]]
    if len(parts) != 2 or not parts[1]:
        return None
    return f'"{ip}:{parts[0]}:{parts[1]}{proto}"'


def bind_ports(text, ip):
    out, in_ports, base, changed = [], False, 0, 0
    for line in text.split("\n"):
        im = INLINE.match(line)
        if im:
            items = []
            for raw in im.group(2).split(","):
                spec = raw.strip().strip("\"'")
                new = rebind(spec, ip) if spec else None
                changed += bool(new)
                items.append(new or raw.strip())
            out.append(f"{im.group(1)}[{', '.join(items)}]{im.group(3)}")
            continue
        k = KEY.match(line)
        if k:
            in_ports, base = True, len(k.group(1))
            out.append(line)
            continue
        if in_ports:
            if not line.strip() or line.lstrip().startswith("#"):
                out.append(line)
                continue
            indent = len(line) - len(line.lstrip())
            if not line.lstrip().startswith("-") or indent < base:
                in_ports = False
            else:
                m = ITEM.match(line)
                new = rebind(m.group(3), ip) if m else None
                if new:
                    line = f"{m.group(1)}- {new}{m.group(4)}"
                    changed += 1
        out.append(line)
    return "\n".join(out), changed


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    ip, total = argv[0], 0
    for path in argv[1:]:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        new, n = bind_ports(text, ip)
        if new != text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
        total += n
    print(f"{total} port mapping(s) bound to {ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
