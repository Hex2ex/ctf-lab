#!/usr/bin/env python3
"""Generates crypto / forensics / misc / reverse+pwn challenges from easy to hard (deterministic, pure Python).
Challenges go to the category folders, solutions to .system/solutions/.
Flags are stored only as SHA256 hashes: verify with `ctf flag <id> <flag>`.
Each challenge folder gets CHALLENGE.md (English) and README.tr.md (Turkish)."""
import base64, hashlib, hmac, json, math, os, random, shutil, struct, subprocess, tempfile, time, wave, zlib
from math import gcd

SYS = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
ROOT = os.path.dirname(SYS)
CAT = {"crypto": "05-crypto", "forensics": "06-forensics", "pwn": "04-pwn-rev"}
LEVEL = {1: "1-easy", 2: "2-medium", 3: "3-hard"}
LEVEL_TR = {1: "Başlangıç", 2: "Orta", 3: "İleri"}
CATALOG, HASHES = [], {}
rnd = random.Random(1337)


def run_cmd(cmd, **kw):
    """subprocess.run that reports a missing optional tool (qrencode, ImageMagick) as exit code 127 instead of raising."""
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, b"", b"")


def write(id_, cat, level, name, question, files, solution, flag, short, tr=None):
    """tr = (name, question) in Turkish, for README.tr.md and the panel."""
    d = os.path.join(ROOT, CAT[cat], LEVEL[level], id_)
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    for n, b in files.items():
        p = os.path.join(d, n); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(b if isinstance(b, bytes) else b.encode())
        if n.endswith(".sh"): os.chmod(p, 0o755)
    where = f"~/CTF/{cat}/{LEVEL[level]}/{id_}"
    with open(os.path.join(d, "CHALLENGE.md"), "w", encoding="utf-8") as f:
        f.write(f"# {name}\n\n| | |\n|---|---|\n| Category | {CAT[cat]} |\n| Level | {LEVEL[level]} |\n| Flag format | `CTFLAB{{...}}` |\n\n{question.strip()}\n\n"
                f"---\nVerify the flag: `ctf flag {id_} 'CTFLAB{{...}}'` (or in the panel)  ·  Work in Kali: `{where}` (`ctf sync`)\n")
    if tr:
        with open(os.path.join(d, "README.tr.md"), "w", encoding="utf-8") as f:
            f.write(f"# {tr[0]}\n\n| | |\n|---|---|\n| Kategori | {CAT[cat]} |\n| Seviye | {LEVEL_TR[level]} |\n| Bayrak biçimi | `CTFLAB{{...}}` |\n\n{tr[1].strip()}\n\n"
                    f"---\nBayrağı doğrula: `ctf flag {id_} 'CTFLAB{{...}}'` (ya da panelden)  ·  Kali'de çalışma yeri: `{where}` (`ctf sync`)\n")
    os.makedirs(os.path.join(SYS, "solutions"), exist_ok=True)
    with open(os.path.join(SYS, "solutions", f"{id_}.md"), "w", encoding="utf-8") as f:
        f.write(f"# Solution: {name}\n\nFlag: `{flag}`\n\n{solution.strip()}\n")
    CATALOG.append(f"{id_}|local|{cat}|{level}|{name}|-||{short}")
    HASHES[id_] = hashlib.sha256(flag.encode()).hexdigest()


# ---------- RSA helpers ----------
def is_prime(n, k=30):
    if n < 2: return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0: return n == p
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(k):
        a = rnd.randrange(2, n - 2); x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True
def next_prime(n):
    n |= 1
    while not is_prime(n): n += 2
    return n
def gen_prime(bits): return next_prime(rnd.getrandbits(bits) | (1 << (bits - 1)) | 1)
def iroot(n, k):
    lo, hi = 0, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        m = (lo + hi) // 2
        if m ** k < n: lo = m + 1
        else: hi = m
    return lo if lo ** k == n else lo - 1 if (lo - 1) ** k <= n else lo
def b2i(b): return int.from_bytes(b, "big")
def rsa_file(**kw): return "\n".join(f"{k} = {v}" for k, v in kw.items()) + "\n"

# ---------- PNG helpers (no PIL) ----------
def png(w, h, pixel, text=None, extra=b""):
    def chunk(t, d): c = struct.pack(">I", len(d)) + t + d; return c + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    raw = b"".join(b"\x00" + bytes(c for x in range(w) for c in pixel(x, y)) for y in range(h))
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    for k, v in (text or {}).items(): out += chunk(b"tEXt", k.encode() + b"\x00" + v.encode())
    return out + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"") + extra
def gradient(x, y): return ((x * 255) // 300, (y * 255) // 200, ((x + y) * 255) // 500)


def crypto():
    # 1) Caesar
    f = "CTFLAB{caesar_is_older_than_you_think}"; k = 7
    plain = f"Records say Caesar used this more than 2000 years ago. Secret message: {f} Good luck!"
    enc = "".join(chr((ord(c) - (65 if c.isupper() else 97) + k) % 26 + (65 if c.isupper() else 97)) if c.isalpha() else c for c in plain)
    write("crypto-caesar", "crypto", 1, "Caesar Cipher", "You have an encrypted message. The letters look shifted...\n\nFile: `message.txt`", {"message.txt": enc + "\n"},
          "Letters are shifted by 7 (ROT7). Try all 25 shifts (CyberChef 'ROT13' with amount=19, or `tr`). The flag starts with `CTFLAB{`.", f,
          "A classic shift cipher. Trying every shift is enough.",
          ("Sezar Şifresi", "Elinde şifrelenmiş bir mesaj var. Yazılar kaydırılmış gibi duruyor...\n\nDosya: `message.txt`"))
    # 2) Base chain
    f = "CTFLAB{encoding_is_not_encryption}"
    v = base64.b64encode(base64.b16encode(base64.b64encode(f.encode()))).decode()
    write("crypto-base-chain", "crypto", 1, "Encoding Chain", "Someone encoded the flag several times. Unwind all of it.\n\nFile: `data.txt`", {"data.txt": v + "\n"},
          "In order: Base64 → Base16 (hex) → Base64. `base64 -d | xxd -r -p | base64 -d`, or CyberChef 'Magic'.", f, "Peeling Base64/hex layers.",
          ("Kodlama Zinciri", "Biri bayrağı birkaç kez kodlamış. Hepsini geri sar.\n\nDosya: `data.txt`"))
    # 3) single-byte XOR
    f = "CTFLAB{xor_in_its_simplest_form}"; k = 0x37
    write("crypto-xor-1byte", "crypto", 1, "Single-Byte XOR", "Every byte was XORed with the same key. The key is one byte (0-255).\n\nFile: `cipher.hex`",
          {"cipher.hex": bytes(c ^ k for c in f.encode()).hex() + "\n"}, "Try all 256 keys; the output must start with `CTFLAB{`. The key is 0x37.", f,
          "First step with XOR: brute force + known prefix.",
          ("Tek Baytlık XOR", "Her bayt aynı anahtarla XOR'lanmış. Anahtar bir bayt (0-255).\n\nDosya: `cipher.hex`"))
    # 4) Vigenere
    f = "CTFLAB{vigenere_key_length_matters}"; key = "LABYRINTH"
    plain = f"The Vigenere cipher was long thought unbreakable. Here is the flag: {f} Author's note: once you know the key length, the rest is frequency analysis."
    out, i = [], 0
    for c in plain:
        if c.isalpha():
            a = 65 if c.isupper() else 97; s = ord(key[i % len(key)]) - 65; out.append(chr((ord(c) - a + s) % 26 + a)); i += 1
        else: out.append(c)
    write("crypto-vigenere", "crypto", 1, "Vigenère", "A cipher whose key is a word. Hint: the flag starts with `CTFLAB`, so you have some known plaintext.\n\nFile: `cipher.txt`", {"cipher.txt": "".join(out) + "\n"},
          "Lining up the known plaintext (`CTFLAB`) with its ciphertext reveals part of the key there; since the key repeats, the word appears (LABYRINTH). dcode.fr 'Vigenère' (known plaintext) or by hand.", f,
          "Known-plaintext attack.",
          ("Vigenère", "Anahtarı kelime olan bir şifre. İpucu: bayrak `CTFLAB` ile başlıyor, yani bildiğin düz metin var.\n\nDosya: `cipher.txt`"))
    # 5) Hash cracking
    words = ("iloveyou", "sunshine", "princess"); f = "CTFLAB{" + "_".join(words) + "}"
    h = f"{hashlib.md5(words[0].encode()).hexdigest()}\n{hashlib.sha1(words[1].encode()).hexdigest()}\n{hashlib.sha256(words[2].encode()).hexdigest()}\n"
    write("crypto-hash-crack", "crypto", 1, "Hash Cracking", "`hashes.txt` holds three different hashes (MD5, SHA1, SHA256), all weak passwords. Flag = `CTFLAB{password1_password2_password3}` (in file order).\n\nHint: `hashid`, `john --format=...`, `hashcat -m 0/100/1400`, `/usr/share/wordlists/rockyou.txt`.",
          {"hashes.txt": h}, "Identify the types with `hashid`, then `john --wordlist=rockyou.txt --format=raw-md5 ...` (raw-sha1, raw-sha256).", f,
          "Dictionary attack with John/hashcat.",
          ("Hash Kırma", "`hashes.txt` içinde üç farklı hash (MD5, SHA1, SHA256) var; hepsi zayıf parola. Bayrak = `CTFLAB{parola1_parola2_parola3}` (dosyadaki sırayla).\n\nİpucu: `hashid`, `john --format=...`, `hashcat -m 0/100/1400`, `/usr/share/wordlists/rockyou.txt`."))
    # 6) small e
    f = "CTFLAB{small_e_and_no_padding_is_bad}"; m = b2i(f.encode()); p, q = gen_prime(512), gen_prime(512); n = p * q
    c = pow(m, 3, n); assert m ** 3 < n and iroot(c, 3) == m
    write("crypto-rsa-small-e", "crypto", 2, "RSA — Small e", "e = 3 and the message was encrypted without padding. A big modulus does not always mean safe.\n\nFile: `rsa.txt`", {"rsa.txt": rsa_file(n=n, e=3, c=c)},
          "Because m³ < n, the modulus never applies: c = m³. Take the integer cube root (`gmpy2.iroot(c,3)`) and convert to bytes.", f, "Decrypting by taking the root when m^e < n.",
          ("RSA — Küçük e", "e = 3 ve mesaj dolgusuz şifrelenmiş. Modülün büyük olması her zaman güvenli demek değil.\n\nDosya: `rsa.txt`"))
    # 7) Fermat
    f = "CTFLAB{close_primes_invite_fermat}"; p = gen_prime(512); q = next_prime(p + rnd.getrandbits(20) + 2); n = p * q; e = 65537
    c = pow(b2i(f.encode()), e, n)
    def fermat(n):
        a = iroot(n, 2) + 1
        while True:
            b2 = a * a - n; bb = iroot(b2, 2)
            if bb * bb == b2: return a - bb, a + bb
            a += 1
    assert set(fermat(n)) == {p, q}
    write("crypto-rsa-fermat", "crypto", 2, "RSA — Close Primes", "Whoever picked p and q for this RSA key was careless.\n\nFile: `rsa.txt`", {"rsa.txt": rsa_file(n=n, e=e, c=c)},
          "p and q are very close → Fermat factorisation: start at a = ⌈√n⌉ and increase a until a²−n is a perfect square; p=a−b, q=a+b. Then d = e⁻¹ mod φ, m = c^d mod n. (`RsaCtfTool --attack fermat` also works.)", f,
          "Fermat factorisation attack.",
          ("RSA — Yakın Asallar", "Bu RSA'da p ve q seçilirken özensiz davranılmış.\n\nDosya: `rsa.txt`"))
    # 8) multi-byte XOR
    f = "CTFLAB{repeating_keys_repeat_mistakes}"; key = b"cipher"
    text = ("Repeating-key XOR is a slightly more advanced version of single-byte XOR. If the key is short and the text is long, "
            "the Hamming distance or the index of coincidence reveals the key length; then every column becomes a separate single-byte XOR problem. "
            "Hidden flag: " + f + " Reminder: in the real world the key must be longer than the message and used only once.")
    write("crypto-xor-multibyte", "crypto", 2, "Repeating-Key XOR", "The key is short but longer than one byte. The text is English and long.\n\nFile: `cipher.hex`",
          {"cipher.hex": bytes(c ^ key[i % len(key)] for i, c in enumerate(text.encode())).hex() + "\n"},
          "Hamming/IC analysis for the key length (`xortool -l ... -c 20`). The known prefix `CTFLAB{` also helps. Key: `cipher`.", f,
          "Finding the key length + per-column frequency analysis.",
          ("Tekrarlayan Anahtarlı XOR", "Anahtar kısa ama birden fazla bayt. Metin İngilizce ve uzun.\n\nDosya: `cipher.hex`"))
    # 9) two-time pad
    m1 = ("The flag is at the end of this message: " + (f := "CTFLAB{never_reuse_a_pad}")).encode()
    m2 = b"Meeting at three o'clock, do not forget the documents, we will talk later."
    n_ = max(len(m1), len(m2)); m1, m2 = m1.ljust(n_), m2.ljust(n_); key = bytes(rnd.getrandbits(8) for _ in range(n_))
    c1, c2 = bytes(x ^ y for x, y in zip(m1, key)), bytes(x ^ y for x, y in zip(m2, key))
    write("crypto-two-time-pad", "crypto", 2, "Two-Time Pad", "A one-time pad is unbreakable in theory... until you use the same key twice.\n\nFile: `cipher.txt` (two messages, hex)",
          {"cipher.txt": f"message1 = {c1.hex()}\nmessage2 = {c2.hex()}\n"},
          "c1 ⊕ c2 = m1 ⊕ m2 (the key cancels out). Try guessed words (' the ', ' flag ', 'Meeting') at every offset (crib dragging).", f,
          "Reusing the same key twice (crib dragging).",
          ("İki Kez Kullanılan Anahtar", "Tek kullanımlık ped teorik olarak kırılamaz... ta ki aynı anahtarı iki kez kullanana kadar.\n\nDosya: `cipher.txt` (iki mesaj, hex)"))
    # 10) Wiener
    f = "CTFLAB{small_d_falls_to_wiener}"
    while True:
        p = gen_prime(512); q = gen_prime(512)
        if p == q: continue
        n = p * q; phi = (p - 1) * (q - 1); d = rnd.getrandbits(230) | (1 << 229) | 1
        if gcd(d, phi) == 1 and (q < p < 2 * q or p < q < 2 * p): break
    e = pow(d, -1, phi); c = pow(b2i(f.encode()), e, n)
    def wiener(e, n):
        fr, num, den = [], e, n
        while den: q_ = num // den; fr.append(q_); num, den = den, num - q_ * den
        h_2, h_1, k_2, k_1 = 0, 1, 1, 0
        for t in fr:  # convergents kk/dd: e/n ≈ k/d
            kk, dd = t * h_1 + h_2, t * k_1 + k_2; h_2, h_1, k_2, k_1 = h_1, kk, k_1, dd
            if kk == 0 or (e * dd - 1) % kk: continue
            s_ = n - (e * dd - 1) // kk + 1; disc = s_ * s_ - 4 * n
            if disc >= 0:
                r = iroot(disc, 2)
                if r * r == disc and (s_ + r) % 2 == 0: return dd
    assert wiener(e, n) == d
    write("crypto-rsa-wiener", "crypto", 3, "RSA — Small Private Exponent", "The private exponent `d` was made small for fast decryption. And e is unusually large...\n\nFile: `rsa.txt`", {"rsa.txt": rsa_file(n=n, e=e, c=c)},
          "e is large (about the size of n) → d may be small. Wiener's attack: find d among the continued-fraction convergents of e/n (d < n^¼/3). `RsaCtfTool --attack wiener`.", f,
          "Wiener's attack (continued fractions).",
          ("RSA — Küçük Özel Üs", "Hızlı şifre çözme uğruna özel üs `d` küçük seçilmiş. e ise alışılmadık derecede büyük...\n\nDosya: `rsa.txt`"))
    # 11) Hastad
    f = "CTFLAB{hastad_three_keys_one_message}"; m = b2i(b"Secret message: " + f.encode() + b" -- extra padding text makes it longer --")
    ns, cs = [], []
    while len(ns) < 3:
        p, q = gen_prime(512), gen_prime(512)
        if p != q and gcd(3, (p - 1) * (q - 1)) == 1: ns.append(p * q); cs.append(pow(m, 3, p * q))
    assert m ** 3 > max(ns)
    N = ns[0] * ns[1] * ns[2]; x = sum(cs[i] * (N // ns[i]) * pow(N // ns[i], -1, ns[i]) for i in range(3)) % N; assert iroot(x, 3) == m
    write("crypto-rsa-hastad", "crypto", 3, "RSA — Broadcast (Håstad)", "The same message was sent to three different recipients with e = 3. The message alone is bigger than n, so the cube-root trick no longer works.\n\nFile: `rsa.txt`",
          {"rsa.txt": rsa_file(n1=ns[0], n2=ns[1], n3=ns[2], e=3, c1=cs[0], c2=cs[1], c3=cs[2])},
          "Use the Chinese Remainder Theorem to get m³ mod (n1·n2·n3); since m³ < n1·n2·n3 this is exactly m³. Take the cube root → message.", f,
          "Håstad's broadcast attack (CRT + cube root).",
          ("RSA — Yayın (Håstad)", "Aynı mesaj e = 3 ile üç farklı alıcıya gönderilmiş. Mesaj tek başına n'yi aşıyor, yani küp kökü numarası artık işe yaramaz.\n\nDosya: `rsa.txt`"))
    # JWT
    def jwt(payload, secret):
        h = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=")
        g = h({"alg": "HS256", "typ": "JWT"}) + b"." + h(payload)
        return (g + b"." + base64.urlsafe_b64encode(hmac.new(secret.encode(), g, "sha256").digest()).rstrip(b"=")).decode()
    f = "CTFLAB{jwt_secret_key_letmein}"
    write("crypto-jwt-weak-key", "crypto", 2, "JWT — Weak Key", "A web application gave a user this JWT. The signing key is weak.\n\nFlag = `CTFLAB{jwt_secret_key_<key>}`\n\nFile: `token.txt`",
          {"token.txt": jwt({"user": "guest", "role": "user"}, "letmein") + "\n"},
          "HS256 signatures crack with a wordlist: `hashcat -m 16500 token.txt rockyou.txt` or `jwt_tool <token> -C -d rockyou.txt`. Key: letmein.", f,
          "Cracking an HS256 JWT signing key with a wordlist.",
          ("JWT — Zayıf Anahtar", "Bir web uygulaması kullanıcıya şu JWT'yi verdi. İmza anahtarı zayıf.\n\nBayrak = `CTFLAB{jwt_secret_key_<anahtar>}`\n\nDosya: `token.txt`"))


def forensics():
    # strings
    f = "CTFLAB{strings_is_your_first_tool}"; data = bytearray(rnd.getrandbits(8) for _ in range(40000)); pos = 23517
    data[pos:pos + len(f) + 2] = b"\x00" + f.encode() + b"\x00"; data[9000:9040] = b"\x00CTFLAB{this_is_not_a_decoy_or_is_it?}\x00\x00"[:40]
    write("for-strings", "forensics", 1, "Mystery File", "What is this file? Is there anything readable in it?\n\nFile: `mystery.bin`", {"mystery.bin": bytes(data)},
          "`file mystery.bin` → data; `strings -n 8 mystery.bin | grep CTFLAB`. There may be two candidates: the right one is complete and properly closed.", f,
          "Basic inspection with `strings` / `file`.",
          ("Gizemli Dosya", "Bu dosya ne? İçinde okunabilir bir şey var mı?\n\nDosya: `mystery.bin`"))
    # exif (jpeg comment) -- if ImageMagick is available
    f = "CTFLAB{metadata_tells_the_whole_story}"
    with tempfile.TemporaryDirectory() as t:
        jp = os.path.join(t, "k.jpg")
        r = run_cmd(["convert", "-size", "640x400", "gradient:#2b5876-#4e4376", "-set", "comment", f"Camera: CTF-Cam 3000 | Note: {f}", "-quality", "90", jp], capture_output=True)
        img = open(jp, "rb").read() if r.returncode == 0 else b""
        if f.encode() not in img: img = png(300, 200, gradient, {"Comment": f"Note: {f}"})  # PNG tEXt if ImageMagick cannot write the comment
    ext = "jpg" if img[:2] == b"\xff\xd8" else "png"
    write("for-exif-comment", "forensics", 1, "The Photo's Note", f"Someone shared this picture. Nothing is visible, but the image itself may be telling you more.\n\nFile: `landscape.{ext}`",
          {f"landscape.{ext}": img}, f"`exiftool landscape.{ext}` or `identify -verbose` / `strings` → the Comment field.", f, "Image metadata (EXIF/Comment).",
          ("Fotoğrafın Notu", f"Bu resmi biri paylaşmış. Gözle görünen bir şey yok ama resmin kendisi daha fazlasını söylüyor olabilir.\n\nDosya: `landscape.{ext}`"))
    # QR
    f = "CTFLAB{qr_codes_are_easy_to_read}"
    with tempfile.TemporaryDirectory() as t:
        q = os.path.join(t, "q.png"); r = run_cmd(["qrencode", "-o", q, "-s", "10", "-m", "3", f], capture_output=True)
        qr = open(q, "rb").read() if r.returncode == 0 else None
    if qr:
        write("misc-qrcode", "forensics", 1, "QR Code", "Don't reach for your phone; decode it inside Kali.\n\nFile: `code.png`", {"code.png": qr},
              "`zbarimg code.png` (apt: zbar-tools) or CyberChef 'Parse QR Code'.", f, "Reading a QR code (zbarimg).",
              ("Karekod", "Telefonunu çıkarma; Kali'nin içinde çöz.\n\nDosya: `code.png`"))
    # zip password
    f = "CTFLAB{zip_password_was_in_the_wordlist}"
    with tempfile.TemporaryDirectory() as t:
        open(os.path.join(t, "flag.txt"), "w").write(f + "\n"); z = os.path.join(t, "secret.zip")
        subprocess.run(["7z", "a", "-tzip", "-pfootball1", "-mem=ZipCrypto", z, os.path.join(t, "flag.txt")], capture_output=True, cwd=t); zb = open(z, "rb").read()
    write("for-zip-password", "forensics", 1, "Password-Protected Zip", "You don't know the zip's password, but people are not very creative with passwords.\n\nFile: `secret.zip`", {"secret.zip": zb},
          "`zip2john secret.zip > h.txt; john --wordlist=/usr/share/wordlists/rockyou.txt h.txt` or `fcrackzip -u -D -p rockyou.txt secret.zip`. Password: football1.", f,
          "Cracking a ZIP password with a wordlist.",
          ("Parolalı Zip", "Zip'in parolasını bilmiyorsun ama insanlar parolaları pek yaratıcı seçmez.\n\nDosya: `secret.zip`"))
    # PNG LSB
    f = "CTFLAB{least_significant_bits_hide_secrets}"; bits = [int(x) for x in "".join(f"{c:08b}" for c in (struct.pack(">I", len(f)) + f.encode()))]
    W, H = 300, 200; ix = [0]
    def pix(x, y):
        r, g, bl = gradient(x, y)
        if ix[0] < len(bits): r = (r & 0xFE) | bits[ix[0]]; ix[0] += 1
        return r, g, bl
    write("for-png-lsb", "forensics", 2, "Invisible Ink", "This picture looks like an ordinary gradient... You can't see the message with your eyes.\n\nFile: `gradient.png`", {"gradient.png": png(W, H, pix)},
          "Hidden in the least significant bits of the red channel (row order). The first 32 bits are the length, then the text. `zsteg gradient.png`, StegSolve or your own script (with PIL).", f,
          "LSB steganography (zsteg / StegSolve).",
          ("Görünmeyen Mürekkep", "Bu resim sıradan bir gradyan gibi... Mesajı gözle göremezsin.\n\nDosya: `gradient.png`"))
    # png + zip
    f = "CTFLAB{check_the_end_of_the_image}"
    with tempfile.TemporaryDirectory() as t:
        open(os.path.join(t, "flag.txt"), "w").write(f + "\n"); z = os.path.join(t, "a.zip"); subprocess.run(["7z", "a", "-tzip", z, "flag.txt"], capture_output=True, cwd=t); zb = open(z, "rb").read()
    write("for-zip-in-image", "forensics", 2, "A Zip Disguised as an Image", "This is a PNG... but the file is too big for the picture.\n\nFile: `profile.png`", {"profile.png": png(120, 120, gradient, extra=zb)},
          "`binwalk profile.png` → a ZIP after the PNG; `binwalk -e`, or `unzip profile.png` / `foremost`.", f, "A file embedded in a file (binwalk / foremost).",
          ("Resim Gibi Zip", "Bu bir PNG... ama dosya boyutu resme göre fazla büyük.\n\nDosya: `profile.png`"))
    # pcap
    f = "CTFLAB{network_traffic_speaks_plaintext}"
    def csum(d):
        if len(d) % 2: d += b"\0"
        s = sum(struct.unpack(f">{len(d)//2}H", d)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16); return ~s & 0xffff
    def packet(src, dst, sp, dp, seq, ack, fl, data=b""):
        tcp = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 5 << 4, fl, 64240, 0, 0)
        ps = bytes(map(int, src.split("."))) + bytes(map(int, dst.split("."))) + struct.pack(">BBH", 0, 6, len(tcp) + len(data))
        tcp = tcp[:16] + struct.pack(">H", csum(ps + tcp + data)) + tcp[18:]
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp) + len(data), rnd.getrandbits(16), 0x4000, 64, 6, 0) + ps[:8]
        ip = ip[:10] + struct.pack(">H", csum(ip[:10] + b"\0\0" + ip[12:])) + ip[12:]
        mac = lambda s: bytes(int(x, 16) for x in s.split(":"))
        return mac("52:54:00:aa:00:01") + mac("52:54:00:aa:00:02") + b"\x08\x00" + ip + tcp + data
    pk, t0, c, s = [], 1_700_000_000.0, "10.0.0.5", "10.0.0.80"
    def flow(sp, req, res):
        nonlocal t0
        ci, si = rnd.getrandbits(31), rnd.getrandbits(31); fr = [(c, s, sp, 80, ci, 0, 0x02, b""), (s, c, 80, sp, si, ci + 1, 0x12, b""), (c, s, sp, 80, ci + 1, si + 1, 0x10, b""),
            (c, s, sp, 80, ci + 1, si + 1, 0x18, req), (s, c, 80, sp, si + 1, ci + 1 + len(req), 0x18, res), (c, s, sp, 80, ci + 1 + len(req), si + 1 + len(res), 0x11, b"")]
        for x in fr: t0 += 0.003; pk.append((t0, packet(*x)))
    http = lambda m, p, h="", body="": (f"{m} {p} HTTP/1.1\r\nHost: intranet.corp.local\r\nUser-Agent: Mozilla/5.0\r\n{h}Content-Length: {len(body)}\r\n\r\n{body}").encode()
    resp = lambda g="OK": f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(g)}\r\n\r\n{g}".encode()
    flow(50123, http("GET", "/"), resp("<h1>Intranet</h1>")); flow(50124, http("GET", "/announcements"), resp("New policy"))
    flow(50125, http("POST", "/login", "Content-Type: application/x-www-form-urlencoded\r\n", f"username=alice&password={f}&remember_me=on"), resp("Welcome alice"))
    flow(50126, http("GET", "/profile", "Cookie: session=abc123\r\n"), resp("Profile page"))
    pc = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for ts, d in pk: pc += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(d), len(d)) + d
    write("for-pcap-login", "forensics", 2, "Network Traffic", "A user's browser traffic on the internal network was captured. What did they send when they logged in?\n\nFile: `traffic.pcap` (Wireshark / tshark)",
          {"traffic.pcap": pc}, "In Wireshark filter `http.request.method == POST` → Follow TCP Stream. `tshark -r traffic.pcap -Y 'http.request.method==POST' -T fields -e urlencoded-form.value`.", f,
          "Plaintext credentials in HTTP traffic (Wireshark).",
          ("Ağ Trafiği", "İç ağda bir kullanıcının tarayıcı trafiği yakalanmış. Kullanıcı giriş yaparken ne göndermiş?\n\nDosya: `traffic.pcap` (Wireshark / tshark)"))
    # log analysis
    f = "CTFLAB{logs_are_the_attackers_footprints}"; paths = ["/", "/products", "/cart", "/about", "/contact", "/blog/post-1", "/blog/post-2", "/static/css/site.css", "/static/js/app.js", "/static/img/logo.png", "/login", "/search?q=book"]
    uas = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0", "Mozilla/5.0 (X11; Linux x86_64) Firefox/119.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6) Safari/604.1", "curl/8.4.0"]
    lines = []; tt = 1_698_300_000
    for i in range(4200):
        tt += rnd.randint(1, 9); ip = f"{rnd.choice([85,88,176,78,31,193])}.{rnd.randint(1,250)}.{rnd.randint(1,250)}.{rnd.randint(1,250)}"
        lines.append((tt, f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(tt))}] "GET {rnd.choice(paths)} HTTP/1.1" {rnd.choice([200,200,200,200,304,404])} {rnd.randint(300,52000)} "-" "{rnd.choice(uas)}"'))
    A = "203.0.113.77"; tt = 1_698_302_000
    attack = [("GET /admin HTTP/1.1", 404, "gobuster/3.6"), ("GET /login.php HTTP/1.1", 200, "gobuster/3.6"), ("GET /product.php?id=1%27 HTTP/1.1", 500, "sqlmap/1.7.11#stable (https://sqlmap.org)"),
              ("GET /product.php?id=1%20UNION%20SELECT%201,table_name,3%20FROM%20information_schema.tables-- HTTP/1.1", 200, "sqlmap/1.7.11#stable (https://sqlmap.org)"),
              ("GET /product.php?id=1%20UNION%20SELECT%201,group_concat(password),3%20FROM%20admins-- HTTP/1.1", 200, "sqlmap/1.7.11#stable (https://sqlmap.org)"),
              (f"GET /static/img/logo.png?x={base64.b64encode(f.encode()).decode()} HTTP/1.1", 200, "curl/8.4.0")]
    for req, code, ua in attack: tt += rnd.randint(20, 90); lines.append((tt, f'{A} - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(tt))}] "{req}" {code} {rnd.randint(300,9000)} "-" "{ua}"'))
    lines.sort()
    write("for-web-log", "forensics", 2, "Server Log", "A web server was hacked. Follow the attacker's trail through an access log of over 4000 lines and find the **exfiltrated data**.\n\nFile: `access.log`",
          {"access.log": "\n".join(l for _, l in lines) + "\n"}, "Cut the noise: `grep -v 'Chrome\\|Firefox\\|Safari'` → the sqlmap/gobuster IP is 203.0.113.77. Its last request (`grep 203.0.113.77 | tail`): the logo.png?x=… parameter is base64 → the flag.", f,
          "Log analysis: finding the attacker's IP and the leak.",
          ("Sunucu Günlüğü", "Bir web sunucusu hacklendi. 4000'den fazla satırlık erişim günlüğünde saldırganın izini sür ve **dışarı sızdırılan veriyi** bul.\n\nDosya: `access.log`"))
    # deleted file (ext4)
    f = "CTFLAB{deleted_files_stay_on_disk}"
    with tempfile.TemporaryDirectory() as t:
        root = os.path.join(t, "root"); os.makedirs(root)
        for n_, i_ in (("notes.txt", "Shopping list: milk, bread\n"), ("README", "This is a test disk.\n"), ("report.csv", "a,b,c\n1,2,3\n"), ("flag.txt", f + "\n")):
            open(os.path.join(root, n_), "w").write(i_)
        img = os.path.join(t, "disk.img"); subprocess.run(["mkfs.ext4", "-q", "-F", "-d", root, img, "6M"], check=True, capture_output=True)
        subprocess.run(["debugfs", "-w", "-R", "rm /flag.txt", img], capture_output=True); disk = open(img, "rb").read()
    write("for-deleted-file", "forensics", 2, "Deleted File", "Someone deleted something from this disk. 'Deleted' does not mean 'destroyed'.\n\nFile: `disk.img` (ext4)", {"disk.img": disk},
          "`strings disk.img | grep CTFLAB`, `debugfs -R 'lsdel' disk.img`, or `photorec`/`foremost`/`extundelete`.", f, "Recovering a deleted file from a disk image.",
          ("Silinmiş Dosya", "Biri diskten bir şeyi silmiş. 'Sildim' demek 'yok ettim' demek değildir.\n\nDosya: `disk.img` (ext4)"))
    # morse
    code = {"A":".-","B":"-...","C":"-.-.","D":"-..","E":".","F":"..-.","G":"--.","H":"....","I":"..","J":".---","K":"-.-","L":".-..","M":"--","N":"-.","O":"---","P":".--.","Q":"--.-","R":".-.","S":"...","T":"-","U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--","Z":"--.."}
    words = ["MORSE", "CAN", "HIDE", "IN", "SOUND"]; f = "CTFLAB{" + "_".join(w.lower() for w in words) + "}"
    sr, unit = 8000, 0.08; samples = []
    tone = lambda sec: [int(9000 * math.sin(2 * math.pi * 700 * i / sr)) for i in range(int(sec * sr))]; silence = lambda sec: [0] * int(sec * sr)
    for w in words:
        for ch in w:
            for s in code[ch]: samples += tone(unit if s == "." else 3 * unit) + silence(unit)
            samples += silence(2 * unit)
        samples += silence(4 * unit)
    with tempfile.TemporaryDirectory() as t:
        w = os.path.join(t, "m.wav"); wf = wave.open(w, "wb"); wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr); wf.writeframes(struct.pack(f"<{len(samples)}h", *samples)); wf.close(); wb = open(w, "rb").read()
    write("for-morse-audio", "forensics", 2, "Audio Recording", "There are strange beeps in this recording. Decode the message. Flag = `CTFLAB{` + the words in lowercase joined with `_` + `}`.\n\nFile: `recording.wav`", {"recording.wav": wb},
          "Waveform/spectrogram in Audacity: short and long beeps = Morse. Decoded: MORSE CAN HIDE IN SOUND.", f, "Morse code in an audio file.",
          ("Ses Kaydı", "Bu ses kaydında tuhaf bip sesleri var. Mesajı çöz. Bayrak = `CTFLAB{` + sözcükler küçük harfle, `_` ile birleşik + `}`.\n\nDosya: `recording.wav`"))
    # brainfuck
    f = "CTFLAB{brainfuck_melts_your_brain}"
    prog = "".join("[-]" + "+" * ord(ch) + "." for ch in f)
    write("misc-brainfuck", "forensics", 2, "Brain-Melting Language", "A program was found, but it doesn't look like any language. What does it print if you run it?\n\nFile: `program.bf`", {"program.bf": prog + "\n"},
          "Brainfuck. Run it with `pip install brainfuck`, an online interpreter, or your own 20-line interpreter.", f, "Running an esolang (Brainfuck).",
          ("Beyin Yakan Dil", "Bir program bulundu ama hiçbir dile benzemiyor. Çalıştırırsan ne yazdırır?\n\nDosya: `program.bf`"))
    # layered encoding → harder misc
    f = "CTFLAB{peel_it_layer_by_layer}"
    v = f.encode()
    for enc in (base64.b32encode, lambda x: x[::-1], base64.b85encode, base64.b16encode): v = enc(v)
    write("misc-layered-encoding", "forensics", 3, "Layer by Layer", "The data was encoded several different ways and reversed somewhere along the way. Work out the order.\n\nFile: `data.txt`", {"data.txt": v.decode() + "\n"},
          "Applied: Base32 → reverse → Base85 → Base16. To undo, go backwards: Base16 → Base85 → reverse → Base32. CyberChef 'Magic' finds it too.", f,
          "Peeling multi-layer encodings (CyberChef).",
          ("Katman Katman", "Veri birkaç farklı şekilde kodlanmış, bir yerde de ters çevrilmiş. Sırayı sen bul.\n\nDosya: `data.txt`"))


def pwn():
    src = {
        "rev-crackme-1": (1, "Crackme 1 — Simple Password", "The program asks for a password. Can you find the right one? No source code, just an ELF.", "CTFLAB{ltrace_and_strings_are_enough}",
            '#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){ if(c<2){puts("usage: ./rev-crackme-1 <password>");return 1;} if(strcmp(v[1],"secretpass42")==0) puts("Correct! CTFLAB{ltrace_and_strings_are_enough}"); else puts("Wrong."); return 0; }\n',
            "`strings rev-crackme-1` shows the password (`secretpass42`); `ltrace ./rev-crackme-1 x` prints the strcmp arguments.", "Intro to reversing: strings / ltrace.",
            ("Crackme 1 — Basit Parola", "Program bir parola istiyor. Doğrusunu bulabilir misin? Kaynak kod yok, sadece ELF.")),
        "rev-crackme-2": (2, "Crackme 2 — Hidden Flag", "This program says 'Wrong' to every input. But the flag is in there somewhere... just not as plaintext.", "CTFLAB{xor_key_0x5a_found_with_gdb}",
            '#include <stdio.h>\n#include <string.h>\nstatic const unsigned char g[]={%s};\nint main(int c,char**v){ char b[64]; (void)v; if(c>5){ for(unsigned i=0;i<sizeof g;i++) b[i]=g[i]^0x5a; b[sizeof g]=0; puts(b);} puts("Wrong."); return 1; }\n',
            "Print `b` before `puts` in gdb, or XOR the `g[]` array with 0x5a in Ghidra (CyberChef). `ltrace` also catches the output, but pass 5+ arguments so that c>5.", "XORed data in an array: gdb / Ghidra.",
            ("Crackme 2 — Gizlenmiş Bayrak", "Bu program her girdiye 'Wrong' diyor. Ama bayrak bir yerlerde... düz metin olarak değil.")),
        "pwn-ret2win": (1, "Pwn 1 — ret2win", "The classic first pwn: a function that `read`s 512 bytes into a 64-byte buffer, and a `win()` function that is never called. The flag is in `flag.txt`. Source code is included.", "CTFLAB{ret2win_first_pwn_victory}",
            '#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\nvoid win(void){ char b[64]; FILE*f=fopen("flag.txt","r"); if(!f){puts("flag.txt missing");exit(1);} fgets(b,64,f); puts(b); exit(0); }\nvoid vuln(void){ char buf[64]; puts("What is your name?"); ssize_t n=read(0,buf,512); if(n>0&&buf[n-1]==10) buf[n-1]=0; else buf[63]=0; printf("Hello %s\\n",buf); }\nint main(void){ setvbuf(stdout,0,2,0); vuln(); puts("Bye"); return 0; }\n',
            "Built with `-fno-stack-protector -no-pie`. `buf` is at rbp-0x50 → the offset to the return address is 0x50+8 = **88**. Confirm it yourself with `cyclic 200 | ./pwn-ret2win` + gdb; get the `win` address with `p win` / `ELF.sym['win']`. Payload: `b'A'*88 + p64(win)` (on some systems add a `ret` gadget in between for `movaps` alignment).", "Overwriting the return address with a stack overflow.",
            ("Pwn 1 — ret2win", "Klasik ilk pwn: 64 baytlık arabelleğe 512 bayt okuyan (`read`) bir fonksiyon ve hiçbir yerden çağrılmayan bir `win()` fonksiyonu. Bayrak `flag.txt` içinde. Kaynak kod verildi.")),
        "pwn-format": (2, "Pwn 2 — Format String", "The program passes your input straight to `printf` and keeps the flag on the stack. Source code is included.", "CTFLAB{printf_never_trusts_user_input}",
            '#include <stdio.h>\n#include <string.h>\nint main(void){ char flag[64]="CTFLAB{printf_never_trusts_user_input}"; char buf[128]; setvbuf(stdout,0,2,0); puts("Tell me something:"); fgets(buf,sizeof buf,stdin); printf(buf); puts(""); (void)flag; return 0; }\n',
            "Leak the stack with `%p.%p.%p...`; the flag array starts at **%22$p** (8 bytes per chunk, little-endian) → convert `%22$p.%23$p.%24$p.%25$p.%26$p` to bytes. `%22$s` will not work because the slot holds the contents, not an address.", "Leaking data from the stack with a format string.",
            ("Pwn 2 — Format String", "Program girdiyi doğrudan `printf`'e veriyor ve bayrağı yığında tutuyor. Kaynak kod verildi.")),
    }
    srcdir = os.path.join(SYS, "src-challenges"); os.makedirs(srcdir, exist_ok=True)
    for id_, (level, name, question, flag, code, solution, short, tr) in src.items():
        if id_ == "rev-crackme-2": code = code % ",".join(str(ord(c) ^ 0x5a) for c in flag)
        with open(os.path.join(srcdir, id_ + ".c"), "w") as fh:
            fh.write(code)
        files = {"flag.txt": flag + "\n"} if id_ == "pwn-ret2win" else {}
        if id_.startswith("pwn"): files[id_ + ".c"] = code
        listing = "`" + id_ + "` (ELF)" + (", `flag.txt`" if id_ == "pwn-ret2win" else "") + (", `" + id_ + ".c`" if id_.startswith("pwn") else "")
        write(id_, "pwn", level, name, question + "\n\nFiles: " + listing, files, solution, flag, short, (tr[0], tr[1] + "\n\nDosyalar: " + listing))


if __name__ == "__main__":
    crypto(); forensics(); pwn()
    with open(os.path.join(SYS, "catalog", "generated.psv"), "w", encoding="utf-8") as f:
        f.write("# Generated challenges (gen_challenges.py)\n" + "\n".join(CATALOG) + "\n")
    with open(os.path.join(SYS, "catalog", "flags.sha256"), "w") as f:
        f.write("\n".join(f"{v}  {k}" for k, v in HASHES.items()) + "\n")
    print(f"{len(CATALOG)} challenges generated. Build the pwn/rev binaries with: ctf build-challenges")
