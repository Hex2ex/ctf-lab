# CTF Lab

Kendi Linux bilgisayarında çalıştırdığın, kendi kendine yeten bir CTF pratik laboratuvarı: "ilk nmap taraması"ndan gerçek Google CTF finallerine kadar **83 lab**, hepsini yöneten tek bir panel, ilerleme takibi ve isteğe bağlı izole VM'ler ile tarayıcıdan kullanılan bir Kali.

- **Her şey isteğe bağlı ve parça parça.** Önce yalnızca dosyalarla başla (VM yok, Docker yok), sonra web lab'larını Docker'da çalıştır, sonra KVM sanal makinelerini ekle. Hiçbir şey ya hep ya hiç değil.
- **Tasarım gereği güvenli.** Zafiyetli yazılım ağında asla dinlemez: VM'ler izole bir sanal ağda yaşar; Docker modunda her port `127.0.0.1`'e bağlanır ve dışarıdan erişilebilen bir lab'ı çalışır bırakmaz.
- **Her yerden kullan.** Paneli ve tam bir Kali masaüstünü başka bir bilgisayarın tarayıcısından aç ya da kendi makinenle WireGuard üzerinden lab ağına katıl.
- Panel ve dokümanlar **İngilizce ve Türkçe** (`EN | TR` düğmesi). English: [README.md](README.md)

> **Yasal / güvenlik.** Bu lab bilerek zafiyetli yazılımlar ve sömürü pratiği içerir. Yalnızca kendi makinende ve kendi ağlarında kullan. Lab'ı (ya da Docker modundaki uygulamaları) asla internete açma. Bkz. [Güvenlik modeli](#güvenlik-modeli) ve [Sorumluluk reddi](#sorumluluk-reddi).

---

## İçindekiler

1. [İçinde ne var](#içinde-ne-var)
2. [Kurulum yolunu seç](#kurulum-yolunu-seç)
3. [Gereksinimler](#gereksinimler)
4. [Hızlı başlangıç](#hızlı-başlangıç)
5. [Lab'ı kullanmak](#labı-kullanmak)
6. [Web Kali ve uzaktan erişim](#web-kali-ve-uzaktan-erişim)
7. [Kendi makinenle katıl (WireGuard)](#kendi-makinenle-katıl-wireguard)
8. [Güvenlik modeli](#güvenlik-modeli)
9. [Yapılandırma](#yapılandırma)
10. [Komut başvurusu](#komut-başvurusu)
11. [Sorun giderme](#sorun-giderme)
12. [Sık sorulanlar](#sık-sorulanlar)
13. [Depo yapısı](#depo-yapısı) · [Katkı](#katkı) · [Emeği geçenler](#emeği-geçenler) · [Sorumluluk reddi](#sorumluluk-reddi) · [Lisans](#lisans)

---

## İçinde ne var

| Klasör (`ctf init` oluşturur) | Ne | Gerektirdiği |
|---|---|---|
| `01-web` | 12 web uygulaması (DVWA, bWAPP, Mutillidae, WebGoat, SQLi-Labs, Upload-Labs, DSVW, Juice Shop, DVNA, Hackazon, WrongSecrets, NodeGoat) + **Vulhub** (300+ gerçek CVE ortamı) | Docker ya da targets VM'i |
| `02-linux` | 29 boot2root makinesi: Metasploitable 2/3, Kioptrix, Mr-Robot, DC-1…9, Stapler, Raven, Symfonos, Brainpan, Nebula… | KVM |
| `03-windows` | Metasploitable 3 (Windows Server 2008 R2) | KVM |
| `04-pwn-rev` | Üretilmiş 4 crackme/pwn sorusu, **ROP Emporium**, **Nightmare**, **how2heap** ve Protostar / Phoenix / Fusion VM'leri | dosyalar / KVM |
| `05-crypto` | Üretilmiş 12 soru: Sezar, XOR, Vigenère, hash kırma, RSA (küçük e, Fermat, Wiener, Håstad), iki kez kullanılan pad, JWT | hiçbir şey |
| `06-forensics` | Üretilmiş 12 soru: strings, EXIF, QR, zip parolası, LSB stego, pcap, günlük, silinmiş dosya, Mors, Brainfuck, katmanlı kodlama | hiçbir şey |
| `07-api` | VAmPI, DVGA (GraphQL), crAPI | Docker ya da targets VM'i |
| `08-archives` | Gerçek yarışma soruları: **CTF Wiki** (118), **DownUnderCTF 2025** (64), **Google CTF 2017–2026** (344); her birinde kategoriye göre `INDEX.md` | dosyalar (istek üzerine indirilir) |
| `09-custom` | `drop-here/` klasörüne attığın CTF'ler | duruma göre |

Her klasörün içindeki seviyeler `1-easy` (başlangıç), `2-medium` (orta), `3-hard` (ileri). Her lab'ın bir `README.md`'si vardır (kendi README'sini getiren projelerde `LAB.md`); üretilen sorularda `CHALLENGE.md` ile Türkçe `README.tr.md` bulunur.

Ayrıca: bir **web paneli** (lab başlat/durdur/sıfırla, öğrenme notları, lab başına zafiyetler, bayrak gönderme, ilerleme), **bayrak denetleyicisi** (yalnızca SHA-256 özetleri; bayrakların kendisi saklanmaz), önüne atılan her CTF'i kuran **drop-here** klasörü, **tarayıcıda Kali** ve **WireGuard** erişimi.

---

## Kurulum yolunu seç

İstediğini veren en küçük yolu seç. Bir sonrakini istediğin zaman ekleyebilirsin.

| Yol | Ne elde edersin | Ne gerekir | Komutlar |
|---|---|---|---|
| **A. Yalnızca dosyalar** | crypto, forensics, pwn/rev soruları, CTF arşivleri, panel, ilerleme takibi | Linux, Python 3, p7zip, e2fsprogs | `ctf init` |
| **B. + Docker'da web lab'ları** | + 15 web/API lab'ı ve Vulhub, yalnızca `127.0.0.1`'de | + compose eklentili Docker | `ctf bootstrap docker` |
| **C. + KVM sanal makineleri** | + 33 boot2root/pwn VM'i, izole lab ağı, *targets VM'i* (web lab'ları VM'de, en güvenlisi), *Kali VM'i*, tarayıcıda Kali, WireGuard | + KVM/libvirt, ~45 GB boş alan, önerilen 16 GB RAM | `host-setup.sh`, `ctf bootstrap targets`, `ctf bootstrap kali` |

Notlar:

- **Docker modunda saldırıyı kendi bilgisayarından yaparsın** (tarayıcı, Burp, kendi araçların): uygulamalar yalnızca `127.0.0.1`'de dinlediği için bir Kali VM'i onlara ulaşamaz. Kali VM'inden web lab'larına saldırmak istiyorsan targets VM'ini kur (yol C).
- **Kali VM'ini kurmak zorunda değilsin.** Zaten Kali/Parrot/başka bir sistemin varsa `bootstrap kali`'yi atla ve WireGuard ile lab ağına katıl (`ctf vpn add`).
- boot2root makineleri (DC-1, Metasploitable…) eksiksiz işletim sistemleridir, bu yüzden hep KVM ister, ama yardımcı iki VM'den hiçbirini istemez.

---

## Gereksinimler

**Arch Linux** üzerinde geliştirildi ve test edildi. A ve B yolları yaygın araçlar kullanır ve her Linux'ta çalışmalı; C yolundaki yardımcı betik paketleri `pacman` ile kurar. Başka dağıtımlarda eşdeğerlerini kendin kur ve `host-setup.sh --no-packages` çalıştır (aşağıdaki paket adları elimizden gelenin en iyisi, test edilmedi).

**A yolu** (bütün yollar)

| Araç | Arch | Debian / Ubuntu | Fedora |
|---|---|---|---|
| Python 3.9+ | `python` | `python3` | `python3` |
| 7z | `p7zip` | `p7zip-full` | `p7zip p7zip-plugins` |
| mkfs.ext4, debugfs | `e2fsprogs` | `e2fsprogs` | `e2fsprogs` |
| rsync, curl, git, ssh | `rsync curl git openssh` | `rsync curl git openssh-client` | `rsync curl git openssh-clients` |
| *isteğe bağlı* qrencode, ImageMagick, gcc | `qrencode imagemagick gcc` | `qrencode imagemagick gcc` | `qrencode ImageMagick gcc` |

**B yolu:** Docker + compose eklentisi (Arch'ta `docker docker-compose`, Debian/Ubuntu'da `docker.io docker-compose-v2`). Kullanıcın `docker` çalıştırabilmeli (genelde `docker` grubunda olmak). Her lab'ın ilk başlatılışında imajı indirilir.

**C yolu**

- BIOS/UEFI'de sanallaştırması açık bir CPU (Intel VT-x / AMD-V) ve `/dev/kvm`.
- Paketler (Arch adlarıyla; `host-setup.sh` kurar): `qemu-desktop libvirt virt-install virt-manager virt-viewer edk2-ovmf swtpm dnsmasq dmidecode libisoburn rsync sshpass inotify-tools caddy ttyd wireguard-tools qrencode`. `.ova` dosyaları için ayrıca `libarchive` (`bsdtar`).
- Disk: Kali + targets VM'i için ~45 GB boş alan. Her boot2root VM'i 1–5 GB ekler; **her şeyi** indirmek yaklaşık 200 GB tutar.
- RAM: Kali VM'i en fazla 8 GB, targets VM'i en fazla 8 GB alır (küçük makinelerde ölçeklenir; bkz. [Yapılandırma](#yapılandırma)). Toplam 16 GB rahat, birkaç VM'i aynı anda çalıştıracaksan 32 GB daha iyi.

---

## Hızlı başlangıç

```bash
git clone https://github.com/Hex2ex/ctf-lab.git
cd ctf-lab
.system/bin/ctf init        # A yolu: soruları, klasörleri, başlatıcıları üretir; `ctf`'i ~/.local/bin'e ekler
ctf list                    # bütün lab'lar ve durumları
ctf panel                   # web paneli
```

> Kod, gizli `.system/` klasöründedir (dosya yöneticisinde gizli dosyaları göster: Ctrl+H). Her şey herhangi bir dizinden çalışır; ayarlanacak bir şey yok.

**B yolu, Docker'da web lab'ları**

```bash
ctf bootstrap docker
ctf start dvwa              # → http://127.0.0.1:8081   (admin / password; sonra bir kez /setup.php'yi aç)
ctf stop dvwa
```

**C yolu, VM'ler**

```bash
sudo bash .system/bin/host-setup.sh     # bir kez: paketler, güvenlik duvarı, lab ağları, WireGuard (sudo parolanı sorar)
ctf bootstrap targets                   # web lab'ları için VM (~0,6 GB indirme, ~5 dk)
ctf bootstrap kali                      # Kali VM'i (~3,6 GB indirme), sonra CTF araçlarını kurar (uzun sürer)
ctf start dc1                           # bir boot2root makinesi; açılınca IP'si bildirilir
ctf kali                                # Kali penceresini açar (kullanıcı kali / parola kali)
```

Kali'de: `nmap -sn 192.168.100.0/24`, sonra `nmap -sC -sV -p- <ip>`. Bir şeyi mi bozdun? `ctf reset dc1` VM'i ilk haline döndürür.

`ctf bootstrap status` bilgisayarında nelerin kurulu olduğunu gösterir, `ctf bootstrap` ise bütün seçenekleri anlatır.

---

## Lab'ı kullanmak

### Panel

`ctf panel` (ya da **Lab Panel** başlatıcısı) paneli tarayıcında `http://127.0.0.1:8765` adresinde açar. Her lab kartında **Başlat / Durdur / Sıfırla**, **Detay** (neler öğreneceğin, zafiyetler ve görevler) ve dosya tabanlı lab'larda **Dosyalar** var. Üst çubuk Kali'yi, web-lab çalışma ortamını ve genel ilerlemeni gösterir. **EN | TR** düğmesi dili değiştirir. Arama zafiyet adlarını anlar: `sql injection`, `ssrf`, `rop` yaz.

### Bayraklar ve ilerleme

Bir lab'ın **Detay**'ını aç ve bayrağı bir görevin kutusuna yaz.

| Rozet | Anlamı |
|---|---|
| ✓ **Doğrulandı** | Bayrağı sistem kontrol etti (üretilmiş crypto, forensics ve pwn/rev soruları). Görevi yalnızca doğru bayrak tamamlar. |
| ◐ **Beyan** | VM ve web lab'larının bayrakları hiçbir yerde kayıtlı değil, bu yüzden doğrulanamaz. Görevi kendin "bitti" diye işaretlersin (bayrakla ya da notla). Beyanlar ayrı sayılır, doğrulananlarla asla karışmaz. |

Üretilen sorularda bayrak biçimi `CTFLAB{...}`. Terminalde: `ctf info <id>`, `ctf flag <id> [görev] '<bayrak>'`, `ctf done <id> <görev> [not]`, `ctf undo <id> <görev>`, `ctf progress`, `ctf solution <id>` (spoiler!). İlerleme `.system/progress.json` dosyasında durur; yedeklemek için bu dosyayı kopyala.

> Spoiler: üretilen soruların çözümleri üretici kaynağında (`.system/bin/gen_challenges.py`) yazılıdır. Bitirmeden okuma.

### boot2root VM'leri

```bash
ctf list linux              # bütün Linux makineleri
ctf start dc1               # ilk kullanımda kurulur (imajı indirir, dönüştürür), sonra açar; IP'sini yazar
ctf info dc1                # neler öğreneceksin, zafiyetler, görevler
ctf console dc1             # VM konsol penceresi
ctf compat dc1              # VM IP almıyor mu? başka ağ kartı / disk denetleyicisi kombinasyonlarını kendisi dener
ctf reset dc1               # ilk haline döndür
```

`ctf install all` bütün VM'leri indirip hazırlar (yaklaşık 36 GB indirme).

### Gerçek CTF arşivleri

```bash
ctf install ctfwiki ductf25 google     # sığ klonlar, `.git` kaldırılır; her birine tüm soruları kategoriye göre listeleyen INDEX.md eklenir
```

`08-archives/*/*/INDEX.md` dosyalarına göz at. İkili dosyaları ana makinende değil Kali içinde çalıştır. `ctf sync` dosyaları Kali'de `~/CTF/<kategori>/` altına kopyalar.

### drop-here: kendi CTF'ini ekle

`drop-here/` klasörüne bir dosya ya da klasör at, gerisini lab halleder. Arka plan izleyicisini bir kez `ctf watch --install` ile aç (bir systemd kullanıcı servisi); ya da tek bir öğeyi elle `ctf import <yol>` ile içe aktar.

| Attığın şey | Ne olur |
|---|---|
| `.ova` `.vmdk` `.vdi` `.qcow2` `.iso` ya da içinde bunlar olan `.zip/.7z/.rar` | izole ağda VM olarak kurulur, açılır, IP'si bildirilir. IP gelmezse ağ kartı/disk kombinasyonlarını kendisi dener |
| `docker-compose.yml` / `Dockerfile` içeren klasör ya da arşiv | Docker ile derlenip çalıştırılır (VM ya da Docker modu, portlar her zamanki gibi bağlanır) |
| `docker save` ile alınmış `.tar` | `docker load` edilir |
| Diğer her şey (pwn binary, pcap, resim, zip…) | Kali içinde `~/CTF/inbox/` klasörüne kopyalanır |

Kendi eklediğini silmek için: `ctf remove custom-<ad>`.

---

## Web Kali ve uzaktan erişim

Kali VM'i kuruluysa onu tarayıcıdan kullanabilirsin: bu bilgisayarda ya da ağındaki herhangi bir bilgisayarda.

```bash
ctf remote enable           # bir web parolası sorar; panel servisini, HTTPS geçidini ve web terminalini başlatır
```

Sonra **`https://<bu-bilgisayar>:8443/`** adresini aç ve kullanıcı **`ctf`**, belirlediğin parolayla gir. Sertifika kendinden imzalıdır, bu yüzden tarayıcı bir kez uyarır; kabul et.

| Adres | Ne |
|---|---|
| `/` | panel (yerelle aynı) |
| `/kali` | Kali masaüstünün tamamı (noVNC), klavye ve fare dahil |
| `/term/` | tarayıcıda bir Kali terminali |
| `/files/…` | soru dosyalarını salt okunur indirme (kartlardaki **Dosyalar** düğmesi) |

Bağlanan herkes aynı Kali masaüstünü paylaşır. Panelde **Masaüstü (web)** ve **Terminal (web)** düğmeleri Kali kapalıysa önce onu açar. `ctf remote status | password | disable` yönetir; `ctf web-kali --open` kısayoldur.

Nasıl çalışır ve neden güvenli: bir Caddy ters vekil sunucusu HTTPS'i sonlandırır ve parola ister; panelin kendisi `127.0.0.1`'e bağlı kalır ve vekilden gelen istekleri yalnızca gizli bir başlıkla kabul eder; Kali'nin VNC ekranı yalnızca `127.0.0.1`'de dinler. Ayrıntılar [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) içinde (İngilizce).

---

## Kendi makinenle katıl (WireGuard)

Kendi araçlarını mı tercih ediyorsun? Bir WireGuard eşi oluştur; bilgisayarın Kali VM'i olmadan doğrudan **lab ağına** katılır.

```bash
ctf vpn add laptop          # yapılandırmayı ve QR kodunu yazdırır (ayrıca: panel → Uzaktan erişim)
ctf vpn list
ctf vpn remove laptop
```

Yapılandırmayı öbür makineye aktar (Windows/macOS/Android/iOS'ta WireGuard uygulaması, Linux'ta `sudo wg-quick up ./laptop.conf`). Makine bir lab adresi (`192.168.100.210–250`) alır ve her hedefe ulaşabilir. Hedefler eş adresine bağlanabildiği için **ters kabuklar (reverse shell) çalışır**. Tünelden yalnızca lab trafiği (`192.168.100.0/24`) geçer; trafiğinin geri kalanına dokunulmaz. Panel bu durumda `https://192.168.100.1:8443/` adresinde de açılır.

İnternet üzerinden bağlanmak için: modeminde **UDP 51820** portunu bu bilgisayara yönlendir ve eşi `CTF_VPN_ENDPOINT=<genel adresin> ctf vpn add laptop` ile oluştur. Eş listesini kısa tut, kullanmadığın eşleri sil.

---

## Güvenlik modeli

| Şey | Erişim durumu |
|---|---|
| Lab ağı `192.168.100.0/24` (Kali `.10`, targets `.20`, boot2root `.100–.200`, VPN eşleri `.210–.250`) | İzole: internet yok, ev ağı yok. VM'ler varsayılan ağ geçidi almaz. Güvenlik duvarı (`ctf-firewall.sh`) yalnızca birbirleriyle ve VPN eşleriyle konuşmalarına izin verir; bilgisayarında köprü adresindeki DHCP/ping dışında hiçbir şeye ulaşamazlar |
| Kali / targets'ın internet erişimi | Ayrı bir NAT ağı: yalnızca internet; güvenlik duvarı bütün özel aralıkları (LAN'ın, hotspot'un, Docker ağların) engeller |
| Zafiyetli web lab'ları, VM modu | targets VM'inin içinde, izole ağda |
| Zafiyetli web lab'ları, Docker modu | Yayınlanan her port `127.0.0.1`'e çevrilir; her başlatmadan sonra `ctf` çalışan konteynerleri denetler ve **bütün arayüzlerden erişilebilen lab'ı durdurur** |
| Panel | `127.0.0.1:8765`; her başlatmada yeni bir anahtar ve `Host` denetimi, tarayıcındaki başka web sitelerine karşı korur |
| HTTPS geçidi (`ctf remote enable`) | `0.0.0.0:8443`, parola korumalı, kendinden imzalı TLS. **Diğer bilgisayarlardan yalnızca bu port ve WireGuard (51820/udp) erişilebilir olmalı** |
| VPN eşleri | Yalnızca lab ağına ve geçide ulaşır; senin LAN'ına ya da bilgisayarın üzerinden internete ulaşamaz |
| QEMU | root olarak değil, senin kullanıcınla çalışır |

Bilmen gereken varsayılan hesaplar: Kali VM'i `kali` / `kali` (konsol ve otomatik giriş; `ctf` oraya kendi SSH anahtarını da kurar); targets VM'i `lab` / `lab` (yalnızca konsol, SSH anahtar ister). VM'lere izole ağın dışından erişilemez, ama bunu değiştirirsen **bu parolaları da değiştir**. Web geçidinin kullanıcısı `ctf`, parolası senin seçtiğin. Zafiyetli lab'lar kendi (herkese açık) varsayılan girişlerini korur; her lab'ın `README.md`'sinde yazar.

Lab'ına parola korumalı bir kabuk açmayı göze almıyorsan 8443 portunu internete yönlendirme; WireGuard'ı tercih et.

---

## Yapılandırma

`.system/config.env` (gerektiğinde oluşur; düz `ANAHTAR=değer` satırları):

| Anahtar | Varsayılan | Anlamı |
|---|---|---|
| `WEB_MODE` | `auto` | `vm`, `docker` ya da `auto` (varsa targets VM'i, yoksa Docker). `ctf mode vm|docker|auto` ile değişir |
| `KALI_TIMEZONE` | ana makinenin | Kali ve targets VM'i için saat dilimi |
| `KALI_KEYMAP` | `us` (Türkçe yerelde `tr,us`) | Kali'de klavye düzeni; iki düzen Alt+Shift ile geçilir |
| `KALI_RAM_MB`, `KALI_VCPUS` | RAM'in ⅓'ü (3–8 GB), CPU'ların ½'si (2–6) | Kali VM'i boyutu, oluşturulurken kullanılır |
| `TARGETS_RAM_MB`, `TARGETS_VCPUS`, `TARGETS_DISK_GB` | RAM'in ⅕'i (2–8 GB), CPU'ların ¼'ü (2–4), 60 | targets VM'i boyutu, oluşturulurken kullanılır |
| `CTF_VPN_ENDPOINT` (ortam değişkeni) | bu bilgisayarın LAN adresi | yeni WireGuard yapılandırmalarına yazılan adres |

Portlar: panel `8765` (yerel), geçit `8443` (ağ), WireGuard `51820/udp`, Kali VNC `5910` / `5700` ve web terminali `7681` (yalnızca yerel); web lab'ları `3000`, `4000`, `5000`, `5013`, `8025`, `8080–8091`, `8888` ve `9090` kullanır.

---

## Komut başvurusu

`ctf help` tam listeyi yazar. En işe yarayanlar:

| Komut | Ne |
|---|---|
| `ctf init` · `ctf bootstrap status\|docker\|targets\|kali\|all` · `ctf mode` | kurulum |
| `ctf list [kategori]` · `ctf status [--json]` | ne var, ne çalışıyor |
| `ctf start <id> [--open]` · `stop` · `reset` · `ip` · `console` · `compat` | lab'ları çalıştır |
| `ctf kali [start\|stop\|setup\|backup\|reset --yes]` · `ctf ssh [kali\|targets]` | Kali VM'i (`backup` şimdiki hali "temiz" olarak kaydeder; `reset` ona döner) |
| `ctf info` · `flag` · `done` · `undo` · `progress` · `solution` | öğrenme ve ilerleme |
| `ctf install <id>\|all` · `ctf remove custom-<ad>` · `ctf import <yol>` · `ctf watch` | ekle ve kaldır |
| `ctf send <dosya…>` · `ctf sync` | dosyaları Kali'ye taşı |
| `ctf vulhub search\|read\|start\|stop` | Vulhub ortamları |
| `ctf remote …` · `ctf vpn …` · `ctf web-kali` | uzaktan erişim |
| `ctf pull` | web-lab imajlarını önceden indir |
| `ctf layout` | klasörleri, README'leri ve başlatıcıları yeniden üret |

Eski Türkçe komutlar (`ctf baslat`, `ctf durum`, `ctf bayrak`…) takma ad olarak çalışmaya devam eder.

---

## Sorun giderme

| Sorun | Dene |
|---|---|
| `ctf: command not found` | `ctf init` onu `~/.local/bin/ctf` olarak bağlar; o klasörü `PATH`'e ekle ya da `.system/bin/ctf` çalıştır |
| `ctf init` araçların eksik olduğunu söylüyor | [gereksinimler](#gereksinimler) tablosundan kur |
| Bir boot2root VM'i IP almıyor | `ctf compat <id>`; birçok eski VM yalnızca IDE disk ve eski ağ kartı modeliyle açılır |
| Eski VM, SSH "no matching key exchange method" | o lab'ın `README.md`'sindeki `ssh -o HostKeyAlgorithms=+ssh-rsa …` satırına bak |
| `ctf bootstrap …` ağların eksik olduğunu söylüyor | bir kez `sudo bash .system/bin/host-setup.sh` çalıştır |
| Docker modu: "Docker is not running" | `sudo systemctl enable --now docker`; kullanıcını `docker` grubuna ekle ve yeniden giriş yap |
| Docker modu: "refusing: … published on ALL interfaces" | tasarlandığı gibi çalışıyor: o lab'ın compose dosyası port yazımı değiştirilemeyen bir söz dizimi kullanıyor. O lab için targets VM'ini kullan ya da bir issue aç |
| Web Kali: "Failed to connect to server" | Kali kapalı ya da henüz açılıyor; başlat (`ctf kali` ya da panelin düğmesi) ve yeniden Connect'e bas |
| `https://…:8443` sertifika uyarısı veriyor | beklenen (kendinden imzalı); bir kez kabul et |
| Başka bilgisayardan `https://<ip>:8443`'e ulaşılamıyor | `ctf remote status`; güvenlik duvarının LAN'dan 8443/tcp'ye izin verdiğini kontrol et |
| Kali kurulumu takıldı ya da başarısız | `ctf kali-log`; `ctf kali setup`'ı tekrar çalıştırmak güvenlidir |
| Bir lab klasörü ya da README yok | `ctf layout` yeniden üretir |

Günlükler `.system/logs/` içinde (içe aktarma günlüğü, VM başına `virt-install` çıktısı, kurulum günlükleri). Uzaktan erişim servisleri için: `journalctl --user -u ctf-caddy -u ctf-panel -u ctf-ttyd`.

---

## Sık sorulanlar

**Kali VM'ini kurmak zorunda mıyım?** Hayır. [Kurulum yolunu seç](#kurulum-yolunu-seç) bölümüne bak: kendi makineni WireGuard ile kullan (`ctf vpn add`) ya da Docker modundaki lab'lara ana makinenden saldır.

**Neden bir "targets" VM'i var?** Bilerek zafiyetli web uygulamalarını ana makinenin çekirdeğinden ve ağından uzak tutmak için. Docker modu bu izolasyonu sadelikle takas eder.

**Windows ya da macOS'ta çalışır mı?** Desteklenmiyor. Linux, KVM/libvirt ve iptables'a dayanır. A ve B yolları (dosyalar, Docker) WSL2 gibi ortamlarda çalışabilir ama test edilmedi.

**Depoyu güncellersem ilerlemem güvende mi?** Evet: `progress.json`, `config.env`, VM'lerin ve indirmelerin git tarafından yok sayılır.

**Nasıl lab eklerim?** Bkz. [Katkı](#katkı).

**Zafiyetli yazılım nereden geliyor?** Bir lab'ı ilk başlattığında kendi yayıncısından indirilir (Docker Hub, GitHub, VulnHub, Kali ve Ubuntu yansıları). Bu depo yalnızca yapıştırıcı kodu içerir.

**Hepsini nasıl kaldırırım?** `ctf kali stop`, her `ctf-…` alanı için `virsh -c qemu:///system undefine <ctf-…> --nvram`, `ctf remote disable`, her eş için `ctf vpn remove`; sonra klasörü ve `/usr/local/bin/ctf-*`, `/etc/systemd/system/ctf-firewall.service`, `/etc/sudoers.d/ctf-vpn`, `/etc/sysctl.d/90-ctf-lab.conf`, `/etc/wireguard/wg-ctf.*`, `/etc/polkit-1/rules.d/50-ctf-lab.rules` dosyalarını sil ve `virsh net-undefine ctf-lab ctf-nat` çalıştır.

---

## Depo yapısı

```
.system/
  bin/            ctf (CLI), panel.py, progress.py, gen_challenges.py, gen_archive_index.py, compose_bind.py,
                  host-setup.sh, kali-setup.sh, ctf-firewall.sh, ctf-vpn-helper, yardımcılar
  catalog/        labs.psv (lab listesi), learn/{en,tr}/ (öğrenme notları), i18n/ (panel metinleri, Türkçe lab metinleri), flags.sha256
  labs/           web lab'larının compose dosyaları / başlatma betikleri
  templates/      targets VM'inin cloud-init dosyaları
  tests/          birim testleri (VM ya da ağ gerekmez)
  xml/            iki libvirt ağ tanımı
docs/ARCHITECTURE.md
```

Geri kalan her şey (`0*-…` klasörleri, `.system/vm`, indirmeler, günlükler, özel anahtarlar, `config.env`, ilerleme) üretilmiştir ya da özeldir ve git tarafından yok sayılır.

Testleri çalıştır: `python3 -I -m unittest discover -s .system/tests -v`.

## Katkı

Issue ve pull request'ler memnuniyetle karşılanır. Lab eklemek için:

1. `.system/catalog/labs.psv` dosyasına bir satır ekle (biçim dosyanın başında anlatılır).
2. Web lab'ı için `.system/labs/<id>/docker-compose.yml` ekle (ya da `LABS_DIR` ve `LISTEN_IP`'ye uyan bir `start.sh`/`stop.sh` çifti).
3. Öğrenme notlarını `.system/catalog/learn/en/<kategori>.json` **ve** `…/tr/…` dosyalarına (aynı id'ler ve sırayla), Türkçe ad/açıklamasını da `.system/catalog/i18n/tr-labs.json` dosyasına ekle. `test_catalog.py` bunların hepsini denetler.
4. Testleri çalıştır, sonra `ctf layout`.

Yeni metinleri önce İngilizce yaz; çeviriler memnuniyetle karşılanır ama zorunlu değildir.

## Emeği geçenler

Bu proje yalnızca başkalarının emeğini indirip çalıştırmayı otomatikleştirir. Bütün zafiyetli uygulamalar, sanal makineler ve soru koleksiyonları yazarlarına aittir ve kendi lisanslarını korur: DVWA, bWAPP, Mutillidae, OWASP WebGoat/Juice Shop/NodeGoat/crAPI/WrongSecrets, SQLi-Labs, Upload-Labs, Hackazon, VAmPI, DVGA, DVNA, DSVW, **Vulhub**, **VulnHub** makineleri (DC serisi, Kioptrix, Mr-Robot, Stapler, …), Rapid7 Metasploitable, Exploit Education, ROP Emporium, Nightmare, how2heap, CTF Wiki, DownUnderCTF, Google CTF, Kali Linux, Ubuntu bulut imajları, noVNC, Caddy, ttyd, WireGuard ve libvirt/QEMU. Teşekkürler.

## Sorumluluk reddi

Bu yazılım **eğitim ve yetkili test** için sunulur. Bilerek zafiyetli yazılım çalıştırır ve saldırı tekniklerini öğretir. Nerede ve nasıl kullandığından sen sorumlusun: yalnızca sahibi olduğun ya da yazılı izin aldığın sistemlere saldır, lab'ı güvenilmeyen ağlardan uzak tut ve internete açma. Yazarlar hasar ya da kötüye kullanım için sorumluluk kabul etmez. Bkz. [lisans](LICENSE).

## Lisans

[MIT](LICENSE). [Emeği geçenler](#emeği-geçenler) altındaki üçüncü taraf malzeme bu deponun **parçası değildir** ve kendi lisanslarına tabidir.
