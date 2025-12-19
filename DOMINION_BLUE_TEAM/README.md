# 🔵 MAVİ KODEKS: Sarsılmaz Kalkan (The Blue Codex)

> "Savunma reaktif değil, proaktiftir. Saldırı anlık bir olaydır, güvenlik ise ebedi bir süreçtir."

---

## 🛡️ Metodoloji: Derinlemesine Savunma (Defense in Depth)

Mavi Takım, sistemleri çok katmanlı bir zırh gibi korur. Bir katman delinse bile diğerleri tehdidi durdurmalıdır.

### 1. Tespit ve İzleme (Detection)
*Gölgelerdeki hareketi görmek.*
- **SIEM (Security Information and Event Management)**: Logların korelasyonu. `Splunk`, `ELK Stack`.
- **IDS/IPS**: Saldırı tespiti ve engelleme sistemleri. `Snort`, `Suricata`.
- **Anomali Analizi**: Normal trafikten sapmaları (örn: gece yarısı 2GB veri çıkışı) yakalamak.

### 2. Olay Müdahale (Incident Response) - NIST Döngüsü
*Kanı durdurmak.*
1.  **Hazırlık (Preparation)**: Playbook'ların hazırlanması, ekiplerin eğitimi.
2.  **Tespit ve Analiz (Detection & Analysis)**: Sinyalin gürültüden ayrılması. "Bu bir false positive mi yoksa gerçek bir saldırı mı?"
3.  **Çevreleme, Eradikasyon, İyileştirme (Containment, Eradication, Recovery)**: Enfekte sunucunun ağdan çekilmesi, virüsün temizlenmesi, sistemin yedeğe dönülmesi.
4.  **Olay Sonrası Aktivite (Post-Incident Activity)**: "Ders Çıkarılanlar" toplantısı.

### 3. Tehdit Avcılığı (Threat Hunting)
*Beklemek yerine aramak.*
- Alarm üretmeyen, sessiz saldırganları bulmak için hipotez tabanlı aramalar yapmak.
- **Pyramid of Pain**: Saldırganın yaşamını zorlaştırmak için Hash/IP gibi kolay değişen veriler yerine **TTPs** (Taktik ve Teknikler) üzerine odaklanmak.

---

## ⚙️ Detection Engineering: Akıllı Tespitler

Mavi takım artık sadece alarm beklemez; kendi dedektörlerini yazar.

### 1. Sigma Rules (Evrensel Tespit Formatı)
Herhangi bir SIEM platformuna (ELK, Splunk, Azure Sentinel) dönüştürülebilen genel kural yazım formatı.
- **Örnek**: PowerShell üzerinden Encoded komut çalıştırıldığında alarm ver.

### 2. Pratik SIEM Sorgu Desenleri
- **Splunk (Yanal Hareket Tespiti)**:
  ```spl
  index=windows EventCode=4624 Logon_Type=3 
  | stats dc(dest_nt_domain) as domain_count by src_ip
  | where domain_count > 5
  ```
- **KQL (Azure Sentinel - EDR Analizi)**:
  ```kql
  DeviceProcessEvents
  | where FileName == "cmd.exe" and ProcessCommandLine contains "/c powershell"
  ```

---

## 🏛️ SOC Mimarisi (Security Operations Center)

| Seviye | Role | Sorumluluklar |
| :--- | :--- | :--- |
| **L1 Analist** | Cephe Hattı | Gelen alarmları triyaje eder (sınıflandırır). Basit vakaları çözer. |
| **L2 Analist** | Soruşturma | L1'in çözemediği karmaşık olayları derinlemesine inceler. |
| **L3 Analist** | Avcı | Gelişmiş tehdit avcılığı yapar, zararlı yazılım analizi (Reverse Engineering) yürütür. |
| **SOC Yöneticisi**| Komutan | Operasyonu yönetir, strateji belirler. |

---

## 🛡️ Mavi Teçhizat

- **Wireshark**: Trafik analizi için mikroskop.
- **Sysmon**: Windows olaylarını derinlemesine loglar.
- **EDR (Endpoint Detection and Response)**: Uç nokta güvenliği.
- **YARA**: Zararlı yazılım imzaları oluşturma dili.


---

## 💻 Sentinel Integrity (Araç Kullanımı)

Dosya bütünlüğünü doğrulamak ve yetkisiz değişiklikleri tespit etmek için SHA-256 tabanlı aracımız:

**Konum**: `TOOLS/sentinel_integrity.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_integrity.py <DOSYA_YOLU> [BEKLENEN_HASH]
```
*Dosyanın parmak izini (hash) oluşturur ve orijinali ile karşılaştırır.*

---

## 📘 BTFM: Blue Team Field Manual (Müdahale Rehberi)

Kriz anında neye bakacağınızı bilmek, paniği önler.

### 🚨 Kritik Windows Event ID'leri (Security Log)
Olay Görüntüleyicisi (Event Viewer) filtrelerinde kullanılması gereken öncelikli ID'ler:

| ID | Olay Türü | Kritiklik | Açıklama |
| :--- | :--- | :--- | :--- |
| **4624** | Logon Success | 🟡 Düşük | Başarılı giriş. *Mesai saatleri dışında veya garip IP'lerden geliyorsa 🔴 Yüksek.* |
| **4625** | Logon Failure | 🟠 Orta | Başarısız giriş. *Ardışık çok sayıda geliyorsa Brute Force belirtisi.* |
| **4720** | Account Created | 🔴 Yüksek | Yeni kullanıcı oluşturuldu. Yetkisiz ise kesin saldırı. |
| **4726** | Account Deleted | 🟠 Orta | Kullanıcı silindi. İz silme çabası olabilir. |
| **4672** | Admin Logon | 🟠 Orta | "Special Privileges" (Yönetici yetkisi) ile oturum açıldı. |
| **1102** | Log Clear | 🔴 KRİTİK | Security logları "Audit Log Cleared" ile silindi. Saldırgan izlerini siliyor. |

### 🐧 Linux Forensics: Log Dosyaları
Şüpheli bir Linux sunucusunda ilk bakılacak yerler:

1.  **Giriş Kayıtları (Auth)**: `/var/log/auth.log` (Debian/Ubuntu) veya `/var/log/secure` (RHEL/CentOS).
    *   *Komut*: `grep "Failed password" /var/log/auth.log`
2.  **Web Sunucu Erişimleri**:
    *   Apache: `/var/log/apache2/access.log`
    *   Nginx: `/var/log/nginx/access.log`
    *   *İpucu*: User-Agent bilgisinde "sqlmap", "nikto", "curl" ara.
3.  **Zamanlanmış Görevler**: `/var/log/cron.log`
4.  **Sistem Mesajları**: `/var/log/syslog` veya `/var/log/messages`

### ⚡ Vaka Müdahale (Incident Response) Acil Durum Listesi
Bir saldırı tespit edildiğinde **PANİK YAPMA**, sırasıyla uygula:

1.  **Tespit Et**: Hangi sistem, hangi IP etkilendi?
2.  **İzole Et**:
    *   🔴 *Fişi Çekme!* (RAM'deki deliller kaybolur).
    *   Bunun yerine: **Ağ kablosunu çek** veya sanal makineyi "Suspend" moduna al.
3.  **Delil Topla**:
    *   RAM dökümünü al (Volatility için).
    *   Disk imajını al.
4.  **Temizle**: Zararlı dosyaları sil, açıkları kapat, parolaları değiştir.
5.  **Geri Dön**: Sistemleri temiz yedeğinden geri yükle.

---

## 🔬 Gelişmiş Analiz: Memory & Malware

Disk yalan söyleyebilir, ama RAM asla unutmaz.

### 🧠 Memory Forensics (Volatility Cheat Sheet)
RAM imajı (`memdump.raw`) alındıktan sonra analiz adımları:

| Komut | Açıklama |
| :--- | :--- |
| `vol.py -f mem.raw imageinfo` | İşletim sistemi profilini çıkarır (Örn: Win7SP1x64). |
| `vol.py -f mem.raw --profile=... pslist` | Çalışan işlemleri listeler. (Gizlenenleri görmek için `psscan`). |
| `vol.py -f mem.raw --profile=... netscan` | Aktif ağ bağlantılarını gösterir (XP/2003 için `connscan`). |
| `vol.py -f mem.raw --profile=... malfind` | Code Injection yapılmış şüpheli bellek alanlarını bulur. |
| `vol.py -f mem.raw --profile=... dumpfiles` | Bellekten şüpheli exe/dll dosyalarını diske çıkarır. |

---

## 🔎 Adli Bilişim Derinliği (Digital Forensics - DFIR)

Siber bir olay gerçekleştikten sonra, saldırganın ayak izlerini bulma sanatı.

### 1. Zaman Çizelgesi Analizi (Timeline Analysis)
Sistemde neyin, ne zaman olduğunu kronolojik olarak sıralamak.
- **$MFT Analysis**: Windows dosya sistemindeki her dosyanın oluşturulma, değiştirme ve erişim zamanları (MACB).
  - *Araç*: `MFTECmd.exe` (Eric Zimmerman tools).
- **Super Timeline**: Loglar, dosya sistemi ve registry verilerinin tek bir zaman çizelgesinde birleştirilmesi.
  - *Araç*: `Plaso (log2timeline)`.

### 2. Kritik Adli Kanıtlar (Artifacts)
- **LNK Dosyaları**: Kullanıcının açtığı son dosyaların ve bu dosyaların o andaki konumlarının kaydı (USB takılması gibi durumlar için kritik).
- **Prefetch (.pf)**: Uygulamaların en son ne zaman ve nereden çalıştırıldığını gösterir.
- **Browser Forensics**: Geçmiş (History), çerezler (Cookies) ve indirme kayıtları üzerinden saldırganın indirdiği pusetleri (tools) tespit etme.
  - *Konum*: `%AppData%\Local\Google\Chrome\User Data\Default\History`

---

## 🎭 Aktif Savunma: Deception Technology (Aldatma)

Saldırganı sadece engellemeyin, onu sahte hedeflere yönlendirerek deşifre edin.

### 1. Honeypots (Ballıklar)
Saldırganın içeri girmesi için tasarlanmış "zafiyetli gibi görünen" sahte sistemler.
- **Low-interaction**: Sadece belirli servisleri (örn: SSH) simüle eder.
- **High-interaction**: Gerçek bir işletim sistemi gibi davranır, saldırganın her hareketini kaydeder.

### 2. Honeytokens & Canary Tokens
Görünürde değerli olan ama aslında birer "alarm" olan sahte veriler.
- **Örnek**: Bir Excel dosyası açıldığında veya bir veritabanı tablosuna erişildiğinde sessizce SOC ekibine IP adresi ve konum bilgisi gönderir.
- **Kullanım**: `Canarytokens.org` üzerinden hızlıca "tetikleyici" dosyalar üretilebilir.

### 3. Tarpits (Zift Kuyuları)
Saldırganın tarama veya brute-force araçlarını yavaşlatmak için ağ seviyesinde yanıt süresini yapay olarak uzatma tekniği.

---

## 🤖 Savunma Otomasyonu: eBPF & SOAR

Geleceğin savunma hattı, kodun çalışma anında (runtime) ve otomatik müdahale ile kuruluyor.

### 1. eBPF (Extended Berkeley Packet Filter)
Linux çekirdeğini (kernel) değiştirmeden, çekirdek seviyesinde güvenli programlar çalıştırma teknolojisi.
- **Kullanım**: Dosya erişimleri, ağ bağlantıları ve sistem çağrılarını mikro saniye seviyesinde izlemek.
- **Araçlar**: `Tetragon`, `Falco`, `Hubble`.
- **Avantaj**: Çok düşük CPU maliyeti ve atlatılamaz izleme.

### 2. SOAR (Security Orchestration, Automation, and Response)
Farklı güvenlik araçlarını bir orkestra şefi gibi yöneten platformlar.
- **Playbooks**: "Eğer ekte zararlı tespit edilirse -> Bilgisayarı ağdan ayır -> Kullanıcıya mail at -> Ticket aç" sürecini saniyeler içinde otomatik yapar.
- **Fayda**: Analistin yükünü azaltmak ve müdahale süresini (MTTR) minimize etmek.

---

## 🔎 İleri Tehdit Avcılığı (Threat Hunting)

Sadece alarm beklemeyin, verinin içinde saldırganı bulun.

### 1. KQL (Kusto Query Language) ile Avlanma
Azure Sentinel ve Microsoft Defender üzerinde kullanılan güçlü sorgulama dili.
- **Örnek: Lateral Movement Tespiti**
  ```kql
  SecurityEvent
  | where EventID == 4624 // Başarılı Login
  | where LogonType == 3  // Network Login
  | summarize Count=count() by TargetAccount, IpAddress
  | where Count > 50      // Kısa sürede çok sayıda farklı login
  ```

### 2. Bellek Adli Bilişimi Derin Dalış (Memory Deep Dive)
Bellekteki ham veriden işletim sistemi yapılarını çekme.
- **Pool Scanning**: Bellekte gizlenmiş (linked list'ten çıkarılmış) prosesleri bulmak için `volatility` ile bellek alanlarını tarama.
- **VAD (Virtual Address Descriptor)**: Bir prosesin bellek haritasını çıkararak enjekte edilmiş kodları (örn: `rwx` yetkili alanlar) tespit etme.

---

## 🏹 Tespit Mühendisliği (Detection Engineering)

Güvenlik duvarının yakalayamadığı saldırıları, özel mantıklar kurarak yakalayın.

### 1. Sigma Kuralları: Ortak Tespit Dili
Sigma, farklı SIEM platformları arasında taşınabilir tespit kuralları yazmayı sağlar.
- **Mantık**: "Eğer `Image` alanı `powershell.exe` ise VE `ParentImage` alanı `winword.exe` ise -> Alarm üret."
- **Condition**: Bir kuralın ne zaman tetikleneceğini belirleyen boolean mantığı.

### 2. SOC Tuning & Alert Fatigue (Alarm Yorgunluğu)
Binlerce anlamsız alarm arasından gerçeği bulma stratejisi.
- **False Positive Reduction**: Sürekli tetiklenen ama zararsız olan (örn: IT ekibinin yedekleme scriptleri) işlemleri istisna (exclusion) listesine alma.
- **Precision vs Recall**: Çok hassas olup her şeyi yakalamak mı (çok gürültü), yoksa sadece kesin saldırıları yakalamak mı (riskli)?

### 3. Davranışsal Analiz (Anomali Tespiti)
- **LOLBAS Monitor**: Meşru Windows araçlarının (`certutil`, `bitsadmin`) alışılmadık parametrelerle veya alışılmadık dizinlerden çalıştırılmasını izleme.

---

## ⚡ Olay Müdahale Otomasyonu (IR Playbooks)

Bir saldırı anında saniyeler hayat kurtarır. Manuel müdahale yerine otomatikleştirilmiş senaryolar (Playbooks) kullanın.

### 1. Playbook Tasarımı: Ransomware Müdahalesi
Bir fidye yazılımı (Ransomware) tespiti durumunda otomatik aksiyonlar:
- **İzolasyon**: Tespit edilen IP'nin ağ anahtarları üzerinden otomatik bloklanması.
- **Snapshot**: Etkilenen makinenin disk yedeğinin dondurulması.
- **User Lock**: İlgili kullanıcı hesabının tüm sistemlerde (AD, Cloud) askıya alınması.

### 2. SOAR Orkestrasyonu (Detection-to-Response)
Farklı araçların tek bir platform üzerinden yönetilerek, tespit anından müdahale anına kadar geçen sürenin (MTTR) minimize edilmesi.

---


### 🧬 YARA Kural Yazımı
Kendi malware avcısı imzanızı oluşturun.

**Örnek: Basit bir PHP Webshell Avcısı**

```yara
rule PHP_Webshell_Detector {
    meta:
        description = "Basit PHP Webshell'leri tespit eder"
        author = "Cyber Sentinel Blue Team"
        severity = "High"
    
    strings:
        $php = "<?php"
        $cmd1 = "system("
        $cmd2 = "shell_exec("
        $cmd3 = "passthru("
        $cmd4 = "eval("
        
    condition:
        $php at 0 and ($cmd1 or $cmd2 or $cmd3 or $cmd4)
}
```
*Bu kural, dosyanın başında `<?php` olan VE içinde tehlikeli fonksiyonlardan biri geçen dosyaları yakalar.*
