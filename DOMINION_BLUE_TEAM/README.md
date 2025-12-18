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
- "Eğer saldırgan X zafiyetini kullansaydı, loglarda ne görürdüm?" sorusunu sormak.

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
