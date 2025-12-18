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
