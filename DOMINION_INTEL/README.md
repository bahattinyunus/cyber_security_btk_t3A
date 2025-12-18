# 👁️ GÖREN GÖZ: İstihbarat Protokolleri (The All-Seeing Eye)

> "Savaşın sisi sadece bilgi ışığıyla dağılır. Düşmanını kendinden daha iyi tanımıyorsan, zaten kaybetmişsindir."

---

## 🌍 İstihbarat Disiplinleri

Siber istihbarat (CTI), sadece "veri toplamak" değil, veriyi "eyleme dönüştürülebilir bilgiye" (actionable intelligence) çevirmektir.

### 1. OSINT (Açık Kaynak İstihbaratı)
*Herkesin önünde duran sırları toplamak.*
- **Arama Motoru Operatörleri (Dorks)**: Google, Bing ve Yandex'in derin sorgulama yeteneklerini kullanmak.
- **Halka Açık Veritabanları**: Şirket kayıtları, patent başvuruları, sızdırılmış veritabanları (Breach Data).
- **Teknik OSINT**: IP adresleri, DNS kayıtları, SSL sertifikaları üzerinden altyapı haritalama.

### 2. SOCMINT (Sosyal Medya İstihbaratı)
*Dijital ayak izlerini takip etmek.*
- Hedef kişilerin sosyal ağlardaki davranışlarını, bağlantılarını ve zafiyetlerini (örn: parola ipuçları) analiz etme.
- Coğrafi konum (Geolocation) tespiti: Bir fotoğraftaki gölgelerden veya tabelalardan konum bulma.

### 3. HUMINT (İnsan İstihbaratı)
*En eski kaynak: İnsan.*
- Siber dünyada bu, forumlarda, Discord sunucularında veya Dark Web marketlerinde insanlarla etkileşime girerek bilgi toplamak anlamına gelir.

---

## 🕵️ İstihbarat Döngüsü (Intelligence Cycle)

1.  **Yönlendirme (Directing)**: Ne öğrenmek istiyoruz? (İstihbarat Gereksinimleri - IRs).
2.  **Toplama (Collecting)**: Ham verinin kaynaklardan çekilmesi.
3.  **İşleme (Processing)**: Verinin okunabilir ve analiz edilebilir formata dönüştürülmesi.
4.  **Analiz (Analysis)**: Noktaların birleştirilmesi. "Bu IP adresi X saldırgan grubuyla mı ilişkili?"
5.  **Yaygınlaştırma (Dissemination)**: Raporun karar vericilere sunulması.

---

## 🗂️ Tehdit Aktörleri ve APT Grupları

Analizlerimizde tehditleri kategorize ederiz:

- **Script Kiddies**: Hazır araç kullanan, yeteneği düşük saldırganlar.
- **Hacktivists**: İdeolojik motivasyonlu gruplar (Anonymous gibi).
- **Cyber Criminals**: Para odaklı çeteler (Fidye yazılımı grupları).
- **APT (Advanced Persistent Threat)**: Devlet destekli, yüksek yetenekli ve sabırlı siber ordular.

---

## 🛠️ İstihbarat Araçları

- **Maltego**: Varlıklar arasındaki ilişkileri görselleştirmek için.
- **SpiderFoot**: Otomatik OSINT taraması.
- **Shodan**: İnternete bağlı cihazların arama motoru.
- **VirusTotal**: Dosya ve URL itibar analizi.


---

## 💻 Sentinel Whois (Araç Kullanımı)

Hızlı alan adı istihbaratı toplamak için komut satırı aracımız:

**Konum**: `TOOLS/sentinel_whois.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_whois.py <DOMAIN_ADI>
```
*IANA sunucularından ham WHOIS verisini çeker.*

---

## 📒 Intel Operasyon Veritabanı (OSINTDB)

### 🔍 Google Hacking Database (Dorks)
Arama motorlarını bir silah gibi kullanın. Bilgi toplamak için özel operatörler.

| Dork | Amaç | Örnek |
| :--- | :--- | :--- |
| `site:` | Belirli bir siteyi tara | `site:hedef.com filetype:pdf` |
| `filetype:` | Dosya türü ara | `filetype:xls "password" -site:github.com` |
| `inurl:` | URL içinde ara | `inurl:admin/login.php` |
| `intitle:` | Sayfa başlığında ara | `intitle:"index of /" parent directory` |
| `ext:` | Uzantı ara | `ext:sql "INSERT INTO" "VALUES"` |

### 🛠️ Çevrimiçi Araç Çantası
Yerel iz bırakmadan bilgi toplamak için.

- **Altyapı Analizi**:
    - [Robtex](https://www.robtex.com/): DNS ve Grafik analiz.
    - [SecurityTrails](https://securitytrails.com/): Geçmiş DNS kayıtları.
    - [Censys](https://censys.io/): İnternet cihaz arama motoru.
- **Tehdit İstihbaratı**:
    - [VirusTotal](https://www.virustotal.com/): Hash/Domain/IP tarama.
    - [Any.Run](https://app.any.run/): İnteraktif Malware Sandbox.
- **Kişi/Kurum**:
    - [Hunter.io](https://hunter.io/): Kurumsal e-posta formatı bulma.
    - [HaveIBeenPwned](https://haveibeenpwned.com/): Sızıntı kontrolü.

---

## 🎭 Advanced OPSEC: Gölgelerde Yürümek

Araştırmacı asla iz olmamalıdır. (Operational Security)

### 🕵️ Sock Puppet (Sahte Kimlik) Oluşturma
Soruşturma için inandırıcı bir "kukla" hesap yaratma sanatı.

1.  **Fake Name Generator**: Gerçekçi isim, adres ve doğum tarihi üretin.
2.  **AI Yüz Üretimi**: `thispersondoesnotexist.com` kullanın (Dikkat: Göz bebekleri ve kulaklar bazen hatalı olur, kontrol edin!).
3.  **Burner Phone**: SMS doğrulamaları için geçici numara servisleri veya sanal numaralar kullanın.
4.  **İzolasyon**:
    *   ASLA kendi tarayıcınızı kullanmayın.
    *   Her operasyon için temiz bir Sanal Makine (VM) açın.
    *   VPN + Tor (Onion over VPN) zinciri kurun.

### 🚫 Tarayıcı Parmak İzi (Fingerprinting)
IP adresinizi gizleseniz bile, tarayıcınız sizi ele verebilir.
*   **User-Agent**: Hangi işletim sistemi ve tarayıcıyı kullandığınızı söyler.
*   **Canvas Fingerprinting**: Ekran kartınızın render alma şekli benzersiz olabilir.
*   **Çözüm**: `Tor Browser` kullanın. Tüm kullanıcıları "aynı" gösterir (Windows boyutunda pencere, standart fontlar).

### ⚠️ OPSEC İhlal Örnekleri (Neleri YAPMAMALISIN?)
*   Kendi kişisel telefonunuzdan şüpheli Wi-Fi ağına bağlanmak.
*   Sock Puppet hesabıyla, kendi gerçek LinkedIn profilinize bakmak ("Profilinizi görüntüleyenler" sizi ele verir).
*   VPN kopsa bile trafiğin gitmesine izin vermek (**Kill Switch** kullanın!).
