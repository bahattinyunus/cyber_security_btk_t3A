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
