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

## 🛰️ OSINT Framework: Veri Kaynakları

İstihbarat toplarken odaklanılması gereken temel kanallar ve araçlar.

| Kategori | Alt Dalları | Popüler Araçlar |
| :--- | :--- | :--- |
| **İnsan (People)** | E-posta, Sosyal Medya, Telefon | `Sherlock`, `Pipl`, `Epieos` |
| **Şirket (Corp)** | Finansal Veri, Domainler, Çalışanlar | `Crunchbase`, `OpenCorporates`, `Hunter.io` |
| **Ağ (Infrastructure)**| IP, DNS, Subdomain | `Shodan`, `VirusTotal`, `Sublist3r` |
| **Görüntü (Image)** | Konum (GEO), Metadata (EXIF) | `Google Lens`, `FEX`, `ExifTool` |
| **Karanlık Web (Deep)** | Forumlar, Veri Sızıntıları | `Tor`, `OnionSearch`, `HaveIBeenPwned` |

---

## 💎 Tehdit Analizi Modelleri

İstihbaratı yapılandırmak ve saldırganları profillemek için kullanılan akademik modeller.

### 1. Diamond Model (Elmas Modeli)
Her siber olayı 4 temel köşe üzerinden analiz eder:
- **Adversary (Saldırgan)**: Kim yapıyor?
- **Capability (Yetenek)**: Hangi araçları/metodları kullanıyor?
- **Infrastructure (Altyapı)**: Hangi sunucu/IP üzerinden geliyor?
- **Victim (Mağdur)**: Kime saldırıyor?

### 2. TLP (Traffic Light Protocol) - Bilgi Paylaşım Etiği
İstihbaratın kimlerle paylaşılabileceğini belirleyen renk kodları:
- 🔴 **Red**: Sadece bu odadakiler.
- 🟡 **Amber**: Sadece kurum içi.
- 🟢 **Green**: Güvenilir partnerler ile.
- ⚪ **White**: Herkese açık.

---

## 🛰️ Tehdit Paylaşım Standartları: STIX & TAXII

İstihbaratın makineler arasında otomatik aktarılması için kullanılan diller.
- **STIX (Structured Threat Information eXpression)**: Tehdit verisinin (IP, Malik, TTP) JSON tabanlı yapılandırılmış hali.
- **TAXII (Trusted Automated eXchange of Indicator Information)**: Bu verinin taşınmasını sağlayan protokol.

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

## 🌍 Jeopolitik İstihbarat & Siber Harp Doktrinleri

Siber saldırılar nadiren vakumda gerçekleşir; genellikle küresel güç savaşlarının bir parçasıdır.

### 1. Jeopolitik Tehdit Analizi
Fiziksel dünyadaki olayların (Savaşlar, seçimler, ekonomik ambargolar) dijital dünyada nasıl bir yansıma bulacağını öngörmek.
- **Örnek**: Bir bölgedeki sınır gerginliğinin ardından, o bölgedeki enerji santrallerine yönelik "recon" (keşif) faaliyetlerinin artışını izlemek.

### 2. Siber Harp ve "Aktif Önlemler" (Active Measures)
Düşman toplumun psikolojisini ve altyapısını bozmaya yönelik koordineli siber operasyonlar.
- **Gray Zone Operations**: Savaş ilan edilmeden, "ret edilebilir" (deniable) şekilde yürütülen yıkıcı saldırılar.
- **Influence Operations**: Sosyal medya algoritmalarını ve veri sızıntılarını kullanarak dezenformasyon yayma.

### 3. Stratejik Öngörü (Strategic Foresight)
Gelecekteki siber tehditleri bugünden tahmin etme ve hazırlık yapma disiplini.
- **Horizon Scanning**: Ufuk taraması yaparak, henüz olgunlaşmamış ama potansiyel olarak yıkıcı siber teknolojileri (örn: Biyosiber saldırılar, Kuantum deşifre) tespit etme.
- **Scenario Planning**: "Yarın ulusal elektrik şebekesi çökerse ne olur?" gibi "Peki ya..." (What-if) senaryoları tasarlayarak kriz yönetimi kapasitesini test etme.
- **National Strategy**: Siber güvenliği bir IT sorunu değil, ulusal beka ve egemenlik meselesi olarak kurgulama.

### 4. Kritik Altyapı ve Jeopolitik Sabotaj
Küresel veri akışını ve stratejik bağlantıları hedef alan fiziksel/mantıksal tehditler.
- **Subsea Cable Security**: Okyanus altı internet kablolarına yönelik fiziksel sabotaj veya kablo iniş noktalarında (Landing Stations) veri trafiğinin mantıksal olarak manipüle edilmesi.
- **Space-Ground Link Interruption**: Uzay tabanlı kritik internet takımlarına (Starlink, Kuiper vb.) yönelik yer istasyonu saldırıları veya yörüngeler arası lazer haberleşme kesintileri.
- **Regional Internet Fragmentation (Splinternet)**: Ülkelerin küresel internetten koparak kendi izole ağlarını kurmalarının jeopolitik etkileri ve bu ağlar arası "stratejik geçitlerin" (Sovereign Gateways) güvenliği.

### 5. Altyapı İstihbaratı (Infrastructure OSINT)
İnternete açık varlıkların ve ulusal saldırı yüzeyinin haritalanması.
- **Shodan & Censys**: IP bazlı değil, servis ve sertifika bazlı arama yaparak gizli altyapıları (Honeypotlar, endüstriyel paneller) tespit etme.
- **BinaryEdge & ZoomEye**: Dünya genelindeki maruziyet verilerini (exposed leaks) ve zafiyetli servislerin coğrafi dağılımını analiz etme.
- **ASN Haritalama**: Bir kuruma veya ülkeye ait tüm IP bloklarını (BGP duyuruları üzerinden) tespit ederek "geniş alan keşfi" yapma.

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

- **Tehdit İstihbaratı**:
    - [VirusTotal](https://www.virustotal.com/): Dosya ve URL analizi.
    - [Any.Run](https://any.run/): İnteraktif zararlı yazılım analizi.
    - [MalwareTraffic](https://www.malware-traffic-analysis.net/): Gerçek saldırı trafikleri.

---

## 🕶️ Darknet İstihbaratı (DARKINT)

Yüzey ağının (Surface Web) ötesindeki illegal ekosistemlerin takibi ve analizi.

### 1. Güvenli Erişim ve Operasyonel Güvenlik (OPSEC)
Darknet üzerinde kimlik ifşası olmadan araştırma yapma teknikleri.
- **Tor Network & Bridges**: Standart Tor çıkış düğümlerinin (Exit Nodes) izlenmesine karşı köprü (Bridges) kullanımı.
- **Tails OS**: Bellekte çalışan ve her kapatıldığında tüm izleri silen amnezi sistemi.
- **Whonix**: İş istasyonu ve ağ geçidini (Gateway) izole ederek IP sızıntılarını önleme.

### 2. İllegal Pazar Yeri (Marketplace) Analizi
Kayıp verilerin, "0-day" açıklarının ve servis olarak siber suç (CaaS) ilanlarının takibi.
- **Trend Takibi**: Yeni çıkan fidye yazılımı (Ransomware) gruplarının sızıntı siteleri (Leak Sites) üzerinden kurban analizi.
- **Kripto Takibi**: Monero (XMR) gibi gizlilik odaklı paraların mikser (mixer) kullanımı ile aklanma süreçlerinin izlenmesi.

### 3. PGP ve Güvenilir Haberleşme
Saldırganlar ve muhbirler arası haberleşmenin doğrulanması.
- **Impersonation Prevention**: Forumlardaki aktörlerin PGP imzalı mesajlarını doğrulayarak sahte profil (Imposter) tespiti.
- **Canary Watch**: Servislerin veya aktörlerin baskına uğrayıp uğramadığını anlamak için kullanılan "Warrant Canary" takibi.

---
    - [VirusTotal](https://www.virustotal.com/): Hash/Domain/IP tarama.
    - [Any.Run](https://app.any.run/): İnteraktif Malware Sandbox.
- **Kişi/Kurum**:
    - [Hunter.io](https://hunter.io/): Kurumsal e-posta formatı bulma.
    - [HaveIBeenPwned](https://haveibeenpwned.com/): Sızıntı kontrolü.

---

## 🤖 Yapay Zeka Destekli IntelOps (AI & Intelligence)

Bilgi bombardımanını, AI ile aksiyona dönüştürülebilir istihbarata çevirme.

### 1. AI-Powered OSINT & Veri Sentezi
LLM modellerini kullanarak binlerce forum iletisini, haber metnini ve raporu saniyeler içinde analiz edip "özet istihbarat" üretme.
- **Target Discovery**: Hedef hakkındaki dağınık verileri birleştirerek ilişki haritaları (graph) oluşturma.

### 2. Otomatik Aktör Profilleme (Automated Profiling)
Saldırı kodlarındaki yazım tarzı, TTP örüntüleri ve dil ipuçlarını AI ile analiz ederek saldırının hangi APT grubuna ait olduğunu otomatik olarak yüzde bazında tahmin etme.

### 3. Sentetik Medya ve Deepfake Tespiti
Yapay zeka ile üretilmiş dezenformasyonun (Deepfake videolar, AI metinleri) tespit edilmesi metodolojileri.
- **Artefakt Analizi**: AI üretiminden kalan dijital izlerin (renk sapmaları, dil tutarsızlıkları) teknik tespiti.

---


## 🌑 Dark Web & Derin İstihbarat

Görünen internetin arkasındaki suç ekosistemini izleme.

### 1. Dark Web İzleme (Tor/I2P)
Saldırganların pazar yerleri, forumlar ve veri sızıntısı (leak) sitelerini takip etmek.
- **Ransomware Sites**: Fidye yazılımı gruplarının (örn: LockBit) kurbanlarını ifşa ettiği sitelerden "erken uyarı" toplama.
- **Initial Access Brokers**: Şirket ağlarına erişim satan aracıların ilanlarını izleyerek olası bir sızıntıyı önceden tespit etme.

### 2. Tehdit Aktörü Profilleme
Bir saldırganın motivasyonunu, çalışma saatlerini ve dil becerilerini analiz ederek kimliğini daraltma.
- **Metadata Analizi**: Saldırganın paylaştığı dosyalardaki zaman dilimi (Timezone) ve yazılım sürüm bilgilerinden coğrafi konum tahmini.

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
