# 🏛️ AKADEMİ: Siber Güvenlik Temelleri (Core Cyber Concepts)

> "Pratikteki ustalık, teorideki derinlikle başlar. Temeli zayıf olan bir savunma, en gelişmiş araçlarla bile ayakta kalamaz."

---

## 📐 Güvenliğin Üç Sütunu: CIA Triad

Siber güvenliğin en temel modeli olan **CIA**, her güvenlik kararının merkezinde yer alır.

### 1. Gizlilik (Confidentiality)
Bilginin sadece yetkili kişiler tarafından görülmesini sağlamaktır.
- **İhlal**: Veri sızıntıları, şifre çalınması.
- **Koruma**: Şifreleme (Encryption), erişim kontrolleri.

### 2. Bütünlük (Integrity)
Bilginin yetkisiz kişilerce değiştirilmemesini, tam ve doğru kalmasını sağlamaktır.
- **İhlal**: Web sitesi içeriğinin değiştirilmesi (Defacement), veritabanı manipülasyonu.
- **Koruma**: Hash fonksiyonları (MD5, SHA256), dijital imzalar.

### 3. Erişilebilirlik (Availability)
Bilginin ve sistemlerin ihtiyaç duyulduğunda yetkili kullanıcılar için hazır olmasını sağlamaktır.
- **İhlal**: DoS/DDoS saldırıları, fidye yazılımları, donanım arızaları.
- **Koruma**: Yedekleme, yedekli sistemler (Redundancy), yük dengeleyiciler.

---

## 🔑 AAA Çerçevesi: Erişim Kontrolü

Sistemlere "kimin, neye, ne zaman" erişeceğini yöneten protokoldür.

- **Identification (Kimlik Belirleme)**: Kullanıcının kim olduğunu iddia etmesi (örn: Kullanıcı adı).
- **Authentication (Kimlik Doğrulama)**: İddia edilen kimliğin kanıtlanması (örn: Şifre, OTP).
- **Authorization (Yetkilendirme)**: Doğrulanmış kullanıcının hangi kaynaklara erişebileceğinin belirlenmesi (örn: Okuma/Yazma izni).
- **Accounting (Hesap verebilirlik/Kayıt)**: Kullanıcının sistemdeki eylemlerinin loglanması ve izlenmesi.

---

## 📊 Risk Yönetimi Denklemi

Siber güvenlik bir "sıfır risk" oyunu değil, bir "risk yönetimi" sürecidir.

> **Risk = Tehdit (Threat) x Zafiyet (Vulnerability) x Etki (Impact)**

- **Vulnerability**: Sistemdeki bir zayıflık (örn: bir yazılım hatası).
- **Threat**: Bu zayıflığı kullanabilecek dış/iç unsur (örn: bir hacker veya kötü niyetli çalışan).
- **Risk**: Bir tehdidin bir zafiyeti kullanarak sisteme zarar verme olasılığı ve yaratacağı sonuç.

### Risk Müdahale Stratejileri:
1. **Mitigation (Azaltma)**: Güvenlik önlemleri alarak riski düşürmek.
2. **Transfer (Devretme)**: Sigorta veya outsourcing ile riski başkasına aktarmak.
3. **Avoidance (Kaçınma)**: Riskli eylemi tamamen durdurmak.
4. **Acceptance (Kabul Etme)**: Riski bilerek ve göze alarak devam etmek.

---

## 📜 Klasik Güvenlik Modelleri (Akademik Temeller)

Sistemlerin güvenliğini matematiksel olarak kanıtlamak için kullanılan modeller.

### 1. Bell-LaPadula (Confidentiality - Gizlilik Odağı)
"Yukarı okuma yok, aşağı yazma yok" (No Read Up, No Write Down).
- Sırrı (Secret) olan biri, Top Secret bir belgeyi okuyamaz.
- Top Secret verisi olan biri, Secret seviyesinde bir belgeye yazı yazıp bilgiyi sızdıramaz.

### 2. Biba Modeli (Integrity - Bütünlük Odağı)
"Aşağı okuma yok, yukarı yazma yok" (No Read Down, No Write Up).
- Yüksek güvenilirliğe sahip verinin, düşük güvenilirliğe sahip kaynaklar tarafından kirletilmesini önler.

---

## 🛡️ Güvenlik Tasarım Prensipleri & Zero Trust

Modern siber güvenliğin bel kemiği.

### 1. Zero Trust Architecture (ZTA) - NIST SP 800-207
"Hiçbir kullanıcıya, cihaza veya ağ segmentine varsayılan olarak güvenilmez."
- **Sürekli Doğrulama**: Her erişim isteği dinamik olarak değerlendirilir.
- **Mikro-Segmentasyon**: Ağın küçük parçalara bölünerek saldırı yüzeyinin azaltılması.
- **Context-Aware**: Giriş saati, konumu ve cihaz sağlığına göre yetki verilmesi.

### 2. Diğer Temel Prensipler
- **Defense in Depth (Derinlemesine Savunma)**: Katmanlı güvenlik. Bir duvar aşılsa bile arkada diğerlerinin olması.
- **Least Privilege (En Az Yetki)**: Bir kullanıcıya işini yapması için gereken *minimum* yetkinin verilmesi.

## 📈 Risk Analizi ve Puanlama (CVSS)

Bir zafiyetin ne kadar tehlikeli olduğunu nesnel olarak hesaplamak.

- **CVSS v3.1**: Mevcut endüstri standardı (Base, Temporal, Environmental skorları).
- **CVSS v4.0 (Yeni)**: Daha hassas ölçüm için "Cyber-Physical" ve "Environmental" faktörlerine ağırlık veren modern yaklaşım.
- **Hesaplama**: Atak vektörü (Ağ mı?), karmaşıklık, gereken yetki ve gizlilik/bütünlük kaybı üzerinden 0-10 arası bir puan üretilir.

---

## 📝 Profesyonel Raporlama & Metodolojiler

Siber güvenlik uzmanı sadece hacklemez, sonucunu profesyonelce raporlar.

### 1. Standart Metodolojiler
- **OSSTMM**: Açık kaynaklı güvenlik testi metodolojisi (Operasyonel odaklı).
- **PTES (Penetration Testing Execution Standard)**: Sızma testlerinin 7 aşaması (Pre-engagement'tan Reporting'e).

### 2. Rapor Bileşenleri
- **Yönetici Özeti (Executive Summary)**: Teknik olmayan dille, iş risklerini anlatan özet.
- **Teknik Bulgular**: PoC (Proof of Concept) kodları, ekran görüntüleri ve düzeltme önerileri.
- **Kritiklik Seviyesi**: Bulgunun sistem üzerindeki etkisi.

---

---

## 🤖 Yapay Zeka (AI) & LLM Güvenliği

Yapay zeka modelleri, siber güvenliğin hem kalkanı hem de yeni saldırı yüzeyidir.

### 1. LLM Zafiyetleri (Prompt Injection)
Modeli, sistem komutlarını veya gizli verileri ifşa etmeye zorlayan "dil tabanlı" saldırılar.
- **Indirect Prompt Injection**: Bir web sayfasındaki gizli metnin, LLM tarafından okunduğunda saldırganın komutlarını icra etmesini sağlama.

### 2. Eğitim Verisi Zehirlenmesi (Data Poisoning)
Modelin eğitim aşamasında veri setine sızarak, belirli girdilere karşı yanlış veya taraflı sonuçlar üretmesini sağlama.

### 3. Güvenli AI Prensipleri
- **Diferansiyel Gizlilik (Differential Privacy)**: Modelin eğitim verisindeki bireysel kayıtları ifşa etmesini engelleme.
- **Model Watermarking**: Üretilen içeriğin veya modelin mülkiyetini kanıtlamak için kullanılan dijital damgalar.

---

## 🚀 Gelecek Ufku: Otonom Savunma ve CPS

Siber güvenliğin bir sonraki aşaması, insan müdahalesinin ötesindedir.

### 1. Otonom Siber Savunma (Autonomous Defense)
Yapay zeka ajanlarının, saldırıları insan hızının ötesinde (milisaniyeler içinde) tespit edip kendi kendine yama (patch) yapabildiği sistemler.
- **Self-Healing Systems**: Saldırıya uğrayan segmenti izole edip, otomatik olarak temiz bir kopyasıyla değiştiren yapılar.

### 2. Siber-Fiziksel Sistemler (CPS)
Siber dünyanın fiziksel dünya ile birleştiği her yer (Akıllı fabrikalar, otonom araçlar, akıllı şehirler).
- **Daha Yüksek Risk**: Bir web sitesinin çökmesi veri kaybıdır; bir nükleer santralin veya otonom aracın hacklenmesi ise hayati risktir.

### 3. Kuantum Sonrası Dünyaya Hazırlık
Kriptografinin ötesinde, kuantum bilgisayarların veri işleme hızına karşı yeni savunma paradigmaları geliştirilmesi.

---

## 🛰️ Uzay ve Uydu Güvenliği (Space Cyber)

Siber güvenlik artık sadece yerküre ile sınırlı değil; yörüngedeki varlıklarımızı da korumalıyız.

### 1. Uzay Segmenti vs Yer Segmenti
- **Uzay Segmenti (Satellite)**: Uydu üzerindeki yazılımın bütünlüğü ve radyasyon gibi fiziksel etkenlere karşı dayanıklılık.
- **Yer Segmenti (Ground Station)**: Uyduları kontrol eden yer istasyonlarının LAN ve WAN güvenliği. Buradaki bir sızma, uydunun "kaçırılmasına" neden olabilir.

### 2. Telemetri ve Komuta (TT&C) Güvenliği
Uydularla iletişim kurmak için kullanılan linklerin (Uplink/Downlink) güvenliği.
- **Telemetry Hijacking**: Şifrelenmemiş telemetri verilerini dinleyerek uydunun konumu ve durumu hakkında bilgi toplama.
- **Command Injection**: Sahte komutlar göndererek uydunun yörüngesini değiştirme veya güneş panellerini kapatma.

### 3. Yörüngesel Dayanıklılık (Orbital Resilience)
Bir siber saldırı durumunda uydunun otonom olarak "Safe Mode"a geçmesi ve yer istasyonuyla güvenli bir kanaldan (Out-of-band) iletişim kurabilme yeteneği.

---


## 📜 Standartlar ve Uyumluluk (Compliance)

Küresel düzeyde kabul görmüş bazı çerçeveler:
- **ISO/IEC 27001**: Bilgi Güvenliği Yönetim Sistemi (ISMS) standardı.
- **NIST Cybersecurity Framework**: Tanımla, Koru, Tespit Et, Müdahale Et, İyileştir.
- **GDPR / KVKK**: Kişisel verilerin korunmasına yönelik yasal düzenlemeler.
- **PCI-DSS**: Ödeme kartı sektörü veri güvenliği standardı.
