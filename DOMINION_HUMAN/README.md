# 🎭 THE MIND: İnsan Faktörü (Social Engineering)

> "Amatörler sistemleri hackler, profesyoneller insanları."

---

## 🧠 Psikolojik Prensipler (Cialdini'nin 6 İlkesi)

Bir insanı "evet" demeye ikna etmenin bilimi.

1.  **Karşılıklılık (Reciprocity)**: Önce sen bir şey ver (örn: bedava USB bellek), o da sana şifresini versin.
2.  **Tutarlılık (Consistency)**: Küçük bir ricanı kabul ettirirsen, büyüğünü de kabul eder.
3.  **Toplumsal Kanıt (Social Proof)**: "Herkes bunu yapıyor" hissi yarat.
4.  **Hoşlanma (Liking)**: Benzerlikler kur, kendini sevdir.
5.  **Otorite (Authority)**: "Ben CEO'yum" veya "Ben IT Direktörüyüm" de. Üniforma veya unvan kullan.
6.  **Kıtlık (Scarcity)**: "Bu teklif son 10 dakika!" diyerek acele ettir.

---

## 🎣 Oltalama Türleri (Phishing)

Siber saldırıların %90'ı bir e-posta ile başlar.

| Tür | Hedef | Açıklama |
| :--- | :--- | :--- |
| **Phishing** | Herkes | Rastgele 10.000 kişiye "faturanız ödenmedi" maili atmak. |
| **Spear Phishing** | Özel Kişi | Hedefin adını, işini, hobilerini bilerek özel mail atmak. |
| **Whaling** | Üst Düzey | CEO, CFO gibi "büyük balıkları" avlamak. |
| **Vishing** | Sesli (Telefon) | Telefonla arayıp "Bankadan arıyoruz" demek. |
| **Smishing** | SMS | "Kargonuz teslim edilemedi" SMS'i atmak. |

---

## 🔍 OSINT: Sosyal Mühendisliğin Yakıtı

Bir saldırı yapmadan önce hedef hakkında toplanan her veri, saldırının başarı şansını artırır.
- **LinkedIn/Instagram**: Hedefin iş arkadaşları, ilgi alanları ve lokasyonu.
- **Whois/DNS**: Teknik altyapı ve ilgili e-posta adresleri.
- **Metadata**: Şirket PDF'lerinden sızan yazar isimleri ve yazılım versiyonları.

---

## 💼 Kriz Yönetimi & Kurumsal İletişim

Büyük bir veri sızıntısı (breach) durumunda, teknik başarı kadar sürecin yönetimi de kritiktir.

### 1. İletişim Protokolü (Incident Communication)
Kriz anında kiminle, ne kadar bilgi paylaşılacağı önceden belirlenmelidir.
- **Hukuk (Legal)**: KVKK/GDPR bildirim süreleri ve yasal sorumluluklar.
- **Halkla İlişkiler (PR)**: Doğru kelimelerle güven kaybını minimize etme. "Hacklendik" yerine "Tespit edilen bir anomali üzerinde çalışıyoruz" gibi profesyonel yaklaşımlar.
- **Yönetim Kurulu (Board)**: Teknik detay yerine "Risk, Etki ve Çözüm Süresi" bildirimi.

### 2. Tabletop Exercises (Masa Başı Tatbikatlar)
Gerçek bir saldırı olmadan, senaryolar üzerinden departmanlar arası koordinasyonun test edilmesi.
- **Senaryo**: "Şirket verileri çalındı ve fidye isteniyor. Hukuk, IT ve PR ne yapacak?"

---

## 🧠 İkna Psikolojisi: Cialdini'nin 6 Prensibi

Sosyal mühendislik, bir kişinin "evet" demesini sağlayan psikolojik tetikleyicileri kullanır.

1.  **Karşılıklılık (Reciprocity)**: Biri bize iyilik yaparsa, kendimizi ona borçlu hissederiz.
2.  **Bağlılık ve Tutarlılık**: Bir konuda küçük bir söz veren kişi, daha büyük isteklere de onay vermeye meyillidir.
3.  **Sosyal Kanıt**: "Herkes bunu yapıyor" algısı, hedefi de aynı şeyi yapmaya iter.
4.  **Hoşlanma**: Kendimize benzeyen veya kibar bulduğumuz insanlara daha kolay güveniriz.
5.  **Otorite**: Kurumsal üniforma, unvan veya teknik terim kullanımı sorgulamayı azaltır.
6.  **Azlık (Scarcity)**: "Sadece 5 dakikanız var" gibi kısıtlı zaman/kaynak algısı panik yaratarak mantıklı düşünmeyi engeller.

---

## 🚧 Gelişmiş Fiziksel Red Teaming

Fiziksel engelleri aşmak, siber alana girmek için en kısa yoldur.

### 1. Site Survey (Saha Keşfi)
Hedef tesisin zayıf noktalarını (kör noktalar, açık pencereler, kart okuyucu tipleri) önceden tespit etme.
### 2. Sensör Bypass
- **PIR Sensörleri**: Soğuk şemsiye veya vücut ısısını gizleyen battaniye ile hareket sensörlerini atlatma.
- **Magnetik Kontaklar**: Kapıdaki magnetik dedektörleri güçlü magnetler ile kandırarak kapının "kapalı" görünmesini sağlama.
### 3. Lock Picking & Decoding
Mekanik kilitlerin manipülasyonu veya anahtar profilinin fotoğraftan okunarak 3D yazıcı ile kopyalanması.

---

## 🛡️ Fiziksel Sosyal Mühendislik

Siber güvenlik sadece ekranda bitmez.
- **Tailgating (Peşine Takılma)**: Yetkili birinin arkasından kapıdan sızmak.
- **Piggybacking**: Birinin kapıyı sizin için tutması (Hoşlanma/Yardım etme psikolojisi).
- **USB Drops**: Otoparka veya tuvalete "Maaş Listesi" yazılı zararlı USB bırakmak.
- **Shoulder Surfing**: Parola girilirken arkadan gizlice izlemek.

---

## 🎭 Pretexting (Senaryo Yazımı)

İnandırıcı bir yalan, gerçeğin detaylarına sahiptir.

- **Senaryo**: "IT Departmanından arıyorum." (Zayıf)
- **Güçlü Senaryo**: "Merhaba Ahmet Bey, 3. kattaki yazıcı güncellemesi takıldı, ekranınızda 404 hatası görüyor musunuz? Hızlıca düzeltmem lazım yoksa tüm katın interneti kesilecek." (Güçlü: İsim + Konum + Aciliyet + Teknik Detay)

---

## 🛠️ Araç Seti

- **Gophish**: Açık kaynaklı phishing kampanya yönetim aracı.
- **SET (Social-Engineer Toolkit)**: Sahte web siteleri kopyalamak için.
- **Maltego**: Hedef hakkında bilgi toplamak için.

---

## 💻 Sentinel Phish (Araç Kullanımı)

Senaryo bazlı oltalama taslakları üreten aracımız.

**Konum**: `TOOLS/sentinel_phish.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_phish.py --scenario ceo_urgent --target "Ahmet Yılmaz"
```
*Hazır sosyal mühendislik metinleri üretir.*
