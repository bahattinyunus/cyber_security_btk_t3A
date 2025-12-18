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
