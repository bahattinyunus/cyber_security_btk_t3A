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
