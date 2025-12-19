# 📡 THE ETHER: Kablosuz Ağlar (Wireless Security)

> "Hava herkesindir. Şifrelemeyen kaybeder."

---

## 📶 Wi-Fi Modları (Kartın Dili)

Wi-Fi saldırıları için donanımınızın dilini değiştirmeniz gerekir.

| Mod | Açıklama |
| :--- | :--- |
| **Managed Mode** | Standart mod. Sadece kendi bağlandığın ağın trafiğini görürsün. |
| **Monitor Mode** | Havada uçuşan **tüm** paketleri (sana gelmese bile) yakalar. Saldırı için şarttır. |
| **Master (AP) Mode** | Kartın modem gibi davranmasını sağlar (Evil Twin saldırıları için). |

---

## 🤝 WPA/WPA2 Handshake (El Sıkışma)

Parolayı kırmak için önce "selamlaşmayı" yakalamalısın.

1.  **AP (Modem)** ve **Client (Kullanıcı)** bağlantı kurarken 4 paketlik bir el sıkışma yapar.
2.  Bu paketlerin içinde parola **gitmez**, ancak parolanın doğruluğunu kanıtlayan matematiksel veriler (MIC) gider.
3.  Saldırgan bu handshake'i yakalar (`airodump-ng`) ve çevrimdışı (offline) olarak sözlük saldırısı yapar.

---

## 🏴‍☠️ Saldırı Vektörleri

### 1. Deauthentication Attack (Deauth)
Kullanıcıyı ağdan koparmak.
*   **Amaç**: Handshake yakalamak (kullanıcı tekrar bağlanmaya çalışırken yakalarsın) veya Evil Twin'e yönlendirmek.
*   **Komut**: `aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon`

### 2. Evil Twin (Şeytani İkiz)
Hedef ağın aynısından (aynı isim, aynı şifreleme) bir tane daha oluşturup daha güçlü sinyal basmak. Kullanıcı yanlışlıkla size bağlanır.

### 3. PMKID Attack
Client beklemeden, doğrudan modemin kendisinden (Router eğer destekliyorsa) hash bilgisini çekmeye yarayan modern saldırı (WPA2/WPA3).

---

## 📡 Modern Kablosuz Teknolojiler & Hacking

### 1. Bluetooth Low Energy (BLE) Security
Giyilebilir teknoloji ve IoT cihazlarının dili.
- **GATT Sniffing**: Cihazlar arası veri paketlerini havada yakalama.
- **GATT Hijacking**: Bağlantı koptuğu anda araya girme.
- **Araçlar**: `bettercap`, `ubertooth-one`, `gatttool`.

### 2. SDR (Software Defined Radio)
Frekansların içine dalmak.
- **Frequency Replay**: Garaj kapısı veya araç kumandası sinyalini kaydedip tekrar basarak açmak.
- **Jamming**: Bir frekansı gürültüyle boğup sinyali kesmek.
- **Araçlar**: `HackRF One`, `RTL-SDR`, `GNU Radio`.

### 3. RFID & NFC Security
- **Cloning**: Şirket kartlarını veya abonman kartlarını kopyalamak (`Proxmark3`).
- **Skimming**: Yakın mesafeden kredi kartı bilgilerini çekme denemeleri.

---

## 📡 Kablosuz Cephesi: 5G & SDR & LoRaWAN

Siber uzayın görünmez sinyalleri arasında yeni savaş alanları.

### 1. 5G & Hücresel Ağ Güvenliği
- **IMSI Catching (Stingray)**: Mobil cihazları sahte bir baz istasyonuna bağlanmaya zorlayarak konum takibi ve SMS dinleme yapma.
- **Network Slicing Security**: Farklı servisler için ayrılmış ağ dilimleri arasındaki izolasyonun bozulması riski.

### 2. SDR Deep Dive (Software Defined Radio)
Uygun fiyatlı donanımlar (RTL-SDR, HackRF) ile tüm radio spektrumunu dinleme/yayınlama.
- **GPS Spoofing**: Sahte GPS sinyalleri yayınlayarak drone veya gemilerin konumunu saptırma.
- **Signal Replay**: Standart dışı frekanslarda (örn: 433MHz akıllı kumandalar) paket yakalayıp tekrar göndererek yetkisiz erişim sağlama.

### 3. LoRaWAN (Düşük Güçlü Geniş Alan Ağı)
Kilometrelerce ötedeki IoT sensörlerinin kullandığı protokol.
- **Zafiyet**: Cihaz bazlı şifreleme anahtarlarının (AppKey) fabrikasyon/varsayılan olarak bırakılması.

---

## ⚔️ Wireless Hardening (Savunma)

1. **WPA3 Geçişi**: Daha güçlü şifreleme ve offline kırma direnci.
2. **MFP (Management Frame Protection)**: Deauth saldırılarını engellemek için yönetim paketlerini şifreleme.
3. **Hidden SSID**: Bir güvenlik önlemi değildir, sadece "gizli" olduğunu sanırsınız. PNL taraması ile bulunabilir.

---

## 🛠️ Aircrack-ng Suite Cheat Sheet

Kablosuz korsanlığın İsviçre çakısı.

- **airmon-ng start wlan0**: Monitor moda geçiş.
- **airodump-ng wlan0mon**: Etraftaki ağları dinle.
- **airodump-ng --bssid <MAC> --channel <CH> --write handshake wlan0mon**: Hedef odaklı dinleme ve kayıt.
- **aireplay-ng --deauth ...**: Saldırı paketi bas.
- **aircrack-ng handshake.cap -w rockyou.txt**: Yakalanan handshake'i kırmayı dene.

---

## 💻 Sentinel WiFi (Araç Kullanımı)

WPA2 Parola güvenliğini analiz eden ve karmaşık sözlük üreten yardımcı aracımız.

**Konum**: `TOOLS/sentinel_wifi.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_wifi.py -s "MyWifiPassword123"
```
*Parolanın WPA2 standartlarına (uzunluk, karmaşıklık) uygunluğunu test eder.*
