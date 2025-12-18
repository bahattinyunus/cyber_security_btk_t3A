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
