# 🔌 THE SILICON: Donanım Hacking (Hardware Security)

> "Yazılımı güncelleyebilirsin, ama donanımı değiştiremezsin."

---

## 🎛️ Donanım Arayüzleri (Arka Kapılar)

IoT cihazlarının üzerindeki gizli kapılar.

| Arayüz | Pin Sayısı | Açıklama | Saldırı Vektörü |
| :--- | :--- | :--- | :--- |
| **UART** | 4 (TX, RX, VCC, GND) | Seri Konsol. Genellikle root shell verir. | Baud rate bulup bağlanmak. |
| **JTAG** | 4-20 | İşlemci Debug portu. | Firmware okuma/yazma, hafıza manipülasyonu. |
| **SPI** | 4 (MISO, MOSI, CLK, CS) | Flash hafıza çipleriyle konuşur. | Firmware dump etmek (BIOS kopyalamak). |
| **I2C** | 2 (SDA, SCL) | Sensörler ve EEPROM'lar arası iletişim. | Veri trafiğini dinlemek. |

---

## 🧰 Donanım Çantası

Fiziksel dünyayı hacklemek için gereken aparatlar.

- **USB-TTL Dönüştürücü (FTDI)**: UART bağlantısı için.
- **Logic Analyzer**: 1 ve 0'ları görerek protokolü anlamak için.
- **Bus Pirate / Shikra**: Çok amaçlı (SPI/I2C/UART) konuşma aracı.
- **J-Link**: JTAG debug işlemleri için profesyonel araç.
- **Multimetre**: Pinlerin voltajını ve kısa devreleri bulmak için.

---

## ⚡ Attack Vectors

### 1. Firmware Dumping (SPI)
Cihazın beynini kopyalamak.
1. Flash çipine bir klips (SOIC8 Clip) takılır.
2. `flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin` komutu ile tüm yazılım çekilir.
3. `binwalk -e firmware.bin` ile dosya sistemi (Linux) dışarı çıkarılır.

### 2. Glitching (Fault Injection)
İşlemciye tam doğru zamanda voltaj dalgalanması vererek "karar mekanizmasını" bozmak.
*   Örn: "Şifre doğru mu?" kontrolü yaparken voltajı düşürürseniz, işlemci yanlışlıkla "Evet" diyebilir.

### 3. BadUSB (Rubber Ducky)
Klavye taklidi yapan zararlı USB'ler.
*   Bilgisayara takıldığı anda saniyede 1000 tuş basarak arka kapı açar.

---

## 💻 Sentinel Serial (Araç Kullanımı)

UART bağlantılarını simüle eden seri konsol aracı.

**Konum**: `TOOLS/sentinel_serial.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_serial.py --port /dev/ttyUSB0 --baud 115200
```
*Bağlantı hızını (Baud Rate) otomatik tespit etmeye çalışır ve konsol açar.*
