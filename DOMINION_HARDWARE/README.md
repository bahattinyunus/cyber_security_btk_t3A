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

## ⚡ Attack Vectors & Methodologies

### 1. JTAG Enumeration: İşlemcinin Kilidini Açmak
Eğer UART kapalıysa, bir sonraki hedef JTAG'dir.
1.  **Pinout Bulma**: JTAGulator veya multimetre ile `TDI`, `TDO`, `TCK`, `TMS` pinleri tespit edilir.
2.  **Bağlantı**: `OpenOCD` ve bir `J-Link` veya `FT232H` kullanılarak işlemciye bağlanılır.
3.  **Hafıza Okuma**: `mdw 0x08000000 100` komutu ile bootloader veya firmware'in ilk baytları okunur.

### 2. Firmware Dumping (SPI)
Cihazın beynini kopyalamak.
1. Flash çipine bir klips (SOIC8 Clip) takılır.
2. `flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin` komutu ile tüm yazılım çekilir.
3. `binwalk -e firmware.bin` ile dosya sistemi (Linux) dışarı çıkarılır.

### 3. Fault Injection: Donanımsal "Beyin Sarsıntısı"
İşlemciye tam doğru zamanda (Clock Glitching) veya voltaj dalgalanması (Voltage Glitching) vererek karar mekanizmasını bozmak.
- **Clock Glitching**: İşlemcinin saat sinyallerini manipüle ederek bir komutun atlanmasını sağlamak (örn: `if (password_correct)` kontrolünü atlamak).
- **Voltage Glitching**: Besleme voltajını anlık düşürerek işlemcinin hatalı sonuç üretmesini zorlamak.

### 4. Side-Channel Attacks (Yan Kanal Saldırıları)
Cihaza dokunmadan, yaydığı enerjiden bilgi çalma.
- **Power Analysis (DPA/SPA)**: İşlemcinin şifreleme yaparken çektiği akımı ölçerek anahtarı (key) tahmin etmek.
- **Electromagnetic Analysis (EMA)**: İşlemcinin yaydığı elektromanyetik dalgaları dinleyerek içerideki işlemleri anlamak.

### 5. BadUSB (Rubber Ducky)
Klavye taklidi yapan zararlı USB'ler.
- Bilgisayara takıldığı anda saniyede 1000 tuş basarak arka kapı açar.
- **Payload**: `DELAY 1000`, `GUI r`, `STRING powershell -enc ...`, `ENTER`.

---

## 🏗️ Hardware Root of Trust (Güvenli Çekirdek)

Donanımı savunmak için kullanılan modern teknolojiler:
- **TPM (Trusted Platform Module)**: Kriptografik anahtarların güvenli saklandığı donanım çipi.
- **Secure Boot**: Sadece imzalı firmware'in çalışmasına izin veren zincirleme doğrulama.
- **PUF (Physically Unclonable Function)**: Silikonun üretimindeki mikroskobik farklılıklardan benzersiz bir "parmak izi" üretilmesi.

---

## 📡 IoT & Gömülü Protokoller

Modern IoT cihazları sadece kablo ile değil, özel hava protokolleri ile konuşur.

### 1. MQTT (Message Queuing Telemetry Transport)
Akıllı ev sistemlerinin "tweet" kanalı.
- **Zafiyet**: Kimlik doğrulaması olmadan `$SYS/#` konusuna abone olarak tüm sistem verilerini dinleme.
- **Saldırı**: Mesaj enjeksiyonu ile kapıları açma veya ışıkları kapatma.

### 2. Zigbee & Z-Wave
Düşük enerjili kablosuz ağlar.
- **Araç**: `KillerBee` framework'ü ile paket yakalama (sniffing) ve tekrar (replay) saldırıları.

---

## ⚙️ Endüstriyel Sistemler: ICS/SCADA Güvenliği

Fabrikalar, enerji santralleri ve kritik altyapıların siber güvenliği.

### 1. Endüstriyel Protokoller
IT dünyasından farklı olarak, gerçek zamanlı ve düşük gecikmeli çalışan sistemler:
- **Modbus**: En eski ve en yaygın protokol. Kimlik doğrulaması yoktur, paket enjeksiyonu ile cihaz durdurulabilir.
- **S7Comm (Siemens)**: Fabrika otomasyonunda kullanılan PLC'lerin (Programlanabilir Mantık Denetleyici) dili.
- **DNP3**: Elektrik şebekeleri ve su yönetim sistemlerinde kullanılan dayanıklı protokol.

### 2. Purdue Modeli (Katmanlı Mimari)
Endüstriyel ağların güvenliğini sağlamak için kullanılan standart hiyerarşi:
- **Seviye 0-1**: Sensörler ve PLC'ler (Fiziksel süreç).
- **Seviye 2-3**: Operatör panelleri (SCADA) ve kontrol merkezi.
- **Level 3.5 (IDMZ)**: IT ve OT dünyasını ayıran en kritik güvenlik katmanı (Industrial DMZ).

### 3. PLC Güvenliği & Saldırı Vektörleri
- **Logic Manipulation**: PLC'ye giden kontrol kodunu (Ladder Logic/SCL) değiştirerek fiziksel süreci manipüle etme (Stuxnet örneği).
- **Network Discovery**: `nmap --script s7-info -p 102 <IP>` ile Siemens PLC versiyon ve CPU bilgisini toplama.

---

## 🧠 BCI ve İleri Biyometrik Güvenlik

Biyolojik ve dijital dünyanın kesişimindeki siber riskler.

### 1. BCI (Beyin-Bilgisayar Arayüzü) Güvenliği
Beyin sinyallerini (EEG/nIR) okuyan cihazların siber güvenliği.
- **Brainjacking**: Nöral cihazların manipüle edilerek kullanıcıya zarar verilmesi veya zihinsel verilerin çalınması riski.
- **Signal Privacy**: Beyin dalgalarından kişinin tercihlerini, duygularını veya PIN kodlarını tahmin etme denemeleri.

### 2. İleri Biyometrik Atlatma (Biometric Spoofing)
- **Pulse Detection Bypass**: Parmak izi veya damar içi (vein scan) okuyucuların sahte ve canlı olmayan materyallerle kandırılması.
- **3D Face Masking**: Derinlik algılayan yüz tanıma sistemlerini, 3D maskeler ve kızılötesi ışık manipülasyonu ile atlatma.

### 3. Bio-Hacking & DNA Güvenliği
Biyolojik veri depolama ve sentetik biyoloji sistemlerine yönelik siber tehditler.
- **Synthetic DNA Malware**: Sentetik DNA sarmalları içine kodlanmış zararlı yazılımlar. DNA sekanslama cihazları bu veriyi işlerken tampon bellek taşması (buffer overflow) tetiklenebilir.
- **Laboratory Automation (Bio-ISAC)**: Genetik düzenleme ve ilaç üretim tesislerindeki laboratuvar robotlarının ve otomasyon yazılımlarının siber sabotaj riskleri.
- **DNA Data Storage Privacy**: DNA üzerinde saklanan devasa verilerin şifrelenmesi ve genetik gizliliğin biyoinformatik tekniklerle korunması.

---
- **Exploitation Methodology**:
    1. **Recon**: Protokol tespiti (Modbus:502, S7:102, Ethernet/IP:44818).
    2. **Analysis**: Sistemin "Stop" veya "Run" moduna alınabilirliğinin testi.
    3. **Injection**: Sahte sensör verileri göndererek (Spoofing) operatör panelini (HMI) yanıltma.
    4. **Persistence**: PLC firmware'ine arka kapı (backdoor) yerleştirerek kalıcılık sağlama.

### 4. Endüstriyel Bal Arıları (Industrial Honeypots)
Kritik altyapılara sızmaya çalışan saldırganları tespit etmek için sahte PLC ve SCADA arayüzleri kurma.
- **Conpot**: Gerçek zamanlı olarak Modbus, S7 ve BACnet servislerini simüle eden düşük etkileşimli endüstriyel bal kutusu.

---

## 🔬 Firmware Emülasyonu (QEMU Analysis)

Elimizde fiziksel donanım yoksa, yazılımını simüle edebiliriz.

1.  **Dinamik Analiz**: Çekilen firmware (`rootfs`) içindeki `bin/httpd` dosyasını QEMU üzerinde çalıştırarak zafiyetli web arayüzünü canlı olarak test etmek.
2.  **Chroot Metodu**: `sudo chroot . qemu-mips-static bin/ls` komutu ile çapraz mimarili dosyaları kendi sisteminizde koşturmak.

---

## 💻 Sentinel Serial (Araç Kullanımı)

UART bağlantılarını simüle eden seri konsol aracı.

**Konum**: `TOOLS/sentinel_serial.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_serial.py --port /dev/ttyUSB0 --baud 115200
```
*Bağlantı hızını (Baud Rate) otomatik tespit etmeye çalışır ve konsol açar.*
