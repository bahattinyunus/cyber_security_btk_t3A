# 🔐 THE CIPHER: Şifre Bilimi (Cryptography)

> "Matematik evrenin dilidir. Kriptografi ise bu dilin en karanlık şiiridir."

---

## 🗝️ Hashing vs Encryption (Kavram Kargaşası)

Bu ikisi aynı şey değildir. Bir güvenlik uzmanı ASLA karıştırmamalıdır.

| Özellik | Encryption (Şifreleme) | Hashing (Özetleme) |
| :--- | :--- | :--- |
| **Yön** | Çift Yönlü (Geri Çevrilebilir) | Tek Yönlü (Geri Çevrilemez) |
| **Amaç** | Gizlilik (Veriyi saklamak) | Bütünlük (Verinin değişmediğini kanıtlamak) |
| **Anahtar** | Var (Public/Private veya Simetrik) | Yok (Salt kullanılabilir) |
| **Çıktı Boyutu** | Veriye göre değişir | Sabittir (Örn: SHA256 hep 64 karakterdir) |
| **Örnekler** | AES, RSA, DES | MD5, SHA-256, Bcrypt |

---

## 🧬 Hash Örnekleri (Tanıma Rehberi)

Bir hash gördüğünüzde ne olduğunu anlamalısınız.

- **MD5** (32 Karakter): `5d41402abc4b2a76b9719d911017c592` (Kırılması çok kolay, ASLA kullanma!)
- **SHA-1** (40 Karakter): `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` (Güvensiz)
- **SHA-256** (64 Karakter): `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` (Standart)
- **NTLM** (32 Karakter): `b4b9b02e6f09a9bd760f388b67351e2b` (Windows Parolaları)

---

## 🔨 Cracking: Kırma Sanatı

Hash'ler "geri çevrilmez" ama "tahmin edilebilir".

### 🐈 Hashcat Cheat Sheet
Dünyanın en hızlı parola kırıcısı.

| Mod | Hash Türü | Komut |
| :--- | :--- | :--- |
| **0** | MD5 | `hashcat -m 0 -a 0 hashes.txt wordlist.txt` |
| **100** | SHA1 | `hashcat -m 100 -a 0 hashes.txt wordlist.txt` |
| **1000** | NTLM | `hashcat -m 1000 -a 0 hashes.txt wordlist.txt` |
| **3200** | Bcrypt | `hashcat -m 3200 -a 0 hashes.txt wordlist.txt` |

*   `-a 0`: Sözlük Saldırısı (Wordlist)
*   `-a 3`: Brute Force (Tüm kombinasyonlar)

### 🔪 John the Ripper (JtR)
Otomatik algılama ustası.

```bash
# Otomatik kırma
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Kırılanları görme
john --show hashes.txt
```

## 🔬 İleri Kriptografi Uygulamaları

### 1. Elliptic Curve Cryptography (ECC)
Geleneksel RSA yerine kullanılan, çok daha küçük anahtar boyutlarıyla aynı güvenliği sağlayan teknoloji.
- **Avantaj**: Daha az CPU gücü ve depolama alanı gerektirir (Örn: 256-bit ECC, 3072-bit RSA'ya eşittir).
- **Kullanım**: Bitcoin, Ethereum, TLS 1.3 (ECDHE).

### 2. Zero-Knowledge Proofs (ZKP - Sıfır Bilgi Kanıtı)
"Bilginin kendisini paylaşmadan, o bilgiye sahip olduğunu kanıtlama" sanatı.
- **Senaryo**: Bir web sitesine şifrenizi göndermeden, şifreyi bildiğinizi matematiksel olarak kanıtlarsınız.
- **Kripto Para**: Zcash ve Monero gibi gizlilik odaklı coinlerin temelidir.

### 3. Homomorphic Encryption
Şifrelenmiş veri üzerinde, veriyi açmadan işlem yapabilme (Örn: Şifreli iki sayıyı toplayıp sonucu yine şifreli olarak almak). Bulut bilişimin geleceğidir.

---

## ⛓️ Blockchain & Web3 Güvenliği

Kriptografinin en popüler ve en riskli uygulama alanı.

### 1. Akıllı Kontrat Zafiyetleri (Smart Contract Bugs)
Kodun kanun olduğu bir dünyada, mantık hatası telafi edilemez.
- **Reentrancy (Yeniden Giriş)**: Bir fonksiyonun işlemi bitmeden tekrar çağrılarak (recursive) bakiyenin boşaltılması.
- **Oracle Manipulation**: Fiyat verisi sağlayan mekanizmaların manipüle edilerek DeFi borç verme protokollerinin dolandırılması.

### 2. DeFi Saldırı Desenleri: Flash Loan Attacks
Aynı blok içinde milyonlarca dolar borç alıp, bir protokoldeki fiyatı manipüle ederek kar elde edip borcu geri ödeme saldırıları.

### 3. Blockchain Forensics (Blokzincir Adli Bilişimi)
Kamuya açık defterler üzerinden fon takibi.
- **Mixers**: İzleri gizlemek için kullanılan servisler (örn: Tornado Cash).
- **Tracking**: `Chainalysis` benzeri metodlarla "şüpheli" cüzdanların borsalara girdiği anın tespiti.

---

## ⚛️ Kuantum Bilgi Güvenliği (Quantum Security)

Kuantum bilgisayarların tehdidine karşı fizik kurallarıyla korunan yeni nesil kriptografi.

### 1. Kuantum Anahtar Dağıtımı (QKD - BB84)
İki tarafın, kuantum mekaniği kurallarını (Fotonların polarizasyonu) kullanarak, arada dinleme (eavesdropping) yapılıp yapılmadığını kesin olarak anlayabildiği anahtar değişimi.
- **Dinamik**: Birisi fiziksel kanalı dinlemeye çalıştığında, fotonların kuantum durumu değişir ve bu durum taraflarca anında tespit edilir.

### 2. PQC Uygulama ve Göç (Practical Migration)
Kuantum sonrası algoritmaların (`Kyber`, `Dilithium`) mevcut sistemlere entegrasyonu.
- **Hybrid Cryptography**: Eski ve yeni algoritmaların aynı anda kullanılması; böylece her iki dünyanın da güvenliğinden faydalanılması (Örn: `RSA` + `Kyber`).
- **Geçiş Zorlukları**: İmza boyutlarının artması ve daha yüksek işlem gücü gereksinimi.

---

## 🏛️ Public Key Infrastructure (PKI)

İnternetin güvenliği, "güven zinciri" üzerine kuruludur.

1.  **CA (Certificate Authority)**: Kimliğinizi doğrulayan güvenilir kurum (örn: Let's Encrypt, DigiCert).
2.  **Digital Certificate (X.509)**: "Bu sunucu gerçekten `google.com`dur" diyen imzalı dijital belge.
3.  **Root Certificates**: Tarayıcınızda önceden yüklü olan, CA'lara güvenmenizi sağlayan ana sertifikalar.

### SSL/TLS Handshake: Sırrı Paylaşma
- İstemci merhaba der (`Client Hello`).
- Sunucu sertifikasını gönderir.
- İstemci sertifikayı doğrular ve bir "oturum anahtarı" (session key) oluşturmak için asimetrik şifrelemeyi (RSA/Diffie-Hellman) kullanır.
- Görüşme artık simetrik şifreleme (AES) ile devam eder.

---

### 1. Kuantum Tehdidinin Mekaniği (Quantum Mechanics of Attacks)
Klasik kriptografiyi bitirecek olan iki ana algoritma:
- **Shor'un Algoritması**: Büyük sayıların asal çarpanlarına ayrılması (Integer Factorization) ve Ayrık Logaritma (Discrete Logarithm) problemlerini polinom zamanda çözer. Bu, günümüzde interneti ayakta tutan **RSA**, **Diffie-Hellman** ve **ECC** (Eliptik Eğri) sistemlerinin anında kırılması demektir.
- **Grover'ın Algoritması**: Yapılandırılmamış veri setlerinde aramayı hızlandırır. Simetrik şifreleme anahtarlarının (AES) "brute-force" süresini karekök oranında azaltır.
  - *Sonuç*: AES-128 artık güvenli değildir (AES-64 seviyesine iner). Kuantum direnci için **AES-256** standart hale gelmelidir (Anahtar boyutu iki katına çıkarılmalıdır).

### 2. CRYSTALS-Kyber (Anahtar Kapsülleme - KEM)
Kyber, güvenli anahtar değişimi için tasarlanmış bir Lattice-based algoritmadır.
- **Matematiksel Temel**: Learning With Errors (LWE) probleminin bir varyasyonu olan Module-LWE üzerine kuruludur.
- **Kullanım**: TLS handshake sırasında simetrik anahtarların (AES) güvenli bir şekilde paylaşılmasını sağlar.
- **Parametreler**: Kyber-512 (AES-128 güvenliği), Kyber-768 (AES-192), Kyber-1024 (AES-256).

### 2. CRYSTALS-Dilithium (Dijital İmzalar)
Dijital kimlik doğrulaması ve yazılım imzalama için seçilen ana post-kuantum algoritmasıdır.
- **Mekanizma**: Fiat-Shamir with Aborts tekniğini kullanır.
- **Karakteristik**: İmza boyutları klasik algoritmalara (RSA/ECDSA) göre çok daha büyüktür (Dilithium-2 için ~2.4KB).
- **Entegrasyon**: Ağ paketlerinin MTU limitlerini zorlayabileceği için protokol seviyesinde (örn: IKEv2, TLS 1.3) parçalı paketleme (fragmentation) desteği gerektirir.

### 3. Kuantum Göçü ve Hibrit Mimari (Hybrid Design)
"Harvest Now, Decrypt Later" (HNDL) riskine karşı önerilen geçiş mimarisi.
- **Yapı**: Klasik bir algoritma (örn: ECDH) ve kuantum sonrası bir algoritma (örn: Kyber) seri olarak bağlanır. Bir taraf kırılsa bile diğeri veriyi korur.
- **Kripto-Çeviklik (Crypto-Agility)**: Uygulamanın, yazılım kodunu değiştirmeden konfigürasyon üzerinden yeni algoritmalara geçebilme yeteneği.

## 🤐 Sıfır Bilgi Kanıtları (Zero-Knowledge Proofs - ZKP)

Bir tarafın (kanıtlayıcı), bir bilginin içeriğini açıklamadan, o bilgiye sahip olduğunu karşı tarafa (doğrulayıcı) ispatlamasını sağlayan kriptografik protokoller.

### 1. zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge)
En yaygın ZKP türüdür. Kanıtlar küçüktür ve doğrulanması çok hızlıdır.
- **Trusted Setup**: Sistemin başlaması için "güvenilir bir kurulum" gerektirir (CRS - Common Reference String).
- **Kullanım**: Gizlilik odaklı kripto paralar (Zcash) ve kimlik doğrulamasında parolanın kendisini göndermeden parola sahipliğini kanıtlama.

### 2. zk-STARKs (Zero-Knowledge Scalable Transparent Argument of Knowledge)
SNARKs'ın daha ölçeklenebilir ve güvenilir kurulum gerektirmeyen versiyonudur.
- **Şeffaflık**: Güvenilir kurulum (trusted setup) gerektirmez, bu da merkeziyetsizliği artırır.
- **Kuantum Direnci**: Kuantum bilgisayarlara karşı dayanıklı olduğu düşünülmektedir.

### 3. Uygulama Alanları
- **Gizli Kimlik Yönetimi**: Yaşınızı kanıtlamak için doğum tarihinizi paylaşmadan sadece "18 yaşından büyük" olduğunuzun kanıtını sunmak.
- **Veri Güvenliği**: Hassas verileri bulut üzerinde, verinin kendisini bulut sağlayıcısına göstermeden işlemek.

---
## 🖼️ Steganography (Veri Gizleme)

Veriyi şifrelemek dikkat çeker. Veriyi *gizlemek* ise sanattır.

**Steghide Kullanımı**:
Resim veya ses dosyalarının içine metin gömün.

1.  **Gömme (Embed)**:
    ```bash
    steghide embed -cf manzara.jpg -ef gizli_mesaj.txt
    ```
2.  **Çıkarma (Extract)**:
    ```bash
    steghide extract -sf manzara.jpg
    ```

---

## 💻 Sentinel Hasher (Araç Kullanımı)

Hızlıca hash üretmek veya dosya bütünlüğünü doğrulamak için Python aracımız.

**Konum**: `TOOLS/sentinel_hasher.py`

**Kullanım**:
```bash
# String Hashleme
python3 TOOLS/sentinel_hasher.py -s "SüperGizliParola"

# Dosya Hashleme
python3 TOOLS/sentinel_hasher.py -f malware.exe
```
