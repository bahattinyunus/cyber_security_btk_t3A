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
