# 📱 MOBİL CEPHESİ: Mobil Güvenlik (Mobile Security)

> "Cebinizdeki cihaz, en büyük sırdaşınız veya en tehlikeli casusunuz olabilir."

---

## 📲 Mobil Güvenlik Alanları

Akıllı telefonlar, geleneksel bilgisayarlardan farklı güvenlik modellerine (Sandboxing, Permissions) sahiptir.

### 1. Android Güvenliği
- **APK Analizi**: `AndroidManifest.xml` zafiyetleri, export edilen activity'ler.
- **Reverse Engineering**: `dex2jar`, `jadx` ile kod analizi.
- **Dynamic Analysis**: `Frida` ve `Drozer` ile runtime manipülasyonu.

### 2. iOS Güvenliği
- **IPA Analizi**: İmzalanmış uygulamaların incelenmesi.
- **Jailbreak Tespiti**: Güvenlik kontrollerini atlatma.
- **Keychain Security**: Hassas verilerin depolanma analizi.

---

## 🚧 Temel Riskler (OWASP Mobile Top 10)

- **Improper Platform Usage**: Android/iOS özelliklerinin yanlış kullanımı.
- **Insecure Data Storage**: Verilerin yerel veritabanlarında şifresiz tutulması.
- **Insecure Communication**: TLS/SSL sertifika pinleme eksiklikleri.
- **Insecure Authentication**: Zayıf oturum yönetimi.

---

## 🛠️ Mobil Arsenal (Tools)

| Araç | Kategori | Kullanım Amacı |
| :--- | :--- | :--- |
| **MobSF** | Framework | Hepsi bir arada mobil zafiyet tarayıcı. |
| **Jadx-GUI** | Decompiler | APK dosyalarını Java koduna dönüştürme. |
| **Frida** | Dynamic | Çalışan uygulamaya kod enjekte etme (Hooking). |
| **Burp Suite** | Proxy | Mobil trafik analizi ve interception. |

---

## 📒 Cheat Sheet: Frida One-Liners (Runtime Hacking)

| Amaç | Komut |
| :--- | :--- |
| **Prosesleri Listele** | `frida-ps -Uai` |
| **Fonksiyon İzle** | `frida-trace -U -i "open*" <package_name>` |
| **SSL Pinning Bypass** | `frida -U -f <package> -l frida-ssl-bypass.js --no-pause` |
| **Script Enjeksiyonu** | `frida -U -n <process_name> -l magic_script.js` |

---

## 🤖 Android Deep Dive: Smali & Bytecode

Java kodunun APK içindeki karşılığı **Smali**'dir. Kaynak kodu görmeseniz bile Smali okuyarak lojiği anlayabilirsiniz.

- **Smali Syntax**:
  - `v0, v1, v2`: Register'lar (Değişken saklama alanları).
  - `invoke-virtual`: Standart fonksiyon çağırma.
  - `const-string`: Bir değişkene metin atama.
- **Modifikasyon**: `apktool d file.apk` ile açıp smali kodunda `if-eqz` (if equals zero) olan bir kontrolü `if-nez` yaparak şifre kontrolünü bypass edebilirsiniz.

---

## 🍎 iOS Security: Mach-O & Jailbreak

iOS ekosistemi Android'e göre daha kapalıdır ancak aynı derecede kırılgandır.

### 1. Mach-O Dosya Yapısı
iOS uygulamalarının (IPA) içindeki ikili dosya formatı.
- **Encryption**: App Store'dan indirilen uygulamalar şifrelidir. Analiz için `frida-ios-dump` gibi araçlarla RAM'den döküm (dump) alınmalıdır.

### 2. Jailbreak Detection Bypass
Uygulamaların root'lu cihazlarda çalışmasını engelleme çabası.
- **Teknikler**: Dosya sistemi kontrolü (`/Applications/Cydia.app`), Cydia port kontrolü veya symbolic link kontrolleri.
- **Bypass**: Frida ile bu kontrollerin yapıldığı `isJailbroken()` fonksiyonlarının dönüş değerini (`return false`) değiştirmek.

---

## 💻 Sentinel Mobile Scout (Placeholder)

Mobil uygulama paketlerini hızlıca taramak için geliştirilecek araç.

**Konum**: `TOOLS/sentinel_mobile.py`
