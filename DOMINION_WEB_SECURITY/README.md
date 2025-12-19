# 🕸️ ÖRÜMCEK AĞI: Web Güvenliği Operasyonları (Web Security)

> "Kodda gizlenen her açık, sisteme açılan bir kapıdır. Biz o kapıları hem bulur hem de mühürleriz."

---

## 🏗️ Modern Web Tehditleri

Web uygulamaları artık sadece HTML/CSS değil; karmaşık API'lar, mikroservisler ve istemci tarafı framework'lerden oluşuyor.

### 1. OWASP Top 10+: Temel Zafiyetler
- **Broken Access Control**: Yetkilendirme hataları.
- **Cryptographic Failures**: Hassas verilerin korunmaması.
- **Injection**: SQL, NoSQL, OS ve LDAP enjeksiyonları.
- **Vulnerable and Outdated Components**: Güncel olmayan kütüphanelerin riskleri.

### 2. Modern Saldırı Vektörleri
- **API Security**: JWT (JSON Web Token) zayıflıkları, Mass Assignment, BOLA (Broken Object Level Authorization).
- **GraphQL**: Query derinliği saldırıları ve introspeksiyon zafiyetleri.
- **Server Side Request Forgery (SSRF)**: İç ağa sızma teknikleri.

---

## 🛠️ Web Arsenal (Araç Seti)

| Araç | Kategori | Kullanım Amacı |
| :--- | :--- | :--- |
| **Burp Suite** | Proxy | HTTP trafiği manipülasyonu ve zafiyet analizi. |
| **OWASP ZAP** | Scanner | Otomatik web tarayıcı. |
| **SQLMap** | Injection | Otomatik SQL enjeksiyon testi. |
| **Postman** | API | API istekleri ve güvenliği testleri. |
| **FFUF** | Fuzzing | Dizin ve parametre keşfi. |

---

## 💻 Sentinel Web Recon (Placeholder)

Bu alanda web zafiyetlerini taramak için özel scriptler geliştirilecek.

**Konum**: `TOOLS/sentinel_web.py`

### 7. SSRF (Server-Side Request Forgery)
Sunucu üzerinden iç ağa veya bulut altyapısına sızma.
- **Cloud Metadata (Bulut Verisi)**:
  - AWS/Google: `http://169.254.169.254/latest/meta-data/` (IAM Key'lerini çalmak için).
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- **İç Ağ Tarama**: Sunucunun ağındaki diğer cihazlara (örn: port 22, 80, 6379-Redis) istek atma.

---

## ⚡ Modern API Güvenliği: GraphQL & REST

### 1. GraphQL Security
Geleneksel REST'ten farklı olarak tek bir endpoint (`/graphql`) üzerinden tüm veriye erişim sağlar.
- **Introspection (İç Gözlem)**: Şemanın (Tabloların, kolonların) dışarıdan sorgulanabilmesi. Kapalı olmalıdır!
  - *Sorgu*: `{ __schema { queryType { name } } }`
- **Injection (Enjeksiyon)**: GraphQL sorgularının içine sızarak yetkisiz veri çekme.

### 2. OAuth & OIDC Flow Vulnerabilities
- **Open Redirect**: Yetkilendirme sonrası yanlış yönlendirme ile `token` çalma.
- **Broken Scope Gradient**: İstenen yetkiden daha fazlasını sessizce ele geçirme.

---

## 📒 Cheat Sheet: JWT Exploitation (JSON Web Token)

| Teknik | Açıklama | Çözüm |
| :--- | :--- | :--- |
| **None Algorithm** | `alg: none` yaparak imzayı devre dışı bırakma. | `none` algoritmasını reddet. |
| **Secret Bruteforce** | Zayıf `secret` anahtarlarını kırmak (`hashcat -m 16500`). | Karmaşık ve uzun anahtar kullan. |
| **Key Confusion** | Asimetrik (RS256) anahtarı simetrik (HS256) olarak zorlamak. | Algoritma kontrolünü sıkı tut. |
| **Token Invalidation** | Çıkış yapılmasına rağmen token'ın hala geçerli olması. | Kara liste (Blacklist) veya kısa ömürlü token kullan. |

---

---

## 🛡️ Tarayıcı Güvenlik Mekanizmaları

Web güvenliğinin en temel ve en karmaşık savunma katmanı tarayıcının kendisidir.

### 1. Same-Origin Policy (SOP)
Bir web sitesinden yüklenen betiğin, başka bir origin'deki (Farklı protokol, host veya port) veriye erişmesini engelleyen temel kuraldır.
- **İstisna**: Görseller, script dosyaları ve stil dosyaları farklı origin'lerden yüklenebilir ancak içeriklerine JS ile erişilemez.

### 2. CORS & CSP Derinlemesine Bakış
- **CORS (Cross-Origin Resource Sharing)**: SOP'yi kontrollü bir şekilde esnetmek için sunucunun "Buna güvenebilirsin" demesi.
  - *Risk*: `Access-Control-Allow-Origin: *` yapılandırması.
- **CSP (Content Security Policy)**: Bir sayfanın hangi kaynaklardan (domainler) veri çekebileceğini belirleyen beyaz liste (Whitelist).
  - *Bypass*: JSONP endpointleri veya "untrusted" CDN'lerin kullanımı ile CSP'yi atlatmak.

### 3. Browser Sandboxing & Isolation
Modern tarayıcılar (Chrome/Edge), her sekmeyi ayrı bir "Sandbox" içinde çalıştırır. Bir sekmedeki zafiyetin işletim sistemine sızmasını engellemek için düşük yetkili prosesler kullanılır.

### 4. V8 Motoru ve JIT Sömürüsü (Advanced)
Chrome'un JS motoru olan V8 üzerindeki bellek yönetim zafiyetleri.
- **JIT (Just-In-Time)**: Dinamik olarak derlenen kodun, optimizasyon hataları (Type Confusion) sonucu bellek güvenliğini bozması.
- **Sandbox Escape**: Renderer prosesindeki bir açıktan faydalanıp, tarayıcı sandbox'ından çıkarak işletim sistemi seviyesinde kod çalıştırma (ACE).
- **Site Isolation**: Her origin (domain) için tamamen farklı işletim sistemi prosesi kullanılarak Spectre gibi yan kanal saldırılarının engellenmesi.

---

## 🔌 API & Mikroservis Güvenliği

Modern uygulamaların birbirleriyle konuştuğu sinir sistemi.

### 1. API Zafiyetleri (OWASP API Top 10)
- **BOLA (Broken Object Level Authorization)**: Bir kullanıcının başka birine ait veriyi (örn: `/api/orders/555`) yetkisiz çekebilmesi.
- **Mass Assignment**: Kayıt veya güncelleme sırasında gönderilen JSON verisine gizli alanlar (örn: `"is_admin": true`) ekleyerek yetki yükseltme.

### 2. Mikroservis Mimarisi Güvenliği
- **mTLS (Mutual TLS)**: Servislerin birbirine güvenmesi için her iki tarafın da sertifika ile kimlik doğrulaması yapması.
- **GraphQL Injection**: Standart SQLi'dan farklı olarak, aşırı karmaşık sorgularla (Deep Nesting) sunucuyu DoS durumuna düşürme veya şema sızıntısı sağlama.
- **API Gateway**: Tüm trafiği karşılayan merkezi noktada hız sınırlama (Rate Limiting) ve JWT (JSON Web Token) doğrulaması.

---

## 🏆 Bug Bounty Metodolojisi & İleri Keşif

Profesyonel bir araştırmacı, zafiyeti bulmadan önce hedefi bir "harita" gibi çıkarır.

### 1. Keşif Zinciri (Recon Chain)
P1/P2 seviyesindeki açıklar genellikle derinlerde saklıdır:
- **Subdomain Discovery**: `Subfinder` + `Httpx` ile çalışan canlı alt alan daları.
- **Parameter Mining**: `Arjun` ile gizli sorgu parametrelerini (örn: `?debug=true`) keşfetme.
- **JS Mining**: Tarayıcıdaki `.js` dosyalarını ayrıştırarak API endpoint'lerini ve gizli anahtarları bulma.

### 2. Gelişmiş Hedef Tespiti
- **ASN Discovery**: Bir şirketin tüm IP bloklarını (`ASN`) bularak kapsam dışı kalmış eski sunucuları tespit etme.
- **Google Dorking for Bounty**:
  - `site:target.com ext:log | ext:txt | ext:conf` (Log ve konfigürasyon sızıntıları).
  - `site:target.com inurl:admin | inurl:staging` (Test ortamları).

### 3. Bug Bounty Cheat Sheet: P1/P2 Örüntüleri
- **IDOR**: `GET /api/user/100` -> `GET /api/user/101` (Başka kullanıcının verisi).
- **Secondary-Order Vulnerabilities**: Bir yerde girilen verinin, sistemin başka bir yerinde (örn: admin panelinde) çalışması.

---

## 🛡️ API Güvenliği Derin Dalış (Modern API Risks)

Mikro hizmet mimarilerinin kalbi olan API'lar, web güvenliğinin en kritik cephesidir.

### 1. BOLA (Broken Object Level Authorization)
OWASP API Top 10'da 1 numara. Bir kullanıcının, yetkisi olmayan bir nesnenin (örn: `/api/orders/200`) ID'sini değiştirerek başka birinin verisine erişmesi.
- **Çözüm**: Her istekte, kullanıcının o spesifik nesne ID'sine erişim hakkı olup olmadığı kontrol edilmelidir.

### 2. Mass Assignment (Toplu Atama)
API'ya gönderilen verilerin, sunucu tarafındaki modellerle doğrudan eşleşmesi sonucu, kullanıcının değiştirmemesi gereken alanları (örn: `is_admin: true`) değiştirebilmesi.

### 3. Shadow & Zombie API'lar
- **Shadow API**: Dokümante edilmemiş veya unutulmuş eski sürümlere ait API uç noktaları. Genellikle daha az korumaya sahiptirler.

---


## 📘 Web Doktrini: Güvenli Kodlama

1. **Giriş Filtreleme**: Kullanıcıdan gelen her veri kirli kabul edilir.
2. **Çıktı Kodlama**: XSS'i önlemek için veriler tarayıcıya basılmadan önce kodlanır.
3. **Prensip**: En az yetki prensibi (Least Privilege) veritabanı bağlantılarında da uygulanır.
