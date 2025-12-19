# 🌐 ŞEBEKE: Altyapı Anatomisi (The Grid)

> "Bütün siber savaşlar nihayetinde kablolar, dalgalar ve protokoller üzerinden yürür. Temeli bilmeyen, kaleyi savunamaz."

---

## 🏗️ OSI Modeli: Evrensel Dil

İnternetin nasıl konuştuğunu anlamak için yedi katmanı ezbere bilmek gerekir.

1.  **Fiziksel (Physical)**: Kablolar, fiber optikler, radyo dalgaları. (Bitler)
2.  **Veri Bağlantısı (Data Link)**: MAC adresleri, Switch'ler. (Çerçeveler/Frames)
3.  **Ağ (Network)**: IP adresleri, Router'lar. (Paketler/Packets) -> *Siber güvenliğin en yoğun olduğu katman.*
4.  **Taşıma (Transport)**: TCP ve UDP. (Segmentler)
5.  **Oturum (Session)**: Bağlantıların yönetimi.
6.  **Sunum (Presentation)**: Şifreleme (SSL/TLS), formatlama.
7.  **Uygulama (Application)**: HTTP, FTP, SMTP. Kullanıcının gördüğü yüz.

---

## 🤝 TCP/IP ve Handshake

Bir bağlantının nasıl kurulduğunu anlamak, port taramalarını anlamanın anahtarıdır.

### 3-Way Handshake (Üçlü El Sıkışma)
1.  **SYN**: İstemci: "Merhaba, konuşabilir miyiz?"
2.  **SYN-ACK**: Sunucu: "Merhaba, evet konuşabiliriz."
3.  **ACK**: İstemci: "Tamam, başlıyorum."

*Saldırganlar bu süreci manipüle ederek (örn: SYN Flood) sistemleri çökertir veya gizli taramalar yapar.*

---

## 🚪 Limanlar ve Tehlikeler (Common Ports)

Her port açılmayı bekleyen bir kapıdır.

| Port | Protokol | İşlev | Risk |
| :--- | :--- | :--- | :--- |
| **21** | FTP | Dosya Transferi | Şifresiz iletişim, veri çalınabilir. |
| **22** | SSH | Güvenli Kabuk | Brute Force saldırılarının bir numaralı hedefi. |
| **23** | Telnet | Uzaktan Erişim | **ASLA KULLANMA.** Tamamen şifresizdir. |
| **53** | DNS | Alan Adı Çözme | DNS Tunneling ile veri kaçırma. |
| **80** | HTTP | Web | SQLi, XSS gibi web saldırıları. |
| **443** | HTTPS | Güvenli Web | Trafik şifreli olduğu için saldırıyı tespit etmek zordur. |
| **3389** | RDP | Uzak Masaüstü | Ransomware gruplarının favori giriş noktası. |

---

## 🛠️ Ağ Analiz Araçları

- **Wireshark**: Ağ trafiğini atomlarına ayırır. Her paketin içini gösterir.
- **Tcpdump**: Komut satırı paket yakalama aracı. Hızlı ve ölümcül.
- **Cisco Packet Tracer**: Ağ topolojilerini simüle etmek için laboratuvar.
- **Ntopng**: Ağ trafiğinin görselleştirilmesi ve anomali tespiti.

---

## 🛡️ Altyapı Savunma Stratejileri

### 1. Zero Trust Network Access (ZTNA)
"Asla güvenme, her zaman doğrula."
- Cihaz ve kullanıcı kimliği ağın içinden gelse bile doğrulanır.
- Mikro-segmentasyon ile yanal hareket (lateral movement) kısıtlanır.

### 2. BGP Hijacking & IPv6 Güvenliği
- **BGP Hijacking**: İnternet trafiğinin sahte rotalarla saldırganın üzerine çekilmesi.
- **IPv6 RA Guard**: IPv6 ağlarında sahte "Router Advertisement" paketlerini engelleme.

---

## 🧠 Paket Analiz Derinliği

> **"Paketler yalan söylemez."**

---

## 📓 Ağ Adli Bilişim Rehberi (Network Forensics)

Paketler yalan söylemez, ancak onları okumayı bilmek gerekir.

### 🦈 Wireshark Filtreleme Sanatı
Gürültüyü azaltmak için temel filtreler.

| Filtre | Açıklama |
| :--- | :--- |
| `ip.addr == 192.168.1.5` | Sadece belirli bir IP'yi izle. |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | Sadece SYN paketleri (Port tarama tespiti). |
| `http.request.method == "POST"` | HTTP POST istekleri (Giriş denemeleri/Veri çıkışı). |
| `frame contains "password"` | Paket içeriğinde "password" kelimesini ara (Güvensiz trafik). |
| `dns.flags.response == 0` | Başarısız DNS sorguları (DGA zafiyeti tespiti). |

### 🔢 CIDR Referans Tablosu (Subnetting)
Hızlı alt ağ hesaplamaları.

| CIDR | Subnet Mask | Toplam IP | Kullanılabilir Host |
| :--- | :--- | :--- | :--- |
| **/32** | 255.255.255.255 | 1 | 1 (Host Route) |
| **/30** | 255.255.255.252 | 4 | 2 (P2P Link) |
| **/29** | 255.255.255.248 | 8 | 6 |
| **/24** | 255.255.255.0 | 256 | 254 (Standart LAN) |
| **/16** | 255.255.0.0 | 65,536 | 65,534 |

### 🔌 Güvenli Olmayan Portlar
Bu portları ağınızda açık görürseniz alarm verin.

- **21 (FTP)**: Şifresiz dosya aktarımı. -> *Alternatif: SFTP (22)*
- **23 (Telnet)**: Şifresiz yönetim. -> *Alternatif: SSH (22)*
- **80 (HTTP)**: Şifresiz web. -> *Alternatif: HTTPS (443)*
- **445 (SMB)**: Wannacry ve türevlerinin yayılma yolu. *İnternete asla açma.*

---

## 🧪 Advanced Packet Crafting & CLI

Arayüzler yavaştır. Terminal hızlıdır.

### 🦈 TShark (CLI Wireshark) Cheatsheet
GUI olmadan trafik analizi.

| Komut | İşlev |
| :--- | :--- |
| `tshark -D` | Arayüzleri listele. |
| `tshark -i eth0 -w capture.pcap` | Trafiği dosyaya kaydet. |
| `tshark -r capture.pcap -Y "http.request"` | Pcap dosyasını oku ve sadece HTTP isteklerini göster. |
| `tshark -r capture.pcap -T fields -e ip.src -e dns.qry.name` | Sadece Kaynak IP ve DNS sorgularını sütun olarak dök. |

---

## 📞 Altyapı ve Modern İletişim Güvenliği

Ağlar geliştikçe, sadece veri değil ses ve vizyon da ağın bir parçası haline geldi.

### 1. VOIP & Birleşik İletişim (UC)
SIP/RTP protokolleri üzerinden yürütülen sesli iletişim sistemleri.
- **SIP Enumeration**: Hedef santraldeki (PBX) kullanıcıları `svwar` ile tespit etme.
- **RTP Injection**: Devam eden bir sesli görüşmeye sahte ses paketleri enjekte etme.
- **Kayıt Çalma (Eavesdropping)**: Şifrelenmemiş SIP trafiğini dinleyerek görüşmeleri kaydetme.

### 2. SD-WAN (Software-Defined WAN)
Geleneksel router'lar yerine yazılım tabanlı yönetilen geniş alan ağları.
- **Zafiyet**: Merkezi yönetim panelinin (Controller) ele geçirilmesi tüm ağın izolasyonunun bozulmasına neden olur.
- **Güvenlik**: IPsec tünellerinin ve uç nokta (Edge) cihazlarının konfigürasyon bütünlüğü.

### 3. Edge Security: CDN & WAF & DDoS
İnternet ile kurum ağı arasındaki ilk savunma hattı.
- **CDN (Content Delivery Network)**: Statik içeriği ön belleğe alarak ana sunucuyu (Origin) gizler.
- **WAF (Web Application Firewall)**: L7 seviyesinde (HTTP) saldırıları (SQLi, XSS) bloklar.
- **DDoS Mitigation**: Anycast ağları kullanarak trafik yükünü küresel ölçekte dağıtma ve temizleme.

---

## 🌐 Egemen Ağ Altyapısı ve Kriz İletişimi (Sovereign Mesh)

Küresel internetin kesildiği veya sansürlendiği olağanüstü durumlarda, iletişimin devamlılığını sağlayan egemen yapılar.

### 1. Egemen Mesh Network (LoRa & Meshtastic)
İnternet altyapısına ihtiyaç duymadan, düşük enerji ve uzun menzilli radyo dalgaları üzerinden kurulan "halk ağı".
- **LoRa (Long Range)**: Kilometrelerce uzaktan metin tabanlı veri aktarımı.
- **Meshtastic**: Cihazların birbirini "router" olarak kullanarak ağı genişlettiği, merkezi olmayan (decentralized) iletişim protokolü.
- **Kullanım**: Doğal afetler veya siber savaş anlarında koordinasyonun sürdürülmesi.

### 2. Kritik Servislerin Millileştirilmesi (DNS & NTP)
- **Sovereign DNS**: Dış dünyaya bağlı kalmadan çalışabilen yerel DNS root sunucuları. Alan adı çözümlemesinin küresel kesintilerden etkilenmemesi.
- **Sovereign NTP**: Zaman senkronizasyonu için atomik saatlere dayalı yerel zaman sunucuları. (Finans ve kriptografi için kritik).

### 3. Out-of-Band (OOB) Yönetimi
Kritik cihazların (Switch, Firewall, Server) yönetim arayüzlerini, asıl veri trafiğinden tamamen izole edilmiş, fiziksel olarak ayrı bir ağ üzerinden yönetme disiplini.
- **Güvenlik**: Bir saldırgan ağ trafiğini ele geçirse dahi, cihazların yönetim katmanına erişemez.

---


### 🐍 Scapy (Python ile Paket Manipülasyonu)
Kendi protokolünü yaz veya trafiği değiştir.

**Örnek: Özel bir SYN Paketi Oluşturma**

```python
from scapy.all import *

# IP Katmanı: Hedef 192.168.1.50
ip_layer = IP(dst="192.168.1.50")

# TCP Katmanı: Port 80, SYN Bayrağı (S), Rastgele Seq Numarası
tcp_layer = TCP(dport=80, flags="S", seq=12345)

# Paketi Birleştir ve Gönder
packet = ip_layer / tcp_layer
send(packet)
```
*Bu script, güvenlik duvarlarını test etmek için özel bayraklara sahip paketler üretmenizi sağlar.*
