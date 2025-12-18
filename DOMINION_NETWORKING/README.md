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

> **"Paketler yalan söylemez."**
