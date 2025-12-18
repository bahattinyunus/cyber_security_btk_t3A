# ☁️ THE SKY: Bulut Güvenliği (Cloud Security)

> "Bulut, başkasının bilgisayarıdır. Ve o bilgisayarın fişini çekemezsin."

---

## 🤝 Paylaşılan Sorumluluk Modeli (Shared Responsibility)

Bulutta her şeyden sen sorumlu değilsin, ama **verinden** sen sorumlusun.

| Alan | Kimin Sorumluluğunda? (AWS/Azure) |
| :--- | :--- |
| **Donanım/Veri Merkezi** | Sağlayıcı (Provider) |
| **İşletim Sistemi (EC2)** | Müşteri (Sen) |
| **Ağ Ayarları (VPC)** | Müşteri (Sen) |
| **Veri Şifreleme** | Müşteri (Sen) |
| **IAM (Kimlik)** | Müşteri (Sen) |

---

## 🔑 IAM: Kimlik ve Erişim (Kilidin Anahtarı)

Bulut saldırılarının %90'ı yanlış yapılandırılmış IAM izinlerinden kaynaklanır.

- **Least Privilege (En Az Yetki)**: Bir kullanıcıya sadece yapması gereken iş kadar yetki verin. `AdministratorAccess` vermeyin!
- **MFA (2FA)**: Root hesabında MFA yoksa, o hesap senin değildir.
- **Access Keys**: Kod içine gömülmüş Access Key'ler bir gün mutlaka sızar. `AWS Secrets Manager` kullanın.

---

## 🪣 S3 Bucket Güvenliği

"Halka açık (Public) veri sızıntılarının" bir numaralı sorumlusu.

### 🚫 Tehlikeli Konfigürasyonlar
1.  **Block Public Access: OFF**: Tüm dünyaya açılan kapı.
2.  **Authenticated Users**: "Herhangi bir AWS hesabı olan herkes" demektir. Sadece *senin* kullanıcıların değil!
3.  **ListObject Yetkisi**: Saldırganın tüm dosyalarını listelemesine izin verir.

---

## 🛠️ Bulut Savaş Araçları

Bulut altyapısını test etmek için.

1.  **Pacu**: AWS sızma testi framework'ü (Bulutun Metasploit'i).
2.  **ScoutSuite**: Çoklu bulut (AWS/Azure/GCP) güvenlik denetimi aracı.
3.  **Prowler**: AWS güvenliğini CIS benchmarklarına göre denetler.

### ⚡ AWS CLI Cheat Sheet
```bash
# Kimlik Kontrolü (Ben kimim?)
aws sts get-caller-identity

# S3 Bucketlarını Listele
aws s3 ls

# Bir Bucket'ın İçeriğini İndir
aws s3 cp s3://hedef-bucket/dosya.txt .

# EC2 Instance'larını Listele
aws ec2 describe-instances --query "Reservations[*].Instances[*].PublicIpAddress"
```

---

## 💻 Sentinel Bucket (Araç Kullanımı)

Bir S3 bucket'ının halka açık olup olmadığını kontrol eden basit aracımız.

**Konum**: `TOOLS/sentinel_bucket.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_bucket.py <BUCKET_ADI>
```
*Kimlik bilgisi gerektirmez, dışarıdan HTTP isteği atar.*
