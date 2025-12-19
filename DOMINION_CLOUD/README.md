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

### ⚡ AWS CLI Cheat Sheet & Persistence
```bash
# Kimlik Kontrolü (Ben kimim?)
aws sts get-caller-identity

# S3 Bucketlarını Listele
aws s3 ls

# Bir Bucket'ın İçeriğini İndir
aws s3 cp s3://hedef-bucket/dosya.txt .

# EC2 Instance'larını Listele
aws ec2 describe-instances --query "Reservations[*].Instances[*].PublicIpAddress"

# Kalıcılık: Yeni bir IAM Kullanıcısı ve Key oluşturma
aws iam create-user --user-name backup_admin
aws iam create-access-key --user-name backup_admin
```

---

## ⚡ Modern Cloud Attack Vectors

### 1. Serverless Security (Lambda & Functions)
- **Event Injection**: Lambda'ya gönderilen event verisinin (örn: API Gateway'den gelen JSON) sanitize edilmemesi.
- **Over-Privileged Roles**: Lambda fonksiyonuna tüm S3 bucket'larına erişim verilmesi.
- **Function Warping**: Kısa ömürlü fonksiyonların içinde shell alarak geçici ortama sızma.

### 2. Container & Kubernetes (K8s) Hacking
- **Misconfigured Kubelet**: Kimlik doğrulaması olmayan Kubelet API'si üzerinden komut çalıştırma.
- **Privileged Containers**: `--privileged` flag'i ile çalışan container'dan ana sunucuya (Host) kaçış (Container Escape).
- **Secrets Management**: K8s secret'larının şifresiz şekilde etcd'de saklanması veya repolara sızması.

### 3. IaC (Infrastructure as Code) Misconfiguration
- **Terraform State Files**: State dosyalarının içine sızan açık metin parolalar ve API anahtarları.
- **Insecure Defaults**: S3 bucketlarını varsayılan olarak halka açık oluşturan şablonlar.

---

## ☁️ Bulut-Yerli (Cloud-Native) Güvenlik Mimarisi

Dinamik bulut ortamlarında güvenlik, sabit duvarlar yerine sürekli izleme ve runtime koruması üzerine kurulur.

### 1. Runtime Security & eBPF
Uygulamalar çalışırken çekirdek (kernel) seviyesinde izleme yaparak anomali tespiti.
- **Cilium/Tetragon**: Container'lar içindeki şüpheli sistem çağrılarını (örn: `setns` ile namespace değiştirme) anında durdurma.
- **Falco**: "Kritik bir dosyaya container içinden erişildi" gibi durumlar için gerçek zamanlı uyarılar üretme.

### 2. Admission Controllers (K8s Giriş Denetimi)
Bir kaynağın Kubernetes kümesine dahil edilmeden önce politikalarla denetlenmesi.
- **OPA Gatekeeper**: "Sadece belirli bir registry'den gelen imajlar çalıştırılabilir" kuralını zorlama.
- **Kyverno**: YAML dosyalarındaki güvenlik açıklarını (örn: root yetkisi isteme) otomatik olarak düzeltme veya engelleme.

### 3. Identity-First Architecture (IAM)
Bulutta IP adresleri geçicidir, kimlikler (IAM) kalıcıdır.
- **Workload Identity**: Container'ların uzun ömürlü key'ler yerine, geçici ve kısıtlı bulut kimlikleri (IAM Roles) kullanması.

---

## 📘 Bulut Savunma Stratejisi

1. **GuardDuty**: Sürekli tehdit izleme ve anomali tespiti.
2. **Security Hub**: Tüm güvenlik bulgularını tek bir panelde birleştirme.
3. **IMDSv2**: SSRF saldırılarını önlemek için Instance Metadata Service v2 kullanımı.

---

## 💻 Sentinel Bucket (Araç Kullanımı)

Bir S3 bucket'ının halka açık olup olmadığını kontrol eden basit aracımız.

**Konum**: `TOOLS/sentinel_bucket.py`

**Kullanım**:
```bash
python3 TOOLS/sentinel_bucket.py <BUCKET_ADI>
```
*Kimlik bilgisi gerektirmez, dışarıdan HTTP isteği atar.*
