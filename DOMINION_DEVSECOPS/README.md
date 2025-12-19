# ⚙️ GÜVENLİ DÖNGÜ: DevSecOps & Otomasyon

> "Hız güvenlikten feragat etmek değildir; güvenliği hızın içine entegre etmektir."

---

## 🛡️ DevSecOps Felsefesi

Güvenlik artık geliştirme sürecinin sonundaki bir engel değil, boru hattının (Pipeline) her adımındaki bir bileşendir.

### 1. Shift Left (Sola Kaydır)
Hataları üretimde (Prod) değil, daha kod yazılırken (IDE/Commit) yakalama felsefesi.

### 2. Güvenlik Otomasyonu (Pipeline)
- **SAST (Static Application Security Testing)**: Kodun derlenmeden taranması.
- **DAST (Dynamic Application Security Testing)**: Çalışan uygulamanın taranması.
- **SCA (Software Composition Analysis)**: Bağımlılıkların (Dependencies) taranması.

### 3. Altyapı Güvenliği (IaC)
Terraform, Ansible ve Kubernetes konfigürasyonlarının güvenliği.

---

## 🛠️ DevSecOps Toolchain

| Araç | Kategori | Kullanım Amacı |
| :--- | :--- | :--- |
| **SonarQube** | SAST | Kod kalitesi ve güvenlik analizi. |
| **Snyk** | SCA | Güvenlik açıklarına sahip kütüphane tespiti. |
| **Trivy** | Scanner | Container ve IaC tarayıcı. |
| **Checkov** | IaC | Terraform ve CloudFormation analizi. |
| **GitLeaks** | Secret Scan | Repoya sızan şifre ve anahtar tespiti. |

---

## 📒 Reference: Security Toolchain Integration

| Pipeline Aşaması | İşlem türü | Önerilen Araç |
| :--- | :--- | :--- |
| **Code (Commit)** | Secret Scanning | `GitLeaks`, `TruffleHog` |
| **Build** | SAST | `SonarQube`, `Semgrep` |
| **Test** | DAST | `OWASP ZAP`, `Nikto` |
| **Deploy** | Container Scan | `Trivy`, `Clair` |
| **Operate** | Compliance | `OpenSCAP`, `Checkov` |

## 📦 Tedarik Zinciri Güvenliği (Supply Chain Security)

Kodun kendisi kadar, onu oluşturan kütüphaneler ve süreçler de güvenli olmalıdır.

### 1. SBOM (Software Bill of Materials)
Uygulamanın içindeki tüm "malzemelerin" (kütüphaneler, bağımlılıklar) listesi.
- **Neden?**: `Log4j` gibi bir açık çıktığında, hangi uygulamalarınızın etkilendiğini anında bulmak için.
- **Araç**: `Syft`, `CycloneDX`.
- **İmzalama**: SBOM'un kendisinin de `cosign` ile imzalanarak bütünlüğünün korunması.

### 2. SLSA & Artifact Integrity
Derlenme sürecinin kurcalanmadığını kanıtlayan çerçeve.
- **Sigstore/Cosign**: Container imajlarını ve binary dosyaları dijital olarak imzalayarak, sadece güvenli kaynaktan gelen kodun çalışmasını garanti altına alma.
- **Attestations**: Derleme (build) sırasında oluşturulan, "bu kod şu tarihte, şu pipeline'da derlendi" diyen kanıt dosyaları.

### 3. Tedarik Zinciri Saldırıları (Dependency Confusion)
Dahili paket isimlerini (örn: `acme-internal-util`) genel paket yöneticilerinde (npm/pypi) aynı isimle yayınlayarak, sistemin sahte/zararlı paketi indirmesini sağlama tekniği.
- **Savunma**: Scoped paket kullanımı ve private registry önceliklendirme.

---

## 📜 Kod Olarak Politika (Policy as Code - PaC)

Güvenlik kurallarını dokümanlarda değil, kodun içinde tanımlayın.

### 1. OPA (Open Policy Agent) & Rego
Altyapınızın (K8s, Terraform, Cloud) belirli bir güvenlik standardına uyup uymadığını denetleyen dil.
- **Örnek**: "Hemen hemen hiçbir container `root` yetkisiyle çalıştırılamaz." kuralını otomatik olarak enforcing yapma.

### 2. IaC Güvenlik Taraması (Deep Dive)
Altyapı daha canlıya çıkmadan zafiyetleri yakalamak:
- **Checkov / Tfsec**: Terraform dosyalarındaki şifrelenmemiş S3 bucket'larını veya açık güvenlik gruplarını (Firewall) tarar.
- **Terrascan**: Cloud-native altyapıyı güvenli konfigürasyon (CIS Benchmarks) açısından denetler.

---

## 🚀 DevSecOps Doktrini

1. **İnsan**: Güvenlik bilincine sahip geliştiriciler.
2. **Süreç**: Her "Pull Request" bir güvenlik testinden geçmelidir.
3. **Teknoloji**: Otomatik tarayıcılar "Fail early" prensibiyle çalışmalıdır.

---

## 💻 Sentinel Scan (Placeholder)

CI/CD süreçlerine entegre edilecek güvenlik tarama betikleri.

**Konum**: `TOOLS/sentinel_devsec.py`
