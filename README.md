# Universal Attack Simulation Framework (UASF)

UASF, **yetkili ve kontrollü** WAAP/WAF PoC gösterimleri için tasarlanmış,
*GET-only*, düşük RPS’li, **demo-safe** bir saldırı simülasyon aracıdır.  
Hedef: engelleme ve gözlemleme katmanlarının (WAF, bot koruması, core rules) nasıl davrandığını, **kanıtlı log** ve **HTML rapor** ile görünür kılmak.

> **Legal & Safety**  
> Yalnızca **kendi sahip olduğunuz** veya **açık yazılı iznini aldığınız** sistemlerde kullanın.  
> Araç “state-changing” işlemler yapmaz (GET-only), RPS düşüktür, yine de üretim ortamlarında dikkatli olun.

---

## Highlights

- **Guided CLI**: Quick / Extended / Custom profilleri, modül seçimi ve hız ayarları.
- **Signature-trigger payloads**: SQLi, XSS, LFI/RFI/Traversal, Open Redirect, NoSQL/LDAP/Command Injection imzaları, WP eko prob’ları.
- **Bot pulse**: WAF bot imzalarını tetiklemek için kısa, güvenli trafik.
- **Evidence & Reporting**  
  - `results.csv`, `results.ndjson`  
  - **HTML rapor**: HTTP code dağılımı, modül istatistikleri, örnekler  
  - Engellemelerde gövdenin ilk 8KB’sını “evidence” klasörüne döker.
- **Output Semantics (net)**  
  - **BLOCK** – WAF/uygulama engelledi (4xx/5xx vb.)  
  - **PASS** – **İstismar kanıtlandı** (ör. Open Redirect’te 3xx + harici `Location`)  
  - **ALLOW** – İstek geçti ama **açık tetiklenmedi** (ör. 200 OK, kanıt yok)

---

## Quick Start

```bash
# 1) Çalıştır
chmod +x uasf.sh
./uasf.sh

# 2) Hedefi gir (örn.)
# Target: https://demo.example.com

# 3) Profil seç (1/2/3)
# 1) Quick  2) Extended  3) Custom

# 4) RPS/TIMEOUT/Concurrency ayarla (Enter ile varsayılan)
