# Universal Attack Simulation Framework (UASF) v2.0

A professional-grade, **demo-safe** WAF/WAAP testing tool designed for controlled security assessments and demonstrations. Enhanced for **AppTrana WAAP** and other enterprise WAF solutions.

> **⚠️ Legal & Safety**  
> Use only on systems you own or have **explicit written authorization** to test.  
> GET-only by default with optional POST support. Low RPS, no state changes.

---

## ✨ Features

### Attack Modules (41 Total)

| Category | Modules |
|----------|---------|
| **SQL Injection** | Basic, Union, Evasion (encoding), Double encoding, Unicode/case mix bypass |
| **XSS** | Basic, Variants (img/js URI), DOM-based, Mutation XSS |
| **File Inclusion** | LFI, RFI, Path traversal (with encoding bypass) |
| **Injection** | NoSQL, LDAP, Command, XXE, Prototype pollution |
| **API Security** | JSON injection, GraphQL introspection, Mass assignment |
| **Protocol** | HTTP smuggling signatures, Parameter pollution, Header injection |
| **Bot Detection** | Bad bot UAs, Bot pulse, Advanced bot bypass |
| **Rate Limiting** | Burst detection, Threshold identification |
| **Headers** | CORS probes, Cache poisoning, Host header, IP spoofing |
| **CMS** | WordPress core, REST API, popular plugin probes |
| **Auth** | JWT manipulation, Open redirect |
| **Client-Side** | Magecart patterns, DOM exfiltration signatures |

### Key Capabilities

- **5 Testing Profiles**: Quick Demo, Extended, Full Security, API Testing, Custom
- **POST/PUT Support**: Optional for API security testing
- **WAF Detection**: Fingerprints AppTrana, Cloudflare, Akamai, Imperva, ModSecurity
- **Rate Limit Detection**: Burst testing to find thresholds
- **Advanced Bot Testing**: Tests multiple bot categories with detection analysis
- **Header Spoofing**: IP bypass, URL override, host header attacks
- **Evidence Collection**: Saves blocked response bodies for analysis
- **Enhanced Reporting**: Modern dark-themed HTML reports with statistics

---

## 🚀 Quick Start

```bash
# 1) Make executable
chmod +x uasf.sh

# 2) Run
./uasf.sh

# 3) Enter target URL
Target: https://your-target.com

# 4) Select profile
1) Quick Demo     - Lightweight showcase
2) Extended Demo  - Broad coverage
3) Full Security  - All modules + evasion
4) API Testing    - JSON/GraphQL focus
5) Custom         - Choose specific modules

# 5) Configure RPS/timeout (optional)

# 6) View results
open uasf_out_*/report.html
```

---

## 📁 Project Structure

```
UASF/
├── uasf.sh                 # Main script (v2.0)
├── lib/                    # Modular libraries
│   ├── http_methods.sh     # POST/PUT/DELETE support
│   ├── evasion.sh          # Encoding & obfuscation
│   ├── detection.sh        # WAF fingerprinting
│   └── report.sh           # Enhanced HTML reports
├── payloads/               # Organized payload files
│   ├── sqli_basic.txt      # Standard SQLi
│   ├── sqli_evasion.txt    # Bypass techniques
│   ├── xss_basic.txt       # Standard XSS
│   ├── xss_dom.txt         # DOM-based XSS
│   ├── api_json.txt        # JSON API attacks
│   ├── api_graphql.txt     # GraphQL testing
│   ├── smuggling.txt       # HTTP smuggling
│   ├── bot_agents.txt      # User-agent library
│   ├── headers.txt         # Header injection
│   └── clientside.txt      # Client-side attacks
└── uasf_out_*/             # Output directory
    ├── results.csv         # All results
    ├── results.ndjson      # JSON format
    ├── report.html         # Visual report
    └── evidence/           # Blocked responses
```

---

## 🎯 AppTrana WAAP Testing

UASF is optimized for testing **Indusface AppTrana WAAP** features:

| AppTrana Feature | UASF Test Module |
|------------------|------------------|
| AI-assisted WAF rules | SQLi/XSS evasion modules |
| Bot mitigation | Bot pulse, Advanced bot bypass |
| API protection | JSON injection, GraphQL |
| DDoS protection | Rate limit detection |
| Client-side protection | Magecart signature probes |

### Correlation ID

Every test run includes a unique `X-UASF-Correlation` header. Use this ID to filter test traffic in your AppTrana dashboard:

```
Attacks → Filter by: X-UASF-Correlation: UASF-1705678900-12345
```

---

## 📊 Output

### CSV Format
```csv
timestamp,module,code,ms,size,ip,url,verdict
2025-01-19T14:30:00+0300,SQL Injection – Basic,403,45,1234,1.2.3.4,https://target/?id=1',BLOCK
```

### Verdicts
- **BLOCK** – WAF blocked the request (4xx/5xx or block signature detected)
- **PASS** – Request succeeded (potential vulnerability)
- **WARN** – Unclear result (404, timeout, etc.)
- **RATE_LIMITED** – Rate limiting triggered (429)

---

## 🔧 Configuration

| Option | Default | Description |
|--------|---------|-------------|
| RPS | 3 | Requests per second |
| Timeout | 8s | Request timeout |
| Concurrency | 2 | Parallel requests |
| POST | Disabled | Enable for API tests |

---

## 📝 License

For authorized security testing and demonstrations only.

---

## 🤝 Contributing

1. Fork the repository
2. Add payloads to `payloads/` directory
3. Submit pull request

