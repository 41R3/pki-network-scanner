# pki-network-scanner🔍
A high-performance, concurrent network scanner designed for Automated Public Key Infrastructure (PKI) visibility, certificate lifecycle management, and Shadow IT discovery. It scans target hosts, domains, or full CIDR subnets to extract, parse, and audit X.509 certificates across multiple TLS-enabled ports.
This tool was built to address the exact operational risks that organizations face regarding certificate expiration, automated renewal failures, and undocumented infrastructure.

## 🚀 Key Features

* **Subnet & CIDR Expansion:** Built-in support to automatically expand large subnets (e.g., `/24`) into individual IP targets.
* **High Concurrency:** Powered by a `ThreadPoolExecutor` architecture capable of scanning hundreds of network assets efficiently.
* **Multi-Port TLS Support:** Scans beyond standard HTTPS (443), targeting common secure ports like LDAPS (636), IMAPS (993), SMTPS (465), and custom alternative ports.
* **Strict Cryptographic Parsing:** Avoids unreliable regular expressions. It utilizes the native `cryptography` library to safely parse raw DER certificate bytes.
* **SNI (Server Name Indication) Compatibility:** Fully supports SNI to isolate accurate certificates behind multi-tenant virtual hosts.
* **DevOps Ready:** Generates standardized JSON to standard output (`stdout`) for easy pipeline integrations, alongside CSV exports for security audits.
  
## 📊 Output Data Schema

The scanner produces a consistent schema for every parsed certificate, facilitating easy parsing for automation pipelines or security dashboards.

### Fields Reference (Per Certificate)

| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| `host` | `string` | The target IP address or hostname connected to. |
| `port` | `integer` | The specific TLS port audited during the handshake. |
| `subject_cn` | `string` \| `null` | The Common Name (CN) extracted from the certificate Subject field. |
| `sans` | `array[string]` | Subject Alternative Names (DNS entries and IP addresses authorized by the cert). |
| `issuer_cn` | `string` \| `null` | The Common Name (CN) of the issuing Certificate Authority (CA). |
| `issuer_org` | `string` \| `null` | The formal Organization Name of the issuing CA (e.g., `Let's Encrypt`, `SwissSign AG`). |
| `not_before` | `string (ISO 8601)`| The exact timestamp marking the beginning of the certificate's validity period. |
| `not_after` | `string (ISO 8601)` | The exact timestamp marking the expiration of the certificate. |
| `days_until_expiry`| `integer` | Remaining lifespan in days relative to execution. **Can be negative** if already expired. |
| `serial_number` | `string (Hex)` | Unique certificate serial number represented as a lowercase hex string. |
| `fingerprint_sha256`| `string (Hex)`| The SHA-256 cryptographic hash of the raw certificate, uppercase with colon separators. |
| `is_self_signed` | `boolean` | `true` if the certificate is self-signed (Subject matches Issuer); `false` otherwise. |
| `key_usage` | `array[string]` | Authorized cryptographic functions (e.g., `digital_signature`, `key_encipherment`). |
| `status` | `string` | Risk classification code: `EXPIRED`, `CRITICAL` (<14 days), `WARNING` (<30 days), or `OK`. |


## 📊 Proof of Concept & Real-World Validation (Case Studies)

To demonstrate the scanner's stability, multi-threading efficiency, and enterprise value, a passive reconnaissance scan was executed across two entirely different infrastructure ecosystems: **Peru** (111 targets) and **Switzerland** (169 targets). 

The tool successfully extracted and categorized all anomalies based on their remaining lifespan.

### 🇵🇪 Case Study 1: Peruvian Infrastructure (111 Targets Scanned)
The scan targeted top-tier universities, government ministries, military institutions, and regional financial entities. Out of 111 hosts, **9 high-risk anomalies** were identified, revealing systematic visibility and automation challenges.

| Target Host | Organization Type | Certificate Authority (CA) | Days Until Expiration | Security Status / Context |
| :--- | :--- | :--- | :--- | :--- |
| `unmsm.edu.pe` | Public University | Self-Signed (`SomeOrganization`) | **-2,178 days** | 🚨 **Severe Shadow IT:** Abandoned test environment legacy endpoint active for 5+ years. |
| `urp.edu.pe` | Private University | Let's Encrypt | **-177 days** | ❌ **Automation Failure:** Silent crash of automated ACME rotation scripts (`certbot`). |
| `marina.mil.pe` | Military (Navy) | Let's Encrypt | **-136 days** | ❌ **Automation Failure:** Critical defense infrastructure missing automated renewal monitoring. |
| `minsa.gob.pe` | Gov (Ministry of Health) | Sectigo Limited | **-100 days** | 🛑 **EXPIRED:** Public health platform running on an unrenewed commercial OV certificate. |
| `uch.edu.pe` | Private University | GoDaddy.com, Inc. | **+8 days** | ⚠️ **CRITICAL:** Core academic infrastructure near immediate downtime. |
| `minem.gob.pe` | Gov (Ministry of Energy) | Sectigo Limited | **+10 days** | ⚠️ **CRITICAL:** High-priority government domain approaching critical expiration threshold. |
| `cajapaita.pe` | Financial Institution | Entrust Limited | **+13 days** | ⚠️ **CRITICAL:** Extended Validation (EV) banking certificate nearing expiration window. |
| `agrobanco.com.pe`| State-Owned Bank | Sectigo Limited | **+16 days** | 🟨 **WARNING:** Financial platform operating inside the risk perimeter. |
| `upao.edu.pe` | Private University | DigiCert Inc (GeoTrust) | **+19 days** | 🟨 **WARNING:** Academic infrastructure requires proactive rotation scheduling. |
<img width="1699" height="708" alt="Captura desde 2026-06-13 12-54-55" src="https://github.com/user-attachments/assets/965005d9-76ca-44aa-8af2-a942da203f26" />


---

### 🇨🇭 Case Study 2: Swiss Infrastructure (169 Targets Scanned)
The scan targeted federal administration systems, cantonal networks, public utilities, and localized banking systems. Out of 169 hosts, **only 2 anomalies** were flagged. While Swiss infrastructure displays exceptional general hygiene (100% trusted public CAs, zero self-signed certificates), it remains vulnerable to human/operational latency.

| Target Host | Organization Type | Certificate Authority (CA) | Days Until Expiration | Security Status / Context |
| :--- | :--- | :--- | :--- | :--- |
| `swisscom.ch` | National Telecom Provider | **SwissSign AG** | **+13 days** | ⚠️ **CRITICAL:** The nation's primary telecommunications infrastructure running on tight manual/operational tracking buffers. |
| `zh.ch` | Gov (Canton of Zürich) | DigiCert Inc | **+15 days** | 🟨 **WARNING:** Critical regional government gateway operating within a narrow renewal window. |

### 🔄 Regional Comparison Insights

| Risk Dimension | Peru (Developing IT Infrastructure) | Switzerland (Highly Regulated Environment) |
| :--- | :--- | :--- |
| **Data Metric** | **8.1% failure/risk rate** (9 out of 111 hosts flagged). | **1.1% risk rate** (2 out of 169 hosts flagged). |
| **Root Cause** | **Lack of Asset Inventory:** High incidence of forgotten legacy systems, unmonitored free CAs, and insecure self-signed exposures. | **Operational Latency:** Superior asset tracking and premium trusted CAs, but bottlenecked by strict timelines and manual verification boundaries. |
| **Business Threat** | Potential entry points for malicious exploitation via undocumented, unpatched legacy assets (*Shadow IT*). | Unexpected service downtime across high-traffic, critical critical infrastructure frameworks. |
<img width="1699" height="708" alt="Captura desde 2026-06-13 12-55-41" src="https://github.com/user-attachments/assets/e4ad5b61-994d-42cc-8f5f-302a618c2780" />



## 💻 Technical Implementation Details

The core network handshake isolates the certificate payload swiftly without opening full application-layer overhead:

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # Discovery allows self-signed inspection

with socket.create_connection((host, port), timeout=timeout) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        der_bytes = ssock.getpeercert(binary_form=True)
```

## 🛠️ Prerequisites & Installation
```bash
# 1. Clone this repository
git clone [https://github.com/41R3/pki-network-scanner.git](https://github.com/41R3/pki-network-scanner.git)
cd pki-network-scanner

# 2. Install the required cryptographic dependency
pip install cryptography
#3 Basic Scan Execution
python3 cert_scanner.py example.com --csv results.csv
```

### 🌐 Network Telemetry & Traffic Behavior (Sniffnet Audit)
<img width="1873" height="1118" alt="Captura desde 2026-06-13 13-59-36" src="https://github.com/user-attachments/assets/41d27f2b-29a8-4b76-a206-29b8ac431d24" />
<img width="1863" height="1118" alt="Captura desde 2026-06-13 14-01-54" src="https://github.com/user-attachments/assets/454c59a2-afd2-49be-9adc-e28c3c97888a" />

