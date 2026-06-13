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


## 💻 Technical Implementation Details

The core network handshake isolates the certificate payload swiftly without opening full application-layer overhead:

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # Discovery allows self-signed inspection

with socket.create_connection((host, port), timeout=timeout) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        der_bytes = ssock.getpeercert(binary_form=True)
