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

To demonstrate the scanner's stability, accuracy, and enterprise value, a comprehensive passive reconnaissance scan was executed across two entirely different infrastructure ecosystems: **Peru** and **Switzerland**. 

The results uncovered distinct infrastructure vulnerabilities and operational patterns in both regions.

### 🇵🇪 Case Study 1: Peruvian Infrastructure (Visibilities & Shadow IT)
**Target Profile:** Top 30 universities, major government branches, and core financial institutions.
* **Shadow IT Discovery:** The scanner flagged critical blind spots in major public academic institutions. For instance, an undocumented subdomain (`paracas.unmsm.edu.pe`) was caught exposing an **expired self-signed certificate for over 2,178 days** (5+ years).
* **ACME Automation Failures:** Detected an official university platform (`urp.edu.pe`) running a Let's Encrypt certificate that **expired 177 days ago**, indicating a silent failure in their automated certificate rotation scripts (e.g., Certbot) that went unmonitored.

### 🇨🇭 Case Study 2: Swiss Infrastructure (Operational Risk & Compliance)
**Target Profile:** Cantonal government domains, local cantonal banks, transport, and national telecoms.
* **Proactive Outage Prevention:** While Swiss financial and academic networks showed superior hygiene (100% trusted CAs like DigiCert and Sectigo), a high-priority risk was found on a primary target: **`swisscom.ch`** (Switzerland's leading telecom provider). The scanner caught a core certificate entering **CRITICAL status with only 13 days of lifespan remaining** before expiration. 
* **Localization Validation:** The parser accurately decoded localized trusted Trust Service Providers (TSPs) like `SwissSign AG` (the issuer for Swisscom), verifying its readiness for European PKI standards.

### 🔄 Regional Comparison Insights

| Risk Dimension | Peru (Developing IT Infrastructure) | Switzerland (Highly Regulated Environment) |
| :--- | :--- | :--- |
| **Root Issue** | **Lack of Asset Inventory:** High presence of forgotten servers, stale test environments, and insecure self-signed certs. | **Operational/Human Latency:** High compliance and trusted CAs, but dependencies on manual tracking leading to tight expiration windows. |
| **Business Threat** | Security breaches through unmonitored, vulnerable legacy entry points (Shadow IT). | Unexpected operational downtime on high-traffic, critical infrastructure assets. |


## 💻 Technical Implementation Details

The core network handshake isolates the certificate payload swiftly without opening full application-layer overhead:

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # Discovery allows self-signed inspection

with socket.create_connection((host, port), timeout=timeout) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        der_bytes = ssock.getpeercert(binary_form=True)
