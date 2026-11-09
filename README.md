# Banking and FinTech Security Operations Center (SOC)

A domain-specific Security Operations Center (SOC) simulating an enterprise **Open Banking REST API Gateway (Northbound HTTP/JSON + JWT)** and a **Core Banking Payment Switch (Southbound TCP Port 8583 / ISO 8583)**, integrated with automated network packet capture (`tcpdump`) and real-time **Splunk Enterprise SIEM** monitoring.

---

## 1. Repository Structure

    fintech-soc/
    ├── docker-compose.yml                # Orchestrates API, ISO-8583 Switch, PCAP Sniffer, & Splunk SIEM
    ├── README.md                         # Project documentation & analyst playbook
    ├── api_gateway/                      # Task 1: Northbound Open Banking FastAPI Server
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── iso_client.py                 # Translates REST requests to ISO 8583 TCP messages
    │   └── main.py                       # Banking API endpoints & structured JSON audit logger
    ├── iso8583_switch/                   # Task 1: Southbound Core Banking Payment Switch (Port 8583)
    │   ├── Dockerfile
    │   └── switch_server.py              # MTI 0100/0200 processor & 50-account SQLite ledger
    ├── scripts/                          # Task 1, 2 & 3 Automation Scripts
    │   ├── simulate.py                   # Normal baseline traffic + 3 FinTech attack scenarios
    │   └── setup_splunk.py               # Automated Splunk index, input, & dashboard provisioner
    ├── siem/                             # Task 3: SIEM & Network Forensics Assets
    │   ├── fintech_soc_dashboard.xml     # 6-Panel Splunk SOC Fraud & Threat Monitoring Dashboard
    │   └── iso8583_dissector.lua         # Custom Wireshark Lua dissector for TCP Port 8583
    ├── logs/                             # Live JSON audit logs & auto-generated Ground-Truth report
    └── pcaps/                            # Automated packet captures (fintech_traffic.pcap)

---

## 2. System Architecture & Protocol Stack (Task 1)

| Tier / Security Zone | Container Name | IP Address & Port | Protocol & Role |
| :--- | :--- | :--- | :--- |
| **FinTech DMZ** | `fintech-api-gateway` | `172.20.0.10:8000` (`localhost:8000`) | Northbound HTTP/1.1 REST API + JWT Auth; translates transactions to ISO 8583 |
| **Core Banking Switch** | `fintech-core-switch` | `172.20.0.20:8583` | Southbound TCP ISO 8583 Payment Switch (`MTI 0100/0110` & `MTI 0200/0210`) + SQLite Ledger |
| **Network Tap Sensor** | `fintech-pcap-sniffer` | Shares `fintech-api` namespace | Captures Northbound HTTP (`8000`) & Southbound ISO 8583 (`8583`) into `pcaps/fintech_traffic.pcap` |
| **SIEM Platform** | `fintech-splunk-siem` | `172.20.0.30:8000` (`localhost:8001`) | Indexes `/var/log/fintech/banking_audit.json` into `index=fintech_soc` |

### Underlying Protocol Correlation
Every customer request to the REST API generates a unique correlation identifier (`trace_id`, e.g., `ATK1-9F4A2C11`) logged in `logs/banking_audit.json`. When the API communicates with the Core Switch over TCP Port `8583`, this exact `trace_id` is embedded inside **ISO 8583 Data Element 37 (Retrieval Reference Number)**:
* **Northbound Layer:** `HTTP/1.1` + `JSON` + `Bearer JWT` (`Port 8000`)
* **Southbound Layer:** `ISO 8583` over `TCP` (`Port 8583`):
  * `MTI 0100` / `0110`: Authorization / Balance Inquiry (`DE 3 = 310000`)
  * `MTI 0200` / `0210`: Financial Transaction / Fund Transfer (`DE 3 = 400000`)
  * `DE 2`: 16-Digit Primary Account Number (PAN)
  * `DE 4`: 12-Digit Zero-Padded Transaction Amount in Cents
  * `DE 11`: 6-Digit System Trace Audit Number (STAN)
  * `DE 37`: Correlation `trace_id`
  * `DE 39`: Switch Response Code (`00` = Approved, `51` = Insufficient Funds, `05` = Do Not Honor / Frozen Account)

---

## 3. Step-by-Step Execution Guide (Windows PowerShell)

### Step 1: Launch the Docker Infrastructure
Make sure Docker Desktop is running on Windows, open PowerShell in the project folder, and run:

    docker compose up -d --build

Verify all 4 containers (`fintech-api-gateway`, `fintech-core-switch`, `fintech-pcap-sniffer`, and `fintech-splunk-siem`) are running:

    docker compose ps

### Step 2: Generate Normal Traffic & All 3 Attack Scenarios
Run the unified simulator to generate normal customer baseline sessions interleaved with all three FinTech attack scenarios:

    python .\scripts\simulate.py --mode full-dataset

You can also run individual modes whenever needed:

    python .\scripts\simulate.py --mode normal
    python .\scripts\simulate.py --mode attack1
    python .\scripts\simulate.py --mode attack2
    python .\scripts\simulate.py --mode attack3

* **Output 1 (Structured Logs):** `logs/banking_audit.json`
* **Output 2 (Ground-Truth Table for Report):** `logs/ground_truth_report.md`
* **Output 3 (Network Packet Capture):** `pcaps/fintech_traffic.pcap`

### Step 3: Auto-Configure Splunk SIEM & SOC Dashboard
Run the automated Splunk setup script (waits for Splunk to initialize, creates the `fintech_soc` index, ingests `banking_audit.json`, and deploys the 6-panel dashboard):

    python .\scripts\setup_splunk.py

* **Splunk Web UI:** `http://localhost:8001`
* **Login Credentials:** Username: `admin` | Password: `FinTechSOC2026!`
* **Direct Dashboard Link:** `http://localhost:8001/en-US/app/search/fintech_soc_dashboard`

---

## 4. Attack Scenarios & Ground-Truth Reference (Task 2)

| Scenario | FinTech Threat Vector | Attack Procedure | Expected Network & SIEM Indicators |
| :--- | :--- | :--- | :--- |
| **Scenario 1: Credential Stuffing -> Account Takeover (ATO) -> Illicit Wire** | Repeated Login Failures & Account Abuse | Attacker (`185.220.101.44`) fires 30 rapid failed logins (`HTTP 401`), compromises `user1001` (`HTTP 200`), registers offshore mule beneficiary `99990001`, and wires `$9,500.00`. | **Wireshark:** Volumetric burst of `POST /api/v1/auth/login` -> `401`, followed by `MTI 0200` with `DE4=000000950000`.<br>**SIEM:** 30 `AUTH_FAIL` -> `AUTH_SUCCESS` -> `BENEFICIARY_ADDED` -> `TRANSACTION_INITIATED` (`$9,500`). |
| **Scenario 2: Broken Object Level Authorization (BOLA / IDOR)** | Abnormal API Activity (OWASP API1:2023) | Attacker (`91.240.118.172`) authenticates as low-privilege `user1015` (Account `1015`) and sequentially scrapes `/api/v1/accounts/{1001..1050}/balance`. | **Wireshark:** Rapid `GET` requests across sequential account URIs using the same JWT.<br>**SIEM:** 50 distinct `target_account` queries by `user1015` (`bola_indicator: true`), plus `DE39=05` on frozen account `1003`. |
| **Scenario 3: AML Structuring ("Smurfing") & Velocity Drain** | Suspicious Transaction Patterns & Switch Rejections | Attacker (`45.155.205.99`) on `user1002` (balance `$10,800.00`) fires 12 rapid transfers of `$950.00` each (`$11,400.00` total) to evade the static `$10,000` CTR threshold. | **Wireshark:** 12 rapid `ISO 8583 MTI 0200` frames (`DE4=000000095000`); first 11 return `DE39=00`, 12th returns `DE39=51` (Insufficient Funds).<br>**SIEM:** 5-minute sliding window sum exceeds `$10,000` despite `max(transaction_amount) < 1000`. |

---

## 5. Teammate Guide: Wireshark Packet Analysis (Task 3)

### Step A: Load the Custom ISO 8583 Lua Dissector
1. Open Windows Wireshark and navigate to **Help -> About Wireshark -> Folders**.
2. Double-click **Personal Lua Plugins** and copy `siem/iso8583_dissector.lua` into that directory.
3. Press `Ctrl + Shift + L` inside Wireshark to reload Lua scripts, then open `pcaps/fintech_traffic.pcap`.

### Step B: Wireshark Display Filters for Evidence Screenshots

* **Filter 1 — Scenario 1 Credential Stuffing Burst & Account Takeover:**

      http.request.uri == "/api/v1/auth/login" || http.response.code == 401

* **Filter 2 — Scenario 1 End-to-End HTTP to ISO 8583 Wire Transfer (`$9,500.00` to `99990001`):**

      frame contains "99990001" || frame contains "000000950000"

* **Filter 3 — Scenario 2 BOLA / IDOR Mass Account Enumeration (`1001..1050`):**

      http.request.method == "GET" && http.request.uri contains "/api/v1/accounts/"

* **Filter 4 — Scenario 3 AML Structuring Burst & Core Switch `DE39=51` Rejection:**

      tcp.port == 8583 && (frame contains "DE102=1002" || frame contains "DE39=51")

---

## 6. Teammate Guide: Splunk Search Queries (SPL)

Run these queries in Splunk (**Search & Reporting** app at `http://localhost:8001`) for Task 3 report screenshots:

### Query 1: Detect Credential Stuffing -> Account Takeover -> High-Value Wire (Scenario 1)

    index=fintech_soc (event_type="AUTH_FAIL" OR event_type="AUTH_SUCCESS" OR event_type="BENEFICIARY_ADDED" OR event_type="TRANSACTION_INITIATED")
    | stats count(eval(event_type="AUTH_FAIL")) as Failed_Logins,
            count(eval(event_type="AUTH_SUCCESS")) as Successful_Logins,
            values(beneficiary_account) as Added_Mule_Beneficiary,
            max(transaction_amount) as Max_Transfer_USD,
            values(user_id) as Targeted_Users
            by client_ip
    | where Failed_Logins >= 10 OR isnotnull(Added_Mule_Beneficiary)
    | sort - Failed_Logins

### Query 2: Detect OWASP API1 BOLA / IDOR Mass Account Enumeration (Scenario 2)

    index=fintech_soc event_type="ACCOUNT_BALANCE_QUERY"
    | stats count as Total_Queries,
            dc(target_account) as Distinct_Accounts_Accessed,
            count(eval(bola_indicator="true")) as Unauthorized_BOLA_Hits,
            values(authenticated_account) as Own_Account
            by user_id, client_ip, user_agent
    | where Distinct_Accounts_Accessed > 1 OR Unauthorized_BOLA_Hits > 0
    | sort - Unauthorized_BOLA_Hits

### Query 3: Detect AML Structuring ("Smurfing") & Velocity Drain (Scenario 3)

    index=fintech_soc event_type="TRANSACTION_INITIATED"
    | bin _time span=5m
    | stats count as Tx_Count,
            sum(transaction_amount) as Cumulative_Attempted_USD,
            sum(eval(if(iso_response_code="00", transaction_amount, 0))) as Approved_Drained_USD,
            max(transaction_amount) as Max_Single_Tx_USD,
            values(static_aml_flag) as Static_CTR_Flag,
            values(iso_response_code) as Switch_DE39_Codes
            by user_id, src_account, dst_account, client_ip
    | where Tx_Count >= 5 AND Max_Single_Tx_USD < 1000 AND Cumulative_Attempted_USD >= 10000

### Query 4: Northbound HTTP to Southbound ISO 8583 Protocol Correlation

    index=fintech_soc trace_id="ATK*"
    | stats values(component) as Layers_Traversed,
            values(event_type) as Events,
            values(client_ip) as Attacker_IP,
            values(endpoint) as HTTP_Endpoint,
            values(iso_mti_req) as ISO_Req_MTI,
            values(iso_mti_resp) as ISO_Resp_MTI,
            values(transaction_amount) as Amount_USD,
            values(iso_response_code) as DE39_Code
            by trace_id
    | sort trace_id