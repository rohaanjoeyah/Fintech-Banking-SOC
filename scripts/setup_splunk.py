import os
import time
import base64
import ssl
import urllib.parse
import urllib.request
import urllib.error

SPLUNK_MGMT_URL = "https://localhost:8089"
SPLUNK_USER = "admin"
SPLUNK_PASS = "FinTechSOC2026!"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_XML_PATH = os.path.join(BASE_DIR, "scripts", "fintech_soc_dashboard.xml")


def splunk_api_request(method: str, path: str, form_data: dict = None) -> tuple:
    url = f"{SPLUNK_MGMT_URL}{path}"
    auth_str = base64.b64encode(f"{SPLUNK_USER}:{SPLUNK_PASS}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_str}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data_bytes = urllib.parse.urlencode(form_data).encode("utf-8") if form_data else None
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10.0) as resp:
            return resp.getcode(), resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return 0, str(e)


def wait_for_splunk() -> bool:
    print("[*] Waiting for Splunk Enterprise container (https://localhost:8089) to finish initializing...")
    for attempt in range(1, 45):
        code, _ = splunk_api_request("GET", "/services/server/info")
        if code == 200:
            print("[+] Splunk Management API is online!")
            return True
        print(f"    ... still starting up (attempt {attempt}/45, waiting 5s)")
        time.sleep(5)
    return False


def configure_splunk():
    if not os.path.exists(DASHBOARD_XML_PATH):
        print(f"[!] Error: Dashboard XML file not found at {DASHBOARD_XML_PATH}")
        return

    with open(DASHBOARD_XML_PATH, "r", encoding="utf-8") as f:
        dashboard_xml = f.read()

    if not wait_for_splunk():
        print("[!] Splunk did not respond in time. Check `docker logs fintech-splunk-siem`.")
        return

    # 1. Create 'fintech_soc' index
    print("[*] Creating Splunk index 'fintech_soc'...")
    code, body = splunk_api_request("POST", "/services/data/indexes", {"name": "fintech_soc"})
    if code in (201, 409):
        print("    [+] Index 'fintech_soc' ready.")
    else:
        print(f"    [!] Index status {code}: {body[:200]}")

    # 2. Configure continuous JSON file ingestion on /var/log/fintech/banking_audit.json
    print("[*] Configuring live monitor on /var/log/fintech/banking_audit.json...")
    monitor_payload = {
        "name": "/var/log/fintech/banking_audit.json",
        "index": "fintech_soc",
        "sourcetype": "_json",
        "disabled": "0"
    }
    code, body = splunk_api_request(
        "POST", "/servicesNS/nobody/search/data/inputs/monitor", monitor_payload
    )
    if code in (201, 409):
        print("    [+] Live JSON log ingestion configured.")
    else:
        print(f"    [!] Monitor status {code}: {body[:200]}")

    # 3. Deploy the 6-Panel FinTech SOC Dashboard from siem/fintech_soc_dashboard.xml
    print("[*] Deploying 6-Panel Banking & FinTech SOC Dashboard...")
    splunk_api_request("DELETE", "/servicesNS/admin/search/data/ui/views/fintech_soc_dashboard")
    view_payload = {
        "name": "fintech_soc_dashboard",
        "eai:data": dashboard_xml
    }
    code, body = splunk_api_request(
        "POST", "/servicesNS/admin/search/data/ui/views", view_payload
    )
    if code in (201, 409):
        print("    [+] Dashboard 'fintech_soc_dashboard' deployed successfully!")
    else:
        print(f"    [!] Dashboard status {code}: {body[:200]}")

    print("\n" + "=" * 85)
    print("[SUCCESS] Splunk SIEM is fully configured and indexing your FinTech logs!")
    print("  1. Open Browser:   http://localhost:8001")
    print("  2. Login:          Username: admin  |  Password: FinTechSOC2026!")
    print("  3. Open Dashboard: http://localhost:8001/en-US/app/search/fintech_soc_dashboard")
    print("=" * 85)


if __name__ == "__main__":
    configure_splunk()