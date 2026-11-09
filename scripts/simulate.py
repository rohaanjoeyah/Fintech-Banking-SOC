import os
import json
import time
import uuid
import random
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE_URL = os.getenv("FINTECH_API_URL", "http://localhost:8000")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_REPORT_PATH = os.path.join(BASE_DIR, "logs", "ground_truth_report.md")

# Realistic residential IP pool for normal retail customers
NORMAL_IPS = [
    "39.42.88.14", "103.215.164.22", "119.152.74.91", "182.185.112.5",
    "202.163.96.45", "110.39.142.88", "43.245.9.102", "58.65.182.31"
]

NORMAL_USER_AGENTS = [
    "FinTech-Mobile-iOS/4.2.1 (iPhone15,2; iOS 17.4)",
    "FinTech-Mobile-Android/4.2.0 (Pixel 8; Android 14)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15"
]


def generate_trace_id(prefix: str = "TRC") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def http_request(method: str, path: str, payload: dict = None, headers: dict = None) -> tuple:
    """Executes an HTTP request against the FastAPI Gateway using standard urllib."""
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            status = resp.getcode()
            body = json.loads(resp.read().decode("utf-8"))
            return status, body
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            err_body = {"detail": str(e)}
        return e.code, err_body
    except Exception as e:
        return 500, {"error": str(e)}


def run_normal_traffic(cycles: int = 20, delay: float = 0.25) -> dict:
    """
    Task 1: Generates realistic retail banking baseline traffic (logins, balance checks,
    and legitimate transfers between $15 and $450).
    """
    start_ts = datetime.now(timezone.utc).isoformat()
    print(f"\n[*] Starting NORMAL Baseline Traffic ({cycles} customer sessions)...")
    first_trace = None
    last_trace = None
    total_events = 0

    for i in range(1, cycles + 1):
        acc_num = random.randint(1004, 1050)
        username = f"user{acc_num}"
        correct_password = f"FinTech#{acc_num}$Secure"
        client_ip = random.choice(NORMAL_IPS)
        ua = random.choice(NORMAL_USER_AGENTS)

        # 10% chance a normal user mistypes their password once before succeeding
        if random.random() < 0.10:
            typo_trace = generate_trace_id("NRM")
            first_trace = first_trace or typo_trace
            last_trace = typo_trace
            http_request(
                "POST", "/api/v1/auth/login",
                payload={"username": username, "password": "WrongPassword!"},
                headers={"X-Forwarded-For": client_ip, "User-Agent": ua, "X-Trace-Id": typo_trace}
            )
            total_events += 1
            time.sleep(0.1)

        # Normal Login
        login_trace = generate_trace_id("NRM")
        first_trace = first_trace or login_trace
        last_trace = login_trace
        status, body = http_request(
            "POST", "/api/v1/auth/login",
            payload={"username": username, "password": correct_password},
            headers={"X-Forwarded-For": client_ip, "User-Agent": ua, "X-Trace-Id": login_trace}
        )
        total_events += 1

        if status == 200 and "access_token" in body:
            token = body["access_token"]
            auth_headers = {
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": client_ip,
                "User-Agent": ua
            }

            # Check own account balance (Triggers ISO 8583 MTI 0100)
            bal_trace = generate_trace_id("NRM")
            last_trace = bal_trace
            http_request(
                "GET", f"/api/v1/accounts/{acc_num}/balance",
                headers={**auth_headers, "X-Trace-Id": bal_trace}
            )
            total_events += 1

            # 60% of sessions perform a normal low-value transfer ($15 - $450)
            if random.random() < 0.60:
                dst_acc = str(random.randint(1004, 1050))
                if dst_acc == str(acc_num):
                    dst_acc = "1005"
                amount = round(random.uniform(15.0, 450.0), 2)
                tx_trace = generate_trace_id("NRM")
                last_trace = tx_trace
                tx_status, tx_body = http_request(
                    "POST", "/api/v1/transfers/initiate",
                    payload={
                        "src_account": str(acc_num),
                        "dst_account": dst_acc,
                        "amount": amount,
                        "remarks": "Routine retail bill/peer payment"
                    },
                    headers={**auth_headers, "X-Trace-Id": tx_trace}
                )
                total_events += 1
                print(f"  [Normal {i:02d}/{cycles:02d}] {username} ({client_ip}) -> Checked balance & transferred ${amount:.2f} (DE39={tx_body.get('iso_response_code')})")
            else:
                print(f"  [Normal {i:02d}/{cycles:02d}] {username} ({client_ip}) -> Logged in & checked balance")

        time.sleep(delay)

    end_ts = datetime.now(timezone.utc).isoformat()
    return {
        "scenario": "Normal Baseline Traffic",
        "start_time": start_ts,
        "end_time": end_ts,
        "source_ip": "Multiple Retail Pool (39.42.x.x, 103.215.x.x)",
        "target_accounts": "1004 - 1050",
        "first_trace_id": first_trace,
        "last_trace_id": last_trace,
        "total_requests": total_events
    }


def run_attack_scenario_1() -> dict:
    """
    Scenario 1: Credential Stuffing -> Account Takeover (ATO) -> Illicit Wire Transfer.
    Covers: Repeated login failures, account abuse indicators, suspicious transaction patterns.
    """
    attacker_ip = "185.220.101.44"
    attacker_ua = "Mozilla/5.0 (X11; Linux x86_64) Hydra-Credential-Stuffer/2.4"
    start_ts = datetime.now(timezone.utc).isoformat()
    print("\n[!] LAUNCHING ATTACK SCENARIO 1: Credential Stuffing -> Account Takeover -> High-Value Wire Transfer")

    first_trace = None
    last_trace = None
    total_reqs = 0

    # Stage 1: High-velocity Credential Stuffing (30 failed attempts across users & user1001)
    print("  [Stage 1] Firing 30 high-velocity credential stuffing requests from 185.220.101.44...")
    stuffed_passwords = [
        "123456", "admin123", "qwerty2026", "pakistan123", "welcome1",
        "banking99", "letmein!", "football2026", "iloveyou", "monkey123"
    ]
    for i in range(30):
        target_user = f"user{1001 + (i % 8)}"
        bad_pwd = stuffed_passwords[i % len(stuffed_passwords)]
        trc = generate_trace_id("ATK1")
        first_trace = first_trace or trc
        last_trace = trc
        http_request(
            "POST", "/api/v1/auth/login",
            payload={"username": target_user, "password": bad_pwd},
            headers={"X-Forwarded-For": attacker_ip, "User-Agent": attacker_ua, "X-Trace-Id": trc}
        )
        total_reqs += 1
        time.sleep(0.03)

    # Stage 2: Successful Account Takeover on user1001
    ato_trace = generate_trace_id("ATK1")
    last_trace = ato_trace
    status, login_body = http_request(
        "POST", "/api/v1/auth/login",
        payload={"username": "user1001", "password": "Password123!"},
        headers={"X-Forwarded-For": attacker_ip, "User-Agent": attacker_ua, "X-Trace-Id": ato_trace}
    )
    total_reqs += 1
    token = login_body.get("access_token", "")
    print(f"  [Stage 2] Account Takeover SUCCESS on user1001! Trace={ato_trace}")

    auth_headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": attacker_ip,
        "User-Agent": attacker_ua
    }

    # Stage 3: Check Victim Balance (MTI 0100)
    bal_trace = generate_trace_id("ATK1")
    http_request("GET", "/api/v1/accounts/1001/balance", headers={**auth_headers, "X-Trace-Id": bal_trace})
    total_reqs += 1

    # Stage 4: Register External Mule Beneficiary
    ben_trace = generate_trace_id("ATK1")
    http_request(
        "POST", "/api/v1/beneficiaries/add",
        payload={
            "beneficiary_account": "99990001",
            "beneficiary_name": "OFFSHORE CRYPTO MULE LLC",
            "bank_code": "CAYMAN-INTL-09"
        },
        headers={**auth_headers, "X-Trace-Id": ben_trace}
    )
    total_reqs += 1
    print(f"  [Stage 3] Added fraudulent external beneficiary 99990001! Trace={ben_trace}")

    # Stage 5: Initiate High-Value Wire Transfer ($9,500.00 -> MTI 0200)
    wire_trace = generate_trace_id("ATK1")
    last_trace = wire_trace
    w_status, w_body = http_request(
        "POST", "/api/v1/transfers/initiate",
        payload={
            "src_account": "1001",
            "dst_account": "99990001",
            "amount": 9500.00,
            "remarks": "URGENT OFFSHORE LIQUIDATION WIRE"
        },
        headers={**auth_headers, "X-Trace-Id": wire_trace}
    )
    total_reqs += 1
    print(f"  [Stage 4] Executed $9,500.00 ATO Wire Transfer! HTTP={w_status} | ISO DE39={w_body.get('iso_response_code')} | Trace={wire_trace}")

    end_ts = datetime.now(timezone.utc).isoformat()
    return {
        "scenario": "Scenario 1: Credential Stuffing -> ATO -> $9,500 Wire Fraud",
        "start_time": start_ts,
        "end_time": end_ts,
        "source_ip": attacker_ip,
        "target_accounts": "user1001 (Account 1001 -> Mule 99990001)",
        "first_trace_id": first_trace,
        "last_trace_id": last_trace,
        "total_requests": total_reqs
    }


def run_attack_scenario_2() -> dict:
    """
    Scenario 2: Broken Object Level Authorization (BOLA / IDOR) Mass Account Enumeration.
    Covers: Abnormal API activity (OWASP API1:2023) & unauthorized data scraping.
    """
    attacker_ip = "91.240.118.172"
    attacker_ua = "python-requests/2.31.0 (OWASP-API1-BOLA-Scraper)"
    start_ts = datetime.now(timezone.utc).isoformat()
    print("\n[!] LAUNCHING ATTACK SCENARIO 2: BOLA / IDOR Mass Account Enumeration (Accounts 1001..1050)")

    first_trace = generate_trace_id("ATK2")
    last_trace = first_trace
    total_reqs = 0

    # Stage 1: Authenticate with a valid low-privilege account (user1015)
    status, login_body = http_request(
        "POST", "/api/v1/auth/login",
        payload={"username": "user1015", "password": "FinTech#1015$Secure"},
        headers={"X-Forwarded-For": attacker_ip, "User-Agent": attacker_ua, "X-Trace-Id": first_trace}
    )
    total_reqs += 1
    token = login_body.get("access_token", "")
    print(f"  [Stage 1] Authenticated as low-privilege user1015 (Account 1015). Trace={first_trace}")

    auth_headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": attacker_ip,
        "User-Agent": attacker_ua
    }

    # Stage 2: Rapidly enumerate all 50 accounts (1001 to 1050) using user1015's JWT
    print("  [Stage 2] Fuzzing /api/v1/accounts/{1001..1050}/balance to harvest balances...")
    scraped_count = 0
    for acc_id in range(1001, 1051):
        trc = generate_trace_id("ATK2")
        last_trace = trc
        s_code, b_body = http_request(
            "GET", f"/api/v1/accounts/{acc_id}/balance",
            headers={**auth_headers, "X-Trace-Id": trc}
        )
        total_reqs += 1
        if s_code == 200:
            scraped_count += 1
        time.sleep(0.02)

    print(f"  [Stage 3] Completed BOLA Enumeration: Scraped {scraped_count}/50 accounts (49 unauthorized cross-account queries!). Last Trace={last_trace}")

    end_ts = datetime.now(timezone.utc).isoformat()
    return {
        "scenario": "Scenario 2: BOLA / IDOR Mass Account Enumeration",
        "start_time": start_ts,
        "end_time": end_ts,
        "source_ip": attacker_ip,
        "target_accounts": "Authenticated as 1015 -> Enumerated 1001..1050",
        "first_trace_id": first_trace,
        "last_trace_id": last_trace,
        "total_requests": total_reqs
    }


def run_attack_scenario_3() -> dict:
    """
    Scenario 3: Anti-Money Laundering (AML) Structuring ("Smurfing") & Velocity Bypass Fraud.
    Covers: Suspicious transaction patterns & ISO 8583 DE39=51 switch rejection telemetry.
    """
    attacker_ip = "45.155.205.99"
    attacker_ua = "FinTech-Smurfing-AutoBot/1.0"
    start_ts = datetime.now(timezone.utc).isoformat()
    print("\n[!] LAUNCHING ATTACK SCENARIO 3: AML Structuring ('Smurfing') & Velocity Account Draining")

    first_trace = generate_trace_id("ATK3")
    last_trace = first_trace
    total_reqs = 0

    # Stage 1: Authenticate as user1002 (Seeded with $10,800.00 in Core Switch)
    status, login_body = http_request(
        "POST", "/api/v1/auth/login",
        payload={"username": "user1002", "password": "FinTech#1002$Secure"},
        headers={"X-Forwarded-For": attacker_ip, "User-Agent": attacker_ua, "X-Trace-Id": first_trace}
    )
    total_reqs += 1
    token = login_body.get("access_token", "")
    print(f"  [Stage 1] Authenticated as user1002 (Starting Balance: $10,800.00). Trace={first_trace}")

    auth_headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": attacker_ip,
        "User-Agent": attacker_ua
    }

    # Stage 2: Execute 12 rapid micro-structured transfers of $950.00 (Total attempted: $11,400.00)
    # Each individual transfer is < $1,000 and evades the $10,000 single-tx CTR threshold!
    print("  [Stage 2] Firing 12 structured transfers of $950.00 each to evade $10,000 CTR limit...")
    approved_tx = 0
    declined_tx = 0
    for i in range(1, 13):
        trc = generate_trace_id("ATK3")
        last_trace = trc
        tx_status, tx_body = http_request(
            "POST", "/api/v1/transfers/initiate",
            payload={
                "src_account": "1002",
                "dst_account": "88887777",
                "amount": 950.00,
                "remarks": f"Structured micro-settlement batch #{i}"
            },
            headers={**auth_headers, "X-Trace-Id": trc}
        )
        total_reqs += 1
        de39 = tx_body.get("iso_response_code")
        rem_bal = tx_body.get("remaining_balance")
        if de39 == "00":
            approved_tx += 1
        else:
            declined_tx += 1
        print(f"    -> Smurf Tx #{i:02d}: Amount=$950.00 | HTTP={tx_status} | ISO DE39={de39} ({tx_body.get('iso_response_desc')}) | RemBal=${rem_bal} | Trace={trc}")
        time.sleep(0.08)

    print(f"  [Stage 3] Structuring Complete: {approved_tx} Approved ($10,450 drained), {declined_tx} Declined with ISO DE39=51 (Insufficient Funds).")

    end_ts = datetime.now(timezone.utc).isoformat()
    return {
        "scenario": "Scenario 3: AML Structuring ('Smurfing') & Velocity Drain",
        "start_time": start_ts,
        "end_time": end_ts,
        "source_ip": attacker_ip,
        "target_accounts": "user1002 (Account 1002 -> Mule 88887777)",
        "first_trace_id": first_trace,
        "last_trace_id": last_trace,
        "total_requests": total_reqs
    }


def print_and_save_ground_truth(results: list):
    """Prints a Markdown Ground-Truth table and saves it to logs/ground_truth_report.md."""
    md_lines = [
        "# FinTech SOC — Simulation & Attack Ground-Truth Report",
        f"Generated on: `{datetime.now(timezone.utc).isoformat()}`\n",
        "| Phase / Scenario | Start Timestamp (UTC) | End Timestamp (UTC) | Source IP | Target Account(s) | First Trace ID | Last Trace ID | Total API Calls |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for r in results:
        md_lines.append(
            f"| **{r['scenario']}** | `{r['start_time']}` | `{r['end_time']}` | `{r['source_ip']}` | {r['target_accounts']} | `{r['first_trace_id']}` | `{r['last_trace_id']}` | {r['total_requests']} |"
        )

    report_text = "\n".join(md_lines) + "\n"
    print("\n" + "=" * 110)
    print(report_text)
    print("=" * 110)

    os.makedirs(os.path.dirname(GT_REPORT_PATH), exist_ok=True)
    with open(GT_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"[+] Ground-Truth Markdown Table saved to: {GT_REPORT_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FinTech SOC Traffic & Attack Simulator")
    parser.add_argument(
        "--mode",
        choices=["normal", "attack1", "attack2", "attack3", "full-dataset"],
        default="full-dataset",
        help="Simulation mode to execute"
    )
    parser.add_argument("--cycles", type=int, default=15, help="Number of normal customer sessions")
    args = parser.parse_args()

    summary_rows = []
    if args.mode == "normal":
        summary_rows.append(run_normal_traffic(cycles=args.cycles))
    elif args.mode == "attack1":
        summary_rows.append(run_attack_scenario_1())
    elif args.mode == "attack2":
        summary_rows.append(run_attack_scenario_2())
    elif args.mode == "attack3":
        summary_rows.append(run_attack_scenario_3())
    elif args.mode == "full-dataset":
        # Complete interleaved SOC dataset for Wireshark & SIEM analysis
        summary_rows.append(run_normal_traffic(cycles=12, delay=0.1))
        summary_rows.append(run_attack_scenario_1())
        summary_rows.append(run_normal_traffic(cycles=8, delay=0.1))
        summary_rows.append(run_attack_scenario_2())
        summary_rows.append(run_normal_traffic(cycles=8, delay=0.1))
        summary_rows.append(run_attack_scenario_3())
        summary_rows.append(run_normal_traffic(cycles=10, delay=0.1))

    print_and_save_ground_truth(summary_rows)