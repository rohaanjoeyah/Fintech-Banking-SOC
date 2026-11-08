import os
import json
import sqlite3
import logging
import threading
import socketserver
from datetime import datetime, timezone

# Configuration via environment variables (works natively on Windows & inside Docker)
HOST = os.getenv("SWITCH_HOST", "0.0.0.0")
PORT = int(os.getenv("SWITCH_PORT", 8583))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("LEDGER_DB_PATH", os.path.join(BASE_DIR, "ledger.db"))
LOG_FILE = os.getenv(
    "AUDIT_LOG_PATH",
    os.path.join( os.path.dirname(BASE_DIR), "logs", "banking_audit.json" )
)

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
db_lock = threading.Lock()

# Configure console output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CORE-SWITCH] %(levelname)s: %(message)s"
)


def write_audit_log(event_data: dict):
    """Appends a structured JSON log entry to the shared banking_audit.json file."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": "ISO8583_CORE_SWITCH",
        **event_data
    }
    with db_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")


def init_ledger_db():
    """Initializes the SQLite Core Banking Ledger and seeds 50 synthetic accounts."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                owner_name TEXT NOT NULL,
                pan TEXT NOT NULL,
                balance_cents INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS switch_transactions (
                tx_id INTEGER PRIMARY KEY AUTOINCREMENT,
                stan TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                mti TEXT NOT NULL,
                src_account TEXT NOT NULL,
                dst_account TEXT,
                amount_cents INTEGER NOT NULL,
                response_code TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        # Check if already seeded
        cursor.execute("SELECT COUNT(*) FROM accounts")
        if cursor.fetchone()[0] == 0:
            logging.info("Seeding 50 synthetic core banking accounts (1001 - 1050)...")
            sample_names = [
                "Ahmed Khan", "Sara Ali", "Zainab Tariq", "Bilal Raza", "Usman Farooq",
                "Ayesha Siddiqui", "Hamza Malik", "Fatima Noor", "Omar Sheikh", "Hira Mansoor"
            ]
            accounts_to_seed = []
            for i in range(1, 51):
                acc_id = str(1000 + i)
                name = f"{sample_names[i % len(sample_names)]} #{i}"
                pan = f"453201511283{1000 + i}"
                
                # Deterministic balances for specific attack scenarios
                if acc_id == "1001":
                    # Scenario 1 (ATO High-Value Wire target): $15,000.00
                    balance_cents = 1500000
                elif acc_id == "1002":
                    # Scenario 3 (AML Structuring target): $10,800.00
                    # Allows eleven $950 transfers ($10,450), failing on the 12th with DE39=51!
                    balance_cents = 1080000
                elif acc_id == "1003":
                    # Frozen account for testing DE39=05 (Do Not Honor)
                    balance_cents = 500000
                else:
                    # Normal accounts: between $2,500.00 and $25,000.00
                    balance_cents = (2500 + (i * 450)) * 100

                status = "FROZEN" if acc_id == "1003" else "ACTIVE"
                accounts_to_seed.append((acc_id, name, pan, balance_cents, status))

            cursor.executemany(
                "INSERT INTO accounts (account_id, owner_name, pan, balance_cents, status) VALUES (?, ?, ?, ?, ?)",
                accounts_to_seed
            )
            conn.commit()
            logging.info("Core Banking Ledger initialized successfully.")
        conn.close()


def parse_iso8583_packet(raw_str: str) -> dict:
    """
    Parses a wire-format ISO 8583 ASCII frame into a dictionary of Data Elements.
    Wire Format: ISO8583|<MTI>|DE2=...|DE3=...|DE4=...|DE11=...|DE37=...|DE102=...|DE103=...
    """
    parts = raw_str.strip().split("|")
    if len(parts) < 2 or parts[0] != "ISO8583":
        raise ValueError("Invalid ISO 8583 header")

    parsed = {"MTI": parts[1]}
    for field in parts[2:]:
        if "=" in field:
            k, v = field.split("=", 1)
            parsed[k.strip()] = v.strip()
    return parsed


def build_iso8583_response(mti: str, elements: dict) -> bytes:
    """Packs an ISO 8583 response with a 4-byte ASCII length prefix."""
    fields = [f"ISO8583|{mti}"]
    for k, v in elements.items():
        fields.append(f"{k}={v}")
    payload = "|".join(fields) + "\n"
    payload_bytes = payload.encode("utf-8")
    length_prefix = f"{len(payload_bytes):04d}".encode("utf-8")
    return length_prefix + payload_bytes


class ISO8583SwitchHandler(socketserver.BaseRequestHandler):
    """Handles incoming TCP connections on Port 8583 from the Open Banking API Gateway."""

    def handle(self):
        client_ip = self.client_address[0]
        try:
            # Read 4-byte length header
            length_bytes = self.request.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return
            msg_length = int(length_bytes.decode("utf-8"))
            raw_payload = self.request.recv(msg_length).decode("utf-8")

            iso_req = parse_iso8583_packet(raw_payload)
            req_mti = iso_req.get("MTI", "")
            pan = iso_req.get("DE2", "0000000000000000")
            proc_code = iso_req.get("DE3", "000000")
            amount_str = iso_req.get("DE4", "000000000000")
            tx_dt = iso_req.get("DE7", datetime.now(timezone.utc).strftime("%m%d%H%M%S"))
            stan = iso_req.get("DE11", "000001")
            trace_id = iso_req.get("DE37", "UNKNOWN")
            src_acc = iso_req.get("DE102", "")
            dst_acc = iso_req.get("DE103", "")

            amount_cents = int(amount_str)

            # Route by Message Type Indicator (MTI)
            if req_mti == "0100":
                # Authorization / Balance Inquiry Request -> Response MTI 0110
                resp_mti = "0110"
                resp_code, balance_cents, owner_name = self.process_balance_inquiry(src_acc)
                resp_elements = {
                    "DE2": pan,
                    "DE3": proc_code,
                    "DE4": amount_str,
                    "DE7": tx_dt,
                    "DE11": stan,
                    "DE37": trace_id,
                    "DE39": resp_code,
                    "DE54": f"{balance_cents:012d}",
                    "DE102": src_acc
                }
                write_audit_log({
                    "trace_id": trace_id,
                    "event_type": "ISO8583_AUTH_INQUIRY",
                    "switch_client_ip": client_ip,
                    "iso_mti_req": req_mti,
                    "iso_mti_resp": resp_mti,
                    "iso_proc_code": proc_code,
                    "iso_stan": stan,
                    "account_id": src_acc,
                    "iso_response_code": resp_code,
                    "balance_dollars": round(balance_cents / 100.0, 2)
                })

            elif req_mti == "0200":
                # Financial Transaction Request -> Response MTI 0210
                resp_mti = "0210"
                resp_code, new_balance_cents = self.process_financial_transfer(
                    stan, trace_id, src_acc, dst_acc, amount_cents
                )
                resp_elements = {
                    "DE2": pan,
                    "DE3": proc_code,
                    "DE4": amount_str,
                    "DE7": tx_dt,
                    "DE11": stan,
                    "DE37": trace_id,
                    "DE39": resp_code,
                    "DE54": f"{new_balance_cents:012d}",
                    "DE102": src_acc,
                    "DE103": dst_acc
                }
                write_audit_log({
                    "trace_id": trace_id,
                    "event_type": "ISO8583_FINANCIAL_TX",
                    "switch_client_ip": client_ip,
                    "iso_mti_req": req_mti,
                    "iso_mti_resp": resp_mti,
                    "iso_proc_code": proc_code,
                    "iso_stan": stan,
                    "src_account": src_acc,
                    "dst_account": dst_acc,
                    "transaction_amount": round(amount_cents / 100.0, 2),
                    "iso_response_code": resp_code,
                    "remaining_balance": round(new_balance_cents / 100.0, 2)
                })
            else:
                # Unsupported Function (DE39 = 12 Invalid Transaction)
                resp_mti = "0210"
                resp_elements = {"DE11": stan, "DE37": trace_id, "DE39": "12"}

            response_packet = build_iso8583_response(resp_mti, resp_elements)
            self.request.sendall(response_packet)
            logging.info(
                f"Processed MTI {req_mti} -> {resp_mti} | Trace={trace_id} | Acc={src_acc} | Amt=${amount_cents/100:.2f} | DE39={resp_elements['DE39']}"
            )

        except Exception as e:
            logging.error(f"Switch error handling packet from {client_ip}: {e}")

    def process_balance_inquiry(self, account_id: str):
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT balance_cents, status, owner_name FROM accounts WHERE account_id = ?",
                (account_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return "14", 0, "UNKNOWN"  # DE39=14: Invalid Account Number
            balance_cents, status, owner_name = row
            if status != "ACTIVE":
                return "05", balance_cents, owner_name  # DE39=05: Do Not Honor (Frozen)
            return "00", balance_cents, owner_name      # DE39=00: Approved

    def process_financial_transfer(self, stan: str, trace_id: str, src_acc: str, dst_acc: str, amount_cents: int):
        now_iso = datetime.now(timezone.utc).isoformat()
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT balance_cents, status FROM accounts WHERE account_id = ?",
                (src_acc,)
            )
            row = cursor.fetchone()

            if not row:
                resp_code = "14"  # Invalid Account
                new_bal = 0
            else:
                balance_cents, status = row
                if status != "ACTIVE":
                    resp_code = "05"  # Do Not Honor (Account Frozen)
                    new_bal = balance_cents
                elif amount_cents <= 0:
                    resp_code = "13"  # Invalid Amount
                    new_bal = balance_cents
                elif amount_cents > 2500000:
                    resp_code = "61"  # Exceeds Withdrawal Amount Limit ($25,000 hard switch cap)
                    new_bal = balance_cents
                elif balance_cents < amount_cents:
                    resp_code = "51"  # Insufficient Funds
                    new_bal = balance_cents
                else:
                    # Deduct from source account
                    new_bal = balance_cents - amount_cents
                    cursor.execute(
                        "UPDATE accounts SET balance_cents = ? WHERE account_id = ?",
                        (new_bal, src_acc)
                    )
                    # Credit destination if it is an internal account
                    cursor.execute(
                        "SELECT balance_cents FROM accounts WHERE account_id = ?",
                        (dst_acc,)
                    )
                    dst_row = cursor.fetchone()
                    if dst_row:
                        cursor.execute(
                            "UPDATE accounts SET balance_cents = balance_cents + ? WHERE account_id = ?",
                            (amount_cents, dst_acc)
                        )
                    resp_code = "00"  # Approved

            cursor.execute("""
                INSERT INTO switch_transactions
                (stan, trace_id, mti, src_account, dst_account, amount_cents, response_code, timestamp)
                VALUES (?, ?, '0200', ?, ?, ?, ?, ?)
            """, (stan, trace_id, src_acc, dst_acc, amount_cents, resp_code, now_iso))
            conn.commit()
            conn.close()
            return resp_code, new_bal


class ThreadedISO8583Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    init_ledger_db()
    logging.info(f"Starting ISO 8583 Core Banking Switch on {HOST}:{PORT}...")
    with ThreadedISO8583Server((HOST, PORT), ISO8583SwitchHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down ISO 8583 Core Banking Switch.")
            server.shutdown()