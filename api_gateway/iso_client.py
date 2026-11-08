import os
import socket
import random
from datetime import datetime, timezone

SWITCH_HOST = os.getenv("SWITCH_HOST", "127.0.0.1")
SWITCH_PORT = int(os.getenv("SWITCH_PORT", 8583))

# Standard ISO 8583 Data Element 39 Response Code Descriptions
ISO_RESPONSE_DESCRIPTIONS = {
    "00": "Approved or completed successfully",
    "05": "Do not honor (Account Frozen / Restricted)",
    "12": "Invalid transaction",
    "13": "Invalid amount",
    "14": "Invalid card/account number (No such account)",
    "51": "Insufficient funds",
    "61": "Exceeds withdrawal amount limit",
    "91": "Issuer or switch is inoperative"
}


def generate_stan() -> str:
    """Generates a 6-digit System Trace Audit Number (DE 11)."""
    return f"{random.randint(100000, 999999)}"


def send_iso8583_message(mti: str, elements: dict) -> dict:
    """
    Packs an ISO 8583 message with a 4-byte ASCII length header, sends it over TCP Port 8583,
    and parses the response from the Core Banking Switch.
    """
    fields = [f"ISO8583|{mti}"]
    for k, v in elements.items():
        fields.append(f"{k}={v}")
    raw_req_str = "|".join(fields) + "\n"
    payload_bytes = raw_req_str.encode("utf-8")
    framed_packet = f"{len(payload_bytes):04d}".encode("utf-8") + payload_bytes

    try:
        with socket.create_connection((SWITCH_HOST, SWITCH_PORT), timeout=5.0) as sock:
            sock.sendall(framed_packet)
            len_bytes = sock.recv(4)
            if not len_bytes or len(len_bytes) < 4:
                return {"DE39": "91", "error": "Empty switch response"}
            resp_len = int(len_bytes.decode("utf-8"))
            raw_resp_str = sock.recv(resp_len).decode("utf-8").strip()

        parts = raw_resp_str.split("|")
        parsed = {"MTI": parts[1] if len(parts) > 1 else "UNKNOWN", "raw_resp": raw_resp_str}
        for field in parts[2:]:
            if "=" in field:
                k, v = field.split("=", 1)
                parsed[k.strip()] = v.strip()
        return parsed

    except Exception as e:
        return {
            "MTI": "0210" if mti == "0200" else "0110",
            "DE39": "91",
            "error": str(e)
        }


def query_switch_balance(account_id: str, trace_id: str) -> dict:
    """Sends MTI 0100 (Balance Inquiry, Processing Code 310000) to the Core Switch."""
    stan = generate_stan()
    pan = f"453201511283{account_id}"
    tx_dt = datetime.now(timezone.utc).strftime("%m%d%H%M%S")

    elements = {
        "DE2": pan,
        "DE3": "310000",          # 310000 = Balance Inquiry
        "DE4": "000000000000",    # $0.00 for inquiry
        "DE7": tx_dt,
        "DE11": stan,
        "DE37": trace_id,
        "DE102": str(account_id)
    }
    resp = send_iso8583_message("0100", elements)
    de39 = resp.get("DE39", "91")
    bal_cents = int(resp.get("DE54", "0"))

    return {
        "iso_mti_req": "0100",
        "iso_mti_resp": resp.get("MTI", "0110"),
        "iso_stan": stan,
        "iso_response_code": de39,
        "iso_response_desc": ISO_RESPONSE_DESCRIPTIONS.get(de39, "Unknown error"),
        "balance_dollars": round(bal_cents / 100.0, 2)
    }


def execute_switch_transfer(src_account: str, dst_account: str, amount_dollars: float, trace_id: str) -> dict:
    """Sends MTI 0200 (Financial Transfer, Processing Code 400000) to the Core Switch."""
    stan = generate_stan()
    pan = f"453201511283{src_account}"
    tx_dt = datetime.now(timezone.utc).strftime("%m%d%H%M%S")
    amount_cents = int(round(amount_dollars * 100))

    elements = {
        "DE2": pan,
        "DE3": "400000",                   # 400000 = Account-to-Account Transfer
        "DE4": f"{amount_cents:012d}",     # 12-digit zero-padded amount in cents
        "DE7": tx_dt,
        "DE11": stan,
        "DE37": trace_id,
        "DE102": str(src_account),
        "DE103": str(dst_account)
    }
    resp = send_iso8583_message("0200", elements)
    de39 = resp.get("DE39", "91")
    rem_cents = int(resp.get("DE54", "0"))

    return {
        "iso_mti_req": "0200",
        "iso_mti_resp": resp.get("MTI", "0210"),
        "iso_stan": stan,
        "iso_response_code": de39,
        "iso_response_desc": ISO_RESPONSE_DESCRIPTIONS.get(de39, "Unknown error"),
        "remaining_balance": round(rem_cents / 100.0, 2)
    }