import os
import uuid
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel

from iso_client import query_switch_balance, execute_switch_transfer

app = FastAPI(title="FinTech Open Banking API Gateway", version="1.0.0")

JWT_SECRET = os.getenv("JWT_SECRET", "fintech-soc-super-secret-jwt-key-2026")
JWT_ALGORITHM = "HS256"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.getenv(
    "AUDIT_LOG_PATH",
    os.path.join(os.path.dirname(BASE_DIR), "logs", "banking_audit.json")
)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
log_lock = threading.Lock()

# Seed 50 synthetic online banking users (user1001 .. user1050)
USERS_DB = {}
BENEFICIARIES_DB = {}

for i in range(1, 51):
    acc_id = str(1000 + i)
    username = f"user{acc_id}"
    # user1001 has a weak password compromised during Scenario 1 Credential Stuffing
    if acc_id == "1001":
        password = "Password123!"
    else:
        password = f"FinTech#{acc_id}$Secure"

    USERS_DB[username] = {
        "user_id": username,
        "account_id": acc_id,
        "password": password,
        "role": "RETAIL_CUSTOMER"
    }
    BENEFICIARIES_DB[acc_id] = ["1005", "1010"]


# Pydantic Schemas
class LoginRequest(BaseModel):
    username: str
    password: str


class BeneficiaryRequest(BaseModel):
    beneficiary_account: str
    beneficiary_name: str
    bank_code: str = "EXT-MULE-BANK"


class TransferRequest(BaseModel):
    src_account: str
    dst_account: str
    amount: float
    remarks: Optional[str] = "Online Fund Transfer"


def write_api_audit_log(event_data: dict):
    """Appends a structured JSON audit record to logs/banking_audit.json."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": "FINTECH_API_GATEWAY",
        **event_data
    }
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


def get_client_ip(request: Request, x_forwarded_for: Optional[str]) -> str:
    """Extracts simulated external IP if X-Forwarded-For is present, otherwise socket IP."""
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def verify_jwt_token(authorization: Optional[str]) -> dict:
    """Decodes and validates Bearer JWT token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization Bearer header")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="JWT token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid JWT token")


@app.get("/health")
def health_check():
    return {"status": "online", "service": "FinTech Open Banking API Gateway"}


@app.post("/api/v1/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None)
):
    trace_id = x_trace_id or f"TRC-{uuid.uuid4().hex[:10].upper()}"
    client_ip = get_client_ip(request, x_forwarded_for)
    user_agent = request.headers.get("user-agent", "unknown")

    user = USERS_DB.get(payload.username)
    if not user or user["password"] != payload.password:
        write_api_audit_log({
            "trace_id": trace_id,
            "event_type": "AUTH_FAIL",
            "http_method": "POST",
            "endpoint": "/api/v1/auth/login",
            "status_code": 401,
            "client_ip": client_ip,
            "user_id": payload.username,
            "account_id": user["account_id"] if user else "UNKNOWN",
            "user_agent": user_agent,
            "reason": "Invalid username or password"
        })
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_payload = {
        "sub": user["user_id"],
        "account_id": user["account_id"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }
    token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    write_api_audit_log({
        "trace_id": trace_id,
        "event_type": "AUTH_SUCCESS",
        "http_method": "POST",
        "endpoint": "/api/v1/auth/login",
        "status_code": 200,
        "client_ip": client_ip,
        "user_id": user["user_id"],
        "account_id": user["account_id"],
        "user_agent": user_agent
    })
    return {
        "status": "success",
        "trace_id": trace_id,
        "access_token": token,
        "account_id": user["account_id"]
    }


@app.get("/api/v1/accounts/{account_id}/balance")
def get_account_balance(
    account_id: str,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_forwarded_for: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None)
):
    trace_id = x_trace_id or f"TRC-{uuid.uuid4().hex[:10].upper()}"
    client_ip = get_client_ip(request, x_forwarded_for)
    user_agent = request.headers.get("user-agent", "unknown")

    claims = verify_jwt_token(authorization)
    jwt_user_id = claims["sub"]
    jwt_account_id = claims["account_id"]

    # Intentional OWASP API1:2023 (BOLA / IDOR) vulnerability for Scenario 2:
    # The API validates the JWT token, but fails to enforce that jwt_account_id == account_id.
    is_bola_access = (jwt_account_id != account_id)

    iso_res = query_switch_balance(account_id, trace_id)
    http_status = 200 if iso_res["iso_response_code"] == "00" else 404

    write_api_audit_log({
        "trace_id": trace_id,
        "event_type": "ACCOUNT_BALANCE_QUERY",
        "http_method": "GET",
        "endpoint": f"/api/v1/accounts/{account_id}/balance",
        "status_code": http_status,
        "client_ip": client_ip,
        "user_id": jwt_user_id,
        "authenticated_account": jwt_account_id,
        "target_account": account_id,
        "bola_indicator": is_bola_access,
        "iso_mti": iso_res["iso_mti_req"],
        "iso_stan": iso_res["iso_stan"],
        "iso_response_code": iso_res["iso_response_code"],
        "balance_dollars": iso_res["balance_dollars"],
        "user_agent": user_agent
    })

    return {
        "trace_id": trace_id,
        "account_id": account_id,
        "balance": iso_res["balance_dollars"],
        "currency": "USD",
        "iso_response_code": iso_res["iso_response_code"],
        "iso_response_desc": iso_res["iso_response_desc"]
    }


@app.post("/api/v1/beneficiaries/add")
def add_beneficiary(
    payload: BeneficiaryRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_forwarded_for: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None)
):
    trace_id = x_trace_id or f"TRC-{uuid.uuid4().hex[:10].upper()}"
    client_ip = get_client_ip(request, x_forwarded_for)
    user_agent = request.headers.get("user-agent", "unknown")

    claims = verify_jwt_token(authorization)
    jwt_user_id = claims["sub"]
    jwt_account_id = claims["account_id"]

    BENEFICIARIES_DB.setdefault(jwt_account_id, []).append(payload.beneficiary_account)

    write_api_audit_log({
        "trace_id": trace_id,
        "event_type": "BENEFICIARY_ADDED",
        "http_method": "POST",
        "endpoint": "/api/v1/beneficiaries/add",
        "status_code": 201,
        "client_ip": client_ip,
        "user_id": jwt_user_id,
        "account_id": jwt_account_id,
        "beneficiary_account": payload.beneficiary_account,
        "beneficiary_name": payload.beneficiary_name,
        "bank_code": payload.bank_code,
        "user_agent": user_agent
    })

    return {
        "status": "beneficiary_added",
        "trace_id": trace_id,
        "account_id": jwt_account_id,
        "beneficiary_account": payload.beneficiary_account
    }


@app.post("/api/v1/transfers/initiate")
def initiate_transfer(
    payload: TransferRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_forwarded_for: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None)
):
    trace_id = x_trace_id or f"TRC-{uuid.uuid4().hex[:10].upper()}"
    client_ip = get_client_ip(request, x_forwarded_for)
    user_agent = request.headers.get("user-agent", "unknown")

    claims = verify_jwt_token(authorization)
    jwt_user_id = claims["sub"]
    jwt_account_id = claims["account_id"]

    if payload.src_account != jwt_account_id:
        write_api_audit_log({
            "trace_id": trace_id,
            "event_type": "UNAUTHORIZED_TRANSFER_ATTEMPT",
            "http_method": "POST",
            "endpoint": "/api/v1/transfers/initiate",
            "status_code": 403,
            "client_ip": client_ip,
            "user_id": jwt_user_id,
            "authenticated_account": jwt_account_id,
            "src_account": payload.src_account,
            "dst_account": payload.dst_account,
            "transaction_amount": payload.amount,
            "user_agent": user_agent
        })
        raise HTTPException(status_code=403, detail="Cannot initiate transfer from another user's account")

    # Execute southbound ISO 8583 MTI 0200 transaction against Core Switch
    iso_res = execute_switch_transfer(
        src_account=payload.src_account,
        dst_account=payload.dst_account,
        amount_dollars=payload.amount,
        trace_id=trace_id
    )

    de39 = iso_res["iso_response_code"]
    http_status = 200 if de39 == "00" else 422

    # Static Single-Transaction AML Rule ($10,000 CTR Reporting Limit)
    # Scenario 3 attackers evade this by structuring $950 transfers!
    static_aml_flag = "CTR_REPORTING_TRIGGERED" if payload.amount >= 10000.0 else "BELOW_STATIC_LIMIT"

    write_api_audit_log({
        "trace_id": trace_id,
        "event_type": "TRANSACTION_INITIATED",
        "http_method": "POST",
        "endpoint": "/api/v1/transfers/initiate",
        "status_code": http_status,
        "client_ip": client_ip,
        "user_id": jwt_user_id,
        "src_account": payload.src_account,
        "dst_account": payload.dst_account,
        "transaction_amount": round(payload.amount, 2),
        "static_aml_flag": static_aml_flag,
        "iso_mti": iso_res["iso_mti_req"],
        "iso_stan": iso_res["iso_stan"],
        "iso_response_code": de39,
        "iso_response_desc": iso_res["iso_response_desc"],
        "remaining_balance": iso_res["remaining_balance"],
        "remarks": payload.remarks,
        "user_agent": user_agent
    })

    return {
        "trace_id": trace_id,
        "status": "approved" if de39 == "00" else "declined",
        "amount": payload.amount,
        "iso_mti": iso_res["iso_mti_resp"],
        "iso_stan": iso_res["iso_stan"],
        "iso_response_code": de39,
        "iso_response_desc": iso_res["iso_response_desc"],
        "remaining_balance": iso_res["remaining_balance"]
    }