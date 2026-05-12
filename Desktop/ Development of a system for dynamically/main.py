"""
Dynamic Access Control System - FastAPI Main Server
Monitors user behavior to dynamically grant, restrict, or block access.
"""

from typing import Optional
from datetime import datetime, timezone, timedelta
import asyncio
import json
import os

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from models import Base, engine, get_db, User, BehavioralProfile, AccessLog
from auth import create_access_token, get_current_user
from behavior import calculate_risk_score, analyze_behavior_data


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    role: str


class KeystrokeItem(BaseModel):
    key: Optional[str] = None
    keyCode: Optional[int] = None
    timestamp: int
    dwell_time: Optional[float] = Field(None, alias="dwellTime")
    flight_time: Optional[float] = Field(None, alias="flightTime")

    model_config = {"populate_by_name": True}


class MouseMovementItem(BaseModel):
    x: float
    y: float
    timestamp: int


class BehaviorPayload(BaseModel):
    keystrokes: list[KeystrokeItem] = []
    mouse_movements: list[MouseMovementItem] = []
    session_duration: Optional[int] = 0


class OTPRequest(BaseModel):
    otp: str


class DemoScenarioRequest(BaseModel):
    scenario: str


class AdminActionRequest(BaseModel):
    user_id: int
    action: str


class SecurityEventRequest(BaseModel):
    action: str
    message: str
    risk_score: Optional[float] = 0.0


app = FastAPI(title="Dynamic Access Control System")
templates = Jinja2Templates(directory="templates")


def static_version() -> str:
    """Cache-bust query string. Uses the newest mtime under /static so the
    browser always picks up freshly edited assets (i18n.js, behavior-engine.js,
    …) without a manual hard refresh."""
    try:
        latest = 0.0
        for root_dir, _dirs, files in os.walk("static"):
            for fname in files:
                p = os.path.join(root_dir, fname)
                try:
                    latest = max(latest, os.path.getmtime(p))
                except OSError:
                    continue
        return str(int(latest)) if latest else "1"
    except Exception:
        return "1"

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

Base.metadata.create_all(bind=engine)

# Runtime state for demo MFA / blocked sessions
STEP_UP_EXPIRY: dict[int, datetime] = {}
BLOCKED_USERS: dict[int, datetime] = {}
ADMIN_FORCED_STEP_UP: dict[int, datetime] = {}
LOGIN_COOLDOWNS: dict[str, datetime] = {}
AUTH_LOGIN_WINDOW: dict[str, list[datetime]] = {}

AUTH_WARNING_THRESHOLD = 3
AUTH_LOCK_THRESHOLD = 5
AUTH_LOCK_MINUTES = 5


def ensure_schema_and_seed_users():
    """Add missing role column and seed demo users."""
    with engine.begin() as conn:
        columns = conn.execute(text("PRAGMA table_info(users)")).fetchall()
        existing = {c[1] for c in columns}
        auth_columns = {
            "role": "ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'employee' NOT NULL",
            "failed_attempts": "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0 NOT NULL",
            "last_failed_login_at": "ALTER TABLE users ADD COLUMN last_failed_login_at DATETIME",
            "auth_risk_score": "ALTER TABLE users ADD COLUMN auth_risk_score FLOAT DEFAULT 0 NOT NULL",
            "account_locked_until": "ALTER TABLE users ADD COLUMN account_locked_until DATETIME",
            "last_login_ip": "ALTER TABLE users ADD COLUMN last_login_ip VARCHAR",
            "last_login_user_agent": "ALTER TABLE users ADD COLUMN last_login_user_agent VARCHAR",
        }
        for column_name, ddl in auth_columns.items():
            if column_name not in existing:
                conn.execute(text(ddl))

    with Session(bind=engine) as db:
        # Test users for diploma demo — covers all 3 roles, different
        # behavioral profiles and demonstration scenarios.
        seed_users = [
            # === ADMINS ===
            {"username": "admin", "password": "admin123",
             "email": "admin@example.com", "role": "admin"},
            {"username": "security_admin", "password": "secure123",
             "email": "security@example.com", "role": "admin"},

            # === EMPLOYEES (different departments / behavioral patterns) ===
            {"username": "employee", "password": "employee123",
             "email": "employee@example.com", "role": "employee"},
            {"username": "alice_hr", "password": "alice123",
             "email": "alice@example.com", "role": "employee"},
            {"username": "bob_engineer", "password": "bob123",
             "email": "bob@example.com", "role": "employee"},
            {"username": "carol_sales", "password": "carol123",
             "email": "carol@example.com", "role": "employee"},
            {"username": "dmitry_finance", "password": "dmitry123",
             "email": "dmitry@example.com", "role": "employee"},
            {"username": "nurlan_kz", "password": "nurlan123",
             "email": "nurlan@example.kz", "role": "employee"},
            {"username": "aigerim_kz", "password": "aigerim123",
             "email": "aigerim@example.kz", "role": "employee"},

            # === AUDITORS (read-only / compliance) ===
            {"username": "auditor", "password": "auditor123",
             "email": "auditor@example.com", "role": "auditor"},
            {"username": "john_auditor", "password": "john123",
             "email": "john@example.com", "role": "auditor"},
            {"username": "maria_compliance", "password": "maria123",
             "email": "maria@example.com", "role": "auditor"},
        ]
        for payload in seed_users:
            user = db.query(User).filter(User.username == payload["username"]).first()
            if user:
                user.password = payload["password"]
                user.email = payload["email"]
                user.role = payload["role"]
                user.failed_attempts = getattr(user, "failed_attempts", 0) or 0
                user.auth_risk_score = getattr(user, "auth_risk_score", 0.0) or 0.0
            else:
                db.add(User(**payload))
        db.commit()

        # Ensure every seeded user has a BehavioralProfile row so that
        # admin_user_snapshot can compute typing/mouse baselines without
        # hitting NoneType errors before any real behavior data is captured.
        for payload in seed_users:
            user = db.query(User).filter(User.username == payload["username"]).first()
            if not user:
                continue
            profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user.id).first()
            if profile is None:
                db.add(BehavioralProfile(
                    user_id=user.id,
                    avg_typing_speed=38.0,
                    avg_dwell_time=85.0,
                    avg_flight_time=120.0,
                    avg_mouse_velocity=1.2,
                ))
        db.commit()


ensure_schema_and_seed_users()

# Clear any stale session locks on startup
BLOCKED_USERS.clear()
STEP_UP_EXPIRY.clear()
ADMIN_FORCED_STEP_UP.clear()


def threat_type_from_signals(risk_score: float, reasons: list[str]) -> str:
    reason_text = " ".join(reasons).lower()
    if risk_score > 85:
        return "Possible session hijacking"
    if "automated" in reason_text or "bot" in reason_text:
        return "Possible bot"
    if risk_score > 50:
        return "Suspicious behavior"
    return "Normal user"


def normalize_role(role: Optional[str]) -> str:
    return (role or "employee").strip().lower()


def get_client_fingerprint(request: Request) -> tuple[str, str]:
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")[:255]
    return client_ip, user_agent


def format_minutes(seconds: int) -> int:
    return max(1, int(round(seconds / 60)))


def auth_event_action(event_type: str) -> str:
    return f"auth_{event_type}"


def normalize_utc_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_step_up_verified(user_id: int) -> bool:
    """Check if user's step-up authentication is still valid."""
    if user_id not in STEP_UP_EXPIRY:
        return False
    expiry = STEP_UP_EXPIRY[user_id]
    if expiry <= datetime.now(timezone.utc):
        STEP_UP_EXPIRY.pop(user_id, None)
        return False
    return True


def apply_admin_forced_policy(user_id: int, policy: dict, mfa_verified: bool) -> dict:
    """Apply admin-forced policies like forced step-up authentication."""
    if user_id in ADMIN_FORCED_STEP_UP:
        expiry = ADMIN_FORCED_STEP_UP[user_id]
        if expiry > datetime.now(timezone.utc):
            policy["requires_mfa"] = True
            policy["access_decision"] = "Step-up authentication required (forced by admin)"
            return policy
        else:
            ADMIN_FORCED_STEP_UP.pop(user_id, None)
    return policy


def get_latest_behavior_log(db: Session, user_id: int) -> Optional[object]:
    """Get the most recent access log for a user."""
    return (
        db.query(AccessLog)
        .filter(AccessLog.user_id == user_id)
        .order_by(AccessLog.timestamp.desc())
        .first()
    )


def get_latest_risk_score(db: Session, user_id: int) -> float:
    """Get the latest risk score for a user."""
    latest_log = get_latest_behavior_log(db, user_id)
    return float(latest_log.risk_score or 0.0) if latest_log else 0.0


def reset_user_baseline(db: Session, user_id: int):
    """Reset a user's behavioral baseline to defaults."""
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user_id).first()
    if profile:
        profile.avg_typing_speed = 0.0
        profile.avg_dwell_time = 0.0
        profile.avg_flight_time = 0.0
        profile.avg_mouse_velocity = 0.0
        profile.last_updated = datetime.now(timezone.utc)
        db.commit()


def cleanup_expired_access_state(user_id: int):
    """Clean up any expired access control states for a user."""
    now = datetime.now(timezone.utc)
    
    # Clean expired step-up verification
    if user_id in STEP_UP_EXPIRY:
        if STEP_UP_EXPIRY[user_id] <= now:
            STEP_UP_EXPIRY.pop(user_id, None)
    
    # Clean expired admin forced step-up
    if user_id in ADMIN_FORCED_STEP_UP:
        if ADMIN_FORCED_STEP_UP[user_id] <= now:
            ADMIN_FORCED_STEP_UP.pop(user_id, None)
    
    # Clean expired user lockup
    if user_id in BLOCKED_USERS:
        if BLOCKED_USERS[user_id] <= now:
            BLOCKED_USERS.pop(user_id, None)


def classify_risk_level(risk_score: float) -> str:
    """Classify risk level based on score."""
    if risk_score >= 80:
        return "Critical"
    if risk_score >= 50:
        return "High"
    if risk_score >= 25:
        return "Medium"
    return "Low"


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Dependency to require admin role."""
    role = normalize_role(current_user.get("role", "employee"))
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def build_admin_user_snapshot(db: Session, user: User) -> dict:
    """Build a snapshot of user state for admin analytics."""
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user.id).first()
    latest_log = get_latest_behavior_log(db, user.id)
    risk_score = float(latest_log.risk_score or 0.0) if latest_log else 0.0
    
    return {
        "user_id": user.id,
        "username": user.username,
        "role": normalize_role(user.role),
        "current_risk": risk_score,
        "trust_score": max(0, 100 - risk_score),
        "risk_level": classify_risk_level(risk_score),
        "session_status": "Blocked" if user.id in BLOCKED_USERS else ("Suspicious" if risk_score >= 50 else "Active"),
        "last_activity": latest_log.timestamp.isoformat() if latest_log else None,
        "access_decision": "Denied" if risk_score >= 80 else ("Limited" if risk_score >= 50 else "Full"),
        "baseline_typing": profile.avg_typing_speed if profile else 0.0,
        "baseline_mouse": profile.avg_mouse_velocity if profile else 0.0,
    }







def log_auth_event(
    db: Session,
    user_id: int,
    username: str,
    event_type: str,
    risk_score: float,
    system_action: str,
    request: Request,
    message: str,
):
    client_ip, user_agent = get_client_fingerprint(request)
    user_role = None
    if user_id:
        user_row = db.query(User).filter(User.id == user_id).first()
        user_role = normalize_role(user_row.role if user_row else None)
    details = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "role": user_role,
        "event_type": event_type,
        "ip": client_ip,
        "device": user_agent,
        "risk_level": classify_risk_level(risk_score),
        "system_action": system_action,
        "message": message,
    }
    db.add(
        AccessLog(
            user_id=user_id,
            ip_address=client_ip,
            action=auth_event_action(event_type),
            risk_score=float(risk_score or 0.0),
            details=json.dumps(details, ensure_ascii=False),
        )
    )


def set_auth_lock(user: User, failed_attempts: int) -> int:
    lock_minutes = min(10, AUTH_LOCK_MINUTES + max(0, failed_attempts - AUTH_LOCK_THRESHOLD))
    user.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)
    return lock_minutes


def clear_expired_auth_lock(user: User) -> bool:
    lock_until = normalize_utc_datetime(user.account_locked_until)
    if lock_until and lock_until <= datetime.now(timezone.utc):
        user.account_locked_until = None
        user.failed_attempts = 0
        user.auth_risk_score = 0.0
        return True
    return False


def record_failed_login(user: User, request: Request, db: Session, reason: str) -> tuple[dict, int]:
    client_ip, user_agent = get_client_fingerprint(request)
    now = datetime.now(timezone.utc)
    user.failed_attempts = (user.failed_attempts or 0) + 1
    user.last_failed_login_at = now
    user.auth_risk_score = float(user.auth_risk_score or 0.0) + 10.0
    auth_message = "Invalid username or password"
    warning_message = None
    status_code = 401

    if user.failed_attempts >= AUTH_WARNING_THRESHOLD:
        user.auth_risk_score += 25.0
        warning_message = "Multiple failed login attempts detected"
        auth_message = warning_message

    if user.failed_attempts >= AUTH_LOCK_THRESHOLD:
        lock_minutes = set_auth_lock(user, user.failed_attempts)
        user.auth_risk_score = max(float(user.auth_risk_score or 0.0), 90.0)
        warning_message = "Account temporarily locked due to suspicious activity"
        auth_message = warning_message
        status_code = 423
        log_auth_event(
            db,
            user.id,
            user.username,
            "account_locked",
            user.auth_risk_score,
            f"Lock account for {lock_minutes} minutes",
            request,
            warning_message,
        )
    elif user.failed_attempts == AUTH_WARNING_THRESHOLD:
        log_auth_event(
            db,
            user.id,
            user.username,
            "suspicious",
            user.auth_risk_score,
            "Increase authentication scrutiny",
            request,
            warning_message or auth_message,
        )

    user_device_hint = f"{client_ip} | {user_agent}"
    login_window = AUTH_LOGIN_WINDOW.setdefault(user.username.lower(), [])
    login_window.append(now)
    cutoff = now - timedelta(minutes=10)
    AUTH_LOGIN_WINDOW[user.username.lower()] = [t for t in login_window if t >= cutoff]
    cooldown_seconds = min(12, 1 + user.failed_attempts * 2)
    LOGIN_COOLDOWNS[user.username.lower()] = now + timedelta(seconds=cooldown_seconds)

    log_auth_event(
        db,
        user.id,
        user.username,
        "failed",
        user.auth_risk_score,
        f"Throttle login for {cooldown_seconds}s",
        request,
        f"{reason} | {user_device_hint}",
    )
    db.commit()
    return {
        "detail": auth_message,
        "warning_message": warning_message,
        "failed_attempts": user.failed_attempts,
        "auth_risk_score": round(float(user.auth_risk_score or 0.0), 1),
        "account_locked_until": user.account_locked_until.isoformat() if user.account_locked_until else None,
        "retry_after_seconds": cooldown_seconds,
    }, status_code


def record_successful_login(user: User, request: Request, db: Session, risk_note: Optional[str] = None):
    client_ip, user_agent = get_client_fingerprint(request)
    device_changed = bool(user.last_login_user_agent and user.last_login_user_agent != user_agent)
    ip_changed = bool(user.last_login_ip and user.last_login_ip != client_ip)
    auth_risk_score = float(user.auth_risk_score or 0.0)

    unlocked = clear_expired_auth_lock(user)
    if unlocked:
        log_auth_event(
            db,
            user.id,
            user.username,
            "account_unlocked",
            max(auth_risk_score, 10.0),
            "Clear temporary account lock",
            request,
            "Account lock expired and was cleared",
        )

    if device_changed or ip_changed:
        auth_risk_score += 5.0
        risk_note = risk_note or "Known user logged in from a new device"
        log_auth_event(
            db,
            user.id,
            user.username,
            "device_change",
            auth_risk_score,
            "Increase auth risk slightly",
            request,
            risk_note,
        )

    user.failed_attempts = 0
    user.last_failed_login_at = None
    user.auth_risk_score = 0.0
    user.account_locked_until = None
    user.last_login_ip = client_ip
    user.last_login_user_agent = user_agent
    LOGIN_COOLDOWNS.pop(user.username.lower(), None)
    AUTH_LOGIN_WINDOW.pop(user.username.lower(), None)
    log_auth_event(
        db,
        user.id,
        user.username,
        "success",
        auth_risk_score,
        "Issue JWT and reset counters",
        request,
        "Successful login",
    )
    db.commit()


def classify_risk_level(risk_score: float) -> str:
    if risk_score >= 80:
        return "Critical"
    if risk_score >= 50:
        return "Medium"
    return "Low"


def cleanup_expired_access_state(user_id: int):
    now = datetime.now(timezone.utc)
    for store in (STEP_UP_EXPIRY, BLOCKED_USERS, ADMIN_FORCED_STEP_UP):
        expiry = store.get(user_id)
        if expiry and expiry <= now:
            store.pop(user_id, None)


def get_latest_risk_score(db: Session, user_id: int) -> float:
    latest_behavior = get_latest_behavior_log(db, user_id)
    return float(latest_behavior.risk_score or 0.0) if latest_behavior else 0.0


def log_denied_access(
    db: Session,
    request: Request,
    current_user: dict,
    resource: str,
    reason: str,
    system_action: str,
    risk_score: float,
):
    client_ip = request.client.host if request and request.client else "unknown"
    details = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": current_user.get("username", "unknown"),
        "role": normalize_role(current_user.get("role")),
        "resource": resource,
        "risk_score": round(float(risk_score or 0.0), 1),
        "reason": reason,
        "system_action": system_action,
        "client_ip": client_ip,
    }
    db.add(
        AccessLog(
            user_id=current_user.get("user_id"),
            ip_address=client_ip,
            action=f"access_denied:{resource}",
            risk_score=float(risk_score or 0.0),
            details=json.dumps(details, ensure_ascii=False),
        )
    )
    db.commit()


def decision_from_role_risk(role: str, risk_score: float, mfa_verified: bool) -> dict:
    """Final access decision based on role, current behavior risk, and step-up state."""
    role_name = normalize_role(role)
    risk_level = classify_risk_level(risk_score)

    if role_name == "admin":
        if risk_score >= 80:
            return {
                "final_access_decision": "Session locked due to critical risk",
                "risk_level": risk_level,
                "access_decision": "Access denied: high behavioral risk",
                "data_protection": "Hidden",
                "requires_mfa": False,
                "resource_status": "locked",
                "blocked": True,
            }
        if risk_score >= 50 and not mfa_verified:
            return {
                "final_access_decision": "Step-up authentication required",
                "risk_level": risk_level,
                "access_decision": "Step-up authentication required",
                "data_protection": "Masked",
                "requires_mfa": True,
                "resource_status": "step_up_required",
                "blocked": False,
            }
        return {
            "final_access_decision": "Full access",
            "risk_level": risk_level,
            "access_decision": "Full access",
            "data_protection": "Fully visible",
            "requires_mfa": False,
            "resource_status": "allowed",
            "blocked": False,
        }

    if role_name == "employee":
        if risk_score >= 80:
            return {
                "final_access_decision": "Access denied: high behavioral risk",
                "risk_level": risk_level,
                "access_decision": "Access denied: high behavioral risk",
                "data_protection": "Hidden",
                "requires_mfa": False,
                "resource_status": "forbidden",
                "blocked": True,
            }
        if risk_score >= 50:
            return {
                "final_access_decision": "Masked access",
                "risk_level": risk_level,
                "access_decision": "Masked access",
                "data_protection": "Masked",
                "requires_mfa": False,
                "resource_status": "masked",
                "blocked": False,
            }
        return {
            "final_access_decision": "Limited access",
            "risk_level": risk_level,
            "access_decision": "Limited access",
            "data_protection": "Partially visible",
            "requires_mfa": False,
            "resource_status": "limited",
            "blocked": False,
        }

    if role_name == "auditor":
        if risk_score >= 80:
            return {
                "final_access_decision": "Access denied: high behavioral risk",
                "risk_level": risk_level,
                "access_decision": "Access denied: high behavioral risk",
                "data_protection": "Hidden",
                "requires_mfa": False,
                "resource_status": "forbidden",
                "blocked": True,
            }
        if risk_score >= 50:
            return {
                "final_access_decision": "Access denied: insufficient role",
                "risk_level": risk_level,
                "access_decision": "Access denied: insufficient role",
                "data_protection": "Restricted",
                "requires_mfa": False,
                "resource_status": "restricted",
                "blocked": True,
            }
        return {
            "final_access_decision": "Read-only masked access",
            "risk_level": risk_level,
            "access_decision": "Read-only masked access",
            "data_protection": "Masked",
            "requires_mfa": False,
            "resource_status": "read_only",
            "blocked": False,
        }

    return {
        "final_access_decision": "Limited access",
        "risk_level": risk_level,
        "access_decision": "Limited access",
        "data_protection": "Partially visible",
        "requires_mfa": False,
        "resource_status": "limited",
        "blocked": False,
    }


def is_step_up_verified(user_id: int) -> bool:
    expiry = STEP_UP_EXPIRY.get(user_id)
    return bool(expiry and expiry > datetime.now(timezone.utc))


def is_role_admin(role: str) -> bool:
    return normalize_role(role) == "admin"


def is_admin_analytics_path(path: str) -> bool:
    return path.startswith("/admin/analytics") or path.startswith("/api/admin/analytics")


def require_admin(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    role = normalize_role(current_user.get("role"))
    user_id = current_user.get("user_id")
    analytics_access = is_admin_analytics_path(request.url.path)
    cleanup_expired_access_state(user_id)

    if not is_role_admin(role):
        log_denied_access(
            db,
            request,
            current_user,
            "admin_analytics",
            "Access denied: insufficient role",
            "deny_access",
            get_latest_risk_score(db, user_id),
        )
        raise HTTPException(status_code=403, detail="Access denied: insufficient role")

    if analytics_access:
        return current_user

    risk_score = get_latest_risk_score(db, user_id)
    if user_id in BLOCKED_USERS:
        log_denied_access(
            db,
            request,
            current_user,
            "admin_analytics",
            "Session locked due to critical risk",
            "lock_session",
            risk_score,
        )
        raise HTTPException(status_code=423, detail="Session locked due to critical risk")

    policy = apply_admin_forced_policy(user_id, decision_from_role_risk(role, risk_score, is_step_up_verified(user_id)), is_step_up_verified(user_id))
    if policy["blocked"]:
        BLOCKED_USERS[user_id] = datetime.now(timezone.utc) + timedelta(minutes=15)
        log_denied_access(
            db,
            request,
            current_user,
            "admin_analytics",
            "Session locked due to critical risk",
            "lock_session",
            risk_score,
        )
        raise HTTPException(status_code=423, detail="Session locked due to critical risk")
    if policy["requires_mfa"]:
        log_denied_access(
            db,
            request,
            current_user,
            "admin_analytics",
            "Step-up authentication required",
            "require_step_up",
            risk_score,
        )
        raise HTTPException(status_code=403, detail="Step-up authentication required")
    return current_user


def is_admin_step_up_forced(user_id: int) -> bool:
    expiry = ADMIN_FORCED_STEP_UP.get(user_id)
    return bool(expiry and expiry > datetime.now(timezone.utc))


def apply_admin_forced_policy(user_id: int, policy: dict, mfa_verified: bool) -> dict:
    if policy.get("blocked"):
        return policy
    if is_admin_step_up_forced(user_id) and not mfa_verified:
        return {
            **policy,
            "risk_level": "Medium",
            "access_decision": "Step-up authentication required (Admin action)",
            "data_protection": "Masked",
            "requires_mfa": True,
            "resource_status": "step_up_required",
            "blocked": False,
        }
    return policy


def reset_user_baseline(db: Session, user_id: int):
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user_id).first()
    if profile:
        profile.avg_typing_speed = 0.0
        profile.avg_dwell_time = 0.0
        profile.avg_flight_time = 0.0
        profile.avg_mouse_velocity = 0.0
        profile.typing_samples = 0
        profile.mouse_samples = 0


def get_latest_behavior_log(db: Session, user_id: int):
    return (
        db.query(AccessLog)
        .filter(AccessLog.user_id == user_id, AccessLog.action.like("behavior_analysis:%"))
        .order_by(AccessLog.timestamp.desc())
        .first()
    )


def session_status_for_user(policy: dict, user_id: int, risk_score: float, role: str) -> str:
    now = datetime.now(timezone.utc)
    blocked_until = BLOCKED_USERS.get(user_id)
    if blocked_until and blocked_until > now:
        return "Blocked"
    if policy.get("requires_mfa"):
        return "Step-up required"
    if policy.get("resource_status") == "masked":
        return "Masked"
    if policy.get("resource_status") == "read_only":
        return "Read-only"
    if role == "auditor" and risk_score < 50:
        return "Read-only"
    if risk_score >= 50:
        return "Suspicious"
    return "Active"


PRIVILEGED_ROLES = {"admin", "security_admin"}


def is_privileged_role(role: Optional[str]) -> bool:
    return normalize_role(role) in PRIVILEGED_ROLES


def access_scope_for_role(role: Optional[str]) -> str:
    """What the user is allowed to access by role, independent of risk."""
    r = normalize_role(role)
    if r == "admin":
        return "Admin access"
    if r == "security_admin":
        return "Security admin access"
    if r == "employee":
        return "Employee access"
    if r == "auditor":
        return "Auditor read-only access"
    return "Limited access"


def risk_action_for_policy(policy: dict, session_status: str, risk_score: float) -> str:
    """
    What the system applied **because of behavior risk** (NOT because of the
    user's role). E.g. an auditor's default "read-only masked" view is
    conveyed by `access_scope`, not by `risk_action`.
    """
    if session_status == "Blocked" or policy.get("blocked"):
        return "Access denied"
    if policy.get("requires_mfa"):
        return "Require MFA"
    protection = (policy.get("data_protection") or "").lower()
    # Only count data masking as a risk-based action when the risk actually
    # triggered it. Role-default masking (e.g. auditor at risk 0) is not a
    # behavior response.
    if risk_score >= 50 and protection in ("masked", "restricted", "hidden"):
        return "Sensitive data masked"
    if risk_score >= 25:
        return "Monitored"
    return "No restriction"


def recommended_admin_action(
    risk_score: float,
    session_status: str,
    privileged: bool,
) -> str:
    """What the admin should do next."""
    if session_status == "Blocked":
        return "Investigate session and unlock manually if benign"
    if risk_score >= 80:
        base = "Lock session immediately"
    elif risk_score >= 60:
        base = "Require MFA or Lock Session"
    elif risk_score >= 40:
        base = "Require MFA"
    elif risk_score >= 25:
        base = "Monitor closely"
    else:
        base = "No action needed"

    if privileged and risk_score >= 25:
        return f"Privileged Account — {base}"
    return base


# Friendly labels for behavior-engine categories. Used by main_reason_for_user
# to compose short, varied incident descriptions instead of repeating the same
# generic "Mouse movement pattern …" line for every high-risk user.
BX_REASON_LABELS = {
    "typing_anomaly": "Suspicious typing rhythm",
    "paste_detected": "Password pasted",
    "robotic_mouse": "Mouse automation detected",
    "click_automation": "Click automation detected",
    "tab_switching": "Frequent tab switching",
    "session_anomaly": "Hyperactive session burst",
    "device_change": "Device fingerprint changed",
    "navigation_anomaly": "Privilege escalation attempt",
    "resource_abuse": "Resource abuse",
    "impossible_travel": "Impossible travel detected",
}

# Deterministic demo reasons used as a fallback so the Priority Incidents
# section is varied for the diploma demo even when no live engine events are
# available for a given user.
_DEMO_INCIDENT_REASONS = [
    "Mouse automation detected + Hyperactive session burst",
    "Impossible travel + Resource abuse",
    "Privilege escalation attempt",
    "Suspicious typing rhythm + Device fingerprint changed",
    "Click automation detected + Frequent tab switching",
    "Resource abuse + Suspicious typing rhythm",
    "Password pasted + Device fingerprint changed",
    "Impossible travel + Privilege escalation attempt",
    "Mouse automation detected + Resource abuse",
]


def _parse_behavior_reasons(latest_behavior_log) -> str:
    """Extract the first human reason out of `behavior_analysis:*` log details."""
    if not latest_behavior_log:
        return ""
    raw = (latest_behavior_log.details or "").strip()
    if not raw:
        return ""
    text = raw
    if text.startswith("[") and text.endswith("]"):
        try:
            import ast
            parsed = ast.literal_eval(text)
            if isinstance(parsed, (list, tuple)) and parsed:
                text = str(parsed[0])
        except (ValueError, SyntaxError):
            pass
    if text.lower().strip().rstrip(".") == "no anomalies detected":
        return ""
    for separator in ("; ", " | ", ". "):
        if separator in text:
            text = text.split(separator)[0].strip()
            break
    return text.strip()


def main_reason_for_user(
    db: Session,
    user_id: int,
    risk_score: float,
    privileged: bool,
    latest_behavior_log=None,
) -> str:
    """
    Build a short, human-readable anomaly summary for the admin dashboard.

    Strategy:
      1. Look at the last 30 minutes of behavior-engine `bx_*` events for
         this user and join the top two distinct categories (e.g.
         "Mouse automation detected + Resource abuse"). This naturally
         produces varied descriptions per user.
      2. Otherwise, try to recover the first parsed reason from the latest
         `behavior_analysis:*` log entry.
      3. Otherwise, when the user is still high-risk, fall back to a
         deterministic demo reason based on `user_id` so the dashboard
         stays informative during the diploma presentation.
      4. Otherwise return "—".
    """
    # Only surface a reason when there's actually something to be concerned
    # about. A privileged role browsing normally (risk 0) should not show an
    # "anomaly" string.
    if risk_score < 25:
        return "—"

    # --- step 1: real bx_* engine events ---
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
        events = (
            db.query(AccessLog)
            .filter(
                AccessLog.user_id == user_id,
                AccessLog.action.like("bx_%"),
                AccessLog.timestamp >= cutoff,
            )
            .order_by(AccessLog.timestamp.desc())
            .limit(40)
            .all()
        )
    except Exception:
        events = []

    if events:
        seen: list[str] = []
        for e in events:
            cat = (e.action or "")[3:]
            label = BX_REASON_LABELS.get(cat)
            if label and label not in seen:
                seen.append(label)
            if len(seen) == 2:
                break
        if seen:
            text = " + ".join(seen)
            if privileged:
                text = f"Privileged account anomaly: {text}"
            return text

    # --- step 2: high-risk users with no live engine events ---
    # In the diploma demo all locked sessions share the same canned
    # `behavior_analysis` details (e.g. "Mouse movement pattern …"). To avoid
    # showing the same line for every Priority Incident, rotate through a
    # short pool of realistic compound reasons keyed by user_id.
    if risk_score >= 50:
        demo = _DEMO_INCIDENT_REASONS[user_id % len(_DEMO_INCIDENT_REASONS)]
        if privileged:
            return f"Privileged account anomaly: {demo}"
        return demo

    # --- step 3: parsed reason from behavior_analysis details ---
    parsed = _parse_behavior_reasons(latest_behavior_log)
    if parsed:
        if privileged:
            parsed = f"Privileged account anomaly: {parsed}"
        if len(parsed) > 90:
            parsed = parsed[:87].rstrip() + "…"
        return parsed

    return "—"


def severity_for_risk(risk_score: float, privileged: bool) -> str:
    """Severity bucket, bumped up one notch for privileged roles."""
    if risk_score >= 80:
        base = "Critical"
    elif risk_score >= 60:
        base = "High"
    elif risk_score >= 35:
        base = "Medium"
    elif risk_score >= 15:
        base = "Low"
    else:
        base = "Info"

    if privileged and risk_score >= 25:
        ladder = ["Info", "Low", "Medium", "High", "Critical"]
        idx = ladder.index(base)
        return ladder[min(idx + 1, len(ladder) - 1)]
    return base


def compute_security_health(high_risk_count: int, blocked_count: int) -> tuple[int, str]:
    """
    Map (#high-risk sessions, #blocked sessions) → (health_score, status).

    Spec:
      0 high-risk         → ≈100, Stable
      1 high-risk         → ≈85,  Warning
      2-3 high-risk       → ≈70,  Warning
      4+ high-risk        → 55-65, Critical (or Warning)
      Each blocked session reduces the score further.
    """
    n = max(0, int(high_risk_count))
    b = max(0, int(blocked_count))

    if n == 0:
        score = 100
    elif n == 1:
        score = 85
    elif n <= 3:
        score = 70
    else:
        score = 60

    # Blocked sessions are already counted in `n` but signal critical
    # exposure — drag the score down further (capped contribution).
    score -= min(b, 5) * 4

    score = max(0, min(100, int(round(score))))

    if score >= 90:
        status = "Stable"
    elif score >= 65:
        status = "Warning"
    else:
        status = "Critical"

    return score, status


def build_admin_user_snapshot(db: Session, user: User) -> dict:
    latest_behavior = get_latest_behavior_log(db, user.id)
    latest_any = (
        db.query(AccessLog)
        .filter(AccessLog.user_id == user.id)
        .order_by(AccessLog.timestamp.desc())
        .first()
    )
    risk_score = float(latest_behavior.risk_score) if latest_behavior else 0.0
    trust_score = max(0.0, 100.0 - risk_score)
    mfa_verified = is_step_up_verified(user.id)
    policy = decision_from_role_risk(user.role or "employee", risk_score, mfa_verified)
    policy = apply_admin_forced_policy(user.id, policy, mfa_verified)
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user.id).first()

    current_typing = 0.0
    current_mouse = 0.0
    if latest_behavior and latest_behavior.details:
        detail_text = latest_behavior.details
        if "Typing speed" in detail_text:
            current_typing = (profile.avg_typing_speed or 0.0) * 1.35
        if "Mouse" in detail_text or "automated" in detail_text.lower():
            current_mouse = (profile.avg_mouse_velocity or 0.0) * 1.8

    if current_typing == 0.0:
        current_typing = (profile.avg_typing_speed or 38.0) * (1.0 + min(risk_score, 60) / 150)
    if current_mouse == 0.0:
        current_mouse = (profile.avg_mouse_velocity or 2.1) * (1.0 + min(risk_score, 70) / 170)

    baseline_typing = profile.avg_typing_speed if profile and profile.avg_typing_speed else 38.0
    baseline_mouse = profile.avg_mouse_velocity if profile and profile.avg_mouse_velocity else 2.1
    session_status = session_status_for_user(policy, user.id, risk_score, normalize_role(user.role))
    privileged = is_privileged_role(user.role)
    access_scope = access_scope_for_role(user.role)
    risk_action = risk_action_for_policy(policy, session_status, risk_score)
    recommended = recommended_admin_action(risk_score, session_status, privileged)
    main_reason = main_reason_for_user(
        db,
        user.id,
        risk_score,
        privileged,
        latest_behavior_log=latest_behavior,
    )
    severity = severity_for_risk(risk_score, privileged)

    return {
        "user_id": user.id,
        "username": user.username,
        "role": user.role or "employee",
        "risk_score": round(risk_score, 1),
        "trust_score": round(trust_score, 1),
        "risk_level": policy.get("risk_level", "Low"),
        # Legacy combined column — kept for backward compatibility. Prefer the
        # new "access_scope" + "risk_action" pair instead.
        "access_decision": policy.get("access_decision", "Limited access"),
        "access_scope": access_scope,
        "risk_action": risk_action,
        "recommended_action": recommended,
        "main_reason": main_reason,
        "session_status": session_status,
        "last_activity": latest_any.timestamp.isoformat() if latest_any and latest_any.timestamp else None,
        "threat_type": threat_type_from_signals(risk_score, [latest_behavior.details] if latest_behavior and latest_behavior.details else []),
        "baseline_typing_speed": round(baseline_typing, 2),
        "current_typing_speed": round(current_typing, 2),
        "typing_deviation": round(current_typing - baseline_typing, 2),
        "baseline_mouse_velocity": round(baseline_mouse, 2),
        "current_mouse_velocity": round(current_mouse, 2),
        "mouse_deviation": round(current_mouse - baseline_mouse, 2),
        # Admin-dashboard-specific flags
        "privileged": privileged,
        "severity": severity,
        "is_high_risk": risk_score >= 50
            or session_status in ("Suspicious", "Step-up required", "Blocked"),
    }


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/api/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    username = body.username.strip()
    password = body.password.strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        await asyncio.sleep(0.75)
        return JSONResponse(status_code=401, content={"detail": "Invalid username or password"})

    client_ip, _ = get_client_fingerprint(request)
    now = datetime.now(timezone.utc)
    clear_expired_auth_lock(user)

    lock_until = normalize_utc_datetime(user.account_locked_until)
    if lock_until and lock_until > now:
        log_auth_event(
            db,
            user.id,
            user.username,
            "locked_attempt",
            float(user.auth_risk_score or 90.0),
            "Prevent login while account is locked",
            request,
            "Account temporarily locked due to suspicious activity",
        )
        db.commit()
        lock_seconds = max(1, int((lock_until - now).total_seconds()))
        return JSONResponse(
            status_code=423,
            content={
                "detail": "Account temporarily locked due to suspicious activity",
                "warning_message": "Account temporarily locked due to suspicious activity",
                "failed_attempts": int(user.failed_attempts or 0),
                "auth_risk_score": float(user.auth_risk_score or 0.0),
                "account_locked_until": lock_until.isoformat(),
                "retry_after_seconds": lock_seconds,
            },
            headers={"Retry-After": str(lock_seconds)},
        )

    if user.password != password:
        failure_payload, failure_status = record_failed_login(user, request, db, "Invalid password provided")
        delay = min(float(failure_payload.get("retry_after_seconds", 1)), 2.0)
        await asyncio.sleep(delay)
        return JSONResponse(
            status_code=failure_status,
            content=failure_payload,
            headers={"Retry-After": str(int(delay))},
        )

    if clear_expired_auth_lock(user):
        log_auth_event(
            db,
            user.id,
            user.username,
            "account_unlocked",
            10.0,
            "Allow login after lock expiry",
            request,
            "Account lock expired and was cleared",
        )

    record_successful_login(user, request, db)

    BLOCKED_USERS.pop(user.id, None)
    STEP_UP_EXPIRY.pop(user.id, None)

    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role or "employee"}
    )

    response = LoginResponse(
        access_token=access_token,
        user_id=user.id,
        username=user.username,
        role=user.role or "employee",
    )
    request.scope["_login_cookie"] = access_token
    return response


@app.middleware("http")
async def set_access_cookie_middleware(request: Request, call_next):
    response = await call_next(request)
    token = request.scope.get("_login_cookie")
    if token:
        response.set_cookie("access_token", token, max_age=1800, path="/", samesite="lax")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": "User"})


@app.get("/admin/analytics", response_class=HTMLResponse)
async def admin_analytics_page(
    request: Request,
    current_user: dict = Depends(require_admin),
):
    _ = current_user
    return templates.TemplateResponse(
        "admin_analytics.html",
        {"request": request, "static_version": static_version()},
    )


@app.post("/api/analyze-behavior")
async def analyze_behavior(
    body: BehaviorPayload,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        data = body.model_dump()
        user_id = current_user["user_id"]
        role = normalize_role(current_user.get("role", "employee"))
        client_ip = request.client.host if request.client else "unknown"

        cleanup_expired_access_state(user_id)

        # Check if user is locked
        if user_id in BLOCKED_USERS:
            locked_until = BLOCKED_USERS[user_id]
            time_remaining = (locked_until - datetime.now(timezone.utc)).total_seconds()
            if time_remaining > 0:
                log_denied_access(
                    db,
                    request,
                    current_user,
                    "behavior_analysis",
                    f"Session locked due to critical risk (locked for {int(time_remaining)}s more)",
                    "lock_session",
                    100.0,
                )
                return JSONResponse(
                    status_code=423,
                    content={
                        "status": "locked",
                        "message": "Session locked due to critical risk",
                        "risk_score": 100,
                        "lock_expires_in": int(time_remaining),
                    },
                )
            else:
                # Lock expired, remove it
                BLOCKED_USERS.pop(user_id, None)

        risk_result = calculate_risk_score(data, user_id, client_ip, db)
        trust_score = max(0, 100 - float(risk_result["risk_score"]))
        mfa_verified = is_step_up_verified(user_id)
        policy = decision_from_role_risk(role, float(risk_result["risk_score"]), mfa_verified)
        policy = apply_admin_forced_policy(user_id, policy, mfa_verified)
        threat_type = threat_type_from_signals(float(risk_result["risk_score"]), risk_result.get("reasons", []))

        if policy["blocked"]:
            # Lock for 2 minutes instead of 15 for testing purposes
            BLOCKED_USERS[user_id] = datetime.now(timezone.utc) + timedelta(minutes=2)
        elif user_id in BLOCKED_USERS and not policy["blocked"]:
            # If user was locked but now shows normal behavior, unlock them
            BLOCKED_USERS.pop(user_id, None)

        profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user_id).first()
        baseline_metrics = {
            "avg_typing_speed": profile.avg_typing_speed if profile else 0.0,
            "avg_mouse_velocity": profile.avg_mouse_velocity if profile else 0.0,
        }
        current_metrics = analyze_behavior_data(data)

        db.add(
            AccessLog(
                user_id=user_id,
                ip_address=client_ip,
                action=f"behavior_analysis:{policy['access_decision']}",
                risk_score=risk_result["risk_score"],
                details=str(risk_result.get("reasons", [])),
            )
        )
        db.commit()

        response = {
            "status": "forbidden" if policy["blocked"] else ("warning" if policy["requires_mfa"] else "allowed"),
            "message": "Access denied due to suspicious behavior" if policy["blocked"] else policy["access_decision"],
            "risk_score": risk_result["risk_score"],
            "trust_score": trust_score,
            "risk_level": policy["risk_level"],
            "access_decision": policy["access_decision"],
            "final_access_decision": policy.get("final_access_decision", policy["access_decision"]),
            "data_protection": policy["data_protection"],
            "resource_status": policy["resource_status"],
            "requires_mfa": policy["requires_mfa"],
            "threat_type": threat_type,
            "role": role,
            "kill_switch": policy["blocked"],
            "reasons": risk_result.get("reasons", []),
            "score_breakdown": risk_result.get("score_breakdown", {}),
            "baseline_metrics": baseline_metrics,
            "current_metrics": current_metrics,
            "explainability": {
                "highlights": risk_result.get("reasons", []),
                "conclusion": "Possible bot or compromised session"
                if threat_type != "Normal user"
                else "Behavior is consistent with baseline profile.",
            },
        }

        if policy["blocked"]:
            log_denied_access(
                db,
                request,
                current_user,
                "behavior_analysis",
                "Session locked due to critical risk",
                "lock_session",
                risk_result["risk_score"],
            )
            response["status"] = "locked"
            response["message"] = "Session locked due to critical risk"
            return JSONResponse(status_code=423, content=response)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing behavior: {str(e)}")


@app.post("/api/step-up-verify")
async def step_up_verify(
    body: OTPRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_id = current_user["user_id"]
    client_ip = request.client.host if request.client else "unknown"
    if body.otp != "123456":
        db.add(AccessLog(user_id=user_id, ip_address=client_ip, action="mfa_failed", risk_score=60))
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid OTP")

    STEP_UP_EXPIRY[user_id] = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.add(AccessLog(user_id=user_id, ip_address=client_ip, action="mfa_success", risk_score=20))
    db.commit()
    return {"status": "verified", "message": "Identity verified. Restrictions reduced for 5 minutes."}


@app.get("/api/protected-resource")
async def protected_resource(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_id = current_user["user_id"]
    role = normalize_role(current_user.get("role", "employee"))
    cleanup_expired_access_state(user_id)
    latest_risk = get_latest_risk_score(db, user_id)
    mfa_verified = is_step_up_verified(user_id)

    if user_id in BLOCKED_USERS:
        log_denied_access(
            db,
            request,
            current_user,
            "protected_resource",
            "Session locked due to critical risk",
            "lock_session",
            latest_risk,
        )
        raise HTTPException(status_code=423, detail="Session locked due to critical risk")

    policy = apply_admin_forced_policy(user_id, decision_from_role_risk(role, latest_risk, mfa_verified), mfa_verified)

    if role == "admin" and policy["resource_status"] == "step_up_required":
        log_denied_access(
            db,
            request,
            current_user,
            "protected_resource",
            "Step-up authentication required",
            "require_step_up",
            latest_risk,
        )
        raise HTTPException(status_code=403, detail="Step-up authentication required")

    if policy["blocked"] or policy["resource_status"] == "forbidden":
        reason = "Access denied: high behavioral risk"
        log_denied_access(db, request, current_user, "protected_resource", reason, "deny_access", latest_risk)
        if latest_risk >= 80:
            # Lock for 2 minutes instead of 15 for testing purposes
            BLOCKED_USERS[user_id] = datetime.now(timezone.utc) + timedelta(minutes=2)
            raise HTTPException(status_code=423, detail="Session locked due to critical risk")
        raise HTTPException(status_code=403, detail=reason)

    if policy["resource_status"] == "step_up_required":
        log_denied_access(
            db,
            request,
            current_user,
            "protected_resource",
            "Step-up authentication required",
            "require_step_up",
            latest_risk,
        )
        raise HTTPException(status_code=403, detail="Step-up authentication required")

    payload = {
        "status": "ok",
        "classification": "sensitive",
        "decision": policy["access_decision"],
        "final_access_decision": policy.get("final_access_decision", policy["access_decision"]),
        "resource_status": policy["resource_status"],
        "data_protection": policy["data_protection"],
        "data": {"tokenized_record": "SR-ALPHA-2991", "amount": "$145,250.00"},
    }
    if role == "employee":
        payload["data"]["amount"] = "$***,***.**"
        payload["data_protection"] = "Masked" if latest_risk >= 50 else "Partially visible"
    if role == "auditor":
        payload["data"] = {"tokenized_record": "SR-ALPHA-2991"}
        payload["data_protection"] = "Masked"
    if policy["resource_status"] == "limited":
        payload["data_protection"] = "Limited"
    if policy["resource_status"] == "read_only":
        payload["data_protection"] = "Read-only masked"
    return payload


@app.post("/api/demo-scenario")
async def demo_scenario(
    body: DemoScenarioRequest,
    current_user: dict = Depends(get_current_user),
):
    role = current_user.get("role", "employee")
    scenario = body.scenario.lower()
    presets = {
        "normal": {"risk_score": 15, "reasons": ["No anomalies detected"], "score_breakdown": {}},
        "suspicious": {
            "risk_score": 58,
            "reasons": ["Typing speed is 54% higher than baseline", "Behavior deviates from profile"],
            "score_breakdown": {"Typing Anomaly": 55, "Mouse Anomaly": 0, "IP Change": 0, "Session Anomaly": 3},
        },
        "high-risk": {
            "risk_score": 92,
            "reasons": ["Mouse movement pattern suggests automated behavior", "Possible compromised session"],
            "score_breakdown": {"Typing Anomaly": 12, "Mouse Anomaly": 80, "IP Change": 0, "Session Anomaly": 0},
        },
    }
    if scenario not in presets:
        raise HTTPException(status_code=400, detail="Scenario must be normal, suspicious, or high-risk")

    p = presets[scenario]
    policy = decision_from_role_risk(role, p["risk_score"], is_step_up_verified(current_user["user_id"]))
    policy = apply_admin_forced_policy(current_user["user_id"], policy, is_step_up_verified(current_user["user_id"]))
    return {
        "status": "forbidden" if policy["blocked"] else ("warning" if policy["requires_mfa"] else "allowed"),
        "message": policy["access_decision"],
        "risk_score": p["risk_score"],
        "trust_score": 100 - p["risk_score"],
        "risk_level": policy["risk_level"],
        "access_decision": policy["access_decision"],
        "final_access_decision": policy.get("final_access_decision", policy["access_decision"]),
        "data_protection": policy["data_protection"],
        "resource_status": policy["resource_status"],
        "requires_mfa": policy["requires_mfa"],
        "threat_type": threat_type_from_signals(p["risk_score"], p["reasons"]),
        "role": role,
        "kill_switch": policy["blocked"],
        "reasons": p["reasons"],
        "score_breakdown": p["score_breakdown"],
        "baseline_metrics": {"avg_typing_speed": 39.5, "avg_mouse_velocity": 2.1},
        "current_metrics": {"typing_speed": 60.0 if scenario != "normal" else 40.5, "mouse_velocity": 4.5 if scenario == "high-risk" else 2.0},
        "explainability": {
            "highlights": p["reasons"],
            "conclusion": "Possible bot or compromised session"
            if scenario != "normal"
            else "Behavior is consistent with baseline profile.",
        },
    }


@app.post("/api/reset-baseline")
async def reset_baseline(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_id = current_user["user_id"]
    reset_user_baseline(db, user_id)
    db.commit()
    STEP_UP_EXPIRY.pop(user_id, None)
    BLOCKED_USERS.pop(user_id, None)
    ADMIN_FORCED_STEP_UP.pop(user_id, None)
    return {"status": "ok", "message": "Behavior baseline reset completed."}


@app.post("/api/unlock-session")
async def unlock_session(
    current_user: dict = Depends(get_current_user),
):
    """Quick unlock endpoint for demo/testing purposes"""
    user_id = current_user["user_id"]
    BLOCKED_USERS.pop(user_id, None)
    STEP_UP_EXPIRY.pop(user_id, None)
    return {"status": "ok", "message": "Session unlocked successfully."}



@app.get("/api/session-context")
async def session_context(request: Request, current_user: dict = Depends(get_current_user)):
    login_time = request.headers.get("x-login-time", "unknown")
    return {
        "device": "MacBook Pro / Chrome",
        "ip": request.client.host if request.client else "unknown",
        "location": "Almaty, KZ (mocked)",
        "session_duration": login_time,
        "monitoring_status": "Active",
    }


@app.get("/api/user-profile")
async def get_user_profile(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user["user_id"]
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user_id).first()
    if not profile:
        return {"message": "No behavioral profile found"}
    return {
        "user_id": user_id,
        "avg_typing_speed": profile.avg_typing_speed,
        "avg_dwell_time": profile.avg_dwell_time,
        "avg_flight_time": profile.avg_flight_time,
        "avg_mouse_velocity": profile.avg_mouse_velocity,
        "last_updated": profile.last_updated.isoformat() if profile.last_updated else None,
    }


@app.get("/api/admin/analytics/summary")
async def admin_analytics_summary(
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _ = current_user
    now = datetime.now(timezone.utc)
    day_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    users = db.query(User).all()
    snapshots = [build_admin_user_snapshot(db, u) for u in users]

    total_users = len(snapshots)
    active_sessions = sum(1 for s in snapshots if s["session_status"] == "Active")
    suspicious_sessions = sum(1 for s in snapshots if s["session_status"] in ["Suspicious", "Step-up required"])
    blocked_sessions = sum(1 for s in snapshots if s["session_status"] == "Blocked")
    # "High-risk" sessions are everything that requires attention from the
    # admin — Suspicious / Step-up / Blocked OR risk >= 50.
    high_risk_sessions = sum(1 for s in snapshots if s.get("is_high_risk"))
    privileged_alerts = sum(
        1 for s in snapshots if s.get("privileged") and s.get("risk_score", 0) >= 25
    )
    avg_trust_score = round(sum(s["trust_score"] for s in snapshots) / total_users, 1) if total_users else 100.0
    health_score, health_status = compute_security_health(high_risk_sessions, blocked_sessions)
    high_risk_events_today = (
        db.query(AccessLog)
        .filter(AccessLog.timestamp >= day_start, AccessLog.risk_score >= 70)
        .count()
    )
    failed_login_attempts_today = (
        db.query(AccessLog)
        .filter(AccessLog.timestamp >= day_start, AccessLog.action == "auth_failed")
        .count()
    )
    locked_accounts = (
        db.query(User)
        .filter(User.account_locked_until.isnot(None), User.account_locked_until > now)
        .count()
    )
    suspicious_auth_events = (
        db.query(AccessLog)
        .filter(
            AccessLog.timestamp >= day_start,
            AccessLog.action.in_([
                "auth_suspicious",
                "auth_account_locked",
                "auth_locked_attempt",
                "auth_cooldown",
                "auth_device_change",
            ]),
        )
        .count()
    )

    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        # Legacy field name; new admin UI prefers `high_risk_sessions`.
        "suspicious_sessions": suspicious_sessions,
        "high_risk_sessions": high_risk_sessions,
        "blocked_sessions": blocked_sessions,
        "privileged_alerts": privileged_alerts,
        "average_trust_score": avg_trust_score,
        "health_score": health_score,
        "health_status": health_status,
        "high_risk_events_today": high_risk_events_today,
        "failed_login_attempts_today": failed_login_attempts_today,
        "locked_accounts": locked_accounts,
        "suspicious_auth_events": suspicious_auth_events,
    }


@app.get("/api/admin/analytics/users")
async def admin_analytics_users(
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _ = current_user
    users = db.query(User).order_by(User.username.asc()).all()
    return {"users": [build_admin_user_snapshot(db, u) for u in users]}


def _demo_risk_trend_for_user(user: User, current_risk: float) -> list[dict]:
    """
    Deterministic 4-point demo trend per user so the chart visually differs
    between users while still ending at their current risk score.
    """
    times = ["09:30", "09:40", "09:50", "10:00"]
    seed = (user.id * 13) % 9
    base = [5 + seed, 20 + (seed * 2 % 11), 45 + (seed % 7), max(5, int(round(current_risk)))]
    base = [max(0, min(100, v)) for v in base]
    return [{"time": t, "risk": v} for t, v in zip(times, base)]


@app.get("/api/admin/analytics/risk-trend")
async def admin_risk_trend(
    user_id: Optional[int] = None,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _ = current_user

    # Per-user trend: deterministic demo data ending at the user's current
    # risk so the chart updates predictably when an admin selects a row.
    if user_id is not None:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"points": [], "user_id": user_id}
        latest = get_latest_behavior_log(db, user.id)
        current = float(latest.risk_score) if latest else 0.0
        return {
            "points": _demo_risk_trend_for_user(user, current),
            "user_id": user.id,
            "username": user.username,
        }

    # Global trend: real behavior_analysis logs across all users.
    recent = (
        db.query(AccessLog)
        .filter(AccessLog.action.like("behavior_analysis:%"))
        .order_by(AccessLog.timestamp.desc())
        .limit(5)
        .all()
    )

    if not recent:
        return {
            "points": [
                {"time": "14:00", "risk": 0},
                {"time": "14:05", "risk": 20},
                {"time": "14:10", "risk": 55},
                {"time": "14:15", "risk": 80},
                {"time": "14:20", "risk": 10},
            ]
        }

    points = []
    for row in reversed(recent):
        points.append(
            {
                "time": row.timestamp.astimezone(timezone.utc).strftime("%H:%M") if row.timestamp else "--:--",
                "risk": round(float(row.risk_score or 0), 1),
            }
        )
    return {"points": points}


@app.get("/api/admin/analytics/threat-categories")
async def admin_threat_categories(
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    System-wide aggregated counts of behavior-engine anomaly categories over
    the last 24 hours. Reads AccessLog rows whose `action` starts with `bx_`
    (written by `/api/security-event`).
    """
    _ = current_user
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    known = [
        "typing_anomaly", "paste_detected", "robotic_mouse", "click_automation",
        "tab_switching", "session_anomaly", "device_change",
        "navigation_anomaly", "resource_abuse", "impossible_travel",
    ]
    counts: dict[str, int] = {c: 0 for c in known}
    privileged_total = 0

    rows = (
        db.query(AccessLog)
        .filter(AccessLog.timestamp >= cutoff, AccessLog.action.like("bx_%"))
        .all()
    )
    for row in rows:
        category = (row.action or "")[3:]  # strip "bx_"
        if category in counts:
            counts[category] += 1
        # Tag privileged-user anomalies separately so the UI can highlight
        # them in the system-wide summary.
        user = db.query(User).filter(User.id == row.user_id).first()
        if user and is_privileged_role(user.role):
            privileged_total += 1

    total = sum(counts.values())
    return {
        "counts": counts,
        "total": total,
        "privileged_total": privileged_total,
        "window_hours": 24,
    }


@app.get("/api/admin/analytics/events")
async def admin_analytics_events(
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _ = current_user
    rows = (
        db.query(AccessLog, User)
        .join(User, AccessLog.user_id == User.id)
        .order_by(AccessLog.timestamp.desc())
        .limit(20)
        .all()
    )

    event_map = {
        "auth_success": ("Login successful", "Session started"),
        "auth_failed": ("Failed login attempt", "Invalid credentials rejected"),
        "auth_suspicious": ("Suspicious login pattern", "Warning issued"),
        "auth_cooldown": ("Login throttled", "Backoff applied"),
        "auth_locked_attempt": ("Locked account login attempt", "Access denied"),
        "auth_account_locked": ("Account locked due to suspicious activity", "Login blocked"),
        "auth_account_unlocked": ("Account unlocked", "Temporary lock cleared"),
        "auth_device_change": ("New device detected", "Auth risk slightly increased"),
        "mfa_failed": ("Step-up authentication failed", "Access kept restricted"),
        "mfa_success": ("Step-up authentication requested", "Restrictions reduced"),
        "critical_session_terminated": ("Session locked by kill switch", "User session revoked"),
        "admin_session_locked": ("Session locked by admin", "User access revoked"),
        "admin_force_step_up": ("Step-up authentication requested", "Additional verification required"),
        "admin_reset_baseline": ("Baseline reset by admin", "Behavior profile cleared"),
    }
    events = []
    for log, user in rows:
        if log.action.startswith("behavior_analysis:"):
            action_text = log.action.split(":", 1)[-1]
            event_type = "Behavior analysis"
            system_action = action_text
            if "Step-up" in action_text:
                event_type = "Suspicious typing detected"
            if "Blocked" in action_text:
                event_type = "Session locked by kill switch"
            if "Limited" in action_text or "restricted" in action_text.lower():
                system_action = "Sensitive data masked"
        else:
            event_type, system_action = event_map.get(log.action, (log.action.replace("_", " ").title(), "Logged"))
            if log.action == "mfa_success":
                event_type = "Step-up authentication requested"
            if log.action == "auth_success":
                system_action = "JWT issued"

        events.append(
            {
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "user": user.username,
                "event_type": event_type,
                "risk_score": round(float(log.risk_score or 0), 1),
                "system_action": system_action,
            }
        )
    return {"events": events}


@app.post("/api/security-event")
async def log_security_event(
    body: SecurityEventRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_id = current_user["user_id"]
    client_ip = request.client.host if request.client else "unknown"
    db.add(
        AccessLog(
            user_id=user_id,
            ip_address=client_ip,
            action=body.action,
            risk_score=float(body.risk_score or 0.0),
            details=body.message,
        )
    )
    db.commit()
    return {"status": "ok"}


@app.get("/api/admin/analytics/users/{target_user_id}")
async def admin_user_detail(
    target_user_id: int,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    _ = current_user
    user = db.query(User).filter(User.id == target_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    snapshot = build_admin_user_snapshot(db, user)
    recent_logs = (
        db.query(AccessLog)
        .filter(AccessLog.user_id == target_user_id)
        .order_by(AccessLog.timestamp.desc())
        .limit(8)
        .all()
    )
    timeline = [
        {
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "message": row.action,
            "risk_score": round(float(row.risk_score or 0), 1),
        }
        for row in recent_logs
    ]
    trend = _demo_risk_trend_for_user(user, snapshot.get("risk_score") or 0.0)
    return {"user": snapshot, "timeline": timeline, "trend": trend}


@app.post("/api/admin/analytics/actions")
async def admin_user_action(
    body: AdminActionRequest,
    current_user: dict = Depends(require_admin),
    request: Request = None,
    db: Session = Depends(get_db),
):
    _ = current_user
    target = db.query(User).filter(User.id == body.user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    action = body.action.strip().lower()
    now = datetime.now(timezone.utc)
    client_ip = request.client.host if request and request.client else "admin-console"

    if action == "require_step_up":
        ADMIN_FORCED_STEP_UP[target.id] = now + timedelta(minutes=20)
        db.add(AccessLog(user_id=target.id, ip_address=client_ip, action="admin_force_step_up", risk_score=60))
        message = f"Step-up auth is now required for {target.username}"
    elif action == "lock_session":
        BLOCKED_USERS[target.id] = now + timedelta(minutes=30)
        db.add(AccessLog(user_id=target.id, ip_address=client_ip, action="admin_session_locked", risk_score=95))
        message = f"Session locked for {target.username}"
    elif action == "reset_baseline":
        reset_user_baseline(db, target.id)
        ADMIN_FORCED_STEP_UP.pop(target.id, None)
        STEP_UP_EXPIRY.pop(target.id, None)
        BLOCKED_USERS.pop(target.id, None)
        db.add(AccessLog(user_id=target.id, ip_address=client_ip, action="admin_reset_baseline", risk_score=10))
        message = f"Behavior baseline reset for {target.username}"
    else:
        raise HTTPException(status_code=400, detail="Unsupported action")

    db.commit()
    return {"status": "ok", "message": message}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
