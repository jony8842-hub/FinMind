from flask import Blueprint, request, jsonify, send_file
from io import BytesIO
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
import json
from zipfile import ZIP_DEFLATED, ZipFile
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
    jwt_required,
    get_jwt_identity,
)
from ..extensions import db, redis_client
from ..models import (
    AdImpression,
    AuditLog,
    Bill,
    Category,
    Expense,
    RecurringExpense,
    Reminder,
    User,
    UserSubscription,
)
import logging
import time

bp = Blueprint("auth", __name__)
logger = logging.getLogger("finmind.auth")
SUPPORTED_CURRENCIES = {
    "USD",
    "INR",
    "EUR",
    "GBP",
    "AED",
    "SGD",
    "AUD",
    "CAD",
    "JPY",
}


@bp.post("/register")
def register():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        logger.warning("Register missing email/password")
        return jsonify(error="email and password required"), 400
    if db.session.query(User).filter_by(email=email).first():
        logger.info("Register email already used: %s", email)
        return jsonify(error="email already used"), 409
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        preferred_currency="INR",
    )
    db.session.add(user)
    db.session.commit()
    logger.info("Registered user id=%s email=%s", user.id, email)
    return jsonify(message="registered"), 201


@bp.post("/login")
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    user = db.session.query(User).filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        logger.warning("Login failed for email=%s", email)
        return jsonify(error="invalid credentials"), 401
    access = create_access_token(identity=str(user.id))
    refresh = create_refresh_token(identity=str(user.id))
    _store_refresh_session(refresh, str(user.id))
    logger.info("Login success user_id=%s", user.id)
    return jsonify(access_token=access, refresh_token=refresh)


@bp.get("/me")
@jwt_required()
def me():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404
    return jsonify(
        id=user.id,
        email=user.email,
        preferred_currency=user.preferred_currency or "INR",
    )


@bp.patch("/me")
@jwt_required()
def update_me():
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404
    data = request.get_json() or {}
    if "preferred_currency" in data:
        cur = str(data.get("preferred_currency") or "").upper().strip()
        if cur not in SUPPORTED_CURRENCIES:
            return jsonify(error="unsupported preferred_currency"), 400
        user.preferred_currency = cur
    db.session.commit()
    return jsonify(
        id=user.id,
        email=user.email,
        preferred_currency=user.preferred_currency or "INR",
    )


def _export_value(value):
    """Convert SQLAlchemy values to stable, JSON-serializable primitives."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    return value


def _export_row(row, *, include_password=False):
    excluded = set() if include_password else {"password_hash"}
    return {
        column.name: _export_value(getattr(row, column.name))
        for column in row.__table__.columns
        if column.name not in excluded
    }


def _account_export(uid: int) -> dict:
    """Build a complete, user-scoped export without leaking password hashes."""
    user = db.session.get(User, uid)
    if not user:
        return {}
    scoped = {
        "categories": Category,
        "expenses": Expense,
        "recurring_expenses": RecurringExpense,
        "bills": Bill,
        "reminders": Reminder,
        "ad_impressions": AdImpression,
        "user_subscriptions": UserSubscription,
        "audit_logs": AuditLog,
    }
    payload = {"user": _export_row(user), "export_version": 1}
    for name, model in scoped.items():
        payload[name] = [
            _export_row(row)
            for row in db.session.query(model).filter_by(user_id=uid).all()
        ]
    return payload


@bp.get("/me/export")
@jwt_required()
def export_me():
    """Download all personal data as a portable JSON-in-ZIP package."""
    uid = int(get_jwt_identity())
    payload = _account_export(uid)
    if not payload:
        return jsonify(error="not found"), 404

    db.session.add(AuditLog(user_id=uid, action="account.export"))
    db.session.commit()
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
        bundle.writestr(
            "account.json",
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        )
    archive.seek(0)
    return send_file(
        archive,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"finmind-account-export-{uid}.zip",
    )


@bp.delete("/me")
@jwt_required()
def delete_me():
    """Permanently delete the authenticated account after an explicit confirmation."""
    uid = int(get_jwt_identity())
    user = db.session.get(User, uid)
    if not user:
        return jsonify(error="not found"), 404
    data = request.get_json(silent=True) or {}
    password = str(data.get("password") or "")
    confirmation = str(data.get("confirm_email") or data.get("confirmation") or "")
    if not password or not check_password_hash(user.password_hash, password):
        return jsonify(error="valid password required"), 400
    if confirmation.strip().lower() != user.email.lower():
        return jsonify(error="confirm_email must match account email"), 400

    # Keep a tombstone audit record while removing every user-owned row.
    db.session.add(AuditLog(user_id=uid, action="account.delete"))
    for model in (
        UserSubscription,
        Reminder,
        Bill,
        Expense,
        RecurringExpense,
        Category,
        AdImpression,
    ):
        db.session.query(model).filter_by(user_id=uid).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()

    # Revoke any refresh sessions belonging to this user when Redis supports scans.
    try:
        for key in redis_client.scan_iter(match="auth:refresh:*"):
            if str(redis_client.get(key)) == str(uid):
                redis_client.delete(key)
    except Exception:
        logger.warning(
            "Could not revoke all refresh sessions for deleted user_id=%s", uid
        )
    return jsonify(message="account permanently deleted")


@bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    claims = get_jwt()
    jti = claims.get("jti")
    if not jti or not redis_client.get(_refresh_key(jti)):
        logger.warning("Refresh rejected: revoked/unknown token jti=%s", jti)
        return jsonify(error="refresh token revoked"), 401
    uid = get_jwt_identity()
    access = create_access_token(identity=str(uid))
    logger.info("Refreshed token for user_id=%s", uid)
    return jsonify(access_token=access)


@bp.post("/logout")
@jwt_required(refresh=True)
def logout():
    claims = get_jwt()
    jti = claims.get("jti")
    if jti:
        redis_client.delete(_refresh_key(jti))
    return jsonify(message="logged out"), 200


def _refresh_key(jti: str) -> str:
    return f"auth:refresh:{jti}"


def _store_refresh_session(refresh_token: str, uid: str):
    payload = decode_token(refresh_token)
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return
    ttl = max(int(exp - time.time()), 1)
    redis_client.setex(_refresh_key(jti), ttl, uid)
