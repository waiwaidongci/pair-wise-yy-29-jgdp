#!/usr/bin/env python3
"""Minimal standards-library digital credential service for local evaluation."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(__file__).with_name("data.db")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              secret_hex TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','retired')),
              created_at TEXT NOT NULL,
              retired_at TEXT,
              UNIQUE(issuer, version)
            );
            CREATE TABLE IF NOT EXISTS templates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              code TEXT NOT NULL,
              name TEXT NOT NULL,
              fields_json TEXT NOT NULL,
              validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
              status TEXT NOT NULL CHECK(status IN ('active','disabled')),
              created_at TEXT NOT NULL,
              UNIQUE(issuer, code)
            );
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              claims_json TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
              key_version INTEGER NOT NULL,
              idempotency_key TEXT NOT NULL,
              revocation_reason TEXT,
              revocation_effective_at TEXT,
              UNIQUE(template_id, holder_id, idempotency_key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
              ON credentials(template_id, holder_id)
              WHERE status IN ('active','disputed');
            CREATE TABLE IF NOT EXISTS revocation_appointments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              issuer TEXT NOT NULL,
              reason TEXT NOT NULL,
              effective_at TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('pending','effective','withdrawn')),
              created_at TEXT NOT NULL,
              applied_at TEXT,
              withdrawn_at TEXT,
              withdrawn_by TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_pending_appointment
              ON revocation_appointments(credential_id)
              WHERE status='pending';
            CREATE INDEX IF NOT EXISTS appointment_due_idx
              ON revocation_appointments(status, effective_at);
            CREATE TABLE IF NOT EXISTS disputes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              raised_by TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
              resolution TEXT,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    def close(self) -> None:
        self.conn.close()


class RevocationScheduler:
    """登记撤销预约，并按给定时刻判定预约处于待生效、已生效还是已撤回。

    本类只维护 revocation_appointments 表与判定逻辑；凭证状态的写入由
    CredentialService 负责，使“预约判定”和“凭证写入”可以分开维护。
    """

    def __init__(self, conn: sqlite3.Connection, audit):
        self.conn = conn
        self.audit = audit

    def register(self, actor: str, credential_id: int, reason: str, effective: datetime) -> sqlite3.Row:
        """登记一条未结（pending）撤销预约；同一凭证只允许一条 pending。"""
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO revocation_appointments(credential_id,issuer,reason,effective_at,status,created_at) VALUES(?,?,?,?,'pending',?)",
                    (credential_id, actor, reason, iso(effective), iso()),
                )
                self.audit(actor, "revocation.schedule", "credential", credential_id, {"appointment_id": cur.lastrowid, "reason": reason, "effective_at": iso(effective)})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "该凭证已有一条未结的撤销预约，可先撤回再重新登记") from exc
        return self.get(cur.lastrowid)

    def get(self, appointment_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM revocation_appointments WHERE id=?", (appointment_id,)).fetchone()
        if not row:
            raise ApiError(404, "撤销预约不存在")
        return row

    def pending_for(self, credential_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM revocation_appointments WHERE credential_id=? AND status='pending' LIMIT 1",
            (credential_id,),
        ).fetchone()

    def due(self, at: datetime) -> list[sqlite3.Row]:
        """返回到点（effective_at <= at）且仍未处理的预约。"""
        return list(self.conn.execute(
            "SELECT * FROM revocation_appointments WHERE status='pending' AND effective_at<=? ORDER BY effective_at, id",
            (iso(at),),
        ).fetchall())

    def settle_due(self, at: datetime | None = None) -> list[int]:
        """把所有到点预约标记为 effective，并返回需要写入凭证状态的凭证 id 列表。"""
        at = at or now()
        stamp = iso(at)
        due = self.due(at)
        credential_ids: list[int] = []
        with self.conn:
            for appointment in due:
                self.conn.execute(
                    "UPDATE revocation_appointments SET status='effective',applied_at=? WHERE id=? AND status='pending'",
                    (stamp, appointment["id"]),
                )
                credential_ids.append(int(appointment["credential_id"]))
                self.audit(appointment["issuer"], "revocation.effective", "revocation_appointment", appointment["id"],
                           {"credential_id": appointment["credential_id"], "effective_at": appointment["effective_at"]})
        return credential_ids

    def withdraw(self, actor: str, appointment_id: int) -> sqlite3.Row:
        """生效前撤回预约；到点后不可撤回。"""
        appointment = self.get(appointment_id)
        if appointment["status"] == "withdrawn":
            raise ApiError(409, "撤销预约已经撤回")
        if appointment["status"] == "effective":
            raise ApiError(409, "撤销预约已生效，无法撤回")
        if parse_time(appointment["effective_at"]) <= now():
            raise ApiError(409, "撤销预约已到生效时间，无法撤回")
        with self.conn:
            self.conn.execute(
                "UPDATE revocation_appointments SET status='withdrawn',withdrawn_at=?,withdrawn_by=? WHERE id=?",
                (iso(), actor, appointment_id),
            )
            self.audit(actor, "revocation.withdraw", "revocation_appointment", appointment_id,
                       {"credential_id": appointment["credential_id"]})
        return self.get(appointment_id)

    def controlling(self, credential_id: int, at: datetime) -> sqlite3.Row | None:
        """按核验时刻返回决定凭证状态的撤销预约。

        到点（effective_at <= at）的预约无论是否已结算都视为已生效；
        未到点的待生效预约次之；已撤回的预约永不生效。
        """
        stamp = iso(at)
        due = self.conn.execute(
            "SELECT * FROM revocation_appointments WHERE credential_id=? AND status IN ('pending','effective') AND effective_at<=? ORDER BY effective_at DESC, id DESC LIMIT 1",
            (credential_id, stamp),
        ).fetchone()
        if due:
            return due
        return self.conn.execute(
            "SELECT * FROM revocation_appointments WHERE credential_id=? AND status='pending' AND effective_at>? LIMIT 1",
            (credential_id, stamp),
        ).fetchone()

    def list(self, status: str | None = None) -> list[dict]:
        sql = (
            "SELECT a.*, c.template_id, c.holder_id "
            "FROM revocation_appointments a JOIN credentials c ON c.id=a.credential_id "
        )
        if status in ("pending", "withdrawn", "effective"):
            sql += "WHERE a.status=? "
            rows = self.conn.execute(sql + "ORDER BY a.id DESC", (status,)).fetchall()
        else:
            rows = self.conn.execute(sql + "ORDER BY a.id DESC").fetchall()
        return [self.dict_from_row(row) for row in rows]

    @staticmethod
    def dict_from_row(row: sqlite3.Row) -> dict:
        keys = row.keys()

        def value(name: str):
            return row[name] if name in keys else None

        return {
            "id": row["id"],
            "credential_id": row["credential_id"],
            "template_id": value("template_id"),
            "holder_id": value("holder_id"),
            "issuer": row["issuer"],
            "reason": row["reason"],
            "effective_at": row["effective_at"],
            "status": row["status"],
            "created_at": row["created_at"],
            "applied_at": row["applied_at"],
            "withdrawn_at": row["withdrawn_at"],
            "withdrawn_by": row["withdrawn_by"],
        }


class CredentialService:
    """Credential issuance and verification with small, explicit trust boundaries."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn
        self.scheduler = RevocationScheduler(store.conn, store.audit)

    def settle_due(self, at: datetime | None = None) -> None:
        """把到点的撤销预约落到凭证状态，确保任何读取前状态已是最新。"""
        at = at or now()
        for credential_id in self.scheduler.settle_due(at):
            self._write_revocation(credential_id)

    def _write_revocation(self, credential_id: int) -> None:
        """凭证写入的唯一入口：按当前生效预约把凭证置为 revoked。"""
        appointment = self.conn.execute(
            "SELECT * FROM revocation_appointments WHERE credential_id=? AND status='effective' ORDER BY effective_at DESC, id DESC LIMIT 1",
            (credential_id,),
        ).fetchone()
        if not appointment:
            return
        with self.conn:
            self.conn.execute(
                "UPDATE credentials SET status='revoked',revocation_reason=?,revocation_effective_at=? WHERE id=? AND status!='revoked'",
                (appointment["reason"], appointment["effective_at"], credential_id),
            )

    @staticmethod
    def _required_actor(actor: str | None, role: str | None, expected: str) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != expected:
            raise ApiError(403, f"需要角色 {expected}")
        return actor

    def _row(self, table: str, identity: int) -> sqlite3.Row:
        row = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    def _active_key(self, issuer: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
        ).fetchone()
        if not row:
            raise ApiError(409, "签发方尚未初始化密钥")
        return row

    def rotate_key(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能轮换自己的密钥")
        with self.conn:
            old = self.conn.execute("SELECT * FROM key_versions WHERE issuer=? AND status='active'", (issuer,)).fetchone()
            version = 1
            if old:
                version = int(old["version"]) + 1
                self.conn.execute("UPDATE key_versions SET status='retired', retired_at=? WHERE id=?", (iso(), old["id"]))
            secret_hex = secrets.token_hex(32)
            cur = self.conn.execute(
                "INSERT INTO key_versions(issuer,version,secret_hex,status,created_at) VALUES(?,?,?,'active',?)",
                (issuer, version, secret_hex, iso()),
            )
            self.store.audit(actor, "key.rotate", "key_version", cur.lastrowid, {"version": version, "retired_previous": bool(old)})
        return {"issuer": issuer, "version": version, "status": "active", "public_fingerprint": hashlib.sha256(secret_hex.encode()).hexdigest()[:20]}

    def create_template(self, actor: str | None, role: str | None, code: str, name: str, fields: list[dict], validity_days: int) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not code.strip() or not name.strip():
            raise ApiError(400, "模板代号和名称不能为空")
        field_names: set[str] = set()
        normalized = []
        for field in fields:
            field_name = str(field.get("name", "")).strip()
            if not field_name or field_name in field_names:
                raise ApiError(400, "模板字段为空或重复")
            field_names.add(field_name)
            normalized.append({"name": field_name, "required": bool(field.get("required", False))})
        if not normalized:
            raise ApiError(400, "模板至少需要一个字段")
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO templates(issuer,code,name,fields_json,validity_days,status,created_at) VALUES(?,?,?,?,?,'active',?)",
                    (actor, code, name, json.dumps(normalized, ensure_ascii=False), int(validity_days), iso()),
                )
                self.store.audit(actor, "template.create", "template", cur.lastrowid, {"code": code, "fields": normalized})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "同一签发方不能重复使用模板代号") from exc
        return {"id": cur.lastrowid, "issuer": actor, "code": code, "name": name, "fields": normalized, "validity_days": validity_days, "status": "active"}

    def issue(self, actor: str | None, role: str | None, template_id: int, holder_id: str, claims: dict, idempotency_key: str, valid_until: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not holder_id.strip() or not idempotency_key.strip():
            raise ApiError(400, "持有人和幂等键不能为空")
        template = self._row("templates", template_id)
        if template["issuer"] != actor:
            raise ApiError(403, "不能使用其他签发方的模板")
        if template["status"] != "active":
            raise ApiError(409, "模板已停用")
        self.settle_due()
        existing = self.conn.execute(
            "SELECT * FROM credentials WHERE template_id=? AND holder_id=? AND idempotency_key=?",
            (template_id, holder_id, idempotency_key),
        ).fetchone()
        if existing:
            return self._credential_dict(existing)
        fields = json.loads(template["fields_json"])
        missing = [f["name"] for f in fields if f["required"] and not str(claims.get(f["name"], "")).strip()]
        unknown = sorted(set(claims) - {f["name"] for f in fields})
        if missing or unknown:
            raise ApiError(400, f"声明不完整，缺少={missing}，未知字段={unknown}")
        live = self.conn.execute(
            "SELECT id FROM credentials WHERE template_id=? AND holder_id=? AND status IN ('active','disputed')",
            (template_id, holder_id),
        ).fetchone()
        if live:
            raise ApiError(409, "该持有人已有有效的同模板凭证；重复提交应使用相同幂等键")
        issued = now()
        expiration = parse_time(valid_until) if valid_until else issued + timedelta(days=int(template["validity_days"]))
        if expiration <= issued:
            raise ApiError(400, "有效期必须晚于签发时间")
        key = self._active_key(actor)
        try:
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO credentials(template_id,issuer,holder_id,claims_json,issued_at,valid_until,status,key_version,idempotency_key)
                       VALUES(?,?,?,?,?,?, 'active',?,?)""",
                    (template_id, actor, holder_id, json.dumps(claims, ensure_ascii=False), iso(issued), iso(expiration), key["version"], idempotency_key),
                )
                self.store.audit(actor, "credential.issue", "credential", cur.lastrowid, {"holder_id": holder_id, "template_id": template_id, "key_version": key["version"]})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "并发签发冲突，请用相同幂等键重试") from exc
        return self._credential_dict(self._row("credentials", cur.lastrowid))

    def revoke(self, actor: str | None, role: str | None, credential_id: int, reason: str, effective_at: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not reason.strip():
            raise ApiError(400, "撤销原因不能为空")
        credential = self._row("credentials", credential_id)
        if credential["issuer"] != actor:
            raise ApiError(403, "只能撤销本机构签发的凭证")
        self.settle_due()
        credential = self._row("credentials", credential_id)
        if credential["status"] == "revoked":
            last_effective = self.conn.execute(
                "SELECT * FROM revocation_appointments WHERE credential_id=? AND status='effective' ORDER BY id DESC LIMIT 1",
                (credential_id,),
            ).fetchone()
            if last_effective and last_effective["reason"] == reason:
                return self._appointment_dict(last_effective)
            raise ApiError(409, "凭证已经撤销")
        if credential["status"] == "disputed":
            raise ApiError(409, "凭证正在争议复核中")
        effective = parse_time(effective_at) if effective_at else now()
        if effective <= now():
            # 即时撤销：登记一条到点即生效的预约，再由统一的结算流程写入凭证。
            appointment = self.scheduler.register(actor, credential_id, reason, now())
            self.settle_due()
        else:
            appointment = self.scheduler.register(actor, credential_id, reason, effective)
        return self._appointment_dict(self.scheduler.get(appointment["id"]))

    def withdraw_appointment(self, actor: str | None, role: str | None, appointment_id: int) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        appointment = self.scheduler.get(appointment_id)
        if appointment["issuer"] != actor:
            raise ApiError(403, "只能撤回本机构登记的撤销预约")
        row = self.scheduler.withdraw(actor, appointment_id)
        return self._appointment_dict(row)

    def list_appointments(self, status: str | None = None) -> dict:
        self.settle_due()
        return {"revocation_appointments": self.scheduler.list(status)}

    def dispute(self, actor: str | None, role: str | None, credential_id: int, reason: str) -> dict:
        actor = self._required_actor(actor, role, "holder")
        self.settle_due()
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能对自己的凭证提出争议")
        if credential["status"] != "revoked":
            raise ApiError(409, "只有已撤销凭证可以提出争议")
        open_dispute = self.conn.execute("SELECT id FROM disputes WHERE credential_id=? AND status='open'", (credential_id,)).fetchone()
        if open_dispute:
            raise ApiError(409, "已有待处理争议")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO disputes(credential_id,raised_by,reason,status,created_at) VALUES(?,?,?,'open',?)",
                (credential_id, actor, reason, iso()),
            )
            self.conn.execute("UPDATE credentials SET status='disputed' WHERE id=?", (credential_id,))
            self.store.audit(actor, "dispute.open", "credential", credential_id, {"dispute_id": cur.lastrowid, "reason": reason})
        return {"id": cur.lastrowid, "credential_id": credential_id, "status": "open"}

    def resolve_dispute(self, actor: str | None, role: str | None, dispute_id: int, decision: str, resolution: str) -> dict:
        actor = self._required_actor(actor, role, "regulator")
        if decision not in {"uphold", "reject"}:
            raise ApiError(400, "决定只能是 uphold 或 reject")
        dispute = self._row("disputes", dispute_id)
        if dispute["status"] != "open":
            raise ApiError(409, "争议已经处理")
        credential = self._row("credentials", dispute["credential_id"])
        if credential["status"] != "disputed":
            raise ApiError(409, "凭证状态与争议不一致")
        new_status = "revoked" if decision == "uphold" else "active"
        dispute_status = "upheld" if decision == "uphold" else "rejected"
        with self.conn:
            self.conn.execute("UPDATE disputes SET status=?,resolution=?,resolved_at=? WHERE id=?", (dispute_status, resolution, iso(), dispute_id))
            if decision == "uphold":
                self.conn.execute("UPDATE credentials SET status='revoked' WHERE id=?", (credential["id"],))
            else:
                # 争议成立、撤销被推翻：凭证恢复有效，对应的已生效撤销预约一并撤回，
                # 并清空凭证上的撤销字段，使后续核验不再受原撤销影响。
                self.conn.execute(
                    "UPDATE credentials SET status='active',revocation_reason=NULL,revocation_effective_at=NULL WHERE id=?",
                    (credential["id"],),
                )
                self.conn.execute(
                    "UPDATE revocation_appointments SET status='withdrawn',withdrawn_at=?,withdrawn_by=? WHERE credential_id=? AND status='effective'",
                    (iso(), f"regulator:{actor}", credential["id"]),
                )
            self.store.audit(actor, "dispute.resolve", "dispute", dispute_id, {"decision": decision, "credential_status": new_status})
        return {"id": dispute_id, "status": decision, "credential_status": new_status, "resolution": resolution}

    def present(self, actor: str | None, role: str | None, credential_id: int, disclosed_fields: list[str] | None) -> dict:
        actor = self._required_actor(actor, role, "holder")
        self.settle_due()
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "不能出示他人的凭证")
        template = self._row("templates", credential["template_id"])
        allowed = [field["name"] for field in json.loads(template["fields_json"])]
        disclosed = disclosed_fields if disclosed_fields is not None else allowed
        if len(disclosed) != len(set(disclosed)) or any(name not in allowed for name in disclosed):
            raise ApiError(400, "披露字段不在模板中或重复")
        claims = json.loads(credential["claims_json"])
        visible = {name: claims[name] for name in disclosed}
        payload = {
            "credential_id": credential["id"],
            "template_id": credential["template_id"],
            "issuer": credential["issuer"],
            "holder_id": credential["holder_id"],
            "claims": visible,
            "valid_until": credential["valid_until"],
            "key_version": credential["key_version"],
        }
        key = self.conn.execute(
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(canonical({"payload": payload, "signature": signature})).decode().rstrip("=")
        self.store.audit(actor, "credential.present", "credential", credential_id, {"disclosed_fields": disclosed})
        self.conn.commit()
        return {"token": token, "payload": payload, "signature": signature, "disclosed_fields": disclosed}

    def verify(self, token: str, at: str | None = None, online: bool = True) -> dict:
        if not token:
            raise ApiError(400, "缺少凭证令牌")
        try:
            padded = token + "=" * (-len(token) % 4)
            envelope = json.loads(base64.urlsafe_b64decode(padded.encode()))
            payload = envelope["payload"]
            supplied_signature = envelope["signature"]
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(400, "凭证令牌格式错误") from exc
        credential = self._row("credentials", int(payload.get("credential_id", 0)))
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(supplied_signature)):
            raise ApiError(400, "凭证签名无效")
        self.settle_due()
        credential = self._row("credentials", credential["id"])
        check_at = parse_time(at)
        expiration = parse_time(credential["valid_until"])
        result = {"valid": True, "status": "valid", "key_retired": key["status"] == "retired", "claims": payload.get("claims", {})}
        if check_at >= expiration:
            result.update(valid=False, status="expired", reason="凭证已过期")
        elif credential["status"] == "disputed":
            result.update(valid=False, status="disputed", reason="撤销决定正在争议复核")
        else:
            # 撤销判定交给 scheduler：按核验时刻决定到点撤销还是尚未失效。
            appointment = self.scheduler.controlling(credential["id"], check_at)
            if appointment is not None and parse_time(appointment["effective_at"]) <= check_at:
                result.update(valid=False, status="revoked", reason=appointment["reason"], revocation_effective_at=appointment["effective_at"])
            elif appointment is not None:
                result.update(status="valid_until_revocation", revocation_starts_at=appointment["effective_at"], revocation_reason=appointment["reason"])
            elif credential["status"] == "revoked":
                # 兼容历史数据：凭证已撤销但没有撤销预约记录。
                effective = parse_time(credential["revocation_effective_at"]) if credential["revocation_effective_at"] else check_at
                if check_at >= effective:
                    result.update(valid=False, status="revoked", reason=credential["revocation_reason"], revocation_effective_at=credential["revocation_effective_at"])
                else:
                    result.update(status="valid_until_revocation", revocation_starts_at=credential["revocation_effective_at"])
        if not online:
            result["offline"] = True
            result["revocation_freshness"] = "needs_online_check"
            if result["valid"]:
                result["status"] = "valid_offline"
        self.conn.commit()
        return result

    def _credential_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "template_id": row["template_id"], "issuer": row["issuer"], "holder_id": row["holder_id"],
            "claims": json.loads(row["claims_json"]), "issued_at": row["issued_at"], "valid_until": row["valid_until"],
            "status": row["status"], "key_version": row["key_version"], "revocation_reason": row["revocation_reason"],
            "revocation_effective_at": row["revocation_effective_at"],
        }

    def _appointment_dict(self, row: sqlite3.Row) -> dict:
        data = self.scheduler.dict_from_row(row)
        if data["template_id"] is None:
            credential = self._row("credentials", int(row["credential_id"]))
            data["template_id"] = credential["template_id"]
            data["holder_id"] = credential["holder_id"]
        return data

    def state(self) -> dict:
        self.settle_due()
        credentials = [self._credential_dict(row) for row in self.conn.execute("SELECT * FROM credentials ORDER BY id DESC")]
        templates = [dict(row) for row in self.conn.execute("SELECT id,issuer,code,name,status,validity_days FROM templates ORDER BY id DESC")]
        appointments = self.scheduler.list()
        audits = [dict(row) for row in self.conn.execute("SELECT at,actor,action,entity_type,entity_id,details_json FROM audit_log ORDER BY id DESC LIMIT 30")]
        return {"templates": templates, "credentials": credentials, "revocation_appointments": appointments, "audits": audits}

    def seed(self) -> None:
        if not self.conn.execute("SELECT id FROM key_versions LIMIT 1").fetchone():
            self.rotate_key("issuer-demo", "issuer", "issuer-demo")
        if not self.conn.execute("SELECT id FROM templates LIMIT 1").fetchone():
            self.create_template("issuer-demo", "issuer", "student-v1", "学生身份", [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}], 365)


class Handler(BaseHTTPRequestHandler):
    service: CredentialService

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "JSON 请求体无效") from exc

    def _parts(self) -> list[str]:
        return [part for part in urlparse(self.path).path.strip("/").split("/") if part]

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            parts = [part for part in parsed.path.strip("/").split("/") if part]
            if parts == ["health"] or parts == ["api", "health"]:
                return self._json(200, {"status": "ok"})
            if parts == ["api", "state"]:
                return self._json(200, self.service.state())
            if parts == ["api", "revocation-appointments"]:
                status = None
                if parsed.query:
                    filters = dict(pair.split("=", 1) for pair in parsed.query.split("&") if "=" in pair)
                    status = filters.get("status")
                return self._json(200, self.service.list_appointments(status))
            if parts == ["revocations"]:
                page = (Path(__file__).parent / "static" / "revocations.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            if not parts:
                page = (Path(__file__).parent / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            raise ApiError(404, "接口不存在")
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except Exception as exc:
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            parts = self._parts()
            body = self._body()
            actor, role = self.headers.get("X-Actor"), self.headers.get("X-Role")
            if parts == ["api", "keys", "rotate"]:
                result = self.service.rotate_key(actor, role, body.get("issuer", actor or ""))
            elif parts == ["api", "templates"]:
                result = self.service.create_template(actor, role, body.get("code", ""), body.get("name", ""), body.get("fields", []), int(body.get("validity_days", 1)))
            elif parts == ["api", "credentials"]:
                result = self.service.issue(actor, role, int(body.get("template_id", 0)), body.get("holder_id", ""), body.get("claims", {}), body.get("idempotency_key", ""), body.get("valid_until"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "revoke":
                result = self.service.revoke(actor, role, int(parts[2]), body.get("reason", ""), body.get("effective_at"))
            elif len(parts) == 4 and parts[:2] == ["api", "revocation-appointments"] and parts[3] == "withdraw":
                result = self.service.withdraw_appointment(actor, role, int(parts[2]))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "dispute":
                result = self.service.dispute(actor, role, int(parts[2]), body.get("reason", ""))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "present":
                result = self.service.present(actor, role, int(parts[2]), body.get("disclosed_fields"))
            elif len(parts) == 4 and parts[:2] == ["api", "disputes"] and parts[3] == "resolve":
                result = self.service.resolve_dispute(actor, role, int(parts[2]), body.get("decision", ""), body.get("resolution", ""))
            elif parts == ["api", "verify"]:
                result = self.service.verify(body.get("token", ""), body.get("at"), bool(body.get("online", True)))
            else:
                raise ApiError(404, "接口不存在")
            self._json(200, result)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


def run(port: int, db_path: str, seed: bool) -> None:
    store = Store(db_path)
    service = CredentialService(store)
    if seed:
        service.seed()
    Handler.service = service
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"digital credentials listening on http://127.0.0.1:{port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8211)
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    if args.init:
        Store(args.db).close()
    if not any((args.seed, not args.init)):
        return
    run(args.port, args.db, args.seed)


if __name__ == "__main__":
    main()
