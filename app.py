import io
import os
import json
import time
import queue
import base64
import secrets
import random
import threading
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, render_template_string, request, session,
                   redirect, url_for, abort, send_file, Response)
from flask_socketio import SocketIO, emit, disconnect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, inspect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ---------------------------------------------------------------
# الإعدادات (تأتي من Environment Variables في Render)
# ---------------------------------------------------------------
MASTER = os.environ.get("MASTER_KEY", "")
if len(MASTER) < 32:
    raise RuntimeError("MASTER_KEY لازم يكون 32 حرف على الأقل")

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///chat.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

MAX_FILE = int(2.5 * 1024 * 1024)  # أقصى حجم للملف
INLINE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp",
                "audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/wav"}
BANNERS = (1, 2, 3, 4, 5)  # أشكال فقاعات الرسائل
VALID_STICKERS = {"s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12"}


def _key(label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=label).derive(MASTER.encode())


# ثلاثة مفاتيح مستقلة، كل واحد لطبقة تشفير
K1 = _key(b"layer1-aes-gcm")
K2 = _key(b"layer2-chacha20")
K3 = base64.urlsafe_b64encode(_key(b"layer3-fernet"))


def enc_bytes(data: bytes) -> str:
    n1 = os.urandom(12)                                   # الطبقة 1: AES-256-GCM
    data = n1 + AESGCM(K1).encrypt(n1, data, None)
    n2 = os.urandom(12)                                   # الطبقة 2: ChaCha20-Poly1305
    data = n2 + ChaCha20Poly1305(K2).encrypt(n2, data, None)
    return Fernet(K3).encrypt(data).decode()              # الطبقة 3: Fernet


def dec_bytes(token: str) -> bytes:
    data = Fernet(K3).decrypt(token.encode())
    n2, data = data[:12], data[12:]
    data = ChaCha20Poly1305(K2).decrypt(n2, data, None)
    n1, data = data[:12], data[12:]
    return AESGCM(K1).decrypt(n1, data, None)


def encrypt(text_val: str) -> str:
    return enc_bytes(text_val.encode("utf-8"))


def decrypt(token: str) -> str:
    return dec_bytes(token).decode("utf-8")


# ---------------------------------------------------------------
# التطبيق وقاعدة البيانات
# ---------------------------------------------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = _key(b"flask-session")
app.config.update(
    SQLALCHEMY_DATABASE_URI=DB_URL,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True, "pool_recycle": 300},
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=3 * 1024 * 1024,
)
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
online = {}  # sid -> user id


@app.after_request
def secure_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(15), default="user")       # owner / admin / user
    is_hidden = db.Column(db.Boolean, default=False)      # إخفاء المستخدم عن العامة
    uid_code = db.Column(db.String(10), unique=True)      # ID عشوائي من 6 أرقام
    created_at = db.Column(db.DateTime, default=now)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), default="")
    kind = db.Column(db.String(15), nullable=False)       # group / private / dm / (general قديم)
    created_by = db.Column(db.Integer, default=None)
    created_at = db.Column(db.DateTime, default=now)


class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, index=True, nullable=False)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    __table_args__ = (db.UniqueConstraint("room_id", "user_id"),)


class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, index=True, nullable=False)
    receiver_id = db.Column(db.Integer, index=True, nullable=False)
    status = db.Column(db.String(15), default="pending")  # pending / accepted
    created_at = db.Column(db.DateTime, default=now)
    __table_args__ = (db.UniqueConstraint("sender_id", "receiver_id"),)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, index=True, nullable=False)
    blob = db.Column(db.Text, nullable=False)             # الرسالة مشفرة بثلاث طبقات
    created_at = db.Column(db.DateTime, default=now)


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, index=True, nullable=False)
    meta = db.Column(db.Text, nullable=False)             # الاسم والنوع وحالة "مرة واحدة" (مشفر)
    data = db.Column(db.Text, nullable=False)             # محتوى الملف (مشفر)
    created_at = db.Column(db.DateTime, default=now)


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40))
    ip = db.Column(db.String(64))
    success = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=now)


def generate_unique_uid_code():
    existing = {u.uid_code for u in User.query.all() if u.uid_code}
    while True:
        code = f"{random.randint(100000, 999999)}"
        if code not in existing:
            return code


def migrate_and_init_db():
    """فحص وترقية قاعدة البيانات الحالية بأمان دون فقدان أي محادثات أو ملفات قديمة"""
    db.create_all()
    insp = inspect(db.engine)

    if insp.has_table("user"):
        u_cols = {c["name"] for c in insp.get_columns("user")}
        with db.engine.begin() as conn:
            if "role" not in u_cols:
                conn.execute(text("ALTER TABLE \"user\" ADD COLUMN role VARCHAR(15) DEFAULT 'user'"))
            if "is_hidden" not in u_cols:
                conn.execute(text("ALTER TABLE \"user\" ADD COLUMN is_hidden BOOLEAN DEFAULT FALSE"))
            if "uid_code" not in u_cols:
                conn.execute(text("ALTER TABLE \"user\" ADD COLUMN uid_code VARCHAR(10)"))

    if insp.has_table("room"):
        r_cols = {c["name"] for c in insp.get_columns("room")}
        with db.engine.begin() as conn:
            if "created_by" not in r_cols:
                conn.execute(text("ALTER TABLE room ADD COLUMN created_by INTEGER"))

    # التأكد من حساب المالك (Owner)
    owner_name = os.environ.get("ADMIN_USERNAME", "").strip()
    owner_pw = os.environ.get("ADMIN_PASSWORD", "")
    if not owner_name or not owner_pw:
        raise RuntimeError("ADMIN_USERNAME و ADMIN_PASSWORD مطلوبين")

    owner = User.query.filter_by(username=owner_name).first()
    if not owner:
        owner = User(username=owner_name)
        db.session.add(owner)
    owner.password_hash = generate_password_hash(owner_pw)
    owner.is_admin = True
    owner.role = "owner"
    if not owner.uid_code:
        owner.uid_code = generate_unique_uid_code()
    db.session.commit()

    # تحديث المستخدمين القدامى الذين ليس لديهم uid_code أو role
    used_codes = {u.uid_code for u in User.query.all() if u.uid_code}
    changed = False
    for u in User.query.all():
        if not u.uid_code:
            while True:
                c = f"{random.randint(100000, 999999)}"
                if c not in used_codes:
                    used_codes.add(c)
                    u.uid_code = c
                    changed = True
                    break
        if u.username == owner_name and u.role != "owner":
            u.role = "owner"
            u.is_admin = True
            changed = True
        elif not u.role:
            u.role = "admin" if u.is_admin else "user"
            changed = True
        if u.is_hidden is None:
            u.is_hidden = False
            changed = True
    if changed:
        db.session.commit()


# ---------------------------------------------------------------
# ذاكرة سريعة: المستخدمون والغرف والأعضاء وآخر الرسائل
# ---------------------------------------------------------------
LOCK = threading.RLock()
USERS, ROOMS, MEMBERS, FRIENDS = {}, {}, {}, []
ROOM_MSGS = {}            # room id -> آخر 100 رسالة في الذاكرة للسرعة (والكل محفوظ بالقاعدة)
ID = {"msg": 0}           # عدّاد أرقام الرسائل يُزامن مع القاعدة عند التشغيل
persist_q = queue.Queue()  # طابور الحفظ في القاعدة


def sync_msg_id():
    last = db.session.query(db.func.max(ChatMessage.id)).scalar() or 0
    with LOCK:
        if last > ID["msg"]:
            ID["msg"] = last


def reload_cache():
    global USERS, ROOMS, MEMBERS, FRIENDS
    users = {}
    for u in User.query.all():
        role = u.role or ("admin" if u.is_admin else "user")
        users[u.id] = {
            "id": u.id,
            "username": u.username,
            "role": role,
            "is_owner": role == "owner",
            "is_admin": role in ("owner", "admin"),
            "is_hidden": bool(u.is_hidden),
            "uid_code": u.uid_code or "000000",
        }
    rooms = {}
    for r in Room.query.all():
        rooms[r.id] = {
            "id": r.id,
            "name": r.name or "",
            "kind": r.kind,
            "created_by": r.created_by,
        }
    members = {}
    for m in Member.query.all():
        members.setdefault(m.room_id, set()).add(m.user_id)
    friends = [
        {"id": f.id, "sender": f.sender_id, "receiver": f.receiver_id, "status": f.status}
        for f in Friendship.query.all()
    ]
    with LOCK:
        USERS, ROOMS, MEMBERS, FRIENDS = users, rooms, members, friends


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def current_user():
    uid = session.get("uid")
    u = USERS.get(uid) if uid else None
    return SimpleNamespace(**u) if u else None


def sock_user():
    uid = online.get(request.sid)
    u = USERS.get(uid) if uid else None
    return SimpleNamespace(**u) if u else None


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            session.clear()
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def staff_required(f):
    """يتيح الوصول للمالك (Owner) والمدير (Admin)"""
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or u.role not in ("owner", "admin"):
            abort(403)
        return f(*a, **kw)
    return wrapper


def owner_required(f):
    """يتيح الوصول للمالك (Owner) فقط"""
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or u.role != "owner":
            abort(403)
        return f(*a, **kw)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf():
    if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        abort(400)


def check_csrf_header():
    if not secrets.compare_digest(request.headers.get("X-CSRF", ""), session.get("csrf", "x")):
        abort(400)


def is_member(rid, uid):
    if rid is None:
        return False
    r = ROOMS.get(rid)
    if not r or r["kind"] == "general":
        return False
    return uid in (MEMBERS.get(rid) or ())


def can_manage_room(user_obj, room_dict):
    if not user_obj or not room_dict:
        return False
    if user_obj.role == "owner":
        return True
    if user_obj.role == "admin" and room_dict["kind"] in ("group", "private"):
        return room_dict.get("created_by") == user_obj.id or room_dict.get("created_by") is None
    if room_dict["kind"] == "private" and room_dict.get("created_by") == user_obj.id:
        return True
    return False


def can_see_user(viewer_obj, target_dict):
    """المستخدم المخفي لا يظهر في القوائم العادية إلا للمالك أو لنفسه"""
    if not target_dict:
        return False
    if viewer_obj.id == target_dict["id"] or viewer_obj.role == "owner":
        return True
    if target_dict.get("is_hidden"):
        return False
    return True


def rooms_payload(uid):
    viewer = USERS.get(uid)
    if not viewer:
        return {"rooms": [], "users": [], "online": [], "friends": [], "requests_in": [], "requests_out": []}
    viewer_ns = SimpleNamespace(**viewer)

    # الغرف والمحادثات الخاصة (مع إخفاء الدردشة العامة "general" دون حذف بياناتها)
    out_rooms = []
    dm_partners = set()
    for rid, mem in MEMBERS.items():
        if uid not in mem:
            continue
        r = ROOMS.get(rid)
        if not r or r["kind"] == "general":
            continue
        if r["kind"] == "dm":
            other = next((x for x in mem if x != uid), None)
            if other and other in USERS:
                dm_partners.add(other)
                out_rooms.append({
                    "id": rid,
                    "name": USERS[other]["username"],
                    "kind": "dm",
                    "with": other,
                })
        else:
            out_rooms.append({
                "id": rid,
                "name": r["name"],
                "kind": r["kind"],
                "created_by": r.get("created_by"),
                "can_manage": can_manage_room(viewer_ns, r),
                "members": sorted(list(mem)),
            })

    # الأصدقاء وطلبات الصداقة
    friend_ids = set()
    req_in = []
    req_out = []
    for f in FRIENDS:
        if f["status"] == "accepted":
            if f["sender"] == uid:
                friend_ids.add(f["receiver"])
            elif f["receiver"] == uid:
                friend_ids.add(f["sender"])
        elif f["status"] == "pending":
            if f["receiver"] == uid and f["sender"] in USERS:
                su = USERS[f["sender"]]
                if not su["is_hidden"] or viewer["role"] == "owner":
                    req_in.append({"req_id": f["id"], "id": su["id"], "username": su["username"], "uid_code": su["uid_code"]})
            elif f["sender"] == uid and f["receiver"] in USERS:
                ru = USERS[f["receiver"]]
                if not ru["is_hidden"] or viewer["role"] == "owner":
                    req_out.append({"req_id": f["id"], "id": ru["id"], "username": ru["username"], "uid_code": ru["uid_code"]})

    # المستخدمون الظاهرون
    visible_users = []
    for u in sorted(USERS.values(), key=lambda x: x["username"]):
        if can_see_user(viewer_ns, u) or u["id"] in dm_partners or u["id"] in friend_ids:
            # إذا كان مخفياً ويظهر فقط بسبب محادثة سابقة لغير المالك، نخفي ظهوره في القائمة العامة ولكن نحفظ اسم المحادثة
            in_directory = can_see_user(viewer_ns, u)
            visible_users.append({
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "uid_code": u["uid_code"],
                "is_hidden": u["is_hidden"] if viewer["role"] == "owner" else False,
                "in_directory": in_directory,
                "is_friend": (u["id"] in friend_ids) and in_directory,
            })

    # المتصلون الآن (مع استثناء المخفيين لغير المالك)
    raw_online = set(online.values())
    visible_online = [
        x for x in sorted(raw_online)
        if x in USERS and can_see_user(viewer_ns, USERS[x])
    ]

    return {
        "rooms": out_rooms,
        "users": visible_users,
        "online": visible_online,
        "friends": [x for x in sorted(friend_ids) if x in USERS and can_see_user(viewer_ns, USERS[x])],
        "requests_in": req_in,
        "requests_out": req_out,
        "me": {
            "id": viewer["id"],
            "username": viewer["username"],
            "role": viewer["role"],
            "uid_code": viewer["uid_code"],
        }
    }


def emit_to_room(rid, event, data, skip_sid=None):
    ids = MEMBERS.get(rid) or ()
    for sid, uid in list(online.items()):
        if uid in ids and sid != skip_sid:
            socketio.emit(event, data, to=sid)


def broadcast_online():
    for sid, uid in list(online.items()):
        u = USERS.get(uid)
        if not u:
            continue
        u_ns = SimpleNamespace(**u)
        vis = [
            x for x in sorted(set(online.values()))
            if x in USERS and can_see_user(u_ns, USERS[x])
        ]
        socketio.emit("online", vis, to=sid)


def notify_all():
    socketio.emit("refresh")
    broadcast_online()


def get_dm(a, b):
    for rid, r in ROOMS.items():
        if r["kind"] == "dm" and MEMBERS.get(rid) == {a, b}:
            return rid
    r = Room(name="", kind="dm", created_by=a)
    db.session.add(r)
    db.session.flush()
    rid = r.id
    db.session.add(Member(room_id=rid, user_id=a))
    db.session.add(Member(room_id=rid, user_id=b))
    db.session.commit()
    reload_cache()
    return rid


def set_members(rid, ids):
    valid = {u.id for u in User.query.filter(User.id.in_(ids))} if ids else set()
    Member.query.filter_by(room_id=rid).delete()
    for uid in valid:
        db.session.add(Member(room_id=rid, user_id=uid))


# ---------------------------------------------------------------
# الرسائل: تُرسل فوراً وتُحفظ بشكل دائم ومشفر في قاعدة البيانات
# ---------------------------------------------------------------
def new_id():
    with LOCK:
        ID["msg"] += 1
        return ID["msg"]


def load_room(rid):
    rows = (ChatMessage.query.filter_by(room_id=rid)
            .order_by(ChatMessage.id.desc()).limit(150).all())
    out = []
    for r in reversed(rows):
        try:
            m = json.loads(decrypt(r.blob))
            m["id"] = r.id
            out.append(m)
        except Exception:
            pass
    return out


def room_msgs(rid):
    lst = ROOM_MSGS.get(rid)
    if lst is None:
        loaded = load_room(rid)
        with LOCK:
            lst = ROOM_MSGS.setdefault(rid, loaded)
    return lst


def find_msg(rid, mid):
    if not mid:
        return None
    for m in room_msgs(rid):
        if m.get("id") == mid:
            return m
    row = db.session.get(ChatMessage, mid)
    if row and row.room_id == rid:
        try:
            m = json.loads(decrypt(row.blob))
            m["id"] = row.id
            return m
        except Exception:
            return None
    return None


def quote_of(rid, mid):
    m = find_msg(rid, mid)
    if not m:
        return None
    f = m.get("f")
    if m.get("st_id"):
        snippet = "✨ ملصق"
    elif m.get("t"):
        snippet = m["t"][:80]
    elif f and f.get("o"):
        snippet = "🔒 مرة واحدة"
    elif f:
        mt = f.get("m", "")
        if mt.startswith("audio/"):
            snippet = "🎤 رسالة صوتية"
        elif mt.startswith("image/"):
            snippet = "🖼️ صورة"
        else:
            snippet = "📎 " + str(f.get("n", "ملف"))
    else:
        snippet = ""
    return {"id": m["id"], "u": m.get("u", "?"), "t": snippet}


def post(rid, user, text_val, fileinfo=None, reply_id=None, cid=None, banner=None, sticker_id=None):
    msg = {"u": user.username, "uid": user.id, "t": text_val, "ts": int(time.time())}
    if fileinfo:
        msg["f"] = fileinfo
    if sticker_id in VALID_STICKERS:
        msg["st_id"] = sticker_id
    if banner in BANNERS:
        msg["b"] = banner
    quote = quote_of(rid, reply_id)
    if quote:
        msg["re"] = quote
    msg["id"] = new_id()
    lst = room_msgs(rid)
    with LOCK:
        lst.append(msg)
        del lst[:-150]
    payload = dict(msg, room=rid)
    if cid:
        payload["cid"] = cid
    emit_to_room(rid, "message", payload)
    persist_q.put(("add", rid, dict(msg)))


def once_status(msgs, uid):
    ids = [m["f"]["id"] for m in msgs if m.get("f") and m["f"].get("o")]
    if not ids:
        return
    rows = db.session.query(Attachment.id, Attachment.meta).filter(Attachment.id.in_(ids)).all()
    metas = {}
    for aid, meta in rows:
        try:
            metas[aid] = json.loads(decrypt(meta))
        except Exception:
            pass
    for m in msgs:
        f = m.get("f")
        if not f or not f.get("o"):
            continue
        meta = metas.get(f["id"])
        if meta is None or meta.get("gone"):
            st = "gone"
        elif meta.get("by") == uid:
            st = "mine_seen" if meta.get("seen") else "mine"
        elif uid in meta.get("seen", []):
            st = "seen"
        else:
            st = "new"
        m["f"] = dict(f, st=st)


def _strip(m):
    return {k: v for k, v in m.items() if k not in ("id", "room", "cid", "st")}


def persist_worker():
    while True:
        op = persist_q.get()
        for attempt in range(3):
            try:
                with app.app_context():
                    kind, rid = op[0], op[1]
                    if kind == "add":
                        msg = op[2]
                        if rid in ROOMS:
                            db.session.add(ChatMessage(
                                id=msg["id"], room_id=rid,
                                blob=encrypt(json.dumps(_strip(msg), ensure_ascii=False))))
                    elif kind == "edit":
                        msg = op[2]
                        row = db.session.get(ChatMessage, msg["id"])
                        if row and row.room_id == rid:
                            row.blob = encrypt(json.dumps(_strip(msg), ensure_ascii=False))
                    elif kind == "delete":
                        mid, fid = op[2], op[3]
                        ChatMessage.query.filter_by(id=mid, room_id=rid).delete()
                        if fid:
                            Attachment.query.filter_by(id=fid, room_id=rid).delete()
                    db.session.commit()
                break
            except Exception as e:
                print("persist error:", e)
                try:
                    with app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                time.sleep(1)


# ---------------------------------------------------------------
# القوالب والواجهات (HTML / CSS / JS)
# ---------------------------------------------------------------
HEAD = """<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>Chat App</title>
<script>
(function(){try{var t=localStorage.getItem("theme")||"auto";var d=t==="dark"||(t==="auto"&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.setAttribute("data-dark",d?"1":"0");}catch(e){}})();
</script>
<style>
:root{
  --bg:#efeae2;--card:#ffffff;--text:#111b21;--muted:#667781;--head:#008069;
  --in:#ffffff;--out:#d9fdd3;--bar:#f0f2f5;--line:#e9edef;--field:#ffffff;
  --link:#027eb5;--accent:#008069;--accent-hover:#017561;--sub:#f8f9fa;--danger:#e53935;
}
html[data-dark="1"]{
  --bg:#0b141a;--card:#111b21;--text:#e9edef;--muted:#8696a0;--head:#202c33;
  --in:#202c33;--out:#005c4b;--bar:#202c33;--line:#2a3942;--field:#2a3942;
  --link:#53bdeb;--accent:#00a884;--accent-hover:#06cf9c;--sub:#182229;--danger:#ef5350;
  color-scheme:dark;
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
header{background:var(--head);color:#fff;padding:10px 14px;display:flex;justify-content:space-between;align-items:center;font-weight:bold;box-shadow:0 1px 4px rgba(0,0,0,.18);z-index:5}
header a{color:#fff;text-decoration:none;margin-inline-start:10px;font-weight:500;font-size:14px;padding:6px 10px;border-radius:8px;background:rgba(255,255,255,.12)}
header a:hover{background:rgba(255,255,255,.22)}
.card{max-width:420px;margin:50px auto;background:var(--card);padding:26px;border-radius:16px;box-shadow:0 6px 24px rgba(0,0,0,.1)}
.wrap{max-width:980px;margin:18px auto;padding:0 12px}
.box{background:var(--card);padding:16px;border-radius:14px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.06);border:1px solid var(--line)}
input,select{width:100%;padding:11px 14px;margin:6px 0;border:1px solid var(--line);border-radius:10px;font-size:15px;background:var(--field);color:var(--text);outline:none}
input:focus,select:focus{border-color:var(--accent)}
input[type=checkbox]{width:auto;margin:0 6px}
.chk{display:inline-flex;align-items:center;padding:5px 10px;margin:3px;background:var(--sub);border-radius:8px;font-size:14px;cursor:pointer}
button{padding:10px 18px;border:none;border-radius:10px;background:var(--accent);color:#fff;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .15s,transform .1s}
button:active{transform:scale(.97)}
button.del{background:var(--danger);padding:6px 12px;font-size:13px}
button.sec{background:var(--line);color:var(--text);padding:6px 12px;font-size:13px}
.err{color:var(--danger);font-size:14px}.ok{color:#00a884;font-weight:bold;background:rgba(0,168,132,.12);padding:10px 14px;border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{padding:10px 8px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
.scroll{overflow-x:auto}
details{border-top:1px solid var(--line);padding:10px 0;margin-top:6px}
summary{font-weight:bold;cursor:pointer;padding:4px 0}
.role-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:bold}
.role-owner{background:#f59e0b;color:#fff}
.role-admin{background:#3b82f6;color:#fff}
.role-user{background:var(--line);color:var(--muted)}
.id-tag{font-family:monospace;background:rgba(0,168,132,.15);color:var(--accent);padding:2px 7px;border-radius:6px;font-size:12px;font-weight:bold}
</style></head><body>"""

LOGIN = HEAD + """
<div class="card">
<h2 style="margin-top:0;text-align:center">🔐 تسجيل الدخول</h2>
<form method="post">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
<input name="username" placeholder="اسم المستخدم" autocomplete="username" required>
<input name="password" type="password" placeholder="كلمة المرور" autocomplete="current-password" required>
<button style="width:100%;margin-top:12px;padding:12px">دخول إلى الدردشة</button>
{% if error %}<p class="err" style="text-align:center;margin-top:12px">{{ error }}</p>{% endif %}
</form></div></body></html>"""

CHAT = HEAD + r"""
<style>
body{display:flex;flex-direction:column;height:100dvh;overflow:hidden}
.ic{background:transparent;padding:6px 8px;font-size:20px;color:inherit;border-radius:50%;display:inline-flex;align-items:center;justify-content:center}
.ic:hover{background:rgba(127,127,127,.15)}
#sub{background:var(--sub);font-size:12px;color:var(--muted);padding:5px 14px;min-height:26px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line)}
#typing{color:var(--accent);font-weight:bold}

/* منطقة الرسائل وفقاعات الدردشة الحديثة (اليمين للمستخدم الحالي، اليسار للطرف الآخر) */
#messages{flex:1;overflow-y:auto;padding:14px 12px;display:flex;flex-direction:column;gap:8px;scroll-behavior:smooth}
.empty-state{margin:auto;text-align:center;color:var(--muted);padding:24px;background:var(--card);border-radius:16px;max-width:320px;box-shadow:0 2px 10px rgba(0,0,0,.06)}
.msg{
  max-width:78%;
  min-width:110px;
  padding:8px 12px 6px;
  border-radius:16px;
  position:relative;
  word-wrap:break-word;
  box-shadow:0 1px 2px rgba(0,0,0,.12);
  display:flex;
  flex-direction:column;
}
/* رسائل المستخدم الحالي: الجهة اليمنى (بداية السطر في RTL) */
.msg.me{
  align-self:flex-start;
  background:var(--out);
  color:var(--text);
  border-start-start-radius:4px;
}
/* رسائل الطرف الآخر: الجهة اليسرى (نهاية السطر في RTL) */
.msg.other{
  align-self:flex-end;
  background:var(--in);
  color:var(--text);
  border-end-start-radius:4px;
}
.msg.pending{opacity:.65}
.msg.failed{opacity:1;outline:2px solid var(--danger)}
.msg.flash{outline:3px solid var(--accent);transition:outline .3s}
.msg .top{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:2px}
.msg.pending .dots{visibility:hidden}
.dots{background:transparent;color:inherit;opacity:.65;padding:0 4px;font-size:18px;line-height:1;border-radius:6px}
.msg .name{font-size:12px;color:var(--accent);font-weight:700}
.msg.me .name{color:#00796b}
html[data-dark="1"] .msg.me .name{color:#5eead4}
.msg .txt{font-size:15px;line-height:1.45;white-space:pre-wrap}
.msg .time{font-size:10px;color:var(--muted);margin-top:3px;align-self:flex-end;direction:ltr}
.msg img.chat-img{max-width:260px;width:100%;border-radius:10px;display:block;margin:4px 0}
.msg .sticker-box{width:128px;height:128px;margin:4px auto;display:flex;align-items:center;justify-content:center}
.msg .sticker-box svg{width:100%;height:100%;filter:drop-shadow(0 3px 6px rgba(0,0,0,.16))}
.msg a{color:var(--link);font-weight:500}
.msg audio{width:230px;max-width:100%;height:38px;display:block;margin:4px 0}

/* بنرات الرسائل */
.msg.bn{color:#fff;border:1.5px solid transparent}
.msg.bn .name,.msg.bn .time{color:inherit !important;opacity:.88}
.msg.bn a{color:inherit;text-decoration:underline}
.msg.bn .quote b,.msg.bn .quote span{color:inherit}
.msg.b1{background:linear-gradient(135deg,#7b2ff7,#b24bf3);border-color:#e9c7ff;box-shadow:0 2px 10px rgba(123,47,247,.35)}
.msg.b2{background:linear-gradient(135deg,#0b1a3a,#09306b);color:#bff6ff;border-color:#00e5ff;box-shadow:0 2px 10px rgba(0,229,255,.3)}
.msg.b3{background:linear-gradient(135deg,#4a148c,#7b1fa2);border-radius:18px}
.msg.b4{background:linear-gradient(135deg,#2563eb,#1d4ed8);border-radius:20px}
.msg.b5{background:linear-gradient(135deg,#f6d365,#fda085);color:#3b2300}
.msg.prev{max-width:none;width:100%;margin:6px 0;cursor:pointer;text-align:center;align-self:stretch}
.msg.prev.on{outline:3px solid var(--accent)}

/* الاقتباس (الرد) */
.quote{border-inline-start:3px solid var(--accent);background:rgba(127,127,127,.14);border-radius:8px;padding:5px 8px;margin-bottom:5px;font-size:12.5px;cursor:pointer}
.quote b{display:block;font-size:11.5px;color:var(--accent)}
.quote span{color:var(--muted)}

/* ملفات المرة الواحدة */
.oncebtn{display:block;width:100%;margin:4px 0;background:rgba(127,127,127,.2);color:inherit;font-size:13.5px;padding:9px 12px;border-radius:10px}
.oncebtn:disabled{opacity:.65;cursor:default}
#viewer{position:fixed;inset:0;background:rgba(0,0,0,.93);z-index:100;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px}
#viewer img{max-width:95%;max-height:80%;-webkit-touch-callout:none;user-select:none;border-radius:10px}

/* شريط الرد */
#replybar{display:none;align-items:center;justify-content:space-between;gap:8px;background:var(--bar);padding:6px 14px;border-top:1px solid var(--line);font-size:13px}
#replybar.on{display:flex}
#rbtext{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}

/* لوحة الملصقات الاحترافية (Stickers) */
#stickerpanel{
  display:none;
  background:var(--card);
  border-top:1px solid var(--line);
  padding:10px 12px;
  max-height:220px;
  overflow-y:auto;
  grid-template-columns:repeat(auto-fill,minmax(72px,1fr));
  gap:10px;
  box-shadow:0 -4px 14px rgba(0,0,0,.08);
}
#stickerpanel.open{display:grid}
.stk-item{
  background:var(--sub);
  border-radius:12px;
  padding:8px;
  cursor:pointer;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  transition:transform .15s,background .15s;
  height:76px;
}
.stk-item:hover{transform:scale(1.08);background:rgba(0,168,132,.14)}
.stk-item svg{width:54px;height:54px}

/* شريط الإدخال وزر الميكروفون العصري */
#form{display:flex;gap:6px;padding:8px 10px;background:var(--bar);align-items:center;border-top:1px solid var(--line)}
#form #text{flex:1;border-radius:22px;border:1px solid var(--line);margin:0;padding:10px 15px;font-size:15px}
#form #send{border-radius:22px;padding:10px 18px}
.tool-btn{color:var(--muted);width:38px;height:38px;border-radius:50%;background:transparent;display:flex;align-items:center;justify-content:center;padding:0;flex-shrink:0}
.tool-btn:hover{background:rgba(127,127,127,.14);color:var(--accent)}
#once.on,#stkbtn.on{background:var(--accent);color:#fff}
#mic{
  background:linear-gradient(135deg,var(--accent),#059669);
  color:#fff;
  width:42px;
  height:42px;
  border-radius:50%;
  padding:0;
  display:flex;
  align-items:center;
  justify-content:center;
  box-shadow:0 2px 8px rgba(0,168,132,.35);
  flex-shrink:0;
}
#mic svg{width:20px;height:20px;fill:currentColor}

/* واجهة التسجيل الصوتي الحديثة */
#rec{
  display:none;
  gap:12px;
  padding:10px 14px;
  background:var(--card);
  border-top:1px solid var(--line);
  align-items:center;
  justify-content:space-between;
}
.recording #form{display:none}
.recording #rec{display:flex}
.rec-info{display:flex;align-items:center;gap:10px;font-weight:bold;font-size:15px}
.rec-dot{width:12px;height:12px;border-radius:50%;background:var(--danger);animation:pulse 1s infinite}
@keyframes pulse{0%{transform:scale(.9);opacity:1}50%{transform:scale(1.25);opacity:.45}100%{transform:scale(.9);opacity:1}}
.rec-waves{display:flex;gap:3px;align-items:center;height:20px}
.rec-waves i{display:block;width:3px;background:var(--accent);border-radius:2px;animation:wave .8s infinite ease-in-out}
.rec-waves i:nth-child(1){height:8px;animation-delay:.1s}
.rec-waves i:nth-child(2){height:16px;animation-delay:.25s}
.rec-waves i:nth-child(3){height:12px;animation-delay:.4s}
.rec-waves i:nth-child(4){height:18px;animation-delay:.15s}
.rec-waves i:nth-child(5){height:10px;animation-delay:.3s}
@keyframes wave{0%,100%{transform:scaleY(.6)}50%{transform:scaleY(1.25)}}

/* القائمة الجانبية المنظمة (Drawer) */
#back{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;z-index:20}
#back.open{display:block}
#drawer{
  position:fixed;top:0;bottom:0;right:0;width:85%;max-width:360px;
  background:var(--card);color:var(--text);
  transform:translateX(100%);transition:transform .22s cubic-bezier(.4,0,.2,1);
  z-index:30;display:flex;flex-direction:column;box-shadow:-4px 0 20px rgba(0,0,0,.2);
}
#drawer.open{transform:translateX(0)}
.profile-card{padding:14px;background:var(--sub);border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
.drawer-tabs{display:grid;grid-template-columns:repeat(4,1fr);background:var(--bar);border-bottom:1px solid var(--line)}
.dtab{padding:10px 4px;font-size:12px;font-weight:bold;background:transparent;color:var(--muted);border-radius:0;border-bottom:3px solid transparent}
.dtab.on{color:var(--accent);border-bottom-color:var(--accent);background:var(--card)}
.dpane{display:none;flex:1;overflow-y:auto;padding:12px}
.dpane.on{display:block}
.sec-title{margin:12px 0 6px;font-size:13px;color:var(--accent);font-weight:700;display:flex;justify-content:space-between;align-items:center}
.item{padding:10px 12px;border-radius:10px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;transition:background .12s}
.item:hover{background:var(--sub)}
.item.on{background:rgba(0,168,132,.16);font-weight:600}
.badge{background:var(--danger);color:#fff;border-radius:10px;padding:1px 7px;font-size:11px;font-weight:bold}
.row{display:flex;gap:6px;flex-wrap:wrap}
.row button{padding:8px 10px;font-size:13px;background:var(--bar);color:var(--text)}
.row button.on{background:var(--accent);color:#fff}
.sw{width:46px;height:46px;border-radius:10px;border:2px solid var(--line);cursor:pointer}
.sw.on{border-color:var(--accent);outline:2px solid var(--accent)}
.sw.img{width:56px;height:80px}
#wallpreview{width:100%;height:84px;border-radius:12px;border:1px solid var(--line);margin-bottom:8px;display:flex;align-items:center;justify-content:center;font-size:12px;color:var(--muted);background-size:cover;background-position:center}

/* النوافذ المنبثقة (إنشاء غرفة / إدارة أعضاء / قائمة الرسالة) */
.modal-back{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;z-index:50;align-items:center;justify-content:center;padding:14px}
.modal-back.open{display:flex}
.modal-box{width:100%;max-width:420px;background:var(--card);border-radius:16px;padding:18px;max-height:86dvh;overflow-y:auto}
#sheetback{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;z-index:60}
#sheetback.open{display:flex;align-items:flex-end;justify-content:center}
#sheet{width:100%;max-width:480px;background:var(--card);border-radius:18px 18px 0 0;padding:12px}
#sheet button{display:block;width:100%;margin:6px 0;background:var(--bar);color:var(--text);padding:12px}
#sheet button.danger{background:var(--danger);color:#fff}
</style>

<header>
  <span style="display:flex;align-items:center;gap:6px">
    <button id="menu" class="ic" title="القائمة">☰</button>
    <b id="title">اختر محادثة</b>
  </span>
  <span style="display:flex;align-items:center;gap:4px">
    <button id="roomInfoBtn" class="ic" style="display:none;font-size:16px" title="إدارة أعضاء الغرفة">👥</button>
    {% if is_staff %}<a href="/admin">⚙️ الإدارة</a>{% endif %}
    <a href="/logout">خروج</a>
  </span>
</header>

<div id="sub">
  <span><span id="cnt">🟢 0 متصل</span> · <span class="id-tag">ID: {{ uid_code }}</span></span>
  <span id="typing"></span>
</div>

<div id="messages"></div>

<div id="replybar">
  <div id="rbtext"></div>
  <button type="button" id="rbx" class="ic">✖</button>
</div>

<!-- لوحة الملصقات (Stickers) -->
<div id="stickerpanel"></div>

<!-- شريط الإرسال -->
<form id="form">
  <button type="button" id="stkbtn" class="tool-btn" title="الملصقات">😊</button>
  <button type="button" id="clip" class="tool-btn" title="إرفاق ملف أو صورة">📎</button>
  <input type="file" id="file" hidden>
  <button type="button" id="once" class="tool-btn" title="عرض لمرة واحدة">🔒</button>
  <input id="text" placeholder="اكتب رسالة..." autocomplete="off">
  <button type="button" id="mic" title="تسجيل رسالة صوتية">
    <svg viewBox="0 0 24 24"><path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3zm5.3-3c0 3-2.54 5.1-5.3 5.1S6.7 14 6.7 11H5c0 3.41 2.72 6.23 6 6.72V21h2v-3.28c3.28-.49 6-3.31 6-6.72h-1.7z"/></svg>
  </button>
  <button id="send">إرسال</button>
</form>

<!-- واجهة التسجيل الصوتي العصرية -->
<div id="rec">
  <button type="button" id="rcancel" class="del">✖ إلغاء</button>
  <div class="rec-info">
    <span class="rec-dot"></span>
    <span id="rt">0:00</span>
    <div class="rec-waves"><i></i><i></i><i></i><i></i><i></i></div>
  </div>
  <button type="button" id="rsend">إرسال التسجيل ➤</button>
</div>

<div id="back"></div>

<!-- القائمة الجانبية المقسمة والمنظمة -->
<aside id="drawer">
  <div class="profile-card">
    <div>
      <div style="font-weight:bold;font-size:15px">{{ username }}
        <span class="role-badge role-{{ role }}">{{ "مالك" if role == "owner" else ("مدير" if role == "admin" else "مستخدم") }}</span>
      </div>
      <div style="font-size:12px;color:var(--muted);margin-top:3px">المعرّف الخاص بك: <span class="id-tag" id="myCode">{{ uid_code }}</span></div>
    </div>
    <button type="button" class="sec" onclick="navigator.clipboard.writeText('{{ uid_code }}');this.textContent='تم النسخ ✓';setTimeout(()=>this.textContent='نسخ ID',1200)">نسخ ID</button>
  </div>

  <div class="drawer-tabs">
    <button type="button" class="dtab on" data-tab="t-chats">💬 المحادثات</button>
    <button type="button" class="dtab" data-tab="t-friends">🤝 الأصدقاء</button>
    <button type="button" class="dtab" data-tab="t-online">🟢 المتصلون</button>
    <button type="button" class="dtab" data-tab="t-style">🎨 المظهر</button>
  </div>

  <!-- تبويب 1: المحادثات والغرف المغلقة والمجموعات -->
  <div class="dpane on" id="t-chats">
    <div class="sec-title">
      <span>🔐 الغرف المغلقة الخاصة</span>
      <button type="button" class="sec" id="newPrivBtn" style="padding:4px 8px;font-size:12px">+ إنشاء غرفة</button>
    </div>
    <div id="privrooms"></div>

    <div class="sec-title"><span>🗂️ المجموعات</span></div>
    <div id="groups"></div>

    <div class="sec-title"><span>✉️ المحادثات الخاصة</span></div>
    <div id="dms"></div>
  </div>

  <!-- تبويب 2: نظام الأصدقاء والبحث عبر ID -->
  <div class="dpane" id="t-friends">
    <div class="sec-title"><span>🔍 إضافة صديق عبر ID (6 أرقام)</span></div>
    <div style="display:flex;gap:6px">
      <input id="searchIdInp" placeholder="أدخل رقم ID مثل 123456" maxlength="6" style="margin:0">
      <button type="button" id="searchIdBtn">بحث</button>
    </div>
    <div id="searchResult" style="margin-top:8px"></div>

    <div class="sec-title"><span>📥 طلبات صداقة واردة</span></div>
    <div id="reqInList"></div>

    <div class="sec-title"><span>👥 قائمة أصدقائي</span></div>
    <div id="friendsList"></div>
  </div>

  <!-- تبويب 3: المتصلون الآن وجميع الأعضاء -->
  <div class="dpane" id="t-online">
    <div class="sec-title"><span>🟢 المتصلون الآن</span></div>
    <div id="onlineList"></div>

    <div class="sec-title"><span>👤 الأعضاء</span></div>
    <div id="allUsersList"></div>
  </div>

  <!-- تبويب 4: الخلفيات والبنرات والمظهر -->
  <div class="dpane" id="t-style">
    <div class="sec-title"><span>🌓 وضع الإضاءة</span></div>
    <div class="row" id="themes">
      <button type="button" data-t="light">☀️ فاتح</button>
      <button type="button" data-t="dark">🌙 داكن</button>
      <button type="button" data-t="auto">🌓 تلقائي</button>
    </div>

    <div class="sec-title"><span>✨ بنرات الرسائل (معاينة مباشرة)</span></div>
    <div id="banners"></div>

    <div class="sec-title"><span>🖼️ خلفية المحادثة (معاينة مباشرة)</span></div>
    <div id="wallpreview">معاينة الخلفية المختارة</div>
    <div class="row" id="walls"></div>
    <div class="row" style="margin-top:8px">
      <button type="button" id="wallpick">📱 صورة من جهازك</button>
      <button type="button" id="wallreset">إعادة ضبط</button>
    </div>
    <input type="file" id="wallfile" accept="image/*" hidden>

    {% if is_staff %}
    <div class="sec-title" style="margin-top:18px"><span>⚙️ قسم الإدارة</span></div>
    <a href="/admin" style="display:block;text-align:center;background:var(--accent);color:#fff;padding:10px;border-radius:10px;text-decoration:none;font-weight:bold">فتح لوحة الإدارة المستقلة</a>
    {% endif %}
  </div>
</aside>

<!-- نافذة إنشاء غرفة مغلقة -->
<div class="modal-back" id="createRoomModal">
  <div class="modal-box">
    <h3 style="margin-top:0">🔐 إنشاء غرفة محادثة مغلقة</h3>
    <input id="newRoomName" placeholder="اسم الغرفة المغلقة">
    <div style="font-size:13px;color:var(--muted);margin:8px 0 4px">اختر الأعضاء المسموح لهم بالدخول:</div>
    <div id="newRoomMembers" style="max-height:180px;overflow-y:auto;border:1px solid var(--line);border-radius:10px;padding:8px"></div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button type="button" id="createRoomSubmit" style="flex:1">إنشاء الغرفة</button>
      <button type="button" class="sec" onclick="$('createRoomModal').classList.remove('open')">إلغاء</button>
    </div>
  </div>
</div>

<!-- نافذة إدارة أعضاء الغرفة المغلقة أو المجموعة -->
<div class="modal-back" id="manageRoomModal">
  <div class="modal-box">
    <h3 style="margin-top:0" id="manageRoomTitle">إدارة أعضاء الغرفة</h3>
    <div id="manageRoomMembers" style="max-height:220px;overflow-y:auto;border:1px solid var(--line);border-radius:10px;padding:8px"></div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button type="button" id="saveRoomMembersBtn" style="flex:1">حفظ التعديلات</button>
      <button type="button" class="sec" onclick="$('manageRoomModal').classList.remove('open')">إغلاق</button>
    </div>
  </div>
</div>

<div id="sheetback"><div id="sheet">
  <button id="sreply">↩️ رد على الرسالة</button>
  <button id="scopy">📋 نسخ النص</button>
  <button id="sedit">✏️ تعديل الرسالة</button>
  <button id="sdel" class="danger">🗑️ حذف الرسالة للجميع</button>
  <button id="sclose">إغلاق</button>
</div></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
<script>
const me = {{ username|tojson }}, myId = {{ uid }}, csrf = {{ csrf_token()|tojson }}, isStaff = {{ is_staff|tojson }};
let rooms = [], users = [], online = [], friends = [], reqIn = [], reqOut = [];
let active = null, unread = {}, tTimer = null, lastTyping = 0;
let replyTo = null, sheetMsg = null, editing = null, onceOn = false;
const $ = id => document.getElementById(id);
const box = $("messages");
const socket = io({transports: ["websocket", "polling"]});

/* ---------- ملصقات SVG الاحترافية المدمجة ---------- */
const STICKERS = {
  s1: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="#FFD93B"/><circle cx="42" cy="48" r="7" fill="#3E2723"/><circle cx="78" cy="48" r="7" fill="#3E2723"/><path d="M35 72 Q60 98 85 72" stroke="#3E2723" stroke-width="6" fill="none" stroke-linecap="round"/><text x="60" y="112" font-size="16" text-anchor="middle" fill="#D97706" font-weight="bold">مرحباً!</text></svg>`,
  s2: `<svg viewBox="0 0 120 120"><path d="M60 102 C60 102 16 74 16 42 C16 25 30 14 44 14 C53 14 60 21 60 28 C60 21 67 14 76 14 C90 14 104 25 104 42 C104 74 60 102 60 102 Z" fill="#F43F5E"/><circle cx="42" cy="36" r="5" fill="#FFE4E6" opacity=".7"/></svg>`,
  s3: `<svg viewBox="0 0 120 120"><circle cx="60" cy="58" r="50" fill="#FFD93B"/><path d="M32 45 Q42 35 52 45" stroke="#3E2723" stroke-width="5" fill="none" stroke-linecap="round"/><path d="M68 45 Q78 35 88 45" stroke="#3E2723" stroke-width="5" fill="none" stroke-linecap="round"/><path d="M34 68 Q60 96 86 68 Z" fill="#E11D48"/><path d="M18 58 Q10 72 22 76" fill="#38BDF8"/><path d="M102 58 Q110 72 98 76" fill="#38BDF8"/></svg>`,
  s4: `<svg viewBox="0 0 120 120"><rect x="24" y="48" width="22" height="48" rx="6" fill="#3B82F6"/><path d="M46 52 L66 20 C70 14 78 18 76 26 L70 46 L94 46 C102 46 104 54 100 62 L90 90 C88 94 82 96 76 96 L46 96 Z" fill="#FBBF24"/></svg>`,
  s5: `<svg viewBox="0 0 120 120"><path d="M60 12 C85 38 100 58 94 84 C88 104 68 110 60 110 C52 110 32 104 26 84 C20 58 35 38 60 12 Z" fill="#F97316"/><path d="M60 40 C74 58 80 72 75 90 C71 102 60 106 60 106 C60 106 49 102 45 90 C40 72 46 58 60 40 Z" fill="#FACC15"/></svg>`,
  s6: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#10B981"/><path d="M36 62 L52 78 L86 44" stroke="#fff" stroke-width="10" fill="none" stroke-linecap="round" stroke-linejoin="round"/><text x="60" y="105" font-size="14" text-anchor="middle" fill="#fff" font-weight="bold">تمام</text></svg>`,
  s7: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#6366F1"/><text x="60" y="55" font-size="22" text-anchor="middle" fill="#fff" font-weight="bold">شكراً</text><text x="60" y="82" font-size="26" text-anchor="middle">🌹</text></svg>`,
  s8: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#FFD93B"/><rect x="20" y="38" width="36" height="22" rx="5" fill="#111827"/><rect x="64" y="38" width="36" height="22" rx="5" fill="#111827"/><line x1="56" y1="45" x2="64" y2="45" stroke="#111827" stroke-width="5"/><path d="M40 80 Q60 92 80 78" stroke="#3E2723" stroke-width="6" fill="none" stroke-linecap="round"/></svg>`,
  s9: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#8B5CF6"/><polygon points="60,18 71,44 98,46 77,64 84,92 60,76 36,92 43,64 22,46 49,44" fill="#FDE047"/></svg>`,
  s10: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#EC4899"/><text x="60" y="58" font-size="22" text-anchor="middle" fill="#fff" font-weight="bold">مبروك</text><text x="60" y="86" font-size="26" text-anchor="middle">🎉</text></svg>`,
  s11: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#0EA5E9"/><path d="M38 46 Q45 54 52 46" stroke="#fff" stroke-width="5" fill="none"/><path d="M68 46 Q75 54 82 46" stroke="#fff" stroke-width="5" fill="none"/><circle cx="60" cy="78" r="10" fill="#fff"/><text x="86" y="32" font-size="18" fill="#fff" font-weight="bold">Zzz</text></svg>`,
  s12: `<svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="#14B8A6"/><text x="60" y="55" font-size="18" text-anchor="middle" fill="#fff" font-weight="bold">السلام عليكم</text><text x="60" y="84" font-size="24" text-anchor="middle">✨</text></svg>`
};

const sp = $("stickerpanel");
Object.keys(STICKERS).forEach(k => {
  const div = document.createElement("div");
  div.className = "stk-item";
  div.innerHTML = STICKERS[k];
  div.onclick = () => {
    if (active === null) { alert("اختر محادثة أولاً"); return; }
    sendSticker(k);
    sp.classList.remove("open");
    $("stkbtn").classList.remove("on");
  };
  sp.appendChild(div);
});
$("stkbtn").onclick = () => {
  sp.classList.toggle("open");
  $("stkbtn").classList.toggle("on", sp.classList.contains("open"));
};

/* ---------- التبويبات في القائمة الجانبية ---------- */
document.querySelectorAll(".dtab").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll(".dtab").forEach(b => b.classList.remove("on"));
    document.querySelectorAll(".dpane").forEach(p => p.classList.remove("on"));
    btn.classList.add("on");
    $(btn.dataset.tab).classList.add("on");
  };
});

function userName(id){ const u = users.find(x => x.id === id); return u ? u.username : "مستخدم"; }
function myBanner(){ try { return parseInt(localStorage.getItem("banner") || "0", 10) || 0; } catch (e) { return 0; } }
function newCid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function findEl(id){ return box.querySelector('[data-id="' + id + '"]'); }

function item(label, rid, n, subText){
  const d = document.createElement("div");
  d.className = "item" + (rid !== null && rid === active ? " on" : "");
  const left = document.createElement("div");
  const s = document.createElement("span"); s.textContent = label; left.appendChild(s);
  if (subText) {
    const sm = document.createElement("div");
    sm.style.fontSize = "11px"; sm.style.color = "var(--muted)";
    sm.textContent = subText; left.appendChild(sm);
  }
  d.appendChild(left);
  if (n) { const b = document.createElement("span"); b.className = "badge"; b.textContent = n; d.appendChild(b); }
  if (rid !== null) d.onclick = () => openRoom(rid);
  return d;
}

function renderSide(){
  // 1. الغرف المغلقة الخاصة
  const pr = $("privrooms"); pr.innerHTML = "";
  const privList = rooms.filter(r => r.kind === "private");
  if (!privList.length) pr.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:4px 8px">لا توجد غرف مغلقة حالياً</div>';
  privList.forEach(r => pr.appendChild(item("🔐 " + r.name, r.id, unread[r.id], (r.members ? r.members.length : 1) + " عضو")));

  // 2. المجموعات
  const gl = $("groups"); gl.innerHTML = "";
  const grpList = rooms.filter(r => r.kind === "group");
  if (!grpList.length) gl.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:4px 8px">لا توجد مجموعات</div>';
  grpList.forEach(r => gl.appendChild(item("🗂️ " + r.name, r.id, unread[r.id])));

  // 3. المحادثات الخاصة النشطة
  const dl = $("dms"); dl.innerHTML = "";
  const dmList = rooms.filter(r => r.kind === "dm");
  if (!dmList.length) dl.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:4px 8px">لا توجد محادثات خاصة بعد</div>';
  dmList.forEach(r => {
    const isOn = online.includes(r.with);
    dl.appendChild(item((isOn ? "🟢 " : "⚪ ") + (r.name || userName(r.with)), r.id, unread[r.id]));
  });

  // 4. طلبات الصداقة الواردة
  const ril = $("reqInList"); ril.innerHTML = "";
  if (!reqIn.length) ril.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:4px 8px">لا توجد طلبات جديدة</div>';
  reqIn.forEach(rq => {
    const d = document.createElement("div");
    d.className = "item";
    d.innerHTML = `<span><b>${rq.username}</b> <span class="id-tag">#${rq.uid_code}</span></span>`;
    const acts = document.createElement("div");
    acts.style.display = "flex"; acts.style.gap = "4px";
    const okB = document.createElement("button"); okB.textContent = "قبول"; okB.style.padding = "4px 10px"; okB.style.fontSize = "12px";
    okB.onclick = () => socket.emit("friend_respond", {req_id: rq.req_id, action: "accept"});
    const noB = document.createElement("button"); noB.textContent = "رفض"; noB.className = "del"; noB.style.padding = "4px 10px";
    noB.onclick = () => socket.emit("friend_respond", {req_id: rq.req_id, action: "reject"});
    acts.appendChild(okB); acts.appendChild(noB);
    d.appendChild(acts);
    ril.appendChild(d);
  });

  // 5. قائمة الأصدقاء
  const fl = $("friendsList"); fl.innerHTML = "";
  const frUsers = users.filter(u => friends.includes(u.id) && u.in_directory);
  if (!frUsers.length) fl.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:4px 8px">أضف أصدقاء باستخدام رقم ID</div>';
  frUsers.forEach(u => {
    const dm = rooms.find(r => r.kind === "dm" && r.with === u.id);
    const el = item((online.includes(u.id) ? "🟢 " : "⚪ ") + u.username, dm ? dm.id : null, dm ? unread[dm.id] : 0, "ID: " + u.uid_code);
    el.onclick = () => socket.emit("dm", {user: u.id});
    fl.appendChild(el);
  });

  // 6. المتصلون الآن
  const ol = $("onlineList"); ol.innerHTML = "";
  const onUsers = users.filter(u => online.includes(u.id) && u.in_directory);
  onUsers.forEach(u => {
    const el = item("🟢 " + u.username + (u.id === myId ? " (أنت)" : ""), null, 0, "ID: " + u.uid_code);
    if (u.id !== myId) el.onclick = () => socket.emit("dm", {user: u.id});
    ol.appendChild(el);
  });

  // 7. جميع الأعضاء الظاهرين
  const aul = $("allUsersList"); aul.innerHTML = "";
  users.filter(u => u.id !== myId && u.in_directory).forEach(u => {
    const dm = rooms.find(r => r.kind === "dm" && r.with === u.id);
    const el = item((online.includes(u.id) ? "🟢 " : "⚪ ") + u.username + (u.is_hidden ? " 👁️‍🗨️(مخفي)" : ""), dm ? dm.id : null, dm ? unread[dm.id] : 0, "ID: " + u.uid_code);
    el.onclick = () => socket.emit("dm", {user: u.id});
    aul.appendChild(el);
  });

  // تحديث الهيدر
  const cur = rooms.find(x => x.id === active);
  if (cur) {
    $("title").textContent = cur.kind === "dm" ? ("✉️ " + (cur.name || userName(cur.with))) : (cur.kind === "private" ? "🔐 " + cur.name : "🗂️ " + cur.name);
    $("roomInfoBtn").style.display = cur.can_manage ? "inline-flex" : "none";
  } else {
    $("title").textContent = "اختر محادثة من القائمة";
    $("roomInfoBtn").style.display = "none";
    if (!box.children.length) {
      box.innerHTML = '<div class="empty-state"><h3>👋 أهلاً بك في الدردشة</h3><p>افتح القائمة الجانبية (☰) لاختيار محادثة، أو إنشاء غرفة مغلقة، أو البحث عن صديق عبر رقم ID.</p></div>';
    }
  }
  $("cnt").textContent = "🟢 " + online.length + " متصل";
}

function openRoom(id){
  active = id; unread[id] = 0; box.innerHTML = ""; $("typing").textContent = ""; clearReply();
  socket.emit("open", {room: id});
  closeDrawer(); renderSide();
}

/* ---------- البحث عن صديق عبر ID وإرسال طلب صداقة ---------- */
$("searchIdBtn").onclick = () => {
  const code = $("searchIdInp").value.trim();
  if (code.length !== 6) {
    $("searchResult").innerHTML = '<span class="err">الرجاء إدخال رقم ID مكون من 6 أرقام</span>';
    return;
  }
  socket.emit("search_id", {uid_code: code});
};
socket.on("search_result", d => {
  const res = $("searchResult");
  if (!d.found) {
    res.innerHTML = '<div class="err">لم يتم العثور على مستخدم بهذا الـ ID</div>';
    return;
  }
  res.innerHTML = "";
  const card = document.createElement("div");
  card.className = "item"; card.style.background = "var(--sub)";
  card.innerHTML = `<div><b>${d.username}</b> <span class="id-tag">#${d.uid_code}</span></div>`;
  const btn = document.createElement("button");
  btn.style.padding = "5px 10px"; btn.style.fontSize = "12px";
  if (d.id === myId) {
    btn.textContent = "حسابك"; btn.disabled = true;
  } else if (d.is_friend) {
    btn.textContent = "مراسلة 💬";
    btn.onclick = () => socket.emit("dm", {user: d.id});
  } else if (d.pending) {
    btn.textContent = "الطلب قيد الانتظار ⏳"; btn.disabled = true;
  } else {
    btn.textContent = "+ طلب صداقة";
    btn.onclick = () => { socket.emit("friend_request", {target_id: d.id}); btn.textContent = "تم الإرسال ✓"; btn.disabled = true; };
  }
  card.appendChild(btn);
  res.appendChild(card);
});

/* ---------- إنشاء وإدارة الغرف المغلقة ---------- */
$("newPrivBtn").onclick = () => {
  $("newRoomName").value = "";
  const container = $("newRoomMembers"); container.innerHTML = "";
  users.filter(u => u.id !== myId && u.in_directory).forEach(u => {
    const lbl = document.createElement("label"); lbl.className = "chk"; styleChk(lbl);
    lbl.innerHTML = `<input type="checkbox" value="${u.id}"> ${u.username} <span class="id-tag">#${u.uid_code}</span>`;
    container.appendChild(lbl);
  });
  $("createRoomModal").classList.add("open");
};
function styleChk(el){ el.style.display = "flex"; el.style.justifyContent = "space-between"; }
$("createRoomSubmit").onclick = () => {
  const name = $("newRoomName").value.trim();
  if (!name) { alert("أدخل اسم الغرفة"); return; }
  const mems = Array.from($("newRoomMembers").querySelectorAll("input:checked")).map(i => parseInt(i.value, 10));
  socket.emit("create_private_room", {name: name, members: mems});
  $("createRoomModal").classList.remove("open");
};

$("roomInfoBtn").onclick = () => {
  const cur = rooms.find(x => x.id === active);
  if (!cur || !cur.can_manage) return;
  $("manageRoomTitle").textContent = "إدارة أعضاء: " + cur.name;
  const container = $("manageRoomMembers"); container.innerHTML = "";
  users.filter(u => u.in_directory).forEach(u => {
    const checked = (cur.members || []).includes(u.id) ? "checked" : "";
    const disabled = (u.id === cur.created_by) ? "disabled" : "";
    const lbl = document.createElement("label"); lbl.className = "chk"; styleChk(lbl);
    lbl.innerHTML = `<span><input type="checkbox" value="${u.id}" ${checked} ${disabled}> ${u.username}</span> <span class="id-tag">#${u.uid_code}</span>`;
    container.appendChild(lbl);
  });
  $("manageRoomModal").classList.add("open");
};
$("saveRoomMembersBtn").onclick = () => {
  const cur = rooms.find(x => x.id === active);
  if (!cur) return;
  const mems = Array.from($("manageRoomMembers").querySelectorAll("input:checked")).map(i => parseInt(i.value, 10));
  socket.emit("update_room_members", {room: cur.id, members: mems});
  $("manageRoomModal").classList.remove("open");
};

/* ---------- الرد والتعديل والحذف ---------- */
function snippetOf(m){
  if (m.st_id) return "✨ ملصق";
  if (m.t) return m.t.slice(0, 60);
  if (m.f) {
    if (m.f.o) return "🔒 مرة واحدة";
    if (m.f.m.indexOf("audio/") === 0) return "🎤 رسالة صوتية";
    if (m.f.m.indexOf("image/") === 0) return "🖼️ صورة";
    return "📎 " + m.f.n;
  }
  return "";
}
function setReply(m){
  clearReply();
  replyTo = {id: m.id, u: m.u, snip: snippetOf(m)};
  $("rbtext").textContent = "↩️ الرد على " + m.u + ": " + replyTo.snip;
  $("replybar").classList.add("on"); $("text").focus();
}
function clearReply(){
  if (editing) $("text").value = "";
  editing = null; replyTo = null; $("replybar").classList.remove("on");
}
function setEdit(m){
  clearReply(); editing = m.id;
  $("rbtext").textContent = "✏️ تعديل الرسالة";
  $("replybar").classList.add("on");
  $("text").value = m.t; $("text").focus();
}
function jumpTo(id){
  const el = findEl(id);
  if (!el) return;
  el.scrollIntoView({block: "center"}); el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1500);
}
function openSheet(m){
  sheetMsg = m;
  $("sdel").style.display = (isStaff || m.u === me) ? "block" : "none";
  $("scopy").style.display = m.t ? "block" : "none";
  $("sedit").style.display = (m.u === me && m.t && !m.st_id) ? "block" : "none";
  $("sheetback").classList.add("open");
}
function closeSheet(){ $("sheetback").classList.remove("open"); }
function removeMsg(id){
  const el = findEl(id); if (el) el.remove();
  if ((replyTo && replyTo.id === id) || editing === id) clearReply();
}
function applyEdit(id, text_val){
  const el = findEl(id);
  if (!el || !el._m) return;
  el._m.t = text_val; el._m.ed = 1;
  const tx = el.querySelector(".txt"); if (tx) tx.textContent = text_val;
  el.querySelector(".time").textContent = timeText(el._m);
}
$("sreply").onclick = () => { if (sheetMsg) setReply(sheetMsg); closeSheet(); };
$("scopy").onclick = () => { try { navigator.clipboard.writeText(sheetMsg.t); } catch (e) {} closeSheet(); };
$("sedit").onclick = () => { if (sheetMsg) setEdit(sheetMsg); closeSheet(); };
$("sdel").onclick = () => {
  if (sheetMsg && confirm("حذف الرسالة للجميع؟")) {
    removeMsg(sheetMsg.id);
    socket.emit("delete", {room: active, id: sheetMsg.id});
  }
  closeSheet();
};
$("sclose").onclick = closeSheet;
$("sheetback").onclick = e => { if (e.target === $("sheetback")) closeSheet(); };
$("rbx").onclick = clearReply;

/* ---------- مرة واحدة ---------- */
function setOnceState(b, st, who){
  b.dataset.st = st;
  const k = b.dataset.kind;
  const L = {
    "new": "🔒 " + k + " (مرة واحدة) — اضغط للعرض",
    "seen": "✔️ تم الفتح",
    "mine": "🔒 " + k + " أُرسلت (مرة واحدة)",
    "mine_seen": "👁️ تمت مشاهدتها" + (who ? " (" + who + ")" : ""),
    "gone": "🕳️ انتهت صلاحيتها"
  };
  b.textContent = L[st] || "";
  b.disabled = st !== "new";
}
function showOnce(url, mime){
  const ov = document.createElement("div"); ov.id = "viewer";
  let el;
  if (mime.indexOf("audio/") === 0) { el = document.createElement("audio"); el.controls = true; el.autoplay = true; }
  else { el = document.createElement("img"); el.draggable = false; }
  el.src = url; ov.appendChild(el);
  const x = document.createElement("button"); x.textContent = "إغلاق ✖";
  x.onclick = () => { URL.revokeObjectURL(url); ov.remove(); };
  ov.appendChild(x); ov.oncontextmenu = e => e.preventDefault();
  document.body.appendChild(ov);
}
async function openOnce(f, b){
  b.disabled = true;
  try {
    const r = await fetch("/once/" + f.id, {method: "POST", headers: {"X-CSRF": csrf}});
    if (!r.ok) { setOnceState(b, r.status === 410 ? "seen" : "gone"); return; }
    const blob = await r.blob();
    setOnceState(b, "seen");
    showOnce(URL.createObjectURL(blob), f.m);
  } catch (e) { setOnceState(b, "new"); }
}
function setOnceMode(v){
  onceOn = v; $("once").classList.toggle("on", v);
  $("text").placeholder = v ? "🔒 الصورة أو الصوت القادم: عرض لمرة واحدة" : "اكتب رسالة...";
}
$("once").onclick = () => setOnceMode(!onceOn);

/* ---------- بناء فقاعة الرسالة (يمين للمستخدم الحالي / يسار للطرف الآخر) ---------- */
function timeText(m){
  return new Date(m.ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) + (m.ed ? " · معدّلة" : "");
}
function build(m){
  const isMine = (m.uid ? m.uid === myId : m.u === me);
  const d = document.createElement("div");
  d.className = "msg " + (isMine ? "me" : "other") + (m.b ? " bn b" + m.b : "") + (m.pending ? " pending" : "");
  if (m.id) d.dataset.id = m.id;
  if (m.cid) d.dataset.cid = m.cid;
  d._m = m;

  const top = document.createElement("div"); top.className = "top";
  const n = document.createElement("span"); n.className = "name"; n.textContent = isMine ? "أنت" : m.u; top.appendChild(n);
  const dots = document.createElement("button"); dots.type = "button"; dots.className = "dots"; dots.textContent = "⋮";
  dots.onclick = ev => { ev.stopPropagation(); if (d._m.id) openSheet(d._m); };
  top.appendChild(dots); d.appendChild(top);

  if (m.re) {
    const q = document.createElement("div"); q.className = "quote";
    const qn = document.createElement("b"); qn.textContent = m.re.u;
    const qt = document.createElement("span"); qt.textContent = m.re.t;
    q.appendChild(qn); q.appendChild(qt);
    q.onclick = ev => { ev.stopPropagation(); jumpTo(m.re.id); };
    d.appendChild(q);
  }

  if (m.st_id && STICKERS[m.st_id]) {
    const sb = document.createElement("div");
    sb.className = "sticker-box";
    sb.innerHTML = STICKERS[m.st_id];
    d.appendChild(sb);
  } else if (m.f && m.f.o) {
    const b = document.createElement("button"); b.type = "button"; b.className = "oncebtn";
    b.dataset.att = m.f.id; b.dataset.kind = m.f.m.indexOf("audio/") === 0 ? "تسجيل صوتي" : "صورة";
    setOnceState(b, m.f.st || (isMine ? "mine" : "new"));
    b.onclick = () => openOnce(m.f, b);
    d.appendChild(b);
  } else if (m.f && m.f.m.indexOf("audio/") === 0) {
    const au = document.createElement("audio");
    au.controls = true; au.preload = "metadata"; au.src = "/file/" + m.f.id;
    d.appendChild(au);
  } else if (m.f) {
    const a = document.createElement("a"); a.href = "/file/" + m.f.id; a.target = "_blank";
    if (m.f.m.indexOf("image/") === 0) {
      const i = document.createElement("img"); i.className = "chat-img"; i.src = "/file/" + m.f.id;
      i.onload = () => { box.scrollTop = box.scrollHeight; };
      a.appendChild(i);
    } else { a.textContent = "📎 " + m.f.n; a.download = m.f.n; }
    d.appendChild(a);
  }

  if (m.t) { const tx = document.createElement("span"); tx.className = "txt"; tx.textContent = m.t; d.appendChild(tx); }
  const t = document.createElement("span"); t.className = "time"; t.textContent = timeText(m);
  d.appendChild(t);
  return d;
}
function add(m){
  const emp = box.querySelector(".empty-state");
  if (emp) emp.remove();
  box.appendChild(build(m));
  box.scrollTop = box.scrollHeight;
}

/* ---------- الاتصال عبر Socket.IO ---------- */
socket.on("connect", () => { socket.emit("get_rooms"); if (active !== null) socket.emit("open", {room: active}); });
socket.on("connect_error", () => { location.href = "/login"; });
socket.on("refresh", () => socket.emit("get_rooms"));
socket.on("online", ids => { online = ids; renderSide(); });
socket.on("rooms", d => {
  rooms = d.rooms || []; users = d.users || []; online = d.online || [];
  friends = d.friends || []; reqIn = d.requests_in || []; reqOut = d.requests_out || [];
  if (active === null || !rooms.find(r => r.id === active)) {
    active = rooms.length ? rooms[0].id : null;
    if (active !== null) openRoom(active);
  }
  renderSide();
});
socket.on("opened", d => openRoom(d.room));
socket.on("history", d => {
  if (d.room !== active) return;
  box.innerHTML = "";
  if (!d.msgs.length) {
    box.innerHTML = '<div class="empty-state">لا توجد رسائل بعد. ابدأ المحادثة الآن!</div>';
  } else {
    d.msgs.forEach(add);
  }
});
socket.on("message", m => {
  if (m.room !== active) { unread[m.room] = (unread[m.room] || 0) + 1; renderSide(); return; }
  const pend = m.cid ? box.querySelector('[data-cid="' + m.cid + '"]') : null;
  if (pend) pend.replaceWith(build(m)); else add(m);
});
socket.on("deleted", d => { if (d.room === active) removeMsg(d.id); });
socket.on("edited", d => { if (d.room === active) applyEdit(d.id, d.t); });
socket.on("once_seen", d => {
  document.querySelectorAll('.oncebtn[data-att="' + d.att + '"]').forEach(b => {
    if (d.uid === myId) setOnceState(b, "seen");
    else if (b.dataset.st === "mine" || b.dataset.st === "mine_seen") setOnceState(b, "mine_seen", d.by);
  });
});
socket.on("typing", d => {
  if (d.room !== active) return;
  $("typing").textContent = d.u + " يكتب الآن...";
  clearTimeout(tTimer); tTimer = setTimeout(() => { $("typing").textContent = ""; }, 3000);
});

/* ---------- إرسال النصوص والملصقات ---------- */
function sendSticker(stId){
  if (active === null) return;
  const cid = newCid();
  const m = {u: me, uid: myId, t: "", st_id: stId, ts: Math.floor(Date.now() / 1000), b: myBanner(), cid: cid, pending: true};
  if (replyTo) m.re = {id: replyTo.id, u: replyTo.u, t: replyTo.snip};
  add(m);
  socket.emit("send", {room: active, text: "", sticker: stId, reply: replyTo ? replyTo.id : null, cid: cid, banner: myBanner()});
  clearReply();
}

$("form").addEventListener("submit", e => {
  e.preventDefault();
  const i = $("text"), text_val = i.value.trim();
  if (editing) {
    if (text_val) { applyEdit(editing, text_val); socket.emit("edit", {room: active, id: editing, text: text_val}); }
    clearReply(); i.value = "";
    return;
  }
  if (text_val && active !== null) {
    const cid = newCid();
    const m = {u: me, uid: myId, t: text_val, ts: Math.floor(Date.now() / 1000), b: myBanner(), cid: cid, pending: true};
    if (replyTo) m.re = {id: replyTo.id, u: replyTo.u, t: replyTo.snip};
    add(m);
    socket.emit("send", {room: active, text: text_val, reply: replyTo ? replyTo.id : null, cid: cid, banner: myBanner()});
    setTimeout(() => {
      const el = box.querySelector('[data-cid="' + cid + '"]');
      if (el && el.classList.contains("pending")) el.classList.add("failed");
    }, 15000);
    clearReply();
  }
  i.value = "";
});
$("text").addEventListener("input", () => {
  const n = Date.now();
  if (active !== null && n - lastTyping > 2000) { lastTyping = n; socket.emit("typing", {room: active}); }
});

function openDrawer(){ $("drawer").classList.add("open"); $("back").classList.add("open"); }
function closeDrawer(){ $("drawer").classList.remove("open"); $("back").classList.remove("open"); }
$("menu").onclick = openDrawer; $("back").onclick = closeDrawer;

/* ---------- الصور والملفات ---------- */
function shrink(file, max, q){
  max = max || 1280; q = q || 0.8;
  return new Promise((res, rej) => {
    const img = new Image();
    img.onload = () => {
      const s = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement("canvas");
      c.width = Math.round(img.width * s); c.height = Math.round(img.height * s);
      c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(img.src);
      c.toBlob(b => b ? res(b) : rej(), "image/jpeg", q);
    };
    img.onerror = rej; img.src = URL.createObjectURL(file);
  });
}
$("clip").onclick = () => $("file").click();
$("file").addEventListener("change", async e => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f || active === null) return;
  let blob = f, name = f.name;
  if (f.type.indexOf("image/") === 0 && f.type !== "image/gif") {
    try { blob = await shrink(f); name = name.replace(/\.\w+$/, "") + ".jpg"; } catch (_) {}
  }
  await sendFile(blob, name);
});
async function sendFile(blob, name){
  if (active === null) return;
  if (blob.size > 2.5 * 1024 * 1024) { alert("الملف كبير، الحد الأقصى 2.5 ميجا"); return; }
  const ph = document.createElement("div");
  ph.className = "msg me pending"; ph.textContent = "⏳ جارٍ رفع وإرسال الملف...";
  box.appendChild(ph); box.scrollTop = box.scrollHeight;
  const fd = new FormData(); fd.append("room", active); fd.append("file", blob, name);
  fd.append("banner", myBanner());
  if (replyTo) fd.append("reply", replyTo.id);
  if (onceOn) fd.append("once", "1");
  setOnceMode(false); clearReply();
  try {
    const r = await fetch("/upload", {method: "POST", headers: {"X-CSRF": csrf}, body: fd});
    if (!r.ok) alert("فشل إرسال الملف");
  } catch (e) { alert("فشل إرسال الملف"); }
  ph.remove();
}

/* ---------- التسجيل الصوتي الحديث ---------- */
let rec = null, chunks = [], rStart = 0, rTimer = null, rCancel = false, rStream = null;
async function startRec(){
  if (active === null) { alert("اختر محادثة أولاً"); return; }
  if (rec) return;
  if (!navigator.mediaDevices || !window.MediaRecorder) { alert("متصفحك لا يدعم التسجيل الصوتي"); return; }
  try { rStream = await navigator.mediaDevices.getUserMedia({audio: true}); }
  catch (e) { alert("يرجى السماح للموقع باستخدام الميكروفون من إعدادات المتصفح"); return; }
  chunks = []; rCancel = false;
  const types = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg;codecs=opus"];
  const mt = types.find(t => MediaRecorder.isTypeSupported(t)) || "";
  const r = mt ? new MediaRecorder(rStream, {mimeType: mt}) : new MediaRecorder(rStream);
  rec = r;
  r.ondataavailable = e => { if (e.data.size) chunks.push(e.data); };
  r.onstop = async () => {
    clearInterval(rTimer); rStream.getTracks().forEach(t => t.stop());
    document.body.classList.remove("recording"); rec = null;
    if (rCancel || !chunks.length) return;
    const type = (r.mimeType || "audio/webm").split(";")[0];
    const ext = type.indexOf("mp4") >= 0 ? "m4a" : (type.indexOf("ogg") >= 0 ? "ogg" : "webm");
    await sendFile(new Blob(chunks, {type: type}), "voice." + ext);
  };
  r.start(); rStart = Date.now(); $("rt").textContent = "0:00" + (onceOn ? " 🔒" : "");
  document.body.classList.add("recording");
  rTimer = setInterval(() => {
    const s = Math.floor((Date.now() - rStart) / 1000);
    $("rt").textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0") + (onceOn ? " 🔒" : "");
    if (s >= 120) stopRec(false);
  }, 500);
}
function stopRec(cancel){
  if (rec && rec.state === "recording") { rCancel = cancel; rec.stop(); }
}
$("mic").onclick = startRec;
$("rcancel").onclick = () => stopRec(true);
$("rsend").onclick = () => stopRec(false);

/* ---------- المظهر والخلفية والبنر مع المعاينة المباشرة ---------- */
function applyTheme(){
  let t = "auto";
  try { t = localStorage.getItem("theme") || "auto"; } catch (e) {}
  const dark = t === "dark" || (t === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-dark", dark ? "1" : "0");
  document.querySelectorAll("#themes button").forEach(b => b.classList.toggle("on", b.dataset.t === t));
}
document.querySelectorAll("#themes button").forEach(b => {
  b.onclick = () => { try { localStorage.setItem("theme", b.dataset.t); } catch (e) {} applyTheme(); };
});
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);
applyTheme();

const WALLS = {
  none: "",
  green: "linear-gradient(160deg,#d4fc79,#96e6a1)",
  blue: "linear-gradient(160deg,#a1c4fd,#c2e9fb)",
  pink: "linear-gradient(160deg,#fbc2eb,#a6c1ee)",
  sunset: "linear-gradient(160deg,#ffecd2,#fcb69f)",
  night: "linear-gradient(160deg,#0f2027,#2c5364)",
  dots: "radial-gradient(rgba(127,127,127,.35) 1px, transparent 1px) 0 0 / 18px 18px, var(--bg)"
};
function getWall(){
  try { return JSON.parse(localStorage.getItem("wall") || "null") || {k: "none"}; }
  catch (e) { return {k: "none"}; }
}
function wallCss(w){
  if (w.k === "img" && w.v) return 'url("' + w.v + '") center / cover no-repeat';
  const m = /^p(\d+)$/.exec(w.k || "");
  if (m) return 'url("/wall/' + m[1] + '") center / cover no-repeat';
  return WALLS[w.k] || "";
}
function applyWall(){
  const w = getWall();
  const css = wallCss(w);
  box.style.background = css;
  $("wallpreview").style.background = css || "var(--bg)";
  document.querySelectorAll("#walls .sw").forEach(s => s.classList.toggle("on", s.dataset.k === w.k));
}
Object.keys(WALLS).forEach(k => {
  const s = document.createElement("div");
  s.className = "sw"; s.dataset.k = k; s.style.background = WALLS[k] || "var(--bg)";
  s.onclick = () => { try { localStorage.setItem("wall", JSON.stringify({k: k})); } catch (e) {} applyWall(); };
  $("walls").appendChild(s);
});
for (let n = 1; n <= 6; n++) {
  const s = document.createElement("div");
  s.className = "sw img"; s.dataset.k = "p" + n;
  s.style.background = 'url("/wall/t/' + n + '") center / cover';
  s.onclick = () => { try { localStorage.setItem("wall", JSON.stringify({k: "p" + n})); } catch (e) {} applyWall(); };
  $("walls").appendChild(s);
}
$("wallpick").onclick = () => $("wallfile").click();
$("wallfile").addEventListener("change", async e => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  try {
    const b = await shrink(f, 1080, 0.72);
    const rd = new FileReader();
    rd.onload = () => {
      try { localStorage.setItem("wall", JSON.stringify({k: "img", v: rd.result})); }
      catch (er) { alert("تعذر حفظ الصورة"); }
      applyWall();
    };
    rd.readAsDataURL(b);
  } catch (er) { alert("تعذر قراءة الصورة"); }
});
$("wallreset").onclick = () => { try { localStorage.removeItem("wall"); } catch (e) {} applyWall(); };
applyWall();

const BN = [[0, "الفقاعة الافتراضية"], [1, "نيون بنفسجي متوهج"], [2, "سماوي داكن مضيء"], [3, "ملكي أرجواني"], [4, "أزرق كلاسيكي"], [5, "ذهبي مشرق"]];
function renderBanners(){
  const w = $("banners"); w.innerHTML = "";
  const cur = myBanner();
  BN.forEach(p => {
    const d = document.createElement("div");
    d.className = "msg me prev" + (p[0] ? " bn b" + p[0] : "") + (cur === p[0] ? " on" : "");
    d.textContent = "معاينة: " + p[1];
    d.onclick = () => { try { localStorage.setItem("banner", String(p[0])); } catch (e) {} renderBanners(); };
    w.appendChild(d);
  });
}
renderBanners();
</script></body></html>"""


ADMIN = HEAD + """
<header>
  <span>⚙️ لوحة الإدارة المستقلة ({{ "مالك الموقع" if me.role == "owner" else "مدير" }})</span>
  <span><a href="/">💬 العودة للدردشة</a><a href="/logout">خروج</a></span>
</header>
<div class="wrap">
{% if msg %}<p class="ok">{{ msg }}</p>{% endif %}

{% if me.role == "owner" %}
<div class="box">
  <h3 style="margin-top:0">➕ إضافة حساب جديد (للمالك فقط)</h3>
  <form method="post" action="/admin/add">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">
      <input name="username" placeholder="اسم المستخدم (3-30 حرف)" required>
      <input name="password" placeholder="كلمة المرور (8 أحرف على الأقل)" required>
      <select name="role">
        <option value="user">مستخدم عادي (User)</option>
        <option value="admin">مدير (Admin / Manager)</option>
      </select>
    </div>
    <button style="margin-top:8px">إضافة الحساب</button>
  </form>
</div>

<div class="box">
  <h3 style="margin-top:0">👥 إدارة المستخدمين والصلاحيات والإخفاء (للمالك فقط)</h3>
  <p style="font-size:13px;color:var(--muted)">المستخدم المخفي لا يظهر في قوائم الأعضاء أو المتصلين للمستخدمين العاديين، ويظهر هنا للمالك فقط مع بقاء جميع محادثاته وبياناته محفوظة.</p>
  <div class="scroll">
    <table>
      <tr><th>الاسم</th><th>ID</th><th>المستوى</th><th>الحالة</th><th>تاريخ الإنشاء</th><th>إجراءات المالك</th></tr>
      {% for u in users %}
      <tr>
        <td><b>{{ u.username }}</b></td>
        <td><span class="id-tag">#{{ u.uid_code }}</span></td>
        <td>
          <span class="role-badge role-{{ u.role }}">
            {{ "مالك الموقع (Owner)" if u.role == "owner" else ("مدير (Admin)" if u.role == "admin" else "مستخدم (User)") }}
          </span>
        </td>
        <td>{{ "👁️‍🗨️ مخفي عن العامة" if u.is_hidden else "🟢 ظاهر" }}</td>
        <td>{{ u.created_at.strftime('%Y-%m-%d') }}</td>
        <td style="display:flex;gap:6px;align-items:center">
          {% if u.role != "owner" %}
          <form method="post" action="/admin/role/{{ u.id }}" style="display:inline">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <input type="hidden" name="role" value="{{ 'user' if u.role == 'admin' else 'admin' }}">
            <button class="sec">{{ "تحويل لمستخدم" if u.role == "admin" else "ترقية لمدير" }}</button>
          </form>
          <form method="post" action="/admin/hide/{{ u.id }}" style="display:inline">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <button class="sec">{{ "إظهار الحساب" if u.is_hidden else "إخفاء الحساب" }}</button>
          </form>
          <form method="post" action="/admin/delete/{{ u.id }}" style="display:inline" onsubmit="return confirm('حذف حساب المستخدم من الدخول؟ (ستبقى الرسائل القديمة محفوظة)')">
            <input type="hidden" name="csrf" value="{{ csrf_token() }}">
            <button class="del">حذف</button>
          </form>
          {% else %}
          <span style="font-size:12px;color:var(--muted)">حساب المالك الأساسي</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
</div>
{% endif %}

<div class="box">
  <h3 style="margin-top:0">🗂️ إدارة المجموعات والغرف المغلقة</h3>
  <form method="post" action="/admin/room/add" style="margin-bottom:14px">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <div style="display:grid;grid-template-columns:2fr 1fr;gap:10px">
      <input name="name" placeholder="اسم المجموعة أو الغرفة" required>
      <select name="kind">
        <option value="group">مجموعة (Group)</option>
        <option value="private">غرفة مغلقة خاصة (Private Room)</option>
      </select>
    </div>
    <div style="margin:8px 0">
      {% for u in visible_users %}
      <label class="chk"><input type="checkbox" name="members" value="{{ u.id }}">{{ u.username }} (#{{ u.uid_code }})</label>
      {% endfor %}
    </div>
    <button>إنشاء</button>
  </form>

  {% for g in groups %}
  <details>
    <summary>
      {{ "🔐" if g.room.kind == "private" else "🗂️" }} {{ g.room.name }}
      ({{ g.members|length }} عضو) — النوع: {{ "غرفة مغلقة" if g.room.kind == "private" else "مجموعة" }}
    </summary>
    <form method="post" action="/admin/room/{{ g.room.id }}/members" style="margin-top:8px">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <div>
        {% for u in visible_users %}
        <label class="chk">
          <input type="checkbox" name="members" value="{{ u.id }}" {{ "checked" if u.id in g.members }}>
          {{ u.username }} (#{{ u.uid_code }})
        </label>
        {% endfor %}
      </div>
      <button style="margin-top:8px">حفظ قائمة الأعضاء</button>
    </form>
    {% if me.role == "owner" %}
    <form method="post" action="/admin/room/{{ g.room.id }}/delete" style="margin-top:8px" onsubmit="return confirm('تأكيد حذف هذه الغرفة؟')">
      <input type="hidden" name="csrf" value="{{ csrf_token() }}">
      <button class="del">حذف الغرفة نهائياً</button>
    </form>
    {% endif %}
  </details>
  {% endfor %}
</div>

{% if me.role == "owner" %}
<div class="box">
  <h3 style="margin-top:0">🌐 سجل عمليات تسجيل الدخول (آخر 100 عملية - خاص بالمالك)</h3>
  <div class="scroll">
    <table>
      <tr><th>الاسم</th><th>عنوان IP</th><th>الحالة</th><th>التوقيت (UTC)</th></tr>
      {% for l in logs %}
      <tr>
        <td>{{ l.username }}</td>
        <td>{{ l.ip }}</td>
        <td>{{ "✅ ناجح" if l.success else "❌ فاشل" }}</td>
        <td>{{ l.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</div>
{% endif %}
</div></body></html>"""


# ---------------------------------------------------------------
# المسارات (Routes)
# ---------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        name = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        ip = request.remote_addr or "?"
        since = now() - timedelta(minutes=10)
        fails = LoginLog.query.filter(LoginLog.ip == ip, LoginLog.success.is_(False),
                                      LoginLog.created_at > since).count()
        if fails >= 5:
            error = "محاولات كثيرة خاطئة، انتظر 10 دقائق"
        else:
            user = User.query.filter_by(username=name).first()
            ok = bool(user and check_password_hash(user.password_hash, pw))
            db.session.add(LoginLog(username=name[:40], ip=ip[:64], success=ok))
            db.session.commit()
            if ok:
                session.clear()
                session["uid"] = user.id
                session.permanent = True
                return redirect(url_for("chat"))
            error = "اسم المستخدم أو كلمة المرور غير صحيحة"
    return render_template_string(LOGIN, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def chat():
    u = current_user()
    return render_template_string(
        CHAT,
        username=u.username,
        uid=u.id,
        uid_code=u.uid_code,
        role=u.role,
        is_staff=(u.role in ("owner", "admin")),
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    check_csrf_header()
    user = current_user()
    rid = request.form.get("room", type=int)
    f = request.files.get("file")
    if not f or not is_member(rid, user.id):
        abort(400)
    raw = f.read()
    if not raw or len(raw) > MAX_FILE:
        abort(413)
    mime = f.mimetype if f.mimetype in INLINE_TYPES else "application/octet-stream"
    once = request.form.get("once") == "1" and mime in INLINE_TYPES
    name = (f.filename or "file")[-80:]
    meta = {"n": name, "m": mime}
    fileinfo = {"n": name, "m": mime}
    if once:
        meta.update({"once": 1, "by": user.id, "seen": [], "gone": 0})
        fileinfo = {"n": "", "m": mime, "o": 1}
    att = Attachment(room_id=rid,
                     meta=encrypt(json.dumps(meta, ensure_ascii=False)),
                     data=enc_bytes(raw))
    db.session.add(att)
    db.session.flush()
    fileinfo["id"] = att.id
    db.session.commit()
    post(rid, user, "", fileinfo, request.form.get("reply", type=int),
         None, request.form.get("banner", type=int))
    return {"ok": True}


@app.route("/file/<int:fid>")
@login_required
def get_file(fid):
    att = db.session.get(Attachment, fid)
    if not att or not att.data or not is_member(att.room_id, current_user().id):
        abort(404)
    meta = json.loads(decrypt(att.meta))
    if meta.get("once"):
        abort(403)
    resp = send_file(io.BytesIO(dec_bytes(att.data)), mimetype=meta["m"],
                     as_attachment=meta["m"] not in INLINE_TYPES,
                     download_name=meta["n"], conditional=True, max_age=3600)
    resp.cache_control.public = False
    resp.cache_control.private = True
    return resp


@app.route("/once/<int:fid>", methods=["POST"])
@login_required
def once_file(fid):
    check_csrf_header()
    user = current_user()
    att = db.session.get(Attachment, fid)
    if not att or not is_member(att.room_id, user.id):
        abort(404)
    meta = json.loads(decrypt(att.meta))
    if not meta.get("once") or meta.get("by") == user.id:
        abort(403)
    seen = meta.setdefault("seen", [])
    if user.id in seen or meta.get("gone") or not att.data:
        abort(410)
    data = dec_bytes(att.data)
    seen.append(user.id)
    others = set(MEMBERS.get(att.room_id) or ()) - {meta.get("by")}
    if others <= set(seen):
        att.data = ""
        meta["gone"] = 1
    att.meta = encrypt(json.dumps(meta, ensure_ascii=False))
    db.session.commit()
    emit_to_room(att.room_id, "once_seen",
                 {"room": att.room_id, "att": fid, "by": user.username, "uid": user.id})
    resp = Response(data, mimetype=meta["m"])
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------
# مسارات لوحة الإدارة والصلاحيات الثلاث
# ---------------------------------------------------------------
@app.route("/admin")
@staff_required
def admin():
    me_user = current_user()
    all_users = User.query.order_by(User.id).all()
    if me_user.role == "owner":
        visible_users = all_users
    else:
        visible_users = [u for u in all_users if not u.is_hidden]

    logs = LoginLog.query.order_by(LoginLog.id.desc()).limit(100).all() if me_user.role == "owner" else []
    groups = []
    for r in Room.query.filter(Room.kind.in_(["group", "private"])).order_by(Room.id):
        r_dict = {"id": r.id, "name": r.name, "kind": r.kind, "created_by": r.created_by}
        if can_manage_room(me_user, r_dict):
            ids = {m.user_id for m in Member.query.filter_by(room_id=r.id)}
            groups.append({"room": r, "members": ids})

    return render_template_string(
        ADMIN,
        me=me_user,
        users=all_users,
        visible_users=visible_users,
        logs=logs,
        groups=groups,
        msg=request.args.get("msg"),
    )


@app.route("/admin/add", methods=["POST"])
@owner_required
def admin_add():
    check_csrf()
    name = request.form.get("username", "").strip()
    pw = request.form.get("password", "")
    role = request.form.get("role", "user")
    if role not in ("user", "admin"):
        role = "user"
    if not (3 <= len(name) <= 30) or len(pw) < 8:
        return redirect(url_for("admin", msg="الاسم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل"))
    if User.query.filter_by(username=name).first():
        return redirect(url_for("admin", msg="الاسم موجود مسبقاً"))
    u = User(
        username=name,
        password_hash=generate_password_hash(pw),
        role=role,
        is_admin=(role == "admin"),
        uid_code=generate_unique_uid_code(),
    )
    db.session.add(u)
    db.session.commit()
    reload_cache()
    notify_all()
    return redirect(url_for("admin", msg=f"تمت إضافة الحساب ({name}) بنجاح"))


@app.route("/admin/role/<int:uid>", methods=["POST"])
@owner_required
def admin_change_role(uid):
    check_csrf()
    u = db.session.get(User, uid)
    new_role = request.form.get("role", "user")
    if u and u.role != "owner" and new_role in ("user", "admin"):
        u.role = new_role
        u.is_admin = (new_role == "admin")
        db.session.commit()
        reload_cache()
        notify_all()
        return redirect(url_for("admin", msg=f"تم تحديث صلاحية {u.username}"))
    return redirect(url_for("admin"))


@app.route("/admin/hide/<int:uid>", methods=["POST"])
@owner_required
def admin_toggle_hide(uid):
    check_csrf()
    u = db.session.get(User, uid)
    if u and u.role != "owner":
        u.is_hidden = not bool(u.is_hidden)
        db.session.commit()
        reload_cache()
        notify_all()
        state = "مخفي الآن" if u.is_hidden else "ظاهر الآن"
        return redirect(url_for("admin", msg=f"حساب {u.username} أصبح {state}"))
    return redirect(url_for("admin"))


@app.route("/admin/delete/<int:uid>", methods=["POST"])
@owner_required
def admin_delete(uid):
    check_csrf()
    u = db.session.get(User, uid)
    if u and u.role != "owner":
        # نحذف عضويته وصداقاته مع الحفاظ على رسائله ومحادثاته السابقة في قاعدة البيانات
        Friendship.query.filter((Friendship.sender_id == uid) | (Friendship.receiver_id == uid)).delete()
        Member.query.filter_by(user_id=uid).delete()
        db.session.delete(u)
        db.session.commit()
        reload_cache()
        for sid, user_id in list(online.items()):
            if user_id == uid:
                socketio.server.disconnect(sid)
                online.pop(sid, None)
        notify_all()
        return redirect(url_for("admin", msg="تم حذف الحساب مع الاحتفاظ بسجل الرسائل"))
    return redirect(url_for("admin"))


@app.route("/admin/room/add", methods=["POST"])
@staff_required
def admin_room_add():
    check_csrf()
    me_user = current_user()
    name = request.form.get("name", "").strip()[:60]
    kind = request.form.get("kind", "group")
    if kind not in ("group", "private"):
        kind = "group"
    if not name:
        return redirect(url_for("admin", msg="اكتب اسم الغرفة أو المجموعة"))
    r = Room(name=name, kind=kind, created_by=me_user.id)
    db.session.add(r)
    db.session.flush()
    mems = set(request.form.getlist("members", type=int))
    mems.add(me_user.id)
    set_members(r.id, mems)
    db.session.commit()
    reload_cache()
    notify_all()
    return redirect(url_for("admin", msg="تم إنشاء الغرفة بنجاح"))


@app.route("/admin/room/<int:rid>/members", methods=["POST"])
@staff_required
def admin_room_members(rid):
    check_csrf()
    me_user = current_user()
    r = db.session.get(Room, rid)
    if r and r.kind in ("group", "private"):
        r_dict = {"id": r.id, "name": r.name, "kind": r.kind, "created_by": r.created_by}
        if can_manage_room(me_user, r_dict):
            mems = set(request.form.getlist("members", type=int))
            if r.created_by:
                mems.add(r.created_by)
            # الحفاظ على الأعضاء المخفيين إن كان المعدّل مديراً وليس المالك
            if me_user.role != "owner":
                current_hidden = {uid for uid in (MEMBERS.get(rid) or ()) if USERS.get(uid, {}).get("is_hidden")}
                mems |= current_hidden
            set_members(rid, mems)
            db.session.commit()
            reload_cache()
            notify_all()
            return redirect(url_for("admin", msg="تم تحديث الأعضاء"))
    return redirect(url_for("admin"))


@app.route("/admin/room/<int:rid>/delete", methods=["POST"])
@owner_required
def admin_room_delete(rid):
    check_csrf()
    r = db.session.get(Room, rid)
    if r and r.kind in ("group", "private"):
        ChatMessage.query.filter_by(room_id=rid).delete()
        Attachment.query.filter_by(room_id=rid).delete()
        Member.query.filter_by(room_id=rid).delete()
        Room.query.filter_by(id=rid).delete()
        ROOM_MSGS.pop(rid, None)
        db.session.commit()
        reload_cache()
        notify_all()
    return redirect(url_for("admin", msg="تم حذف الغرفة بناءً على أمر المالك"))


# ---------------------------------------------------------------
# أحداث الدردشة والغرف والأصدقاء (WebSocket)
# ---------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    user = current_user()
    if not user:
        return False
    online[request.sid] = user.id
    broadcast_online()


@socketio.on("disconnect")
def on_disconnect():
    online.pop(request.sid, None)
    broadcast_online()


@socketio.on("get_rooms")
def on_get_rooms():
    ctx = sock_user()
    if not ctx:
        disconnect()
        return
    emit("rooms", rooms_payload(ctx.id))


@socketio.on("open")
def on_open(data):
    ctx = sock_user()
    if not ctx:
        disconnect()
        return
    rid = to_int((data or {}).get("room"))
    if not is_member(rid, ctx.id):
        return
    msgs = [dict(m) for m in room_msgs(rid)]
    once_status(msgs, ctx.id)
    emit("history", {"room": rid, "msgs": msgs})


@socketio.on("send")
def on_send(data):
    ctx = sock_user()
    if not ctx:
        disconnect()
        return
    data = data or {}
    rid = to_int(data.get("room"))
    if not is_member(rid, ctx.id):
        return
    sticker = str(data.get("sticker", "")).strip()
    text_val = str(data.get("text", "")).strip()[:1000]
    if not text_val and sticker not in VALID_STICKERS:
        return
    cid = str(data.get("cid", ""))[:40] or None
    post(rid, ctx, text_val, None, to_int(data.get("reply")), cid, to_int(data.get("banner")),
         sticker if sticker in VALID_STICKERS else None)


@socketio.on("edit")
def on_edit(data):
    ctx = sock_user()
    if not ctx:
        disconnect()
        return
    data = data or {}
    rid = to_int(data.get("room"))
    mid = to_int(data.get("id"))
    text_val = str(data.get("text", "")).strip()[:1000]
    if not mid or not text_val or not is_member(rid, ctx.id):
        return
    m = find_msg(rid, mid)
    if not m or m.get("u") != ctx.username or not m.get("t"):
        return
    with LOCK:
        m["t"] = text_val
        m["ed"] = 1
    emit_to_room(rid, "edited", {"room": rid, "id": mid, "t": text_val})
    persist_q.put(("edit", rid, dict(m)))


@socketio.on("delete")
def on_delete(data):
    ctx = sock_user()
    if not ctx:
        disconnect()
        return
    data = data or {}
    rid = to_int(data.get("room"))
    mid = to_int(data.get("id"))
    if not mid or not is_member(rid, ctx.id):
        return
    m = find_msg(rid, mid)
    if not m or not (ctx.role in ("owner", "admin") or m.get("u") == ctx.username):
        return
    with LOCK:
        lst = ROOM_MSGS.get(rid)
        if lst is not None:
            lst[:] = [x for x in lst if x.get("id") != mid]
    fid = to_int((m.get("f") or {}).get("id"))
    emit_to_room(rid, "deleted", {"room": rid, "id": mid})
    persist_q.put(("delete", rid, mid, fid))


@socketio.on("typing")
def on_typing(data):
    ctx = sock_user()
    if not ctx:
        return
    rid = to_int((data or {}).get("room"))
    if is_member(rid, ctx.id):
        emit_to_room(rid, "typing", {"room": rid, "u": ctx.username}, skip_sid=request.sid)


@socketio.on("dm")
def on_dm(data):
    ctx = sock_user()
    if not ctx:
        disconnect()
        return
    other = to_int((data or {}).get("user"))
    if not other or other == ctx.id or other not in USERS:
        return
    # منع غير المالك من بدء محادثة جديدة مع مستخدم مخفي إلا إذا كانت المحادثة موجودة مسبقاً
    target = USERS[other]
    existing_dm = any(r["kind"] == "dm" and MEMBERS.get(rid) == {ctx.id, other} for rid, r in ROOMS.items())
    if target.get("is_hidden") and ctx.role != "owner" and not existing_dm:
        return
    rid = get_dm(ctx.id, other)
    emit("rooms", rooms_payload(ctx.id))
    emit("opened", {"room": rid})
    for sid, uid in list(online.items()):
        if uid == other:
            socketio.emit("refresh", to=sid)


@socketio.on("search_id")
def on_search_id(data):
    ctx = sock_user()
    if not ctx:
        return
    code = str((data or {}).get("uid_code", "")).strip()
    target = next((u for u in USERS.values() if u["uid_code"] == code), None)
    if not target or not can_see_user(ctx, target):
        emit("search_result", {"found": False})
        return
    is_fr = any(
        f["status"] == "accepted" and {f["sender"], f["receiver"]} == {ctx.id, target["id"]}
        for f in FRIENDS
    )
    is_pend = any(
        f["status"] == "pending" and {f["sender"], f["receiver"]} == {ctx.id, target["id"]}
        for f in FRIENDS
    )
    emit("search_result", {
        "found": True,
        "id": target["id"],
        "username": target["username"],
        "uid_code": target["uid_code"],
        "is_friend": is_fr,
        "pending": is_pend,
    })


@socketio.on("friend_request")
def on_friend_request(data):
    ctx = sock_user()
    if not ctx:
        return
    tid = to_int((data or {}).get("target_id"))
    target = USERS.get(tid)
    if not target or tid == ctx.id or not can_see_user(ctx, target):
        return
    exists = Friendship.query.filter(
        ((Friendship.sender_id == ctx.id) & (Friendship.receiver_id == tid)) |
        ((Friendship.sender_id == tid) & (Friendship.receiver_id == ctx.id))
    ).first()
    if not exists:
        db.session.add(Friendship(sender_id=ctx.id, receiver_id=tid, status="pending"))
        db.session.commit()
        reload_cache()
        notify_all()


@socketio.on("friend_respond")
def on_friend_respond(data):
    ctx = sock_user()
    if not ctx:
        return
    req_id = to_int((data or {}).get("req_id"))
    action = (data or {}).get("action")
    fr = db.session.get(Friendship, req_id)
    if not fr or fr.receiver_id != ctx.id:
        return
    if action == "accept":
        fr.status = "accepted"
        db.session.commit()
        get_dm(fr.sender_id, fr.receiver_id)
    else:
        db.session.delete(fr)
        db.session.commit()
    reload_cache()
    notify_all()


@socketio.on("create_private_room")
def on_create_private_room(data):
    ctx = sock_user()
    if not ctx:
        return
    name = str((data or {}).get("name", "")).strip()[:50]
    raw_members = (data or {}).get("members") or []
    if not name:
        return
    mems = {ctx.id}
    for m in raw_members:
        mid = to_int(m)
        if mid and mid in USERS and can_see_user(ctx, USERS[mid]):
            mems.add(mid)
    r = Room(name=name, kind="private", created_by=ctx.id)
    db.session.add(r)
    db.session.flush()
    set_members(r.id, mems)
    db.session.commit()
    reload_cache()
    notify_all()
    emit("opened", {"room": r.id})


@socketio.on("update_room_members")
def on_update_room_members(data):
    ctx = sock_user()
    if not ctx:
        return
    rid = to_int((data or {}).get("room"))
    r = ROOMS.get(rid)
    if not r or not can_manage_room(ctx, r):
        return
    raw_members = (data or {}).get("members") or []
    mems = {ctx.id}
    if r.get("created_by"):
        mems.add(r["created_by"])
    for m in raw_members:
        mid = to_int(m)
        if mid and mid in USERS and can_see_user(ctx, USERS[mid]):
            mems.add(mid)
    if ctx.role != "owner":
        current_hidden = {uid for uid in (MEMBERS.get(rid) or ()) if USERS.get(uid, {}).get("is_hidden")}
        mems |= current_hidden
    set_members(rid, mems)
    db.session.commit()
    reload_cache()
    notify_all()


# ---------------------------------------------------------------
# صور الخلفيات المدمجة (SVG سريعة وعالية الدقة)
# ---------------------------------------------------------------
WALL_SVGS = {
    1: '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="700"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0f2027"/><stop offset="50%" stop-color="#203a43"/><stop offset="100%" stop-color="#2c5364"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#g)"/><circle cx="80" cy="120" r="50" fill="#ffffff10"/><circle cx="320" cy="480" r="90" fill="#ffffff08"/></svg>',
    2: '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="700"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1a1c2e"/><stop offset="100%" stop-color="#3b1d5e"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#g)"/><circle cx="200" cy="350" r="140" fill="#a855f715"/></svg>',
    3: '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="700"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#064e3b"/><stop offset="100%" stop-color="#022c22"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#g)"/><path d="M0 500 Q200 420 400 520 L400 700 L0 700 Z" fill="#10b98118"/></svg>',
    4: '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="700"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#1e1b4b"/><stop offset="100%" stop-color="#311042"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#g)"/></svg>',
    5: '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="700"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#27272a"/><stop offset="100%" stop-color="#09090b"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#g)"/></svg>',
    6: '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="700"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#134e4a"/><stop offset="100%" stop-color="#0f172a"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#g)"/></svg>',
}


@app.route("/wall/<int:n>")
@app.route("/wall/t/<int:n>")
def wall_img(n):
    svg = WALL_SVGS.get(n)
    if not svg:
        abort(404)
    resp = Response(svg, mimetype="image/svg+xml")
    resp.cache_control.max_age = 86400
    return resp


# ---------------------------------------------------------------
# تهيئة التطبيق عند التشغيل
# ---------------------------------------------------------------
with app.app_context():
    migrate_and_init_db()
    sync_msg_id()
    reload_cache()

threading.Thread(target=persist_worker, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))