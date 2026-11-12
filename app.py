import io
import os
import json
import time
import base64
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, render_template_string, request, session,
                   redirect, url_for, abort, send_file)
from flask_socketio import SocketIO, emit, disconnect
from flask_sqlalchemy import SQLAlchemy
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


def encrypt(text: str) -> str:
    return enc_bytes(text.encode("utf-8"))


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
    created_at = db.Column(db.DateTime, default=now)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), default="")
    kind = db.Column(db.String(10), nullable=False)  # general / group / dm
    created_at = db.Column(db.DateTime, default=now)


class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, index=True, nullable=False)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    __table_args__ = (db.UniqueConstraint("room_id", "user_id"),)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, index=True, nullable=False)
    blob = db.Column(db.Text, nullable=False)  # الرسالة مشفرة بثلاث طبقات
    created_at = db.Column(db.DateTime, default=now)


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, index=True, nullable=False)
    meta = db.Column(db.Text, nullable=False)  # الاسم والنوع (مشفر)
    data = db.Column(db.Text, nullable=False)  # محتوى الملف (مشفر)
    created_at = db.Column(db.DateTime, default=now)


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40))
    ip = db.Column(db.String(64))
    success = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=now)


def ensure_owner():
    name = os.environ.get("ADMIN_USERNAME", "").strip()
    pw = os.environ.get("ADMIN_PASSWORD", "")
    if not name or not pw:
        raise RuntimeError("ADMIN_USERNAME و ADMIN_PASSWORD مطلوبين")
    u = User.query.filter_by(username=name).first()
    if not u:
        u = User(username=name)
        db.session.add(u)
    u.password_hash = generate_password_hash(pw)
    u.is_admin = True
    db.session.commit()


def ensure_general():
    g = Room.query.filter_by(kind="general").first()
    if not g:
        g = Room(name="عام", kind="general")
        db.session.add(g)
        db.session.commit()
    have = {m.user_id for m in Member.query.filter_by(room_id=g.id)}
    for u in User.query.all():
        if u.id not in have:
            db.session.add(Member(room_id=g.id, user_id=u.id))
    db.session.commit()


with app.app_context():
    db.create_all()
    ensure_owner()
    ensure_general()


# ---------------------------------------------------------------
# أدوات مساعدة
# ---------------------------------------------------------------
def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            session.clear()
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not u.is_admin:
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


def is_member(rid, uid):
    if rid is None:
        return False
    return Member.query.filter_by(room_id=rid, user_id=uid).first() is not None


def rooms_payload(uid):
    out = []
    for m in Member.query.filter_by(user_id=uid):
        r = db.session.get(Room, m.room_id)
        if not r:
            continue
        if r.kind == "dm":
            other = Member.query.filter(Member.room_id == r.id, Member.user_id != uid).first()
            out.append({"id": r.id, "name": "", "kind": "dm",
                        "with": other.user_id if other else None})
        else:
            out.append({"id": r.id, "name": r.name, "kind": r.kind})
    users = [{"id": u.id, "username": u.username}
             for u in User.query.order_by(User.username)]
    return {"rooms": out, "users": users, "online": sorted(set(online.values()))}


def emit_to_room(rid, event, data, skip_sid=None):
    ids = {m.user_id for m in Member.query.filter_by(room_id=rid)}
    for sid, uid in list(online.items()):
        if uid in ids and sid != skip_sid:
            socketio.emit(event, data, to=sid)


def notify_all():
    socketio.emit("refresh")
    socketio.emit("online", sorted(set(online.values())))


def get_dm(a, b):
    ra = {m.room_id for m in Member.query.filter_by(user_id=a)}
    rb = {m.room_id for m in Member.query.filter_by(user_id=b)}
    for rid in ra & rb:
        r = db.session.get(Room, rid)
        if r and r.kind == "dm":
            return r
    r = Room(name="", kind="dm")
    db.session.add(r)
    db.session.flush()
    db.session.add(Member(room_id=r.id, user_id=a))
    db.session.add(Member(room_id=r.id, user_id=b))
    db.session.commit()
    return r


def purge_room(rid):
    ChatMessage.query.filter_by(room_id=rid).delete()
    Attachment.query.filter_by(room_id=rid).delete()
    Member.query.filter_by(room_id=rid).delete()
    Room.query.filter_by(id=rid).delete()


def set_members(rid, ids):
    valid = {u.id for u in User.query.filter(User.id.in_(ids))} if ids else set()
    Member.query.filter_by(room_id=rid).delete()
    for uid in valid:
        db.session.add(Member(room_id=rid, user_id=uid))


def quote_of(rid, mid):
    row = db.session.get(ChatMessage, mid) if mid else None
    if not row or row.room_id != rid:
        return None
    try:
        m = json.loads(decrypt(row.blob))
    except Exception:
        return None
    f = m.get("f")
    if m.get("t"):
        snippet = m["t"][:80]
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
    return {"id": row.id, "u": m.get("u", "?"), "t": snippet}


def post(rid, user, text, fileinfo, reply_id=None):
    msg = {"u": user.username, "t": text, "ts": int(time.time())}
    if fileinfo:
        msg["f"] = fileinfo
    quote = quote_of(rid, reply_id)
    if quote:
        msg["re"] = quote
    row = ChatMessage(room_id=rid, blob=encrypt(json.dumps(msg, ensure_ascii=False)))
    db.session.add(row)
    db.session.commit()
    emit_to_room(rid, "message", dict(msg, room=rid, id=row.id))


# ---------------------------------------------------------------
# القوالب
# ---------------------------------------------------------------
HEAD = """<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>دردشة</title>
<script>
(function(){try{var t=localStorage.getItem("theme")||"auto";var d=t==="dark"||(t==="auto"&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.setAttribute("data-dark",d?"1":"0");}catch(e){}})();
</script>
<style>
:root{--bg:#ece5dd;--card:#fff;--text:#111;--muted:#555;--head:#075e54;--in:#fff;--out:#dcf8c6;--bar:#f0f0f0;--line:#e3e3e3;--field:#fff;--link:#0b57d0;--accent:#075e54;--sub:#f7f7f7}
html[data-dark="1"]{--bg:#0b141a;--card:#1f2c33;--text:#e9edef;--muted:#8696a0;--head:#1f2c33;--in:#202c33;--out:#005c4b;--bar:#1f2c33;--line:#2a3942;--field:#2a3942;--link:#53bdeb;--accent:#00a884;--sub:#111b21;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--text)}
header{background:var(--head);color:#fff;padding:12px 14px;display:flex;justify-content:space-between;align-items:center;font-weight:bold}
header a{color:#fff;text-decoration:none;margin-inline-start:12px;font-weight:normal}
.card{max-width:420px;margin:40px auto;background:var(--card);padding:24px;border-radius:14px}
.wrap{max-width:900px;margin:14px auto;padding:0 10px}
.box{background:var(--card);padding:14px;border-radius:12px;margin-bottom:14px}
input{width:100%;padding:12px;margin:6px 0;border:1px solid var(--line);border-radius:10px;font-size:16px;background:var(--field);color:var(--text)}
input[type=checkbox]{width:auto;margin:0 6px}
.chk{display:block;padding:4px 0}
button{padding:10px 18px;border:none;border-radius:10px;background:var(--accent);color:#fff;font-size:16px}
button.del{background:#c0392b;padding:6px 12px;font-size:14px}
.err{color:#e74c3c}.ok{color:#27ae60}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{padding:6px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
.scroll{overflow-x:auto}
details{border-top:1px solid var(--line);padding:8px 0}
summary{font-weight:bold;cursor:pointer}
</style></head><body>"""

LOGIN = HEAD + """
<div class="card">
<h2>🔐 تسجيل الدخول</h2>
<form method="post">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
<input name="username" placeholder="اسم المستخدم" autocomplete="username" required>
<input name="password" type="password" placeholder="كلمة المرور" autocomplete="current-password" required>
<button style="width:100%;margin-top:8px">دخول</button>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
</form></div></body></html>"""

CHAT = HEAD + r"""
<style>
body{display:flex;flex-direction:column;height:100dvh;overflow:hidden}
.ic{background:transparent;padding:0 8px;font-size:20px;color:inherit}
#sub{background:var(--sub);font-size:12px;color:var(--muted);padding:4px 12px;min-height:24px}
#typing{color:var(--accent);font-weight:bold}
#messages{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:6px}
.msg{max-width:82%;padding:8px 12px;border-radius:12px;background:var(--in);color:var(--text);word-wrap:break-word;box-shadow:0 1px 1px rgba(0,0,0,.15)}
.msg.me{align-self:flex-start;background:var(--out)}
.msg.flash{outline:2px solid var(--accent)}
.msg .name{font-size:12px;color:var(--accent);font-weight:bold;display:block}
.msg .top{display:flex;justify-content:space-between;align-items:center;gap:10px}
.dots{background:transparent;color:var(--muted);padding:0 6px;font-size:22px;line-height:1;border-radius:6px}
.msg .time{font-size:10px;color:var(--muted);display:block;text-align:left}
.msg img{max-width:100%;border-radius:8px;display:block;margin:4px 0}
.msg a{color:var(--link)}
.msg audio{width:230px;max-width:100%;display:block;margin:4px 0}
.quote{border-inline-start:3px solid var(--accent);background:rgba(127,127,127,.18);border-radius:6px;padding:4px 8px;margin-bottom:4px;font-size:13px;cursor:pointer}
.quote b{display:block;font-size:12px;color:var(--accent)}
.quote span{color:var(--muted)}
#replybar{display:none;align-items:center;justify-content:space-between;gap:8px;background:var(--bar);padding:6px 12px;border-top:1px solid var(--line);font-size:13px}
#replybar.on{display:flex}
#rbtext{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
#form{display:flex;gap:6px;padding:8px;background:var(--bar);align-items:center}
#form #text{flex:1;border-radius:20px;border:none;margin:0}
#form #send{border-radius:20px}
#clip,#mic{color:var(--accent)}
#rec{display:none;gap:8px;padding:10px;background:var(--bar);align-items:center;justify-content:space-between}
#rt{color:#e74c3c;font-weight:bold}
.recording #form{display:none}
.recording #rec{display:flex}
#back{position:fixed;inset:0;background:rgba(0,0,0,.4);display:none;z-index:10}
#back.open{display:block}
#drawer{position:fixed;top:0;bottom:0;right:0;width:78%;max-width:320px;background:var(--card);color:var(--text);transform:translateX(100%);transition:transform .2s;z-index:20;overflow-y:auto;padding:12px}
#drawer.open{transform:translateX(0)}
#drawer h4{margin:14px 0 6px;color:var(--accent)}
.item{padding:10px;border-radius:8px;cursor:pointer;display:flex;justify-content:space-between}
.item.on{background:rgba(127,127,127,.22)}
.badge{background:#c0392b;color:#fff;border-radius:10px;padding:0 7px;font-size:12px}
.row{display:flex;gap:6px;flex-wrap:wrap}
.row button{padding:8px 10px;font-size:14px;background:var(--bar);color:var(--text)}
.row button.on{background:var(--accent);color:#fff}
.sw{width:44px;height:44px;border-radius:10px;border:2px solid var(--line);cursor:pointer}
.sw.on{border-color:var(--accent)}
#sheetback{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;z-index:30}
#sheetback.open{display:flex;align-items:flex-end;justify-content:center}
#sheet{width:100%;max-width:480px;background:var(--card);border-radius:16px 16px 0 0;padding:10px}
#sheet button{display:block;width:100%;margin:6px 0;background:var(--bar);color:var(--text)}
#sheet button.danger{background:#c0392b;color:#fff}
</style>
<header>
<span><button id="menu" class="ic">☰</button><b id="title">...</b></span>
<span>{% if is_admin %}<a href="/admin">⚙️</a>{% endif %}<a href="/logout">خروج</a></span>
</header>
<div id="sub"><span id="cnt"></span> <span id="typing"></span></div>
<div id="messages"></div>
<div id="replybar"><div id="rbtext"></div><button type="button" id="rbx" class="ic">✖</button></div>
<form id="form">
<button type="button" id="clip" class="ic">📎</button>
<input type="file" id="file" hidden>
<button type="button" id="mic" class="ic">🎤</button>
<input id="text" placeholder="اكتب رسالة..." autocomplete="off">
<button id="send">إرسال</button>
</form>
<div id="rec"><button type="button" id="rcancel" class="del">✖ إلغاء</button><span id="rt">⏺ 0:00</span><button type="button" id="rsend">إرسال ➤</button></div>
<div id="back"></div>
<aside id="drawer">
<h4>المجموعات</h4><div id="groups"></div>
<h4>الأشخاص (رسالة خاصة)</h4><div id="people"></div>
<h4>المظهر</h4>
<div class="row" id="themes"><button data-t="light">☀️ فاتح</button><button data-t="dark">🌙 داكن</button><button data-t="auto">🌓 تلقائي</button></div>
<h4>خلفية المحادثة</h4>
<div class="row" id="walls"></div>
<div class="row" style="margin-top:8px"><button id="wallpick">🖼️ صورة من جوالك</button><button id="wallreset">إزالة</button></div>
<input type="file" id="wallfile" accept="image/*" hidden>
</aside>
<div id="sheetback"><div id="sheet">
<button id="sreply">↩️ رد</button><button id="scopy">📋 نسخ النص</button><button id="sedit">✏️ تعديل</button><button id="sdel" class="danger">🗑️ حذف الرسالة</button><button id="sclose">إغلاق</button>
</div></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
<script>
const me = {{ username|tojson }}, myId = {{ uid }}, csrf = {{ csrf_token()|tojson }}, isAdmin = {{ is_admin|tojson }};
let rooms = [], users = [], online = [], active = null, unread = {}, tTimer = null, lastTyping = 0, replyTo = null, sheetMsg = null, editing = null;
const $ = id => document.getElementById(id);
const box = $("messages");
const socket = io();

function userName(id){ const u = users.find(x => x.id === id); return u ? u.username : "?"; }

function item(label, rid, n){
  const d = document.createElement("div");
  d.className = "item" + (rid === active ? " on" : "");
  const s = document.createElement("span"); s.textContent = label; d.appendChild(s);
  if (n) { const b = document.createElement("span"); b.className = "badge"; b.textContent = n; d.appendChild(b); }
  if (rid !== null) d.onclick = () => openRoom(rid);
  return d;
}

function renderSide(){
  const gl = $("groups"); gl.innerHTML = "";
  rooms.filter(r => r.kind !== "dm")
    .sort((a, b) => (b.kind === "general") - (a.kind === "general") || a.name.localeCompare(b.name))
    .forEach(r => gl.appendChild(item("# " + r.name, r.id, unread[r.id])));
  const pl = $("people"); pl.innerHTML = "";
  users.filter(u => u.id !== myId).forEach(u => {
    const dm = rooms.find(r => r.kind === "dm" && r.with === u.id);
    const el = item((online.includes(u.id) ? "🟢 " : "⚪ ") + u.username, dm ? dm.id : null, dm ? unread[dm.id] : 0);
    el.onclick = () => socket.emit("dm", {user: u.id});
    pl.appendChild(el);
  });
  const r = rooms.find(x => x.id === active);
  $("title").textContent = r ? (r.kind === "dm" ? "🔒 " + userName(r.with) : "# " + r.name) : "...";
  $("cnt").textContent = "🟢 " + online.length + " متصل";
}

function openRoom(id){
  active = id; unread[id] = 0; box.innerHTML = ""; $("typing").textContent = ""; clearReply();
  socket.emit("open", {room: id});
  closeDrawer(); renderSide();
}

/* ---------- الرد والحذف ---------- */
function snippetOf(m){
  if (m.t) return m.t.slice(0, 60);
  if (m.f) {
    if (m.f.m.indexOf("audio/") === 0) return "🎤 رسالة صوتية";
    if (m.f.m.indexOf("image/") === 0) return "🖼️ صورة";
    return "📎 " + m.f.n;
  }
  return "";
}
function setReply(m){
  clearReply();
  replyTo = {id: m.id, u: m.u};
  $("rbtext").textContent = "↩️ " + m.u + ": " + snippetOf(m);
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
  const el = box.querySelector('[data-id="' + id + '"]');
  if (!el) return;
  el.scrollIntoView({block: "center"}); el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1500);
}
function openSheet(m){
  sheetMsg = m;
  $("sdel").style.display = (isAdmin || m.u === me) ? "block" : "none";
  $("scopy").style.display = m.t ? "block" : "none";
  $("sedit").style.display = (m.u === me && m.t) ? "block" : "none";
  $("sheetback").classList.add("open");
}
function closeSheet(){ $("sheetback").classList.remove("open"); }
$("sreply").onclick = () => { if (sheetMsg) setReply(sheetMsg); closeSheet(); };
$("scopy").onclick = () => { try { navigator.clipboard.writeText(sheetMsg.t); } catch (e) {} closeSheet(); };
$("sdel").onclick = () => {
  if (sheetMsg && confirm("حذف الرسالة للجميع؟")) socket.emit("delete", {room: active, id: sheetMsg.id});
  closeSheet();
};
$("sclose").onclick = closeSheet;
$("sedit").onclick = () => { if (sheetMsg) setEdit(sheetMsg); closeSheet(); };
$("sheetback").onclick = e => { if (e.target === $("sheetback")) closeSheet(); };
$("rbx").onclick = clearReply;

function timeText(m){
  return new Date(m.ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) + (m.ed ? " · معدّلة" : "");
}
function add(m){
  const d = document.createElement("div");
  d.className = "msg" + (m.u === me ? " me" : "");
  if (m.id) d.dataset.id = m.id;
  const top = document.createElement("div"); top.className = "top";
  const n = document.createElement("span"); n.className = "name"; n.textContent = m.u; top.appendChild(n);
  const dots = document.createElement("button"); dots.type = "button"; dots.className = "dots"; dots.textContent = "⋮";
  dots.onclick = ev => { ev.stopPropagation(); if (d._m.id) openSheet(d._m); };
  top.appendChild(dots); d.appendChild(top); d._m = m;
  if (m.re) {
    const q = document.createElement("div"); q.className = "quote";
    const qn = document.createElement("b"); qn.textContent = m.re.u;
    const qt = document.createElement("span"); qt.textContent = m.re.t;
    q.appendChild(qn); q.appendChild(qt);
    q.onclick = ev => { ev.stopPropagation(); jumpTo(m.re.id); };
    d.appendChild(q);
  }
  if (m.f && m.f.m.indexOf("audio/") === 0) {
    const au = document.createElement("audio");
    au.controls = true; au.preload = "metadata"; au.src = "/file/" + m.f.id;
    d.appendChild(au);
  } else if (m.f) {
    const a = document.createElement("a"); a.href = "/file/" + m.f.id; a.target = "_blank";
    if (m.f.m.indexOf("image/") === 0) {
      const i = document.createElement("img"); i.src = "/file/" + m.f.id;
      i.onload = () => { box.scrollTop = box.scrollHeight; };
      a.appendChild(i);
    } else { a.textContent = "📎 " + m.f.n; a.download = m.f.n; }
    d.appendChild(a);
  }
  if (m.t) { const tx = document.createElement("span"); tx.className = "txt"; tx.textContent = m.t; d.appendChild(tx); }
  const t = document.createElement("span"); t.className = "time";
  t.textContent = timeText(m);
  d.appendChild(t);
  box.appendChild(d); box.scrollTop = box.scrollHeight;
}

/* ---------- الاتصال ---------- */
socket.on("connect", () => { socket.emit("get_rooms"); if (active !== null) socket.emit("open", {room: active}); });
socket.on("connect_error", () => { location.href = "/login"; });
socket.on("refresh", () => socket.emit("get_rooms"));
socket.on("online", ids => { online = ids; renderSide(); });
socket.on("rooms", d => {
  rooms = d.rooms; users = d.users; online = d.online;
  if (active === null || !rooms.find(r => r.id === active)) {
    const g = rooms.find(r => r.kind === "general");
    if (g) openRoom(g.id);
  }
  renderSide();
});
socket.on("opened", d => openRoom(d.room));
socket.on("history", d => {
  if (d.room !== active) return;
  box.innerHTML = ""; d.msgs.forEach(add);
});
socket.on("message", m => {
  if (m.room === active) add(m);
  else { unread[m.room] = (unread[m.room] || 0) + 1; renderSide(); }
});
socket.on("deleted", d => {
  if (d.room === active) {
    const el = box.querySelector('[data-id="' + d.id + '"]');
    if (el) el.remove();
  }
  if ((replyTo && replyTo.id === d.id) || editing === d.id) clearReply();
});
socket.on("edited", d => {
  if (d.room !== active) return;
  const el = box.querySelector('[data-id="' + d.id + '"]');
  if (!el || !el._m) return;
  el._m.t = d.t; el._m.ed = 1;
  const tx = el.querySelector(".txt"); if (tx) tx.textContent = d.t;
  el.querySelector(".time").textContent = timeText(el._m);
});
socket.on("typing", d => {
  if (d.room !== active) return;
  $("typing").textContent = d.u + " يكتب...";
  clearTimeout(tTimer); tTimer = setTimeout(() => { $("typing").textContent = ""; }, 3000);
});

$("form").addEventListener("submit", e => {
  e.preventDefault();
  const i = $("text"), text = i.value.trim();
  if (editing) {
    if (text) socket.emit("edit", {room: active, id: editing, text: text});
    clearReply(); i.value = "";
    return;
  }
  if (text && active !== null) {
    socket.emit("send", {room: active, text: text, reply: replyTo ? replyTo.id : null});
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
  const fd = new FormData(); fd.append("room", active); fd.append("file", blob, name);
  if (replyTo) fd.append("reply", replyTo.id);
  clearReply();
  const r = await fetch("/upload", {method: "POST", headers: {"X-CSRF": csrf}, body: fd});
  if (!r.ok) alert("فشل رفع الملف");
}

/* ---------- التسجيل الصوتي ---------- */
let rec = null, chunks = [], rStart = 0, rTimer = null, rCancel = false, rStream = null;
async function startRec(){
  if (active === null || rec) return;
  if (!navigator.mediaDevices || !window.MediaRecorder) { alert("متصفحك لا يدعم التسجيل الصوتي"); return; }
  try { rStream = await navigator.mediaDevices.getUserMedia({audio: true}); }
  catch (e) { alert("اسمح للموقع باستخدام المايكروفون من إعدادات المتصفح"); return; }
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
  r.start(); rStart = Date.now(); $("rt").textContent = "⏺ 0:00";
  document.body.classList.add("recording");
  rTimer = setInterval(() => {
    const s = Math.floor((Date.now() - rStart) / 1000);
    $("rt").textContent = "⏺ " + Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    if (s >= 120) stopRec(false);
  }, 500);
}
function stopRec(cancel){
  if (rec && rec.state === "recording") { rCancel = cancel; rec.stop(); }
}
$("mic").onclick = startRec;
$("rcancel").onclick = () => stopRec(true);
$("rsend").onclick = () => stopRec(false);

/* ---------- الوضع الداكن والخلفية (تُحفظ على جهازك) ---------- */
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
function applyWall(){
  const w = getWall();
  box.style.background = (w.k === "img" && w.v) ? 'url("' + w.v + '") center / cover no-repeat' : (WALLS[w.k] || "");
  document.querySelectorAll("#walls .sw").forEach(s => s.classList.toggle("on", s.dataset.k === w.k));
}
Object.keys(WALLS).forEach(k => {
  const s = document.createElement("div");
  s.className = "sw"; s.dataset.k = k; s.style.background = WALLS[k] || "var(--bg)";
  s.onclick = () => { try { localStorage.setItem("wall", JSON.stringify({k: k})); } catch (e) {} applyWall(); };
  $("walls").appendChild(s);
});
$("wallpick").onclick = () => $("wallfile").click();
$("wallfile").addEventListener("change", async e => {
  const f = e.target.files[0]; e.target.value = "";
  if (!f) return;
  try {
    const b = await shrink(f, 1080, 0.7);
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
</script></body></html>"""

ADMIN = HEAD + """
<header><span>⚙️ لوحة الإدارة</span><span><a href="/">الدردشة</a><a href="/logout">خروج</a></span></header>
<div class="wrap">
{% if msg %}<p class="ok">{{ msg }}</p>{% endif %}

<div class="box"><h3>➕ إضافة مستخدم</h3>
<form method="post" action="/admin/add">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
<input name="username" placeholder="اسم المستخدم" required>
<input name="password" placeholder="كلمة المرور (8 أحرف على الأقل)" required>
<button>إضافة</button></form></div>

<div class="box"><h3>👥 المستخدمون</h3><div class="scroll"><table>
<tr><th>الاسم</th><th>النوع</th><th>أُضيف</th><th></th></tr>
{% for u in users %}<tr>
<td>{{ u.username }}</td><td>{{ "مالك" if u.is_admin else "مستخدم" }}</td>
<td>{{ u.created_at.strftime('%Y-%m-%d') }}</td>
<td>{% if not u.is_admin %}
<form method="post" action="/admin/delete/{{ u.id }}" onsubmit="return confirm('حذف المستخدم؟')">
<input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="del">حذف</button></form>
{% endif %}</td></tr>{% endfor %}
</table></div></div>

<div class="box"><h3>🗂️ المجموعات</h3>
<p>مجموعة «عام» تضم الجميع تلقائياً. أنشئ مجموعات خاصة واختر أعضاءها:</p>
<form method="post" action="/admin/room/add">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
<input name="name" placeholder="اسم المجموعة" required>
{% for u in users %}<label class="chk"><input type="checkbox" name="members" value="{{ u.id }}">{{ u.username }}</label>{% endfor %}
<button>إنشاء مجموعة</button></form>
{% for g in groups %}
<details><summary>{{ g.room.name }} ({{ g.members|length }} عضو)</summary>
<form method="post" action="/admin/room/{{ g.room.id }}/members">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
{% for u in users %}<label class="chk"><input type="checkbox" name="members" value="{{ u.id }}" {{ "checked" if u.id in g.members }}>{{ u.username }}</label>{% endfor %}
<button>حفظ الأعضاء</button></form>
<form method="post" action="/admin/room/{{ g.room.id }}/delete" style="margin-top:8px" onsubmit="return confirm('حذف المجموعة بكل رسائلها؟')">
<input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="del">حذف المجموعة</button></form>
</details>{% endfor %}
</div>

<div class="box"><h3>🌐 سجل الدخول (آخر 100، بتوقيت UTC)</h3><div class="scroll"><table>
<tr><th>الاسم</th><th>IP</th><th>النتيجة</th><th>الوقت</th></tr>
{% for l in logs %}<tr>
<td>{{ l.username }}</td><td>{{ l.ip }}</td><td>{{ "✅" if l.success else "❌" }}</td>
<td>{{ l.created_at.strftime('%Y-%m-%d %H:%M') }}</td></tr>{% endfor %}
</table></div></div>
</div></body></html>"""


# ---------------------------------------------------------------
# المسارات
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
            error = "محاولات كثيرة، انتظر 10 دقائق"
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
            error = "اسم المستخدم أو كلمة المرور خاطئة"
    return render_template_string(LOGIN, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def chat():
    u = current_user()
    return render_template_string(CHAT, username=u.username, uid=u.id, is_admin=u.is_admin)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if not secrets.compare_digest(request.headers.get("X-CSRF", ""), session.get("csrf", "x")):
        abort(400)
    user = current_user()
    rid = request.form.get("room", type=int)
    f = request.files.get("file")
    if not f or not is_member(rid, user.id):
        abort(400)
    raw = f.read()
    if not raw or len(raw) > MAX_FILE:
        abort(413)
    mime = f.mimetype if f.mimetype in INLINE_TYPES else "application/octet-stream"
    name = (f.filename or "file")[-80:]
    att = Attachment(room_id=rid,
                     meta=encrypt(json.dumps({"n": name, "m": mime}, ensure_ascii=False)),
                     data=enc_bytes(raw))
    db.session.add(att)
    db.session.flush()
    post(rid, user, "", {"id": att.id, "n": name, "m": mime},
         request.form.get("reply", type=int))
    return {"ok": True}


@app.route("/file/<int:fid>")
@login_required
def get_file(fid):
    att = db.session.get(Attachment, fid)
    if not att or not is_member(att.room_id, current_user().id):
        abort(404)
    meta = json.loads(decrypt(att.meta))
    resp = send_file(io.BytesIO(dec_bytes(att.data)), mimetype=meta["m"],
                     as_attachment=meta["m"] not in INLINE_TYPES,
                     download_name=meta["n"], conditional=True, max_age=3600)
    resp.cache_control.public = False
    resp.cache_control.private = True
    return resp


@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.id).all()
    logs = LoginLog.query.order_by(LoginLog.id.desc()).limit(100).all()
    groups = []
    for r in Room.query.filter_by(kind="group").order_by(Room.id):
        ids = {m.user_id for m in Member.query.filter_by(room_id=r.id)}
        groups.append({"room": r, "members": ids})
    return render_template_string(ADMIN, users=users, logs=logs, groups=groups,
                                  msg=request.args.get("msg"))


@app.route("/admin/add", methods=["POST"])
@admin_required
def admin_add():
    check_csrf()
    name = request.form.get("username", "").strip()
    pw = request.form.get("password", "")
    if not (3 <= len(name) <= 30) or len(pw) < 8:
        return redirect(url_for("admin", msg="الاسم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل"))
    if User.query.filter_by(username=name).first():
        return redirect(url_for("admin", msg="الاسم موجود مسبقاً"))
    db.session.add(User(username=name, password_hash=generate_password_hash(pw)))
    db.session.commit()
    ensure_general()
    notify_all()
    return redirect(url_for("admin", msg="تمت إضافة المستخدم"))


@app.route("/admin/delete/<int:uid>", methods=["POST"])
@admin_required
def admin_delete(uid):
    check_csrf()
    u = db.session.get(User, uid)
    if u and not u.is_admin:
        dm_ids = [r.id for r in Room.query.join(Member, Member.room_id == Room.id)
                  .filter(Member.user_id == uid, Room.kind == "dm")]
        for rid in dm_ids:
            purge_room(rid)
        Member.query.filter_by(user_id=uid).delete()
        db.session.delete(u)
        db.session.commit()
        for sid, user_id in list(online.items()):  # طرده فوراً
            if user_id == uid:
                socketio.server.disconnect(sid)
                online.pop(sid, None)
        notify_all()
        return redirect(url_for("admin", msg="تم حذف المستخدم"))
    return redirect(url_for("admin"))


@app.route("/admin/room/add", methods=["POST"])
@admin_required
def admin_room_add():
    check_csrf()
    name = request.form.get("name", "").strip()[:60]
    if not name:
        return redirect(url_for("admin", msg="اكتب اسم المجموعة"))
    r = Room(name=name, kind="group")
    db.session.add(r)
    db.session.flush()
    set_members(r.id, request.form.getlist("members", type=int))
    db.session.commit()
    notify_all()
    return redirect(url_for("admin", msg="تم إنشاء المجموعة"))


@app.route("/admin/room/<int:rid>/members", methods=["POST"])
@admin_required
def admin_room_members(rid):
    check_csrf()
    r = db.session.get(Room, rid)
    if r and r.kind == "group":
        set_members(rid, request.form.getlist("members", type=int))
        db.session.commit()
        notify_all()
    return redirect(url_for("admin", msg="تم حفظ الأعضاء"))


@app.route("/admin/room/<int:rid>/delete", methods=["POST"])
@admin_required
def admin_room_delete(rid):
    check_csrf()
    r = db.session.get(Room, rid)
    if r and r.kind == "group":
        purge_room(rid)
        db.session.commit()
        notify_all()
    return redirect(url_for("admin", msg="تم حذف المجموعة"))


# ---------------------------------------------------------------
# الدردشة (WebSocket)
# ---------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    user = current_user()
    if not user:
        return False
    online[request.sid] = user.id
    socketio.emit("online", sorted(set(online.values())))


@socketio.on("disconnect")
def on_disconnect():
    online.pop(request.sid, None)
    socketio.emit("online", sorted(set(online.values())))


@socketio.on("get_rooms")
def on_get_rooms():
    user = current_user()
    if not user:
        disconnect()
        return
    emit("rooms", rooms_payload(user.id))


@socketio.on("open")
def on_open(data):
    user = current_user()
    if not user:
        disconnect()
        return
    rid = to_int((data or {}).get("room"))
    if not is_member(rid, user.id):
        return
    rows = (ChatMessage.query.filter_by(room_id=rid)
            .order_by(ChatMessage.id.desc()).limit(50).all())
    msgs = []
    for r in reversed(rows):
        try:
            m = json.loads(decrypt(r.blob))
            m["id"] = r.id
            msgs.append(m)
        except Exception:
            pass
    emit("history", {"room": rid, "msgs": msgs})


@socketio.on("send")
def on_send(data):
    user = current_user()
    if not user:
        disconnect()
        return
    rid = to_int((data or {}).get("room"))
    text = str((data or {}).get("text", "")).strip()[:1000]
    if not text or not is_member(rid, user.id):
        return
    post(rid, user, text, None, to_int((data or {}).get("reply")))


@socketio.on("delete")
def on_delete(data):
    user = current_user()
    if not user:
        disconnect()
        return
    rid = to_int((data or {}).get("room"))
    mid = to_int((data or {}).get("id"))
    if not mid or not is_member(rid, user.id):
        return
    row = db.session.get(ChatMessage, mid)
    if not row or row.room_id != rid:
        return
    try:
        m = json.loads(decrypt(row.blob))
    except Exception:
        m = {}
    if not (user.is_admin or m.get("u") == user.username):
        return
    fid = to_int((m.get("f") or {}).get("id"))
    if fid:
        att = db.session.get(Attachment, fid)
        if att and att.room_id == rid:
            db.session.delete(att)
    db.session.delete(row)
    db.session.commit()
    emit_to_room(rid, "deleted", {"room": rid, "id": mid})


@socketio.on("edit")
def on_edit(data):
    user = current_user()
    if not user:
        disconnect()
        return
    rid = to_int((data or {}).get("room"))
    mid = to_int((data or {}).get("id"))
    text = str((data or {}).get("text", "")).strip()[:1000]
    if not mid or not text or not is_member(rid, user.id):
        return
    row = db.session.get(ChatMessage, mid)
    if not row or row.room_id != rid:
        return
    try:
        m = json.loads(decrypt(row.blob))
    except Exception:
        return
    if m.get("u") != user.username or not m.get("t"):  # تعديل رسائلك النصية فقط
        return
    m["t"] = text
    m["ed"] = 1
    row.blob = encrypt(json.dumps(m, ensure_ascii=False))
    db.session.commit()
    emit_to_room(rid, "edited", {"room": rid, "id": mid, "t": text})


@socketio.on("typing")
def on_typing(data):
    user = current_user()
    if not user:
        return
    rid = to_int((data or {}).get("room"))
    if is_member(rid, user.id):
        emit_to_room(rid, "typing", {"room": rid, "u": user.username}, skip_sid=request.sid)


@socketio.on("dm")
def on_dm(data):
    user = current_user()
    if not user:
        disconnect()
        return
    other = db.session.get(User, to_int((data or {}).get("user")) or 0)
    if not other or other.id == user.id:
        return
    r = get_dm(user.id, other.id)
    emit("rooms", rooms_payload(user.id))
    emit("opened", {"room": r.id})
    for sid, uid in list(online.items()):
        if uid == other.id:
            socketio.emit("refresh", to=sid)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
