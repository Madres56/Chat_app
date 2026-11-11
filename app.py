import os
import json
import base64
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, render_template_string, request, session,
                   redirect, url_for, abort)
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


def _key(label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=label).derive(MASTER.encode())


# ثلاثة مفاتيح مستقلة، كل واحد لطبقة تشفير
K1 = _key(b"layer1-aes-gcm")
K2 = _key(b"layer2-chacha20")
K3 = base64.urlsafe_b64encode(_key(b"layer3-fernet"))


def encrypt(text: str) -> str:
    data = text.encode("utf-8")
    n1 = os.urandom(12)                                   # الطبقة 1: AES-256-GCM
    data = n1 + AESGCM(K1).encrypt(n1, data, None)
    n2 = os.urandom(12)                                   # الطبقة 2: ChaCha20-Poly1305
    data = n2 + ChaCha20Poly1305(K2).encrypt(n2, data, None)
    return Fernet(K3).encrypt(data).decode()              # الطبقة 3: Fernet


def decrypt(token: str) -> str:
    data = Fernet(K3).decrypt(token.encode())
    n2, data = data[:12], data[12:]
    data = ChaCha20Poly1305(K2).decrypt(n2, data, None)
    n1, data = data[:12], data[12:]
    return AESGCM(K1).decrypt(n1, data, None).decode("utf-8")


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
)
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
online = {}  # sid -> user id


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blob = db.Column(db.Text, nullable=False)  # الرسالة مشفرة بثلاث طبقات
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


with app.app_context():
    db.create_all()
    ensure_owner()


# ---------------------------------------------------------------
# أدوات مساعدة
# ---------------------------------------------------------------
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


# ---------------------------------------------------------------
# الصفحات
# ---------------------------------------------------------------
HEAD = """<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>دردشة</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,sans-serif;background:#ece5dd}
header{background:#075e54;color:#fff;padding:14px;display:flex;justify-content:space-between;font-weight:bold}
header a{color:#fff;text-decoration:none;margin-inline-start:12px;font-weight:normal}
.card{max-width:420px;margin:40px auto;background:#fff;padding:24px;border-radius:14px}
.wrap{max-width:900px;margin:14px auto;padding:0 10px}
.box{background:#fff;padding:14px;border-radius:12px;margin-bottom:14px}
input{width:100%;padding:12px;margin:6px 0;border:1px solid #ccc;border-radius:10px;font-size:16px}
button{padding:10px 18px;border:none;border-radius:10px;background:#075e54;color:#fff;font-size:16px}
button.del{background:#c0392b;padding:6px 12px;font-size:14px}
.err{color:#c0392b}.ok{color:#1e8449}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{padding:6px;border-bottom:1px solid #eee;text-align:right;white-space:nowrap}
.scroll{overflow-x:auto}
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

CHAT = HEAD + """
<style>
body{display:flex;flex-direction:column;height:100dvh}
#messages{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:6px}
.msg{max-width:80%;padding:8px 12px;border-radius:12px;background:#fff;word-wrap:break-word}
.msg.me{align-self:flex-start;background:#dcf8c6}
.msg .name{font-size:12px;color:#075e54;font-weight:bold;display:block}
form{display:flex;gap:6px;padding:8px;background:#f0f0f0}
form input{flex:1;border-radius:20px;border:none;margin:0}
form button{border-radius:20px}
</style>
<header><span>💬 {{ username }}</span>
<span>{% if is_admin %}<a href="/admin">⚙️ الإدارة</a>{% endif %}<a href="/logout">خروج</a></span></header>
<div id="messages"></div>
<form id="form"><input id="text" placeholder="اكتب رسالة..." autocomplete="off"><button>إرسال</button></form>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
<script>
const me = {{ username|tojson }};
const box = document.getElementById("messages");
const socket = io();
function add(m){
  const d = document.createElement("div");
  d.className = "msg" + (m.u === me ? " me" : "");
  const n = document.createElement("span");
  n.className = "name"; n.textContent = m.u;
  d.appendChild(n); d.appendChild(document.createTextNode(m.t));
  box.appendChild(d); box.scrollTop = box.scrollHeight;
}
socket.on("history", list => list.forEach(add));
socket.on("message", add);
socket.on("connect_error", () => location.href = "/login");
document.getElementById("form").addEventListener("submit", e => {
  e.preventDefault();
  const i = document.getElementById("text");
  if (i.value.trim()) socket.emit("send", {text: i.value});
  i.value = "";
});
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
<form method="post" action="/admin/delete/{{ u.id }}" onsubmit="return confirm('حذف {{ u.username }}؟')">
<input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="del">حذف</button></form>
{% endif %}</td></tr>{% endfor %}
</table></div></div>

<div class="box"><h3>🌐 سجل الدخول (آخر 100، بتوقيت UTC)</h3><div class="scroll"><table>
<tr><th>الاسم</th><th>IP</th><th>النتيجة</th><th>الوقت</th></tr>
{% for l in logs %}<tr>
<td>{{ l.username }}</td><td>{{ l.ip }}</td><td>{{ "✅" if l.success else "❌" }}</td>
<td>{{ l.created_at.strftime('%Y-%m-%d %H:%M') }}</td></tr>{% endfor %}
</table></div></div>
</div></body></html>"""


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
    return render_template_string(CHAT, username=u.username, is_admin=u.is_admin)


@app.route("/admin")
@admin_required
def admin():
    users = User.query.order_by(User.id).all()
    logs = LoginLog.query.order_by(LoginLog.id.desc()).limit(100).all()
    return render_template_string(ADMIN, users=users, logs=logs, msg=request.args.get("msg"))


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
    return redirect(url_for("admin", msg="تمت إضافة المستخدم"))


@app.route("/admin/delete/<int:uid>", methods=["POST"])
@admin_required
def admin_delete(uid):
    check_csrf()
    u = db.session.get(User, uid)
    if u and not u.is_admin:
        db.session.delete(u)
        db.session.commit()
        for sid, user_id in list(online.items()):  # طرده فوراً من الدردشة
            if user_id == uid:
                socketio.server.disconnect(sid)
        return redirect(url_for("admin", msg="تم حذف المستخدم"))
    return redirect(url_for("admin"))


# ---------------------------------------------------------------
# الدردشة (WebSocket)
# ---------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    user = current_user()
    if not user:
        return False
    online[request.sid] = user.id
    rows = Message.query.order_by(Message.id.desc()).limit(50).all()
    msgs = []
    for r in reversed(rows):
        try:
            msgs.append(json.loads(decrypt(r.blob)))
        except Exception:
            pass
    emit("history", msgs)


@socketio.on("disconnect")
def on_disconnect():
    online.pop(request.sid, None)


@socketio.on("send")
def on_send(data):
    user = current_user()
    if not user:
        disconnect()
        return
    text = str((data or {}).get("text", "")).strip()[:500]
    if not text:
        return
    msg = {"u": user.username, "t": text}
    db.session.add(Message(blob=encrypt(json.dumps(msg, ensure_ascii=False))))
    db.session.commit()
    emit("message", msg, broadcast=True)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
