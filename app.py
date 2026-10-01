import os, secrets, string, datetime
from flask import Flask, request, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///attendance.db")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(16))
db = SQLAlchemy(app)

ROT_SECONDS = 30
YEARS = ["Second Year", "Third Year", "Final Year"]
DIVS = {"SY": ["A", "B", "C", "D"], "TY": ["A", "B","C","D"], "FY": ["A", "B","C","D"]}
DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


# ---------- models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10))            # admin | professor | student
    login_id = db.Column(db.String(40), unique=True)
    name = db.Column(db.String(120))
    password_hash = db.Column(db.String(200))
    year = db.Column(db.String(4), nullable=True)
    div = db.Column(db.String(4), nullable=True)
    grn = db.Column(db.String(40), nullable=True)

    def check(self, pw):
        return check_password_hash(self.password_hash, pw)

    def public(self):
        return {"id": self.id, "role": self.role, "login_id": self.login_id, "name": self.name,
                "year": self.year, "div": self.div, "grn": self.grn}


class Timetable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(4))
    start = db.Column(db.String(5))
    end = db.Column(db.String(5))
    year = db.Column(db.String(4))
    div = db.Column(db.String(4))
    subject = db.Column(db.String(120))
    professor_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def public(self):
        prof = User.query.get(self.professor_id)
        return {"id": self.id, "day": self.day, "start": self.start, "end": self.end,
                "year": self.year, "div": self.div, "subject": self.subject,
                "professor_id": self.professor_id, "professor_name": prof.name if prof else None}


class Session_(db.Model):
    __tablename__ = "session_"
    id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.String(4))
    div = db.Column(db.String(4))
    subject = db.Column(db.String(120))
    professor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    token = db.Column(db.String(10))
    prev_token = db.Column(db.String(10), nullable=True)
    expires_at = db.Column(db.DateTime)
    open = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("session_.id"))
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    marked_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# ---------- helpers ----------
def gen_token(n=6):
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def current_user():
    uid = session.get("uid")
    return User.query.get(uid) if uid else None


def require_role(role):
    u = current_user()
    if not u or u.role != role:
        return None
    return u


def rotate_if_needed(s):
    if s.open and datetime.datetime.utcnow() >= s.expires_at:
        s.prev_token = s.token
        s.token = gen_token()
        s.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=ROT_SECONDS)
        db.session.commit()
    return s


# ---------- auth ----------
@app.post("/api/login")
def login():
    d = request.json or {}
    u = User.query.filter_by(role=d.get("role"), login_id=d.get("login_id")).first()
    if not u or not u.check(d.get("password", "")):
        return jsonify({"error": "Incorrect ID or password."}), 401
    session["uid"] = u.id
    return jsonify(u.public())


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(u.public() if u else None)


# ---------- admin: timetable ----------
@app.get("/api/admin/timetable")
def tt_list():
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    return jsonify([t.public() for t in Timetable.query.all()])


@app.post("/api/admin/timetable")
def tt_add():
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    d = request.json or {}
    t = Timetable(day=d["day"], start=d["start"], end=d["end"], year=d["year"],
                  div=d["div"], subject=d["subject"].strip(), professor_id=d["professor_id"])
    db.session.add(t)
    db.session.commit()
    return jsonify(t.public())


@app.delete("/api/admin/timetable/<int:tid>")
def tt_del(tid):
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    t = Timetable.query.get_or_404(tid)
    db.session.delete(t)
    db.session.commit()
    return jsonify({"ok": True})


# ---------- admin: professors & students ----------
@app.get("/api/admin/users")
def users_list():
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    role = request.args.get("role")
    q = User.query.filter(User.role == role) if role else User.query.filter(User.role != "admin")
    return jsonify([u.public() for u in q.all()])


@app.post("/api/admin/users")
def users_add():
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    d = request.json or {}
    if User.query.filter_by(login_id=d["login_id"]).first():
        return jsonify({"error": "That ID is already in use."}), 400
    pw = d.get("password") or d["login_id"]
    u = User(role=d["role"], login_id=d["login_id"], name=d["name"],
              password_hash=generate_password_hash(pw),
              year=d.get("year"), div=d.get("div"), grn=d.get("grn"))
    db.session.add(u)
    db.session.commit()
    return jsonify(u.public())


@app.put("/api/admin/users/<int:uid>")
def users_edit(uid):
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    u = User.query.get_or_404(uid)
    d = request.json or {}
    for f in ("name", "year", "div", "grn"):
        if f in d:
            setattr(u, f, d[f])
    db.session.commit()
    return jsonify(u.public())


@app.post("/api/admin/users/<int:uid>/reset-password")
def users_reset_pw(uid):
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    u = User.query.get_or_404(uid)
    u.password_hash = generate_password_hash(u.login_id)
    db.session.commit()
    return jsonify({"ok": True, "new_password": u.login_id})


@app.delete("/api/admin/users/<int:uid>")
def users_del(uid):
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    u = User.query.get_or_404(uid)
    db.session.delete(u)
    db.session.commit()
    return jsonify({"ok": True})


# ---------- admin: reports ----------
@app.get("/api/admin/reports/sessions")
def rep_sessions():
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    out = []
    for s in Session_.query.order_by(Session_.created_at.desc()).all():
        out.append({"id": s.id, "year": s.year, "div": s.div, "subject": s.subject,
                    "created_at": s.created_at.isoformat(),
                    "present": Attendance.query.filter_by(session_id=s.id).count()})
    return jsonify(out)


@app.get("/api/admin/reports/students")
def rep_students():
    if not require_role("admin"):
        return jsonify({"error": "Admins only."}), 403
    year, div = request.args.get("year"), request.args.get("div")
    students = User.query.filter_by(role="student", year=year, div=div).all()
    sess_ids = [s.id for s in Session_.query.filter_by(year=year, div=div).all()]
    out = []
    for st in students:
        a = Attendance.query.filter(Attendance.student_id == st.id, Attendance.session_id.in_(sess_ids)).count()
        n = len(sess_ids)
        out.append({"login_id": st.login_id, "name": st.name, "attended": a, "total": n,
                    "pct": round(a / n * 100) if n else 0})
    return jsonify(out)


# ---------- professor ----------
@app.get("/api/prof/assignments")
def prof_assignments():
    u = require_role("professor")
    if not u:
        return jsonify({"error": "Professors only."}), 403
    rows = Timetable.query.filter_by(professor_id=u.id).all()
    seen, out = set(), []
    for r in rows:
        k = (r.year, r.div, r.subject)
        if k not in seen:
            seen.add(k)
            out.append({"year": r.year, "div": r.div, "subject": r.subject})
    return jsonify(out)


@app.post("/api/prof/session/start")
def prof_start():
    u = require_role("professor")
    if not u:
        return jsonify({"error": "Professors only."}), 403
    d = request.json or {}
    Session_.query.filter_by(professor_id=u.id, open=True).update({"open": False})
    s = Session_(year=d["year"], div=d["div"], subject=d["subject"], professor_id=u.id,
                 token=gen_token(), expires_at=datetime.datetime.utcnow() + datetime.timedelta(seconds=ROT_SECONDS))
    db.session.add(s)
    db.session.commit()
    return jsonify({"id": s.id})


@app.post("/api/prof/session/stop")
def prof_stop():
    u = require_role("professor")
    if not u:
        return jsonify({"error": "Professors only."}), 403
    Session_.query.filter_by(professor_id=u.id, open=True).update({"open": False})
    db.session.commit()
    return jsonify({"ok": True})


@app.get("/api/prof/session/current")
def prof_current():
    u = require_role("professor")
    if not u:
        return jsonify({"error": "Professors only."}), 403
    s = Session_.query.filter_by(professor_id=u.id, open=True).first()
    if not s:
        return jsonify(None)
    rotate_if_needed(s)
    roll = User.query.filter_by(role="student", year=s.year, div=s.div).all()
    present = {a.student_id for a in Attendance.query.filter_by(session_id=s.id).all()}
    return jsonify({"id": s.id, "year": s.year, "div": s.div, "subject": s.subject, "token": s.token,
                    "roll": [{"login_id": st.login_id, "name": st.name, "present": st.id in present} for st in roll]})


@app.get("/api/prof/sessions")
def prof_sessions():
    u = require_role("professor")
    if not u:
        return jsonify({"error": "Professors only."}), 403
    out = []
    for s in Session_.query.filter_by(professor_id=u.id).order_by(Session_.created_at.desc()).all():
        out.append({"year": s.year, "div": s.div, "subject": s.subject,
                    "created_at": s.created_at.isoformat(),
                    "present": Attendance.query.filter_by(session_id=s.id).count()})
    return jsonify(out)


# ---------- student ----------
@app.get("/api/student/today")
def student_today():
    u = require_role("student")
    if not u:
        return jsonify({"error": "Students only."}), 403
    now = datetime.datetime.now()
    t = now.strftime("%H:%M")
    day = DOW[(now.weekday() + 1) % 7]  # datetime Monday=0 -> DOW index (Mon=1)
    slot = Timetable.query.filter_by(year=u.year, div=u.div, day=day).filter(
        Timetable.start <= t, Timetable.end >= t).first()
    if not slot:
        return jsonify({"slot": None})
    s = Session_.query.filter_by(year=u.year, div=u.div, subject=slot.subject, open=True).first()
    marked = False
    if s:
        rotate_if_needed(s)
        marked = Attendance.query.filter_by(session_id=s.id, student_id=u.id).first() is not None
    return jsonify({"slot": {"subject": slot.subject, "start": slot.start, "end": slot.end},
                    "session_open": bool(s), "marked": marked})


@app.post("/api/student/mark")
def student_mark():
    u = require_role("student")
    if not u:
        return jsonify({"error": "Students only."}), 403
    code = (request.json or {}).get("code", "").strip().upper()
    s = Session_.query.filter_by(year=u.year, div=u.div, open=True).first()
    if not s:
        return jsonify({"error": "No live session."}), 400
    rotate_if_needed(s)
    if code not in (s.token, s.prev_token):
        return jsonify({"error": "Code expired or wrong. Use the current code."}), 400
    if Attendance.query.filter_by(session_id=s.id, student_id=u.id).first():
        return jsonify({"error": "Already marked."}), 400
    db.session.add(Attendance(session_id=s.id, student_id=u.id))
    db.session.commit()
    return jsonify({"ok": True})


@app.get("/api/student/stats")
def student_stats():
    u = require_role("student")
    if not u:
        return jsonify({"error": "Students only."}), 403
    sess_ids = [s.id for s in Session_.query.filter_by(year=u.year, div=u.div).all()]
    a = Attendance.query.filter(Attendance.student_id == u.id, Attendance.session_id.in_(sess_ids)).count()
    n = len(sess_ids)
    return jsonify({"attended": a, "total": n, "pct": round(a / n * 100) if n else 0})


@app.get("/api/meta")
def meta():
    return jsonify({"years": YEARS, "divs": DIVS})


# ---------- static frontend ----------
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------- seed + init ----------
def seed():
    if User.query.first():
        return
    admin = User(role="admin", login_id="admin", name="Administrator",
                 password_hash=generate_password_hash("admin123"))
    db.session.add(admin)
    profs = [
        User(role="professor", login_id="EMP001", name="Prof. Anjali Kulkarni",
             password_hash=generate_password_hash("EMP001")),
        User(role="professor", login_id="EMP002", name="Prof. Rakesh Iyer",
             password_hash=generate_password_hash("EMP002")),
    ]
    db.session.add_all(profs)
    db.session.commit()
    students = [("401", "Aditya Jayram Bhosale", "25UGCS25329"), ("402", "Swetank Kumar", "25UGCS24778"),
                ("403", "Santosh Kumar", "25UGCS25127"), ("404", "Suhana Shaikh", "25UGCS23988")]
    for roll, name, grn in students:
        db.session.add(User(role="student", login_id=roll, name=name, grn=grn, year="SY", div="D",
                             password_hash=generate_password_hash(roll)))
    db.session.add(Timetable(day="Mon", start="09:00", end="10:00", year="SY", div="D",
                              subject="Data Structures", professor_id=profs[0].id))
    db.session.add(Timetable(day="Tue", start="11:00", end="12:00", year="SY", div="D",
                              subject="Object Oriented Programming", professor_id=profs[1].id))
    db.session.commit()


with app.app_context():
    db.create_all()
    seed()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
