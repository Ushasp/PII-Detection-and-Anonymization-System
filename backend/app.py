from flask import Flask, request, redirect, send_from_directory, session, make_response
import csv
import io
import datetime
import mysql.connector
import hashlib
import re
import spacy

nlp = spacy.load("en_core_web_sm")

app = Flask(__name__)
app.secret_key = "mysecretkey"

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Usha@2003",
    database="pii_anonymizer"
)

cursor = db.cursor()

# Auto-create activity_logs table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    action VARCHAR(20),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
db.commit()

# Auto-create registered_users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS registered_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(200),
    username VARCHAR(100) UNIQUE,
    email VARCHAR(200),
    phone VARCHAR(20),
    password VARCHAR(300),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
db.commit()

# ===============================
# HASH GENERATION
# ===============================

def generate_hash(value):
    hash_object = hashlib.sha256(value.encode())
    return hash_object.hexdigest()[:6]


# ===============================
# ANONYMIZATION FUNCTIONS
# ===============================

def anonymize_name(name):
    h = generate_hash(name)
    num = int(h, 16) % 1000
    return f"USR{num}"

def anonymize_email(email):
    h = generate_hash(email)
    return f"user{h}@anon.com"

def anonymize_phone(phone):
    h = generate_hash(phone)
    num = int(h, 16) % 9000000000
    return "9" + str(num).zfill(9)

def anonymize_aadhar(aadhar):
    h = generate_hash(aadhar)
    num = int(h, 16) % 900000000000
    return str(100000000000 + num)

def anonymize_address(address):
    h = generate_hash(address)
    num = int(h, 16) % 1000
    return f"AREA{num}"


# ===============================
# TEXT ANONYMIZATION
# ===============================

def anonymize_text(text):

    doc = nlp(text)
    anonymized_text = text

    # =========================
    # 1️⃣ NLP Detection (spaCy)
    # =========================
    # =========================

    name_patterns = re.findall(
    r"(?:i am|im|i'm)\s+([a-zA-Z]+(?:\s[a-zA-Z]+){0,3})",
    anonymized_text,
    re.IGNORECASE
)

    for name in name_patterns:
        fake_name = anonymize_name(name.strip())
        anonymized_text = re.sub(re.escape(name), fake_name, anonymized_text, flags=re.IGNORECASE)

    # =========================
    # 2️⃣ EMAIL Detection
    # =========================
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', anonymized_text)
    for email in emails:
        anonymized_text = anonymized_text.replace(email, anonymize_email(email))

    # =========================
    # 3️⃣ PHONE Detection
    # =========================
    phones = re.findall(r'\b\d{10}\b', anonymized_text)
    for phone in phones:
        anonymized_text = anonymized_text.replace(phone, anonymize_phone(phone))

    # =========================
    # 4️⃣ AADHAAR Detection
    # =========================
    aadhars = re.findall(r'\b\d{12}\b', anonymized_text)
    for aadhar in aadhars:
        anonymized_text = anonymized_text.replace(aadhar, anonymize_aadhar(aadhar))

    # =========================
    # 5️⃣ NAME Fallback (VERY IMPORTANT 🔥)
    # =========================

    name_patterns1 = re.findall(r'i am ([A-Za-z ]+)', anonymized_text, re.IGNORECASE)
    for name in name_patterns1:
        fake_name = anonymize_name(name.strip())
        anonymized_text = anonymized_text.replace(name.strip(), fake_name)

    name_patterns2 = re.findall(r'my name is ([A-Za-z ]+)', anonymized_text, re.IGNORECASE)
    for name in name_patterns2:
        fake_name = anonymize_name(name.strip())
        anonymized_text = anonymized_text.replace(name.strip(), fake_name)

    # =========================
    # 6️⃣ LOCATION Fallback
    # =========================

    location_patterns = re.findall(r'live in ([A-Za-z ]+)', anonymized_text, re.IGNORECASE)
    for loc in location_patterns:
        fake_loc = anonymize_address(loc.strip())
        anonymized_text = anonymized_text.replace(loc.strip(), fake_loc)

    return anonymized_text
# ===============================
# HOME PAGE
# ===============================

@app.route("/")
def home():
    username = session.get("username")
    if username:
        try:
            cursor.execute("INSERT INTO activity_logs (username, action) VALUES (%s, %s)", (username, "LOGOUT"))
            db.commit()
        except Exception:
            pass
    session.clear()
    return send_from_directory("../frontend", "login.html")


# ===============================
# REGISTER PAGE
# ===============================

@app.route("/register")
def register():
    return send_from_directory("../frontend", "register.html")


@app.route("/register-user", methods=["POST"])
def register_user():
    full_name        = request.form.get("full_name", "").strip()
    username         = request.form.get("username", "").strip()
    email            = request.form.get("email", "").strip()
    phone            = request.form.get("phone", "").strip()
    password         = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Basic server-side validation
    if not all([full_name, username, email, phone, password]):
        return redirect("/register?error=missing_fields")

    if password != confirm_password:
        return redirect("/register?error=password_mismatch")

    if len(password) < 6:
        return redirect("/register?error=weak_password")

    # Hash password with SHA-256
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor.execute(
            "INSERT INTO registered_users (full_name, username, email, phone, password) VALUES (%s, %s, %s, %s, %s)",
            (full_name, username, email, phone, hashed_pw)
        )
        db.commit()
        return redirect("/?registered=1")
    except mysql.connector.errors.IntegrityError:
        # Username already exists
        return redirect("/register?error=username_taken")
    except Exception as e:
        return f"<h3>Registration error: {str(e)}</h3>"


# ===============================
# LOGIN SYSTEM
# ===============================

@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role")

    if role == "admin":
        if username == "admin" and password == "Admin@123":
            session["username"] = username
            session["role"] = "admin"
            cursor.execute("INSERT INTO activity_logs (username, action) VALUES (%s, %s)", (username, "LOGIN"))
            db.commit()
            return redirect("/admin-dashboard")
        else:
            return redirect("/?error=invalid_admin")

    else:
        # Verify against registered_users table
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute(
            "SELECT username, full_name FROM registered_users WHERE username=%s AND password=%s",
            (username, hashed_pw)
        )
        user = cursor.fetchone()

        if user:
            session["username"] = username
            session["role"] = "user"
            cursor.execute("INSERT INTO activity_logs (username, action) VALUES (%s, %s)", (username, "LOGIN"))
            db.commit()
            return redirect("/user-dashboard")
        else:
            return redirect("/?error=invalid_user")


# ===============================
# USER DASHBOARD
# ===============================

@app.route("/user-dashboard")
def user_dashboard():

    if session.get("role") != "user":
        return "Access Denied"

    return send_from_directory("../frontend", "user_dashboard.html")


# ===============================
# ADMIN DASHBOARD
# ===============================

@app.route("/admin-dashboard")
def admin_dashboard():

    if session.get("role") != "admin":
        return "Access Denied"

    return send_from_directory("../frontend", "admin_dashboard.html")


# ===============================
# DATA FORM (USER ONLY)
# ===============================

@app.route("/data-form")
def data_form():

    if session.get("role") != "user":
        return "<h3>Only users can submit data</h3>"

    return send_from_directory("../frontend", "data_form.html")


# ===============================
# TEXT FORM (USER ONLY)
# ===============================

@app.route("/text-form")
def text_form():

    if session.get("role") != "user":
        return "<h3>Only users can anonymize text</h3>"

    return send_from_directory("../frontend", "text_form.html")


# ===============================
# TEXT ANONYMIZATION SUBMIT
# ===============================

@app.route("/anonymize-text", methods=["POST"])
def anonymize_text_route():

    username = session.get("username")

    text = request.form.get("text")

    anonymized_text = anonymize_text(text)

    cursor.execute("""
    INSERT INTO anonymized_text_records
    (username, original_text, anonymized_text)
    VALUES (%s,%s,%s)
    """, (username, text, anonymized_text))

    db.commit()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Text Anonymization Result — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
*, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
#vanta-bg {{ position:fixed; inset:0; z-index:0; }}
body {{
  font-family: 'Segoe UI', Arial, sans-serif;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: #050d1a;
  padding: 30px 20px;
}}
.container {{
  position: relative;
  z-index: 1;
  width: min(720px, 96vw);
  background: rgba(10,20,45,0.80);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(59,130,246,0.3);
  border-radius: 20px;
  padding: 40px 36px;
  box-shadow: 0 0 40px rgba(59,130,246,0.2), 0 20px 60px rgba(0,0,0,0.5);
  animation: fadeUp 0.6s ease both;
}}
@keyframes fadeUp {{
  from {{ opacity:0; transform:translateY(28px); }}
  to   {{ opacity:1; transform:translateY(0); }}
}}
.header {{
  text-align: center;
  margin-bottom: 28px;
}}
.header .icon {{ font-size:2.8rem; margin-bottom:10px; filter:drop-shadow(0 0 12px rgba(59,130,246,0.7)); }}
.header h1 {{ color:#f0f4ff; font-size:1.4rem; font-weight:700; }}
.header p {{ color:#64748b; font-size:0.84rem; margin-top:4px; }}
.section {{ margin-bottom:18px; }}
.section h2 {{
  font-size:0.72rem; font-weight:600; text-transform:uppercase;
  letter-spacing:0.06em; margin-bottom:8px; display:flex; align-items:center; gap:6px;
}}
.section h2.original {{ color:#ff8c42; }}
.section h2.anonymized {{ color:#22d3ee; }}
.text-box {{
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 12px;
  padding: 18px 20px;
  font-size:0.9rem; line-height:1.7;
  color:#e2e8f0;
}}
.text-box.anon {{ color:#67e8f9; border-color:rgba(34,211,238,0.25); }}
.back-link {{
  display:inline-flex; align-items:center; gap:6px;
  color:#3b82f6; font-size:0.88rem; text-decoration:none;
  font-weight:600; margin-top:10px;
  transition:color 0.2s, transform 0.2s;
}}
.back-link:hover {{ color:#06b6d4; transform:translateX(-3px); }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
<div class="container">
  <div class="header">
    <div class="icon">🔍</div>
    <h1>Text Anonymization Result</h1>
    <p>All personally identifiable information has been masked</p>
  </div>
  <div class="section">
    <h2 class="original">📄 Original Text</h2>
    <div class="text-box">{text}</div>
  </div>
  <div class="section">
    <h2 class="anonymized">🔒 Anonymized Text</h2>
    <div class="text-box anon">{anonymized_text}</div>
  </div>
  <a href="/user-dashboard" class="back-link">⬅ Back to Dashboard</a>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""


# ===============================
# STRUCTURED DATA SUBMISSION
# ===============================

@app.route("/submit-data", methods=["POST"])
def submit_data():

    username = session.get("username")

    name = request.form.get("name")
    email = request.form.get("email")
    aadhar = request.form.get("aadhar")
    phone = request.form.get("phone")
    address = request.form.get("address")

    # Validation
    if len(aadhar) != 12 or not aadhar.isdigit():
        return "Invalid Aadhaar Number"

    if len(phone) != 10 or not phone.isdigit():
        return "Invalid Phone Number"

    # Anonymization
    anon_name = anonymize_name(name)
    anon_email = anonymize_email(email)
    anon_aadhar = anonymize_aadhar(aadhar)
    anon_phone = anonymize_phone(phone)
    anon_address = anonymize_address(address)

    # Store in DB
    cursor.execute("""
    INSERT INTO anonymized_records
    (username,
    original_name, anonymized_name,
    original_email, anonymized_email,
    original_phone, anonymized_phone,
    original_aadhar, anonymized_aadhar,
    original_address, anonymized_address)

    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (

    username,
    name, anon_name,
    email, anon_email,
    phone, anon_phone,
    aadhar, anon_aadhar,
    address, anon_address

    ))

    db.commit()

    # ✅ FIX: Dynamic dashboard link
    dashboard_link = "/admin-dashboard" if session.get("role") == "admin" else "/user-dashboard"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Submission Result — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
*, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
#vanta-bg {{ position:fixed; inset:0; z-index:0; }}
body {{
  font-family: 'Segoe UI', Arial, sans-serif;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: #050d1a;
  padding: 30px 20px;
}}
.container {{
  position: relative;
  z-index: 1;
  width: min(700px, 96vw);
  background: rgba(10,20,45,0.80);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(59,130,246,0.3);
  border-radius: 20px;
  padding: 40px 36px;
  box-shadow: 0 0 40px rgba(59,130,246,0.2), 0 20px 60px rgba(0,0,0,0.5);
  animation: fadeUp 0.6s ease both;
}}
@keyframes fadeUp {{
  from {{ opacity:0; transform:translateY(28px); }}
  to   {{ opacity:1; transform:translateY(0); }}
}}
.header {{
  text-align: center;
  margin-bottom: 28px;
}}
.header .icon {{ font-size:2.8rem; margin-bottom:10px; filter:drop-shadow(0 0 12px rgba(59,130,246,0.7)); }}
.header h1 {{ color:#f0f4ff; font-size:1.4rem; font-weight:700; }}
.header p {{ color:#64748b; font-size:0.84rem; margin-top:4px; }}
.grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 24px;
}}
.box {{
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 14px;
  padding: 20px;
}}
.box h2 {{
  font-size:0.75rem; font-weight:600; color:#64748b;
  text-transform:uppercase; letter-spacing:0.06em;
  margin-bottom:14px; display:flex; align-items:center; gap:6px;
}}
.box h2.original {{ color:#ff8c42; }}
.box h2.anonymized {{ color:#22d3ee; }}
.field {{
  margin-bottom: 10px;
}}
.field .lbl {{
  font-size:0.68rem; color:#475569; text-transform:uppercase;
  letter-spacing:0.04em; margin-bottom:2px;
}}
.field .val {{
  font-size:0.88rem; color:#e2e8f0; font-weight:500;
  word-break: break-all;
}}
.field .val.anon {{ color:#67e8f9; }}
.back-link {{
  display:inline-flex; align-items:center; gap:6px;
  color:#3b82f6; font-size:0.88rem; text-decoration:none;
  font-weight:600;
  transition:color 0.2s, transform 0.2s;
  margin-top:4px;
}}
.back-link:hover {{ color:#06b6d4; transform:translateX(-3px); }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
<div class="container">
  <div class="header">
    <div class="icon">✅</div>
    <h1>Data Submitted Successfully</h1>
    <p>Your data has been anonymized and securely stored</p>
  </div>
  <div class="grid">
    <div class="box">
      <h2 class="original">📄 Original Data</h2>
      <div class="field"><div class="lbl">Name</div><div class="val">{name}</div></div>
      <div class="field"><div class="lbl">Email</div><div class="val">{email}</div></div>
      <div class="field"><div class="lbl">Phone</div><div class="val">{phone}</div></div>
      <div class="field"><div class="lbl">Aadhaar</div><div class="val">{aadhar}</div></div>
      <div class="field"><div class="lbl">Address</div><div class="val">{address}</div></div>
    </div>
    <div class="box">
      <h2 class="anonymized">🔒 Anonymized Data</h2>
      <div class="field"><div class="lbl">Name</div><div class="val anon">{anon_name}</div></div>
      <div class="field"><div class="lbl">Email</div><div class="val anon">{anon_email}</div></div>
      <div class="field"><div class="lbl">Phone</div><div class="val anon">{anon_phone}</div></div>
      <div class="field"><div class="lbl">Aadhaar</div><div class="val anon">{anon_aadhar}</div></div>
      <div class="field"><div class="lbl">Address</div><div class="val anon">{anon_address}</div></div>
    </div>
  </div>
  <a href="{dashboard_link}" class="back-link">⬅ Back to Dashboard</a>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""
# ===============================
# ADMIN VIEW STRUCTURED DATA
# ===============================

@app.route("/view-data")
def view_data():

    if session.get("role") != "admin":
        return "<h3>Access Denied. Admin Only.</h3>"

    cursor.execute("""
    SELECT 
    original_name, original_email, original_phone, original_aadhar, original_address,
    anonymized_name, anonymized_email, anonymized_phone, anonymized_aadhar, anonymized_address
    FROM anonymized_records
    """)

    rows = cursor.fetchall()

    dashboard_link = "/admin-dashboard" if session.get("role") == "admin" else "/user-dashboard"

    rows_html = ""
    for row in rows:
        rows_html += f"""
        <tr>
          <td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td>
          <td>{row[5]}</td><td>{row[6]}</td><td>{row[7]}</td><td>{row[8]}</td><td>{row[9]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>View Records — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
*, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
#vanta-bg {{ position:fixed; inset:0; z-index:0; }}
body {{
  font-family: 'Segoe UI', Arial, sans-serif;
  min-height: 100vh;
  background: #050d1a;
  display: flex;
}}
.sidebar {{
  z-index: 10;
  width: 230px;
  flex-shrink: 0;
  background: rgba(5,13,30,0.92);
  backdrop-filter: blur(20px);
  border-right: 1px solid rgba(59,130,246,0.18);
  padding: 24px 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  height: 100vh;
  position: sticky;
  top: 0;
}}
.sidebar-brand {{
  display: flex; align-items: center; gap: 10px;
  padding: 8px 10px 20px;
  border-bottom: 1px solid rgba(59,130,246,0.15);
  margin-bottom: 10px;
}}
.sidebar-brand .b-icon {{ font-size:1.5rem; }}
.sidebar-brand .b-name {{ font-size:0.9rem; font-weight:700; color:#f0f4ff; }}
.sidebar-brand .b-sub  {{ font-size:0.68rem; color:#64748b; }}
.sidebar a {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 14px; border-radius: 10px;
  color: #64748b; text-decoration: none;
  font-size: 0.87rem; font-weight: 500;
  transition: background 0.2s, color 0.2s;
}}
.sidebar a:hover, .sidebar a.active {{
  background: rgba(59,130,246,0.14);
  color: #f0f4ff;
}}
.sidebar-foot {{
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid rgba(59,130,246,0.12);
}}
.main {{
  flex: 1;
  padding: 24px;
  position: relative;
  z-index: 1;
  overflow: auto;
}}
.topbar {{
  background: rgba(10,20,45,0.7);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 14px;
  padding: 15px 22px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 22px;
}}
.topbar h2 {{ color:#f0f4ff; font-size:1.1rem; font-weight:700; }}
.back-link {{
  display:inline-flex; align-items:center; gap:6px;
  color:#3b82f6; font-size:0.85rem; text-decoration:none; font-weight:600;
  transition:color 0.2s;
}}
.back-link:hover {{ color:#06b6d4; }}
.table-wrap {{
  background: rgba(10,20,45,0.70);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 14px;
  overflow: auto;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.83rem;
}}
thead tr {{
  background: rgba(59,130,246,0.1);
}}
thead th {{
  padding: 12px 14px;
  text-align: left;
  font-size:0.7rem; font-weight:600; color:#64748b;
  text-transform:uppercase; letter-spacing:0.05em;
  border-bottom: 1px solid rgba(59,130,246,0.15);
}}
thead th.orig {{ color:#ff8c42; }}
thead th.anon {{ color:#22d3ee; }}
.group-header th {{
  padding: 8px 14px;
  font-size:0.72rem; font-weight:700;
  letter-spacing:0.08em;
  text-align:center;
  text-transform:uppercase;
}}
tbody tr {{
  border-bottom: 1px solid rgba(255,255,255,0.04);
  transition: background 0.15s;
}}
tbody tr:hover {{ background: rgba(59,130,246,0.07); }}
tbody td {{
  padding: 10px 14px;
  color: #cbd5e1;
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
tbody tr td:nth-child(n+6) {{ color: #67e8f9; }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
<div class="sidebar">
  <div class="sidebar-brand">
    <span class="b-icon">🔏</span>
    <div>
      <div class="b-name">PII System</div>
      <div class="b-sub">Admin Panel</div>
    </div>
  </div>
  <a href="/admin-dashboard">📊 &nbsp;Dashboard</a>
  <a href="/view-data" class="active">🗄️ &nbsp;View Records</a>
  <a href="/admin-text-data">📝 &nbsp;Text Records</a>
  <a href="/download-options">⬇️ &nbsp;Download Data</a>
  <a href="/admin-users">👥 &nbsp;Manage Users</a>
  <a href="/admin-logs">📋 &nbsp;Activity Logs</a>
  <div class="sidebar-foot">
    <a href="/">⬅ &nbsp;Logout</a>
  </div>
</div>
<div class="main">
  <div class="topbar">
    <h2>🗄️ Data Comparison — Admin View</h2>
    <a href="{dashboard_link}" class="back-link">⬅ Back to Dashboard</a>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr class="group-header">
          <th colspan="5" class="orig">📄 Original Data</th>
          <th colspan="5" class="anon">🔒 Anonymized Data</th>
        </tr>
        <tr>
          <th class="orig">Name</th><th class="orig">Email</th><th class="orig">Phone</th><th class="orig">Aadhaar</th><th class="orig">Address</th>
          <th class="anon">Name</th><th class="anon">Email</th><th class="anon">Phone</th><th class="anon">Aadhaar</th><th class="anon">Address</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""
# ===============================
# ADMIN VIEW TEXT DATA
# ===============================

@app.route("/dashboard-stats")
def dashboard_stats():

    if session.get("role") != "admin":
        return {"error": "Unauthorized"}

    cursor.execute("SELECT COUNT(*) FROM anonymized_records")
    total_records = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM anonymized_text_records")
    total_texts = cursor.fetchone()[0]

    # Count total unique users from anonymized_records (this is the user data table)
    cursor.execute("SELECT COUNT(*) FROM anonymized_records")
    users = cursor.fetchone()[0]

    return {
        "records": total_records,
        "texts": total_texts,
        "users": users
    }

@app.route("/user-dashboard-stats")
def user_dashboard_stats():

    if session.get("role") != "user":
        return {"error": "Unauthorized"}

    username = session.get("username")

    cursor.execute("SELECT COUNT(*) FROM anonymized_records WHERE username = %s", (username,))
    my_records = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM anonymized_text_records WHERE username = %s", (username,))
    my_texts = cursor.fetchone()[0]

    # Total users = total records in the system
    cursor.execute("SELECT COUNT(*) FROM anonymized_records")
    total_users = cursor.fetchone()[0]

    return {
        "records": my_records,
        "texts": my_texts,
        "users": total_users
    }

@app.route("/admin-text-data")
def admin_text_data():

    if session.get("role") != "admin":
        return "<h3>Access Denied</h3>"

    cursor.execute("SELECT * FROM anonymized_text_records")

    rows = cursor.fetchall()

    rows_html = ""
    for row in rows:
        rows_html += f"""
        <tr>
          <td>{row[1]}</td>
          <td>{row[2]}</td>
          <td>{row[3]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Text Records — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
*, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
#vanta-bg {{ position:fixed; inset:0; z-index:0; }}
body {{
  font-family: 'Segoe UI', Arial, sans-serif;
  min-height: 100vh;
  background: #050d1a;
  display: flex;
}}
.sidebar {{
  z-index: 10;
  width: 230px;
  flex-shrink: 0;
  background: rgba(5,13,30,0.92);
  backdrop-filter: blur(20px);
  border-right: 1px solid rgba(59,130,246,0.18);
  padding: 24px 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  height: 100vh;
  position: sticky;
  top: 0;
}}
.sidebar-brand {{
  display: flex; align-items: center; gap: 10px;
  padding: 8px 10px 20px;
  border-bottom: 1px solid rgba(59,130,246,0.15);
  margin-bottom: 10px;
}}
.sidebar-brand .b-icon {{ font-size:1.5rem; }}
.sidebar-brand .b-name {{ font-size:0.9rem; font-weight:700; color:#f0f4ff; }}
.sidebar-brand .b-sub  {{ font-size:0.68rem; color:#64748b; }}
.sidebar a {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 14px; border-radius: 10px;
  color: #64748b; text-decoration: none;
  font-size: 0.87rem; font-weight: 500;
  transition: background 0.2s, color 0.2s;
}}
.sidebar a:hover, .sidebar a.active {{
  background: rgba(59,130,246,0.14);
  color: #f0f4ff;
}}
.sidebar-foot {{
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid rgba(59,130,246,0.12);
}}
.main {{
  flex: 1;
  padding: 24px;
  position: relative;
  z-index: 1;
  overflow: auto;
}}
.topbar {{
  background: rgba(10,20,45,0.7);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 14px;
  padding: 15px 22px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 22px;
}}
.topbar h2 {{ color:#f0f4ff; font-size:1.1rem; font-weight:700; }}
.back-link {{
  display:inline-flex; align-items:center; gap:6px;
  color:#3b82f6; font-size:0.85rem; text-decoration:none; font-weight:600;
  transition:color 0.2s;
}}
.back-link:hover {{ color:#06b6d4; }}
.table-wrap {{
  background: rgba(10,20,45,0.70);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(59,130,246,0.2);
  border-radius: 14px;
  overflow: auto;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.84rem;
}}
thead th {{
  padding: 13px 16px;
  text-align: left;
  font-size:0.7rem; font-weight:600; color:#64748b;
  text-transform:uppercase; letter-spacing:0.05em;
  background: rgba(59,130,246,0.08);
  border-bottom: 1px solid rgba(59,130,246,0.15);
}}
thead th:first-child {{ color:#94a3b8; }}
thead th:nth-child(2) {{ color:#ff8c42; }}
thead th:nth-child(3) {{ color:#22d3ee; }}
tbody tr {{
  border-bottom: 1px solid rgba(255,255,255,0.04);
  transition: background 0.15s;
}}
tbody tr:hover {{ background: rgba(59,130,246,0.07); }}
tbody td {{
  padding: 12px 16px;
  color: #cbd5e1;
  vertical-align: top;
  max-width: 400px;
  word-break: break-word;
  line-height: 1.5;
}}
tbody td:first-child {{
  color: #94a3b8;
  font-weight: 600;
  white-space: nowrap;
  width: 90px;
}}
tbody td:nth-child(3) {{ color: #67e8f9; }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
<div class="sidebar">
  <div class="sidebar-brand">
    <span class="b-icon">🔏</span>
    <div>
      <div class="b-name">PII System</div>
      <div class="b-sub">Admin Panel</div>
    </div>
  </div>
  <a href="/admin-dashboard">📊 &nbsp;Dashboard</a>
  <a href="/view-data">🗄️ &nbsp;View Records</a>
  <a href="/admin-text-data" class="active">📝 &nbsp;Text Records</a>
  <a href="/download-options">⬇️ &nbsp;Download Data</a>
  <a href="/admin-users">👥 &nbsp;Manage Users</a>
  <a href="/admin-logs">📋 &nbsp;Activity Logs</a>
  <div class="sidebar-foot">
    <a href="/">⬅ &nbsp;Logout</a>
  </div>
</div>
<div class="main">
  <div class="topbar">
    <h2>📝 Text Anonymization Records</h2>
    <a href="/admin-dashboard" class="back-link">⬅ Back to Dashboard</a>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Original Text</th>
          <th>Anonymized Text</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""



# ===============================
# HOW IT WORKS (USER)
# ===============================

@app.route("/how-it-works")
def how_it_works():
    if session.get("role") != "user":
        return redirect("/")
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>How It Works — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
#vanta-bg { position:fixed; inset:0; z-index:0; }
body { font-family: 'Segoe UI', Arial, sans-serif; min-height:100vh; display:flex; background:#050d1a; }
.sidebar { z-index:10; width:230px; flex-shrink:0; background:rgba(5,13,30,0.92); backdrop-filter:blur(20px); border-right:1px solid rgba(59,130,246,0.18); padding:24px 16px; display:flex; flex-direction:column; gap:4px; height:100vh; position:sticky; top:0; }
.sidebar-brand { display:flex; align-items:center; gap:10px; padding:8px 10px 20px; border-bottom:1px solid rgba(59,130,246,0.15); margin-bottom:10px; }
.sidebar-brand .b-icon { font-size:1.5rem; }
.sidebar-brand .b-name { font-size:0.9rem; font-weight:700; color:#f0f4ff; }
.sidebar-brand .b-sub  { font-size:0.68rem; color:#64748b; }
.sidebar a { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:10px; color:#64748b; text-decoration:none; font-size:0.87rem; font-weight:500; transition:background 0.2s, color 0.2s; }
.sidebar a:hover, .sidebar a.active { background:rgba(59,130,246,0.14); color:#f0f4ff; }
.sidebar-foot { margin-top:auto; padding-top:16px; border-top:1px solid rgba(59,130,246,0.12); }
.main { flex:1; padding:24px; position:relative; z-index:1; overflow-y:auto; display:flex; align-items:flex-start; justify-content:center; }
.card { width:min(760px,100%); background:rgba(10,20,45,0.80); backdrop-filter:blur(16px); border:1px solid rgba(59,130,246,0.3); border-radius:20px; padding:40px 40px; box-shadow:0 0 40px rgba(59,130,246,0.2); animation:fadeUp 0.6s ease both; margin-top:20px; }
@keyframes fadeUp { from{opacity:0;transform:translateY(28px)} to{opacity:1;transform:translateY(0)} }
.card-header { text-align:center; margin-bottom:32px; }
.card-header .icon { font-size:3rem; margin-bottom:12px; filter:drop-shadow(0 0 12px rgba(59,130,246,0.7)); }
.card-header h1 { color:#f0f4ff; font-size:1.5rem; font-weight:700; }
.card-header p { color:#64748b; font-size:0.85rem; margin-top:6px; }
.step { display:flex; gap:16px; margin-bottom:22px; align-items:flex-start; }
.step-num { min-width:36px; height:36px; border-radius:50%; background:linear-gradient(135deg,#3b82f6,#06b6d4); display:flex; align-items:center; justify-content:center; color:#fff; font-weight:700; font-size:0.9rem; flex-shrink:0; }
.step-body h3 { color:#f0f4ff; font-size:0.95rem; font-weight:600; margin-bottom:4px; }
.step-body p { color:#94a3b8; font-size:0.85rem; line-height:1.6; }
.sub-list { margin-top:8px; display:flex; flex-wrap:wrap; gap:8px; }
.tag { background:rgba(59,130,246,0.12); border:1px solid rgba(59,130,246,0.25); border-radius:20px; padding:4px 12px; font-size:0.78rem; color:#93c5fd; }
.divider { border:none; border-top:1px solid rgba(59,130,246,0.12); margin:28px 0; }
.back-link { display:inline-flex; align-items:center; gap:6px; color:#3b82f6; font-size:0.88rem; text-decoration:none; font-weight:600; transition:color 0.2s, transform 0.2s; }
.back-link:hover { color:#06b6d4; transform:translateX(-3px); }
</style>
</head>
<body>
<div id="vanta-bg"></div>
<div class="sidebar">
  <div class="sidebar-brand">
    <span class="b-icon">🔏</span>
    <div><div class="b-name">PII System</div><div class="b-sub">User Panel</div></div>
  </div>
  <a href="/user-dashboard">📊 &nbsp;Dashboard</a>
  <a href="/data-form">📋 &nbsp;Submit Data</a>
  <a href="/text-form">✏️ &nbsp;Text Anonymization</a>
  <a href="/how-it-works" class="active">❓ &nbsp;How It Works</a>
  <a href="/about">ℹ️ &nbsp;About</a>
  <div class="sidebar-foot"><a href="/">⬅ &nbsp;Logout</a></div>
</div>
<div class="main">
  <div class="card">
    <div class="card-header">
      <div class="icon">⚙️</div>
      <h1>How This System Works</h1>
      <p>A step-by-step guide to PII detection and anonymization</p>
    </div>
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <h3>User Enters Personal or Text Data</h3>
        <p>You submit a form with structured data (name, email, phone, Aadhaar, address) or paste free-form text containing personal information.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <h3>System Detects Sensitive Information</h3>
        <p>The system automatically identifies the following PII categories:</p>
        <div class="sub-list">
          <span class="tag">👤 Names</span>
          <span class="tag">📧 Email IDs</span>
          <span class="tag">📞 Phone Numbers</span>
          <span class="tag">🪪 Aadhaar Numbers</span>
          <span class="tag">📍 Locations</span>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <h3>Data is Anonymized Using Multiple Techniques</h3>
        <div class="sub-list">
          <span class="tag">🔐 SHA-256 Hashing</span>
          <span class="tag">🔎 Pattern Matching (Regex)</span>
          <span class="tag">🧠 NLP-based Detection (spaCy)</span>
        </div>
      </div>
    </div>
    <div class="step">
      <div class="step-num">4</div>
      <div class="step-body">
        <h3>Secure Storage</h3>
        <p>Both the original and anonymized data are securely stored in the database. Raw PII is never exposed outside the system.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">5</div>
      <div class="step-body">
        <h3>Role-based Access Control</h3>
        <p>Users can only view their own data. Admins can view the complete system data including original and anonymized records side-by-side.</p>
      </div>
    </div>
    <hr class="divider">
    <a href="/user-dashboard" class="back-link">⬅ Back to Dashboard</a>
  </div>
</div>
<script>
VANTA.NET({
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
});
</script>
</body>
</html>"""


# ===============================
# ABOUT PAGE (USER)
# ===============================

@app.route("/about")
def about():
    if session.get("role") != "user":
        return redirect("/")
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>About — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
#vanta-bg { position:fixed; inset:0; z-index:0; }
body { font-family: 'Segoe UI', Arial, sans-serif; min-height:100vh; display:flex; background:#050d1a; }
.sidebar { z-index:10; width:230px; flex-shrink:0; background:rgba(5,13,30,0.92); backdrop-filter:blur(20px); border-right:1px solid rgba(59,130,246,0.18); padding:24px 16px; display:flex; flex-direction:column; gap:4px; height:100vh; position:sticky; top:0; }
.sidebar-brand { display:flex; align-items:center; gap:10px; padding:8px 10px 20px; border-bottom:1px solid rgba(59,130,246,0.15); margin-bottom:10px; }
.sidebar-brand .b-icon { font-size:1.5rem; }
.sidebar-brand .b-name { font-size:0.9rem; font-weight:700; color:#f0f4ff; }
.sidebar-brand .b-sub  { font-size:0.68rem; color:#64748b; }
.sidebar a { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:10px; color:#64748b; text-decoration:none; font-size:0.87rem; font-weight:500; transition:background 0.2s, color 0.2s; }
.sidebar a:hover, .sidebar a.active { background:rgba(59,130,246,0.14); color:#f0f4ff; }
.sidebar-foot { margin-top:auto; padding-top:16px; border-top:1px solid rgba(59,130,246,0.12); }
.main { flex:1; padding:24px; position:relative; z-index:1; overflow-y:auto; display:flex; align-items:flex-start; justify-content:center; }
.card { width:min(760px,100%); background:rgba(10,20,45,0.80); backdrop-filter:blur(16px); border:1px solid rgba(59,130,246,0.3); border-radius:20px; padding:40px 40px; box-shadow:0 0 40px rgba(59,130,246,0.2); animation:fadeUp 0.6s ease both; margin-top:20px; }
@keyframes fadeUp { from{opacity:0;transform:translateY(28px)} to{opacity:1;transform:translateY(0)} }
.card-header { text-align:center; margin-bottom:32px; }
.card-header .icon { font-size:3rem; margin-bottom:12px; filter:drop-shadow(0 0 12px rgba(59,130,246,0.7)); }
.card-header h1 { color:#f0f4ff; font-size:1.5rem; font-weight:700; }
.card-header p { color:#64748b; font-size:0.85rem; margin-top:6px; }
.desc { color:#94a3b8; font-size:0.92rem; line-height:1.8; margin-bottom:22px; }
.features-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:28px; }
.feat { background:rgba(59,130,246,0.07); border:1px solid rgba(59,130,246,0.2); border-radius:14px; padding:18px 20px; }
.feat .f-icon { font-size:1.6rem; margin-bottom:8px; }
.feat h3 { color:#f0f4ff; font-size:0.92rem; font-weight:600; margin-bottom:4px; }
.feat p { color:#64748b; font-size:0.82rem; line-height:1.5; }
.divider { border:none; border-top:1px solid rgba(59,130,246,0.12); margin:24px 0; }
.back-link { display:inline-flex; align-items:center; gap:6px; color:#3b82f6; font-size:0.88rem; text-decoration:none; font-weight:600; transition:color 0.2s; }
.back-link:hover { color:#06b6d4; transform:translateX(-3px); }
</style>
</head>
<body>
<div id="vanta-bg"></div>
<div class="sidebar">
  <div class="sidebar-brand">
    <span class="b-icon">🔏</span>
    <div><div class="b-name">PII System</div><div class="b-sub">User Panel</div></div>
  </div>
  <a href="/user-dashboard">📊 &nbsp;Dashboard</a>
  <a href="/data-form">📋 &nbsp;Submit Data</a>
  <a href="/text-form">✏️ &nbsp;Text Anonymization</a>
  <a href="/how-it-works">❓ &nbsp;How It Works</a>
  <a href="/about" class="active">ℹ️ &nbsp;About</a>
  <div class="sidebar-foot"><a href="/">⬅ &nbsp;Logout</a></div>
</div>
<div class="main">
  <div class="card">
    <div class="card-header">
      <div class="icon">🛡️</div>
      <h1>About This Project</h1>
      <p>PII Anonymization System — Privacy by Design</p>
    </div>
    <p class="desc">
      This PII Anonymization System is designed to protect sensitive user data. It detects and anonymizes personal information like names, phone numbers, email IDs, Aadhaar numbers, and locations using advanced techniques such as pattern matching and Natural Language Processing (NLP).
    </p>
    <p class="desc">
      The system ensures that sensitive data is securely stored in anonymized form, while allowing authorized admin users to view both original and anonymized data for auditing purposes.
    </p>
    <div class="features-grid">
      <div class="feat">
        <div class="f-icon">📋</div>
        <h3>Structured Data Anonymization</h3>
        <p>Form-based personal data is detected and replaced with anonymized tokens before storage.</p>
      </div>
      <div class="feat">
        <div class="f-icon">✏️</div>
        <h3>Text-based Data Anonymization</h3>
        <p>Free-form text is scanned and all PII entities are masked using NLP and regex patterns.</p>
      </div>
      <div class="feat">
        <div class="f-icon">🔐</div>
        <h3>Role-based Access (Admin/User)</h3>
        <p>Users see only their own records. Admins have full visibility with export and management tools.</p>
      </div>
      <div class="feat">
        <div class="f-icon">🗄️</div>
        <h3>Secure Data Storage</h3>
        <p>All records are stored in a secured database. Original data is never exposed in the UI.</p>
      </div>
    </div>
    <hr class="divider">
    <a href="/user-dashboard" class="back-link">⬅ Back to Dashboard</a>
  </div>
</div>
<script>
VANTA.NET({
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
});
</script>
</body>
</html>"""


# ===============================
# DOWNLOAD ANONYMIZED DATA (ADMIN)
# ===============================

ADMIN_SIDEBAR = """
<div class="sidebar">
  <div class="sidebar-brand">
    <span class="b-icon">🔏</span>
    <div><div class="b-name">PII System</div><div class="b-sub">Admin Panel</div></div>
  </div>
  <a href="/admin-dashboard">📊 &nbsp;Dashboard</a>
  <a href="/view-data">🗄️ &nbsp;View Records</a>
  <a href="/admin-text-data">📝 &nbsp;Text Records</a>
  <a href="/download-options" {dl_active}>⬇️ &nbsp;Download Data</a>
  <a href="/admin-users" {usr_active}>👥 &nbsp;Manage Users</a>
  <a href="/admin-logs" {log_active}>📋 &nbsp;Activity Logs</a>
  <div class="sidebar-foot"><a href="/">⬅ &nbsp;Logout</a></div>
</div>"""

ADMIN_SIDEBAR_CSS = """
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
#vanta-bg { position:fixed; inset:0; z-index:0; }
body { font-family: 'Segoe UI', Arial, sans-serif; min-height:100vh; display:flex; background:#050d1a; }
.sidebar { z-index:10; width:230px; flex-shrink:0; background:rgba(5,13,30,0.92); backdrop-filter:blur(20px); border-right:1px solid rgba(59,130,246,0.18); padding:24px 16px; display:flex; flex-direction:column; gap:4px; height:100vh; position:sticky; top:0; }
.sidebar-brand { display:flex; align-items:center; gap:10px; padding:8px 10px 20px; border-bottom:1px solid rgba(59,130,246,0.15); margin-bottom:10px; }
.sidebar-brand .b-icon { font-size:1.5rem; }
.sidebar-brand .b-name { font-size:0.9rem; font-weight:700; color:#f0f4ff; }
.sidebar-brand .b-sub  { font-size:0.68rem; color:#64748b; }
.sidebar a { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:10px; color:#64748b; text-decoration:none; font-size:0.87rem; font-weight:500; transition:background 0.2s, color 0.2s; }
.sidebar a:hover, .sidebar a.active { background:rgba(59,130,246,0.14); color:#f0f4ff; }
.sidebar-foot { margin-top:auto; padding-top:16px; border-top:1px solid rgba(59,130,246,0.12); }
.main { flex:1; padding:24px; position:relative; z-index:1; overflow-y:auto; display:flex; align-items:flex-start; justify-content:center; }
.topbar { background:rgba(10,20,45,0.7); backdrop-filter:blur(12px); border:1px solid rgba(59,130,246,0.2); border-radius:14px; padding:15px 22px; display:flex; justify-content:space-between; align-items:center; margin-bottom:22px; width:100%; }
.topbar h2 { color:#f0f4ff; font-size:1.1rem; font-weight:700; }
.main-inner { flex:1; display:flex; flex-direction:column; width:100%; }
"""

VANTA_SCRIPTS = """
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<script>
VANTA.NET({
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
});
</script>"""


@app.route("/download-options")
def download_options():
    if session.get("role") != "admin":
        return redirect("/")
    sidebar = ADMIN_SIDEBAR.format(dl_active='class="active"', usr_active='', log_active='')
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Download Data — PII Anonymization System</title>
{VANTA_SCRIPTS.split('<script>')[0]}
<style>
{ADMIN_SIDEBAR_CSS}
.card {{ background:rgba(10,20,45,0.80); backdrop-filter:blur(16px); border:1px solid rgba(59,130,246,0.3); border-radius:20px; padding:36px 36px; box-shadow:0 0 40px rgba(59,130,246,0.2); animation:fadeUp 0.6s ease both; width:min(620px,100%); }}
@keyframes fadeUp {{ from{{opacity:0;transform:translateY(28px)}} to{{opacity:1;transform:translateY(0)}} }}
.card-header {{ text-align:center; margin-bottom:32px; }}
.card-header .icon {{ font-size:2.8rem; margin-bottom:10px; filter:drop-shadow(0 0 12px rgba(59,130,246,0.7)); }}
.card-header h1 {{ color:#f0f4ff; font-size:1.4rem; font-weight:700; }}
.card-header p {{ color:#64748b; font-size:0.84rem; margin-top:4px; }}
.section-title {{ font-size:0.75rem; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.07em; margin-bottom:12px; margin-top:24px; }}
.dl-group {{ background:rgba(255,255,255,0.03); border:1px solid rgba(59,130,246,0.15); border-radius:14px; padding:20px 22px; margin-bottom:16px; }}
.dl-group h3 {{ color:#f0f4ff; font-size:0.95rem; font-weight:600; margin-bottom:14px; display:flex; align-items:center; gap:8px; }}
.format-row {{ display:flex; gap:10px; flex-wrap:wrap; }}
.dl-btn {{ display:inline-flex; align-items:center; gap:8px; padding:10px 20px; border-radius:10px; font-size:0.85rem; font-weight:600; text-decoration:none; transition:opacity 0.2s, transform 0.2s; cursor:pointer; border:none; }}
.dl-btn:hover {{ opacity:0.85; transform:translateY(-2px); }}
.btn-csv {{ background:linear-gradient(135deg,#3b82f6,#06b6d4); color:#fff; }}
.btn-excel {{ background:linear-gradient(135deg,#22c55e,#16a34a); color:#fff; }}
.btn-pdf {{ background:linear-gradient(135deg,#ef4444,#dc2626); color:#fff; }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
{sidebar}
<div class="main">
  <div class="card">
    <div class="card-header">
      <div class="icon">⬇️</div>
      <h1>Download Anonymized Data</h1>
      <p>Export anonymized records in your preferred format</p>
    </div>
    <div class="dl-group">
      <h3>📋 Form Data</h3>
      <div class="format-row">
        <a href="/download/form/csv" class="dl-btn btn-csv">📄 CSV</a>
        <a href="/download/form/excel" class="dl-btn btn-excel">📊 Excel</a>
        <a href="/download/form/pdf" class="dl-btn btn-pdf">📑 PDF</a>
      </div>
    </div>
    <div class="dl-group">
      <h3>✏️ Text Data</h3>
      <div class="format-row">
        <a href="/download/text/csv" class="dl-btn btn-csv">📄 CSV</a>
        <a href="/download/text/excel" class="dl-btn btn-excel">📊 Excel</a>
        <a href="/download/text/pdf" class="dl-btn btn-pdf">📑 PDF</a>
      </div>
    </div>
  </div>
</div>
{VANTA_SCRIPTS.split('<script>')[0]}
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""


@app.route("/download/form/<fmt>")
def download_form_data(fmt):
    if session.get("role") != "admin":
        return redirect("/")
    cursor.execute("SELECT anonymized_name, anonymized_email, anonymized_phone, anonymized_aadhar, anonymized_address FROM anonymized_records")
    rows = cursor.fetchall()
    headers = ["Name", "Email", "Phone", "Aadhaar", "Address"]

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=anonymized_form_data.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    elif fmt == "excel":
        try:
            import openpyxl
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Anonymized Form Data"
            ws.append(headers)
            for row in rows:
                ws.append(list(row))
            output = io.BytesIO()
            wb.save(output)
            output.seek(0)
            response = make_response(output.read())
            response.headers["Content-Disposition"] = "attachment; filename=anonymized_form_data.xlsx"
            response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            return response
        except ImportError:
            return "openpyxl not installed. Run: pip install openpyxl", 500

    elif fmt == "pdf":
        try:
            from reportlab.lib.pagesizes import letter, landscape
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            output = io.BytesIO()
            doc = SimpleDocTemplate(output, pagesize=landscape(letter))
            data = [headers] + [list(r) for r in rows]
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f0f4ff"), colors.white]),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#ccddee")),
                ("PADDING",    (0,0), (-1,-1), 8),
            ]))
            doc.build([t])
            output.seek(0)
            response = make_response(output.read())
            response.headers["Content-Disposition"] = "attachment; filename=anonymized_form_data.pdf"
            response.headers["Content-Type"] = "application/pdf"
            return response
        except ImportError:
            return "reportlab not installed. Run: pip install reportlab", 500
    return "Unknown format", 400


@app.route("/download/text/<fmt>")
def download_text_data(fmt):
    if session.get("role") != "admin":
        return redirect("/")
    cursor.execute("SELECT username, anonymized_text FROM anonymized_text_records")
    rows = cursor.fetchall()
    headers = ["User", "Anonymized Text"]

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=anonymized_text_data.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    elif fmt == "excel":
        try:
            import openpyxl
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Anonymized Text Data"
            ws.append(headers)
            for row in rows:
                ws.append(list(row))
            output = io.BytesIO()
            wb.save(output)
            output.seek(0)
            response = make_response(output.read())
            response.headers["Content-Disposition"] = "attachment; filename=anonymized_text_data.xlsx"
            response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            return response
        except ImportError:
            return "openpyxl not installed. Run: pip install openpyxl", 500

    elif fmt == "pdf":
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
            from reportlab.lib import colors
            output = io.BytesIO()
            doc = SimpleDocTemplate(output, pagesize=letter)
            data = [headers] + [list(r) for r in rows]
            t = Table(data, colWidths=[80, 400])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f0f4ff"), colors.white]),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#ccddee")),
                ("PADDING",    (0,0), (-1,-1), 8),
                ("WORDWRAP",   (1,1), (1,-1), True),
            ]))
            doc.build([t])
            output.seek(0)
            response = make_response(output.read())
            response.headers["Content-Disposition"] = "attachment; filename=anonymized_text_data.pdf"
            response.headers["Content-Type"] = "application/pdf"
            return response
        except ImportError:
            return "reportlab not installed. Run: pip install reportlab", 500
    return "Unknown format", 400


# ===============================
# MANAGE USERS (ADMIN)
# ===============================

@app.route("/admin-users")
def admin_users():
    if session.get("role") != "admin":
        return redirect("/")
    cursor.execute("""
        SELECT id, original_name, original_email, original_phone
        FROM anonymized_records
        ORDER BY id
    """)
    rows = cursor.fetchall()
    sidebar = ADMIN_SIDEBAR.format(dl_active='', usr_active='class="active"', log_active='')

    rows_html = ""
    for row in rows:
        rows_html += f"""
        <tr>
          <td>{row[0]}</td>
          <td>{row[1]}</td>
          <td>{row[2]}</td>
          <td>{row[3]}</td>
          <td>
            <a href="/admin-update/{row[0]}" class="btn btn-update">✏️ Update</a>
            <a href="/admin-delete/{row[0]}" class="btn btn-delete" onclick="return confirm('Delete this record?')">🗑️ Delete</a>
          </td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Manage Users — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
{ADMIN_SIDEBAR_CSS}
.topbar {{ background:rgba(10,20,45,0.7); backdrop-filter:blur(12px); border:1px solid rgba(59,130,246,0.2); border-radius:14px; padding:15px 22px; display:flex; justify-content:space-between; align-items:center; margin-bottom:22px; }}
.topbar h2 {{ color:#f0f4ff; font-size:1.1rem; font-weight:700; }}
.table-wrap {{ background:rgba(10,20,45,0.70); backdrop-filter:blur(12px); border:1px solid rgba(59,130,246,0.2); border-radius:14px; overflow:auto; }}
table {{ width:100%; border-collapse:collapse; font-size:0.84rem; }}
thead th {{ padding:13px 16px; text-align:left; font-size:0.7rem; font-weight:600; color:#64748b; text-transform:uppercase; letter-spacing:0.05em; background:rgba(59,130,246,0.08); border-bottom:1px solid rgba(59,130,246,0.15); }}
tbody tr {{ border-bottom:1px solid rgba(255,255,255,0.04); transition:background 0.15s; }}
tbody tr:hover {{ background:rgba(59,130,246,0.07); }}
tbody td {{ padding:11px 16px; color:#cbd5e1; }}
tbody td:first-child {{ color:#64748b; font-weight:600; width:50px; }}
.btn {{ display:inline-flex; align-items:center; gap:5px; padding:6px 14px; border-radius:8px; font-size:0.78rem; font-weight:600; text-decoration:none; transition:opacity 0.2s, transform 0.2s; margin-right:6px; }}
.btn:hover {{ opacity:0.85; transform:translateY(-1px); }}
.btn-update {{ background:rgba(234,179,8,0.15); border:1px solid rgba(234,179,8,0.4); color:#fbbf24; }}
.btn-delete {{ background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.35); color:#f87171; }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
{sidebar}
<div class="main">
  <div style="flex:1; display:flex; flex-direction:column; width:100%;">
    <div class="topbar">
      <h2>👥 User Management</h2>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""


@app.route("/admin-delete/<int:record_id>")
def admin_delete(record_id):
    if session.get("role") != "admin":
        return redirect("/")
    cursor.execute("DELETE FROM anonymized_records WHERE id = %s", (record_id,))
    db.commit()
    return redirect("/admin-users")


@app.route("/admin-update/<int:record_id>", methods=["GET", "POST"])
def admin_update(record_id):
    if session.get("role") != "admin":
        return redirect("/")
    sidebar = ADMIN_SIDEBAR.format(dl_active='', usr_active='class="active"', log_active='')

    if request.method == "POST":
        new_name  = request.form.get("name")
        new_email = request.form.get("email")
        new_phone = request.form.get("phone")
        cursor.execute("""
            UPDATE anonymized_records
            SET original_name=%s, original_email=%s, original_phone=%s
            WHERE id=%s
        """, (new_name, new_email, new_phone, record_id))
        db.commit()
        return redirect("/admin-users")

    cursor.execute("SELECT id, original_name, original_email, original_phone FROM anonymized_records WHERE id=%s", (record_id,))
    row = cursor.fetchone()
    if not row:
        return redirect("/admin-users")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Update User — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
{ADMIN_SIDEBAR_CSS}
.card {{ background:rgba(10,20,45,0.80); backdrop-filter:blur(16px); border:1px solid rgba(59,130,246,0.3); border-radius:20px; padding:36px 36px; box-shadow:0 0 40px rgba(59,130,246,0.2); animation:fadeUp 0.6s ease both; width:min(480px,100%); }}
@keyframes fadeUp {{ from{{opacity:0;transform:translateY(28px)}} to{{opacity:1;transform:translateY(0)}} }}
.card h2 {{ color:#f0f4ff; font-size:1.2rem; font-weight:700; margin-bottom:22px; display:flex; align-items:center; gap:8px; }}
label {{ display:block; font-size:0.72rem; font-weight:600; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:5px; margin-top:14px; }}
input {{ width:100%; padding:11px 14px; background:rgba(255,255,255,0.05); border:1px solid rgba(59,130,246,0.25); border-radius:10px; color:#f0f4ff; font-size:0.9rem; outline:none; transition:border-color 0.25s; }}
input:focus {{ border-color:#3b82f6; box-shadow:0 0 0 3px rgba(59,130,246,0.18); }}
.btn-row {{ display:flex; gap:10px; margin-top:22px; }}
.btn-save {{ flex:1; padding:12px; background:linear-gradient(135deg,#3b82f6,#06b6d4); border:none; border-radius:10px; color:#fff; font-size:0.95rem; font-weight:700; cursor:pointer; transition:opacity 0.2s; }}
.btn-save:hover {{ opacity:0.88; }}
.btn-cancel {{ padding:12px 18px; background:rgba(255,255,255,0.05); border:1px solid rgba(59,130,246,0.2); border-radius:10px; color:#64748b; font-size:0.9rem; text-decoration:none; display:inline-flex; align-items:center; transition:color 0.2s; }}
.btn-cancel:hover {{ color:#f0f4ff; }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
{sidebar}
<div class="main">
  <div class="card">
    <h2>✏️ Update Record #{row[0]}</h2>
    <form action="/admin-update/{row[0]}" method="POST">
      <label>Full Name</label>
      <input type="text" name="name" value="{row[1]}" required>
      <label>Email</label>
      <input type="email" name="email" value="{row[2]}" required>
      <label>Phone</label>
      <input type="text" name="phone" value="{row[3]}" required>
      <div class="btn-row">
        <button type="submit" class="btn-save">💾 Save Changes</button>
        <a href="/admin-users" class="btn-cancel">Cancel</a>
      </div>
    </form>
  </div>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""


# ===============================
# USER ACTIVITY LOGS (ADMIN)
# ===============================

@app.route("/admin-logs")
def admin_logs():
    if session.get("role") != "admin":
        return redirect("/")
    sidebar = ADMIN_SIDEBAR.format(dl_active='', usr_active='', log_active='class="active"')

    try:
        cursor.execute("SELECT username, action, timestamp FROM activity_logs ORDER BY timestamp DESC")
        rows = cursor.fetchall()
    except Exception:
        rows = []

    rows_html = ""
    for row in rows:
        action_class = "action-login" if str(row[1]).upper() == "LOGIN" else "action-logout"
        rows_html += f"""
        <tr>
          <td>{row[0]}</td>
          <td>{row[2]}</td>
          <td class="{action_class}">{str(row[1]).upper()}</td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="3" style="text-align:center;color:#475569;padding:30px;">No activity logs yet. Logs will appear here after users log in or out.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Activity Logs — PII Anonymization System</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
<style>
{ADMIN_SIDEBAR_CSS}
.topbar {{ background:rgba(10,20,45,0.7); backdrop-filter:blur(12px); border:1px solid rgba(59,130,246,0.2); border-radius:14px; padding:15px 22px; display:flex; justify-content:space-between; align-items:center; margin-bottom:22px; }}
.topbar h2 {{ color:#f0f4ff; font-size:1.1rem; font-weight:700; }}
.table-wrap {{ background:rgba(10,20,45,0.70); backdrop-filter:blur(12px); border:1px solid rgba(59,130,246,0.2); border-radius:14px; overflow:auto; }}
table {{ width:100%; border-collapse:collapse; font-size:0.84rem; }}
thead th {{ padding:13px 16px; text-align:left; font-size:0.7rem; font-weight:600; color:#64748b; text-transform:uppercase; letter-spacing:0.05em; background:rgba(59,130,246,0.08); border-bottom:1px solid rgba(59,130,246,0.15); }}
tbody tr {{ border-bottom:1px solid rgba(255,255,255,0.04); transition:background 0.15s; }}
tbody tr:hover {{ background:rgba(59,130,246,0.07); }}
tbody td {{ padding:11px 16px; color:#cbd5e1; }}
tbody td:first-child {{ color:#94a3b8; font-weight:600; width:120px; }}
tbody td:nth-child(2) {{ color:#64748b; font-size:0.82rem; }}
.action-login  {{ color:#4ade80; font-weight:700; letter-spacing:0.06em; }}
.action-logout {{ color:#f87171; font-weight:700; letter-spacing:0.06em; }}
.note {{ background:rgba(59,130,246,0.07); border:1px solid rgba(59,130,246,0.2); border-radius:10px; padding:14px 18px; margin-bottom:18px; color:#64748b; font-size:0.82rem; line-height:1.6; }}
.note code {{ background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px; font-size:0.8rem; color:#93c5fd; }}
</style>
</head>
<body>
<div id="vanta-bg"></div>
{sidebar}
<div class="main">
  <div style="flex:1; display:flex; flex-direction:column; width:100%;">
    <div class="topbar">
      <h2>📋 User Activity Logs</h2>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>User</th><th>Time</th><th>Action</th></tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>
</div>
<script>
VANTA.NET({{
  el: "#vanta-bg",
  mouseControls: true, touchControls: true, gyroControls: false,
  minHeight: 200.00, minWidth: 200.00, scale: 1.00, scaleMobile: 1.00,
  color: 0x3b82f6, backgroundColor: 0x050d1a,
  points: 10.00, maxDistance: 22.00, spacing: 18.00
}});
</script>
</body>
</html>"""


# ===============================
# SERVE CSS
# ===============================

@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory("../frontend/css", filename)


# ===============================
# RUN SERVER
# ===============================

if __name__ == "__main__":
    app.run(debug=True)