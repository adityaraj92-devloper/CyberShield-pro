from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from scanners.xss_checker import check_xss
from scanners.sql_checker import check_sqli
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from flask import send_file

import ssl
import socket
import whois
import requests
import re

def check_ssl(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ):

                return "✅ Valid"

    except:

        return "❌ Invalid"

def check_headers(domain):

    try:

        response = requests.get(
            "https://" + domain,
            timeout=5
        )
        print(response.headers)

        headers = response.headers

        score = 0

        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for header in required_headers:

            if header in headers:
                score += 25

        return score

    except:

        return 0

def check_ports(domain):

    ports = [21, 22, 80, 443]
    open_ports = []

    for port in ports:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(1)

            result = sock.connect_ex(
                (domain, port)
            )

            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            pass

    return str(open_ports)

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = 'cybershieldsecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybershield.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    phone = db.Column(db.String(15))

    password = db.Column(
        db.String(255),
        nullable=False
    )

# Scan Model
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    website = db.Column(db.String(255))

    risk_score = db.Column(db.Integer)

    risk_level = db.Column(db.String(20))

    recommendations = db.Column(db.Text)

    open_ports = db.Column(db.String(255))

    xss_status = db.Column(db.String(50))

    ssl_status = db.Column(db.String(50))

    header_score = db.Column(db.Integer)

    sqli_status = db.Column(db.String(50))

    whois_info = db.Column(db.String(255))

    scan_date = db.Column(db.String(100))


def check_ssl(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ):

                return "Valid"

    except:

        return "Invalid"

def get_whois(domain):

    try:

        data = whois.whois(domain)

        if data.registrar:
            return str(data.registrar)

        return "Unknown"

    except:

        return "Unknown"

# Home
@app.route("/")
def home():
    return render_template("index.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
             return "Passwords do not match"

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:
            return "Email already registered!"

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:
            return "Username already exists!"


        hashed_password = generate_password_hash(
            password
        )

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session["user"] = user.username

            return redirect( 
                url_for("dashboard")
            )

        return "Invalid Email or Password"

    return render_template("login.html")

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route("/scan", methods=["POST"])
def scan():

    if "user" not in session:
        return redirect(url_for("login"))

    website = request.form.get("website")

    website = website.replace(
        "https://", ""
    ).replace(
        "http://", ""
    ).split("/")[0]

    ssl_status = check_ssl(website)

    header_score = check_headers(website)

    open_ports = check_ports(website)

    whois_info = get_whois(website)

    xss_status = check_xss(website)

    sqli_status = check_sqli(website)

    print(ssl_status)
    print("SSL STATUS =", repr(ssl_status))

    risk_score = 10

    if ssl_status != "Valid":
        risk_score += 30

    if header_score < 50:
        risk_score += 20

    if xss_status == "❌ Vulnerable":
        risk_score += 20

    if sqli_status == "❌ Vulnerable":
        risk_score += 20

    print("SSL =", ssl_status)
    print("HEADER =", header_score)
    print("XSS =", xss_status)
    print("SQLI =", sqli_status)
    print("FINAL RISK =", risk_score)

    if risk_score <= 30:
        risk_level = "LOW 🟢"

    elif risk_score <= 60:
        risk_level = "MEDIUM 🟡"

    else:
        risk_level = "HIGH 🔴"

    recommendations = []

    if header_score < 50:
        recommendations.append(
            "Add security headers (CSP, HSTS, X-Frame-Options)"
        )

    if xss_status == "❌ Vulnerable":
        recommendations.append(
            "Sanitize user input to prevent XSS attacks"
        )

    if sqli_status == "❌ Vulnerable":
        recommendations.append(
            "Use parameterized SQL queries"
        )

    if ssl_status != "Valid":
        recommendations.append(
            "Enable SSL certificate"
        )

    recommendations_text = "\n".join(recommendations)

    if not recommendations_text:
        recommendations_text = "No major issues found."

    new_scan = Scan(
        website=website,
        risk_score=risk_score,
        risk_level=risk_level,
        ssl_status=ssl_status,
        header_score=header_score,
        whois_info=whois_info,
        open_ports=open_ports,
        scan_date=str(datetime.now()),
        xss_status=xss_status,
        sqli_status=sqli_status,
        recommendations=recommendations_text,
    )

    db.session.add(new_scan)
    db.session.commit()

    return redirect(url_for("dashboard"))

# Dashboard
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    scans = Scan.query.order_by(
        Scan.id.desc()
    ).all()

    return render_template(
        "dashboard.html",
        username=session["user"],
        scans=scans
    )

@app.route("/report/<int:scan_id>")
def report(scan_id):

    scan = Scan.query.get_or_404(scan_id)

    filename = f"report_{scan.id}.pdf"

    pdf = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph("CyberShield Pro Security Report", styles["Title"])
    )

    content.append(
        Paragraph(f"Website: {scan.website}", styles["Normal"])
    )

    content.append(
        Paragraph(f"SSL: {scan.ssl_status}", styles["Normal"])
    )

    content.append(
        Paragraph(f"XSS: {scan.xss_status}", styles["Normal"])
    )

    content.append(
        Paragraph(f"SQLi: {scan.sqli_status}", styles["Normal"])
    )

    content.append(
        Paragraph(f"Header Score: {scan.header_score}", styles["Normal"])
    )

    content.append(
        Paragraph(f"Ports: {scan.open_ports}", styles["Normal"])
    )

    content.append(
        Paragraph(f"WHOIS: {scan.whois_info}", styles["Normal"])
    )
    content.append(
    Paragraph(f"Risk Score: {scan.risk_score}", styles["Normal"])
    )
    content.append(
    Paragraph(f"Risk Level: {scan.risk_level}",styles["Normal"])
    )

    content.append(
    Paragraph(
        f"Recommendations: {scan.recommendations}",
        styles["Normal"]
    )
)

    pdf.build(content)

    return send_file(
        filename,
        as_attachment=True
    )

# Logout
@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect(url_for("home"))

# Create tables
with app.app_context():
    db.create_all()

# Run
if __name__ == "__main__":
    app.run(debug=True)
