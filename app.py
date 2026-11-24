import os
import secrets
from urllib.parse import urlsplit

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)

database_url = os.getenv("DATABASE_URL", "sqlite:///servicecheck.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in first."


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class MonitoredService(db.Model):
    __tablename__ = "monitored_services"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    expected_status = db.Column(db.Integer, nullable=False)
    timeout_seconds = db.Column(db.Integer, nullable=False)
    expected_text = db.Column(db.String(250))
    created_at = db.Column(
        db.DateTime(timezone=True), server_default=db.func.now(), nullable=False
    )


def valid_service_url(value):
    if not value or len(value) > 2048:
        return False

    if any(char.isspace() or ord(char) < 32 for char in value):
        return False

    try:
        parsed = urlsplit(value)
        port = parsed.port
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and (port is None or 1 <= port <= 65535)
        )
    except ValueError:
        return False


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not password or not confirm_password:
            flash("Please complete every field.", "error")
        elif password != confirm_password:
            flash("The passwords do not match.", "error")
        elif len(password) < 8:
            flash("The password must be at least 8 characters.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            new_user = User(full_name=full_name, email=email)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("You are now logged in.", "success")
            return redirect(url_for("home"))

        flash("The email or password is incorrect.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.pop("services_csrf", None)
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/services", methods=["GET", "POST"])
@login_required
def services():
    if request.method == "POST":
        token = session.get("services_csrf")
        submitted_token = request.form.get("csrf_token", "").encode("utf-8")

        if not token or not secrets.compare_digest(
            token.encode("ascii"), submitted_token
        ):
            return "Invalid form token. Reload the page and try again.", 400

        name = request.form.get("name", "").strip()
        url = request.form.get("url", "").strip()
        expected_text = request.form.get("expected_text", "").strip()
        expected_status = request.form.get("expected_status", type=int)
        timeout_seconds = request.form.get("timeout_seconds", type=int)

        if not name or len(name) > 100:
            flash("Enter a service name between 1 and 100 characters.", "error")
        elif not valid_service_url(url):
            flash("Enter a valid HTTP or HTTPS URL without credentials.", "error")
        elif expected_status is None or not 100 <= expected_status <= 599:
            flash("Enter an expected HTTP status between 100 and 599.", "error")
        elif timeout_seconds is None or not 1 <= timeout_seconds <= 30:
            flash("Enter a timeout between 1 and 30 seconds.", "error")
        elif len(expected_text) > 250:
            flash("Expected response text must be 250 characters or fewer.", "error")
        else:
            service = MonitoredService(
                owner_id=current_user.id,
                name=name,
                url=url,
                expected_status=expected_status,
                timeout_seconds=timeout_seconds,
                expected_text=expected_text or None,
            )
            db.session.add(service)
            db.session.commit()
            flash("Service saved.", "success")
            return redirect(url_for("services"))

    if "services_csrf" not in session:
        session["services_csrf"] = secrets.token_urlsafe(32)

    return render_template("services.html", csrf_token=session["services_csrf"])


@app.route("/api/services")
def search_services():
    if not current_user.is_authenticated:
        return {"error": "Log in to search your services."}, 401

    search = request.args.get("query", "").strip()
    if len(search) > 100:
        return {"error": "Search must be 100 characters or fewer."}, 400

    query = MonitoredService.query.filter_by(owner_id=current_user.id)

    if search:
        query = query.filter(
            db.func.lower(MonitoredService.name).contains(
                search.lower(), autoescape=True
            )
        )

    matches = query.order_by(MonitoredService.id.desc()).limit(100).all()

    return {
        "services": [
            {
                "id": service.id,
                "name": service.name,
                "url": service.url,
                "expected_status": service.expected_status,
                "timeout_seconds": service.timeout_seconds,
                "expected_text": service.expected_text,
            }
            for service in matches
        ]
    }


@app.route("/health")
def health():
    return {"status": "healthy"}, 200


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)