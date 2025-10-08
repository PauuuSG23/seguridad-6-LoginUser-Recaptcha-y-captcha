# app.py
from flask import Flask, render_template, flash, redirect, url_for, session, request
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
import os  # para os.getenv, para leer variables de entorno

from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from forms import LoginForm
from models import Base, User

from datetime import datetime, timedelta


# ===  constantes de throttling y helper === thorttle significa aceleración controlada de un proceso
MAX_FAILS = 2                # Intentos permitidos antes de bloquear
FAIL_WINDOW_SECONDS = 60     # Ventana para contar fallos (1 minuto)
LOCK_SECONDS = 60            # Bloqueo 1 minuto

def normalize_username(u: str) -> str:
    return (u or "").strip().lower()
# ===============================================


load_dotenv()

app = Flask(__name__)
# Configuración base
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev_secret_change_me"),
    WTF_CSRF_SECRET_KEY=os.getenv("WTF_CSRF_SECRET_KEY", "dev_csrf_change_me"),
    RECAPTCHA_PUBLIC_KEY=os.getenv("RECAPTCHA_SITE_KEY"),
    RECAPTCHA_PRIVATE_KEY=os.getenv("RECAPTCHA_SECRET_KEY"),
    RECAPTCHA_PARAMETERS={"hl": "es"},
    # Cookies (ajustar SECURE=True solo si sirves por HTTPS)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # cambiar a True en producción con HTTPS
)

csrf = CSRFProtect(app)

# ---------- SQLAlchemy ----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta DATABASE_URL en .env (ej: mysql+pymysql://root:@localhost/flask_login_demo)")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base.metadata.create_all(engine)

# ---------- Flask-Login ----------
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Inicia sesión para continuar."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    try:
        return db.get(User, int(user_id))
    finally:
        db.close()

@login_manager.unauthorized_handler
def unauthorized():
    flash("Inicia sesión para continuar.", "warning")
    return redirect(url_for("login", next=request.path))

@app.teardown_appcontext
def remove_session(exception=None):
    SessionLocal.remove()

# ---------- Rutas ----------
@app.route("/")
def index():
    # Landing informativa
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Si ya está autenticado, respeta ?next= o lleva a dashboard
    if current_user.is_authenticated:
        dest = request.args.get("next") or url_for("dashboard")
        return redirect(dest)

    form = LoginForm()
    if form.validate_on_submit():
        now = datetime.utcnow()
        input_username = normalize_username(form.username.data)
        db = SessionLocal()
        try:
            # --- 1) Verificar si está bloqueado ---
            from models import AuthThrottle, User  # evita imports circulares en runtime
            throttle = db.query(AuthThrottle).filter(AuthThrottle.username == input_username).first()
            if throttle and throttle.locked_until and now < throttle.locked_until:
                remaining = int((throttle.locked_until - now).total_seconds())
                flash(f"Usuario bloqueado. Inténtalo en {remaining} s.", "danger")
                # 👉 aquí mandamos lock_remaining al template para el banner + countdown
                return render_template("login.html", form=form, lock_remaining=remaining)

            # --- 2) Intentar autenticar ---
            user = db.query(User).filter(User.username == input_username).first()
            is_valid = bool(user and user.check_password(form.password.data))

            if is_valid:
                # éxito → reset de throttle y login
                if throttle:
                    throttle.fail_count = 0
                    throttle.first_fail_at = None
                    throttle.locked_until = None
                    db.add(throttle)
                    db.commit()

                login_user(user)
                flash("¡Bienvenido!", "success")
                next_url = request.args.get("next")
                return redirect(next_url or url_for("dashboard"))

            # --- 3) Fallo: actualizar contadores/lock sin filtrar info ---
            if not throttle:
                throttle = AuthThrottle(
                    username=input_username,
                    fail_count=1,
                    first_fail_at=now,
                    locked_until=None
                )
                db.add(throttle)
                db.commit()
            else:
                # Si ventana venció, reinicia contador
                if not throttle.first_fail_at or (now - throttle.first_fail_at).total_seconds() > FAIL_WINDOW_SECONDS:
                    throttle.fail_count = 1
                    throttle.first_fail_at = now
                    throttle.locked_until = None
                else:
                    throttle.fail_count += 1
                    # ¿se alcanza umbral?
                    if throttle.fail_count >= MAX_FAILS:
                        throttle.fail_count = 0
                        throttle.first_fail_at = None
                        throttle.locked_until = now + timedelta(seconds=LOCK_SECONDS)

                db.add(throttle)
                db.commit()

            # Mensaje genérico (sin filtrar si el usuario existe o no)
            flash("Usuario o contraseña inválidos.", "danger")

        finally:
            db.close()

    elif form.is_submitted():
        for field, errors in form.errors.items():
            for err in errors:
                flash(f"{getattr(form, field).label.text}: {err}", "danger")
        flash("Revisa el formulario.", "warning")

    # Render normal (sin bloqueo)
    return render_template("login.html", form=form)



@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("login"))

# Páginas protegidas
@app.route("/dashboard")
@login_required
def dashboard():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("dashboard.html", data=data)

@app.route("/perfil")
@login_required
def perfil():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("perfil.html", data=data)

@app.route("/reportes")
@login_required
def reportes():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("reportes.html", data=data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8095)
