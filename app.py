# app.py
from flask import Flask, render_template, flash, redirect, url_for, session, request
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
import os  # para os.getenv, para leer variables de entorno
import random
import time
from functools import wraps
import logging

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

# === Sistema de CAPTCHAs ===
active_captchas = {}

def generate_math_captcha():
    """Genera un CAPTCHA matemático simple"""
    num1 = random.randint(1, 20)
    num2 = random.randint(1, 20)
    operator = random.choice(['+', '-', '*'])
    
    if operator == '+':
        answer = num1 + num2
        question = f"{num1} + {num2} = ?"
    elif operator == '-':
        # Asegurar que el resultado no sea negativo
        num1, num2 = max(num1, num2), min(num1, num2)
        answer = num1 - num2
        question = f"{num1} - {num2} = ?"
    else:  # *
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 5)
        answer = num1 * num2
        question = f"{num1} × {num2} = ?"
    
    captcha_id = f"math_{int(time.time())}"
    return captcha_id, question, str(answer)

def generate_sequence_captcha():
    """Genera un CAPTCHA de secuencia lógica"""
    sequences = [
        {
            'question': "2, 4, 6, 8, ?",
            'options': ["10", "9", "12", "7"],
            'answer': "10"
        },
        {
            'question': "A, C, E, G, ?",
            'options': ["H", "I", "J", "K"],
            'answer': "I"
        },
        {
            'question': "5, 10, 15, 20, ?",
            'options': ["25", "30", "35", "40"],
            'answer': "25"
        },
        {
            'question': "Z, Y, X, W, ?",
            'options': ["V", "U", "T", "S"],
            'answer': "V"
        },
        {
            'question': "1, 4, 9, 16, ?",
            'options': ["25", "20", "36", "24"],
            'answer': "25"
        }
    ]
    
    seq = random.choice(sequences)
    captcha_id = f"seq_{int(time.time())}"
    return captcha_id, seq['question'], seq['options'], seq['answer']

def generate_security_captcha():
    """Genera un CAPTCHA de pregunta de seguridad"""
    questions = [
        {
            'question': "¿Cuántos lados tiene un triángulo?",
            'answer': "3",
            'hint': "Escribe el número en texto"
        },
        {
            'question': "¿Qué animal se conoce como el mejor amigo del hombre?",
            'answer': "perro",
            'hint': "Escríbelo en minúsculas"
        },
        {
            'question': "¿En qué continente se encuentra España?",
            'answer': "europa",
            'hint': "Escríbelo en minúsculas"
        },
        {
            'question': "¿Cuántos días tiene una semana?",
            'answer': "7",
            'hint': "Escribe el número en texto"
        },
        {
            'question': "¿Qué color se forma mezclando azul y amarillo?",
            'answer': "verde",
            'hint': "Escríbelo en minúsculas"
        }
    ]
    
    q = random.choice(questions)
    captcha_id = f"sec_{int(time.time())}"
    return captcha_id, q['question'], q['answer'], q.get('hint', '')

def cleanup_old_captchas():
    """Limpia CAPTCHAs más antiguos de 10 minutos"""
    current_time = time.time()
    expired = []
    for captcha_id in active_captchas.keys():
        try:
            captcha_time = int(captcha_id.split('_')[1])
            if current_time - captcha_time > 600:  # 10 minutos
                expired.append(captcha_id)
        except (IndexError, ValueError):
            expired.append(captcha_id)
    
    for captcha_id in expired:
        active_captchas.pop(captcha_id, None)

# Decorador para rutas que requieren CAPTCHA específico
def captcha_required(captcha_number):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            key = f'captcha{captcha_number}_passed'
            logger.debug("captcha_required check for key=%s (in session=%s)", key, key in session)
            # mostrar claves actuales de session para depuración
            try:
                logger.debug("session snapshot: %s", {k: session.get(k) for k in session.keys()})
            except Exception:
                logger.exception("No se pudo serializar session para logging")
            if not session.get(key):
                flash(f"Debes completar el CAPTCHA {captcha_number} primero.", "warning")
                return redirect(url_for(f'verify_captcha{captcha_number}'))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
# ===============================================

load_dotenv()

app = Flask(__name__)
# configurar logging básico
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
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

# ========== Rutas para CAPTCHAs ==========
@app.route("/verify_captcha1", methods=["GET", "POST"])
@login_required
def verify_captcha1():
    if request.method == "POST":
        captcha_id = request.form.get('captcha_id')
        user_answer = request.form.get('answer', '').strip()
        
        if captcha_id in active_captchas:
            correct_answer = active_captchas[captcha_id]
            # Limpiar CAPTCHAs antiguos
            cleanup_old_captchas()
            
            if user_answer == correct_answer:
                session['captcha1_passed'] = True
                flash("¡CAPTCHA verificado correctamente!", "success")
                return redirect(url_for('perfil'))
            else:
                flash("Respuesta incorrecta. Intenta nuevamente.", "danger")
        
        return redirect(url_for('verify_captcha1'))
    
    # GET request - generar nuevo CAPTCHA
    captcha_id, question, answer = generate_math_captcha()
    active_captchas[captcha_id] = answer
    return render_template('captcha1.html', 
                         captcha_question=question, 
                         captcha_id=captcha_id)

@app.route("/verify_captcha2", methods=["GET", "POST"])
@login_required
def verify_captcha2():
    if request.method == "POST":
        captcha_id = request.form.get('captcha_id')
        user_answer = request.form.get('answer', '').strip()
        
        if captcha_id in active_captchas:
            correct_answer = active_captchas[captcha_id]
            cleanup_old_captchas()
            
            if user_answer == correct_answer:
                session['captcha2_passed'] = True
                flash("¡CAPTCHA verificado correctamente!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Respuesta incorrecta. Intenta nuevamente.", "danger")
        
        return redirect(url_for('verify_captcha2'))
    
    captcha_id, question, options, answer = generate_sequence_captcha()
    active_captchas[captcha_id] = answer
    return render_template('captcha2.html', 
                         captcha_question=question, 
                         options=options,
                         captcha_id=captcha_id)

@app.route("/verify_captcha3", methods=["GET", "POST"])
@login_required
def verify_captcha3():
    if request.method == "POST":
        captcha_id = request.form.get('captcha_id')
        user_answer = request.form.get('answer', '').strip().lower()
        
        if captcha_id in active_captchas:
            correct_answer = active_captchas[captcha_id]
            cleanup_old_captchas()
            
            if user_answer == correct_answer.lower():
                session['captcha3_passed'] = True
                flash("¡CAPTCHA verificado correctamente!", "success")
                return redirect(url_for('reportes'))
            else:
                flash("Respuesta incorrecta. Intenta nuevamente.", "danger")
        
        return redirect(url_for('verify_captcha3'))
    
    captcha_id, question, answer, hint = generate_security_captcha()
    active_captchas[captcha_id] = answer
    return render_template('captcha3.html', 
                         captcha_question=question, 
                         hint=hint,
                         captcha_id=captcha_id)

# ========== Rutas protegidas con CAPTCHAs ==========
@app.route("/dashboard")
@login_required
@captcha_required(2)
def dashboard():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("dashboard.html", data=data)

@app.route("/perfil")
@login_required
@captcha_required(1)
def perfil():
    db = SessionLocal()
    try:
        user = db.get(User, int(current_user.get_id()))
        if not user:
            flash("Usuario no encontrado.", "warning")
            return redirect(url_for("login"))
        data = {
            "id": user.id,
            "doc_id": getattr(user, 'doc_id', ''),
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
        return render_template("perfil.html", data=data)
    finally:
        db.close()

@app.route("/reportes")
@login_required
@captcha_required(3)
def reportes():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("reportes.html", data=data)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    # Limpiar CAPTCHAs al cerrar sesión
    for key in list(session.keys()):
        if key.startswith('captcha') and key.endswith('_passed'):
            session.pop(key)
    active_captchas.clear()
    
    logout_user()
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("login"))

# Ruta para limpiar CAPTCHAs expirados
@app.route("/cleanup_captchas")
def cleanup_captchas_route():
    cleanup_old_captchas()
    return "CAPTCHAs expirados limpiados"


@app.route('/_debug_session')
def _debug_session():
    """Endpoint de depuración que muestra el contenido actual de la sesión y cookies.
    No dejar en producción."""
    try:
        session_data = {k: session.get(k) for k in session.keys()}
    except Exception:
        session_data = "<unserializable session>"

    cookies = {k: request.cookies.get(k) for k in request.cookies.keys()}
    info = {
        'session': session_data,
        'cookies': cookies,
        'remote_addr': request.remote_addr,
        'path': request.path
    }
    logger.debug("/_debug_session called: %s", info)
    from flask import jsonify
    return jsonify(info)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8095)