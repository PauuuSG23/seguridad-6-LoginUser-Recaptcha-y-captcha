# forms.py
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    """Formulario de login con reCAPTCHA."""
    username = StringField(
        "Usuario",
        validators=[DataRequired("El usuario es obligatorio."), Length(min=3, max=50)]
    )
    password = PasswordField(
        "Contraseña",
        validators=[DataRequired("La contraseña es obligatoria.")]
    )
    recaptcha = RecaptchaField()
    submit = SubmitField("Ingresar")
