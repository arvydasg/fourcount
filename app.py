from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    logout_user,
    login_user,
    login_required,
)

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
print(basedir)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "db.db")
app.config["SECRET_KEY"] = "your_secret_key_here"
db = SQLAlchemy(app)

# Encrypting and Decrypting password
bcrypt = Bcrypt(app)

# Authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ===== MODELS ========================================================================


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# ===== ROUTES ========================================================================


@app.route("/all_users", methods=["GET", "POST"])
def route_all_users():
    all_users = User.query.all()

    if not all_users:
        return render_template("no_data.html")

    return render_template("all_users.html", all_users=all_users)


@app.route("/", methods=["GET", "POST"])
def route_register():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for("route_all_users"))

    form = RegisterForm()

    if form.validate_on_submit():
        koduotas_slaptazodis = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        new_user = User(
            name=form.name.data, email=form.email.data, password=koduotas_slaptazodis
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("route_login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def route_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("route_groups"))
        flash("Invalid username or password")

    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
def route_logout():
    logout_user()
    return redirect(url_for("route_login"))


@app.route("/groups", methods=["GET", "POST"])
def route_groups():
    return render_template("groups.html")


# ===== FORMS ========================================================================


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

    def validate_name(self, name):
        existing_user_username = User.query.filter_by(name=name.data).first()

        if existing_user_username:
            abort(400, "That username already exists.")


class LoginForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(host="0.0.0.0", debug=False)
