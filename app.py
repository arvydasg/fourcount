from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, DecimalField
from wtforms.validators import DataRequired, Email, EqualTo
import os
from datetime import datetime
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
    groups = db.relationship(
        "Group", secondary="user_group", backref=db.backref("members", lazy="dynamic")
    )


# Association table between User and Group
user_group = db.Table(
    "user_group",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("group_id", db.Integer, db.ForeignKey("group.id")),
)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    bills = db.relationship("Bill", backref="group", lazy=True)


class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))


# ===== ROUTES ========================================================================


@app.route("/", methods=["GET", "POST"])
def route_register():
    db.create_all()
    if current_user.is_authenticated:
        flash(
            "You are already registered and logged in, redirecting you to your groups page!"
        )
        flash("To register a new user - please log out first 🙏")
        return redirect(url_for("route_groups"))

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
        flash("Registration successful, you can login now 🙏")
        return redirect(url_for("route_login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def route_login():
    if current_user.is_authenticated:
        flash("You are already logged in, redirecting you to your groups page!")
        flash("To login with different user you must logout first 🙏")
        return redirect(url_for("route_groups"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Welcome to your groups page! 🙏")
                return redirect(url_for("route_groups"))
        flash("Invalid username or password")

    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
def route_logout():
    logout_user()
    flash("You have been successfully logged out 🙏")
    return redirect(url_for("route_login"))


@app.route("/groups", methods=["GET", "POST"])
@login_required
def route_groups():
    groups = current_user.groups
    form = AddGroupForm()
    if form.validate_on_submit():
        new_group = Group(name=form.name.data)
        db.session.add(new_group)
        current_user.groups.append(new_group)
        db.session.commit()
        flash("New group created successfully.")
        return redirect(url_for("route_groups"))
    return render_template("groups.html", groups=groups, form=form)


@app.route("/groups/add", methods=["GET", "POST"])
@login_required
def route_add_group():
    form = AddGroupForm()
    if form.validate_on_submit():
        new_group = Group(name=form.name.data)
        db.session.add(new_group)
        current_user.groups.append(new_group)
        db.session.commit()
        flash("New group created successfully.")
        return redirect(url_for("route_groups"))
    return render_template("add_group.html", form=form)


@app.route("/groups/<int:group_id>/bills", methods=["GET", "POST"])
@login_required
def route_bills(group_id):
    group = Group.query.get(group_id)
    if group not in current_user.groups:
        abort(403)

    bills = group.bills
    form = AddBillForm()
    if form.validate_on_submit():
        new_bill = Bill(name=form.name.data, amount=form.amount.data, group=group)
        db.session.add(new_bill)
        db.session.commit()
        flash("New bill added successfully.")
        return redirect(url_for("add_bill", group_id=group_id))

    return render_template("bills.html", group=group, bills=bills, form=form)


@app.route("/groups/<int:group_id>/add_bill", methods=["POST"])
@login_required
def add_bill(group_id):
    group = Group.query.get(group_id)
    if group not in current_user.groups:
        abort(403)

    form = AddBillForm()
    if form.validate_on_submit():
        bill = Bill(name=form.name.data, amount=form.amount.data, group_id=group.id)
        db.session.add(bill)
        db.session.commit()
        flash("New bill added successfully.")
        return redirect(url_for("route_bills", group_id=group.id))

    flash_errors(form)
    return redirect(url_for("route_bills", group_id=group.id))


# ===== FORMS ========================================================================


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password"),
        ],
    )
    submit = SubmitField("Submit")

    def validate_name(self, name):
        existing_user_username = User.query.filter_by(name=name.data).first()

        if existing_user_username:
            abort(400, "That username already exists.")


class LoginForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class AddGroupForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Add Group")


class AddBillForm(FlaskForm):
    name = StringField("Description", validators=[DataRequired()])
    amount = DecimalField("Amount", validators=[DataRequired()])
    submit = SubmitField("Add Bill")


# --------------------------------------------------------------------
# CREATING CUSTOM ERROR PAGES


# Invalid URL
# if I don't pass the error code at the end, terminal shows 200
@app.errorhandler(404)
def page_not_found(e):
    return (render_template("errors/404.html"), 404)


# Internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(host="0.0.0.0", debug=True)
