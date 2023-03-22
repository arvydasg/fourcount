from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
print(basedir)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "db.db")
app.config["SECRET_KEY"] = "your_secret_key_here"
db = SQLAlchemy(app)


# ===== MODELS ========================================================================


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# ===== ROUTES ========================================================================


@app.route("/", methods=["GET", "POST"])
def route_index():
    users_data = User.query.all()

    if not users_data:
        return render_template("no_data.html")

    return render_template("index.html", users_data=users_data)


@app.route("/register", methods=["GET", "POST"])
def route_register():
    form = NewUserForm()

    if form.validate_on_submit():
        new_user = User(
            name=form.name.data, email=form.email.data, password=form.password.data
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("route_index"))

    return render_template("register.html", form=form)


# ===== FORMS ========================================================================


class NewUserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(host="0.0.0.0", debug=True)
