from app import db, app, User

with app.app_context():
    bill = User(name="bill", email="bill@gmail.com", password="1968")
    steve = User(name="steve", email="steve@gmail.com", password="1968")
    onute = User(name="onute", email="onute@gmail.com", password="1968")

    db.session.add_all([bill, steve, onute])
    db.session.commit()
