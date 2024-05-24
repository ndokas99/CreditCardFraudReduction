from flask import Flask, flash, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sqlalchemy.orm import backref
from werkzeug.security import generate_password_hash, check_password_hash
from string import ascii_uppercase, digits
from random import choice
from os import path
from re import search

settings = {
    "SECRET_KEY": 'G15FH6HHD75DGFJ7JD9HD',
    "SQLALCHEMY_DATABASE_URI": 'sqlite:///accHolders.db',
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": "kudakwashe.ndokanga@students.uz.ac.zw",
    "MAIL_PASSWORD": "R192098Z"
}

app = Flask(__name__)
app.debug = False
app.config.update(settings)
db = SQLAlchemy(app)
mail = Mail(app)


class Acc(db.Model):
    accNumber = db.Column(db.Integer, primary_key=True, autoincrement=True)
    idNumber = db.Column(db.Text, unique=True, nullable=False)
    fullname = db.Column(db.Text, nullable=False)
    comms = db.relationship('Comm')
    login = db.relationship('Login')
    alerts = db.relationship('Alerts', backref=backref("acc"))


class Comm(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('acc.accNumber'), primary_key=True)
    email = db.Column(db.Text, nullable=False)


class Login(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('acc.accNumber'), primary_key=True)
    password = db.Column(db.Text, nullable=False)
    secCode = db.Column(db.String, unique=True, nullable=False)


class Alerts(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('acc.accNumber'), primary_key=True)
    reason = db.Column(db.Text, nullable=False)
    active = db.Column(db.Integer, nullable=False)


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    message = db.Column(db.String, nullable=False)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/createPage')
def createPage():
    return render_template("create.html")


@app.route('/transactPage')
def transactPage():
    return render_template("transact.html")


@app.route('/create', methods=['POST'])
def create():
    if request.method == 'POST':
        idNum = request.form['idNum']
        idNum = idNum.replace(" ", "").replace("-", "")
        fullname = request.form['fullName']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']

        if Acc.query.filter_by(idNumber=idNum).first():
            flash("Account with this ID already exists")
        elif fullname.count(" ") < 1:
            flash("Fullname should contain at least two words", category="error")
        elif not search(r".*?@.*?[.]com", email):
            flash("Email is invalid", category="error")
        elif email.count(" ") > 0:
            flash("Email should not contain spaces", category="error")
        elif password1 != password2:
            flash("Passwords do not match", category="error")
        elif len(password1) < 7:
            flash("Passwords should be at least 7 characters", category="error")
        else:
            code, codeHash = generate_code()
            acc = Acc(idNumber=idNum, fullname=fullname)
            db.session.add(acc)
            db.session.commit()

            acc = Acc.query.filter_by(idNumber=idNum).first()
            comm = Comm(id=acc.accNumber, email=email)
            db.session.add(comm)
            login = Login(id=acc.accNumber,
                          password=generate_password_hash(password1, method="sha256"),
                          secCode=codeHash)
            db.session.add(login)
            db.session.commit()
            send_to_acc_holder(code, email, fullname, acc.accNumber)
            flash("Account created successfully. Check your mailbox for account details.", category="success")
            return render_template("transact.html")

        return render_template("create.html")


@app.route('/transact', methods=['POST'])
def transact():
    if request.method == 'POST':
        accNum = request.form['accNum']
        password = request.form['password']
        code = request.form['code']

        alerts = Alerts.query.filter_by(id=accNum).first()
        if alerts.active == 1:
            flash("Account is currently not operational. Contact admin for assistance", category="error")
        else:
            acc = Acc.query.filter_by(accNumber=accNum).first()
            if acc:
                if check_password_hash(acc.login[0].password, password):
                    if check_password_hash(acc.login[0].secCode, code):
                        new_code, codeHash = generate_code()
                        acc.login[0].secCode = codeHash
                        db.session.commit()
                        send_to_acc_holder(new_code, acc.comms[0].email, acc.fullname)
                        flash("Transaction successful", category="success")
                    else:
                        flash("Verification code does not match account", category='error')
                else:
                    flash("Password invalid", category="error")
            else:
                flash("Account does not exist", category="error")

        return render_template("transact.html")


@app.route('/help')
def help_():
    return render_template("help.html")


@app.route('/feedback', methods=['POST'])
def feedback():
    if request.method == 'POST':
        feed = Feedback(email=request.form['email'],
                        message=request.form['msg'])
        db.session.add(feed)
        db.session.commit()
        flash("Feedback message send successfully", category="success")
        return render_template("help.html")


@app.route('/alert')
def alert():
    return render_template("alert.html")


@app.route('/confirm', methods=['POST'])
def confirm():
    if request.method == 'POST':
        accNum = request.form['accNum']
        password = request.form['password']
        code = request.form['code']
        reason = request.form['reason']

        alerted = Alerts.query.filter_by(id=accNum).first()
        if alerted:
            if alerted.active == 1:
                flash("Account has already been blocked. Contact admin for assistance", category="error")
            elif alerted.active == 0:
                alerted.active = 1
                db.session.commit()
                flash("Account has been blocked and admin has been alerted. Please wait as your problem is attended to.",
                      category="success")
        else:
            acc = Acc.query.filter_by(accNumber=accNum).first()
            if acc:
                if check_password_hash(acc.login[0].password, password):
                    if check_password_hash(acc.login[0].secCode, code):
                        alerts = Alerts(id=accNum, reason=reason or 'Not specified', active=1)

                        with app.app_context():
                            msg = Message(sender=app.config.get("MAIL_USERNAME"),
                                          recipients=[f'<{app.config.get("MAIL_USERNAME")}>'])
                            msg.subject = "Account blocking requested"
                            msg.html = render_template("block.html")
                            mail.send(msg)

                        db.session.add(alerts)
                        db.session.commit()
                        flash("Account has been blocked and admin has been alerted. Please wait as your problem is "
                              "attended to.", category="success")
        return render_template("alert.html")


@app.route('/admin')
def admin():
    return render_template("admin.html")


@app.route('/ccfrs', methods=['POST'])
def ccfrs():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == "admin" and password == "hct260":
            feeds = Feedback.query.all()
            alerts = Alerts.query.filter_by(active=1).all()
            return render_template("ccfrs.html", feeds=feeds, alerts=alerts)
        else:
            flash("Access denied", category="error")
            return render_template("admin.html")


@app.route('/unblock/<int:Id>', methods=['POST'])
def unblock(Id):
    if request.method == 'POST':
        acc = Alerts.query.filter_by(id=Id).first()
        acc.active = 0
        db.session.commit()
        feeds = Feedback.query.all()
        alerts = Alerts.query.filter_by(active=1).all()
        flash("Account unblocked successfully", category="success")
        return render_template("ccfrs.html", feeds=feeds, alerts=alerts)
    return render_template("index.html")


def generate_code():
    code = ''.join(choice(ascii_uppercase + digits) for _ in range(8))
    hashcode = generate_password_hash(code, method='sha256')
    acc = Login.query.filter_by(secCode=hashcode).first()
    if acc:
        generate_code()
    else:
        return code, hashcode


def send_to_acc_holder(code, email, name, num=None):
    with app.app_context():
        msg = Message(sender=app.config.get("MAIL_USERNAME"), recipients=[f'<{email}>'])
        if num is None:
            msg.subject = "CCFR System verification code update"
            msg.html = render_template("update_email.html", name=name, code=code)
        else:
            msg.subject = "CCFR System account details"
            msg.html = render_template("create_email.html", name=name, code=code, num=num)
        mail.send(msg)


def create_database():
    if not path.exists("accHolders.db"):
        db.create_all()


if __name__ == '__main__':
  with app.app_context():
    create_database()
    app.run("0.0.0.0")
