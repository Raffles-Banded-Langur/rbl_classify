import random, os
import traceback
import json
import requests
import re
from flask import Flask, redirect, url_for, render_template, request, session, flash, Markup
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

########### SETUP & CONFIG ###############
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "abccccc")
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', "abccccc")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

url = os.environ.get('DATABASE_URL', None)
if url: 
    app.config['SQLALCHEMY_DATABASE_URI'] = url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///test.db"

db = SQLAlchemy(app)
db.create_all()

app.config.update(
	DEBUG=True,
	#EMAIL SETTINGS
	MAIL_SERVER='smtp.gmail.com',
	MAIL_PORT=465,
	MAIL_USE_SSL=True,
# gmail authentication
    MAIL_USERNAME = os.environ['APP_MAIL_USERNAME'],
    MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD'],
    MAIL_DEFAULT_SENDER = os.environ['APP_MAIL_USERNAME']+'@gmail.com'
	)
mail = Mail(app)

########### MODELS ###############

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_1 = db.Column(db.String(80))
    image_2 = db.Column(db.String(80))
    classification = db.Column(db.String(80))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, image_1, image_2, classification, user_id):
        self.image_1 = image_1
        self.image_2 = image_2
        self.classification = classification
        self.user_id = user_id

    def __repr__(self):
        return '<Image %r and %r have been classified as %r by %r>' % (self.image_1, self.image_2, self.classification, self.id)

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique = True, nullable=False)
    password = db.Column(db.String, nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    classifications = db.relationship('Match', backref='users', lazy=True)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(password)

    def __repr__(self):
        return '<name {}'.format(self.name)


########### HELPER FUNCTIONS ###############

def verify_email(email):
    """Validate the email address using a regex."""
    if not re.match("[^@]+@[^@]+\.[^@]+", email):
        return False
    return True

def verify_password(password,confirm_password):
    if password == confirm_password:
        return True
    return False

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
    try:
        msg = Message(
            subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
    except:
        return False
    return True

def send_confirmation_email(email):
    try:
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('confirm_email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        return send_email(email, subject, html)
    except:
        return False
    return True

def send_pw_reset_email(email):
    try:
        token = generate_confirmation_token(email)
        confirm_url = url_for('reset_password', token=token, _external=True)
        html = render_template('forgotpw_email.html', confirm_url=confirm_url)
        subject = "Reset Password"
        return send_email(email, subject, html)
    except:
        return False
    return True


########### VIEWS ###############

#TO-DO: Disable flush on deployment server.
"""
@app.route('/flush')
def flushing():
    db.reflect()
    db.drop_all()
    db.create_all()
    return 'OMG db has been flushed!'
"""


@app.route('/')
def homepage():
    db.create_all()
    if session.get('logged_in') == True:
        return redirect((url_for('training')))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(name=request.form['username']).first()
        if user is not None and bcrypt.check_password_hash(
                user.password, request.form['password']):

            if user.confirmed == True:
                session['resend_confirmation_email'] = False
                session['logged_in'] = True
                session['username'] = request.form['username']
                return redirect(url_for('training'))
            else:
                session['resend_confirmation_email'] = True
                session['username'] = request.form['username']
                flash('You have not confirmed your email yet! Please check your inbox to login.',"error")
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in',None)
    session.pop('username', None)
    flash("You were logged out successfully!")
    return redirect(url_for('homepage'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        if request.form['username'] == '' or request.form['password'] == '' or \
            request.form['email'] == '' or request.form['confirm_password'] == '':
            flash('Please fill all the fields!','error')
        elif not verify_password(request.form['password'], request.form['confirm_password']):
            flash('Password doesn\'t match! Try again!', 'error')
        elif not verify_email(request.form['email']):
            flash('Invalid email address. Please enter a valid email address!', 'error')
        elif User.query.filter_by(email=request.form['email']).first() is None and \
            User.query.filter_by(name=request.form['username']).first() is None:

            new_user = User(request.form['username'],request.form['email'], request.form['password'])
            db.session.add(new_user)
            db.session.commit()

            if send_confirmation_email(request.form['email'])==True:
                flash('A confirmation email has been sent via email.', 'success')
            else:
                flash('Oops! Something went wrong. Please check your email address and try again!', 'error')
                db.session.rollback()
            return redirect(url_for('login'))
        else:
            db.session.rollback()
            flash('Oops! Username ' + request.form['username'] + ' or Email ' + request.form['email'] \
             + ' already exists!', 'error')
    else:
        error = 'Invalid Credentials. Please try again.'
    return render_template('signup.html')



@app.route("/confirm_email/<token>")
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login to continue.', 'success')
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Please login to continue.', 'success')
    return redirect(url_for('login'))


@app.route("/resend_confirmation")
def resend_confirmation():
    user = User.query.filter_by(name=session['username']).first()
    if user is not None:
        send_confirmation_email(user.email)
        flash('The confirmation email has been sent again. Please check your inbox', 'success')
    return redirect(url_for('homepage'))

@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        if not verify_email(request.form['email']):
            flash("Please enter a valid email address.","error")
        else:
            user = User.query.filter_by(email=request.form['email']).first()
            if user is not None:
                send_pw_reset_email(user.email)
                flash('A link to reset your password has been sent to your email.', 'success')
                redirect(url_for('homepage'))
            else:
                flash('There is no account associated with this email address!','error')
    return render_template('forgot_password.html')

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'GET':
        try:
            email = confirm_token(token)
        except:
            flash('The confirmation link is invalid or has expired.', 'danger')
        user = User.query.filter_by(email=email).first_or_404()
        session['email'] = user.email
    if request.method == 'POST':
        if request.form['password'] == '' or request.form['confirm_password'] == '':
            flash('Please fill all the fields!', 'error')
        elif not verify_password(request.form['password'], request.form['confirm_password']):
            flash('Password doesn\'t match! Try again!', 'danger')
        else:
            user = User.query.filter_by(email=session.get('email')).first_or_404()
            if user is not None:
                user.password = bcrypt.generate_password_hash(request.form['password'])
                db.session.add(user)
                db.session.commit()
                session.pop('email',None)
                flash('Your password has been reset! Please login to continue.', 'success')
                return redirect(url_for('login'))
            else:
                flash('The confirmation link is invalid or has expired.', 'danger')
    return render_template('reset_password.html')

@app.route("/leaderboard")
def leaderboard():
    if session.get('logged_in') != True:
        return redirect(url_for('login'))

    board = db.engine.execute('''
    SELECT users.name, count(match.id) FROM match
    JOIN users on users.id = match.user_id
    GROUP BY users.id
    ORDER BY count(match.id) DESC
    LIMIT 50
    ''')
    user = User.query.filter_by(name=session['username']).first()
    total_count = Match.query.filter_by(user_id=user.id).count()
    return render_template('leaderboard.html', board=board,
                           total_count=total_count)

@app.route("/credits")
def credits():
    if session.get('logged_in') == True:
        user = User.query.filter_by(name=session['username']).first()
        total_count = Match.query.filter_by(user_id=user.id).count()
    else:
        total_count = ''
    return render_template('credits.html', total_count=total_count)

@app.route('/training')
def training():
    if session.get('logged_in') != True:
        return redirect(url_for('login'))
    the_time = datetime.now().strftime("%A, %d %b %Y %l:%M %p")
    image_ids=['a1', 'a2', 'b1', 'b2', 'c1', 'c2', 'd1', 'd2', 's1', 's2']
    image_1 = random.choice(image_ids)
    image_2 = random.choice([x for x in image_ids if x != image_1])
    
    # Deal with Invalid Sessions
    try:
        user = User.query.filter_by(name=session['username']).first()
    except:
        return redirect(url_for('logout'))

    if user is None:
        return redirect(url_for('logout'))

    total_count = Match.query.filter_by(user_id=user.id).count()
    return render_template('training.html', time=the_time,
        image_1=image_1, image_2=image_2, total_count=total_count,
        options=["Not at all!", "Not too sure..", "Definitely!"])

@app.route('/classify', methods=['GET', 'POST'])
def classify():
    if session.get('logged_in') != True:
        return redirect(url_for('login'))

    # Gather Image Limits
    limit = requests.get("https://s3-ap-southeast-1.amazonaws.com/rblwg2/images/meta.json")
    limit  = json.loads(limit.text)['image_count']
    image_ids = list(range(1, int(limit)+1))
    list_image_random_ids = random.sample(set(image_ids), 2)
    image_1 = list_image_random_ids[0]
    image_2 = list_image_random_ids[1]
    image_1 = "https://s3-ap-southeast-1.amazonaws.com/rblwg2/images/image_" + '{:05d}'.format(image_1) + ".jpg"
    image_2 = "https://s3-ap-southeast-1.amazonaws.com/rblwg2/images/image_" + '{:05d}'.format(image_2) + ".jpg"
    #image_1 = "http://edge.zimage.io/?url=" + image_1 + "&w=600"
    #image_2 = "http://edge.zimage.io/?url=" + image_2 + "&w=600"
    #image_1 = "http://s3-ap-southeast-1.amazonaws.com.rsz.io/rblwg/images/image" + '{:05d}'.format(image_1) + ".jpg?width=600"
    #image_2 = "http://s3-ap-southeast-1.amazonaws.com.rsz.io/rblwg/images/image" + '{:05d}'.format(image_2) + ".jpg?width=600"

    user = User.query.filter_by(name=session['username']).first()
    total_count = Match.query.filter_by(user_id=user.id).count()
    return render_template('classify.html',
        image_1=image_1, image_2=image_2, total_count=total_count,
        options=["Not at all!", "Not too sure..", "Definitely!"])


@app.route('/submit', methods=['POST'])
def submit():
    classification = request.form['classification']
    image_1 = request.form['image_1']
    image_2 = request.form['image_2']

    # Clean URLs
    image_1 = image_1.split("/")[-1].split("&")[0]
    image_2 = image_2.split("/")[-1].split("&")[0]
    user = User.query.filter_by(name=session['username']).first()

    if (db):
        db.session.add(Match(image_1, image_2, classification, user.id))
        db.session.commit()
    return redirect(url_for('classify'))

@app.errorhandler(500)
def internal_error(exception):
    """Show traceback in the browser when running a flask app on a production server.
    By default, flask does not show any useful information when running on a production server.
    By adding this view, we output the Python traceback to the error 500 page.
    """
    trace = traceback.format_exc()
    return("<pre>" + trace + "</pre>"), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)
