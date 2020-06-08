from flask import Flask, render_template, redirect, request, send_file
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from bcrypt import hashpw, checkpw, gensalt
from os import listdir, stat, remove

users = {}
login_manager = LoginManager()
login_manager.login_view = "/login"
app = Flask("Flask-1")
app.config['SECRET_KEY'] = "sg16hs6h9ilm738fr5sgh54fkp0sw"
login_manager.init_app(app)
files_path = app.root_path + '\\files\\'


@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return users[user_id]
    return None


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Log in')


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')


class UploadForm(FlaskForm):
    file_object = FileField('File: ', validators=[FileRequired()])
    submit = SubmitField('Upload')


@app.route('/')
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    files = {}
    names = listdir(files_path)
    for name in names:
        files[name] = stat(files_path + name).st_size
        
    return render_template('index.html', title='index', path=files_path, files=files)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit() and request.method == 'POST':
        file = form.file_object.data
        file.save(files_path + file.filename)
        return redirect('/index')
    return render_template('upload.html', title='upload', form=form)


@app.route('/download/<filename>', methods=['GET', 'POST'])
@login_required
def download(filename):
    try:
        return send_file(files_path + filename, attachment_filename=filename, as_attachment=True)
    except Exception as e:
        return "File not found"


@app.route('/delete/<filename>', methods=['GET', 'POST'])
@login_required
def delete(filename):
    try:
        remove(files_path + filename)
        return redirect('/index')
    except Exception as e:
        return "File not found"


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit() and request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        remember = 'remember_me' in request.form and request.form['remember_me'] == 'y'
        if username in users:
            user = users[username]
            if checkpw(password.encode('utf-8'), user.user_hash):
                user.authenticated = True
                login_user(user, remember)
                return redirect('/index')
        form.username.errors.append("Invalid username or password")
        form.password.errors.append("Invalid username or password")
        return render_template('login.html', title='Login', form=form)
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
@login_required
def logout():
    user = current_user
    logout_user()
    user.authenticated = False
    return redirect('/login')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit() and request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]

        if username not in users.keys():
            users[username] = User(username, password)
            return redirect('/login')
        else:
            form.username.errors.append("User with this name already exists")
            return render_template('signup.html', title='Signup', form=form)
    return render_template('signup.html', title='Signup', form=form)


@app.route('/admin')
@login_required
def admin():
    if current_user.user_id == 'admin':
        return render_template('admin.html', title='Admin', users=users)
    return redirect('/index')


class User:
    user_id = 0
    user_hash = 0
    user_salt = 0
    authenticated = False

    def __init__(self, user_id, password):
        self.user_id = user_id
        self.user_salt = gensalt(12)
        self.user_hash = hashpw(password.encode('utf-8'), self.user_salt)
        print(self.user_id)
        print(self.user_hash)
        print(self.user_salt)

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id

    def get_hash(self):
        return self.user_hash

    def get_salt(self):
        return self.user_salt


users['admin'] = User('admin', 'admin')
app.run(port=8080, host='127.0.0.1')
