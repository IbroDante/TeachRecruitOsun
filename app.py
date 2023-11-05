from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
from flask_wtf import FlaskForm
from wtforms.fields import StringField, DateTimeField, SelectField, IntegerField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo, DataRequired
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from flask_wtf.file import FileField, FileAllowed
from flask import send_file
import os
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
from wtforms.widgets import TextArea


app = Flask(__name__)
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root123@localhost/teachosun'
app.secret_key = 'root1234'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    roles = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    # Add a relationship to link User and Form models
    forms = relationship('Form', backref='user_forms', lazy=True)

    def __init__(self, name, username, email, password, roles=None):
        self.name = name
        self.username = username
        self.email = email
        self.password = password
        self.roles = roles


class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photo_path = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    birthday = db.Column(db.DateTime, nullable=True)
    gender = db.Column(db.String(10), nullable=False)
    marital = db.Column(db.String(10), nullable=False)
    phonenumber = db.Column(db.String(20), nullable=False)
    institution = db.Column(db.String(20), nullable=False)
    qualification = db.Column(db.String(20), nullable=False)
    grade = db.Column(db.String(20), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    lga = db.Column(db.String(20), nullable=False)
    trcn = db.Column(db.String(20), nullable=False)
    courseofstudy = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    zipcode = db.Column(db.String(20), nullable=False)

    # Add a foreign key column that references the User model
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref='form_user', lazy=True)

    def __init__(self, photo_path, name, birthday, gender, marital, phonenumber, institution, qualification, grade, state, lga, trcn, courseofstudy, address, city, zipcode):
        self.photo_path = photo_path
        self.name = name
        self.birthday = birthday
        self.gender = gender
        self.marital = marital
        self.phonenumber = phonenumber
        self.institution = institution
        self.qualification = qualification
        self.grade = grade
        self.state = state
        self.lga = lga
        self.trcn = trcn
        self.courseofstudy = courseofstudy
        self.address = address
        self.city = city
        self.zipcode = zipcode


class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    form_id = db.Column(db.Integer, ForeignKey('form.id'), nullable=False)

    def __init__(self, name, description, file_path, form_id):
        self.name = name
        self.description = description
        self.file_path = file_path
        self.form_id = form_id


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Full Name"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo(
        'password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exists, Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()

        if existing_user_email:
            raise ValidationError(
                "That email already exists, Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()

        if not user:
            raise ValidationError(
                "Username not found. Please check your username.")

    def validate_password(self, password):
        user = User.query.filter_by(username=self.username.data).first()

        if user and not bcrypt.check_password_hash(user.password, password.data):
            raise ValidationError(
                "Incorrect password. Please check your password.")


class RegForm(FlaskForm):
    photo_path = FileField('Upload Photo', validators=[
        FileAllowed(['jpg', 'png', 'jpeg'])])
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Full Name"})
    birthday = DateTimeField(validators=[InputRequired(
    )], format='%Y-%m-%d', render_kw={"placeholder": "Birth Day"})
    gender = SelectField(validators=[InputRequired()], choices=[('select', 'Select'), (
        'female', 'Female'), ('male', 'Male'), ('other', 'Other')], render_kw={"placeholder": "Gender"})
    marital = SelectField(validators=[InputRequired()], choices=[('select', 'Marital Status'), (
        'married', 'Married'), ('single', 'Single'), ('divorced', 'Divorced')], render_kw={"placeholder": "Marital Status"})
    phonenumber = IntegerField(validators=[InputRequired()], render_kw={
                               "placeholder": "Phone Number"})
    institution = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Institution"})
    qualification = SelectField(validators=[InputRequired()], choices=[('select qualification', 'Select Qualification'), ('bachelors degree', 'Bachelors Degree'), ('hnd/nd', 'HND/ND'),
                                                                       ('nce', 'NCE'), ('others', 'Others')], render_kw={"placeholder": "Highest Qualification"})

    grade = SelectField(validators=[InputRequired()], choices=[('select grade', 'Select Grade'), ('first class', 'First Class'), ('second class upper', 'Second Class Upper'),
                                                               ('second class lower', 'Second Class Lower'), ('third class', 'Third Class'), ('pass', 'Pass'), ('others', 'Others')], render_kw={"placeholder": "Grade"})
    state = SelectField(validators=[InputRequired()], choices=[('select state', 'Select State'), ('ondo state', 'Ondo State'), ('ogun state', 'Ogun state'),
                                                               ('osun state', 'Osun State'), ('oyo state', 'Oyo State'), ('ekiti state', 'Ekiti State'), ('others', 'Others')], render_kw={"placeholder": "State of Origin"})
    lga = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Local Govt"})
    trcn = SelectField(validators=[InputRequired()], choices=[('select', 'Are you a Registered Member of TRCN'), (
        'yes', 'Yes'), ('no', 'No')], render_kw={"placeholder": "Are you a Registered Member of TRCN"})

    courseofstudy = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Course of Study"})
    address = StringField(validators=[InputRequired(), Length(
        min=7, max=100)], render_kw={"placeholder": "Address"})
    city = StringField(validators=[InputRequired(), Length(
        min=7, max=100)], render_kw={"placeholder": "City"})
    zipcode = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Zip Code"})

    material_name = StringField(validators=[Length(max=100)], render_kw={
        "placeholder": "Material Name"})
    material_description = StringField(validators=[Length(max=255)], render_kw={
        "placeholder": "Material Description"})
    material_file = FileField('Upload Material')
    submit = SubmitField("Submit")


def validate_user_info(user_id, name, phonenumber):
    user = User.query.get(user_id)
    if user and (user.name == name or Form.query.filter_by(user_id=user.id, name=name, phonenumber=phonenumber).first()):
        return True
    return False

    # def validate_phonenumber(self, phonenumber):
    #     existing_user_phonenumber = User.query.filter_by(phonenumber=phonenumber.data).first()

    #     if existing_user_phonenumber:
    #         raise ValidationError("That Phone Number already exists. Please choose a different one.")

    # def validate_email(self, email):
    #     existing_user_email = User.query.filter_by(email=email.data).first()

    #     if existing_user_email:
    #         raise ValidationError("That email already exists. Please choose a different one.")


with app.app_context():
    #     # Create database tables using db.create_all()
    db.create_all()


@app.route("/")
def main():
    return render_template("index.html")


@app.route("/index.html")
def index():
    return render_template("index.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template("login.html", form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    user = current_user
    user_forms = Form.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", user_forms=user_forms, user=current_user)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            name=form.name.data,
            roles="user"
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route("/form.html", methods=['GET', 'POST'])
@login_required
def form():
    form = RegForm()

    # Check if the user has already submitted a form
    existing_form = Form.query.filter_by(user_id=current_user.id).first()

    if existing_form:
        flash("You have already submitted a form!")
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        # Get the current user who is logged in
        user = current_user

        if not validate_user_info(user.id, form.name.data, form.phonenumber.data):
            flash(
                'Name does not match your profile creation. Please check your information.')
            return render_template("form.html", form=form)

        photo_path = None

        # Handle photo upload
        if form.photo_path.data:  # Check if a photo has been uploaded
            # Save the uploaded photo to a directory (you can customize this)
            photo_path = os.path.join(
                app.config['UPLOAD_FOLDER'], secure_filename(form.photo_path.data.filename))
            form.photo_path.data.save(photo_path)

        # Create a new form record
        new_form = Form(
            photo_path=photo_path,  # Save the photo file path in the database
            name=form.name.data,
            birthday=form.birthday.data,
            gender=form.gender.data,
            marital=form.marital.data,
            phonenumber=form.phonenumber.data,
            institution=form.institution.data,
            qualification=form.qualification.data,
            grade=form.grade.data,
            state=form.state.data,
            lga=form.lga.data,
            trcn=form.trcn.data,
            courseofstudy=form.courseofstudy.data,
            address=form.address.data,
            city=form.city.data,
            zipcode=form.zipcode.data
        )

        new_form.user = current_user

        db.session.add(new_form)
        db.session.commit()

        # Handle material upload only if the form submission is valid
        if form.material_file.data:
            # Save the uploaded file to a directory (you can customize this)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(
                form.material_file.data.filename))
            form.material_file.data.save(file_path)

            # Create a new material associated with the form submission
            new_material = Material(
                name=form.material_name.data,
                description=form.material_description.data,
                file_path=file_path,
                form_id=new_form.id
            )

            db.session.add(new_material)
            db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template("form.html", form=form)


# print form


@app.route("/print_form/<int:form_id>")
@login_required
def print_form(form_id):
    user_form = Form.query.filter_by(
        id=form_id, user_id=current_user.id).first()
    if user_form:
        return render_template("print_form.html", user_form=user_form)
    else:
        flash("Form not found.")
        return redirect(url_for('dashboard'))


# Delete Form
@app.route("/delete_form/<int:form_id>", methods=['POST'])
@login_required
def delete_form(form_id):
    deleted_form = Form.query.filter_by(
        id=form_id, user_id=current_user.id).first()

    if deleted_form is None:
        flash("Form.")
    else:
        db.session.delete(deleted_form)
        db.session.commit()
        flash("Form deleted successfully.")

    return redirect(url_for('dashboard'))


@app.route("/download_material/<int:material_id>")
def download_material(material_id):
    material = Material.query.get(material_id)

    if material:
        return send_file(material.file_path, as_attachment=True)
    else:
        return redirect(url_for('dashboard'))


@app.route("/delete_material/<int:material_id>")
@login_required
def delete_material(material_id):
    material = Material.query.get(material_id)

    if material:
        # Check if the material belongs to the current user's form
        if material.form.user_id == current_user.id:
            # Delete the material file from the filesystem
            os.remove(material.file_path)

            # Delete the material from the database
            db.session.delete(material)
            db.session.commit()
        else:
            flash('Unauthorized to delete this material', 'error')

    return redirect(url_for('dashboard'))


@app.route("/teachform.html")
@login_required
def teach():
    return render_template("teachform.html")


@app.route("/about.html")
def about():
    return render_template("about.html")


@app.route("/contact.html")
def contact():
    return render_template("contact.html")


@app.route("/faq.html")
def faq():
    return render_template("faq.html")


if __name__ == '__main__':
    app.run()
