from flask import Flask, render_template, redirect, url_for, session, flash, request, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
import boto3
import os
from werkzeug.utils import secure_filename
import uuid
from io import BytesIO
from crypto_utils import encrypt_data
from crypto_utils import decrypt_data

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'my_schema'
app.secret_key = 'your_secret_key_here'

# AWS S3 Configuration
app.config['S3_BUCKET'] = 'your-bucket-name'
app.config['S3_KEY'] = 'your-access-key'
app.config['S3_SECRET'] = 'your-secret-key'
app.config['S3_LOCATION'] = 'https://{}.s3.amazonaws.com/'.format(app.config['S3_BUCKET'])


mysql = MySQL(app)

# Initialize S3 client
s3 = boto3.client(
    "s3",
    aws_access_key_id=app.config['S3_KEY'],
    aws_secret_access_key=app.config['S3_SECRET']
)

class UploadForm(FlaskForm):
    file = FileField("File", validators=[DataRequired()])
    submit = SubmitField("Upload")

class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self,field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where email=%s",(field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        # store data into database 
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (fullName,email,hashed_password) VALUES (%s,%s,%s)",(name,email,hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html',form=form)

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s",(email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('home'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html',form=form)

@app.route('/home')
def home():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('home.html',user=user)
            
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        
        if file:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"

            # Encrypt file before uploading
            file_data = file.read()
            encrypted_data = encrypt_data(file_data)
            encrypted_stream = BytesIO(encrypted_data)

            
            # Upload to S3
            s3.upload_fileobj(
                file,
                app.config["S3_BUCKET"],
                unique_filename,
                ExtraArgs={
                    "ContentType": file.content_type
                }
            )
            
            # Store file info in database
            user_id = session['user_id']
            cursor = mysql.connection.cursor()
            cursor.execute(
                "INSERT INTO user_files (user_id, file_name, s3_key) VALUES (%s, %s, %s)",
                (user_id, filename, unique_filename)
            )
            mysql.connection.commit()
            cursor.close()
            
            flash("File uploaded successfully!")
            return redirect(url_for('my_files'))
    
    return render_template('upload.html', form=form)

@app.route('/my-files')
def my_files():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, file_name, s3_key, upload_date FROM user_files WHERE user_id = %s", (user_id,))
    files = cursor.fetchall()
    cursor.close()
    
    return render_template('my_files.html', files=files)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT file_name, s3_key FROM user_files WHERE id = %s AND user_id = %s", 
        (file_id, user_id)
    )
    file_info = cursor.fetchone()
    cursor.close()
    
    if not file_info:
        flash("File not found or you don't have permission to download it.")
        return redirect(url_for('my_files'))
    
    file_name = file_info[0]
    s3_key = file_info[1]
    
    # Get file from S3
    file_obj = BytesIO()
    s3.download_fileobj(app.config["S3_BUCKET"], s3_key, file_obj)
    file_obj.seek(0)

    # Decrypt the file
    decrypted_data = decrypt_data(file_obj.read())
    decrypted_stream = BytesIO(decrypted_data)

    
    return send_file(
        file_obj,
        as_attachment=True,
        download_name=file_name
    )

if __name__ == '__main__':
    app.run(debug=True)
