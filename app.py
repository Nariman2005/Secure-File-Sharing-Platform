from flask import Flask, render_template, redirect, url_for, session, flash, request, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import os
from werkzeug.utils import secure_filename
import uuid
from io import BytesIO
from crypto_utils import encrypt_data, compute_hash
from crypto_utils import decrypt_data, verify_hash
from config import Config

app = Flask(__name__)

# Load configuration from config.py
app.config['MYSQL_HOST'] = Config.MYSQL_HOST
app.config['MYSQL_USER'] = Config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = Config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = Config.MYSQL_DB
app.secret_key = Config.SECRET_KEY

# AWS S3 Configuration
app.config['S3_BUCKET'] = Config.S3_BUCKET
app.config['S3_KEY'] = Config.S3_KEY
app.config['S3_SECRET'] = Config.S3_SECRET
app.config['S3_LOCATION'] = Config.S3_LOCATION

mysql = MySQL(app)

# Initialize S3 client with explicit region
try:
    s3 = boto3.client(
        "s3",
        aws_access_key_id=app.config['S3_KEY'],
        aws_secret_access_key=app.config['S3_SECRET'],
        region_name='us-east-1'  # Add explicit region
    )
    # Test S3 connection
    s3.head_bucket(Bucket=app.config['S3_BUCKET'])
    print(f"✅ S3 connection successful. Bucket: {app.config['S3_BUCKET']}")
except ClientError as e:
    print(f"❌ S3 connection failed: {e}")
except NoCredentialsError:
    print("❌ AWS credentials not found")

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

            try:
                # Read file data and hash
                file_data = file.read()
                file_hash = compute_hash(file_data)

                # Append hash to data before encryption
                combined_data = f"{file_hash}::".encode() + file_data

                # Encrypt file before uploading
                encrypted_data = encrypt_data(combined_data)
                encrypted_stream = BytesIO(encrypted_data)

                # Upload to S3 with better error handling
                s3.upload_fileobj(
                    encrypted_stream,
                    app.config["S3_BUCKET"],
                    unique_filename,
                    ExtraArgs={
                        "ContentType": "application/octet-stream",
                        "ServerSideEncryption": "AES256"  # Add server-side encryption
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
                
                flash(f"File '{filename}' uploaded successfully!", "success")
                return redirect(url_for('my_files'))
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchBucket':
                    flash("S3 bucket does not exist. Please check your configuration.", "danger")
                elif error_code == 'AccessDenied':
                    flash("Access denied to S3 bucket. Please check your AWS permissions.", "danger")
                else:
                    flash(f"AWS S3 error: {e}", "danger")
                return redirect(url_for('upload_file'))
            except Exception as e:
                flash(f"Upload failed: {str(e)}", "danger")
                return redirect(url_for('upload_file'))
    
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
        flash("File not found or you don't have permission to download it.", "danger")
        return redirect(url_for('my_files'))
    
    file_name = file_info[0]
    s3_key = file_info[1]
    
    try:
        # Check if file exists in S3 first
        try:
            s3.head_object(Bucket=app.config["S3_BUCKET"], Key=s3_key)
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                flash(f"File '{file_name}' not found in storage.", "danger")
                return redirect(url_for('my_files'))
            elif e.response['Error']['Code'] == '403':
                flash("Access denied. Please check your AWS credentials and bucket permissions.", "danger")
                return redirect(url_for('my_files'))
            else:
                raise e
        
        # Get file from S3
        file_obj = BytesIO()
        s3.download_fileobj(app.config["S3_BUCKET"], s3_key, file_obj)
        file_obj.seek(0)

        # Decrypt the data
        decrypted_data = decrypt_data(file_obj.read())

        # Split the hash from the content
        header, actual_file_data = decrypted_data.split(b"::", 1)
        original_hash = header.decode()

        # Verify file integrity
        if not verify_hash(actual_file_data, original_hash):
            flash("File integrity check failed! The file may have been tampered with.", "danger")
            return redirect(url_for('my_files'))
        
        # Create BytesIO object for sending file
        decrypted_file_obj = BytesIO(actual_file_data)
        decrypted_file_obj.seek(0)
    
        return send_file(
            decrypted_file_obj,
            as_attachment=True,
            download_name=file_name,
            mimetype='application/octet-stream'
        )

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            flash("S3 bucket does not exist. Please check your configuration.", "danger")
        elif error_code == 'AccessDenied' or error_code == '403':
            flash("Access denied to S3. Please check your AWS credentials and permissions.", "danger")
        elif error_code == 'NoSuchKey':
            flash(f"File '{file_name}' not found in storage.", "danger")
        else:
            flash(f"AWS S3 error ({error_code}): {e}", "danger")
        return redirect(url_for('my_files'))
    except Exception as e:
        flash(f"Download failed: {str(e)}", "danger")
        return redirect(url_for('my_files'))

# Add a route to test S3 connection
@app.route('/test-s3')
def test_s3():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Test bucket access
        response = s3.head_bucket(Bucket=app.config['S3_BUCKET'])
        
        # List objects to test read permission
        objects = s3.list_objects_v2(Bucket=app.config['S3_BUCKET'], MaxKeys=1)
        
        flash("S3 connection successful! Bucket is accessible.", "success")
        return redirect(url_for('my_files'))
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            flash("S3 bucket 'secure-file-share-bucket-cyber-knights' does not exist.", "danger")
        elif error_code == '403' or error_code == 'AccessDenied':
            flash("Access denied to S3 bucket. Check your AWS credentials and permissions.", "danger")
        else:
            flash(f"S3 connection failed ({error_code}): {e}", "danger")
        return redirect(url_for('my_files'))
    except Exception as e:
        flash(f"S3 test failed: {str(e)}", "danger")
        return redirect(url_for('my_files'))

if __name__ == '__main__':
    app.run(debug=True)