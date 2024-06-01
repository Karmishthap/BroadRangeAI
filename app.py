from flask import Flask, render_template, request, jsonify, redirect, make_response, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import uuid
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from python_code import extract_video_id, get_transcript, answer_question_with_transformers, send_email, translate_text, get_function_by_signal, send_signup_email, send_login_email
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'
# Configure Flask-Mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'botmyurl@gmail.com'
app.config['MAIL_PASSWORD'] = 'zoki lhrj pncf dnuo'
app.config['MAIL_DEFAULT_SENDER'] = 'botmyurl@gmail.com'
mail = Mail(app)

db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    session_token = db.Column(db.String(255))
    reset_token = db.Column(db.String(255))
    reset_token_expiration = db.Column(db.DateTime)

# Create database tables within the application context
with app.app_context():
     db.create_all()

# Helper functions
# def validate_password(email, password):
#     """Validate user's password."""
#     user = User.query.filter_by(email=email).first()
#     if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
#         return True
#     return False
def validate_password(email, password):
    """Validate user's password."""
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return True
    return False

def generate_session_token():
    """Generate a unique session token."""
    return str(uuid.uuid4())

def generate_reset_token():
    """Generate a unique reset token."""
    return str(uuid.uuid4())

def send_reset_email(to_email, reset_token):
    """Send reset password email."""
    msg = Message('Reset Your Password', recipients=[to_email])
    reset_link = url_for('reset_password', token=reset_token, _external=True)
    msg.body = f'Click the link below to reset your password:\n{reset_link}'
    mail.send(msg)

# Routes
@app.route('/')
def index():
    """Render the login page."""
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    """Authenticate user and set session token."""
    email = request.form['email']
    password = request.form['password']
    
    if validate_password(email, password):
        session_token = generate_session_token()
        user = User.query.filter_by(email=email).first()
        user.session_token = session_token
        db.session.commit()
        
        # Set session token as a cookie
        response = make_response(redirect('/dashboard'))
        response.set_cookie('session_token', session_token, httponly=True, secure=True)
        return response
    else:
        flash('Invalid email or password', 'error')
        return redirect('/')

@app.route('/dashboard')
def dashboard():
    return render_template('index.html')
# @app.route('/dashboard')
# def dashboard():
#     """Render dashboard if user is authenticated."""
#     session_token = request.cookies.get('session_token')
#     user = User.query.filter_by(session_token=session_token).first()
#     if user:
#         return 'Welcome to the dashboard!'
#     return 'Access denied'

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     """Handle user registration."""
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
        
#         if User.query.filter_by(email=email).first():
#             flash('Email already exists. Please use a different email.', 'error')
#             return redirect('/signup')
#         else:
#             hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
#             new_user = User(email=email, password=hashed_password.decode('utf-8'))
#             db.session.add(new_user)
#             db.session.commit()
#             flash('Account created successfully. Please log in.', 'success')
#             return redirect('/')
#     return render_template('signup.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user registration."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please use a different email.', 'error')
            return redirect('/signup')
        else:
            # Hash the password before storing it
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. Please log in.', 'success')
            return redirect('/')
    return render_template('signup.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password."""
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate reset token and set expiration time
            reset_token = generate_reset_token()
            user.reset_token = reset_token
            user.reset_token_expiration = datetime.now() + timedelta(hours=1)  # Set expiration time (e.g., 1 hour)
            db.session.commit()

            # Send reset password email
            send_reset_email(email, reset_token)
            
            flash('Reset password link has been sent to your email.', 'info')
        else:
            flash('Email not found.', 'error')
        return redirect('/')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset."""
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect('/reset_password/' + token)
        
        # Find the user by the reset token
        user = User.query.filter_by(reset_token=token).first()
        
        if user:
            # Check if the reset token is still valid
            if user.reset_token_expiration >= datetime.now():
                # Update the user's password
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                user.password = hashed_password
                # Clear the reset token and its expiration
                user.reset_token = None
                user.reset_token_expiration = None
                db.session.commit()
                
                flash('Password reset successfully. Please log in with your new password.', 'success')
                return redirect('/')
            else:
                flash('Reset token has expired. Please try again.', 'error')
                return redirect('/forgot_password')
        else:
            flash('Invalid or expired reset token.', 'error')
            return redirect('/forgot_password')
    
    return render_template('reset_password.html', token=token)

@app.route('/chatbot')
def chatbot():
    return render_template('page.html')

# @app.route('/send_email', methods=['POST'])
# def send_email_route():
#     try:
#         to_emails = request.form.get('to_emails').split(',')
#         subject = request.form['subject']
#         content = request.form['content']
#         signal = 'email'
#         email_function = get_function_by_signal(signal)
        
#         if email_function:
#             for to_email in to_emails:
#                 email_function(to_email, subject, content)
#             return jsonify({'status': 'Email sent successfully!'})
#         else:
#             return jsonify({'error': 'Invalid signal'})
#     except Exception as e:
#         return jsonify({'error': f"An error occurred: {str(e)}"})

# Jinja2 environment setup
file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

# Route to send email
@app.route('/send_email', methods=['POST'])
def send_email_route():
    try:
        subject = "Your Query answered by Multilingual URL ChatBot"
        to_emails = request.form.get('to_emails').split(',')
        extracted_question = request.form.get('question')
        extracted_answer = request.form.get('answer')
        extarcted_url = request.form.get('url')
        extracted_description = request.form.get('description')
        # Render HTML template
        #template = env.get_template('email_template.html')
        content = render_template(
            'email_template.html',
            url=extarcted_url,
            description=extracted_description,
            question=extracted_question,
            answer=extracted_answer
        )
        # signal = 'email'
        # email_function = get_function_by_signal(signal)
        print("Content of the email:", content)
        
        for to_email in to_emails:
            msg = Message(subject, recipients=[to_email])
            msg.html = content
            mail.send(msg)

        # if email_function:
        #     for to_email in to_emails:
        #         msg = Message(subject, recipients=[to_email])
        #         msg.html = content
        #         mail.send(msg)
        return jsonify({'status': 'Email sent successfully!'})
        # else:
        #     return jsonify({'error': 'Invalid signal'})        
    except Exception as e:
        return jsonify({'error': f"An error occurred: {str(e)}"})
    
@app.route('/process_url', methods=['POST'])
def process_url():
    try:
        global transcript  # Use the global variable
        youtube_url = request.form['youtube_url']
        video_id = extract_video_id(youtube_url)
        transcript = get_transcript(video_id)
        return jsonify(transcript)
    except Exception as e:
        return jsonify({'error': f"An error occurred: {e}"})

@app.route('/transcript_print', methods=['POST'])
def transcript_print():
    # try:
        if transcript:
            transcript_with_timestamps2 = [
                f"{int(entry['start'] // 60):02d}:{int(entry['start'] % 60):02d} - {entry['text']}"
                for entry in transcript
            ]
            return jsonify({'transcript': transcript_with_timestamps2})
        else:
            return jsonify({'transcript': 'No transcript available'})
    # except Exception as e:
        # error_message = str(e)
        # if "video language" in error_message.lower():
        #     return jsonify({'error': 'Video language is different'})
        # else:
        #     return jsonify({'error': 'An error occurred during processing'})


@app.route('/ask_question', methods=['POST'])
def ask_question():
    try:
        question = request.form['question']
        target_language = request.form.get('target_language', 'en')  # Default to English if not provided

        if target_language.lower() == 'other':
            target_language = request.form.get('other_language_textbox', 'en')
            
        if not transcript:
            return jsonify({'error': 'No transcript available'})

        if question.lower() == 'transcript':
            transcript_with_timestamps = [
                f"{int(entry['start'] // 60):02d}:{int(entry['start'] % 60):02d} - {entry['text']}"
                for entry in transcript
            ]
            return jsonify({'transcript': transcript_with_timestamps})
        
        ai_answer = answer_question_with_transformers(transcript, question, target_language)
        return jsonify({'answer': ai_answer})
    except Exception as e:
        return jsonify({'error': f"Error processing question: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)
