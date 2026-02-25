from flask import Flask, render_template, request, redirect, session, flash, jsonify
from supabase import create_client
import random
import bcrypt
import datetime
import smtplib
import logging
import re
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ⚙️ LOGGING CONFIGURATION
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "supersecretkey_change_in_production_123!@#"  # ⚠️ CHANGE THIS!

# 🔑 SUPABASE CONFIGURATION
try:
    SUPABASE_URL = {"url"}
    SUPABASE_KEY = {"key"}
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    logger.info("Supabase client initialized successfully")
except Exception as e:
    logger.critical(f"Failed to initialize Supabase: {str(e)}")
    supabase = None

# 📧 EMAIL CONFIGURATION
SENDER_EMAIL = "jadavjivraj2008@gmail.com"
SENDER_APP_PASSWORD = "uzvs thbb hvyd btzf"
OTP_VALIDITY_SECONDS = 300  # 5 minutes


# 🛡️ VALIDATION HELPERS
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username(username):
    """Validate username: 3-20 chars, alphanumeric and underscore only"""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None


def validate_otp(otp):
    """Validate OTP format: exactly 6 digits"""
    return otp.isdigit() and len(otp) == 6


# 🔐 SESSION PROTECTION DECORATOR
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash('Please login first', 'error')
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function


# 📧 SEND OTP EMAIL WITH ERROR HANDLING
def send_otp_email(recipient_email, otp_code):
    """
    Send OTP via email with proper error handling
    Returns: (success: bool, error_message: str or None)
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = "Your OTP Code"
        
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #1a1a1a; color: #fff; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #2a2a2a; padding: 30px; border-radius: 10px;">
                    <h2 style="color: #00a8ff;">Your Verification Code</h2>
                    <p style="font-size: 16px;">Your OTP code is:</p>
                    <div style="background-color: #3a3a3a; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                        <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #00a8ff;">{otp_code}</span>
                    </div>
                    <p style="color: #999;">This code will expire in 5 minutes.</p>
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
                </div>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Connect and send
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"OTP sent successfully to {recipient_email}")
        return True, None
        
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication failed - check email credentials")
        return False, "Email configuration error. Please contact support."
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error occurred: {str(e)}")
        return False, "Failed to send email. Please try again."
    except Exception as e:
        logger.error(f"Unexpected error sending email: {str(e)}")
        return False, "An unexpected error occurred. Please try again."


# 🆕 REGISTER NEW USER
@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            
            # Input validation
            if not username or not email:
                flash("All fields are required", "error")
                return render_template("register.html")
            
            if not validate_username(username):
                flash("Username must be 3-20 characters (letters, numbers, underscore only)", "error")
                return render_template("register.html")
            
            if not validate_email(email):
                flash("Invalid email format", "error")
                return render_template("register.html")
            
            # Check database connection
            if not supabase:
                logger.error("Database connection unavailable")
                flash("Service temporarily unavailable. Please try again later.", "error")
                return render_template("register.html")
            
            # Generate OTP
            otp = str(random.randint(100000, 999999))
            otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
            expires = (datetime.datetime.now() + datetime.timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat()
            
            # Check if user exists
            user_response = supabase.table("usersdata").select("*").eq("email", email).execute()
            
            if user_response.data:
                # Update existing user
                supabase.table("usersdata").update({
                    "otp_hash": otp_hash,
                    "otp_expires": expires
                }).eq("email", email).execute()
                logger.info(f"OTP regenerated for existing user: {email}")
            else:
                # Check if username is taken
                username_check = supabase.table("usersdata").select("*").eq("username", username).execute()
                if username_check.data:
                    flash("Username already taken. Please choose another.", "error")
                    return render_template("register.html")
                
                # Insert new user
                supabase.table("usersdata").insert({
                    "username": username,
                    "email": email,
                    "otp_hash": otp_hash,
                    "otp_expires": expires,
                    "is_verified": False,
                    "welcome_text": ""
                }).execute()
                logger.info(f"New user created: {email}")
            
            # Send OTP
            success, error_msg = send_otp_email(email, otp)
            if not success:
                flash(error_msg, "error")
                return render_template("register.html")
            
            session["email"] = email
            session["otp_attempts"] = 0
            flash("OTP sent to your email!", "success")
            return redirect("/verify")
            
        except Exception as e:
            logger.error(f"Error in register route: {str(e)}")
            flash("An unexpected error occurred. Please try again.", "error")
            return render_template("register.html")
    
    return render_template("register.html")


# 🔑 LOGIN EXISTING USER
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            
            if not username:
                flash("Username is required", "error")
                return render_template("login.html")
            
            if not validate_username(username):
                flash("Invalid username format", "error")
                return render_template("login.html")
            
            if not supabase:
                flash("Service temporarily unavailable. Please try again later.", "error")
                return render_template("login.html")
            
            # Find user
            user_response = supabase.table("usersdata").select("*").eq("username", username).execute()
            
            if not user_response.data:
                flash("Account not found. Please register first.", "error")
                return render_template("login.html")
            
            email = user_response.data[0]["email"]
            
            # Generate new OTP
            otp = str(random.randint(100000, 999999))
            otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
            expires = (datetime.datetime.now() + datetime.timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat()
            
            supabase.table("usersdata").update({
                "otp_hash": otp_hash,
                "otp_expires": expires
            }).eq("username", username).execute()
            
            # Send OTP
            success, error_msg = send_otp_email(email, otp)
            if not success:
                flash(error_msg, "error")
                return render_template("login.html")
            
            session["email"] = email
            session["otp_attempts"] = 0
            flash("OTP sent to your email!", "success")
            return redirect("/verify")
            
        except Exception as e:
            logger.error(f"Error in login route: {str(e)}")
            flash("An unexpected error occurred. Please try again.", "error")
            return render_template("login.html")
    
    return render_template("login.html")


# ✅ VERIFY OTP
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "email" not in session:
        flash("Session expired. Please login again.", "error")
        return redirect("/")
    
    if request.method == "POST":
        try:
            otp_input = request.form.get("otp", "").strip()
            email = session.get("email")
            
            # Check OTP attempts
            attempts = session.get("otp_attempts", 0)
            if attempts >= 5:
                session.clear()
                flash("Too many failed attempts. Please request a new OTP.", "error")
                return redirect("/")
            
            if not validate_otp(otp_input):
                session["otp_attempts"] = attempts + 1
                flash("OTP must be exactly 6 digits", "error")
                return render_template("verify.html")
            
            if not supabase:
                flash("Service temporarily unavailable. Please try again later.", "error")
                return render_template("verify.html")
            
            # Get user data
            user_response = supabase.table("usersdata").select("*").eq("email", email).single().execute()
            
            if not user_response.data:
                session.clear()
                flash("User not found. Please register again.", "error")
                return redirect("/")
            
            user_data = user_response.data
            
            # Check if OTP exists
            if not user_data.get("otp_hash"):
                flash("No OTP found. Please request a new one.", "error")
                return redirect("/")
            
            # Check OTP expiration
            otp_expires = datetime.datetime.fromisoformat(user_data["otp_expires"])
            if datetime.datetime.now() > otp_expires:
                flash("OTP has expired. Please request a new one.", "error")
                return redirect("/")
            
            # Verify OTP
            if bcrypt.checkpw(otp_input.encode(), user_data["otp_hash"].encode()):
                # Success! Clear OTP and mark verified
                supabase.table("usersdata").update({
                    "is_verified": True,
                    "last_login": datetime.datetime.now().isoformat(),
                    "otp_hash": None,
                    "otp_expires": None
                }).eq("email", email).execute()
                
                session["otp_attempts"] = 0
                session["verified"] = True
                logger.info(f"User verified successfully: {email}")
                flash("Login successful!", "success")
                return redirect("/welcome")
            else:
                session["otp_attempts"] = attempts + 1
                remaining = 5 - (attempts + 1)
                flash(f"Invalid OTP. {remaining} attempts remaining.", "error")
                return render_template("verify.html")
                
        except Exception as e:
            logger.error(f"Error in verify route: {str(e)}")
            flash("An unexpected error occurred. Please try again.", "error")
            return render_template("verify.html")
    
    return render_template("verify.html")


# 🔄 RESEND OTP
@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    try:
        email = session.get("email")
        if not email:
            return jsonify({"success": False, "message": "Session expired"}), 401
        
        if not supabase:
            return jsonify({"success": False, "message": "Service unavailable"}), 503
        
        # Generate new OTP
        otp = str(random.randint(100000, 999999))
        otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
        expires = (datetime.datetime.now() + datetime.timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat()
        
        supabase.table("usersdata").update({
            "otp_hash": otp_hash,
            "otp_expires": expires
        }).eq("email", email).execute()
        
        # Send new OTP
        success, error_msg = send_otp_email(email, otp)
        if not success:
            return jsonify({"success": False, "message": error_msg}), 500
        
        session["otp_attempts"] = 0
        logger.info(f"OTP resent to: {email}")
        return jsonify({"success": True, "message": "New OTP sent!"})
        
    except Exception as e:
        logger.error(f"Error resending OTP: {str(e)}")
        return jsonify({"success": False, "message": "Failed to resend OTP"}), 500


# 🏠 WELCOME PAGE
@app.route("/welcome", methods=["GET", "POST"])
@login_required
def welcome():
    try:
        email = session.get("email")
        
        if not supabase:
            flash("Service temporarily unavailable.", "error")
            return redirect("/logout")
        
        if request.method == "POST":
            welcome_text = request.form.get("welcome_text", "").strip()
            
            if len(welcome_text) > 500:
                flash("Text is too long (max 500 characters)", "error")
            else:
                supabase.table("usersdata").update({
                    "welcome_text": welcome_text
                }).eq("email", email).execute()
                flash("Text saved successfully!", "success")
        
        user_response = supabase.table("usersdata").select("*").eq("email", email).single().execute()
        
        if not user_response.data:
            session.clear()
            flash("User not found", "error")
            return redirect("/")
        
        return render_template("welcome.html", user=user_response.data)
        
    except Exception as e:
        logger.error(f"Error in welcome route: {str(e)}")
        flash("An error occurred loading your profile", "error")
        return redirect("/logout")


# 🚪 LOGOUT
@app.route("/logout")
def logout():
    email = session.get("email")
    session.clear()
    if email:
        logger.info(f"User logged out: {email}")
    flash("You have been logged out successfully", "info")
    return redirect("/")


# ❌ ERROR HANDLERS
@app.errorhandler(404)
def not_found(e):
    logger.warning(f"404 error: {request.url}")
    return render_template("error.html", error_code=404, error_message="Page not found"), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 error: {str(e)}")
    return render_template("error.html", error_code=500, error_message="Internal server error"), 500


@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return render_template("error.html", error_code=500, error_message="Something went wrong"), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)