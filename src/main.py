# Standard Library Imports
import logging
import random
import string
import uuid
import hashlib
# Third-party Imports
import pyotp
import qrcode
import yagmail
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from passlib.context import CryptContext
from contextlib import asynccontextmanager

# Internal Module Imports
from src.database import db  # Ensures database is initialized when FastAPI starts
from src.encryption_routes import router as encryption_router
from src.models import (
    EmailRequest,
    LoginRequest,
    Login_status,
    OTPVerificationRequest,
    UpdatePasswordRequest,
    UserRequest
)
from src.user_operations import UserOperations
from src.webauthn_routes import router as webauthn_router
from starlette.middleware.sessions import SessionMiddleware
from src.core.email_service import EmailTemplateManager
from datetime import datetime, timedelta
import jwt
from fastapi import Response, Request


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
SECRET_KEY = "your-32-character-secret-key-1234567890"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = BackgroundScheduler()
    scheduler.add_job(user_ops.cleanup_expired_otps, 'interval', minutes=30)
    scheduler.start()
    yield
    scheduler.shutdown()
    db.close_connection()  # Your existing cleanup

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow all origins (change this to frontend domain in production)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
user_ops = UserOperations()

# Include the encryption router with optional prefix
app.include_router(encryption_router)
app.include_router(webauthn_router)

@app.post("/add_user")
async def add_user(user: UserRequest):
    """API endpoint to add a new user."""
    return user_ops.add_user(user.first_name, user.last_name, user.email, user.password)

@app.post("/login")
async def login(user: LoginRequest, response: Response):
    """API endpoint to verify user login credentials with 2FA."""
    db_user = user_ops.get_user_by_email(user.email)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email ")

    if not pwd_context.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Verify OTP
    totp = pyotp.TOTP(db_user["totp_secret"])
    if not totp.verify(user.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")

        # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode(
        {
            "sub": user.email,
            "exp": datetime.utcnow() + access_token_expires
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    # Set HTTP-only cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=True,  # In production
        samesite="Lax"
    )

    return {"message": "Login successful"}


@app.get("/validate_session")
async def validate_session(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return {"authenticated": False}

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"authenticated": True, "email": payload["sub"]}
    except jwt.ExpiredSignatureError:
        return {"authenticated": False, "reason": "Token expired"}
    except jwt.InvalidTokenError:
        return {"authenticated": False, "reason": "Invalid token"}

@app.post("/generate_qr")
async def generate_qr(request: EmailRequest):
    """Generate a QR code for Google Authenticator."""
    user = user_ops.get_user_by_email(request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    totp_secret = user["totp_secret"]
    otp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=request.email, issuer_name="ED-App")

    # Generate QR code
    qr = qrcode.make(otp_uri)
    img_bytes = qr.get_image().convert("RGB")

    response = Response(content=img_bytes.tobytes(), media_type="image/png")
    return {"qr_url": otp_uri, "secret": totp_secret}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(
        key="session_token",
        httponly=True,
        secure=True,
        samesite="Lax"
    )
    return {"message": "Logged out successfully"}

@app.post("/login-status")
async def get_login_status(request: Login_status):
    """API endpoint to get a user's login status."""
    return user_ops.get_login_status(request.email)


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def send_email(email: str, otp: str, reference_key: str):
    sender_email = "idoican80@gmail.com"
    password = "pbqloirhdnnviaal"
    full_name = user_ops.get_user_by_emailid(email)
    yag = yagmail.SMTP(user=sender_email, password=password)
    subject = "Your Secure Login Verification Code | ED-App"
    email_manager = EmailTemplateManager()
    body = email_manager.render_verification_email({
        "full_name": full_name,
        "otp": otp,
        "reference_key": reference_key
    })
    yag.send(
        to=email,
        subject=subject,
        contents=body,
        headers={"Content-Type": "text/html"}
    )


@app.post("/generate_otp")
async def generate_otp_api(request: EmailRequest):
    logger.info(f"Received OTP generation request for email: {request.email}")
    try:
        db_user = user_ops.get_user_by_email(request.email)
        if not db_user:
            logger.warning(f"User not found: {request.email}")
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Database error for {request.email}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    otp = generate_otp()
    reference_key = str(uuid.uuid4())

    # Store OTP in database
    if not user_ops.store_otp(request.email, otp, reference_key):
        raise HTTPException(status_code=500, detail="Failed to store OTP")

    logger.info(f"Generated OTP {otp} for email {request.email} with reference key {reference_key}")

    send_email(request.email, otp, reference_key)

    return {"reference_key": reference_key}


@app.post("/verify_otp_qr")
async def verify_otp_api(request: OTPVerificationRequest):
    verification = user_ops.verify_otp(request.reference_key, request.otp)

    if not verification["is_valid"]:
        raise HTTPException(
            status_code=400,
            detail=verification.get("error", "OTP verification failed")
        )

    # OTP verified, generate QR
    qr_response = await generate_qr(EmailRequest(**{"email": verification["email"]}))

    return qr_response


@app.post("/verify_otp_fp")
async def verify_otp_api(request: OTPVerificationRequest):
    verification = user_ops.verify_otp(request.reference_key, request.otp)

    if not verification["is_valid"]:
        raise HTTPException(
            status_code=400,
            detail=verification.get("error", "OTP verification failed")
        )

    return {"otp_verification_status": "True"}

@app.post("/update_password")
async def update_password(request: UpdatePasswordRequest):
    """API endpoint to update user password."""
    return user_ops.update_password(request.email, request.new_password)

@app.post("/get_user_full_name")
async def get_user_full_name_api(request: EmailRequest):
    """
    API endpoint to get a user's full name (first + last name) by email.
    Returns JSON with the full name string.
    """
    try:
        full_name = user_ops.get_user_full_name(request.email)
        return {"full_name": full_name}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/current_user")
async def get_current_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"email : {payload["sub"]}")
        return {"email": payload["sub"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

