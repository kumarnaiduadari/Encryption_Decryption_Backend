from fastapi import FastAPI, HTTPException
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from src.models import UserRequest, LoginRequest, TOTPSecret , EmailRequest , Login_status, OTPVerificationRequest, UpdatePasswordRequest
from src.user_operations import UserOperations
import src.user_operations
from src.database import db  # Ensures database is initialized when FastAPI starts
import pyotp
import qrcode
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
import random
import string
import yagmail
import uuid
import time, logging
from typing import Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield  # App is running
    db.close_connection()  # Runs on shutdown

app = FastAPI(lifespan=lifespan)

# ✅ Add CORS Middleware to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (change this to frontend domain in production)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
user_ops = UserOperations()

@app.post("/add_user")
async def add_user(user: UserRequest):
    """API endpoint to add a new user."""
    return user_ops.add_user(user.first_name, user.last_name, user.email, user.password)

@app.put("/update_user")
async def update_user(user: UserRequest):
    """API endpoint to update an existing user's details."""
    return user_ops.update_user(user.first_name, user.last_name, user.email, user.password)

@app.post("/login")
async def login(user: LoginRequest):
    """API endpoint to verify user login credentials with 2FA."""
    db_user = user_ops.get_user_by_email(user.email)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not pwd_context.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Verify OTP
    totp = pyotp.TOTP(db_user["totp_secret"])
    if not totp.verify(user.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    return {"message": "Login successful"}

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
async def logout(user: Login_status):
    """API endpoint to log out a user by setting login_status to False."""
    return user_ops.logout_user(user.email)

@app.post("/login-status")
async def get_login_status(request: Login_status):
    """API endpoint to get a user's login status."""
    return user_ops.get_login_status(request.email)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_email(email: str, otp: str, reference_key: str):
    sender_email = "idoican80@gmail.com"
    password = "pbqloirhdnnviaal"
    yag = yagmail.SMTP(user=sender_email, password=password)
    subject = "Login OTP Verification"
    body = f"Your OTP is {otp}. Reference Key: {reference_key}"
    yag.send(to=email, subject=subject, contents=body)


otp_storage: Dict[str, Dict[str, str | float]] = {}

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
    timestamp = time.time()
    
    otp_storage[reference_key] = {"otp": otp, "email": request.email, "timestamp": timestamp}
    logger.info(f"Generated OTP {otp} for email {request.email} with reference key {reference_key}")
    
    send_email(request.email, otp, reference_key)
    
    return {"reference_key": reference_key}


@app.post("/verify_otp_qr")
async def verify_otp_api(request: OTPVerificationRequest):
    data = otp_storage.get(request.reference_key)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid reference key")
    
    # Check if OTP is expired (valid for 2 minutes)
    if time.time() - data["timestamp"] > 120:
        raise HTTPException(status_code=400, detail="OTP expired")
    
    if data["otp"] != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # OTP verified, generate QR
    qr_response = await generate_qr(EmailRequest(**{"email": request.email}))
    
    return qr_response

@app.post("/verify_otp_fp")
async def verify_otp_api(request: OTPVerificationRequest):
    data = otp_storage.get(request.reference_key)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid reference key")
    
    # Check if OTP is expired (valid for 2 minutes)
    if time.time() - data["timestamp"] > 120:
        raise HTTPException(status_code=400, detail="OTP expired")
    
    if data["otp"] != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    return {"Ötp Verification status": "True"}

@app.post("/update_password")
async def update_password(request: UpdatePasswordRequest):
    """API endpoint to update user password."""
    return user_ops.update_password(request.email, request.new_password)