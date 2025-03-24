from fastapi import FastAPI, HTTPException
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from src.models import UserRequest, LoginRequest, TOTPSecret , EmailRequest # Importing models
from src.user_operations import UserOperations
import src.user_operations
from src.database import db  # Ensures database is initialized when FastAPI starts
import pyotp
import qrcode
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware


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
