from fastapi import FastAPI, HTTPException, Form, Query
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from src.models import UserRequest, LoginRequest, TOTPSecret , EmailRequest , Login_status, OTPVerificationRequest, UpdatePasswordRequest, TextEncryptionRequest, TextDecryptionRequest
from src.user_operations import UserOperations
import src.user_operations
from src.database import db  # Ensures database is initialized when FastAPI starts
import pyotp
from fastapi.responses import JSONResponse
import qrcode
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
import random
import string
import yagmail
import uuid
import time, logging
from typing import Dict
from fastapi import APIRouter, UploadFile, File, Depends
from fastapi.responses import FileResponse
import shutil
import os
import zlib

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

router = APIRouter()

@router.post("/encrypt")
async def encrypt_file(email: str = Form(...), file: UploadFile = File(...)):
    """Encrypts a file while keeping its format unchanged."""
    logging.info(f"Received encryption request for file: {file.filename} from {email}")

    # Read file data
    file_content = await file.read()
    logging.info(f"Step 1: Read file data ({len(file_content)} bytes)")

    # 🔹 Step 1: Compress file
    compressed_data = user_ops.compress_data(file_content)  # Implement this function
    logging.info(f"Step 2: Compressed file size: {len(compressed_data)} bytes")

    # 🔹 Step 2: Encrypt using user's top_secret
    user_top_secret = user_ops.get_top_secret(email)  # Fetch from DB
    logging.info("Step 3: Retrieved user's top_secret key")

    encrypted_data = user_ops.aes_encrypt(compressed_data, user_top_secret)  # Implement AES
    logging.info(f"Step 4: Encrypted file using user's top_secret (Size: {len(encrypted_data)} bytes)")

    # 🔹 Step 3: Attach email to file header
    final_data = email.encode() + b"||" + encrypted_data
    logging.info("Step 5: Attached email to file header")

    # 🔹 Step 4: Encrypt with Global Key
    global_key = 'supersecureglobalkey16'  # Fetch from config
    logging.info("Step 6: Retrieved global encryption key")

    fully_encrypted = user_ops.aes_encrypt(final_data, global_key)
    logging.info(f"Step 7: Fully encrypted file (Size: {len(fully_encrypted)} bytes)")
    encrypted_dir = "encrypted_files"
    os.makedirs(encrypted_dir, exist_ok=True)

    # Save encrypted file with `.enc` extension
    encrypted_file_path = os.path.abspath(f"{encrypted_dir}/{file.filename}.enc")

    with open(encrypted_file_path, "wb") as f:
        f.write(fully_encrypted)
    logging.info(f"Step 8: Encrypted file saved at: {encrypted_file_path}")

    return {"message": "File encrypted successfully", "file_path": encrypted_file_path}

DECRYPTED_FILES_DIR = os.path.abspath("decrypted_files")
# Define the base directory for decrypted files
@router.post("/decrypt")
async def decrypt_file(file: UploadFile = File(...)):
    """Decrypts a file and returns the file path in JSON response."""
    
    logger.info(f"🔹 Received file for decryption: {file.filename}")

    # 🔹 Step 1: Read encrypted data
    encrypted_data = await file.read()
    logger.info("✅ Encrypted file data read successfully.")

    # 🔹 Step 2: Decrypt with Global Key
    global_key = "supersecureglobalkey16"
    decrypted_global = user_ops.aes_decrypt(encrypted_data, global_key)
    logger.info("✅ Decryption with global key completed.")

    # 🔹 Step 3: Extract email from header
    try:
        email, encrypted_user_data = decrypted_global.split(b"||", 1)
        email = email.decode()
        logger.info(f"✅ Extracted email from header: {email}")
    except ValueError:
        logger.error("❌ Failed to extract email from decrypted data.")
        raise HTTPException(status_code=400, detail="Invalid encrypted file format.")

    # 🔹 Step 4: Decrypt with User's top_secret
    user_top_secret = user_ops.get_top_secret(email)
    decompressed_data = user_ops.aes_decrypt(encrypted_user_data, user_top_secret)
    logger.info("✅ Decryption with user's top_secret completed.")

    # 🔹 Step 5: Decompress data
    original_file_data = user_ops.decompress_data(decompressed_data)  # Implement this in `user_ops`
    logger.info("✅ File decompression completed.")

    # 🔹 Ensure the decrypted_files directory exists
    os.makedirs(DECRYPTED_FILES_DIR, exist_ok=True)

    # 🔹 Save decrypted file with original extension
    original_filename = file.filename.replace(".enc", "")
    decrypted_file_path = os.path.join(DECRYPTED_FILES_DIR, original_filename)

    with open(decrypted_file_path, "wb") as f:
        f.write(original_file_data)
    
    logger.info(f"✅ Decrypted file saved at: {decrypted_file_path}")

    return JSONResponse(content={"message": "File decrypted successfully", "file_path": decrypted_file_path})

@router.post("/encrypt_text")
def encrypt_text(request: TextEncryptionRequest):
    try:
        # Step 1: Compress the given text
        compressed_text = zlib.compress(request.text.encode())
        
        # Step 2: Encrypt using the top secret key
        top_secret = user_ops.get_top_secret(request.email)  # Fetch user's top secret key
        encrypted_data = user_ops.aes_encrypt(compressed_text, top_secret)
        
        # Step 3: Attach the email to the encrypted data
        data_with_email = f"{request.email}||".encode() + encrypted_data
        
        # Step 4: Encrypt using the global key
        global_key = "b7f94e5f1c8a4d1fa8d3c7b5e0f2a6d9"
        final_encrypted_text = user_ops.aes_encrypt(data_with_email, global_key)
        
        return {"encrypted_text": final_encrypted_text.hex()}
    except Exception as e:
        return {"error": str(e)}

@router.post("/decrypt_text")
def decrypt_text(request: TextDecryptionRequest):
    try:
        # Step 1: Decrypt using the global key
        global_key = "b7f94e5f1c8a4d1fa8d3c7b5e0f2a6d9"
        decrypted_global = user_ops.aes_decrypt(bytes.fromhex(request.encrypted_text), global_key)
        
        # Step 2: Extract email and encrypted data
        email, encrypted_data = decrypted_global.split(b"||", 1)
        email = email.decode()
        
        # Step 3: Decrypt using the top secret key
        top_secret = user_ops.get_top_secret(email)
        decrypted_compressed_text = user_ops.aes_decrypt(encrypted_data, top_secret)
        
        # Step 4: Decompress the text
        original_text = zlib.decompress(decrypted_compressed_text).decode()
        
        return {"email": email, "decrypted_text": original_text}
    except Exception as e:
        return {"error": str(e)}
    
@router.get("/download")
async def download_file(file_path: str = Query(...)):
    """Downloads a file from the given file path."""
    logging.info(f"Received download request for file: {file_path}")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    filename = os.path.basename(file_path) # get filename.

    return FileResponse(file_path, filename=filename)



app.include_router(router)