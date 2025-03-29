from pydantic import BaseModel, EmailStr

# Model for user creation and update
class UserRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    otp: str  # Add OTP for two-factor authentication

class Login_status(BaseModel):
    email : EmailStr

# Model for returning the QR code URL
class TOTPSecret(BaseModel):
    qr_url: str
    secret: str

class EmailRequest(BaseModel):
    email: str

class OTPVerificationRequest(BaseModel):
    otp: str
    reference_key: str
    email : EmailStr