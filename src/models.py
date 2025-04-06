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
    email: EmailStr

class OTPVerificationRequest(BaseModel):
    otp: str
    reference_key: str
    email : EmailStr

class UpdatePasswordRequest(BaseModel):
    email: EmailStr
    new_password: str

class TextEncryptionRequest(BaseModel):
    email: EmailStr
    text: str

class TextDecryptionRequest(BaseModel):
    encrypted_text: str


# Request models
class RegisterRequest(BaseModel):
    username: str


class VerifyRegisterRequest(BaseModel):
    username: str
    credential: dict
    challenge: str


class AuthenticateRequest(BaseModel):
    username: str


class VerifyAuthenticateRequest(BaseModel):
    username: str
    credential: dict
    challenge: str

