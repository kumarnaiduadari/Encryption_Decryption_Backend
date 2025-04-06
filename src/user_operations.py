import mysql

from src.database import db
from fastapi import HTTPException
from mysql.connector import Error
from passlib.context import CryptContext
import pyotp
import gzip
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import logging

logger = logging.getLogger(__name__)

class UserOperations:
    def __init__(self):
        """Initialize with an active database connection."""
        self.db = db

    def get_user_by_email(self, email):
        """Fetch user details by email."""
        query = "SELECT email, password, totp_secret FROM users WHERE email = %s"
        db.cursor.execute(query, (email,))
        user = db.cursor.fetchone()

        if user:
            update_query = "UPDATE users SET login_status = TRUE WHERE email = %s"
            db.cursor.execute(update_query, (email,))
            db.conn.commit()
            return {"email": user["email"], "password": user["password"], "totp_secret": user["totp_secret"]}

        return None

    def add_user(self, first_name: str, last_name: str, email: str, password: str) -> dict:
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        if not self.db.conn or not self.db.cursor:
            print("❌ Database connection failed")
            raise HTTPException(status_code=500, detail="Database connection failed")

        try:
            print(f"⏳ Attempting to register user: {email}")

            # Proceed directly with user creation
            hashed_password = pwd_context.hash(password)
            totp_secret = pyotp.random_base32()
            print(f"🔑 Generated TOTP secret for {email}")

            insert_query = """
            INSERT INTO users (first_name, last_name, email, password, totp_secret)
            VALUES (%s, %s, %s, %s, %s)
            """
            self.db.cursor.execute(insert_query,
                                   (first_name, last_name, email, hashed_password, totp_secret))
            self.db.conn.commit()

            print(f"✅ Successfully registered user: {email}")
            return {
                "message": "User added successfully",
                "2fa_secret": totp_secret
            }

        except mysql.connector.Error as e:
            if e.errno == 1062:  # Duplicate entry error code
                print(f"🚫 Registration failed - Email already exists: {email}")
                raise HTTPException(
                    status_code=400,
                    detail="Email already registered"
                )
            print(f"⚠️ Database error during registration: {str(e)}")
            raise HTTPException(
                status_code=400,
                detail="Registration failed. Please try again."
            )

        except Exception as e:
            print(f"🔥 Unexpected error during registration: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Internal server error during registration"
            )

    def logout_user(self, email):
        """Update login_status to False when the user logs out."""
        if not self.db.conn or not self.db.cursor:
            raise HTTPException(status_code=500, detail="Database connection failed.")

        try:
            # Check if user exists and is logged in
            query = "SELECT login_status FROM users WHERE email = %s"
            self.db.cursor.execute(query, (email,))
            user = self.db.cursor.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            if not user[0]:  # If login_status is already False
                raise HTTPException(status_code=400, detail="User is already logged out.")

            # Update login_status to False
            update_query = "UPDATE users SET login_status = FALSE WHERE email = %s"
            self.db.cursor.execute(update_query, (email,))
            self.db.conn.commit()

            return {"message": "Logout successful"}
        except Error as e:
            raise HTTPException(status_code=400, detail=f"Error logging out: {e}")
        
    def get_login_status(self, email):
        """Fetch the login_status of a user."""
        if not self.db.conn or not self.db.cursor:
            raise HTTPException(status_code=500, detail="Database connection failed.")

        try:
            query = "SELECT login_status FROM users WHERE email = %s"
            self.db.cursor.execute(query, (email,))
            user = self.db.cursor.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            return {"email": email, "login_status": bool(user[0])}
        except Error as e:
            raise HTTPException(status_code=400, detail=f"Error fetching login status: {e}")
        
    def update_password(self, email, new_password):
        """Update user password securely."""
        if not self.db.conn or not self.db.cursor:
            raise HTTPException(status_code=500, detail="Database connection failed.")

        try:
            # Hash the new password before storing it
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            hashed_password = pwd_context.hash(new_password)

            update_query = "UPDATE users SET password = %s WHERE email = %s;"
            self.db.cursor.execute(update_query, (hashed_password, email))
            self.db.conn.commit()

            if self.db.cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found.")

            return {"message": "Password updated successfully."}
        except Error as e:
            raise HTTPException(status_code=400, detail=f"Error updating password: {e}")

    def store_webauthn_user(self, username: str, user_id: bytes) -> int:
        """Store a new WebAuthn user and return the user ID."""
        try:
            query = "INSERT INTO webauthn_users (username, user_id) VALUES (%s, %s)"
            self.db.cursor.execute(query, (username, user_id))
            self.db.conn.commit()
            return self.db.cursor.lastrowid
        except Error as e:
            logger.error(f"Error storing WebAuthn user: {e}")
            raise HTTPException(status_code=400, detail="Failed to create WebAuthn user")

    def get_webauthn_user(self, username: str) -> dict:
        """Retrieve a WebAuthn user by username."""
        try:
            query = "SELECT * FROM webauthn_users WHERE username = %s"
            self.db.cursor.execute(query, (username,))
            user = self.db.cursor.fetchone()
            print(f"[DEBUG] WebAuthn user: {user}")
            if not user:
                raise HTTPException(status_code=404, detail="WebAuthn user not found")
            return user
        except Error as e:
            logger.error(f"Error fetching WebAuthn user: {e}")
            raise HTTPException(status_code=400, detail="Database error")

    def store_credential(self, user_id: int, credential_id: bytes, public_key: bytes) -> bool:
        """Store a WebAuthn credential."""
        try:
            query = """
            INSERT INTO webauthn_credentials 
            (user_id, credential_id, public_key) 
            VALUES (%s, %s, %s)
            """
            self.db.cursor.execute(query, (user_id, credential_id, public_key))
            self.db.conn.commit()
            return True
        except Error as e:
            logger.error(f"Error storing credential: {e}")
            return False

    def get_credentials(self, user_id: int) -> list:
        """Get all credentials for a user."""
        try:
            query = "SELECT * FROM webauthn_credentials WHERE user_id = %s"
            self.db.cursor.execute(query, (user_id,))
            return self.db.cursor.fetchall()
        except Error as e:
            logger.error(f"Error fetching credentials: {e}")
            return []

    def store_challenge(self, user_id: int, challenge: bytes) -> bool:
        """Store a WebAuthn challenge."""
        try:
            # Clear existing challenges first
            self.db.cursor.execute(
                "DELETE FROM webauthn_challenges WHERE user_id = %s",
                (user_id,)
            )

            query = "INSERT INTO webauthn_challenges (user_id, challenge) VALUES (%s, %s)"
            self.db.cursor.execute(query, (user_id, challenge))
            self.db.conn.commit()
            return True
        except Error as e:
            logger.error(f"Error storing challenge: {e}")
            return False

    def get_challenge(self, user_id: int) -> bytes:
        """Retrieve the latest challenge for a user."""
        try:
            query = """
            SELECT challenge FROM webauthn_challenges 
            WHERE user_id = %s 
            ORDER BY created_at DESC LIMIT 1
            """
            self.db.cursor.execute(query, (user_id,))
            result = self.db.cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="No challenge found")
            return result['challenge']
        except Error as e:
            logger.error(f"Error fetching challenge: {e}")
            raise HTTPException(status_code=400, detail="Database error")

    def update_sign_count(self, credential_id: bytes, new_count: int) -> bool:
        """Update the sign count for a credential."""
        try:
            query = """
            UPDATE webauthn_credentials 
            SET sign_count = %s 
            WHERE credential_id = %s
            """
            self.db.cursor.execute(query, (new_count, credential_id))
            self.db.conn.commit()
            return True
        except Error as e:
            logger.error(f"Error updating sign count: {e}")
            return False

    # ===== Keep all your existing encryption methods =====
    # [Keep all your existing aes_encrypt(), aes_decrypt(),
    # compress_data(), decompress_data(), etc.]


    # Global AES Key (Should be stored securely)
    GLOBAL_KEY = b'supersecureglobalkey16'

    def derive_key(self, secret: str):
        """Derives a 256-bit AES key from the given secret."""
        salt = b'static_salt_value'  # Use a secure random salt in production
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(secret.encode())

    def aes_encrypt(self, data: bytes, key: str) -> bytes:
        """Encrypts data using AES-256."""

        # Ensure key is converted to bytes and is exactly 32 bytes long
        key = key.encode()  # Convert string to bytes
        key = key.ljust(32, b'\0')[:32]  # Ensure key is exactly 32 bytes

        iv = secrets.token_bytes(16)  # Generate a 16-byte IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to make data a multiple of 16 bytes
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        padded_data = data + padding

        logger.info(f"Encrypting data: Original length = {len(data)}, Padded length = {len(padded_data)}")

        # Encrypt data and prepend IV for decryption
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def aes_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES (CBC mode)"""
        # Ensure key is converted to bytes and is exactly 32 bytes long
        key = key.encode()  # Convert string to bytes
        key = key.ljust(32, b'\0')[:32]  # Ensure key is exactly 32 bytes

        # Extract IV (first 16 bytes)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        logger.info(f"Decrypting data: Ciphertext length = {len(ciphertext)}")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding (assuming PKCS7 padding)
        pad_len = decrypted_padded[-1]
        decrypted_data = decrypted_padded[:-pad_len]

        logger.info(f"Decrypted data length (after padding removal) = {len(decrypted_data)}")

        return decrypted_data


    def compress_data(self, data: bytes):
        """Compress data using gzip."""
        return gzip.compress(data)

    def decompress_data(self, data: bytes):
        """Decompress gzip data."""
        return gzip.decompress(data)
    
    def get_top_secret(self, email):
        """Fetch the user's top_secret from the database using email."""
        query = "SELECT totp_secret FROM users WHERE email = %s"
        self.db.cursor.execute(query, (email,))
        user = self.db.cursor.fetchone()

        if user:
            return user["totp_secret"]
        
        raise HTTPException(status_code=404, detail="User not found")

    def get_user_full_name(self, email: str) -> str:
        """
        Fetch user's full name (first + last name) from the database.
        Args:
            email (str): User's email address
        Returns:
            str: Concatenated first and last name
        Raises:
            HTTPException: For database errors or user not found
        """
        print(f"[INFO] Starting get_user_full_name for email: {email}")

        # Database connection check
        if not self.db.conn or not self.db.cursor:
            print("[ERROR] Database connection not established")
            raise HTTPException(status_code=500, detail="Database connection failed.")

        try:
            print(f"[DEBUG] Preparing SQL query for email: {email}")
            query = "SELECT first_name, last_name FROM users WHERE email = %s"

            print(f"[DEBUG] Executing query for email: {email}")
            self.db.cursor.execute(query, (email,))
            user = self.db.cursor.fetchone()

            if not user:
                print(f"[WARNING] No user found with email: {email}")
                raise HTTPException(status_code=404, detail="User not found")

            print("[DEBUG] Extracting first and last name from results")
            first_name= user["first_name"]
            last_name = user["last_name"]
            full_name = f"{first_name} {last_name}"

            print(f"[INFO] Successfully retrieved full name: {full_name}")
            return full_name

        except Error as e:
            print(f"[ERROR] Database error for {email}: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Error fetching user name: {e}")

        except Exception as e:
            print(f"[CRITICAL] Unexpected error for {email}: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error")

    def store_otp(self, email: str, otp: str, reference_key: str) -> bool:
        """Store OTP in the database."""
        try:
            query = """
            INSERT INTO otps (reference_key, email, otp) 
            VALUES (%s, %s, %s)
            """
            self.db.cursor.execute(query, (reference_key, email, otp))
            self.db.conn.commit()
            return True
        except Error as e:
            logger.error(f"Error storing OTP: {e}")
            return False

    def verify_otp(self, reference_key: str, otp: str) -> dict:
        """
        Verify OTP from database.
        Returns dict with 'is_valid' and 'email' if valid
        """
        try:
            # First check if OTP exists and is not expired or used
            query = """
            SELECT email, otp, timestamp 
            FROM otps 
            WHERE reference_key = %s 
            AND is_used = FALSE 
            AND timestamp > NOW() - INTERVAL 2 MINUTE
            """
            self.db.cursor.execute(query, (reference_key,))
            otp_record = self.db.cursor.fetchone()

            if not otp_record:
                return {"is_valid": False, "error": "Invalid or expired OTP"}

            # Verify OTP matches
            if otp_record["otp"] != otp:
                return {"is_valid": False, "error": "Invalid OTP"}

            # Mark OTP as used
            update_query = "UPDATE otps SET is_used = TRUE WHERE reference_key = %s"
            self.db.cursor.execute(update_query, (reference_key,))
            self.db.conn.commit()

            return {
                "is_valid": True,
                "email": otp_record["email"]
            }
        except Error as e:
            logger.error(f"Error verifying OTP: {e}")
            return {"is_valid": False, "error": "Database error"}

    def cleanup_expired_otps(self):
        """Clean up expired OTPs from the database."""
        try:
            query = "DELETE FROM otps WHERE timestamp < NOW() - INTERVAL 2 MINUTE"
            self.db.cursor.execute(query)
            self.db.conn.commit()
            return True
        except Error as e:
            logger.error(f"Error cleaning up expired OTPs: {e}")
            return False



# Automatically create an instance of UserOperations when imported
user_ops = UserOperations()
