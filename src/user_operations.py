from src.database import db
from fastapi import HTTPException
from mysql.connector import Error
from passlib.context import CryptContext
import pyotp

class UserOperations:
    def __init__(self):
        """Initialize with an active database connection."""
        self.db = db

    
    def add_user(self, first_name, last_name, email, password):
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        """Insert a new user into the database with hashed password and TOTP secret."""
        if not self.db.conn or not self.db.cursor:
            raise HTTPException(status_code=500, detail="Database connection failed.")

        try:
            hashed_password = pwd_context.hash(password)
            totp_secret = pyotp.random_base32()  # Generate unique 2FA secret

            insert_query = """
            INSERT INTO users (first_name, last_name, email, password, totp_secret) 
            VALUES (%s, %s, %s, %s, %s);
            """
            self.db.cursor.execute(insert_query, (first_name, last_name, email, hashed_password, totp_secret))
            self.db.conn.commit()

            return {"message": "User added successfully", "2fa_secret": totp_secret}
        except Error as e:
            raise HTTPException(status_code=400, detail=f"Error inserting user: {e}")

    def update_user(self, first_name, last_name, email, password):
        """Update user details based on email."""
        if not self.db.conn or not self.db.cursor:
            raise HTTPException(status_code=500, detail="Database connection failed.")
        
        try:
            update_query = """
            UPDATE users 
            SET first_name = %s, last_name = %s, password = %s 
            WHERE email = %s;
            """
            self.db.cursor.execute(update_query, (first_name, last_name, password, email))
            self.db.conn.commit()
            if self.db.cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found.")
            return {"message": "User updated successfully"}
        except Error as e:
            raise HTTPException(status_code=400, detail=f"Error updating user: {e}")
        

    def get_user_by_email(self, email):
        """Fetch user details by email."""
        query = "SELECT email, password, totp_secret FROM users WHERE email = %s"
        db.cursor.execute(query, (email,))
        user = db.cursor.fetchone()
        
        if user:
            return {"email": user[0], "password": user[1], "totp_secret": user[2]}
        
        return None



# Automatically create an instance of UserOperations when imported
user_ops = UserOperations()
