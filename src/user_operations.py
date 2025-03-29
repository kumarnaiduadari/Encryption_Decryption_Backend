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
            update_query = "UPDATE users SET login_status = TRUE WHERE email = %s"
            db.cursor.execute(update_query, (email,))
            db.conn.commit()
            return {"email": user[0], "password": user[1], "totp_secret": user[2]}
        
        return None
    
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




# Automatically create an instance of UserOperations when imported
user_ops = UserOperations()
