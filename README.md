# Encryption & Decryption Authentication System

## Overview
This project implements a **secure authentication system** that supports:
- **Password Authentication** (hashed using bcrypt)
- **Google Authenticator (TOTP)** for two-factor authentication (2FA)
- **Fingerprint Authentication** using Windows Hello API

## Features
- Secure user authentication with password hashing
- Two-factor authentication (2FA) using Google Authenticator
- Windows Hello-based fingerprint authentication
- REST APIs built with **FastAPI**
- Database storage using **MySQL**

## Technologies Used
- **Python** (FastAPI, Passlib, PyOTP, FIDO2, PyMySQL)
- **MySQL** (for user data storage)
- **Windows Hello API** (for fingerprint authentication)
- **Postman** (for API testing)

---

## Installation & Setup
### 1️⃣ Clone the Repository
```sh
git clone https://github.com/yourusername/Encryption_Decryption.git
cd Encryption_Decryption
```

### 2️⃣ Create a Virtual Environment
```sh
python -m venv ED_Venv
source ED_Venv/bin/activate  # On macOS/Linux
ED_Venv\Scripts\activate    # On Windows
```

### 3️⃣ Install Dependencies
```sh
pip install -r requirements.txt
```

### 4️⃣ Set Up MySQL Database
- Create a database named `authentication_db`
- Update `database.py` with your MySQL credentials

```sh
mysql -u root -p
CREATE DATABASE authentication_db;
```

### 5️⃣ Run the FastAPI Server
```sh
uvicorn src.main:app --host 0.0.0.0 --port 2616 --reload
```

### 6️⃣ Test APIs in Postman or Browser
- Open **http://127.0.0.1:2616/docs** for API documentation.

---

## API Endpoints

### **1️⃣ User Registration**
**Endpoint:** `POST /register`
```json
{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john.doe@example.com",
    "password": "securepassword"
}
```

### **2️⃣ Generate QR for Google Authenticator**
**Endpoint:** `POST /generate_qr`
```json
{
    "email": "john.doe@example.com"
}
```

### **3️⃣ Login with Password + TOTP**
**Endpoint:** `POST /login`
```json
{
    "email": "john.doe@example.com",
    "password": "securepassword",
    "totp_code": "123456"
}
```

### **4️⃣ Fingerprint Authentication**
**Endpoint:** `POST /fingerprint_auth`
```json
{
    "email": "john.doe@example.com"
}
```

---

## Removing Virtual Environment from Git
If you accidentally committed the `ED_Venv` folder, remove it:
```sh
git rm -r --cached ED_Venv
echo "ED_Venv/" >> .gitignore
git add .gitignore
git commit -m "Removed ED_Venv from Git tracking"
git push origin main  # Change 'main' if using another branch
```

---

## Author
- **Your Name**  
- Email: `your-email@example.com`
- GitHub: [yourusername](https://github.com/yourusername)

## License
This project is open-source and available under the **MIT License**.

