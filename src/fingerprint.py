import mysql.connector
import win32security
import getpass

# Database Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "12shroot",
    "database": "user_database"
}

### 🔹 Database Connection ###
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

### 🔹 Register User with Windows Hello ###
def register_user(email):
    """Registers a user using Windows Hello."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get Windows Username
    windows_user = getpass.getuser()

    # Store in MySQL
    cursor.execute("INSERT INTO users (email, windows_user) VALUES (%s, %s) ON DUPLICATE KEY UPDATE windows_user=%s", 
                   (email, windows_user, windows_user))
    conn.commit()

    print(f"✅ {email} registered with Windows Hello.")
    conn.close()

### 🔹 Authenticate with Windows Hello ###
def authenticate_user(email):
    """Authenticates the user using Windows Hello."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch stored Windows user
    cursor.execute("SELECT windows_user FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        print("❌ User not found.")
        return False

    stored_windows_user = user["windows_user"]
    current_windows_user = getpass.getuser()

    # Verify if the user matches the Windows Hello identity
    if stored_windows_user != current_windows_user:
        print("❌ Windows Hello authentication failed. User mismatch.")
        return False

    # Windows Hello Authentication
    try:
        win32security.LogonUser(
            current_windows_user,  # Username
            None,  # Domain (None for local)
            None,  # Password (not needed for Windows Hello)
            win32security.LOGON32_LOGON_INTERACTIVE,
            win32security.LOGON32_PROVIDER_DEFAULT
        )
        print("✅ Authentication successful!")
        return True
    except Exception as e:
        print("❌ Authentication failed:", e)
        return False

### 🔹 Main Menu ###
if __name__ == "__main__":
    print("\n🔐 Windows Hello Authentication 🔐")
    print("1️⃣ Register User")
    print("2️⃣ Authenticate User")
    choice = input("\nEnter your choice (1 or 2): ")

    email = input("Enter your email: ")

    if choice == "1":
        register_user(email)
    elif choice == "2":
        authenticate_user(email)
    else:
        print("❌ Invalid choice. Exiting.")
