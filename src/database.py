import mysql.connector
from mysql.connector import Error


class MySQLDatabase:
    def __init__(self, host, user, password, database):
        """Initialize database connection and create tables."""
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Establish a connection to the MySQL database."""
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            if self.conn.is_connected():
                self.cursor = self.conn.cursor(dictionary=True)
                print("✅ Connected to MySQL database")
        except Error as e:
            print(f"❌ Error connecting to MySQL: {e}")
            raise RuntimeError(f"Database connection failed: {e}")

    def create_tables(self):
        """Create all required tables if they don't exist."""
        if not self.conn or not self.cursor:
            print("❌ Database connection not established")
            return

        try:
            # Main users table (for traditional auth)
            users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                first_name VARCHAR(50),
                last_name VARCHAR(50),
                email VARCHAR(100) UNIQUE,
                password VARCHAR(255),
                totp_secret VARCHAR(32),
                login_status BOOLEAN DEFAULT FALSE
            );
            """

            # WebAuthn tables
            webauthn_users = """
            CREATE TABLE IF NOT EXISTS webauthn_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                user_id VARBINARY(64) NOT NULL
            );
            """

            webauthn_credentials = """
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                credential_id VARBINARY(255) NOT NULL,
                public_key VARBINARY(1024) NOT NULL,
                sign_count INT DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES webauthn_users(id) ON DELETE CASCADE,
                UNIQUE (credential_id(255))
            );
            """

            webauthn_challenges = """
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                challenge VARBINARY(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES webauthn_users(id) ON DELETE CASCADE
            );
            """

            otp_table = """
            CREATE TABLE IF NOT EXISTS otps (
                id INT AUTO_INCREMENT PRIMARY KEY,
                reference_key VARCHAR(36) UNIQUE NOT NULL,
                email VARCHAR(100) NOT NULL,
                otp VARCHAR(6) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
            );
            """

            # Execute all table creations
            for query in [users_table, webauthn_users,
                          webauthn_credentials, webauthn_challenges, otp_table]:
                self.cursor.execute(query)

            self.conn.commit()
            print("✅ All tables created/verified")

        except Error as e:
            print(f"❌ Error creating tables: {e}")
            raise RuntimeError(f"Table creation failed: {e}")

    def close_connection(self):
        """Close the database connection gracefully."""
        if self.cursor:
            self.cursor.close()
        if self.conn and self.conn.is_connected():
            self.conn.close()
            print("🔌 MySQL connection closed")


# Initialize database connection
db = MySQLDatabase(
    host="localhost",
    user="root",
    password="12shroot",
    database="encryption_decryption"
)