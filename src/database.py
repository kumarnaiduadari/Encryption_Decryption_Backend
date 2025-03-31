import mysql.connector
from mysql.connector import Error

class MySQLDatabase:
    def __init__(self, host, user, password, database):
        """Initialize database connection and create table."""
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_table()

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
                self.cursor = self.conn.cursor()
                print("✅ Connected to MySQL database.")
        except Error as e:
            print(f"❌ Error connecting to MySQL: {e}")
            self.conn = None

    def create_table(self):
        """Create 'users' table with TOTP secret column if it does not exist."""
        if not self.conn or not self.cursor:
            print("❌ Database connection failed. Cannot create table.")
            return

        try:
            create_table_query = """
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
            self.cursor.execute(create_table_query)
            self.conn.commit()
            print("✅ Table 'users' is ready.")
        except Error as e:
            print(f"❌ Error creating table: {e}")

    def close_connection(self):
        """Close the database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
            print("🔌 MySQL connection closed.")

# Automatically initialize database when this module is imported
db = MySQLDatabase(host="localhost", user="root", password="root", database="encryption_decryption")
