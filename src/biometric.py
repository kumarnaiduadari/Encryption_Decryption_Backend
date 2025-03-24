import win32security
import ctypes

def authenticate_user():
    """Attempts to authenticate the current user using Windows Hello credentials."""
    username = ctypes.create_unicode_buffer(256)
    ctypes.windll.advapi32.GetUserNameW(username, ctypes.byref(ctypes.c_uint32(256)))

    try:
        token = win32security.LogonUser(
            username.value,  # Current username
            None,            # Domain (None for local machine)
            None,            # No password (Windows Hello is passwordless)
            win32security.LOGON32_LOGON_INTERACTIVE,
            win32security.LOGON32_PROVIDER_DEFAULT
        )
        print("Authentication successful!")
        return True
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False

# Run the function
authenticate_user()
