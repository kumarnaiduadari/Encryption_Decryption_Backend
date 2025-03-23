import hashlib
import time
import ctypes
from ctypes import wintypes

# Load Windows Biometric Framework (WBF) API
winbio = ctypes.WinDLL("winbio.dll")

# Define constants
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 2
WINBIO_FLAG_DEFAULT = 0
WINBIO_SESSION_HANDLE = wintypes.HANDLE
WINBIO_ID_TYPE_GUID = 2

class WINBIO_IDENTITY(ctypes.Structure):
    _fields_ = [("Type", wintypes.ULONG),
                ("Value", wintypes.BYTE * 78)]

def capture_fingerprint():
    # Open a biometric session
    session = WINBIO_SESSION_HANDLE()
    result = winbio.WinBioOpenSession(WINBIO_TYPE_FINGERPRINT,
                                      WINBIO_POOL_SYSTEM,
                                      WINBIO_FLAG_DEFAULT,
                                      None, 0, None, ctypes.byref(session))

    if result != 0:
        print("Failed to open biometric session.")
        return None

    # Capture fingerprint
    identity = WINBIO_IDENTITY()
    sub_factor = wintypes.ULONG()
    reject_detail = wintypes.ULONG()

    print("Place your finger on the scanner...")
    time.sleep(2)  # Give time to place the finger

    result = winbio.WinBioCaptureSample(session, WINBIO_ID_TYPE_GUID, 0, ctypes.byref(identity), ctypes.byref(sub_factor), ctypes.byref(reject_detail))

    if result != 0:
        print("Failed to capture fingerprint.")
        return None

    # Convert fingerprint data to hash
    fingerprint_data = bytes(identity.Value)
    fingerprint_hash = hashlib.sha256(fingerprint_data).hexdigest()

    print("Fingerprint Hash:", fingerprint_hash)

    # Close session
    winbio.WinBioCloseSession(session)

    return fingerprint_hash

# Run the fingerprint capture
fingerprint_hash = capture_fingerprint()
