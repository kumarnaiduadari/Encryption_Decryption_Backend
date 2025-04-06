# src/encryption_routes.py
from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Form
from fastapi.responses import JSONResponse, FileResponse
import os
import zlib
import logging
from typing import Dict
from src.user_operations import UserOperations
from src.models import TextEncryptionRequest, TextDecryptionRequest

router = APIRouter()
user_ops = UserOperations()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DECRYPTED_FILES_DIR = os.path.abspath("decrypted_files")


@router.post("/encrypt")
async def encrypt_file(email: str = Form(...), file: UploadFile = File(...)):
    """Encrypts a file while keeping its format unchanged."""
    logger.info(f"Received encryption request for file: {file.filename} from {email}")

    # Read file data
    file_content = await file.read()
    logger.info(f"Step 1: Read file data ({len(file_content)} bytes)")

    # Step 1: Compress file
    compressed_data = user_ops.compress_data(file_content)
    logger.info(f"Step 2: Compressed file size: {len(compressed_data)} bytes")

    # Step 2: Encrypt using user's top_secret
    user_top_secret = user_ops.get_top_secret(email)
    logger.info("Step 3: Retrieved user's top_secret key")

    encrypted_data = user_ops.aes_encrypt(compressed_data, user_top_secret)
    logger.info(f"Step 4: Encrypted file using user's top_secret (Size: {len(encrypted_data)} bytes)")

    # Step 3: Attach email to file header
    final_data = email.encode() + b"||" + encrypted_data
    logger.info("Step 5: Attached email to file header")

    # Step 4: Encrypt with Global Key
    global_key = 'supersecureglobalkey16'
    logger.info("Step 6: Retrieved global encryption key")

    fully_encrypted = user_ops.aes_encrypt(final_data, global_key)
    logger.info(f"Step 7: Fully encrypted file (Size: {len(fully_encrypted)} bytes)")

    encrypted_dir = "encrypted_files"
    os.makedirs(encrypted_dir, exist_ok=True)

    # Save encrypted file with `.enc` extension
    encrypted_file_path = os.path.abspath(f"{encrypted_dir}/{file.filename}.enc")

    with open(encrypted_file_path, "wb") as f:
        f.write(fully_encrypted)
    logger.info(f"Step 8: Encrypted file saved at: {encrypted_file_path}")

    return {"message": "File encrypted successfully", "file_path": encrypted_file_path}


@router.post("/decrypt")
async def decrypt_file(file: UploadFile = File(...)):
    """Decrypts a file and returns the file path in JSON response."""
    logger.info(f"🔹 Received file for decryption: {file.filename}")

    # Step 1: Read encrypted data
    encrypted_data = await file.read()
    logger.info("✅ Encrypted file data read successfully.")

    # Step 2: Decrypt with Global Key
    global_key = "supersecureglobalkey16"
    decrypted_global = user_ops.aes_decrypt(encrypted_data, global_key)
    logger.info("✅ Decryption with global key completed.")

    # Step 3: Extract email from header
    try:
        email, encrypted_user_data = decrypted_global.split(b"||", 1)
        email = email.decode()
        logger.info(f"✅ Extracted email from header: {email}")
    except ValueError:
        logger.error("❌ Failed to extract email from decrypted data.")
        raise HTTPException(status_code=400, detail="Invalid encrypted file format.")

    # Step 4: Decrypt with User's top_secret
    user_top_secret = user_ops.get_top_secret(email)
    decompressed_data = user_ops.aes_decrypt(encrypted_user_data, user_top_secret)
    logger.info("✅ Decryption with user's top_secret completed.")

    # Step 5: Decompress data
    original_file_data = user_ops.decompress_data(decompressed_data)
    logger.info("✅ File decompression completed.")

    # Ensure the decrypted_files directory exists
    os.makedirs(DECRYPTED_FILES_DIR, exist_ok=True)

    # Save decrypted file with original extension
    original_filename = file.filename.replace(".enc", "")
    decrypted_file_path = os.path.join(DECRYPTED_FILES_DIR, original_filename)

    with open(decrypted_file_path, "wb") as f:
        f.write(original_file_data)

    logger.info(f"✅ Decrypted file saved at: {decrypted_file_path}")

    return JSONResponse(content={"message": "File decrypted successfully", "file_path": decrypted_file_path})


@router.post("/encrypt_text")
def encrypt_text(request: TextEncryptionRequest):
    try:
        # Step 1: Compress the given text
        compressed_text = zlib.compress(request.text.encode())

        # Step 2: Encrypt using the top secret key
        top_secret = user_ops.get_top_secret(request.email)
        encrypted_data = user_ops.aes_encrypt(compressed_text, top_secret)

        # Step 3: Attach the email to the encrypted data
        data_with_email = f"{request.email}||".encode() + encrypted_data

        # Step 4: Encrypt using the global key
        global_key = "b7f94e5f1c8a4d1fa8d3c7b5e0f2a6d9"
        final_encrypted_text = user_ops.aes_encrypt(data_with_email, global_key)

        return {"encrypted_text": final_encrypted_text.hex()}
    except Exception as e:
        return {"error": str(e)}


@router.post("/decrypt_text")
def decrypt_text(request: TextDecryptionRequest):
    try:
        # Step 1: Decrypt using the global key
        global_key = "b7f94e5f1c8a4d1fa8d3c7b5e0f2a6d9"
        decrypted_global = user_ops.aes_decrypt(bytes.fromhex(request.encrypted_text), global_key)

        # Step 2: Extract email and encrypted data
        email, encrypted_data = decrypted_global.split(b"||", 1)
        email = email.decode()

        # Step 3: Decrypt using the top secret key
        top_secret = user_ops.get_top_secret(email)
        decrypted_compressed_text = user_ops.aes_decrypt(encrypted_data, top_secret)

        # Step 4: Decompress the text
        original_text = zlib.decompress(decrypted_compressed_text).decode()

        return {"email": email, "decrypted_text": original_text}
    except Exception as e:
        return {"error": str(e)}


@router.get("/download")
async def download_file(file_path: str = Query(...)):
    """Downloads a file from the given file path."""
    logger.info(f"Received download request for file: {file_path}")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    filename = os.path.basename(file_path)
    return FileResponse(file_path, filename=filename)