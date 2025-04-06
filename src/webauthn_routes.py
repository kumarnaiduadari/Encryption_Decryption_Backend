from fastapi import APIRouter, HTTPException
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement,AuthenticatorTransport, PublicKeyCredentialType, AuthenticatorSelectionCriteria
from webauthn.helpers import options_to_json
from src.models import RegisterRequest, VerifyRegisterRequest, AuthenticateRequest, VerifyAuthenticateRequest
import base64
import json
import logging
from src.user_operations import user_ops

router = APIRouter(prefix="/webauthn", tags=["WebAuthn"])

logger = logging.getLogger(__name__)

def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@router.post("/register/options")
async def get_register_options(request: RegisterRequest):
    username = request.username
    user_id = username.encode("utf-8")
    logger.info(f"Generating registration options for user: {username}")

    options = generate_registration_options(
        rp_name="My WebAuthn App",
        rp_id="localhost",
        user_name=username,
        user_id=user_id,
    )

    # Store user and challenge in database
    user_id = user_ops.store_webauthn_user(username, user_id)
    if not user_ops.store_challenge(user_id, options.challenge):
        raise HTTPException(status_code=500, detail="Failed to store challenge")

    return json.loads(options_to_json(options))


@router.post("/register/verify")
async def verify_register(request: VerifyRegisterRequest):
    try:
        logger.info(f"Verifying registration for user: {request.username}")

        # Get user and challenge from database
        user = user_ops.get_webauthn_user(request.username)
        challenge = user_ops.get_challenge(user['id'])
        if not challenge:
            raise HTTPException(status_code=400, detail="Challenge not found")

        verified_data = verify_registration_response(
            credential=request.credential,
            expected_challenge=challenge,
            expected_origin="http://localhost:3000",
            expected_rp_id="localhost",
        )

        # Store credential in database
        if not user_ops.store_credential(
                user['id'],
                verified_data.credential_id,
                verified_data.credential_public_key
        ):
            raise HTTPException(status_code=500, detail="Failed to store credential")

        return {
            "status": "ok",
            "credential_id": encode_base64(verified_data.credential_id)
        }
    except Exception as e:
        logger.error(f"Error in registration verification: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/authenticate/options")
async def get_authenticate_options(request: AuthenticateRequest):
    try:
        logger.info(f"Auth options for user: {request.username}")

        # Get user and credentials from database
        user = user_ops.get_webauthn_user(request.username)
        credentials = user_ops.get_credentials(user['id'])
        if not credentials:
            raise HTTPException(status_code=400, detail="No credentials found")

        # Create credential descriptors
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=cred['credential_id'],
                type=PublicKeyCredentialType.PUBLIC_KEY,
            transports = [AuthenticatorTransport.INTERNAL],
        ) for cred in credentials
        ]

        options = generate_authentication_options(
            rp_id="localhost",
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        # Store new challenge
        if not user_ops.store_challenge(user['id'], options.challenge):
            raise HTTPException(status_code=500, detail="Failed to store challenge")

        return json.loads(options_to_json(options))
    except Exception as e:
        logger.error(f"Error in auth options: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/authenticate/verify")
async def verify_authenticate(request: VerifyAuthenticateRequest):
    try:
        logger.info(f"Verifying auth for user: {request.username}")

        # Get user, credential and challenge from database
        user = user_ops.get_webauthn_user(request.username)
        print(user)
        print(type(user))
        credentials = user_ops.get_credentials(user['id'])
        print(credentials)
        print(type(credentials))
        challenge = user_ops.get_challenge(user['id'])
        print(challenge)


        if not credentials:
            raise HTTPException(status_code=400, detail="No credentials found")
        if not challenge:
            raise HTTPException(status_code=400, detail="Challenge not found")

        # Find the matching credential
        request_credential_id = base64.urlsafe_b64decode(
            request.credential['rawId'] + '=' * (-len(request.credential['rawId']) % 4))

        # Find the matching credential
        credential = next((c for c in credentials
                           if c['credential_id'] == request_credential_id), None)
        if not credential:
            raise HTTPException(status_code=400, detail="Credential not found")

        verified_data = verify_authentication_response(
            credential=request.credential,
            expected_challenge=challenge,
            expected_origin="http://localhost:3000",
            expected_rp_id="localhost",
            credential_public_key=credential['public_key'],
            credential_current_sign_count=credential['sign_count'],
            require_user_verification=False
        )

        # Update sign count
        user_ops.update_sign_count(
            credential['credential_id'],
            verified_data.new_sign_count
        )

        return {
            "status": "ok",
            "message": f"Welcome, {request.username}!",
            "new_sign_count": verified_data.new_sign_count
        }
    except Exception as e:
        logger.error(f"Error in auth verification: {e}")
        raise HTTPException(status_code=400, detail=str(e))