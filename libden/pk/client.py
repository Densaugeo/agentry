#!/usr/bin/env python3
"""
WebAuthn Test Utility

A command-line tool for generating WebAuthn registration and authentication
responses for testing purposes. Outputs JSON compatible with WebAuthn browser APIs.
"""

import argparse
import base64
import json
import hashlib
import struct
import os
import sys

from fido2 import cbor
from fido2.utils import websafe_encode, websafe_decode

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from urllib.parse import urlparse

def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url (no padding)."""
    return websafe_encode(data)


def base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    return websafe_decode(data)


def create_client_data_json(challenge: str, origin: str, typ: str = "webauthn.create") -> str:
    """Create the clientDataJSON string."""
    client_data = {
        "type": typ,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": False
    }
    return json.dumps(client_data, separators=(',', ':'))


def create_credential(private_key: ec.EllipticCurvePrivateKey, challenge: str, rp_id: str, origin: str) -> dict:
    """
    Generate a WebAuthn registration response.
    """
    
    # Get the public key numbers
    public_key = private_key.public_key()
    public_key_numbers = public_key.public_numbers()
    
    # Extract X and Y coordinates
    x = public_key_numbers.x.to_bytes(32, 'big')
    y = public_key_numbers.y.to_bytes(32, 'big')
    
    # Generate credential ID (for testing, use a hash of the public key)
    credential_id = hashlib.sha256(x + y).digest()[:16]
    
    # Create clientDataJSON
    client_data_json = create_client_data_json(challenge, origin, "webauthn.create")
    client_data_json_encoded = base64url_encode(client_data_json.encode('utf-8'))
    
    # Create the credential public key in COSE format
    public_key_cose = {
        1: 2,    # kty: EC2
        3: -7,   # alg: ES256
        -1: 1,   # crv: P-256
        -2: x,   # x coordinate
        -3: y    # y coordinate
    }
    
    # Create authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('ascii')).digest()
    flags = 0x41  # UP + AT flags
    counter = struct.pack('>I', 0)
    aaguid = b'\x00' * 16
    credential_id_len = struct.pack('>H', len(credential_id))
    
    authenticator_data = (
        rp_id_hash + 
        bytes([flags]) + 
        counter + 
        aaguid + 
        credential_id_len + 
        credential_id + 
        cbor.encode(public_key_cose)
    )
    
    # Create attestation object
    attestation = {
        "fmt": "none",
        "attStmt": {},
        "authData": authenticator_data
    }
    attestation_object = cbor.encode(attestation)
    
    return {
        "id": base64url_encode(credential_id),
        "rawId": base64url_encode(credential_id),
        "response": {
            "attestationObject": base64url_encode(attestation_object),
            "clientDataJSON": client_data_json_encoded
        },
        "type": "public-key"
    }


def login(private_key: ec.EllipticCurvePrivateKey, challenge: str, rp_id: str, origin: str, credential_id: str) -> dict:
    """
    Generate a WebAuthn authentication response.
    """
    
    # Decode credential ID
    cred_id = base64url_decode(credential_id)
    
    # Create clientDataJSON
    client_data_json = create_client_data_json(challenge, origin, "webauthn.get")
    client_data_json_encoded = base64url_encode(client_data_json.encode('utf-8'))
    
    # Create authenticatorData
    rp_id_hash = hashlib.sha256(rp_id.encode('ascii')).digest()
    flags = 0x01  # UP flag
    counter = struct.pack('>I', 1)  # Increment counter
    
    authenticator_data = rp_id_hash + bytes([flags]) + counter
    
    # Sign the data (authenticatorData + SHA256(clientDataJSON))
    client_data_json_hash = hashlib.sha256(client_data_json.encode('utf-8')).digest()
    data_to_sign = authenticator_data + client_data_json_hash
    signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    
    return {
        "id": credential_id,
        "rawId": credential_id,
        "response": {
            "authenticatorData": base64url_encode(authenticator_data),
            "clientDataJSON": client_data_json_encoded,
            "signature": base64url_encode(signature),
            "userHandle": None
        },
        "type": "public-key"
    }


def main():
    parser = argparse.ArgumentParser(
        description="WebAuthn test utility for generating registration and authentication responses"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Create Credential subcommand
    create_credential_parser = subparsers.add_parser("create-credential",
        help="Generate registration response")
    create_credential_parser.add_argument("--challenge", required=True,
        help="Base64url-encoded challenge")
    create_credential_parser.add_argument("--private-key", required=True,
        help="Path to PEM file with private key")
    create_credential_parser.add_argument("--rp-id", required=True,
        help="Relying Party ID")
    create_credential_parser.add_argument("--origin", required=True,
        help="Relying Party origin (e.g., https://passkeys.io)")
    
    # Login subcommand
    login_parser = subparsers.add_parser("login",
        help="Generate authentication response")
    login_parser.add_argument("--challenge", required=True,
        help="Base64url-encoded challenge")
    login_parser.add_argument("--credential-id", required=True,
        help="Base64url-encoded credential ID")
    login_parser.add_argument("--private-key", required=True,
        help="Path to PEM file with private key")
    login_parser.add_argument("--rp-id", required=True,
        help="Relying Party ID")
    login_parser.add_argument("--origin", required=True,
        help="Relying Party origin (e.g., https://passkeys.io)")
    
    args = parser.parse_args()
    
    # Load private key
    try:
        with open(args.private_key, 'rb') as f:
            private_key_pem = f.read()
    except FileNotFoundError:
        print(f"Error: Private key file not found: {args.private_key}", file=sys.stderr)
        sys.exit(1)
    
    # Parse the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    assert isinstance(private_key, ec.EllipticCurvePrivateKey), f'Private key' \
        f' key {args.private_key} is of type {type(private_key)}, but only' \
        f' elliptic curve keys are currently supported.'
    
    # Execute command
    if args.command == "create-credential":
        result = create_credential(
            private_key,
            args.challenge,
            args.rp_id,
            args.origin,
        )
    elif args.command == "login":
        result = login(
            private_key,
            args.challenge,
            args.rp_id,
            args.origin,
            args.credential_id
        )
    else:
        print(f"Error: Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)
    
    # Output JSON
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
