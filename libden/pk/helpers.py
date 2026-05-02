import base64


def wb64_from_bytes(bytes_: bytes) -> str:
    '''
    Encode bytes to URL-safe base 64 with no padding, as in WebAuthn spec
    '''
    return str(base64.urlsafe_b64encode(bytes_).replace(b'=', b''), 'ascii')

def bytes_from_wb64(b64: str) -> bytes:
    '''
    Decode bytes from URL-safe base 64 with no padding, as in WebAuthn spec
    '''
    return base64.urlsafe_b64decode(b64 + '==')
