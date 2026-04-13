# WebAuthn Test Utility - Specification

## Overview

A command-line utility for generating WebAuthn registration and authentication responses from challenges and private keys. Designed for automated testing, particularly for integration with test suites and curl-based workflows.

## Goals

- Generate valid WebAuthn credential registration responses (attestation)
- Generate valid WebAuthn authentication responses (assertions)
- Work with passkeys.io demo page via curl
- Framework and language agnostic (usable from any test framework or shell script)
- Minimal dependencies for easy inclusion in test environments

## Non-Goals

- Full WebAuthn Relying Party implementation
- User verification (UV) flags beyond basic automation needs
- Token binding support
- Large dependency management (e.g., full FIDO ecosystem)

## CLI Interface

### Registration

```bash
webauthn-register --challenge <base64url> --private-key <pem> --origin <origin> [--user-id <base64url>]
```

Outputs JSON suitable for `navigator.credentials.create()`:
```json
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "response": {
    "attestationObject": "base64url-encoded-cbor",
    "clientDataJSON": "base64url-encoded-json"
  },
  "type": "public-key"
}
```

### Authentication

```bash
webauthn-authenticate --challenge <base64url> --credential-id <base64url> --private-key <pem> --origin <origin>
```

Outputs JSON suitable for `navigator.credentials.get()`:
```json
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "response": {
    "authenticatorData": "base64url-encoded-bytes",
    "clientDataJSON": "base64url-encoded-json",
    "signature": "base64url-encoded-sig",
    "userHandle": "base64url-encoded-user-handle-or-null"
  },
  "type": "public-key"
}
```

## Implementation Language

Initial testing in Python. May rewrite in Rust if project is successful enough to publish.

## Testing Requirements

- Unit tests for cryptographic operations
- Integration test compatible with passkeys.io (demo server)
- Test vectors from WebAuthn specification

## Dependencies

- FIDO2/WebAuthn libraries for Go or Python
- CBOR encoding (for attestation)
- No external API calls

## Success Criteria

- Can register a credential using a challenge from passkeys.io
- Can authenticate using the registered credential
- Successfully completes passkeys.io demo flow
- Works from shell script / curl without test framework
