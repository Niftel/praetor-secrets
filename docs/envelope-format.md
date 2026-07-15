# Envelope record format

Status: Draft implementation format  
Format version: `1`  
Algorithm identifier: `AES-256-GCM-DEK+AES-256-GCM-KEK`

## Purpose

An envelope record encrypts one version of a credential payload with a unique
random data-encryption key (DEK). A named 256-bit master key, acting as the
key-encryption key (KEK), wraps that DEK. PostgreSQL may store the record but
cannot decrypt it without a configured master key.

The implementation uses Go's standard AES-GCM AEAD. It composes the standard
primitive and does not implement a cipher, mode, nonce construction, padding
scheme, or random-number generator.

## JSON record

`[]byte` values use standard padded base64 when represented as JSON.

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM-DEK+AES-256-GCM-KEK",
  "record_id": "32 lowercase hexadecimal characters",
  "master_key_id": "operator-defined stable key identifier",
  "context": {
    "credential_id": "credential identifier",
    "organization_id": "organization identifier",
    "schema_version": 1,
    "credential_version": 3
  },
  "payload_nonce": "base64",
  "ciphertext": "base64",
  "wrap_nonce": "base64",
  "wrapped_data_key": "base64"
}
```

Unknown versions and algorithms fail closed. The v1 decoder does not infer or
upgrade a record format during decryption.

## Encryption

For every record:

1. Generate a 128-bit random record ID.
2. Generate a new random 256-bit DEK.
3. Generate an independent random nonce of the size required by Go's AES-GCM
   implementation.
4. Encrypt the payload with the DEK and `credential-payload` associated data.
5. Generate another independent random AES-GCM nonce.
6. Wrap the DEK with the selected 256-bit master key and `data-key-wrap`
   associated data.
7. Erase the package's mutable DEK byte slice after use on a best-effort basis.

The caller owns and retains responsibility for plaintext and master-key buffers.
Go does not guarantee that compiler or runtime copies are erased from memory.

## Associated data

Associated data is deterministic JSON encoding of a fixed Go struct in this
field order:

```json
{
  "purpose": "credential-payload or data-key-wrap",
  "version": 1,
  "algorithm": "AES-256-GCM-DEK+AES-256-GCM-KEK",
  "record_id": "...",
  "master_key_id": "empty for credential-payload; the KEK ID for data-key-wrap",
  "credential_id": "...",
  "organization_id": "...",
  "schema_version": 1,
  "credential_version": 3
}
```

The purpose differs between payload encryption and DEK wrapping so ciphertexts
cannot be moved between those uses. `master_key_id` is deliberately empty for
payload associated data and populated for DEK wrapping. This permits KEK rotation
to rewrap the same DEK without re-encrypting the credential payload. The remaining
identifiers and versions prevent moving a record between credentials,
organizations, schemas, or credential versions.

## Authoritative context

Decryption requires the caller to supply the expected context from authoritative
immutable storage. The package does not trust the context embedded in the record.
The embedded and expected values must match before any plaintext is returned.

Passing context copied only from the untrusted record defeats the substitution
protection and is prohibited at the storage layer.

## Key rotation

`master_key_id` selects a key from a bounded keyring. New encryption uses the
current primary key. Existing records remain readable while their named key is in
the keyring.

Rotation rewraps the existing DEK with a new KEK and fresh nonce after
authenticating both the wrapped DEK and payload. The rotation operation must not
decrypt or re-encrypt the credential payload unnecessarily. Rotation and key-file
loading are separate implementation tasks.

## Failure behavior

The package returns no plaintext when:

- format version or algorithm is unsupported;
- expected context differs;
- the named master key is unavailable;
- a nonce or ciphertext is malformed;
- the wrapped DEK fails authentication;
- the unwrapped key is not exactly 256 bits; or
- payload authentication fails.

AEAD failures collapse to a stable authentication error rather than exposing
which value or tag failed.

## Required tests

Version 1 includes tests for:

- JSON round trips without plaintext;
- empty, ordinary, and maximum initial payload sizes;
- randomized independent encryptions;
- unknown and incorrect master keys;
- cross-credential, organization, schema, and version substitution;
- record ID, nonce, ciphertext, and wrapped-key tampering;
- malformed and unsupported records; and
- entropy-source failure without a partial record.
