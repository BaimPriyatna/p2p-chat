"""tests/test_encryption.py — Comprehensive tests for Phase 8 ChaCha20-Poly1305 AEAD.

Covers:
    - Official RFC 8439 Section 2.8.2 AEAD test vector verification.
    - EncryptedFrame wire packing and unpacking, truncation, and bounds checking.
    - AEAD tamper detection (ciphertext, tag, sequence AAD, nonce, wrong key).
    - Monotonic sequence tracking, replay prevention, reordering rejection.
    - Nonce uniqueness and reuse prevention.
    - Bidirectional SessionCipher integration with Phase 7 SessionKeys.
    - Directional key reflection attack immunity.
    - Edge cases: zero-length payload, large binary payload, custom AAD.
"""

import os
import pytest

from core.crypto.encryption import (
    HEADER_LEN,
    KEY_LEN,
    MAX_SEQUENCE,
    MIN_FRAME_LEN,
    NONCE_LEN,
    SEQUENCE_LEN,
    TAG_LEN,
    AuthenticationError,
    EncryptedFrame,
    EncryptionError,
    FrameDecryptor,
    FrameEncryptor,
    NonceReuseError,
    ReplayError,
    SequenceOverflowError,
    SessionCipher,
    decrypt,
    decrypt_frame,
    encrypt,
    encrypt_frame,
)
from core.crypto.kdf import derive_session_keys
from core.crypto.key_exchange import (
    compute_shared_secret,
    generate_ephemeral_keypair,
)


def test_rfc8439_test_vector():
    """Verify raw AEAD against official RFC 8439 Section 2.8.2 test vector."""
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )

    expected_ciphertext = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    ct_and_tag = encrypt(key, nonce, plaintext, associated_data=aad)
    ciphertext = ct_and_tag[:-TAG_LEN]
    tag = ct_and_tag[-TAG_LEN:]

    assert ciphertext == expected_ciphertext
    assert tag == expected_tag

    # Decrypt and verify match
    decrypted = decrypt(key, nonce, ct_and_tag, associated_data=aad)
    assert decrypted == plaintext


def test_frame_pack_unpack_roundtrip():
    """Verify EncryptedFrame serialization and deserialization."""
    seq = 42
    nonce = os.urandom(12)
    ciphertext = b"secret-encrypted-payload"
    tag = os.urandom(16)

    frame = EncryptedFrame(sequence=seq, nonce=nonce, ciphertext=ciphertext, tag=tag)
    wire_bytes = frame.pack()

    assert len(wire_bytes) == HEADER_LEN + len(ciphertext) + TAG_LEN
    unpacked = EncryptedFrame.unpack(wire_bytes)

    assert unpacked.sequence == seq
    assert unpacked.nonce == nonce
    assert unpacked.ciphertext == ciphertext
    assert unpacked.tag == tag
    assert unpacked.ciphertext_and_tag == ciphertext + tag


def test_frame_unpack_invalid_length():
    """Verify unpack rejects truncated or malformed frame buffers."""
    with pytest.raises(EncryptionError, match="Frame data too short"):
        EncryptedFrame.unpack(b"short")

    with pytest.raises(EncryptionError, match="Frame data must be bytes"):
        EncryptedFrame.unpack("not-bytes")  # type: ignore


def test_frame_validation_bounds():
    """Verify EncryptedFrame field validation bounds."""
    valid_nonce = b"\x00" * 12
    valid_tag = b"\x00" * 16

    with pytest.raises(EncryptionError, match="Sequence out of 64-bit bounds"):
        EncryptedFrame(sequence=-1, nonce=valid_nonce, ciphertext=b"", tag=valid_tag)

    with pytest.raises(EncryptionError, match="Sequence out of 64-bit bounds"):
        EncryptedFrame(sequence=MAX_SEQUENCE + 1, nonce=valid_nonce, ciphertext=b"", tag=valid_tag)

    with pytest.raises(EncryptionError, match="Nonce must be exactly 12 bytes"):
        EncryptedFrame(sequence=0, nonce=b"\x00" * 11, ciphertext=b"", tag=valid_tag)

    with pytest.raises(EncryptionError, match="Tag must be exactly 16 bytes"):
        EncryptedFrame(sequence=0, nonce=valid_nonce, ciphertext=b"", tag=b"\x00" * 15)


def test_encrypt_decrypt_frame_basic():
    """Verify encrypt_frame and decrypt_frame roundtrip."""
    key = os.urandom(32)
    seq = 100
    msg = b"Hello, encrypted world!"

    frame = encrypt_frame(key, sequence=seq, plaintext=msg)
    assert frame.sequence == seq
    assert len(frame.nonce) == 12
    assert len(frame.tag) == 16

    plaintext = decrypt_frame(key, frame, expected_sequence=seq)
    assert plaintext == msg


def test_tamper_detection_ciphertext():
    """Verify that bit flips in ciphertext raise AuthenticationError."""
    key = os.urandom(32)
    frame = encrypt_frame(key, sequence=1, plaintext=b"Sensitive message")
    tampered_ct = bytearray(frame.ciphertext)
    tampered_ct[0] ^= 0x01

    tampered_frame = EncryptedFrame(
        sequence=frame.sequence,
        nonce=frame.nonce,
        ciphertext=bytes(tampered_ct),
        tag=frame.tag,
    )

    with pytest.raises(AuthenticationError):
        decrypt_frame(key, tampered_frame)


def test_tamper_detection_tag():
    """Verify that bit flips in Poly1305 tag raise AuthenticationError."""
    key = os.urandom(32)
    frame = encrypt_frame(key, sequence=1, plaintext=b"Sensitive message")
    tampered_tag = bytearray(frame.tag)
    tampered_tag[0] ^= 0x01

    tampered_frame = EncryptedFrame(
        sequence=frame.sequence,
        nonce=frame.nonce,
        ciphertext=frame.ciphertext,
        tag=bytes(tampered_tag),
    )

    with pytest.raises(AuthenticationError):
        decrypt_frame(key, tampered_frame)


def test_tamper_detection_sequence_aad():
    """Verify that modifying the sequence number in the header invalidates the tag.

    Sequence is bound to AAD, so altering sequence on the wire fails tag authentication.
    """
    key = os.urandom(32)
    frame = encrypt_frame(key, sequence=5, plaintext=b"Bound sequence test")

    # Attacker alters sequence from 5 to 6 without re-encrypting
    wire_bytes = bytearray(frame.pack())
    wire_bytes[7] = 6  # alter lowest byte of 64-bit sequence

    tampered_frame = EncryptedFrame.unpack(bytes(wire_bytes))
    assert tampered_frame.sequence == 6

    with pytest.raises(AuthenticationError):
        decrypt_frame(key, tampered_frame)


def test_tamper_detection_nonce():
    """Verify that modifying the nonce invalidates the tag."""
    key = os.urandom(32)
    frame = encrypt_frame(key, sequence=1, plaintext=b"Nonce tamper test")

    tampered_nonce = bytearray(frame.nonce)
    tampered_nonce[0] ^= 0xFF

    tampered_frame = EncryptedFrame(
        sequence=frame.sequence,
        nonce=bytes(tampered_nonce),
        ciphertext=frame.ciphertext,
        tag=frame.tag,
    )

    with pytest.raises(AuthenticationError):
        decrypt_frame(key, tampered_frame)


def test_wrong_key_fails_authentication():
    """Verify decrypting with a wrong key fails with AuthenticationError."""
    key1 = os.urandom(32)
    key2 = os.urandom(32)

    frame = encrypt_frame(key1, sequence=1, plaintext=b"Secret data")

    with pytest.raises(AuthenticationError):
        decrypt_frame(key2, frame)


def test_frame_encryptor_decryptor_strict_order():
    """Verify stateful encryptor and decryptor enforce strictly monotonic sequences."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key, strict_order=True)

    messages = [b"msg-0", b"msg-1", b"msg-2", b"msg-3"]
    frames = []

    for idx, msg in enumerate(messages):
        assert encryptor.next_sequence == idx
        f = encryptor.encrypt(msg)
        assert f.sequence == idx
        frames.append(f)

    # Decrypt in order
    for idx, f in enumerate(frames):
        plain = decryptor.decrypt(f)
        assert plain == messages[idx]
        assert decryptor.last_sequence == idx


def test_replay_attack_rejected():
    """Verify that replayed frames are rejected."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key, strict_order=True)

    f0 = encryptor.encrypt(b"frame 0")
    f1 = encryptor.encrypt(b"frame 1")

    assert decryptor.decrypt(f0) == b"frame 0"
    assert decryptor.decrypt(f1) == b"frame 1"

    # Replay f0
    with pytest.raises(ReplayError, match="Out of order sequence"):
        decryptor.decrypt(f0)

    # Replay f1
    with pytest.raises(ReplayError, match="Out of order sequence"):
        decryptor.decrypt(f1)


def test_out_of_order_frame_rejected_strict():
    """Verify that skipping a sequence number is rejected under strict_order."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key, strict_order=True)

    f0 = encryptor.encrypt(b"frame 0")
    f1 = encryptor.encrypt(b"frame 1")

    # Send f1 before f0
    with pytest.raises(ReplayError, match="expected 0, got 1"):
        decryptor.decrypt(f1)


def test_decryptor_loose_order():
    """Verify that non-strict decryptor permits monotonic gaps but prevents regression/duplicate."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key, strict_order=False)

    f0 = encryptor.encrypt(b"frame 0")
    f1 = encryptor.encrypt(b"frame 1")
    f2 = encryptor.encrypt(b"frame 2")

    # Accept f0 then f2 (gap of f1)
    assert decryptor.decrypt(f0) == b"frame 0"
    assert decryptor.decrypt(f2) == b"frame 2"

    # Attempt to replay f0 or f2
    with pytest.raises(ReplayError):
        decryptor.decrypt(f0)
    with pytest.raises(ReplayError):
        decryptor.decrypt(f2)


def test_nonce_reuse_prevention():
    """Verify FrameEncryptor detects and rejects any duplicate nonce attempt."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)

    # Simulate forced duplicate sequence
    encryptor.encrypt(b"first")
    encryptor._next_sequence = 0  # Force reset sequence without new key

    with pytest.raises(NonceReuseError):
        encryptor.encrypt(b"second")


def test_sequence_overflow_prevention():
    """Verify sequence counter overflow triggers SequenceOverflowError."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    encryptor._next_sequence = MAX_SEQUENCE + 1

    with pytest.raises(SequenceOverflowError):
        encryptor.encrypt(b"overflow")


def test_session_cipher_bidirectional_integration():
    """Verify full end-to-end SessionCipher with Phase 7 derived session keys."""
    # 1. Ephemeral X25519 key exchange
    init_kp = generate_ephemeral_keypair()
    resp_kp = generate_ephemeral_keypair()

    init_secret = compute_shared_secret(init_kp.private_key, resp_kp.public_key)
    resp_secret = compute_shared_secret(resp_kp.private_key, init_kp.public_key)
    assert init_secret == resp_secret

    salt = os.urandom(32)  # Simulated authenticated transcript hash
    init_keys = derive_session_keys(init_secret, salt, is_initiator=True)
    resp_keys = derive_session_keys(resp_secret, salt, is_initiator=False)

    # 2. Initialize SessionCipher on both sides
    init_cipher = SessionCipher.from_session_keys(init_keys)
    resp_cipher = SessionCipher.from_session_keys(resp_keys)

    # 3. Initiator -> Responder chat
    init_wire = init_cipher.encrypt(b"Hi from initiator!")
    resp_received = resp_cipher.decrypt(init_wire)
    assert resp_received == b"Hi from initiator!"

    # 4. Responder -> Initiator reply
    resp_wire = resp_cipher.encrypt(b"Hello from responder!")
    init_received = init_cipher.decrypt(resp_wire)
    assert init_received == b"Hello from responder!"

    # 5. Multi-message conversation
    for i in range(10):
        init_data = init_cipher.encrypt(f"Ping {i}".encode())
        assert resp_cipher.decrypt(init_data) == f"Ping {i}".encode()

        resp_data = resp_cipher.encrypt(f"Pong {i}".encode())
        assert init_cipher.decrypt(resp_data) == f"Pong {i}".encode()


def test_reflection_attack_immunity():
    """Verify that a reflected frame cannot be decrypted by the sender itself.

    Because send_key != recv_key (directional keys from Phase 7), an attacker
    looping packets back to the sender triggers AuthenticationError.
    """
    secret = os.urandom(32)
    salt = os.urandom(32)
    init_keys = derive_session_keys(secret, salt, is_initiator=True)
    cipher = SessionCipher.from_session_keys(init_keys)

    outgoing_wire = cipher.encrypt(b"Reflect me if you can")

    # Initiator receives its own outgoing frame back
    with pytest.raises(AuthenticationError):
        cipher.decrypt(outgoing_wire)


def test_empty_payload_encryption():
    """Verify 0-byte payload encryption and authentication works correctly."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key)

    wire = encryptor.encrypt_raw(b"")
    assert len(wire) == MIN_FRAME_LEN  # 20 bytes header + 16 bytes tag

    plaintext = decryptor.decrypt_raw(wire)
    assert plaintext == b""


def test_large_binary_chunk_encryption():
    """Verify large payload (e.g. 1 MB binary chunk) encryption roundtrip."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key)

    large_data = os.urandom(1024 * 1024)  # 1 MB
    wire = encryptor.encrypt_raw(large_data)
    decrypted = decryptor.decrypt_raw(wire)

    assert decrypted == large_data


def test_associated_data_custom_binding():
    """Verify custom associated data is cryptographically authenticated."""
    key = os.urandom(32)
    encryptor = FrameEncryptor(key)
    decryptor = FrameDecryptor(key)

    extra_aad = b"stream_id=file-transfer-chunk-01"
    wire = encryptor.encrypt_raw(b"Chunk payload", associated_data=extra_aad)

    # Success with matching AAD
    assert decryptor.decrypt_raw(wire, associated_data=extra_aad) == b"Chunk payload"

    # Reset decryptor sequence to test mismatched AAD
    decryptor2 = FrameDecryptor(key)
    with pytest.raises(AuthenticationError):
        decryptor2.decrypt_raw(wire, associated_data=b"mismatched-aad")
