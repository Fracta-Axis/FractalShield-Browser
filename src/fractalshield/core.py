import os
import hmac
import hashlib
from typing import Tuple, Optional, List
from argon2 import low_level

# ==================== CONSTANTES DEL PAPER v1.1 ====================
MAGIC_PREFIX = b"MFSU\x04"
KEY_LEN = 32
MAC_LEN = 32
RAW_KEY_LEN = KEY_LEN + MAC_LEN
M_COST_BASE = 65536
P_PARALLELISM = 4
T_COST_BASE = 3

# ==================== HELPERS ====================
def _sha3_pre_hash(password: bytes) -> bytes:
    return hashlib.sha3_256(password).digest()

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def _pkcs7_unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def derive_layer_key(password: bytes, salt: bytes, sid: bytes, layer: int,
                     t_cost: int = T_COST_BASE, m_cost: int = M_COST_BASE) -> Tuple[bytes, bytes]:
    pre_hashed = _sha3_pre_hash(password)
    context = pre_hashed + sid + salt + f"layer_{layer}".encode()
    raw_key = low_level.hash_secret_raw(
        secret=context, salt=salt,
        time_cost=t_cost, memory_cost=m_cost,
        parallelism=P_PARALLELISM, hash_len=RAW_KEY_LEN,
        type=low_level.Type.ID
    )
    return raw_key[:KEY_LEN], raw_key[KEY_LEN:]

def _sha3_counter_keystream(dk: bytes, iv: bytes, length: int) -> bytes:
    kmix = hashlib.sha3_256(dk[:32] + iv).digest()
    buf = bytearray()
    i = 0
    while len(buf) < length:
        block = hashlib.sha3_256(kmix + i.to_bytes(4, "big")).digest()
        buf.extend(block)
        i += 1
    return bytes(buf[:length])

def check_magic_constant_time(plaintext: bytes) -> bool:
    if len(plaintext) < len(MAGIC_PREFIX):
        return False
    return hmac.compare_digest(plaintext[:len(MAGIC_PREFIX)], MAGIC_PREFIX)

# ==================== CIFRADO COMPLETO ====================
def fractal_shield_encrypt(data: bytes, password: bytes, level: int = 1) -> bytes:
    N = 3 if level == 1 else 4 if level == 2 else 5
    sid = os.urandom(16)
    s0 = os.urandom(16)                                 # sal expuesta para K0 y order_enc

    padded = _pkcs7_pad(data)
    real_payload = MAGIC_PREFIX + padded
    L = len(real_payload)

    layer_cts = [None] * N

    # Capa 0 (real)
    k0_enc, _ = derive_layer_key(password, s0, sid, 0, T_COST_BASE)
    ct0 = _sha3_counter_keystream(k0_enc, s0, L)
    layer_cts[0] = s0 + bytes(a ^ b for a, b in zip(real_payload, ct0))

    # Capas decoy
    for i in range(1, N):
        si = os.urandom(16)
        t_cost = T_COST_BASE * (1 << i)
        ki_enc, _ = derive_layer_key(password, si, sid, i, t_cost)
        di = _sha3_counter_keystream(ki_enc, si, L)
        layer_cts[i] = si + di

    # Shuffle key-dependent
    order_seed = hashlib.sha3_256(password + b"ORDER" + sid).digest()
    indices = list(range(N))
    for i in range(N-1, 0, -1):
        j = int.from_bytes(hashlib.sha3_256(order_seed + i.to_bytes(4, "big")).digest()[:4], "big") % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]

    shuffled_layers = [layer_cts[idx] for idx in indices]

    # order_enc bajo k0
    order_bytes = bytes(indices)
    order_keystream = _sha3_counter_keystream(k0_enc, s0, len(order_bytes))
    order_enc = bytes(a ^ b for a, b in zip(order_bytes, order_keystream))

    # Global MAC (OP3)
    kMAC = hashlib.sha3_256(k0_enc + b"MAC" + sid).digest()
    mac_input = sid + s0 + order_enc + b"".join(shuffled_layers)
    tau = hmac.new(kMAC, mac_input, hashlib.sha3_256).digest()

    return sid + s0 + order_enc + b"".join(shuffled_layers) + tau


# ==================== DESCIFRADO CIEGO (OFV) ====================
def fractal_shield_decrypt(encrypted_blob: bytes, password: bytes, level: int = 1) -> Optional[bytes]:
    N = 3 if level == 1 else 4 if level == 2 else 5

    if len(encrypted_blob) < 16 + 16 + N + 32:
        return None

    sid = encrypted_blob[:16]
    s0 = encrypted_blob[16:32]
    order_enc = encrypted_blob[32:32 + N]
    layers_data = encrypted_blob[32 + N:-32]
    received_tau = encrypted_blob[-32:]

    k0_enc, _ = derive_layer_key(password, s0, sid, 0, T_COST_BASE)

    # Recuperar orden
    order_keystream = _sha3_counter_keystream(k0_enc, s0, N)
    order_bytes = bytes(a ^ b for a, b in zip(order_enc, order_keystream))
    try:
        indices = list(order_bytes)
        if len(set(indices)) != N or max(indices) >= N:
            return None
    except:
        return None

    # Global MAC check
    kMAC = hashlib.sha3_256(k0_enc + b"MAC" + sid).digest()
    mac_input = sid + s0 + order_enc + layers_data
    expected_tau = hmac.new(kMAC, mac_input, hashlib.sha3_256).digest()
    if not hmac.compare_digest(received_tau, expected_tau):
        return None

    layer_block_len = len(layers_data) // N
    L = layer_block_len - 16

    # Reordenar capas lógicamente
    ordered_layer_data = [None] * N
    for physical_idx, logical_idx in enumerate(indices):
        ordered_layer_data[logical_idx] = layers_data[physical_idx * layer_block_len : (physical_idx + 1) * layer_block_len]

    decrypted_candidates: List[bytes] = []

    # DESCIFRADO CIEGO
    for i in range(N):
        layer_block = ordered_layer_data[i]
        iv = layer_block[:16]
        ciphertext = layer_block[16:]
        
        t_cost = T_COST_BASE * (1 << i)
        enc_key, _ = derive_layer_key(password, iv, sid, i, t_cost)

        keystream = _sha3_counter_keystream(enc_key, iv, L)
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        decrypted_candidates.append(plaintext)

    # Búsqueda final del MAGIC (ciega)
    for candidate in decrypted_candidates:
        if check_magic_constant_time(candidate):
            try:
                unpadded = _pkcs7_unpad(candidate[len(MAGIC_PREFIX):])
                return unpadded
            except:
                pass
    return None


# ==================== PRUEBA v1.0 ====================
if __name__ == "__main__":
    pwd = b"mi_contrasena_fractal_2026"
    data = b"usuario_invisible_en_el_navegador_fractal"

    encrypted = fractal_shield_encrypt(data, pwd, level=1)
    decrypted = fractal_shield_decrypt(encrypted, pwd, level=1)

    print(f"✅ Encriptado: {len(encrypted)} bytes")
    print(f"✅ Descifrado correcto: {decrypted == data}")
    if decrypted:
        print(f"   Contenido: {decrypted.decode('utf-8')}")
