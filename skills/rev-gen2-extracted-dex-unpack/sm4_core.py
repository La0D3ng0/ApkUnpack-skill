"""Small, dependency-free SM4 block primitive. No mode or padding is implied."""

from __future__ import annotations


SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)
FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
CK = tuple(
    int.from_bytes(bytes(((4 * i + j) * 7) & 0xFF for j in range(4)), "big")
    for i in range(32)
)
MASK = 0xFFFFFFFF


def rotl(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & MASK


def tau(value: int) -> int:
    return (
        (SBOX[(value >> 24) & 0xFF] << 24)
        | (SBOX[(value >> 16) & 0xFF] << 16)
        | (SBOX[(value >> 8) & 0xFF] << 8)
        | SBOX[value & 0xFF]
    )


def key_schedule(key: bytes) -> tuple[int, ...]:
    if len(key) != 16:
        raise ValueError("SM4 key must be exactly 16 bytes")
    words = [int.from_bytes(key[i:i + 4], "big") ^ FK[i // 4]
             for i in range(0, 16, 4)]
    round_keys = []
    for i in range(32):
        value = tau(words[i + 1] ^ words[i + 2] ^ words[i + 3] ^ CK[i])
        next_word = words[i] ^ value ^ rotl(value, 13) ^ rotl(value, 23)
        round_keys.append(next_word)
        words.append(next_word)
    return tuple(round_keys)


def crypt_block(block: bytes, round_keys: tuple[int, ...]) -> bytes:
    if len(block) != 16 or len(round_keys) != 32:
        raise ValueError("SM4 requires one 16-byte block and 32 round keys")
    words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]
    for i in range(32):
        value = tau(words[i + 1] ^ words[i + 2] ^ words[i + 3] ^ round_keys[i])
        next_word = words[i] ^ value ^ rotl(value, 2) ^ rotl(value, 10) ^ rotl(value, 18) ^ rotl(value, 24)
        words.append(next_word)
    return b"".join(word.to_bytes(4, "big") for word in reversed(words[-4:]))


def decrypt_block(block: bytes, round_keys: tuple[int, ...]) -> bytes:
    return crypt_block(block, tuple(reversed(round_keys)))


def decrypt_ecb(data: bytes, round_keys: tuple[int, ...]) -> bytes:
    """Decrypt full blocks without padding. Call only for verified SM4-ECB paths."""
    if len(data) % 16:
        raise ValueError("SM4-ECB input length must be block aligned")
    inverse = tuple(reversed(round_keys))
    return b"".join(crypt_block(data[i:i + 16], inverse)
                    for i in range(0, len(data), 16))
