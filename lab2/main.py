def xtea_encrypt(key, block, num_rounds=32):
    """
    Зашифрувати один блок даних за допомогою XTEA.

    :param key: 16-байтний ключ шифрування.
    :param block: Блок даних для шифрування (8 байтів).
    :param num_rounds: Кількість раундів шифрування (за замовчуванням 32).
    :return: Зашифрований блок даних (8 байтів).
    """
    v0, v1 = int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    sum_val = 0

    for _ in range(num_rounds):
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + k[sum_val & 3])) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) ^ (v0 >> 5)) + v0) ^ ((sum_val + delta) + k[(sum_val >> 11) & 3])) & 0xFFFFFFFF

    return (v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big'))

def xtea_decrypt(key, block, num_rounds=32):
    """
    Розшифрувати один блок даних за допомогою XTEA.

    :param key: 16-байтний ключ шифрування.
    :param block: Блок даних для розшифрування (8 байтів).
    :param num_rounds: Кількість раундів шифрування (за замовчуванням 32).
    :return: Розшифрований блок даних (8 байтів).
    """
    v0, v1 = int.from_bytes(block[:4], 'big'), int.from_bytes(block[4:], 'big')
    k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    sum_val = (delta * num_rounds) & 0xFFFFFFFF

    for _ in range(num_rounds):
        v1 = (v1 - (((v0 << 4) ^ (v0 >> 5)) + v0) ^ ((sum_val + delta) + k[(sum_val >> 11) & 3])) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + k[sum_val & 3])) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF

    return (v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big'))

# Приклад використання
key = b'0123456789ABCDEF'  # 16-байтний ключ
block = b'ABCDEFGH'         # 8-байтний блок даних

encrypted = xtea_encrypt(key, block)
print(f"Зашифрований блок: {encrypted.hex()}")

decrypted = xtea_decrypt(key, encrypted)
print(f"Розшифрований блок: {decrypted.decode()}")
