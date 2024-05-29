from Crypto.Hash import HAVAL


# Приклад функції для обчислення HAVAL хешу
def haval_hash(data, bits=256, passes=5):
    """
    Обчислює хеш HAVAL для заданих даних.

    :param data: Вхідні дані (рядок або байти)
    :param bits: Довжина вихідного хешу (128, 160, 192, 224, 256 біт)
    :param passes: Кількість раундів (3, 4, 5)
    :return: Хеш-значення в шістнадцятковому форматі
    """
    if isinstance(data, str):
        data = data.encode()  # Перетворюємо рядок у байти

    hash_obj = HAVAL.new(bits=bits, passes=passes)
    hash_obj.update(data)
    return hash_obj.hexdigest()

# Приклад використання
data = "Hello, World!"
hash_value = haval_hash(data, bits=256, passes=5)
print(f"HAVAL Hash: {hash_value}")
