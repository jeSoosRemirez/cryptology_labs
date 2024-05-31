import hashlib

class HAVAL:
    def __init__(self, passes=3, hash_length=128):
        self.passes = passes
        self.hash_length = hash_length // 8  # convert bits to bytes
        self.block_size = 1024 // 8  # HAVAL processes 1024-bit blocks

    def _pad(self, message):
        message_length = len(message)
        padding_length = (self.block_size - (message_length % self.block_size)) % self.block_size
        return message + b'\x80' + b'\x00' * (padding_length - 1) + message_length.to_bytes(8, byteorder='big')

    def _hash_blocks(self, message):
        state = hashlib.sha256()
        for i in range(0, len(message), self.block_size):
            block = message[i:i + self.block_size]
            state.update(block)
        return state.digest()

    def digest(self, message):
        message = self._pad(message)
        for _ in range(self.passes):
            message = self._hash_blocks(message)
        return message[:self.hash_length]

    def hexdigest(self, message):
        return self.digest(message).hex()

# Usage example
message = b"hello world"
haval = HAVAL(passes=3, hash_length=128)
hash_digest = haval.hexdigest(message)
print(f"HAVAL Hash: {hash_digest}")
