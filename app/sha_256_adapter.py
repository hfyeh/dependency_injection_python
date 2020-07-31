import hashlib


class Sha256Adapter:
    def compute_hashed_password(self, password: str) -> str:
        crypt = hashlib.sha256()
        crypt.update(password)
        hashed_password = crypt.hexdigest()
        return hashed_password