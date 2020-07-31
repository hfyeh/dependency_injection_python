import hashlib
from abc import ABCMeta, abstractmethod


class IHash(metaclass=ABCMeta):
    @abstractmethod
    def compute_hashed_password(self, password: str) -> str:
        pass


class Sha256Adapter(IHash):
    def compute_hashed_password(self, password: str) -> str:
        crypt = hashlib.sha256()
        crypt.update(password)
        hashed_password = crypt.hexdigest()
        return hashed_password
