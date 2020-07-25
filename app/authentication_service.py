from .user import User
import hashlib

class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        password_from_db = User.query.filter_by(username=username).first().password
        raise NotImplementedError()

    def get_hash(self, plain_text: str) -> str:
        crypt = hashlib.sha256()
        crypt.update(plain_text)
        hash = crypt.hexdigest()
        return hash
