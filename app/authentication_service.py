from .user import User
import hashlib
import requests


class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        password_from_db = User.query.filter_by(username=username).first().password

        crypt = hashlib.sha256()
        crypt.update(password)
        hash = crypt.hexdigest()
        hashed_password = hash

        raise NotImplementedError()

    def get_otp(self, username: str) -> str:
        response = requests.post('https://sharefun.com/api/otp', data={username: username})
        if response.status_code == requests.codes.ok:
            otp = response.json()['otp']
        else:
            raise PermissionError()
        return otp
