from .user import User

class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        password_from_db = User.query.filter_by(username=username).first().password
        raise NotImplementedError()
