from .user import User

class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        raise NotImplementedError()

    def get_password(self, username: str) -> str:
        return User.query.filter_by(username=username).first().password
