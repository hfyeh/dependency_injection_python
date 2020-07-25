class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        raise NotImplementedError()
