from abc import ABCMeta, abstractmethod

from .otp_service import OtpService, IOtpService
from .sha_256_adapter import Sha256Adapter, IHash
from .user import User, IUser


class IAuthenticationService(metaclass=ABCMeta):
    @abstractmethod
    def verify(self, username: str, password: str, otp: str) -> bool:
        pass


class AuthenticationBaseDecorator(IAuthenticationService):
    def __init__(self, authentication_service: IAuthenticationService):
        self._authentication_service = authentication_service

    def verify(self, username: str, password: str, otp: str) -> bool:
        return self._authentication_service.verify(username, password, otp)


class AuthenticationService(IAuthenticationService):
    def __init__(self, user: IUser = User(), hash: IHash = Sha256Adapter(), otp_service: IOtpService = OtpService()):
        self._user: IUser = user
        self._hash: IHash = hash
        self._otp_service: IOtpService = otp_service

    def verify(self, username: str, password: str, otp: str) -> bool:
        password_from_db = self._user.get_password(username)

        hashed_password = self._hash.compute(password)

        current_otp = self._otp_service.get_current_otp(username)

        if password_from_db == hashed_password and otp == current_otp:
            return True
        else:
            return False


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
