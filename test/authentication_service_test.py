import unittest
from unittest import mock
from unittest.mock import create_autospec

from app import AuthenticationService

DefaultHashedPassword = 'hashed_password'

DefaultOtp = 'current_otp'

DefaultPassword = '123456'

DefaultUsername = 'sharefun'


class AuthenticationServiceTest(unittest.TestCase):
    def setUp(self):
        self._logging = mock.Mock()
        self._notification = mock.Mock()
        self._failed_counter = mock.Mock()
        self._otp_service = mock.Mock()
        self._hash = mock.Mock()
        self._user = mock.Mock()

        self._authentication_service = AuthenticationService(self._user,
                                                             self._hash,
                                                             self._otp_service,
                                                             self._failed_counter,
                                                             self._notification,
                                                             self._logging)

    def test_is_valid(self):
        self._given_account_is_locked(False)
        self._given_password(DefaultHashedPassword)
        self._hash.compute = create_autospec(self._hash.compute, return_value=DefaultHashedPassword)
        self._otp_service.get_current_otp = create_autospec(self._otp_service.get_current_otp,
                                                            return_value=DefaultOtp)

        is_valid = self._authentication_service.verify(DefaultUsername, DefaultPassword, DefaultOtp)
        self.assertTrue(is_valid)

    def _given_password(self, password):
        self._user.get_password = create_autospec(self._user.get_password, return_value=password)

    def _given_account_is_locked(self, is_locked):
        self._failed_counter.is_account_locked = create_autospec(self._failed_counter.is_account_locked,
                                                                 return_value=is_locked)


if __name__ == '__main__':
    unittest.main()
