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
        self._given_hash(DefaultHashedPassword)
        self._given_otp(DefaultOtp)

        is_valid = self._when_verify(DefaultUsername, DefaultPassword, DefaultOtp)
        self._should_be_valid(is_valid)

    def test_is_invalid(self):
        self._given_account_is_locked(False)
        self._given_password(DefaultHashedPassword)
        self._given_hash(DefaultHashedPassword)
        self._given_otp(DefaultOtp)

        is_valid = self._when_verify(DefaultUsername, DefaultPassword, 'wrong_otp')
        self._should_be_invalid(is_valid)

    def _should_be_invalid(self, is_valid):
        self.assertFalse(is_valid)

    def _should_be_valid(self, is_valid):
        self.assertTrue(is_valid)

    def _when_verify(self, username, password, otp):
        is_valid = self._authentication_service.verify(username, password, otp)
        return is_valid

    def _given_otp(self, otp):
        self._otp_service.get_current_otp = create_autospec(self._otp_service.get_current_otp,
                                                            return_value=otp)

    def _given_hash(self, password):
        self._hash.compute = create_autospec(self._hash.compute, return_value=password)

    def _given_password(self, password):
        self._user.get_password = create_autospec(self._user.get_password, return_value=password)

    def _given_account_is_locked(self, is_locked):
        self._failed_counter.is_account_locked = create_autospec(self._failed_counter.is_account_locked,
                                                                 return_value=is_locked)


if __name__ == '__main__':
    unittest.main()
