import unittest
from unittest import mock
from unittest.mock import create_autospec

from app import AuthenticationService, FailedTooManyTimesError
from app.notification_decorator import NotificationDecorator

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

        self._authentication_service = AuthenticationService(self._user, self._hash, self._otp_service,
                                                             self._failed_counter, self._logging)
        self._authentication_service = NotificationDecorator(self._authentication_service,
                                                             self._notification)

    def test_is_valid(self):
        is_valid = self._when_valid()
        self._should_be_valid(is_valid)

    def test_is_invalid(self):
        is_valid = self._when_invalid()
        self._should_be_invalid(is_valid)

    def test_add_failed_count_when_invalid(self):
        is_valid = self._when_invalid()
        self._should_add_failed_count(DefaultUsername)

    def test_get_failed_count_when_invalid(self):
        is_valid = self._when_invalid()
        self._should_get_failed_count(DefaultUsername)

    def test_notify_user_when_invalid(self):
        is_valid = self._when_invalid()
        self._should_notify_user(DefaultUsername)

    def test_log_failed_count_when_invalid(self):
        is_valid = self._when_invalid()
        self._should_log_failed_count()

    def test_reset_failed_count_when_valid(self):
        is_valid = self._when_valid()
        self._should_reset_failed_count(DefaultUsername)

    def test_raise_error_when_account_is_locked(self):
        self._given_account_is_locked(True)
        self._should_raise_error(FailedTooManyTimesError, self._authentication_service.verify,
                                 [DefaultUsername, DefaultPassword, DefaultOtp])

    def _should_raise_error(self, error, func, args):
        with self.assertRaises(error):
            func(*args)

    def _should_reset_failed_count(self, username):
        self._failed_counter.reset.assert_called_once_with(username)

    def _when_valid(self):
        self._given_account_is_locked(False)
        self._given_password(DefaultHashedPassword)
        self._given_hash(DefaultHashedPassword)
        self._given_otp(DefaultOtp)
        is_valid = self._when_verify(DefaultUsername, DefaultPassword, DefaultOtp)
        return is_valid

    def _should_log_failed_count(self):
        self._logging.info.assert_called_once()

    def _should_get_failed_count(self, username):
        self._failed_counter.get.assert_called_once_with(username)

    def _should_notify_user(self, username):
        self._notification.notify.assert_called_once_with(username)

    def _should_add_failed_count(self, username):
        self._failed_counter.add.assert_called_once_with(username)

    def _when_invalid(self):
        self._given_account_is_locked(False)
        self._given_password(DefaultHashedPassword)
        self._given_hash(DefaultHashedPassword)
        self._given_otp(DefaultOtp)
        is_valid = self._when_verify(DefaultUsername, DefaultPassword, 'wrong_otp')
        return is_valid

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
