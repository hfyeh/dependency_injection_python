import unittest
from unittest import mock
from unittest.mock import create_autospec

from app import AuthenticationService


class AuthenticationServiceTest(unittest.TestCase):
    def test_is_valid(self):
        user = mock.Mock()
        hash = mock.Mock()
        otp_service = mock.Mock()
        failed_counter = mock.Mock()
        notification = mock.Mock()
        logging = mock.Mock()

        failed_counter.is_account_locked = create_autospec(failed_counter.is_account_locked, return_value=False)
        user.get_password = create_autospec(user.get_password, return_value='hashed_password')
        hash.compute = create_autospec(hash.compute, return_value='hashed_password')
        otp_service.get_current_otp = create_autospec(otp_service.get_current_otp, return_value='current_otp')

        authentication_service = AuthenticationService(user,
                                                       hash,
                                                       otp_service,
                                                       failed_counter,
                                                       notification,
                                                       logging)

        is_valid = authentication_service.verify('sharefun', '123456', 'current_otp')
        self.assertTrue(is_valid)


if __name__ == '__main__':
    unittest.main()
