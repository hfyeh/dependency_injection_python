import unittest
from unittest import mock

from app import AuthenticationService


class AuthenticationServiceTest(unittest.TestCase):
    def test_is_valid(self):
        user = mock.Mock()
        hash = mock.Mock()
        otp_service = mock.Mock()
        failed_counter = mock.Mock()
        notification = mock.Mock()
        logging = mock.Mock()

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
