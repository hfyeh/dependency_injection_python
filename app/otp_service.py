import requests


class OtpService:
    def get_current_otp(self, username: str) -> str:
        response = requests.post('https://sharefun.com/api/otp', data={username: username})
        if not (response.status_code == requests.codes.ok):
            raise PermissionError()
        current_otp = response.json()['otp']
        return current_otp