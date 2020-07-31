import requests


class FailedCounter:
    def reset_failed_count(self, username: str) -> None:
        response = requests.post('https://sharefun.com/api/failed_counter/reset', data={username: username})
        response.raise_for_status()

    def add_failed_count(self, username: str) -> None:
        response = requests.post('https://sharefun.com/api/failed_counter/add', data={username: username})
        response.raise_for_status()

    def get_failed_count(self, username: str) -> int:
        response = requests.post('https://sharefun.com/api/get_failed_count', data={username: username})
        response.raise_for_status()
        failed_count = response.json()['failed_count']
        return failed_count
