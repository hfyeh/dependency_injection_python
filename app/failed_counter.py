import requests


class FailedCounter:
    def reset_failed_count(self, username: str) -> None:
        response = requests.post('https://sharefun.com/api/failed_counter/reset', data={username: username})
        response.raise_for_status()

    def add_failed_count(self, username: str) -> None:
        response = requests.post('https://sharefun.com/api/failed_counter/add', data={username: username})
        response.raise_for_status()
