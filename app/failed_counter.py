from abc import ABCMeta, abstractmethod

import requests


class IFailedCounter(metaclass=ABCMeta):
    @abstractmethod
    def reset_failed_count(self, username: str) -> None:
        pass

    @abstractmethod
    def add_failed_count(self, username: str) -> None:
        pass

    @abstractmethod
    def get_failed_count(self, username: str) -> int:
        pass

    @abstractmethod
    def is_account_locked(self, username: str) -> bool:
        pass


class FailedCounter(IFailedCounter):
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

    def is_account_locked(self, username: str) -> bool:
        response = requests.post('https://sharefun.com/api/is_locked', data={username: username})
        response.raise_for_status()
        is_acount_locked = response.json()['is_account_locked']
        return is_acount_locked
