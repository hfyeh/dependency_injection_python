import logging


class Logging:
    def log_failed_count(self, message) -> None:
        logging.info(message)