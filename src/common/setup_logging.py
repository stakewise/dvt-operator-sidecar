import logging
from datetime import datetime, timezone

from pythonjsonlogger import jsonlogger

from src.config import settings
from src.config.settings import LOG_DATE_FORMAT, LOG_JSON


class JsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            date = datetime.fromtimestamp(record.created, tz=timezone.utc)
            log_record['timestamp'] = date.strftime(LOG_DATE_FORMAT)
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname


def setup_logging():
    if settings.log_format == LOG_JSON:
        formatter = JsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
        logHandler = logging.StreamHandler()
        logHandler.setFormatter(formatter)
        logging.basicConfig(
            level=settings.log_level,
            handlers=[logHandler],
        )
    else:
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt=LOG_DATE_FORMAT,
            level=settings.log_level,
        )


def setup_sentry():
    if settings.sentry_dsn:
        # pylint: disable-next=import-outside-toplevel
        import sentry_sdk

        sentry_sdk.init(
            settings.sentry_dsn,
            traces_sample_rate=0.1,
            environment=settings.sentry_environment,
        )
