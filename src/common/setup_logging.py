import logging
from datetime import datetime, timezone

from pythonjsonlogger import jsonlogger

from src.common.utils import format_error
from src.config import settings
from src.config.settings import LOG_DATE_FORMAT, LOG_JSON


class JsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):  # type: ignore
        super().add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            date = datetime.fromtimestamp(record.created, tz=timezone.utc)
            log_record['timestamp'] = date.strftime(LOG_DATE_FORMAT)
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname


class ExtendedLogger(logging.Logger):
    def error_verbose(self, msg, *args, **kwargs):  # type: ignore
        if settings.verbose:
            kwargs['exc_info'] = True
        args = [format_error(arg) if isinstance(arg, Exception) else arg for arg in args]
        self.error(msg, *args, **kwargs)

    def exception_verbose(self, e: Exception):  # type: ignore
        self.error_verbose('%s', e)

    def warning(self, msg, *args, **kwargs):  # type: ignore
        args = [format_error(arg) if isinstance(arg, Exception) else arg for arg in args]
        super().warning(msg, *args, **kwargs)


def setup_logging() -> None:
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
            format='%(asctime)s %(levelname)-8s %(name)s %(message)s',
            datefmt=LOG_DATE_FORMAT,
            level=settings.log_level,
        )

    logging.setLoggerClass(ExtendedLogger)


def setup_sentry() -> None:
    if settings.sentry_dsn:
        # pylint: disable-next=import-outside-toplevel
        import sentry_sdk

        sentry_sdk.init(
            settings.sentry_dsn,
            traces_sample_rate=0.1,
            environment=settings.sentry_environment or settings.network,
        )
