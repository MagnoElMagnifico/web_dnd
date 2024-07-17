import argparse
import logging
import sys
import tomllib
import traceback

from pathlib import Path
from server import HttpServer

""" Loads and configures the HTTP server """


def config_assert(config, key, value_type, section=None, allowed_values=None):
    """Asserts that the config has a specific attribute.
    If it fails, shows an error an terminates the program with error exit code.
    :param config: Configuration dictionary to check
    :param key: Key name to check
    :param value_type: Data type of the stored value
    :param section: Show in the error message so the user knows where to put this key
    :param allowed_values: List of the allowed values of the attribute"""

    if key not in config:
        if section is None:
            print(f'CONFIG: "{key}" property is required')
        else:
            print(f'CONFIG: "{key}" property is required in the section "{section}"')
        exit(1)

    if not isinstance(config[key], value_type):
        print(f'CONFIG: "{key}" must be a {value_type.__name__}')
        exit(1)

    if allowed_values is not None:
        if config[key] not in allowed_values:
            print(
                f'CONFIG: the value "{config[key]}" for the key "{key}" is not allowed. Valid options: {allowed_values}'
            )
            exit(1)


def parse_command_line_options():
    """Parses CLI arguments received"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default="webdnd_config.toml",
        help="Path to config file",
    )
    return parser.parse_args()


def parse_config_file(config_path):
    """Reads and parses the TOML config file"""

    config_file = None
    try:
        config_file = open(config_path, "rb")
        return tomllib.load(config_file)

    except FileNotFoundError:
        print(f'CONFIG: "{config_path}" cannot be found')
        exit(1)
    except tomllib.TOMLDecodeError as e:
        print(f'CONFIG: "{config_path}" contains errors: {e}')
        exit(1)
    finally:
        if config_file is not None:
            config_file.close()


def get_log_level(value):
    """Helper function to transform from str to logging level"""

    match value:
        case "debug":
            return logging.DEBUG

        case "info":
            return logging.INFO

        case "warn":
            return logging.WARN

        case "error":
            return logging.ERROR

        case "critical":
            return logging.CRITICAL

        case other:
            raise ValueError(f'Invalid log level: "{other}"')


def config_logging(config):
    """Configurates the logging system with the specified config"""

    logger = logging.getLogger("web_dnd")

    if "logging" not in config:
        # Disable all logging
        logger.propagate = False
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

    # Check if logging to stdout is enabled
    if (
        "stdout" in config["logging"]
        and "enable" in config["logging"]["stdout"]
        and config["logging"]["stdout"]["enable"]
    ):

        # Assert that required properties exist
        config_assert(
            config["logging"]["stdout"],
            "level",
            str,
            allowed_values=["debug", "info", "warn", "error", "critical"],
            section="logging.stdout",
        )

        log_stdout = logging.StreamHandler(sys.stdout)
        log_stdout.setLevel(get_log_level(config["logging"]["stdout"]["level"]))
        log_stdout.setFormatter(formatter)
        logger.addHandler(log_stdout)

    # Check if logging to stderr is enabled
    if (
        "stderr" in config["logging"]
        and "enable" in config["logging"]["stderr"]
        and config["logging"]["stderr"]["enable"]
    ):

        # Assert that required properties exist
        config_assert(
            config["logging"]["stderr"],
            "level",
            str,
            allowed_values=["debug", "info", "warn", "error", "critical"],
            section="logging.stderr",
        )

        log_stderr = logging.StreamHandler(sys.stderr)
        log_stderr.setLevel(get_log_level(config["logging"]["stderr"]["level"]))
        log_stderr.setFormatter(formatter)
        logger.addHandler(log_stderr)

    # Check if logging to file is enabled
    if (
        "file" in config["logging"]
        and "enable" in config["logging"]["file"]
        and config["logging"]["file"]["enable"]
    ):

        # Assert that required properties exist
        config_assert(
            config["logging"]["file"],
            "level",
            str,
            allowed_values=["debug", "info", "warn", "error", "critical"],
            section="logging.file",
        )
        config_assert(
            config["logging"]["file"], "filepath", str, section="logging.file"
        )

        log_file = logging.FileHandler(
            config["logging"]["file"]["filepath"], encoding="utf-8"
        )
        log_file.setLevel(get_log_level(config["logging"]["file"]["level"]))
        log_file.setFormatter(formatter)
        logger.addHandler(log_file)

    return logger


def main():
    args = parse_command_line_options()

    # Open config file
    config = parse_config_file(args.config)

    # Logger setup
    config_logging(config)

    # Check if required properties exist
    config_assert(config, "ip", str)
    config_assert(config, "port", int)
    config_assert(config, "serve_path", str)

    config_assert(config["routing"], "not_found", str, section="routing")
    config_assert(config["routing"], "server_error", str, section="routing")

    # PasswordHasher settings
    config_assert(config["security"], "n", int, section="security")
    config_assert(config["security"], "r", int, section="security")
    config_assert(config["security"], "p", int, section="security")
    config_assert(config["security"], "dklen", int, section="security")
    config_assert(config["security"], "salt_size", int, section="security")

    # Database settings
    config_assert(config["database"], "filepath", str, section="database")

    # HttpServer creation
    server = HttpServer(config)
    server.serve_forever()

    logging.shutdown()


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        pass

    except Exception as e:
        # Log any unhandled exception
        exception_msg = "".join(traceback.format_exception(e))

        logger = logging.getLogger("web_dnd")
        logger.debug(f"{exception_msg}")
        logger.critical(f"Unhandled exception -- {e}")
