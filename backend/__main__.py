import argparse
import logging
import sys
import tomllib
import traceback

from pathlib import Path
from server import HttpServer

''' Loads and configures the HTTP server '''


def config_assert(config, key, value_type, section=None, allowed_values=None):
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
            print(f'CONFIG: the value "{config[key]}" for the key "{key}" is not allowed. Valid options: {allowed_values}')
            exit(1)


def parse_command_line_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', type=Path, default='webdnd_config.toml', help='Path to config file')
    return parser.parse_args()


def parse_config_file(config_path):
    try:
        config_file = open(config_path, 'rb')
        return tomllib.load(config_file)

    except FileNotFoundError:
        print(f'CONFIG: "{config_path}" cannot be found')
        exit(1)
    except tomllib.TOMLDecodeError as e:
        print(f'CONFIG: "{config_path}" contains errors: {e}')
        exit(1)
    finally:
        config_file.close()


def config_logging(config):
    logger = logging.getLogger('web_dnd')

    if 'logging' not in config:
        # Disable all logging
        logger.disable(logging.CRITICAL)
        return logger

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')

    # Check if logging to stdout is enabled
    if 'stdout' in config['logging'] \
            and 'enable' in config['logging']['stdout'] \
            and config['logging']['stdout']['enable']:

        # Assert that required properties exist
        config_assert(config['logging']['stdout'], 'level', str,
                      allowed_values=['debug', 'info', 'warn', 'error', 'critical'],
                      section='logging.stdout')

        stdout_level = getattr(logging, config['logging']['stdout']['level'].upper(), None)

        log_stdout = logging.StreamHandler(sys.stdout)
        log_stdout.setLevel(stdout_level)
        log_stdout.setFormatter(formatter)
        logger.addHandler(log_stdout)

    # Check if logging to stderr is enabled
    if 'stderr' in config['logging'] \
            and 'enable' in config['logging']['stderr'] \
            and config['logging']['stderr']['enable']:

        # Assert that required properties exist
        config_assert(config['logging']['stderr'], 'level', str,
                      allowed_values=['debug', 'info', 'warn', 'error', 'critical'],
                      section='logging.stderr')

        stderr_level = getattr(logging, config['logging']['stderr']['level'].upper(), None)

        log_stderr = logging.StreamHandler(sys.stderr)
        log_stderr.setLevel(stderr_level)
        log_stderr.setFormatter(formatter)
        logger.addHandler(log_stderr)

    # Check if logging to file is enabled
    if 'file' in config['logging'] \
            and 'enable' in config['logging']['file'] \
            and config['logging']['file']['enable']:

        # Assert that required properties exist
        config_assert(config['logging']['file'], 'level', str,
                      allowed_values=['debug', 'info', 'warn', 'error', 'critical'],
                      section='logging.file')
        config_assert(config['logging']['file'], 'filepath', str, section='logging.file')

        file_level = getattr(logging, config['logging']['file']['level'].upper(), None)

        log_file = logging.FileHandler(config['logging']['file']['filepath'], encoding='utf-8')
        log_file.setLevel(file_level)
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
    config_assert(config, 'ip', str)
    config_assert(config, 'port', int)
    config_assert(config, 'serve_path', str)

    config_assert(config['routing'], 'not_found', str)
    config_assert(config['routing'], 'server_error', str)
    # config_assert(config['routing'], 'try_extensions', list)

    # HttpServer creation
    server = HttpServer(config)
    server.serve_forever()

    logging.shutdown()


if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        pass

    except Exception as e:
        # Log any unhandled exception
        exception_msg = ''.join(traceback.format_exception(e))

        logger = logging.getLogger('web_dnd')
        logger.debug(f'{exception_msg}')
        logger.critical(f'Unhandled exception -- {e}')
