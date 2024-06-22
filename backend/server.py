import argparse
import logging
import sys
import tomllib
import traceback

from pathlib import Path
from http_server import HttpServer


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
        config = tomllib.load(config_file)

        # Check if required properties exist
        config_assert(config, 'ip', str)
        config_assert(config, 'port', int)
        config_assert(config, 'serve_path', str)

        return config

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
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')

    # Check if logging to stdout is enabled
    if 'logging' in config and 'enable' in config['logging'] and config['logging']['enable']:
        log_config = config['logging']

        # Assert that required properties exist
        config_assert(log_config, 'level', str,
                      allowed_values=['debug', 'info', 'warn', 'error', 'critical'],
                      section='logging')

        stdout_level = getattr(logging, log_config['level'].upper(), None)

        log_stdout = logging.StreamHandler(sys.stdout)
        log_stdout.setLevel(stdout_level)
        log_stdout.setFormatter(formatter)
        logger.addHandler(log_stdout)

    # Check if logging to file is enabled
    if 'file_logging' in config and 'enable' in config['file_logging'] and config['file_logging']['enable']:
        filelog_config = config['file_logging']

        # Assert that required properties exist
        config_assert(filelog_config, 'level', str,
                      allowed_values=['debug', 'info', 'warn', 'error', 'critical'],
                      section='file_logging')
        config_assert(filelog_config, 'file', str, section='file_logging')

        file_level = getattr(logging, filelog_config['level'].upper(), None)

        log_file = logging.FileHandler(filelog_config['file'], encoding='utf-8')
        log_file.setLevel(file_level)
        log_file.setFormatter(formatter)
        logger.addHandler(log_file)

    return logger


def main():
    args = parse_command_line_options()

    # Open config file
    config = parse_config_file(args.config)

    # Logger setup
    logger = config_logging(config)

    # HttpServer creation
    try:
        server = HttpServer(config['ip'], config['port'], Path(config['serve_path']))
        server.serve_forever()
    except Exception as e:
        # Log any unhandled exception
        exception_msg = traceback.format_exception(e)
        logger.debug(f'{exception_msg}')
        logger.critical(f'{e}')

    logging.shutdown()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
