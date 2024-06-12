import argparse
import logging
import mimetypes
import os
import socket
import sys

from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlparse, unquote


class HttpError(Exception):
    ''' Base class exception for all the errors in the application '''


class HttpFormatError(HttpError):
    ''' The format of the HTTP message is invalid '''


class HttpFileNotFoundError(HttpError):
    ''' The requested file was not found '''


class HttpRequest:
    def __init__(self, method, url, version, headers, body):
        assert isinstance(url, str), 'URL must be a string'
        assert isinstance(version, str), 'version must be a string'
        assert isinstance(body, str | None), 'body must be a string'
        assert isinstance(headers, dict), 'headers must be a dictionary'

        if method not in ['GET', 'POST']:
            raise NotImplementedError(f'The method {method} is not supported')

        self._method = method
        self._url = url
        self._version = version
        self._body = body
        self._headers = headers

    def __getitem__(self, key):
        assert isinstance(key, str), 'Key must be a string'
        return self._headers[key]

    @property
    def body(self):
        return self._body

    @property
    def url(self):
        return self._url

    @property
    def method(self):
        return self._method

    @property
    def version(self):
        return self._method

    @classmethod
    def from_str(cls, msg):
        assert isinstance(msg, str) and msg, 'msg must be a not-empty string'

        # Iterate line by line
        line_iter = iter(msg.splitlines())

        # Process first line: method, url and version
        first_line = next(line_iter).split(' ')

        if len(first_line) != 3:
            raise HttpFormatError(f'Expected 3 fields, got {len(first_line)}: {' '.join(first_line)}')

        [method, url, version] = first_line

        # The rest must be headers and body
        headers = {}
        body = None

        try:
            line = next(line_iter)
            while line:  # Iter until empty line
                [header, value] = [e.strip() for e in line.split(':', 1)]
                headers[header.lower()] = value
                line = next(line_iter)

            assert not line, 'Malformed header: expected empty line'
            line = next(line_iter)

            body = ''.join(line_iter)

        except StopIteration:
            ...

        return cls(method, url, version, headers, body)

    def __str__(self):
        request = f'{self._method} {self._url} {self._version}\r\n'
        request += ''.join([f'{header}: {value}\r\n' for header, value in self._headers.items()])
        if self._body:
            request += f'\r\n{self._body}'
        return request


class HttpResponse:
    def __init__(self, version, status):
        assert isinstance(version, str), 'version must be a string'
        assert isinstance(status, HTTPStatus), 'status must be http.HTTPStatus'

        self._version = version
        self._status = status
        self._headers = {}
        self._body = None

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        assert isinstance(status, HTTPStatus), 'status must be http.HTTPStatus'
        self._status = status

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, version):
        assert isinstance(version, str), 'version must be a string'
        self._version = version

    def add_body(self, new_body):
        # TODO: add option to remove whitespace
        self._body = new_body
        self._headers['content-length'] = len(new_body)

    def body_from_file(self, filepath):
        assert isinstance(filepath, Path), 'filepath must be pathlib.Path'

        self.add_body(filepath.read_bytes())

        mimetype = mimetypes.guess_type(filepath)
        self._headers['content-type'] = mimetype[0]
        self._headers['content-encoding'] = mimetype[1]

    def __setitem__(self, key, value):
        assert isinstance(key, str), 'key must be a string'
        self._headers[key.lower()] = value

    def __getitem__(self, key):
        assert isinstance(key, str), 'key must be a string'
        return self._headers[key]

    def __str__(self):
        response = f'{self._version} {self._status.value} {self._status.phrase}\r\n'
        response += ''.join([f'{header}: {value}\r\n' for header, value in self._headers.items()])
        if self._body:
            if isinstance(self._body, bytes):
                response += f'\r\n{self._body.decode('ascii')}'
            elif isinstance(self._body, str):
                response += f'\r\n{self._body}'

        return response

    def to_bytes(self):
        header = f'{self._version} {self._status.value} {self._status.phrase}\r\n'
        header += ''.join([f'{header}: {value}\r\n' for header, value in self._headers.items()])
        header += '\r\n'

        response = bytearray(header, 'ascii')

        if self._body:
            if isinstance(self._body, bytes):
                response += self._body
            elif isinstance(self._body, str):
                response += self._body.encode('ascii')

        return response


class HttpServer:
    def __init__(self, ip='', port=8080, working_dir=os.getcwd()):
        self._log = logging.getLogger('web_dnd')
        self._ip = ip
        self._port = port

        mimetypes.init()
        assert isinstance(working_dir, Path), 'working_dir must be pathlib.Path'
        self._working_dir = working_dir.resolve()
        self._routing = {
            '/': 'index.html'
        }

        self._not_found_response = HttpResponse('HTTP/1.1', HTTPStatus.NOT_FOUND)
        self._not_found_response['content-type'] = 'text/html'
        self._not_found_response.add_body('''
            <html>
                <head>
                    <title>Web Dnd</title>
                <head>
                <body>
                    <h1>404 - Not Found</h1>
                </body>
            <html>
            ''')

        self._internal_error_response = HttpResponse('HTTP/1.1', HTTPStatus.INTERNAL_SERVER_ERROR)
        self._internal_error_response['content-type'] = 'text/html'
        self._internal_error_response.add_body('''
            <html>
                <head>
                    <title>Web Dnd</title>
                <head>
                <body>
                    <h1>500 - Internal Server Error</h1>
                </body>
            <html>
            ''')

    def serve_forever(self):
        # Socket creation
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Bind the socket to the given IP. Panic if it was invalid.
            try:
                server_socket.bind((self._ip, self._port))
            except Exception as e:  # TODO: specify exception
                self._log.critical(e)
                exit(1)

            server_socket.listen()

            repr_ip = ''
            match self._ip:
                case '':
                    repr_ip = '0.0.0.0'
                case '<broadcast>':
                    repr_ip = '255.255.255.255'
                case ip:
                    repr_ip = ip

            self._log.info(f'Server running on {self._working_dir}: http://{repr_ip}:{self._port}/')

            while True:
                connection_socket, address = server_socket.accept()
                self._log.debug(f'Accept {address[0]}:{address[1]}')

                # TODO: threads
                with connection_socket:
                    # Handle petitions until the connection is closed
                    while True:
                        # FIXME: problems with the path /AAAAAA<repeats 1024 times>
                        data = connection_socket.recv(1024)

                        if not data:
                            self._log.debug(f'End connection {address[0]}:{address[1]}')
                            break

                        request = HttpRequest.from_str(data.decode('ascii'))
                        response = self.handle_request(request, address)
                        connection_socket.sendall(response.to_bytes())

    def filepath_from_url(self, url):
        # URL decode and parse
        decoded_url = unquote(url)
        parsed_url = urlparse(decoded_url)

        # Apply routing if avaliable
        if parsed_url.path in self._routing:
            return Path(self._routing[parsed_url.path])

        if parsed_url.path[0] != '/':
            raise HttpFormatError(f'URL path must start with /, got {parsed_url.path}')

        requested_file = self._working_dir / parsed_url.path[1:]
        requested_file.resolve()

        if not requested_file.exists():
            raise HttpFileNotFoundError(f'"{requested_file}" does not exist')

        if requested_file.is_dir():
            raise HttpFileNotFoundError(f'"{requested_file}" is a directory')

        # Security check: the files must be inside the working directory: avoids Directory Path Traversal
        # FIXME: does not work with 'españa.txt'
        if os.path.commonprefix([requested_file, self._working_dir]) != self._working_dir:
            raise HttpFileNotFoundError(f'"{requested_file}" is not under "{self._working_dir}"')

        self._log.debug(requested_file)
        return requested_file

    def handle_request(self, request, address):
        response = None
        try:
            requested_file = self.filepath_from_url(request.url)
            response = HttpResponse('HTTP/1.1', HTTPStatus.OK)
            response.body_from_file(requested_file)

        except HttpFileNotFoundError as e:
            response = self._not_found_response
            self._log.debug(e)

        self._log.info(f'{address[0]} -- {request.method} {unquote(request.url)} -- {response.status.value} {response.status.phrase}')
        return response


def main():
    # CLI parser setup
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', type=str, default='127.0.0.1', help='IP del servidor')
    parser.add_argument('port', type=int, default=8080, help='Puerto del servidor')
    parser.add_argument('--dir', type=Path, default=os.getcwd(), help='Selecciona un directorio a servir. Por defecto usa el CWD')
    parser.add_argument('--log', type=str, default='debug', choices=['debug', 'info', 'warn', 'error', 'critical'], help='Configura el nivel de logging de stdout')
    parser.add_argument('--logfile', type=Path, default='web_dnd.log', help='Configura el archivo de log')
    args = parser.parse_args()

    # Logger setup
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    numeric_level = getattr(logging, args.log.upper(), None)

    log_stdout = logging.StreamHandler(sys.stdout)
    log_stdout.setLevel(numeric_level)
    log_stdout.setFormatter(formatter)

    log_file = logging.FileHandler(args.logfile, encoding='utf-8')
    log_file.setLevel(logging.DEBUG)
    log_file.setFormatter(formatter)

    logger = logging.getLogger('web_dnd')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(log_stdout)
    logger.addHandler(log_file)

    # HttpServer creation
    try:
        server = HttpServer(args.ip, args.port, args.dir.resolve())
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    logging.shutdown()


if __name__ == '__main__':
    main()
