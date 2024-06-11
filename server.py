import argparse
import logging
import socket
import sys
from pathlib import Path
from http import HTTPStatus


class HttpRequest:
    def __init__(self, method, url, version, headers, body):
        assert method in ['GET', 'POST']
        assert isinstance(url, str)
        assert isinstance(version, str)
        assert isinstance(body, str | None)
        assert isinstance(headers, dict)

        self._method = method
        self._url = url
        self._version = version
        self._body = body
        self._headers = headers

    def __getitem__(self, key):
        assert isinstance(key, str)
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
        assert isinstance(msg, str) and len(msg) > 0

        # Iterate line by line
        line_iter = iter(msg.splitlines())

        # Process first line: method, url and version
        first_line = next(line_iter)
        [method, url, version] = first_line.split(' ')

        # The rest must be headers and body
        headers = {}
        body = None

        try:
            line = next(line_iter)
            while line:  # Iter until empty line
                [header, value] = [e.strip() for e in line.split(':', 1)]
                headers[header.lower()] = value
                line = next(line_iter)

            # This line must be empty
            assert not line
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
        assert isinstance(version, str)
        assert isinstance(status, HTTPStatus)

        self._version = version
        self._status = status
        self._headers = {}
        self._body = None

    def __getitem__(self, key):
        assert isinstance(key, str)
        return self._headers[key]

    @property
    def status(self):
        return self._status

    @property
    def version(self):
        return self._version

    def __setitem__(self, key, value):
        assert isinstance(key, str)
        self._headers[key.lower()] = value

    def add_body(self):
        raise NotImplementedError()

    def body_from_file(self, file):
        raise NotImplementedError()

    def __str__(self):
        response = f'{self._version} {self._status.value} {self._status.phrase}\r\n'
        response += ''.join([f'{header}: {value}\r\n' for header, value in self._headers.items()])
        if self._body:
            response += f'\r\n{self._body}'
        return response


class HttpServer:
    def __init__(self, ip='', port=8080):
        self._ip = ip
        self._port = port

    def serve_forever(self):
        log = logging.getLogger('web_dnd')

        # Socket creation
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Bind the socket to the given IP. Panic if it was invalid.
            try:
                server_socket.bind((self._ip, self._port))
            except Exception as e:
                log.critical(e)
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

            log.info(f'Server running: http://{repr_ip}:{self._port}/')

            # TODO: threads
            while True:
                connection_socket, address = server_socket.accept()
                with connection_socket:
                    log.info(f'Connected by {address}')

                    # Handle petitions until the connection is closed
                    while True:
                        data = connection_socket.recv(1024)

                        if not data:
                            break

                        request = HttpRequest.from_str(data.decode('ascii'))
                        log.info(f'Received from client:\n{request}')

                        response = HttpResponse('HTTP/1.1', HTTPStatus.OK)
                        response['content-type'] = 'text/html; charset=UTF-8'
                        response._body = '''\
                            <html>
                                <head><title>Web DnD</title></head>
                                <body>
                                    <h1>Web Dnd</h1>
                                    <p>This is a test</p>
                                </body>
                            </html>
                            '''
                        response['content-length'] = len(response._body)
                        log.info(f'Response sent:\n{response}')
                        connection_socket.sendall(bytes(str(response), 'ascii'))


def main():
    # CLI parser setup
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', type=str, default='127.0.0.1', help='IP del servidor')
    parser.add_argument('port', type=int, default=8080, help='Puerto del servidor')
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
        server = HttpServer(args.ip, args.port)
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    logging.shutdown()


if __name__ == '__main__':
    main()
