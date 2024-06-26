import json
import logging
import mimetypes
import socket
import traceback
import re
import sqlite3

from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlparse, unquote

from security import PasswordHasher, get_random_id
from database import Database

''' Defines the HTTP message types (Request and Response) and the HttpServer class '''


class HttpError(Exception):
    ''' Base class exception for all the errors in the web server '''


class HttpFormatError(HttpError):
    '''
    The format of the HTTP message is invalid.
    If this exception is thrown, the server must return 400 Bad Request and
    close the connection.
    '''


def get_filepath(path, working_dir):
    assert isinstance(working_dir, Path), 'working_dir must be a pathlib.Path'

    # If the requested path is not a Path object, try to create one
    if not isinstance(path, Path):
        path = Path(str(path))

    # The / operator will not work if path starts with '/'
    try:
        path = path.relative_to('/')
    except ValueError:
        # If this exception is thrown, it means it is not relative to '/', so it
        # does not start with '/'
        pass

    requested_file = (working_dir / path).resolve()

    if not requested_file.exists() or requested_file.is_dir():
        raise FileNotFoundError(f'"{requested_file}" could not be found')

    # Avoid Directory Path Traversal
    if working_dir not in requested_file.parents:
        raise FileNotFoundError(f'"{requested_file}" is not under "{working_dir}"')

    return requested_file


class HttpRequest:
    def __init__(self, method, url, version, headers, body):
        assert isinstance(method, str), 'Method must be a string'
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

    def __contains__(self, key):
        assert isinstance(key, str), 'Key must be a string'
        return key in self._headers

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

    # Regex inicialization for request parsing
    accept_header_re = re.compile(r'([A-z0-9/*+-]+)\s*;?\s*q?=?(\d\.\d{1,3})?')

    # https://www.rfc-editor.org/rfc/rfc2616.html#section-2.2
    # https://httpwg.org/specs/rfc6265.html#sane-set-cookie-syntax
    cookie_header_re = re.compile(r'([^\x00-\x1F()<>@,;:\\\"/\[\]?={} \t]+)\s*=\s*\"?([\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*)\"?')

    @classmethod
    def from_bytes(cls, msg):
        assert isinstance(msg, bytes) and len(msg) > 0, 'msg must be a not-empty byte sequence'
        msg_str = msg.decode('ascii')

        # Iterate line by line, but keep the line endings
        line_iter = iter(msg_str.splitlines(keepends=True))

        # In order to figure out the body, let's count the bytes of all the
        # headers. This will be the offset.
        header_size = 0

        # Ignore first empty lines
        request_line = next(line_iter)
        header_size += len(request_line)
        while request_line.strip() == '':
            request_line = next(line_iter)
            header_size += len(request_line)

        # Process start line: method, url and version
        request_line_fields = request_line.split(' ')

        if len(request_line_fields) != 3:
            raise HttpFormatError(f'Expected 3 fields, got {len(request_line_fields)}: "{request_line}"')

        method, url, version = [e.strip() for e in request_line_fields]
        # The rest must be headers and body
        headers = {}
        body = None

        try:
            header_line = next(line_iter)
            header_size += len(header_line)

            while header_line.strip() != '':  # Iter until empty line
                header, value_str = [e.strip() for e in header_line.split(':', 1)]
                header = header.lower()

                match header:
                    case 'cookie':
                        value = {e[0]: e[1] for e in cls.cookie_header_re.findall(value_str)}

                    case 'accept':
                        # print(value_str, cls.accept_header_re.findall(value_str))
                        value = value_str

                    case _:
                        value = value_str

                headers[header.lower()] = value

                header_line = next(line_iter)
                header_size += len(header_line)

            if 'content-length' in headers:
                body = msg_str[header_size:header_size + int(headers['content-length'])]
            else:
                body = msg_str[header_size:]

        except StopIteration:
            pass

        return cls(method, url, version, headers, body)

    def __str__(self):
        request = f'{self._method} {self._url} {self._version}\r\n'
        request += ''.join([f'{header}: {value}\r\n' for header, value in self._headers.items()])
        if self._body:
            request += f'\r\n{self._body}'
        return request


# TODO: change API: create function to easilly create responses from file and JSON
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

        mt = mimetypes.guess_type(filepath)
        content_type = mt[0] if mt[0] else 'text/plain'
        charset      = mt[1] if mt[1] else 'utf-8'
        self._headers['content-type'] = f'{content_type}; charset={charset}'

    def body_from_json(self, json_body):
        assert isinstance(json_body, dict), 'json_body must be a dict'
        self.add_body(json.dumps(json_body).encode('utf-8'))
        self._headers['content-type'] = 'application/json; charset=utf-8'

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
    def __init__(self, config):
        mimetypes.init()

        # NOTE: these are read-only, no need for locks
        self._log = logging.getLogger('web_dnd')  # This is thread safe
        self._ip = config['ip']
        self._port = config['port']
        self._working_dir = Path(config['serve_path']).resolve()
        self._routing = config['routing']['paths']

        self._hasher = PasswordHasher(config)
        self._db = Database(config)

        # Preload default responses
        # 404
        not_found = HttpResponse('HTTP/1.1', HTTPStatus.NOT_FOUND)
        not_found.body_from_file(get_filepath(config['routing']['not_found'], self._working_dir))
        self._not_found_response = not_found.to_bytes()

        # 500
        server_error = HttpResponse('HTTP/1.1', HTTPStatus.INTERNAL_SERVER_ERROR)
        server_error.body_from_file(get_filepath(config['routing']['server_error'], self._working_dir))
        self._server_error_response = server_error.to_bytes()

    def serve_forever(self):
        # Socket creation
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Allow reusing the same IP and port between executions
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            # Bind the socket to the given IP and listen for connections
            server_socket.bind((self._ip, self._port))
            server_socket.listen()

            match self._ip:
                case '':
                    repr_ip = '0.0.0.0'
                case '<broadcast>':
                    repr_ip = '255.255.255.255'
                case ip:
                    repr_ip = ip

            self._log.info(f'Server running on {self._working_dir}: http://{repr_ip}:{self._port}/')

            # Handle requests in parallel
            # FIXME?: cannot close the server if there is still pending connections
            with ThreadPoolExecutor() as thp:
                while True:
                    connection_socket, address = server_socket.accept()
                    thp.submit(self.thread_handle_request, connection_socket, address)

    def thread_handle_request(self, connection_socket, address):
        self._log.info(f'Accept {address[0]}:{address[1]}')

        with connection_socket:
            # Handle petitions until the connection is closed
            # TODO: Maybe handle this request and then quit, so the thread can
            # be used for more than one connection. This will solve the previous
            # FIXME. But, how to handle the socket?
            while True:
                try:
                    # FIXME: problems with the path /AAA<repeats 1024 times>
                    data = connection_socket.recv(1024)

                    if not data:
                        self._log.info(f'End connection {address[0]}:{address[1]}')
                        break

                    request = HttpRequest.from_bytes(data)

                    match request.method:
                        case 'GET':
                            response = self.do_GET(request, address)

                        case 'POST':
                            response = self.do_POST(request, address)

                        case other:
                            raise NotImplementedError(f'Handle unsupported method: "{other}"')

                    connection_socket.sendall(response.to_bytes())

                    # TODO: Connection: close
                    # TODO: HttpFormatError -- 400 Bad Request
                    # TODO: Do not always send HTML. Should check for the 'accept' header

                except FileNotFoundError as e:
                    self._log.error(f'{e}')
                    connection_socket.sendall(self._not_found_response)

                except Exception as e:
                    # Log any unhandled exception
                    exception_msg = ''.join(traceback.format_exception(e))
                    self._log.critical(f'Unhandled exception in thread -- {e}\n{exception_msg}')

                    connection_socket.sendall(self._server_error_response)

    def do_GET(self, request, address):
        # All the GET requests will return the required file
        # TODO: check for 'accept' header

        # URL decode and parse
        decoded_url = unquote(request.url)
        parsed_url = urlparse(decoded_url)

        # Test if the cookies are working
        if parsed_url.path == '/' and 'cookie' in request and 'SID' in request['cookie']:
            with self._db.get_handle() as db:
                if db.check_session_id(request['cookie']['SID']):
                    response = HttpResponse('HTTP/1.1', HTTPStatus.OK)
                    content = b'''You made it!'''
                    response.add_body(content)
                    response['content-type'] = 'text/plain; charset=utf-8'
                    response['content-length'] = len(content)
                    return response

        # Apply routing if avaliable
        if parsed_url.path in self._routing:
            requested_file = self._routing[parsed_url.path]
        else:
            requested_file = parsed_url.path

        # Safely get its filepath
        filepath = get_filepath(requested_file, self._working_dir)

        # Return the response
        response = HttpResponse('HTTP/1.1', HTTPStatus.OK)
        response.body_from_file(filepath)
        self._log.info(f'{address[0]} -- {request.method} {request.url} -- {response.status.value} {response.status.phrase}')
        return response

    def do_POST(self, request, address):
        # if 'application/json' not in request['accept']:
        #     return

        match request.url:
            case '/api/signup':
                try:
                    request_json = json.loads(request.body)

                    # Check the required parameters
                    if 'password' not in request_json or 'username' not in request_json:
                        response = HttpResponse('HTTP/1.1', HTTPStatus.BAD_REQUEST)
                        response.body_from_json({
                            'error': 'Malformed request',
                            'description': 'La petición debe tener los campos "username" y "password"'
                        })
                        return response

                    # TODO: check username and password format

                    password_hash = self._hasher.compute_hash(request_json['password'])
                    session_id = get_random_id()

                    with self._db.get_handle() as db:
                        db.signup(request_json['username'], password_hash, session_id)

                        # TODO: Remove this when deploying to production
                        self._log.debug(f'Credentials -- "{request_json['username']}" :: "{request_json['password']}"')

                    self._log.info(f'"{address[0]}" -- Create user "{request_json['username']}" -- OK')
                    response = HttpResponse('HTTP/1.1', HTTPStatus.OK)
                    response['set-cookie'] = f'SID={session_id}; SameSite=Strict; HttpOnly; Path=/; Max-Age={24 * 60 * 60}'
                    response['content-length'] = 0
                    return response

                except sqlite3.IntegrityError:
                    self._log.info(f'"{address[0]}" -- Create user "{request_json['username']}" -- Already exists')
                    response = HttpResponse('HTTP/1.1', HTTPStatus.BAD_REQUEST)
                    response.body_from_json({
                        'error': 'Already exists',
                        'description': f'El nombre de usuario "{request_json['username']}" ya existe'
                    })
                    return response

            # TODO: solve cookie session problems:
            #   - Session/Cookie hijacking
            #   - Cross-site request forgery
            case '/api/login':
                request_json = json.loads(request.body)

                # Check the required parameters
                if 'password' not in request_json or 'username' not in request_json:
                    response = HttpResponse('HTTP/1.1', HTTPStatus.BAD_REQUEST)
                    response.body_from_json({
                        'error': 'Malformed request',
                        'description': 'La petición debe tener los campos "username" y "password"'
                    })
                    return response

                # TODO: check username and password format

                with self._db.get_handle() as db:
                    user_data = db.get_user_data(request_json['username'])

                    if user_data is None:
                        self._log.info(f'"{address[0]}" -- Login user "{request_json['username']}" -- Failed: user does not exist')
                        response = HttpResponse('HTTP/1.1', HTTPStatus.UNAUTHORIZED)
                        response.body_from_json({
                            'error': 'Unauthorized',
                            'description': 'El usuario o la constraseña son incorrectos'
                        })
                        return response

                    _, password_hash, session_id = user_data

                    if session_id is not None:
                        self._log.warn(f'{address[0]} -- The user "{request_json['username']}" tried to log in while having a SID set')

                    if self._hasher.check_password(password_hash, request_json['password']):
                        session_id = get_random_id()
                        db.login(request_json['username'], session_id)

                        self._log.info(f'"{address[0]}" -- Login user "{request_json['username']}" -- OK')
                        response = HttpResponse('HTTP/1.1', HTTPStatus.OK)
                        response['set-cookie'] = f'SID={session_id}; SameSite=Strict; HttpOnly; Path=/; Max-Age={24 * 60 * 60}'
                        response['content-length'] = 0
                        return response

                    else:
                        self._log.info(f'"{address[0]}" -- Login user "{request_json['username']}" -- Failed: wrong password')
                        response = HttpResponse('HTTP/1.1', HTTPStatus.UNAUTHORIZED)
                        response.body_from_json({
                            'error': 'Unauthorized',
                            'description': 'El usuario o la constraseña son incorrectos'
                        })
                        return response
