import json
import logging
import mimetypes
import socket
import traceback
import sqlite3
import re

from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlparse, unquote

from http_msg import HttpRequest, HttpResponse
from database import Database


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


class HttpServer:
    def __init__(self, config):
        mimetypes.init()

        # NOTE: these are read-only, no need for locks
        self._log = logging.getLogger('web_dnd')  # This is thread safe
        self._ip = config['ip']
        self._port = config['port']
        self._working_dir = Path(config['serve_path']).resolve()
        self._routing = config['routing']['paths']

        self._db = Database(config)

        # Preload default responses
        # 404
        self._not_found_response = HttpResponse.from_file(
            HTTPStatus.NOT_FOUND,
            get_filepath(config['routing']['not_found'], self._working_dir)
        ).to_bytes()

        # 500
        self._server_error_response = HttpResponse.from_file(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            get_filepath(config['routing']['server_error'], self._working_dir)
        ).to_bytes()

    def serve_forever(self):
        # Socket creation
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Allow reusing the same IP and port between executions
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
           # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

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

                except FileNotFoundError as e:
                    self._log.info(f'{address[0]} -- {request.method} {request.url} -- Not found: {e}')
                    connection_socket.sendall(self._not_found_response)

                except Exception as e:
                    # Log any unhandled exception
                    exception_msg = ''.join(traceback.format_exception(e))
                    self._log.critical(f'Unhandled exception in thread -- {e}\n{exception_msg}')

                    connection_socket.sendall(self._server_error_response)

    def do_GET(self, request, address):
        # All the GET requests will return the required file
        # TODO: Do not always send HTML. Should check for the 'accept' header

        # URL decode and parse
        decoded_url = unquote(request.url)
        parsed_url = urlparse(decoded_url)

        # Test if the cookies are working
        if parsed_url.path == '/' and 'cookie' in request and 'SID' in request['cookie']:
            with self._db.get_handle() as db:
                if db.check_session_id(request['cookie']['SID']):
                    return HttpResponse.from_str(HTTPStatus.OK, 'You made it!')

        # Apply routing if avaliable
        if parsed_url.path in self._routing:
            requested_file = self._routing[parsed_url.path]
        else:
            requested_file = parsed_url.path

        # Safely get its filepath
        filepath = get_filepath(requested_file, self._working_dir)

        # Return the response
        response = HttpResponse.from_file(HTTPStatus.OK, filepath)
        self._log.info(f'{address[0]} -- GET {request.url} -- OK')
        return response

    def do_POST(self, request, address):
        match request.url:
            case '/api/signup':
                try:
                    request_json = json.loads(request.body)

                    # Check the required parameters
                    if 'password' not in request_json or 'username' not in request_json:
                        return HttpResponse.from_json(HTTPStatus.BAD_REQUEST, {
                            'error': 'Malformed request',
                            'description': 'La petición debe tener los campos "username" y "password"'
                        })

                    # TODO: check username and password format
                    #The following characters are not allowed:
                    #: ; < = > ? _ ` ~
                    #Also other characters that you would usually think they won`t work (something in the caliber of 'ඞ')
                    if (re.search("^[\x20-\x39 \x40-\x5E \x61-\x7D áéíóúÁÉÍÓÚ]", request_json['username'])
                    or re.search("^[\x20-\x39 \x40-\x5E \x61-\x7D áéíóúÁÉÍÓÚ]", request_json['password'])):
                        return HttpResponse.from_json(HTTPStatus.BAD_REQUEST, {
                            'error': 'Malformed request',
                            'description': 'El nombre de usuario o contraseña contienen caracteres inválidos'
                        })


                    with self._db.get_handle() as db:
                        session_id = db.signup(request_json['username'], request_json['password'])

                        # TODO: Remove this when deploying to production
                        self._log.debug(f'Credentials -- "{request_json['username']}" :: "{request_json['password']}"')
                        self._log.info(f'"{address[0]}" -- Create user "{request_json['username']}" -- OK')

                        response = HttpResponse(HTTPStatus.OK)
                        response['set-cookie'] = f'SID={session_id}; SameSite=Strict; HttpOnly; Path=/; Max-Age={24 * 60 * 60}'
                        response['content-length'] = 0
                        return response

                except sqlite3.IntegrityError:
                    self._log.info(f'"{address[0]}" -- Create user "{request_json['username']}" -- Already exists')
                    return HttpResponse.from_json(HTTPStatus.BAD_REQUEST, {
                        'error': 'Already exists',
                        'description': f'El nombre de usuario "{request_json['username']}" ya existe'
                    })

            # TODO: solve cookie session problems:
            #   - Session/Cookie hijacking
            #   - Cross-site request forgery
            case '/api/login':
                request_json = json.loads(request.body)

                # Check the required parameters
                if 'password' not in request_json or 'username' not in request_json:
                    return HttpResponse.from_json(HTTPStatus.BAD_REQUEST, {
                        'error': 'Malformed request',
                        'description': 'La petición debe tener los campos "username" y "password"'
                    })

                # TODO: check username and password format

                with self._db.get_handle() as db:
                    session_id = db.login(request_json['username'], request_json['password'])

                    if session_id is not None:
                        # Loging successful
                        self._log.info(f'"{address[0]}" -- Login user "{request_json['username']}" -- OK')
                        response = HttpResponse(HTTPStatus.OK)
                        response['set-cookie'] = f'SID={session_id}; SameSite=Strict; HttpOnly; Path=/; Max-Age={24 * 60 * 60}'
                        response['content-length'] = 0
                        return response

                    else:
                        # Loggin failed
                        self._log.info(f'"{address[0]}" -- Login user "{request_json['username']}" -- Failed')
                        return HttpResponse.from_json(HTTPStatus.UNAUTHORIZED, {
                            'error': 'Unauthorized',
                            'description': 'El usuario o la constraseña son incorrectos'
                        })

            case other:
                raise FileNotFoundError(f'"{other}" invalid POST URL')
