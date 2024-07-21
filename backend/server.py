import json
import logging
import mimetypes
import re
import socket
import sqlite3
import sys
import traceback

from concurrent.futures import ThreadPoolExecutor
from http import HTTPMethod, HTTPStatus
from pathlib import Path
from typing import NoReturn

from database import Database
from http_msg import HttpRequest, HttpResponse
from templates import TemplateEngine, filepath_from_url


class HttpServer:
    def __init__(self, config: dict) -> None:
        """Sets up the server with the given configuration"""
        mimetypes.init()

        # These are read-only, no need for locks
        self._log = logging.getLogger("web_dnd")  # This is thread safe
        self._ip: str = config["ip"]
        self._port: int = config["port"]
        self._working_dir = Path(config["serve_path"]).absolute().resolve()
        self._routing: dict[str, str] = config["routing"]["paths"]
        self._session_max_age: int = config["security"]["session_max_age"]

        self._db = Database(config)
        self._tem_engine = TemplateEngine(self._working_dir)

        # Preload default responses
        # 404
        self._not_found_response = HttpResponse.from_template(
            HTTPStatus.NOT_FOUND,
            self._working_dir / "error.html",
            self._tem_engine,
            error=True,
        ).to_bytes()

        # 500
        self._server_error_response = HttpResponse.from_template(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            self._working_dir / "error.html",
            self._tem_engine,
            error=True,
        ).to_bytes()

    def serve_forever(self) -> NoReturn:
        """
        Server main function.
        Receives connections from the client and schedule them in a thread.
        """

        # Socket creation
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Allow reusing the same IP and port between executions
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sys.platform != "windows":
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            # Bind the socket to the given IP and listen for connections
            server_socket.bind((self._ip, self._port))
            server_socket.listen()

            match self._ip:
                case "":
                    repr_ip = "0.0.0.0"
                case "<broadcast>":
                    repr_ip = "255.255.255.255"
                case ip:
                    repr_ip = ip

            self._log.info(
                f"Server running on {self._working_dir}: http://{repr_ip}:{self._port}/"
            )

            # Handle requests in parallel
            # TODO: Cannot close the server if there is still pending connections
            with ThreadPoolExecutor() as thp:
                while True:
                    connection_socket, address = server_socket.accept()
                    thp.submit(self.thread_handle_request, connection_socket, address)

    def thread_handle_request(
        self, connection_socket: socket.socket, address: tuple[str, int]
    ) -> None:
        """Main function of each server thread to handle a petition."""

        self._log.info(f"Accept {address[0]}:{address[1]}")
        with connection_socket:

            # Handle petitions until the connection is closed
            # TODO: Maybe handle this request and then quit, so the thread can
            # be used for more than one connection. This will solve the previous
            # TODO. But, how to handle the socket?

            while True:
                try:
                    # FIXME: Problems with the path /AAA<repeats 1024 times>
                    data = connection_socket.recv(1024)

                    if not data:
                        self._log.info(f"End connection {address[0]}:{address[1]}")
                        break

                    request = HttpRequest.from_bytes(data)
                    match request.method:
                        case HTTPMethod.GET:
                            response = self.do_GET(request, address)

                        case HTTPMethod.POST:
                            response = self.do_POST(request, address)

                        case other:
                            raise ValueError(f'Got unreachable method: "{other.value}"')
                    connection_socket.sendall(response.to_bytes())

                    # TODO: Connection: close
                    # TODO: HttpFormatError -- 400 Bad Request
                    # TODO: Database error
                    # TODO: Check accept header to send JSON or HTML

                except FileNotFoundError as e:
                    self._log.info(
                        f"{address[0]} -- {request.method} {request.url.path} -- Not found: {e}"  # pyright: ignore
                    )
                    connection_socket.sendall(self._not_found_response)

                except Exception as e:
                    # Log any unhandled exception
                    exception_msg = "".join(traceback.format_exception(e))
                    self._log.critical(
                        f"Unhandled exception in thread -- {e}\n{exception_msg}"
                    )

                    connection_socket.sendall(self._server_error_response)

    def is_authenticated(self, request: HttpRequest) -> bool:
        """:returns: `True` if the request is properly authenticated"""
        session_id = request.cookie("SID")
        if session_id is not None:
            with self._db.get_handle() as db:
                return db.check_session_id(session_id)

        return False

    def do_GET(self, request: HttpRequest, address: tuple[str, int]) -> HttpResponse:
        """Handles GET requests.
        Mainly returns a file to the client, but also delegates the API to
        `do_GET_API`.
        """

        url = request.url.path

        # Apply routing if possible
        if url in self._routing:
            url = self._routing[url]

        filepath = None
        if self.is_authenticated(request):

            # Delegate the API to another method
            api_response = self.do_GET_API(url, request, address)
            if api_response is not None:
                return api_response

            try:
                # Try to fetch that file from the private resources
                filepath = filepath_from_url(url, self._working_dir / "private")

            except FileNotFoundError:
                pass

        # If autentication failed or the file was not found, try in the public
        # resources.
        if filepath is None:
            filepath = filepath_from_url(url, self._working_dir)

        # Return the requested file.
        # Only try the templates if the file is HTML
        if filepath.suffix == ".html":
            response = HttpResponse.from_template_or_file(
                HTTPStatus.OK, filepath, self._tem_engine
            )
        else:
            response = HttpResponse.from_file(HTTPStatus.OK, filepath)

        self._log.info(f"{address[0]} -- GET {request.url.path} -- OK")
        return response

    def do_GET_API(
        self, url: str, request: HttpRequest, address: tuple[str, int]
    ) -> HttpResponse | None:
        """Handle GET API calls.
        **Precondition**: the request must be authenticated before calling this
        function.
        """

        match url:
            case "/api/campaigns":
                with self._db.get_handle() as db:
                    return HttpResponse.from_json(
                        HTTPStatus.OK,
                        {"campaigns": db.get_campaigns(request.cookie("SID"))},
                    )

            case "/api/characters":
                with self._db.get_handle() as db:
                    return HttpResponse.from_json(
                        HTTPStatus.OK,
                        {"characters": db.get_characters(request.cookie("SID"))},
                    )

            case _:
                return None

    def do_POST(self, request: HttpRequest, address: tuple[str, int]) -> HttpResponse:
        """
        Handle POST petitions (mainly API).
        :raise FileNotFoundError: If the URL is invalid.
        """

        match request.url.path:
            case "/api/signup":
                try:
                    if request.body is None:
                        return HttpResponse.from_json(
                            HTTPStatus.BAD_REQUEST,
                            {
                                "error": "Malformed request",
                                "description": 'La petición debe tener los campos "username" y "password"',
                            },
                        )

                    request_json = json.loads(request.body)

                    # Check the required parameters
                    if "password" not in request_json or "username" not in request_json:
                        return HttpResponse.from_json(
                            HTTPStatus.BAD_REQUEST,
                            {
                                "error": "Malformed request",
                                "description": 'La petición debe tener los campos "username" y "password"',
                            },
                        )

                    # Check username and password format
                    if (
                        # Valid characters for username: A-Z a-z 0-9 and _
                        re.search(r"\w{3,15}", request_json["username"]) is None
                        # Valid characters for passwords: extended ascii but for
                        # control characters
                        or re.search(
                            r"[\x20-\x7E\x80-\xFF]{12,}", request_json["password"]
                        )
                        is None
                    ):
                        return HttpResponse.from_json(
                            HTTPStatus.BAD_REQUEST,
                            {
                                "error": "Invalid data",
                                "description": "El nombre de usuario caracteres inválidos",
                            },
                        )

                    with self._db.get_handle() as db:
                        session_id = db.signup(
                            request_json["username"], request_json["password"]
                        )

                        # TODO: Remove this when deploying to production
                        self._log.debug(
                            f'Credentials -- "{request_json['username']}" :: "{request_json['password']}"'
                        )
                        self._log.info(
                            f'"{address[0]}" -- Create user "{request_json['username']}" -- OK'
                        )

                        response = HttpResponse(HTTPStatus.OK)
                        response["set-cookie"] = (
                            f"SID={session_id}; SameSite=Strict; HttpOnly; Path=/; Max-Age={self._session_max_age}"
                        )
                        response["content-length"] = 0
                        return response

                except sqlite3.IntegrityError:
                    self._log.info(
                        f'"{address[0]}" -- Create user "{request_json['username']}" -- Already exists'
                    )
                    return HttpResponse.from_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "error": "Already exists",
                            "description": f'El nombre de usuario "{request_json['username']}" ya existe',
                        },
                    )

            # TODO: solve cookie session problems:
            #   - Session/Cookie hijacking
            #   - Cross-site request forgery
            case "/api/login":
                if request.body is None:
                    return HttpResponse.from_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "error": "Malformed request",
                            "description": 'La petición debe tener los campos "username" y "password"',
                        },
                    )

                request_json = json.loads(request.body)

                # Check the required parameters
                if "password" not in request_json or "username" not in request_json:
                    return HttpResponse.from_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "error": "Malformed request",
                            "description": 'La petición debe tener los campos "username" y "password"',
                        },
                    )

                with self._db.get_handle() as db:
                    session_id = db.login(
                        request_json["username"], request_json["password"]
                    )

                    if session_id is not None:
                        # Loging successful
                        self._log.info(
                            f'"{address[0]}" -- Login user "{request_json['username']}" -- OK'
                        )
                        response = HttpResponse(HTTPStatus.OK)
                        response["set-cookie"] = (
                            f"SID={session_id}; SameSite=Strict; HttpOnly; Path=/; Max-Age={self._session_max_age}"
                        )
                        response["content-length"] = 0
                        return response

                    else:
                        # Loggin failed
                        self._log.info(
                            f'"{address[0]}" -- Login user "{request_json['username']}" -- Failed'
                        )
                        return HttpResponse.from_json(
                            HTTPStatus.UNAUTHORIZED,
                            {
                                "error": "Unauthorized",
                                "description": "El usuario o la constraseña son incorrectos",
                            },
                        )

            case other:
                raise FileNotFoundError(f'"{other}" invalid POST URL')
