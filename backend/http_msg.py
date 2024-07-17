import re
import json
import mimetypes
from http import HTTPStatus
from pathlib import Path

HTTP_VERSION = "HTTP/1.1"


class HttpError(Exception):
    """Base class exception for all the errors in the web server"""


class HttpFormatError(HttpError):
    """
    The format of the HTTP message is invalid.
    If this exception is thrown, the server must return 400 Bad Request and
    close the connection.
    """


class HttpRequest:
    # Regex inicialization for request parsing
    accept_header_re = re.compile(r"([A-z0-9/*+-]+)\s*;?\s*q?=?(\d\.\d{1,3})?")

    # https://www.rfc-editor.org/rfc/rfc2616.html#section-2.2
    # https://httpwg.org/specs/rfc6265.html#sane-set-cookie-syntax
    cookie_header_re = re.compile(
        r"([^\x00-\x1F()<>@,;:\\\"/\[\]?={} \t]+)\s*=\s*\"?([\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*)\"?"
    )

    @classmethod
    def from_bytes(cls, msg):
        assert (
            isinstance(msg, bytes) and len(msg) > 0
        ), "msg must be a not-empty byte sequence"
        msg_str = msg.decode("ascii")

        # Iterate line by line, but keep the line endings
        line_iter = iter(msg_str.splitlines(keepends=True))

        # In order to figure out the body, let's count the bytes of all the
        # headers. This will be the offset.
        header_size = 0

        # Ignore first empty lines
        request_line = next(line_iter)
        header_size += len(request_line)
        while request_line.strip() == "":
            request_line = next(line_iter)
            header_size += len(request_line)

        # Process start line: method, url and version
        request_line_fields = request_line.split(" ")

        if len(request_line_fields) != 3:
            raise HttpFormatError(
                f'Expected 3 fields, got {len(request_line_fields)}: "{request_line}"'
            )

        method, url, version = [e.strip() for e in request_line_fields]
        # The rest must be headers and body
        headers = {}
        body = None

        try:
            header_line = next(line_iter)
            header_size += len(header_line)

            while header_line.strip() != "":  # Iter until empty line
                header, value_str = [e.strip() for e in header_line.split(":", 1)]
                header = header.lower()

                match header:
                    case "cookie":
                        value = {
                            e[0]: e[1] for e in cls.cookie_header_re.findall(value_str)
                        }

                    case "accept":
                        # print(value_str, cls.accept_header_re.findall(value_str))
                        value = value_str

                    case _:
                        value = value_str

                headers[header.lower()] = value

                header_line = next(line_iter)
                header_size += len(header_line)

            if "content-length" in headers:
                body = msg_str[
                    header_size : header_size + int(headers["content-length"])
                ]
            else:
                body = msg_str[header_size:]

        except StopIteration:
            pass

        return cls(method, url, version, headers, body)

    def __init__(self, method, url, version, headers, body):
        assert isinstance(method, str), "Method must be a string"
        assert isinstance(url, str), "URL must be a string"
        assert isinstance(version, str), "version must be a string"
        assert isinstance(body, str | None), "body must be a string"
        assert isinstance(headers, dict), "headers must be a dictionary"

        if method not in ["GET", "POST"]:
            raise NotImplementedError(f"The method {method} is not supported")

        self._method = method
        self._url = url
        self._version = version
        self._body = body
        self._headers = headers

    def __getitem__(self, key):
        assert isinstance(key, str), "Key must be a string"
        return self._headers[key]

    def __contains__(self, key):
        assert isinstance(key, str), "Key must be a string"
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

    def __str__(self):
        request = f"{self._method} {self._url} {self._version}\r\n"
        request += "".join(
            [f"{header}: {value}\r\n" for header, value in self._headers.items()]
        )
        if self._body:
            request += f"\r\n{self._body}"
        return request


class HttpResponse:
    # TODO: add option to remove whitespace
    # minify_js = re.compile(r'\s{1,}|\n|//.*\n|/\*[\w\W]*\*/')

    @classmethod
    def from_file(cls, status, filepath):
        assert isinstance(filepath, Path), "filepath must be pathlib.Path"

        response = cls(status)
        response.add_body(filepath.read_bytes())

        # Guess the content type
        mt = mimetypes.guess_type(filepath)
        content_type = mt[0] if mt[0] else "text/plain"
        charset = mt[1] if mt[1] else "utf-8"
        response["content-type"] = f"{content_type}; charset={charset}"
        return response

    @classmethod
    def from_str(cls, status, str_body):
        assert isinstance(str_body, str), "str_body must be a string"

        response = cls(status)
        response.add_body(str_body.encode("utf-8"))
        response["content-type"] = "text/plain; charset=utf-8"
        return response

    @classmethod
    def from_json(cls, status, json_body):
        assert isinstance(json_body, dict), "json_body must be a dict"

        response = cls(status)
        response.add_body(json.dumps(json_body).encode("utf-8"))
        response["content-type"] = "application/json; charset=utf-8"
        return response

    def __init__(self, status):
        assert isinstance(status, HTTPStatus), "status must be http.HTTPStatus"

        self._status = status
        self._headers = {}
        self._body = None

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        assert isinstance(status, HTTPStatus), "status must be http.HTTPStatus"
        self._status = status

    def add_body(self, new_body):
        self._body = new_body
        self._headers["content-length"] = len(new_body)

    def __setitem__(self, key, value):
        assert isinstance(key, str), "key must be a string"
        self._headers[key.lower()] = value

    def __getitem__(self, key):
        assert isinstance(key, str), "key must be a string"
        return self._headers[key]

    def __str__(self):
        response = f"{HTTP_VERSION} {self._status.value} {self._status.phrase}\r\n"
        response += "".join(
            [f"{header}: {value}\r\n" for header, value in self._headers.items()]
        )
        if self._body:
            if isinstance(self._body, bytes):
                response += f"\r\n{self._body.decode('ascii')}"
            elif isinstance(self._body, str):
                response += f"\r\n{self._body}"

        return response

    def to_bytes(self):
        header = f"{HTTP_VERSION} {self._status.value} {self._status.phrase}\r\n"
        header += "".join(
            [f"{header}: {value}\r\n" for header, value in self._headers.items()]
        )
        header += "\r\n"

        response = bytearray(header, "ascii")

        if self._body:
            if isinstance(self._body, bytes):
                response += self._body
            elif isinstance(self._body, str):
                response += self._body.encode("ascii")

        return response
