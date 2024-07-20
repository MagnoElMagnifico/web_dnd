import sqlite3
import security

from typing import Self


class DatabaseHandle:
    def __init__(self, db_file: str, hasher: security.PasswordHasher) -> None:
        self.db_file = db_file
        self.hasher = hasher

    def __enter__(self) -> Self:
        self.connection = sqlite3.connect(self.db_file)
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb) -> None:
        self.connection.close()

    def check_session_id(self, session_id: str) -> bool:
        """:return: `True` if the given `session_id` is valid"""

        result = self.cursor.execute(
            """\
            select count(*)
            from users
            where session_id = ?;
            """,
            (session_id,),
        ).fetchone()

        self.connection.commit()

        return int(result[0]) == 1

    def signup(self, user_name: str, password: str) -> str:
        """
        Creates a new user in the database.

        :param user_name: username of the new user.
        :param password: the password of the new user. This will be hashed with
        a random salt value for security (see `security` module).
        :return: the `session_id` for the new user.
        :raises sqlite3.IntegrityError: if the username already exists.
        """
        password_hash = self.hasher.compute_hash(password)
        session_id = self.hasher.get_random_id()

        # Throws sqlite3.IntegrityError (UNIQUE constraint) when user_name
        # already exists.
        self.cursor.execute(
            """\
            insert into users (user_name, passwd_hash, session_id) values (?, ?, ?);
            """,
            (
                user_name,
                password_hash,
                session_id,
            ),
        )

        self.connection.commit()
        return session_id

    def login(self, user_name: str, password: str) -> str | None:
        """
        Checks if the password matchs the user. In that case returns a new
        `session_id`, otherwise `None`.
        """

        password_hash = self.cursor.execute(
            """\
            select passwd_hash
            from users
            where user_name = ?
            """,
            (user_name,),
        ).fetchone()

        # If the query does not return any rows, the user does not exist.
        if password_hash is None:
            return None

        password_hash = password_hash[0]

        # If the passwords do not match, exit.
        if not self.hasher.check_password(password_hash, password):
            return None

        # Otherwise, login the user by creating a session_id
        session_id = self.hasher.get_random_id()

        # Add the session id to the database
        self.cursor.execute(
            """\
            update users
            set session_id = ?
            where user_name = ?
            """,
            (
                session_id,
                user_name,
            ),
        )

        self.connection.commit()
        return session_id

    def get_campaigns(self, session_id: str) -> list[str]:
        result = self.cursor.execute(
            """
            select campaign_name
            from campaigns
                 join users on campaigns.dm = users.user_name
            where users.session_id = ?
            order by campaign_name desc;
            """,
            (session_id,),
        ).fetchall()

        return [e[0] for e in result]

    def get_characters(self, session_id: str) -> list[str]:
        result = self.cursor.execute(
            """
            select character_name
            from character_owners
                 join users on character_owners.user_name = users.user_name
            where users.session_id = ?
            order by character_name desc;
            """,
            (session_id,),
        ).fetchall()

        return [e[0] for e in result]


class Database:
    def __init__(self, config: dict) -> None:
        """
        Create the database if it does not exist.

        Required config fields:
        - `config['database']['filepath']` Filepath of the database
        - Other fields required by the securityPasswordHasher class
        """

        self.db_file = config["database"]["filepath"]
        self.hasher = security.PasswordHasher(config)

        # Check if the database is empty
        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()
        result = cursor.execute(
            """\
            select count(*)
            from sqlite_master
            where type = 'table'
            """
        ).fetchone()
        connection.commit()

        # In that case, execute the creation script
        if int(result[0]) == 0 and "creation_script" in config["database"]:
            with open(config["database"]["creation_script"], "r") as f:
                cursor.executescript(f.read())
                connection.commit()

        connection.close()

    def get_handle(self) -> DatabaseHandle:
        """
        SQLite is thread safe, but the Python module may be not. It is required
        to create a new connection to the datase for every
        thread.

        So use this method to create a new object to handle the database
        connection and cursor.
        """
        return DatabaseHandle(self.db_file, self.hasher)
