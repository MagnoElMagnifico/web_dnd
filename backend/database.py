import sqlite3


class Database:
    def __init__(self, config):
        self.db_file = config['database']['filepath']

        # Check if the database is empty
        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()
        result = cursor.execute(
            '''\
            select count(*)
            from sqlite_master
            where type = 'table'
            ''').fetchone()
        connection.commit()

        # In that case, execute the creation script
        if int(result[0]) == 0 and 'creation_script' in config['database']:
            with open(config['database']['creation_script'], 'r') as f:
                cursor.executescript(f.read())
                connection.commit()

        connection.close()

    def get_handle(self):
        # SQLite is thread safe, but the module is not
        # It is required to create a new connection for every thread.
        return DatabaseHandle(self.db_file)


class DatabaseHandle:
    def __init__(self, db_file):
        self.db_file = db_file

    def __enter__(self):
        self.connection = sqlite3.connect(self.db_file)
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.connection.close()

    def signup(self, user_name, password_hash, session_id):
        self.cursor.execute(
            '''\
            insert into users (user_name, passwd_hash, session_id) values (?, ?, ?);
            ''',
            (user_name, password_hash, session_id,))
        self.connection.commit()

    def check_session_id(self, session_id):
        result = self.cursor.execute(
            '''\
            select count(*)
            from users
            where session_id = ?;
            ''',
            (session_id,)).fetchone()
        self.connection.commit()

        return int(result[0]) == 1

    def get_user_data(self, user_name):
        result = self.cursor.execute(
            '''\
            select user_name, passwd_hash, session_id
            from users
            where user_name = ?
            ''',
            (user_name,)).fetchone()
        self.connection.commit()
        return result

    def login(self, user_name, session_id):
        # TODO: This might be a security problem. This function logs a user
        # without checking the password.
        # Maybe the Database class should have the PasswordHasher.
        self.cursor.execute(
            '''\
            update users
            set session_id = ?
            where user_name = ?
            ''',
            (session_id, user_name,))
        self.connection.commit()
