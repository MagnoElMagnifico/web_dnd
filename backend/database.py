import sqlite3


class Database:
    def __init__(self, name, creation_script):
        connection = sqlite3.connect(name)
        self._cursor = connection.cursor()

        # Check if the database is empty
        result = self._cursor.execute(
            '''\
            select count(*)
            from sqlite_master
            where type = 'table'
            ''').fetchone()

        # In that case, execute the creation script
        if int(result[0]) == 0 and creation_script:
            with open(creation_script, 'r') as f:
                self._cursor.executescript(f.read())

    def close(self):
        self._cursor.close()
