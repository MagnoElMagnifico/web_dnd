import hashlib
import uuid
import base64


def get_random_id():
    # TODO: use the secrets module instead
    return uuid.uuid4().hex


class PasswordHasher:
    def __init__(self, config):
        self.n = config['security']['n']
        self.r = config['security']['r']
        self.p = config['security']['p']
        self.dklen = config['security']['dklen']
        self.maxmem = 64 * 1024 * 1024  # 64 MiB

    def compute_hash(self, password):
        salt = uuid.uuid4()

        hash = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt.bytes,
            n=self.n, r=self.r, p=self.p,
            maxmem=self.maxmem,
            dklen=self.dklen
        )

        hash_b64 = base64.b64encode(hash).decode('ascii')
        return f'{self.n}${self.r}${self.p}${salt.hex}${hash_b64}'

    def check_password(self, hash, password):
        n, r, p, salt_hex, password_hash = hash.split('$')

        salt_bin = bytes.fromhex(salt_hex)
        password_hash_bin = base64.b64decode(password_hash.encode('ascii'))

        n = int(n)
        r = int(r)
        p = int(p)

        recomputed_hash = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt_bin,
            n=n, r=r, p=p,
            maxmem=self.maxmem,
            dklen=len(password_hash_bin)
        )

        return recomputed_hash == password_hash_bin
