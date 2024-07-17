import base64
import hashlib
import secrets


class PasswordHasher:
    def __init__(self, config):
        self.salt_size = config["security"]["salt_size"]
        self.n = config["security"]["n"]
        self.r = config["security"]["r"]
        self.p = config["security"]["p"]
        self.dklen = config["security"]["dklen"]
        self.maxmem = 64 * 1024 * 1024  # 64 MiB

    def compute_hash(self, password):
        """
        Returns a cryptographic hash of the given password using a random salt.

        Format:

        ```
        N$R$P$SALT$HASH
        ```
        """

        salt = self.get_random_id()

        hash = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt.encode("ascii"),
            n=self.n,
            r=self.r,
            p=self.p,
            maxmem=self.maxmem,
            dklen=self.dklen,
        )

        hash_b64 = base64.b64encode(hash).decode("ascii")
        return f"{self.n}${self.r}${self.p}${salt}${hash_b64}"

    def check_password(self, hash, password):
        """
        Recomputes the hash for the given password to see if it matches.
        It must be in the format specified by `compute_hash`.
        :returns: `True` if the password is correct
        """

        n, r, p, salt_hex, password_hash = hash.split("$")

        salt_bin = salt_hex.encode("ascii")
        password_hash_bin = base64.b64decode(password_hash.encode("ascii"))

        n = int(n)
        r = int(r)
        p = int(p)

        recomputed_hash = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt_bin,
            n=n,
            r=r,
            p=p,
            maxmem=self.maxmem,
            dklen=len(password_hash_bin),
        )

        # FIXME?: secrets.compare_digest()
        return recomputed_hash == password_hash_bin

    def get_random_id(self):
        """Returns a cryptographically secure random number"""
        return secrets.token_urlsafe(self.salt_size)
