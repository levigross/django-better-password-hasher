import hashlib

from django.utils.crypto import pbkdf2
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.conf import settings


class BetterPasswordHasher(PBKDF2PasswordHasher):
    iterations = 100000
    algorithm = "pbkdf2_sha512"
    digest = hashlib.sha512

    def encode(self, password, salt, iterations=None):
        assert password
        assert salt and '$' not in salt
        if not iterations:
            iterations = self.iterations
        hash = pbkdf2(password, salt+settings.SECRET_KEY, iterations, digest=self.digest)
        hash = hash.encode('base64').strip()
        return "%s$%d$%s$%s" % (self.algorithm, iterations, salt, hash)

