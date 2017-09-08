# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import nacl.public


class PrivateKey(object):
    def __init__(self, key):
        self._key = key

    @property
    def key(self):
        return self._key

    @property
    def public_key(self):
        return PublicKey(self._key.public_key)

    def encode(self, raw=False):
        if raw:
            return self._key.encode()
        return self._key.encode(nacl.encoding.Base64Encoder)

    def __eq__(self, other):
        return self.key == other.key


class PublicKey(object):
    def __init__(self, key):
        self._key = key

    @property
    def key(self):
        return self._key

    def encode(self, raw=False):
        if raw:
            return self._key.encode()
        return self._key.encode(nacl.encoding.Base64Encoder)

    def __eq__(self, other):
        return self.key == other.key


def generate_key():
    '''GenerateKey generates a new key pair.
    :return: a nacl.public.PrivateKey
    '''
    return PrivateKey(nacl.public.PrivateKey.generate())
