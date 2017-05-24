# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import base64
import json
import six
from nacl.public import Box, PublicKey
from nacl.encoding import Base64Encoder

import bakery
import macaroon


def encode_caveat(condition, root_key, third_party_info, key, ns):
    ''' Encrypts a third-party caveat with the given condtion
    and root key. The thirdPartyInfo key holds information about the
    third party we're encrypting the caveat for; the key is the
    public/private key pair of the party that's adding the caveat.

    The caveat will be encoded according to the version information
    found in thirdPartyInfo.

    @param condition:
    @param root_key:
    @param third_party_info:
    @param key:
    @param ns:
    @return:
    '''
    if third_party_info.version == bakery.BAKERY_V1:
        return _encode_caveat_v1(condition, root_key,
                                 third_party_info.public_key, key)

    raise NotImplemented('bakery v1 support only')


def _encode_caveat_v1(condition, root_key, third_party_pub_key, key):
    ''' encodeCaveatV1 creates a JSON-encoded third-party caveat
    with the given condtion and root key. The thirdPartyPubKey key
    represents the public key of the third party we're encrypting
    the caveat for; the key is the public/private key pair of the party
    that's adding the caveat.

    @param condition:
    @param root_key:
    @param third_party_pub_key:
    @param key:
    @return:
    '''
    plain_data = json.dumps(
        {'RootKey': base64.b64encode(root_key).decode('ascii'),
         'Condition': condition})
    box = Box(key, third_party_pub_key)

    encrypted = box.encrypt(six.b(plain_data))
    nonce = encrypted[0:Box.NONCE_SIZE]
    encrypted = encrypted[Box.NONCE_SIZE:]
    return base64.b64encode(six.b(json.dumps({
        'ThirdPartyPublicKey': third_party_pub_key.encode(
            Base64Encoder).decode('ascii'),
        'FirstPartyPublicKey': key.public_key.encode(
            Base64Encoder).decode('ascii'),
        'Nonce': base64.b64encode(nonce).decode('ascii'),
        'Id': base64.b64encode(encrypted).decode('ascii')
    })))


def decode_caveat(key, caveat):
    ''' decodeCaveat attempts to decode caveat by decrypting the encrypted part
    using key.
    '''
    if len(caveat) == 0:
        raise ValueError('empty third party caveat')

    first = caveat[0]
    if first == 'e':
        return _decode_caveat_v1(key, caveat)
    raise NotImplemented('only bakery v1 supported')


def _decode_caveat_v1(key, caveat):
    ''' decodeCaveatV1 attempts to decode a base64 encoded JSON id. This
    encoding is nominally version -1.

    @param key:
    @param caveat:
    @return:
    '''

    data = base64.b64decode(caveat).decode('utf-8')
    wrapper = json.loads(data)
    tp_public_key = PublicKey(base64.b64decode(wrapper['ThirdPartyPublicKey']))
    if key.public_key != tp_public_key:
        raise Exception('public key mismatch')  # TODO

    if wrapper.get('FirstPartyPublicKey', None) is None:
        raise Exception('target service public key not specified')

    # The encrypted string is base64 encoded in the JSON representation.
    secret = base64.b64decode(wrapper.get('Id'))
    nonce = base64.b64decode(wrapper.get('Nonce'))

    fp_public_key = PublicKey(base64.b64decode(
        wrapper.get('FirstPartyPublicKey')))

    box = Box(key, fp_public_key)
    c = box.decrypt(secret, nonce)
    record = json.loads(c.decode('utf-8'))
    fp_key = PublicKey(base64.b64decode(wrapper.get('FirstPartyPublicKey')))
    return macaroon.ThirdPartyCaveatInfo(
        record.get('Condition'),
        bytes(fp_key),
        bytes(key),
        base64.b64decode(record.get('RootKey')),
        caveat,
        bakery.BAKERY_V1)
