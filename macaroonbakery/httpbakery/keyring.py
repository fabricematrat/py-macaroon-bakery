# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

from six.moves.urllib.parse import urlparse

import nacl.public
import requests

import macaroonbakery


class ThirdPartyLocator(macaroonbakery.ThirdPartyLocator):
    ''' Implements macaroonbakery.ThirdPartyLocator by first looking in the
    backing cache and, if that fails, making an HTTP request to find the
    information associated with the given discharge location.
    '''

    def __init__(self, url, allow_insecure=False):
        '''
        @param url: the url to retrieve public_key
        @param allow_insecure: By default it refuses to use insecure URLs.
        '''
        self._allow_insecure = allow_insecure
        self._url = url.rstrip('/')
        self._cache = {}

    def third_party_info(self, loc):
        u = urlparse(loc)
        if u.scheme != 'https' and self._allow_insecure:
            raise macaroonbakery.ThirdPartyInfoNotFound(
                'untrusted discharge URL {}'.format(loc))
        loc = loc.rstrip('/')
        info = self._cache.get(loc)
        if info is not None:
            return info

        resp = requests.get(self._url + '/discharge/info')
        status_code = resp.status_code
        if status_code != 200:
            raise macaroonbakery.ThirdPartyInfoNotFound(
                'unable to get info from /discharge/info')
        json_resp = resp.json()
        if json_resp is None:
            raise macaroonbakery.ThirdPartyInfoNotFound(
                'no response from /discharge/info')
        pk = json_resp.get('PublicKey')
        if pk is None:
            raise macaroonbakery.ThirdPartyInfoNotFound(
                'no public key found in /discharge/info')
        idm_pk = nacl.public.PublicKey(pk,
                                       encoder=nacl.encoding.Base64Encoder)
        version = json_resp.get('Version')
        if version is None:
            version = macaroonbakery.BAKERY_V1
        self._cache[loc] = macaroonbakery.ThirdPartyInfo(
            version=version,
            public_key=macaroonbakery.PublicKey(idm_pk)
        )
        return self._cache.get(loc)
