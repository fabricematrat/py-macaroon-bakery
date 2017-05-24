# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.
from unittest import TestCase

try:
    from cookielib import Cookie, CookieJar         # Python 2
except ImportError:
    from http.cookiejar import Cookie, CookieJar    # Python 3  # NOQA
import requests
import json
import base64
import nacl

from macaroonbakery import httpbakery


class TestBakery(TestCase):
    def test_discharge(self):
        jar = requests.cookies.RequestsCookieJar()
        resp = requests.get('https://api.jujucharms.com/charmstore/v5/'
                            '~fabricematrat/trusty/wordpress-0'
                            '/archive/config.yaml',
                            auth=httpbakery.BakeryAuth(cookies=jar))
        resp.raise_for_status()
        assert 'macaroon-authn' in jar.keys()
        resp = requests.get('https://api.jujucharms.com/charmstore/v5/'
                            '~fabricematrat/trusty/wordpress-0'
                            '/archive/config.yaml',
                            cookies=jar,
                            auth=httpbakery.BakeryAuth(cookies=jar))
        resp.raise_for_status()
        print (resp.text)
        assert False, "I mean for this to fail"

    def test_discharge_with_agent(self):
        jar = requests.cookies.RequestsCookieJar()
        c = Cookie(0, 'agent-login',
                   base64.urlsafe_b64encode(json.dumps(
                       {'username': 'test-create-charge@admin@idm',
                        'public_key':
                            'IpyN3NnQf3Xx6B+Ak7wCNkpD76JnjgUGhZ9cvxfwhHo='
                        }).encode('ascii')).decode('ascii'),
                   None, False, 'api.staging.jujucharms.com',
                   True, False, '/identity/', True, False, None, False,
                   None, None, None, False)

        jar.set_cookie(c)
        key = nacl.public.PrivateKey(
            base64.b64decode('A1WViDFn25Ti4XLKw8T1AOeuP+EcD0Gs01BYEvdzZxo='))
        key.public_key = nacl.public.PublicKey(
            base64.b64decode('IpyN3NnQf3Xx6B+Ak7wCNkpD76JnjgUGhZ9cvxfwhHo='))

        resp = requests.get(
            'https://api.staging.jujucharms.com/charmstore/v5/~fabricematrat/'
            'trusty/wordpress-0/archive/config.yaml',
            auth=httpbakery.BakeryAuth(cookies=jar, key=key))
        resp.raise_for_status()
        print (resp.text)
        assert False, "I mean for this to fail"
