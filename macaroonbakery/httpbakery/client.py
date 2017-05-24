# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import base64
try:
    from cookielib import Cookie, CookieJar         # Python 2
except ImportError:
    from http.cookiejar import Cookie, CookieJar    # Python 3  # NOQA
import requests
try:
    from urlparse import urlparse                   # Python 2
    from urlparse import urljoin                   # Python 2
except ImportError:
    # from urllib.parse import urlparse               # Python 3  # NOQA
    from urllib.parse import urlparse               # Python 3  # NOQA
    from urllib.parse import urljoin               # Python 3  # NOQA
import webbrowser

from macaroonbakery.bakery import discharge_all
from macaroonbakery import utils

ERR_INTERACTION_REQUIRED = 'interaction required'
ERR_DISCHARGE_REQUIRED = 'macaroon discharge required'
TIME_OUT = 30
MAX_DISCHARGE_RETRIES = 3


class BakeryAuth:
    ''' BakeryAuth holds the context for making HTTP requests
        that automatically acquire and discharge macaroons around the requests
        framework.
        Usage:
            from macaroonbakery import httpbakery
            jar = requests.cookies.RequestsCookieJar()
            resp = requests.get('some protected url',
                                auth=httpbakery.BakeryAuth(cookies=jar))
            resp.raise_for_status()
    '''
    def __init__(self, visit_page=None, key=None, cookies=None):
        '''

        @param visit_page: holds a Visitor that is called when the
        discharge process requires further interaction.
        @param key: holds the client's key. If set, the client will try to
        discharge third party caveats with the special location "local" by
        using this key.
        @param cookies: storage for the cookies, that will or contains a cookie
        for a given URL on the given cookie jar that will holds the macaroon
        slice.
        '''
        if visit_page is None:
            visit_page = _visit_page_with_browser
        if cookies is None:
            cookies = requests.cookies.RequestsCookieJar()
        if 'agent-login' in cookies.keys():
            self._visit_page = _visit_page_for_agent(cookies, key)
        else:
            self._visit_page = visit_page
        self._jar = cookies
        self._key = key

    def __call__(self, req):
        req.headers['Bakery-Protocol-Version'] = '1'
        hook = _prepare_discharge_hook(req.copy(), self._key, self._jar,
                                       self._visit_page)
        req.register_hook(event='response', hook=hook)
        return req


def _prepare_discharge_hook(req, key, jar, visit_page):

    class Retry:
        count = 0

    def hook(response, *args, **kwargs):
        b1 = (response.status_code == 401
              and response.headers.get('WWW-Authenticate', '') == 'Macaroon')
        if not b1 and response.status_code != 407:
            return response
        if response.headers.get('Content-Type', '') != 'application/json':
            return response

        try:
            error = response.json()
        except:
            raise BakeryException(
                'unable to read the response discharge error')
        if error.get('Code', '') != ERR_DISCHARGE_REQUIRED:
            return response
        Retry.count += 1
        if Retry.count > MAX_DISCHARGE_RETRIES:
            raise BakeryException('too many discharges')
        info = error.get('Info', None)
        if not isinstance(info, dict):
            raise BakeryException(
                'unable to read info in the response discharge error')
        serialized_macaroon = info.get('Macaroon', None)
        if not isinstance(serialized_macaroon, dict):
            raise BakeryException(
                'unable to get the macaroon from the response discharge error')

        macaroon = utils.deserialize(serialized_macaroon)
        discharges = discharge_all(macaroon, visit_page, jar, key)
        encoded_discharges = map(utils.serialize_macaroon_string, discharges)

        a = "[" + ",".join(encoded_discharges) + "]"
        all_macaroons = base64.urlsafe_b64encode(
            a.encode('utf-8')).decode('ascii')

        full_path = urljoin(response.url,
                            error['Info']['MacaroonPath'])
        parsed_url = urlparse(full_path)
        c = Cookie(
            version=0,
            name='macaroon-' + error['Info']['CookieNameSuffix'],
            value=all_macaroons, port=None, port_specified=False,
            domain=parsed_url[1], domain_specified=True,
            domain_initial_dot=False, path=parsed_url[2],
            path_specified=True, secure=False,
            expires=None, discard=False, comment=None, comment_url=None,
            rest=None, rfc2109=False)
        jar.set_cookie(c)
        # Replace the internal cookie jar as it is a copy of the original
        # passed in
        req._cookies = jar
        req.headers.pop('Cookie', None)
        req.prepare_cookies(req._cookies)
        req.headers['Bakery-Protocol-Version'] = '1'
        with requests.Session() as s:
            return s.send(req)
    return hook


class BakeryException(requests.RequestException):
    ''' Bakery exception '''


def _visit_page_with_browser(visit_url):
    # Open a browser so the user can validate its identity.
    webbrowser.open(visit_url, new=1)


def _visit_page_for_agent(cookies, key):
    def visit_page_for_agent(visit_url):
        resp = requests.get(visit_url, cookies=cookies,
                            auth=BakeryAuth(cookies=cookies, key=key))
        resp.raise_for_status()
    return visit_page_for_agent
