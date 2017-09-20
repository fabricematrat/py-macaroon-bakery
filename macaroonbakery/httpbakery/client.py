# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.
import abc
import base64
from collections import namedtuple
import json
import requests

from six.moves.http_cookies import SimpleCookie
from six.moves.http_cookiejar import Cookie
from six.moves.urllib.parse import urljoin
from six.moves.urllib.parse import urlparse

from pymacaroons import Macaroon
from pymacaroons.serializers.json_serializer import JsonSerializer

from macaroonbakery.bakery import discharge_all
from macaroonbakery import utils

MAX_DISCHARGE_RETRIES = 3


class BakeryAuth:
    ''' BakeryAuth holds the context for making HTTP requests with macaroons.

        This will automatically acquire and discharge macaroons around the
        requests framework.
        Usage:
            from macaroonbakery import httpbakery
            jar = requests.cookies.RequestsCookieJar()
            resp = requests.get('some protected url',
                                cookies=jar,
                                auth=httpbakery.BakeryAuth(cookies=jar))
            resp.raise_for_status()
    '''
    def __init__(self, interaction_methods=None, key=None,
                 cookies=requests.cookies.RequestsCookieJar()):
        '''

        @param interaction_methods holds a list of supported interaction
        (Interactor) methods, with preferred methods earlier in the list.
        On receiving an interaction-required error when discharging,
        the kind method of each Interactor in turn will be called
        and, if the error indicates that the interaction kind is supported,
        the interact method will be called to complete the discharge.
        @param key holds the client's private nacl key. If set, the client
        will try to discharge third party caveats with the special location
        "local" by using this key.
        @param cookies storage for the cookies {CookieJar}. It should be the
        same than in the requests cookies
        '''
        if interaction_methods is None:
            interaction_methods = [httpbakery.WebBrowserInteractor()]
        self._interaction_methods = interaction_methods
        self._jar = cookies
        self._key = key

    def __call__(self, req):
        req.headers[macaroonbakery.BAKERY_PROTOCOL_HEADER] = '{}'.format(
            macaroonbakery.BAKERY_LATEST_VERSION)
        hook = _prepare_discharge_hook(req.copy(), self._jar,
                                       self._interaction_methods)
        req.register_hook(event='response', hook=hook)
        return req


class Interactor(object):
    '''Represents a way of persuading a discharger that it should grant a
    discharge macaroon.
    '''
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def kind(self):
        '''Returns the interaction method name. This corresponds to the
        key in the InteractionMethods type.
        @return string
        '''
        raise NotImplementedError('kind method must be defined in '
                                  'subclass')

    def interact(self, ctx, client, location, interactionRequiredErr):
        '''
        // Interact performs the interaction, and returns a token that can be
        // used to acquire the discharge macaroon. The location provides
        // the third party caveat location to make it possible to use
        // relative URLs.
        //
        // If the given interaction isn't supported by the client for
        // the given location, it may return an error with an
        // ErrInteractionMethodNotFound cause which will cause the
        // interactor to be ignored that time.

        :param client:
        :param location:
        :param interactionRequiredErr:
        :return:
        '''
        raise NotImplementedError('authorize method must be defined in '
                                  'subclass')


class DischargeToken(namedtuple('DischargeToken', 'kind, value')):
    '''  Holds a token that is intended to persuade a discharger to discharge
    a third party caveat.

    @param kind holds the kind of the token. By convention this
    matches the name of the interaction method used to
    obtain the token, but that's not required.
    @param value holds the value of the token.
    '''


class LegacyInteractor(object):
    ''' May optionally be implemented by Interactor implementations
    that implement the legacy interaction-required error protocols.
    '''
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def legacy_interact(self, ctx, client, location, visitURL):
        ''' Implements the "visit" half of a legacy discharge
        interaction. The "wait" half will be implemented by httpbakery.
        The location is the location specified by the third party
        caveat.
        '''
        raise NotImplementedError('legacy_interact method must be defined in '
                                  'subclass')


def _prepare_discharge_hook(req, key, jar, interaction_methods):
    ''' Return the hook function (called when the response is received.)

    This allows us to intercept the response and do any necessary
    macaroon discharge before returning.
    '''
    class Retry:
        # Define a local class so that we can use its class variable as
        # mutable state accessed by the closures below.
        count = 0

    def hook(response, *args, **kwargs):
        ''' Requests hooks system, this is the hook for the response.
        '''
        status_code = response.status_code
        if status_code != 407 and status_code != 401:
            return response

        if (response.status_code == 401 and
                    response.headers.get('WWW-Authenticate') != 'Macaroon'):
            return response

        if response.headers.get('Content-Type') != 'application/json':
            return response

        error = response.json()
        if error.get('Code') != httpbakery.ERR_DISCHARGE_REQUIRED:
            return response
        Retry.count += 1
        if Retry.count > MAX_DISCHARGE_RETRIES:
            raise BakeryException('too many discharges')
        info = error.get('Info')
        if not isinstance(info, dict):
            raise BakeryException(
                'unable to read info in discharge error response')
        serialized_macaroon = info.get('Macaroon')
        if not isinstance(serialized_macaroon, dict):
            raise BakeryException(
                'unable to read macaroon in discharge error response')
        macaroon = macaroonbakery.Macaroon.deserialize(serialized_macaroon)
        ctx = macaroonbakery.AuthContext()
        discharges = macaroonbakery.discharge_all(ctx,
                                                  macaroon,
                                                  acquire_discharge,
                                                  key)
        encoded_discharges = map(utils.serialize_macaroon_string, discharges)

        macaroons = '[' + ','.join(encoded_discharges) + ']'
        all_macaroons = base64.urlsafe_b64encode(
            macaroons.encode('utf-8')).decode('ascii')

        full_path = urljoin(response.url,
                            info['MacaroonPath'])
        parsed_url = urlparse(full_path)
        if info and info.get('CookieNameSuffix'):
            name = 'macaroon-' + info['CookieNameSuffix']
        else:
            name = 'macaroon-' + discharges[0].signature
        cookie = Cookie(
            version=0,
            name=name,
            value=all_macaroons,
            port=None,
            port_specified=False,
            domain=parsed_url[1],
            domain_specified=True,
            domain_initial_dot=False,
            path=parsed_url[2],
            path_specified=True,
            secure=False,
            expires=None,
            discard=False,
            comment=None,
            comment_url=None,
            rest=None,
            rfc2109=False)
        jar.set_cookie(cookie)
        # Replace the private _cookies from req as it is a copy of
        # the original cookie jar passed into the requests method and we need
        # to set the cookie for this request.
        req._cookies = jar
        req.headers.pop('Cookie', None)
        req.prepare_cookies(req._cookies)
        req.headers['Bakery-Protocol-Version'] = '1'
        with requests.Session() as s:
            return s.send(req)
    return hook


class BakeryException(requests.RequestException):
    ''' Bakery exception '''


def extract_macaroons(headers):
    ''' Returns an array of any macaroons found in the given slice of cookies.
    @param headers: dict of headers
    @return: An array of array of mpy macaroons
    '''
    cookie_string = "\n".join(headers.get_all('Cookie', failobj=[]))
    cs = SimpleCookie()
    cs.load(cookie_string)
    mss = []
    for c in cs:
        if not c.startswith('macaroon-'):
            continue
        data = base64.b64decode(cs[c].value)
        data_as_objs = json.loads(data.decode('utf-8'))
        ms = [Macaroon.deserialize(json.dumps(x), serializer=JsonSerializer())
              for x in data_as_objs]
        mss.append(ms)
    return mss
