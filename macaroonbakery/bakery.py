# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import base64

try:
    from cookielib import Cookie, CookieJar  # Python 2
except ImportError:
    from http.cookiejar import Cookie, CookieJar  # Python 3  # NOQA
import json
import requests
import utils

import nacl.utils
from nacl.public import Box
from pymacaroons import Macaroon


ERR_INTERACTION_REQUIRED = 'interaction required'
ERR_DISCHARGE_REQUIRED = 'macaroon discharge required'
TIME_OUT = 30
DEFAULT_PROTOCOL_VERSION = {'Bakery-Protocol-Version': '1'}
MAX_DISCHARGE_RETRIES = 3

BAKERY_V0 = 0
BAKERY_V1 = 1
BAKERY_V2 = 2
BAKERY_V3 = 3
LATEST_BAKERY_VERSION = BAKERY_V1
NONCE_LEN = 24


class DischargeException(Exception):
    """A discharge error occurred."""


def discharge_all(macaroon, visit_page, jar, key=None):
    discharges = [macaroon]
    client = _Client(visit_page, jar)
    try:
        client.discharge_caveats(macaroon, discharges, macaroon, key)
    except Exception as exc:
        raise DischargeException('unable to discharge the macaroon', exc)
    return discharges


def discharge(key, id, caveat=None, checker=None, locator=None):
    if caveat is None:
        caveat = id
    cav_info = _decode_caveat(key, caveat)
    return Macaroon(location="", key=cav_info['RootKey'], identifier=id)


class _Client:
    def __init__(self, visit_page, jar):
        self._visit_page = visit_page
        self._jar = jar

    def discharge_caveats(self, macaroon, discharges,
                          primary_macaroon, key):
        '''Gathers discharge macaroons for all the third party caveats
           for the macaroon passed in.

        @param macaroon the macaroon to discharge.
        @param discharges the list of discharged macaroons.
        @param primary_macaroon used for signature of the discharge macaroon.
        '''
        caveats = macaroon.third_party_caveats()
        for caveat in caveats:
            location = caveat.location
            if key is not None and location == 'local':
                # if tuple is only 2 element otherwise TODO add caveat
                dm = discharge(key, id=caveat.caveat_id)
            else:
                dm = self._get_discharge(location, caveat.caveat_id)
            dm = primary_macaroon.prepare_for_request(dm)
            discharges.append(dm)
            self.discharge_caveats(dm, discharges, primary_macaroon, key)

    def _get_discharge(self, third_party_location, condition):
        ''' Get the discharge macaroon from the third party location.

        @param third_party_location where to get a discharge from.
        @param condition associated  to the discharged macaroon.
        @return a discharged macaroon.
        @raise DischargeError when an error occurs during the discharge
            process.
        '''
        headers = DEFAULT_PROTOCOL_VERSION
        payload = {'id': condition}

        response = requests.post(third_party_location + '/discharge',
                                 headers=headers,
                                 data=payload,
                                 # timeout=TIME_OUT, TODO: add a time out
                                 cookies=self._jar)
        status_code = response.status_code
        if status_code == 200:
            return _extract_macaroon_from_response(response)
        elif status_code == 401 and response.headers.get(
                'WWW-Authenticate',
                '') == 'Macaroon':
            error = response.json()
            if error.get('Code', '') != ERR_INTERACTION_REQUIRED:
                return DischargeException(
                    'unable to get code from discharge')
            visit_url, wait_url = _extract_urls(response)
            self._visit_page(visit_url)
            # Wait on the wait url and then get a macaroon if validated.
            return _acquire_macaroon_from_wait(wait_url)


def _decode_caveat(key, caveat):
    data = base64.b64decode(caveat).decode('utf-8')
    tpid = json.loads(data)
    third_party_public_key = nacl.public.PublicKey(
        base64.b64decode(tpid['ThirdPartyPublicKey']))
    if key.public_key != third_party_public_key:
        return 'some error'
    if tpid.get('FirstPartyPublicKey', None) is None:
        return 'target service public key not specified'
    # The encrypted string is base64 encoded in the JSON representation.
    secret = base64.b64decode(tpid['Id'])
    first_party_public_key = nacl.public.PublicKey(
        base64.b64decode(tpid['FirstPartyPublicKey']))
    box = Box(key,
              first_party_public_key)
    c = box.decrypt(secret, base64.b64decode(tpid['Nonce']))
    record = json.loads(c.decode('utf-8'))
    return {
        'Condition': record['Condition'],
        'FirstPartyPublicKey': first_party_public_key,
        'ThirdPartyKeyPair': key,
        'RootKey': base64.b64decode(record['RootKey']),
        'Caveat': caveat,
        'MacaroonId': id,
    }


def _extract_macaroon_from_response(response):
    ''' Extract the macaroon from a direct successful discharge.

    @param response from direct successful discharge.
    @return a macaroon object.
    @raises DischargeError if any error happens.
    '''
    response_json = response.json()
    return utils.deserialize(response_json['Macaroon'])


def _acquire_macaroon_from_wait(wait_url):
    ''' Wait that the user did validate its identity as the get will block
        until then.
        If validated then we get the macaroon from the wait endpoint
        response.

    @param wait_url the get url to call to get a macaroon.
    @return a macaroon object
    @raises DischargeError if any error happens.
    '''
    resp = requests.get(wait_url, headers=DEFAULT_PROTOCOL_VERSION)
    response_json = resp.json()
    macaroon = response_json['Macaroon']
    return utils.deserialize(macaroon)


def _extract_urls(response):
    ''' Return the visit and wait URL from response.

    @param response the response from the discharge endpoint.
    @return the visit and wait URL.
    @raises DischargeError for ant error during the process response.
    '''
    response_json = response.json()
    visit_url = response_json['Info']['VisitURL']
    wait_url = response_json['Info']['WaitURL']
    return visit_url, wait_url


class ThirdPartyInfo:
    def __init__(self, version, public_key):
        '''
        @param version: holds latest the bakery protocol version supported
        by the discharger.
        @param public_key: holds the public key of the third party.
        '''
        self.version = version
        self.public_key = public_key
