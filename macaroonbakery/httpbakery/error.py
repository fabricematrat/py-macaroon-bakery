# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.
import json

import macaroonbakery


def get_error(macaroon, path, cookie_suffix_name):
    ''' Get response content and headers from a discharge macaroons error.

    @param macaroon may hold a macaroon that, when discharged, may
    allow access to a service.
    @param path holds the URL path to be associated with the macaroon.
    The macaroon is potentially valid for all URLs under the given path.
    @param cookie_suffix_name holds the desired cookie name suffix to be
    associated with the macaroon. The actual name used will be
    ("macaroon-" + CookieName). Clients may ignore this field -
    older clients will always use ("macaroon-" + macaroon.signature() in hex)
    @return content and the headers to set on the response.
    '''
    content = json.dumps(
        {
            'Code': 'macaroon discharge required',
            'Message': 'discharge required',
            'Info': {
                'Macaroon': macaroon.to_dict(),
                'MacaroonPath': path,
                'CookieNameSuffix': cookie_suffix_name
            },
        }
    )
    return content, {
        'WWW-Authenticate': 'Macaroon',
        'Content-Type': 'application/json'
    }

BAKERY_PROTOCOL_HEADER = 'Bakery-Protocol-Version'


def request_version(req_headers):
    ''' Determines the bakery protocol version from a client request.
    If the protocol cannot be determined, or is invalid, the original version
    of the protocol is used. If a later version is found, the latest known
    version is used, which is OK because versions are backwardly compatible.

    @param req_headers: the request headers as a dict.
    @return: protocol version as an int.
    '''
    vs = req_headers.get(BAKERY_PROTOCOL_HEADER)
    if vs is None:
        # No header - use backward compatibility mode.
        return macaroonbakery.BAKERY_V1
    try:
        x = int(vs)
    except ValueError:
        # Badly formed header - use backward compatibility mode.
        return macaroonbakery.BAKERY_V1
    if x > macaroonbakery.LATEST_BAKERY_VERSION:
        # Later version than we know about - use the
        # latest version that we can.
        return macaroonbakery.LATEST_BAKERY_VERSION
    return x
