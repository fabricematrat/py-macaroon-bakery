# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import json
import six

from pymacaroons import Macaroon

from macaroonbakery import json_serializer


def deserialize(json_macaroon):
    '''Deserialize a JSON macaroon into a macaroon object from pymacaroons.
        @param the JSON macaroon to deserialize as a dict.
        @return the deserialized macaroon object.
    '''
    return Macaroon.deserialize(json.dumps(json_macaroon),
                                json_serializer.JsonSerializer())


def serialize_macaroon_string(macaroon):
    '''Serialize macaroon object to string.

    @param macaroon object to be serialized.
    @return a string serialization form of the macaroon.
    '''
    return macaroon.serialize(json_serializer.JsonSerializer())


def add_padding(s):
    '''Add padding to base64 encoded string
    pymacaroons does not give padded base64 string from serialization.

    @param string s to be padded.
    @return a padded string.
    '''
    return s + six.b('=') * ((4 - (len(s) % 4)) % 4)
