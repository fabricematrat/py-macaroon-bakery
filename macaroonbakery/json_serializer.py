# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import base64
import json
import utils

from pymacaroons.utils import convert_to_bytes
from pymacaroons.macaroon import Macaroon
from pymacaroons.caveat import Caveat


class JsonSerializer(object):
    def serialize(self, macaroon):
        serialized = {
            'identifier': macaroon.identifier,
            'signature': macaroon.signature
        }
        if macaroon.location:
            serialized['location'] = macaroon.location
        if macaroon.caveats:
            serialized['caveats'] = [
                to_dict(caveat) for caveat in macaroon.caveats]

        return json.dumps(serialized)

    def deserialize(self, serialized):
        caveats = []
        deserialized = json.loads(serialized)

        for c in deserialized['caveats']:
            caveat = Caveat(
                caveat_id=c['cid'],
                verification_key_id=(
                    raw_b64decode(c['vid']) if c.get('vid') else None
                ),
                location=(
                    c['cl'] if c.get('cl') else None
                )
            )
            caveats.append(caveat)

        return Macaroon(
            location=deserialized['location'],
            identifier=deserialized['identifier'],
            caveats=caveats,
            signature=deserialized['signature']
        )


def raw_b64decode(s):
    return base64.urlsafe_b64decode(utils.add_padding(convert_to_bytes(s)))


def to_dict(c):
    serialized = {}
    if len(c.caveat_id) > 0:
        serialized['cid'] = c.caveat_id
    if c.verification_key_id:
        serialized['vid'] = base64.urlsafe_b64encode(
            c.verification_key_id).decode('ascii')
    if c.location:
        serialized['cl'] = c.location
    return serialized
