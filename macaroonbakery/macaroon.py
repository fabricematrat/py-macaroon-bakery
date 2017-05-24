# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

import base64
import copy
import os

import bakery
import codec
import pymacaroons

MACAROON_V1 = 1
MACAROON_V2 = 2


class Macaroon:
    ''' Macaroon represents an undischarged macaroon along its first
    party caveat namespace and associated third party caveat information
    which should be passed to the third party when discharging a caveat.
    '''
    def __init__(self, root_key, id, location=None,
                 version=bakery.LATEST_BAKERY_VERSION, ns=None):
        ''' Creates a new macaroon with the given root key, id and location.
        If the version is more than the latest known version,
        the latest known version will be used. The namespace is that
        of the service creating it.
        @param root_key:
        @param id:
        @param location:
        @param version: the bakery version.
        @param ns:
        '''
        if version > bakery.LATEST_BAKERY_VERSION:
            version = bakery.LATEST_BAKERY_VERSION
        # m holds the underlying macaroon.
        self.m = pymacaroons.Macaroon(location=location, key=root_key,
                                      identifier=id)
        # version holds the version of the macaroon.
        self.version = version
        self.caveat_data = {}

    def add_caveat(self, cav, key=None, loc=None):
        ''' Returns a new macaroon with the given caveat.
        It encrypts it using the given key pair
        and by looking up the location using the given locator.
        As a special case, if the caveat's Location field has the prefix
        "local " the caveat is added as a client self-discharge caveat using
        the public key base64-encoded in the rest of the location. In this
        case, the Condition field must be empty. The resulting third-party
        caveat will encode the condition "true" encrypted with that public
        key.

        @param cav: the caveat to be added.
        @param key: the key to encrypt third party caveat.
        @param loc: locator to find the location.
        @return: a new macaroon object with the given caveat.
        '''
        if cav.location is None:
            m = self.m.add_first_party_caveat(cav.condition)
            new_macaroon = copy.copy(self)
            new_macaroon.m = m
            return new_macaroon
        if key is None:
            raise ValueError(
                'no private key to encrypt third party caveat')
        local_info, ok = parse_local_location(cav.location)
        if ok:
            info = local_info
            cav.location = 'local'
            if cav.condition is not '':
                raise ValueError(
                    "cannot specify caveat condition in "
                    "local third-party caveat")
            cav.condition = "true"
        else:
            if loc is None:
                raise ValueError(
                    'no locator when adding third party caveat')
            info = loc.third_party_info(cav.location)
        root_key = os.urandom(24)
        # Use the least supported version to encode the caveat.
        if self.version < info.version:
            info.version = self.version

        caveat_info = codec.encode_caveat(cav.condition, root_key, info,
                                          key, None)
        if info.version < bakery.BAKERY_V3:
            # We're encoding for an earlier client or third party which does
            # not understand bundled caveat info, so use the encoded
            # caveat information as the caveat id.
            id = caveat_info
        else:
            id = self._new_caveat_id(self.caveat_id_prefix)
            self.caveat_data[id] = caveat_info

        m = self.m.add_third_party_caveat(cav.location, root_key, id)
        new_macaroon = copy.copy(self)
        new_macaroon.m = m
        return new_macaroon

    def add_caveats(self, cavs, key, loc):
        ''' Convenience method that calls m.add_caveat for each
        caveat in cavs.

        @param cavs: arrary of caveats.
        @param key: the key to encrypt third party caveat.
        @param loc: locator to find the location.
        @return: a new macaroon object with the given caveats.
        '''
        m = self
        for cav in cavs:
            m = m.add_caveat(cav, key, loc)
        return m

    def serialize(self):
        ''' Returns a dictionary holding the macaroon data
        in V1 JSON format. Note that this differs from
        the underlying macaroon serialize method as
        it does not return a string. This makes it easier
        to incorporate the macaroon into other JSON
        objects.

        @return: a dictionary holding the macaroon data
        in V1 JSON format
        '''
        if self.version == bakery.BAKERY_V1:
            # latest libmacaroons do not support the old format
            m_j = self.m.serialize('json')
            val = {
                'identifier': _field_v2(m_j, 'i'),
                'signature': _field_v2(m_j, 's'),
            }
            location = m_j.get('l')
            if location is not None:
                val['location'] = location
            cavs = m_j.get('c')
            if cavs is not None:
                val['caveats'] = map(cavs, _cav_v2_to_v1)
            return val
        raise NotImplemented('only bakery v1 suppported')

    def _new_caveat_id(self, base):
        ''' Returns a third party caveat id that
        does not duplicate any third party caveat ids already inside
        macaroon.
        If base is non-empty, it is used as the id prefix.
        @param base:
        @return:
        '''
        # Add a version byte to the caveat id. Technically
        # this is unnecessary as the caveat-decoding logic
        # that looks at versions should never see this id,
        # but if the caveat payload isn't provided with the
        # payload, having this version gives a strong indication
        # that the payload has been omitted so we can produce
        # a better error for the user.
        id = bakery.BAKERY_V1
        return id

    def first_party_caveats(self):
        ''' Returns the first party caveats from this macaroon.

        @return: the first party caveats from this macaroon.
        '''
        return self.m.first_party_caveats()

    def third_party_caveats(self):
        ''' Returns the third party caveats.

        @return: the third party caveats.
        '''
        return self.m.third_party_caveats()


def macaroon_version(bakery_version):
    ''' macaroon_version returns the macaroon version that should
    be used with the given bakery Version.

    @param bakery_version: the bakery version
    @return: macaroon_version the derived macaroon version
    '''
    if bakery_version in [bakery.BAKERY_V0, bakery.BAKERY_V1]:
        return MACAROON_V1
    return MACAROON_V2


def parse_local_location(loc):
    '''
    parseLocalLocation parses a local caveat location as generated by
    LocalThirdPartyCaveat. This is of the form:

        local <version> <pubkey>

    where <version> is the bakery version of the client that we're
    adding the local caveat for.

    It returns false if the location does not represent a local
    caveat location.
    @return: a tuple of location and if the location is local.
    '''
    if not(loc.startswith('local ')):
        return (), False
    v = bakery.BAKERY_V1
    fields = loc.splits()
    fields = fields[1:]  # Skip 'local'
    if len(fields) == 2:
        try:
            v = int(fields[0])
        except ValueError:
            return (), False
        fields = fields[1:]
    if len(fields) == 1:
        return (base64.b64decode(fields[0]), v), True
    return (), False


class ThirdPartyLocator:
    ''' ThirdPartyInfo returns information on the third
        party at the given location. It returns None if no match is found.
    '''
    def __init__(self):
        self._store = {}

    def third_party_info(self, loc):
        return self._store.get(loc, None)

    def add_info(self, loc, info):
        self._store[loc.rstrip('\\')] = info


class ThirdPartyCaveatInfo:
    '''ThirdPartyCaveatInfo holds the information decoded from
    a third party caveat id.
    '''
    def __init__(self, condition, first_party_public_key, third_party_key_pair,
                 root_key, caveat, version):
        '''
        @param condition: holds the third party condition to be discharged.
        This is the only field that most third party dischargers will
        need to consider.
        @param first_party_public_key: 	holds the public key of the party
        that created the third party caveat.
        @param third_party_key_pair: holds the key pair used to decrypt
        the caveat - the key pair of the discharging service.
        @param root_key: holds the secret root key encoded by the caveat.
        @param caveat: holds the full encoded caveat id from which all
        the other fields are derived.
        @param version: holds the version that was used to encode
        the caveat id.
        '''
        self.condition = condition,
        self.first_party_public_key = first_party_public_key,
        self.third_party_key_pair = third_party_key_pair,
        self.root_key = root_key,
        self.caveat = caveat,
        self.version = version,

    def __eq__(self, other):
        if self.condition != other.condition:
            return False
        if self.first_party_public_key != other.first_party_public_key:
            return False
        if self.third_party_key_pair != other.third_party_key_pair:
            return False
        if self.caveat != other.caveat:
            return False
        if self.version != other.version:
            return False
        return True


def _field_v2(dict, field):
    val = dict.get(field)
    if val is None:
        return base64.b64decode(dict.get(field + '64'))
    return val


def _cav_v2_to_v1(cav):
    val = {
        'cid': _field_v2(cav, 'i'),
        'vid': _field_v2(cav, 'v')
    }
    location = cav.get('l')
    if location is not None:
        val['cl'] = location
    return val
