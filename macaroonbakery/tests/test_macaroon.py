# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.

from unittest import TestCase

import nacl.utils
import base64

from macaroonbakery import bakery, macaroon, checkers, codec


class TestMacaroon(TestCase):
    def test_new_macaroon(self):
        m = macaroon.Macaroon(b'rootkey',
                              b'some id',
                              'here',
                              bakery.LATEST_BAKERY_VERSION)
        assert m is not None
        assert m.version == bakery.LATEST_BAKERY_VERSION
        assert m.m.identifier == "some id"
        assert m.m.location == "here"
        assert m.version == macaroon.macaroon_version(
            bakery.LATEST_BAKERY_VERSION)

    def test_add_first_party_caveat(self):
        m = macaroon.Macaroon('rootkey',
                              'some id',
                              'here',
                              bakery.LATEST_BAKERY_VERSION)
        m = m.add_caveat(checkers.Caveat("test_condition"))
        caveats = m.first_party_caveats()
        assert len(caveats) == 1
        assert caveats[0].caveat_id == "test_condition"

    def test_add_third_party_caveat(self):
        m = macaroon.Macaroon('rootkey',
                              'some id',
                              'here',
                              bakery.LATEST_BAKERY_VERSION)
        loc = macaroon.ThirdPartyLocator()
        fp_key = nacl.public.PrivateKey.generate()
        tp_key = nacl.public.PrivateKey.generate()

        loc.add_info("test_location",
                     bakery.ThirdPartyInfo(
                         bakery.BAKERY_V1,
                         tp_key.public_key))
        m = m.add_caveat(checkers.Caveat(condition="test_condition",
                                         location="test_location"),
                         fp_key, loc)

        tp_cav = m.third_party_caveats()
        assert len(tp_cav) == 1
        assert tp_cav[0].location == "test_location"
        cav = codec.decode_caveat(tp_key, tp_cav[0].caveat_id)
        assert cav == macaroon.ThirdPartyCaveatInfo(
            condition="test_condition",
            first_party_public_key=fp_key.public_key,
            third_party_key_pair=tp_key,
            root_key='random',
            caveat=tp_cav[0].caveat_id,
            version=bakery.BAKERY_V1
        )

    def test_decode_caveat_from_go(self):
        tp_key = nacl.public.PrivateKey(base64.b64decode(
            'TSpvLpQkRj+T3JXnsW2n43n5zP/0X4zn0RvDiWC3IJ0='))
        fp_key = nacl.public.PrivateKey(base64.b64decode(
            'KXpsoJ9ujZYi/O2Cca6kaWh65MSawzy79LWkrjOfzcs='))
        # This caveat has been generated from the go code
        # to check the compatibilty
        encrypted_cav = 'eyJUaGlyZFBhcnR5UHVibGljS2V5IjoiOFA3R1ZZc3BlWlN4c' \
                        '3hFdmJsSVFFSTFqdTBTSWl0WlIrRFdhWE40cmxocz0iLCJGaX' \
                        'JzdFBhcnR5UHVibGljS2V5IjoiSDlqSFJqSUxidXppa1VKd2o' \
                        '5VGtDWk9qeW5oVmtTdHVsaUFRT2d6Y0NoZz0iLCJOb25jZSI6' \
                        'Ii9lWTRTTWR6TGFxbDlsRFc3bHUyZTZuSzJnVG9veVl0IiwiS' \
                        'WQiOiJra0ZuOGJEaEt4RUxtUjd0NkJxTU0vdHhMMFVqaEZjR1' \
                        'BORldUUExGdjVla1dWUjA4Uk1sbGJhc3c4VGdFbkhzM0laeVo' \
                        '0V2lEOHhRUWdjU3ljOHY4eUt4dEhxejVEczJOYmh1ZDJhUFdt' \
                        'UTVMcVlNWitmZ2FNaTAxdE9DIn0='
        cav = codec.decode_caveat(tp_key, encrypted_cav)
        assert cav == macaroon.ThirdPartyCaveatInfo(
            condition="caveat condition",
            first_party_public_key=fp_key.public_key,
            third_party_key_pair=tp_key,
            root_key='random',
            caveat=encrypted_cav,
            version=bakery.BAKERY_V1
        )
