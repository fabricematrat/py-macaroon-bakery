# Copyright 2017 Canonical Ltd.
# Licensed under the LGPLv3, see LICENCE file for details.


class Caveat:
    ''' Caveat represents a condition that must be true for a check to
    complete successfully. If Location is non-empty, the caveat must be
    discharged by a third party at the given location.
    The Namespace field holds the namespace URI of the
    condition - if it is non-empty, it will be converted to
    a namespace prefix before adding to the macaroon.
    '''
    def __init__(self, condition, location=None, namespace=None):
        self.condition = condition
        self.namespace = namespace
        self.location = location
