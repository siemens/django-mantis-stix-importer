#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_django-mantis-stix-importer
------------

Tests for `django-mantis-stix-importer` modules module.
"""


from utils import deltaCalc

from django import test

from mantis_stix_importer.management.commands.mantis_stix_import import Command

from custom_test_runner import CustomSettingsTestCase

import pprint

pp = pprint.PrettyPrinter(indent=2)


class XML_Import_Tests(CustomSettingsTestCase):

    new_settings = dict(
        INSTALLED_APPS=(
           'dingos',
        )
    )

    def setUp(self):
        self.command = Command()

    def test_import(self):

        @deltaCalc
        def t_import(*args,**kwargs):
            return self.command.handle(*args,**kwargs)


        (delta,result) = t_import('tests/testdata/xml/STIX_Phishing_Indicator.xml',
                                  placeholder_fillers=[('source', 'Example_import')],
                                  identifier_ns_uri=None,
                                  marking_json='tests/testdata/markings/import_info.json')
        #pp.pprint(delta)

        expected = [ ('DataTypeNameSpace', 11),
                     ('Fact', 82),
                     ('FactDataType', 12),
                     ('FactTerm', 52),
                     ('FactTerm2Type', 55),
                     ('FactValue', 69),
                     ('Identifier', 16),
                     ('IdentifierNameSpace', 2),
                     ('InfoObject', 16),
                     ('InfoObject2Fact', 92),
                     ('InfoObjectFamily', 4),
                     ('InfoObjectType', 10),
                     ('Marking2X', 15),
                     ('NodeID', 50),
                     ('Revision', 4)]

        self.assertEqual(delta,expected)

        (delta,result) = t_import('tests/testdata/xml/STIX_Phishing_Indicator.xml',
                                  placeholder_fillers=[('source', 'Example_import')],
                                  identifier_ns_uri=None,
                                  marking_json='tests/testdata/markings/import_info.json')

        #pp.pprint(delta)

        expected = [ ('Identifier', 1),
                     ('InfoObject', 16),
                     ('InfoObject2Fact', 92),
                     ('Marking2X', 15)]

        self.assertEqual(delta,expected)


