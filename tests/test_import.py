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

from datetime import datetime

now = datetime.now()

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
                                  marking_json='tests/testdata/markings/import_info.json',
                                  default_timestamp = '2013-02-26 13:11:33.253370+00:00')

        expected = [ ('DataTypeNameSpace', 22),
                     ('Fact', 83),
                     ('FactDataType', 16),
                     ('FactTerm', 52),
                     ('FactTerm2Type', 56),
                     ('FactTermNamespaceMap', 46),
                     ('FactValue', 70),
                     ('Identifier', 18),
                     ('IdentifierNameSpace', 2),
                     ('InfoObject', 18),
                     ('InfoObject2Fact', 100),
                     ('InfoObjectFamily', 4),
                     ('InfoObjectType', 10),
                     ('Marking2X', 15),
                     ('NodeID', 49),
                     ('PositionalNamespace', 93),
                     ('Revision', 4)] 

        self.assertEqual(delta,expected)

        # If we import the same object with the same date and now markings,
        # there should be no difference in the database, since
        # existing objects of the same timestamp are not overwritten
        # (and if they were, there should still be no difference ;)

        (delta,result) = t_import('tests/testdata/xml/STIX_Phishing_Indicator.xml',
                                  default_timestamp = '2013-02-26 13:11:33.253370+00:00')

        expected = []

        self.assertEqual(delta,expected)


        # If we import with a later date, all that is added to the database
        # are entries in the InfoObject-table and the InfoObject2Fact-table:
        # all the facts and values were unchanged and are not duplicated.

        (delta,result) = t_import('tests/testdata/xml/STIX_Phishing_Indicator.xml',
                                  default_timestamp = '2013-02-26 14:11:33.253370+00:00')

        expected = [('InfoObject', 15), ('InfoObject2Fact', 94)]

        self.assertEqual(delta,expected)

        (delta,result) = t_import('tests/testdata/xml/STIX_Phishing_Indicator.xml',
                                  default_timestamp = '2013-02-26 15:11:33.253370+00:00')

        expected = [('InfoObject', 15), ('InfoObject2Fact', 94)]

        self.assertEqual(delta,expected)


