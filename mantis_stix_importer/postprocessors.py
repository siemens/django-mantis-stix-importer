# Copyright (c) Siemens AG, 2014
#
# This file is part of MANTIS.  MANTIS is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2
# of the License, or(at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import re
import ipaddr

from dingos.core.extractors import InfoObjectDetails

class hashes(InfoObjectDetails):

    """
    This class defines an exporter that extracts all information about hash values
    from a set of CybOX objects. It makes the following columns/json-keys available:

    - hash_type
    - hash_value
    - iobject_uri

    You can all the exporter in a query as follows:

    hashes(<list of columns out of columns specified above>,

           hash_type = <hash_type, e.g. 'MD5'>

              (if no hash_type is given, all hash types are returned)

           format= 'json'/'cvs',

              (default: json)

           include_column_names= True/False

              (Governs, whether csv output has a first header row
               with column names.

               default: True)


    """

    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = [('hash_type','Hash Type'),
        ('hash_value','Hash Value'),
        ('iobject_url', 'URL to containing InfoObject')]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):

        # extract keyword arguments that may modify result

        specific_hash_type = kwargs.get('hash_type',None)

        for io2f in self.io2fs:
            #
            # We iterate through all the facts that are contained
            # in the set of objects with which the
            # class was instantiated. If we wanted to
            # operate on an object-by-object base,
            # we could instead iterate over the following:
            #
            #  - self.iobject_map, which maps iobject pks to the following
            #    information:
            #       {'identifier_ns': <identifier namespace uri>,
            #        'identifier_uid': <identifier uid>,
            #        'name': <object name>,
            #        'iobject_type': <info object type, eg.g 'WinExecutableFile'>
            #        'iobject_type_family': <info object type family, e.g. 'cybox.mitre.org'>,
            #        'iobject': <InfoObject instance>
            #        'url': <url under which object can be viewed: '/mantis/View/InfoObject/<pk>/'>,
            #        'facts': <list of InfoObject2Fact instances contained in info object>
            #    InfoObject2Fact objects contained in the Information Object
            # - self.graph (if a graph was passed):
            #   A networkx-graph, where each node represents a iobject pk and
            #   ``self.graph.node[pk]``  contains the same information
            #   as ``self.iobject_map[pk]``.
            #

            # Hashes in CybOX are contained in a fact with fact term ending in 'Simple_Hash_Value' as
            # follows::
            #
            #    (...)
            #    <cyboxCommon:Hash>
            #      <cyboxCommon:Type xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
            #      <cyboxCommon:Simple_Hash_Value>a7a0390e99406f8975a1895860f55f2f</cyboxCommon:Simple_Hash_Value>
            #    </cyboxCommon:Hash>
            #

            if 'Simple_Hash_Value' in io2f.fact.fact_term.term and not io2f.fact.fact_term.attribute:
                hash_value = io2f.fact.fact_values.all()[0]
                # In order to find out about the hash type (if one is provided), we have
                # to iterate through the siblings of the 'Simple_Hash_Value' element:
                siblings = self.get_siblings(io2f)
                for sibling in siblings:
                    hash_type = None
                    if 'Hash/Type' in sibling.fact_term.term:
                        hash_type = sibling.fact_values.all()[0].value
                        break

                # We only include the hash in the list of results, if either no specific hash type
                # has been requested, or the hash type specified in the object matches the
                # specific hash type that was requested

                if  (not specific_hash_type) or hash_type == specific_hash_type:
                    self.results.append({'hash_type':hash_type,
                                         'hash_value':hash_value.value,
                                         'iobject_url': self.iobject_map[io2f.iobject.pk]['url']}
                    )





class ips(InfoObjectDetails):

    """
    This class defines an exporter that extracts all information about ips
    from a set of CybOX objects. It makes the following columns/json-keys available:

    - ip
    - category
    - condition

    You can all the exporter in a query as follows:

    ips(<list of columns out of columns specified above>,

        format= 'json'/'cvs',

           (default: json)

        include_column_names= True/False

              (Governs, whether csv output has a first header row
               with column names.

               default: True)


    """

    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = [('ip','IP'),
        ('category','Category'),
        ('condition', 'Condition'),
        ('iobject_url', 'URL to containing InfoObject')]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):


        for io2f in self.io2fs:
            #
            # We iterate through all the facts that are contained
            # in the set of objects with which the
            # class was instantiated. If we wanted to
            # operate on an object-by-object base,
            # we could instead iterate over the following:
            #
            #  - self.iobject_map, which maps iobject pks to the following
            #    information:
            #       {'identifier_ns': <identifier namespace uri>,
            #        'identifier_uid': <identifier uid>,
            #        'name': <object name>,
            #        'iobject_type': <info object type, eg.g 'WinExecutableFile'>
            #        'iobject_type_family': <info object type family, e.g. 'cybox.mitre.org'>,
            #        'iobject': <InfoObject instance>
            #        'url': <url under which object can be viewed: '/mantis/View/InfoObject/<pk>/'>,
            #        'facts': <list of InfoObject2Fact instances contained in info object>
            #    InfoObject2Fact objects contained in the Information Object
            # - self.graph (if a graph was passed):
            #   A networkx-graph, where each node represents a iobject pk and
            #   ``self.graph.node[pk]``  contains the same information
            #   as ``self.iobject_map[pk]``.
            #

            # Address objects are defined follows:
            #
            #  <cybox:Properties xsi:type="AddressObject:AddressObjectType" category="ipv4-addr">
            #                  <AddressObject:Address_Value condition='Equals'>127.0.0.1</AddressObject:Address_Value>
            # </cybox:Properties>
            #


            if 'Address_Value' in io2f.fact.fact_term.term and not io2f.fact.fact_term.attribute:
                address_values = map(lambda av : av.value, io2f.fact.fact_values.all())

                # In order to find out about the category, we have to look at the attributes
                # associated with this fact.

                attributes = self.get_attributes(io2f)

                # The result looks something like this::
                #
                #     {'category': [('ipv4-addr', 'Properties')],
                #      'condition': [('Equals', 'Properties/Address_Value')]}
                #
                # Note that we have a list of results, because an attribute may occur several
                # times "above" an element. The list is ordered from the closest occurrance of
                # the attribute to the most distant one


                category = attributes.get('category',[(None,None)])[0][0]

                condition = attributes.get('condition',[(None,None)])[0][0]

                if not category:
                    # Damn, no category information is provided, so we have to check
                    # with a regular expression, whether address value is an ip4 address
                    try:
                        checked_ip=ipaddr.IPAddress(address_values[0])
                        category = "ipv%s-addr" % checked_ip.version
                        is_ip = True
                    except ValueError:
                        category = None
                        is_ip = False

                else:
                    is_ip = (category[0:2] == 'ip')

                # We only include the hash in the list of results, if either no specific hash type
                # has been requested, or the hash type specified in the object matches the
                # specific hash type that was requested

                if is_ip:
                    self.results.append({'ip': ','.join(address_values),
                    'category' : category,
                    'condition' : condition,
                    'iobject_url': self.iobject_map[io2f.iobject.pk]['url']}

                    )


class fqdns(InfoObjectDetails):

    """
    This class defines an exporter that extracts all information about fqdns
    from a set of CybOX objects. It makes the following columns/json-keys available:

    - fqdn

    You can all the exporter in a query as follows:

    fqdns(<list of columns out of columns specified above>,

        format= 'json'/'cvs',

           (default: json)

        include_column_names= True/False

              (Governs, whether csv output has a first header row
               with column names.

               default: True)


    """

    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = [('fqdn','FQDN'),
                       # .,..
                       ('iobject_url', 'URL to containing InfoObject')
                      ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):

        for io2f in self.io2fs:
            #
            # We iterate through all the facts that are contained
            # in the set of objects with which the
            # class was instantiated. If we wanted to
            # operate on an object-by-object base,
            # we could instead iterate over the following:
            #
            #  - self.iobject_map, which maps iobject pks to the following
            #    information:
            #       {'identifier_ns': <identifier namespace uri>,
            #        'identifier_uid': <identifier uid>,
            #        'name': <object name>,
            #        'iobject_type': <info object type, eg.g 'WinExecutableFile'>
            #        'iobject_type_family': <info object type family, e.g. 'cybox.mitre.org'>,
            #        'iobject': <InfoObject instance>
            #        'url': <url under which object can be viewed: '/mantis/View/InfoObject/<pk>/'>,
            #        'facts': <list of InfoObject2Fact instances contained in info object>
            #    InfoObject2Fact objects contained in the Information Object
            # - self.graph (if a graph was passed):
            #   A networkx-graph, where each node represents a iobject pk and
            #   ``self.graph.node[pk]``  contains the same information
            #   as ``self.iobject_map[pk]``.
            #

            # In order to better understand how 'io2f's (InfoObject2Fact) and the other
            # models relate to each other, please have a look at
            #
            # http://django-dingos.readthedocs.org/en/latest/_downloads/dingos_data_model.pdf
            #
            # and refer to the code indingos.models
            pass

        self.results =  [{'fqdn': 'THIS EXPORTER IS NOT YET IMPLEMENTED'}]




