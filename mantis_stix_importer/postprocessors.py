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
    enrich_details = True

    exporter_name = 'hashes'

    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = InfoObjectDetails._default_columns + [('hash_type','Hash Type'),
                       ('hash_value','Hash Value'),
                       ("fact.pk", "Fakt PK")
                       ('filename','File Name')
                       ]


    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):

        # extract keyword arguments that may modify result

        specific_hash_type = kwargs.get('hash_type',None)

        hash_io2fs = self.io2fs.filter(fact__fact_term__term__contains='Simple_Hash_Value',fact__fact_term__attribute='')

        filenames = self.io2fs.filter(fact__fact_term__term__contains='File_Name',fact__fact_term__attribute='').values_list('iobject_id','node_id','value')

        print filenames

        file_name_dict = {}
        for (iobject_id,node_id,file_name) in filenames:
            file_name_dict[iobject_id] = (node_id,file_name)



        for io2f in hash_io2fs: # self.io2fs:

            # Hashes in CybOX are contained in a fact with fact term ending in 'Simple_Hash_Value' as
            # follows::
            #
            #    (...)
            #    <cyboxCommon:Hash>
            #      <cyboxCommon:Type xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
            #      <cyboxCommon:Simple_Hash_Value>a7a0390e99406f8975a1895860f55f2f</cyboxCommon:Simple_Hash_Value>
            #    </cyboxCommon:Hash>
            #



            hash_value = io2f.value

            hash_type = ''
            # In order to find out about the hash type (if one is provided), we have
            # to iterate through the siblings of the 'Simple_Hash_Value' element:

            siblings = self.get_siblings(io2f)
            #try:
            #    sibling = siblings[0]
            #except:
            #    sibling = None
            #if sibling:

            for sibling in siblings:
                hash_type = None
                if 'Hash/Type' in sibling.term:
                    hash_type = sibling.value
                    break


            
            
            # We only include the hash in the list of results, if either no specific hash type
            # has been requested, or the hash type specified in the object matches the
            # specific hash type that was requested


            if  (not specific_hash_type) or hash_type in specific_hash_type:
                result_dict = self.init_result_dict(io2f)
                
                result_dict['hash_type'] = hash_type
                result_dict['hash_value'] = hash_value
                result_dict['filename'] = ""


                (node_id,file_name) = file_name_dict.get(result_dict['_object_pk'],(None,None))

                if node_id:
                    fn_node_id = node_id.split(':')
                    hash_node_id = io2f.node_id.split(':')
                    if len(hash_node_id) == len(fn_node_id)+2 and hash_node_id[0] == fn_node_id[0]:
                        result_dict['filename'] = file_name

                self.results.append(result_dict)

            






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

    enrich_details = True

    exporter_name = 'IPs'



    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = InfoObjectDetails._default_columns + [('ip','IP'),
        ('category','Category'),
        ('condition', 'Condition'),
        ('apply_condition', 'Apply Condition'),
        ("fact.pk", "Fakt PK")]


    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):

        #ip_io2fs = self.io2fs.filter(term__icontains='Address_Value',attribute='')

        for io2f in self.io2fs:

            if 'Address_Value' in io2f.term and not io2f.attribute:
                address_value = io2f.value

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


                category = attributes.get('category',[('',None)])[0][0]

                condition = attributes.get('condition',[('',None)])[0][0]

                apply_condition = attributes.get('apply_condition',[('',None)])[0][0]

                if not category:
                    # Damn, no category information is provided, so we have to check
                    # with a regular expression, whether address value is an ip4 address
                    try:
                        checked_ip=ipaddr.IPAddress(address_value)
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
                    result_dict = self.init_result_dict(io2f)
                    result_dict['category'] = category
                    result_dict['condition'] = condition
                    result_dict['apply_condition'] = apply_condition

                    #if apply_condition and apply_condition == 'ALL':
                    #    address_values = [",".join(address_values)]


                    #for value in address_values:
                    result = result_dict.copy()
                    result['ip'] = address_value

                    self.results.append(result)



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


    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "fqdn"

    default_columns = InfoObjectDetails._default_columns + [
        ('fqdn', 'FQDN'),
        ('condition', 'Condition'),
        ('apply_condition', 'Apply Condition'),
        ("fact.pk", "Fakt PK")
    ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects
    def extractor(self, **kwargs):

        fqdn_io2fvs = self.io2fs.filter(iobject_type_name__in=['DomainNameObject',
                                                               'LinkObject',
                                                                'URIObject'],
                                        term='Properties/Value',
                                        attribute=''
                                        )


        for io2f in fqdn_io2fvs:
            result_dict = self.init_result_dict(io2f)
            result_dict['condition'] = ''
            result_dict['apply_condition'] = ''
            result_dict['fqdn'] = ''

            attributes = self.get_attributes(io2f)


            # The result looks something like this::
            #
            #     {'category': [('ipv4-addr', 'Properties')],
            #      'condition': [('Equals', 'Properties/Address_Value')]}
            #
            # Note that we have a list of results, because an attribute may occur several
            # times "above" an element. The list is ordered from the closest occurrance of
            # the attribute to the most distant one


            apply_condition = attributes.get('apply_condition',[('',None)])[0][0]

            condition = attributes.get('condition',[('',None)])[0][0]

            result = result_dict.copy()
            result['fqdn'] = io2f.value
            result['condition']= condition
            result['apply_condition'] = apply_condition
            self.results.append(result)

