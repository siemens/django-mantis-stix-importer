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
import re



from django.db.models import Q
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

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
                       ("fact.pk", "Fakt PK"),
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


                if hash_type in ['MD5','SHA1','SHA256','SSDEEP']:
                    result_dict['actionable_type'] = 'Hash'
                    result_dict['actionable_subtype'] = hash_type
                    result_dict['actionable_info'] = hash_value
                elif not hash_type:
                    """
                    By the definition in FIPS 180-4, published March 2012, there are
                    160 bits in the output of SHA-1
                    224 bits in the output of SHA-224
                    256 bits in the output of SHA-256
                    384 bits in the output of SHA-384
                    512 bits in the output of SHA-512
                    224 bits in the output of SHA-512/224
                    256 bits in the output of SHA-512/256
                    """
                    length_hashtype_map = {
                        32 : "MD5",
                        40 : "SHA1",
                        64 : "SHA256"
                    }

                    try:
                        hash_type = length_hashtype_map[len(hash_value)]
                        result_dict['actionable_type'] = 'Hash'
                        result_dict['actionable_subtype'] = hash_type
                        result_dict['actionable_info'] = hash_value
                    except KeyError:
                        #no suiting hash_type found
                        pass

                self.results.append(result_dict)

            
class filenames(InfoObjectDetails):

    """

    """
    enrich_details = True

    exporter_name = 'filenames'

    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = InfoObjectDetails._default_columns + [('filename','File Name'),
                       ]


    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):

        filename_io2fvs = self.io2fs.filter(term__contains='File_Name',attribute='')

        for io2fv in filename_io2fvs:

            filename = io2fv.value

            siblings = self.get_siblings(io2fv)

            file_path = None
            for sibling in siblings:
                if 'File/Path' in sibling.term and sibling.attribute == '':
                    file_path = sibling.value
                    file_path_fact_pk = sibling.fact_id
                    break




            # We only include the hash in the list of results, if either no specific hash type
            # has been requested, or the hash type specified in the object matches the
            # specific hash type that was requested

            result_dict = self.init_result_dict(io2fv)

            result_dict['filename'] = filename

            result_dict['actionable_type'] = 'Filename'
            result_dict['actionable_subtype'] = ''
            result_dict['actionable_info'] = filename

            if file_path:
                result_dict['file_path'] = file_path

            self.results.append(result_dict)

            # if the filepath contains the filename (as it should),
            # we also create a 'file_path' actionable

            #if file_path and re.search("%s$" % filename,file_path):
            #    result_copy = result_dict.copy()
            #    result_dict['actionable_type'] = 'Filepath'
            #    result_dict['actionable_subtype'] = ''
            #    result_dict['actionable_info'] = file_path
            #    result_dict['fact.pk'] = file_path_fact_pk







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

                    if category:
                        if 'v4' in category:
                            result['actionable_type'] = 'IP'
                            result['actionable_subtype'] = 'v4'
                            result['actionable_info'] = address_value
                        elif 'v6' in category:
                            result['actionable_type'] = 'IP'
                            result['actionable_subtype'] = 'v6'
                            result['actionable_info'] = address_value

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

    def is_valid_fqdn(self,fqdn):
        if len(fqdn) > 255:
            return False
        if fqdn[-1] == ".":
            fqdn = fqdn[:-1] # strip exactly one dot from the right, if present
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in fqdn.split("."))

    def is_valid_url(self,url):
        val = URLValidator()
        try:
            val(url)
        except ValidationError:
            return False
        return True

    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "fqdns"

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

        q_dedicated_objects = Q(iobject_type_name__in=['DomainNameObject',
                                                       'DomainObject',
                                                       'LinkObject',
                                                       'URIObject'],
                                        term='Properties/Value',
                                        attribute=''
                                        )

        q_dns_query = Q(iobject_type_name='DNSQueryObject',
                        term='Properties/Question/QName',
                        attribute = '')

        q_domain_name = Q(term__contains='/Domain_Name/Value',
                          attribute = '')




        fqdn_io2fvs = self.io2fs.filter(q_dedicated_objects | q_dns_query | q_domain_name)

        #print "Found"
        #printer_res =  map(lambda x: "%s %s %s %s" % (x.iobject_type_name,x.term,x.attribute,x.value),self.io2fs)
        #print printer_res
        #print fqdn_io2fvs

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




            if(self.is_valid_fqdn(result['fqdn'])):
                 result['actionable_type'] = 'FQDN'
                 result['actionable_subtype'] = ''
                 result['actionable_info'] = result['fqdn']
            elif(self.is_valid_url(result['fqdn'])):
                 result['actionable_type'] = 'URL'
                 result['actionable_subtype'] = ''
                 result['actionable_info'] = result['fqdn']

            self.results.append(result)

            # If an IP occurs as domain name, we also want it
            # to appear as IP actionable rather than FQDN only
            try:
                checked_ip=ipaddr.IPAddress(result['actionable_info'])
                is_ip = True
                category = "v%s" % checked_ip.version
            except ValueError:
                category = None
                is_ip = False

            if is_ip:
                copied_result = result.copy()
                copied_result['actionable_type'] = 'IP'
                copied_result['actionable_subtype'] = category

                self.results.append(copied_result)


class email_addresses(InfoObjectDetails):
    """

    """
    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "email_addresses"

    default_columns = InfoObjectDetails._default_columns + [
        ('email_address', 'Email Address'),
        ('condition', 'Condition'),
        ('apply_condition', 'Apply Condition'),
        ("fact.pk", "Fact PK")
    ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects
    def extractor(self, **kwargs):

        q_all_address_values = Q(iobject_type_name='EmailMessageObject',
                                 term__icontains='Address_Value',
                                 attribute=''
                                )

        email_io2fvs = self.io2fs.filter(q_all_address_values)

        for io2f in email_io2fvs:
            result_dict = self.init_result_dict(io2f)
            result_dict['condition'] = ''
            result_dict['apply_condition'] = ''

            if '@' in io2f.value:
                attributes = self.get_attributes(io2f)

                apply_condition = attributes.get('apply_condition',[('',None)])[0][0]

                condition = attributes.get('condition',[('',None)])[0][0]

                result = result_dict.copy()
                result['email_address'] = io2f.value
                result['condition']= condition
                result['apply_condition'] = apply_condition

                result['actionable_type'] = 'Email_Address'

                if "From" in io2f.term or "Sender" in io2f.term:
                    result['actionable_subtype'] = 'sender'
                elif "Recipient" in io2f.term:
                    result['actionable_subtype'] = 'recipient'
                else:
                    result['actionable_subtype'] = ''
                result['actionable_info'] = result['email_address']

                self.results.append(result)


class email_subjects(InfoObjectDetails):
    """

    """
    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "email_subjects"

    default_columns = InfoObjectDetails._default_columns + [
        ('email_subject', 'Email Address'),
    ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects
    def extractor(self, **kwargs):

        q_all_subjects      = Q(iobject_type_name='EmailMessageObject',
                                 term__icontains='Header/Subject',
                                 attribute=''
                                )

        subject_io2fvs = self.io2fs.filter(q_all_subjects)

        for io2f in subject_io2fvs:
            result = self.init_result_dict(io2f)
            result['email_subject'] = io2f.value
            result['actionable_type'] = 'email_subject'
            result['actionable_subtype'] = ''
            result['actionable_info'] = io2f.value

            self.results.append(result)

class x_mailers(InfoObjectDetails):
    """

    """
    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "x_mailer"

    default_columns = InfoObjectDetails._default_columns + [
        ('x_mailer', 'X Mailer'),
    ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects
    def extractor(self, **kwargs):

        q_relevant_facts      = Q(iobject_type_name='EmailMessageObject',
                                  term__icontains='Header/X_Mailer',
                                  attribute=''
                                )

        relevant_io2fvs = self.io2fs.filter(q_relevant_facts)

        for io2f in relevant_io2fvs:
            result = self.init_result_dict(io2f)
            result['x_mailer'] = io2f.value
            result['actionable_type'] = 'x_mailer'
            result['actionable_subtype'] = ''
            result['actionable_info'] = io2f.value

            self.results.append(result)

class user_agents(InfoObjectDetails):
    """

    """
    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "user_agent"

    default_columns = InfoObjectDetails._default_columns + [
        ('user_agent', 'User Agent'),
    ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects
    def extractor(self, **kwargs):

        q_relevant_facts      = Q(iobject_type_name='HTTPSessionObject',
                                  term__icontains='/User_Agent',
                                  attribute=''
                                )

        relevant_io2fvs = self.io2fs.filter(q_relevant_facts)

        for io2f in relevant_io2fvs:
            result = self.init_result_dict(io2f)
            result['user_agent'] = io2f.value
            result['actionable_type'] = 'user_agent'
            result['actionable_subtype'] = ''
            result['actionable_info'] = io2f.value

            self.results.append(result)
