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

from lxml import etree, objectify

import pprint

pp = pprint.PrettyPrinter(indent=2)

from operator import itemgetter

from networkx.algorithms.shortest_paths.unweighted import all_pairs_shortest_path_length

from networkx.algorithms.shortest_paths.generic import shortest_path_length

from django.db.models import Q
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

from dingos.core.extractors import InfoObjectDetails

from dingos.graph_utils import dfs_preorder_nodes

from dingos_authoring.models import AuthoredData


class BasicSTIXExtractor(InfoObjectDetails):


    extract_relationships = True

    reverse_graph = None

    shortest_paths = None

    reverse_shortest_paths = None



    def init_result_dict(self,obj_or_io2f):
        result = super(BasicSTIXExtractor,self).init_result_dict(obj_or_io2f)

        if self.extract_relationships and not self.reverse_graph:

            self.reverse_graph = self.graph.reverse()
            self.shortest_paths = shortest_path_length(self.graph)
            self.reverse_shortest_paths = shortest_path_length(self.reverse_graph)

        iobject_pk = result['_iobject_pk']
        if self.package_graph:
            iobject_pk = result['_iobject_pk']

            # The user also wants info about the packages that contain the object in question
            node_ids = list(dfs_preorder_nodes(self.package_graph, source=iobject_pk))

            package_names = []
            package_urls = []
            for id in node_ids:
                node = self.package_graph.node[id]
                # TODO: Below is STIX-specific and should be factored out
                # by making the iobject type configurable
                if "STIX_Package" in node['iobject_type']:
                    package_names.append(node['name'])
                    package_urls.append(node['url'])
            result['_package_names'] = "| ".join(package_names)
            result['_package_urls'] = "| ".join(package_urls)

        if self.extract_relationships:
            predecessors = self.reverse_shortest_paths[iobject_pk]
            reachable_nodes = predecessors.items()
            reachable_nodes.sort(key=itemgetter(1))


            related_nodes = []

            while reachable_nodes:
                object_pk, length = reachable_nodes.pop()
                node_info = self.graph.node[object_pk]

                if node_info['iobject_type'] == 'Indicator':
                    kill_chain_phase_object_pks = list(dfs_preorder_nodes(self.graph,
                                                               source=object_pk,
                                                               edge_pred= lambda x : 'phase_id' in x['attribute']))[1:]

                    kill_chain_phase_nodes = map(lambda x: self.graph.node[x],kill_chain_phase_object_pks)

                    node_info['kill_chain_phase_nodes'] = kill_chain_phase_nodes

                    related_nodes.append(node_info)
                #elif node_info['iobject_type'] == 'ThreatActor':
                #    threat_actor_nodes.append(node_info)
                #elif node_info['iobject_type'] == 'Campaign':
                #    campaign_nodes.append(node_info)

            # We cannot link threat actors and campaings to indicators, yet, so we take
            # all campaigns and threat actors found in the report

            for pk in self.graph.nodes():
                if 'Campaign' in self.graph.node[pk]['iobject_type']:
                    related_nodes.append(self.graph.node[pk])
                elif 'Threat' in self.graph.node[pk]['iobject_type']:
                    related_nodes.append(self.graph.node[pk])
                    identity_object_pks = list(dfs_preorder_nodes(self.graph,
                                               source=pk,
                                               edge_pred= lambda x : 'Identity' in x['term']))[1:]

                    identity_object_nodes = map(lambda x: self.graph.node[x],identity_object_pks)

                    self.graph.node[pk]['identity_object_nodes'] = identity_object_nodes



            result['_relationship_info'] = related_nodes


        return result


class hashes(BasicSTIXExtractor):

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


                (node_id,file_name) = file_name_dict.get(result_dict['_iobject_pk'],(None,None))

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


class filenames(BasicSTIXExtractor):

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




class test_mechanisms(BasicSTIXExtractor):

    """

    """
    enrich_details = True

    exporter_name = 'test_mechanisms'

    # define the default columns that are output if no column
    # information is provided in the call

    default_columns = InfoObjectDetails._default_columns + [('rule_id','Rule ID'),
                       ]


    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects

    def extractor(self,**kwargs):

        query_obj = (Q(iobject_type_name='OpenIOC2010',term='ioc',attribute='')  |
                    Q(iobject_type_name='Snort',term='Rule') )

        ids_io2fvs = self.io2fs.filter(query_obj)# iobject_type_name__in=['OpenIOC2010','Snort'],term__in=['Rule','ioc'])



        sid_search = re.compile(r"sid\s*:\s*(?P<sid>[0-9]+)\s*;")



        actionable_type = 'IDS_Rule'


        for io2fv in ids_io2fvs:
            actionable_subtype=''
            rule_id= None
            ids_rule = ''

            term = io2fv.term
            value = io2fv.value
            print value
            if term == 'Rule':
                actionable_subtype = 'Snort'
                m = sid_search.search(value)
                if m:
                    rule_id = m.groupdict()['sid']
                else:
                    rule_id = None
                ids_rule = value
            elif term == 'ioc':
                actionable_subtype = 'IOC'
                try:
                    rule_id=io2fv.referenced_iobject_identifier.uid
                    rule_namespace=io2fv.referenced_iobject_identifier.namespace.uri
                except:
                    rule_id=None

                if rule_id:
                    # retrieve the XML from which the object was imported
                    authored_objects = io2fv.iobject.yielded_by.all().filter(kind=AuthoredData.XML).order_by('-timestamp')

                    if authored_objects:

                        authored_object = authored_objects[0]
                        root = etree.fromstring(authored_object.content)
                        ioc_root =  root.xpath("//ns:ioc[@id ='%s']" % rule_id,namespaces={'ns':'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1'}) # [@id='{%s}%s']" % (rule_namespace,rule_id))
                        if ioc_root:
                            ioc_root = ioc_root[0]
                        i = ioc_root.tag.find('}')
                        if i >= 0:
                            ioc_root.tag = ioc_root.tag[i+1:]

                        #objectify.deannotate(ioc_root,
                        #                     pytype=False,
                        #                     xsi=False,
                        #                     xsi_nil=False,
                        #                     cleanup_namespaces=True)
                        #print "XML"
                        #etree.cleanup_namespaces(ioc_root)
                        xml_string =  etree.tostring(ioc_root,
                                             pretty_print=True,
                                             xml_declaration=True,
                                             encoding='UTF-8')
                        xml_string=re.sub(r'\s*xmlns:(?!xsi)[^=]+="[^"]+"',"",xml_string)
                        ids_rule = xml_string

            if rule_id:
                result_dict = self.init_result_dict(io2fv)
                result_dict['rule_id'] = rule_id
                result_dict['actionable_type'] = actionable_type
                result_dict['actionable_subtype'] = actionable_subtype
                result_dict['actionable_info'] = rule_id
                result_dict['actionable_ids_rule'] = ids_rule

            self.results.append(result_dict)
        pp.pprint(self.results)

class ips(BasicSTIXExtractor):

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



class fqdns(BasicSTIXExtractor):
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
            # Validation may raise an error if there is no schema or the schema
            # is not in ['http','https','ftp', ...]. For our purposes, we
            # do not care about the schema or its existence.

            if '//' in url:
                check_url = url.split('//',1)[1]
                check_url = "http://%s" % check_url
            else:
                check_url = "http://%s" % url
            try:
                val(check_url)
            except:
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
                        term='Properties/Question/QName/Value',
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


class email_addresses(BasicSTIXExtractor):
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


class email_subjects(BasicSTIXExtractor):
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
            result['actionable_type'] = 'Email_Subject'
            result['actionable_subtype'] = ''
            result['actionable_info'] = io2f.value

            self.results.append(result)

class x_mailers(BasicSTIXExtractor):
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
            result['actionable_type'] = 'X_Mailer'
            result['actionable_subtype'] = ''
            result['actionable_info'] = io2f.value

            self.results.append(result)

class user_agents(BasicSTIXExtractor):
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
            result['actionable_type'] = 'User_Agent'
            result['actionable_subtype'] = ''
            result['actionable_info'] = io2f.value

            self.results.append(result)

class winregistrykeys(BasicSTIXExtractor):
    """

    """
    enrich_details = True

    # define the default columns that are output if no column
    # information is provided in the call

    exporter_name = "winregistrykeys"

    default_columns = InfoObjectDetails._default_columns + [
        ('winregistrykey', 'Windows Registry Key'),
    ]

    # define below the extractor function that sets self.results
    # to a dictionary that maps column-names / keys to
    # values extracted from the information objects
    def extractor(self, **kwargs):
        q_all_subjects = Q(iobject_type_name='WinRegistryKeyObject',
                           term__contains='Properties',
                           )

        subject_io2fvs = self.io2fs.filter(q_all_subjects)
        infos = {}
        for io2f in subject_io2fvs:
            pk = io2f.iobject.pk
            data = {io2f.term: io2f.value}
            try:
                infos[pk].update(data)
            except KeyError:
                infos[pk] = data

            # this is the main fact, use it to initialize the result
            if io2f.term == 'Properties/Key':
                infos[pk].update({'result': self.init_result_dict(io2f)})

        for pk in infos:
            try:
                result = infos[pk]['result']
            except KeyError:  # this should never happen... this means we could not find a fact 'Properties/Key'
                continue  # skip this infoobject...

            try:
                hive = infos[pk]['Properties/Hive']
                key = infos[pk]['Properties/Key']
                # TODO: cybox supports list of values... we only support one (name,data,datatype)-tuple at the moment
                value = infos[pk]['Properties/Values/Value/Name']
                data = infos[pk]['Properties/Values/Value/Data']
                datatype = infos[pk]['Properties/Values/Value/Datatype']
            except KeyError: # we are missing an important fact... recover somehow?
                continue  # skip this key

            key_representation = "%s\%s /v %s /t %s /d %s" % (hive, key, value, datatype, data)
            result['winregistrykey'] = key_representation
            result['actionable_type'] = 'WinRegistryKey'
            result['actionable_subtype'] = ''
            result['actionable_info'] = key_representation

            self.results.append(result)
