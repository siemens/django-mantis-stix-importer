# Copyright (c) Siemens AG, 2013
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
import logging
import hashlib

from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from django.utils import timezone

from dingos.core.xml_utils import extract_attributes

from dingos.core.decorators import print_arguments
from dingos.core.utilities import search_by_re_list

from dingos import *

from dingos.models import FactDataType

from mantis_core.models import \
    Identifier

from mantis_openioc_importer.importer import OpenIOC_Import

OpenIOC_Importer = OpenIOC_Import()

from mantis_core.import_handling import MantisImporter

# Import configuration constants from __init__.py

from mantis_stix_importer import *


logger = logging.getLogger(__name__)




class STIX_Import:
    # The following regular expression is used to extract family (stix or cybox),
    # object type
    # from CybOX/STIX style namespace uris such as the following::
    #     http://cybox.mitre.org/objects#AddressObject-2
    #     http://cybox.mitre.org/common-2

    RE_LIST_NS_TYPE_FROM_NS_URL = [
        re.compile(
        "(?P<iotype_ns>http://(?P<family>(?P<family_tag>[^.]+)\.mitre.org)/([^#]+#)?(?P<type>.+?))((-|(_v))(?P<revision>.*))?$")]

    # In Cybox 1.x, the object properties were encompassed in an element called "Defined_Object". In the interest
    # of equal fact terms for equal things, we rename occurrences of "Defined_Object" to "Properties" upon
    # import.

    RE_DEFINED_OBJECT = re.compile("Defined_Object")

    def __init__(self, *args, **kwargs):

        self.toplevel_attrs = {}

        self.create_timestamp = timezone.now()

        self.import_data = {'last_timestamp': self.create_timestamp,
                            'last_namespace_id': None}

        self.namespace_dict = {None: DINGOS_NAMESPACE_URI}

        self.default_identifier_ns_uri = None

        self.processors = {'OpenIOC2010': OpenIOC_Import}



    #
    # First of all, we define functions for the hooks provided to us
    # by the DINGO xml-import.
    #


    def id_and_revision_extractor(self, xml_elt):
        """
        Function for generating a unique identifier for extracted embedded content;
        to be used for DINGO's xml-import hook 'embedded_id_gen'.

        The CybOX XML format inlines lot's of stuff that we want to treat as separate
        Information Object; for example, the description of a file object attached
        to an email object may be given directly as part of the XML describing
        the email rather than at a different location that is then referenced
        from the XML describing the email.

        The DINGO xml_import can be configured to recognize and extract
        embedded content. When this happens, we need some way to refer
        to the extracted stuff. This function specifies how to generate
        a fresh identifier for CybOX import.
        """
        result = {'id': None,
                  'timestamp': None,
        }

        if xml_elt.properties:
            attributes = extract_attributes(xml_elt, prefix_key_char='@')
            # Extract identifier:
            if '@id' in attributes:
                result['id'] = attributes['@id']
            elif '@object_reference' in attributes:
                # 'object_reference' is used in Cybox 1.0 as follows::
                #
                #     (...)
                #     <EmailMessageObj:Attachments>
                #           <EmailMessageObj:File xsi:type="FileObj:FileObjectType"
                #              object_reference="cybox:object-3cf6a958-5c3f-11e2-a06c-0050569761d3"/>
                #     </EmailMessageObj:Attachments>
                #     (...)
                result['id'] = attributes['@object_reference']

            # Extract timestamp information
            #
            # Unfortunately, STIX/Cybox do not allow for addition of revision/timestamp information
            # along with the identifier of an object. We therefore use a modified version of STIX/CybOX,
            # that allows 'revision_timestamp' information in an attribute whereever an 'id' or 'idref' attribute
            # is allowed.
            # We use a modified version of STIX/CybOX, in which each identifyable object can also carry
            # an attribute 'revision_timestamp'. We cannot use 'timestamp', because there
            # are CybOX elements such as 'Action' that carry a timestamp attribute with a different
            # semantic (the timestamp refers to the action, not the CybOX document)

            if '@revision_timestamp' in attributes:
                result['timestamp'] = attributes['@revision_timestamp']

        return result

    def stix_embedding_pred(self, parent, child, ns_mapping):
        """
        Predicate for recognizing inlined content in a CybOX XML structure; to
        be used for DINGO's xml-import hook 'embedded_predicate'.

        The CybOX XML format inlines lot's of stuff that we want to treat as separate
        Information Object; for example, the description of a file object attached
        to an email object may be given directly as part of the XML describing
        the email rather than at a different location that is then referenced
        from the XML describing the email.

        The DINGO xml_import provides a hook for a predicate
        for finding out whether a child element of a given parent element
        should be extracted as separate DingoObjDict. Here, we define
        the predicate for CybOX XML files.

        If the predicate identifies an embedding, it must return something from which
        the name of the InfoObjectType of the embedded OutdatedInfoObject can be
        derived. In the first example, this is the name of the grand-child namespace
        (``SocketAddressObj``); in the second example, it is the element name of
        the element that starts the embedding (``Hash``).

        """

        child_attributes = extract_attributes(child, prefix_key_char='')

        # We look for 'id' or 'object_reference' attributes.
        # 'id' should be obvious; 'object_reference' is used in Cybox 1.0 as follows::
        #
        #     (...)
        #     <EmailMessageObj:Attachments>
        #           <EmailMessageObj:File xsi:type="FileObj:FileObjectType"
        #              object_reference="cybox:object-3cf6a958-5c3f-11e2-a06c-0050569761d3"/>
        #     </EmailMessageObj:Attachments>
        #     (...)


        def extract_typeinfo(child):


            # Let's try to find a grandchild and return the namespace of this grandchild:
            # This can be used as indicator for the object type that is referenced here.

            # Let's further try to find a grandchild (if there is one)

            grandchild = child.children
            type_info = None

            while grandchild is not None:
                try:
                    grandchild_attrs = extract_attributes(grandchild, prefix_key_char='')
                    if 'xsi:type' in grandchild_attrs and grandchild.name=='Properties':
                        type_info = grandchild_attrs['xsi:type'].split(':')[0]
                    else:
                        type_info = grandchild.ns().name
                    break

                except:
                    # This catches if the grandchild does not have a namespace
                    grandchild = grandchild.next
            if type_info:
                logger.debug("Found type info %s" % type_info)
                return type_info
            else:
                logger.debug("Embedding, but did not find type info")
                return True

        parent_attrs = extract_attributes(parent, prefix_key_char='')

        if parent.name=='Test_Mechanism':
            if 'xsi:type' in parent_attrs:
                if 'OpenIOC2010TestMechanismType' in parent_attrs['xsi:type']:
                    # We have an embedded OpenIOC document.

                    # We extract
                    id_and_revision_info = OpenIOC_Importer.id_and_revision_extractor(child)
                    id_and_revision_info['defer_processing'] = {'processor': 'OpenIOC2010'}
                    return {'embedded_ns':child.ns().name,
                            'id_and_revision_info':id_and_revision_info}

        if ('id' in child_attributes or
                    'object_reference' in child_attributes):
            return extract_typeinfo(child)


        elif child.name=='Object' and parent.name=='Observable':
            # Unfortunately, the example files created by MITRE from Mandiant reports
            # and OpenIOCs give an identifier to an observable, but not to the
            # object embedded in the observable. We, however, need an identifier for
            # the object, because otherwise the whole machinery that infers an object's
            # type does not work. So, if we find an object without identifier that
            # is embedded in an observable with identifier, we also want to extract
            # the object ... and need to derive the object identifier from the
            # observable identifier.
            parent_id_and_revision_info = self.id_and_revision_extractor(parent)
            if 'id' in parent_id_and_revision_info:
                split_id = parent_id_and_revision_info['id'].split(':')
                if len(split_id) == 2:
                    # We derive the identifier of the object from the identifier of the observable
                    # as follows
                    parent_id_and_revision_info['id'] = "%s:object-in-%s" % (split_id[0],split_id[1])
                    return {'embedded_ns' : extract_typeinfo(child),
                            'id_and_revision_info': parent_id_and_revision_info}
                else:
                    # The identifier had a faulty shape (no namespace info). This should not happen,
                    # but if it does, we give up.
                    return False
        else:

            return False


    # Next, we define functions for the hooks provided by the
    # 'from_dict' method of DINGO InfoObject Objects.
    #
    # These hook allow us to influence, how information contained
    # in a DingoObjDict is imported into the system.
    #
    # The hooking is carried out by defining a list
    # containing pairs of predicates (i.e., a function returning True or False)
    # and an associated hooking function. For each InfoObject2Fact object
    # (in the first case) resp. each attribute (in the second case),
    # the list is iterated by applying the predicate to input data.
    # If the predicate returns True, then the hooking function is applied
    # and may change the parameters for creation of fact.

    def cybox_RAW_ft_handler(self, enrichment, fact, attr_info, add_fact_kargs):
        """
        Handler for facts whose content is to be written to disk rather
        than stored in the database. We use it for all elements
        that contain the string 'Raw_' ('Raw_Header', 'Raw_Artifact', ...)

        Note that

        TODO: This handler is currently only a proof of concept: in the following
        revisions, we need to put more effort in to managing disk-storage (where to
        save stuff to, etc.)
        """
        # get the value
        raw_value = add_fact_kargs['values'][0]

        if len(raw_value) >= RAW_DATA_TO_DB_FOR_LENGTH_LESS_THAN:
            # rewrite the argument for the creation of the fact: there are
            # no values to be added to the database
            add_fact_kargs['values'] = [hashlib.sha256(raw_value).hexdigest()]

            add_fact_kargs['value_on_disk'] = True

            file_name = '%s.blob' % (add_fact_kargs['values'][0])

            if default_storage.exists(file_name):
                default_storage.delete(file_name)

            default_storage.save(file_name, ContentFile(raw_value))

        return True


    def reference_handler(self, iobject, fact, attr_info, add_fact_kargs):
        """
        Handler for facts that contain a reference to a fact.

        As shown below in the handler list, this handler is called
        when a attribute with key '@idref' on the fact's node
        is detected -- this attribute signifies that this fact does not contain
        a value but points to another object. Thus we either retrieve
        the object or, if an object with the given id does not yet exist,
        create a PLACEHOLDER object.

        We further create/refer to the fitting fact data type:
        we want the fact data type to express that the fact is
        a reference to an object.
        """

        (namespace, namespace_uri, uid) = self.split_qname(attr_info['idref'])

        timestamp = None

        if '@revision_timestamp' in attr_info:
            timestamp = attr_info['@revision_timestamp']

        if not timestamp:
            timestamp = self.import_data['last_timestamp']

        (target_mantis_obj, existed) = MantisImporter.create_iobject(
            uid=uid,
            identifier_ns_uri=namespace_uri,
            timestamp=timestamp)

        logger.debug("Creation of Placeholder for %s %s returned %s" % (namespace_uri, uid, existed))
        add_fact_kargs['value_iobject_id'] = Identifier.objects.get(uid=uid, namespace__uri=namespace_uri)

        return True


    def cybox_valueset_fact_handler(self, enrichment, fact, attr_info, add_fact_kargs):
        """
        Handler for dealing with 'value_set' values.

        Unfortunately, CybOX et al. sometimes use comma-separated
        value lists rather than an XML structure that can contain
        several values.

        This handler is called for elements concerning a value-set
        such as the following example::

            <URIObj:Value condition="IsInSet"
            value_set="www.sample1.com/index.html, sample2.com/login.html, dev.sample3.com/index/kb.html"
            datatype="AnyURI"/>

        """

        value_list = attr_info['value_set'][fact['node_id']].split(",")
        value_list = map(lambda x: x.strip(), value_list)

        add_fact_kargs['values'] = value_list

        return True


    def cybox_csv_handler(self, enrichment, fact, attr_info, add_fact_kargs):
        """
        Handler for dealing with comma-separated values.

        Unfortunately, CybOX et al. sometimes use comma-separated
        value lists rather than an XML structure that can contain
        several values.

        This handler is called for elements concerning comma-separated
        values such as the following example::

           <AddrObj:Address_Value condition="Equals" apply_condition="ANY">attacker@example.com,attacker1@example.com,attacker@bad.example.com</AddrObj:Address_Value>


        The handler itself is rather straightforward  -- here
        the difficult part is finding out when to actually apply it;
        The current specification of the predicate (see below) probably
        still misses a few cases...
        """

        # Since Cybox 2.0.1, '##comma##' is to be used instead of ','. So,
        # we first check whether '##comma##' occurs -- if so, we take
        # that as separator; if not, we take ','

        if '##comma## ' in fact['value']:
            separator = '##comma##'
        else:
            separator = ','

        value_list = map(lambda x: x.strip(), fact['value'].split(separator))

        add_fact_kargs['values'] = value_list

        return True

    def cybox_csv_predicate(self, fact, attr_info):
        """
        Predicate for dealing with comma-separated values.

        Unfortunately, CybOX et al. sometimes use comma-separated
        value lists.

        This predicate recognizes elements containing
        comma-separated values such as the following example::

           <AddrObj:Address_Value condition="Equals" apply_condition="ANY">attacker@example.com,attacker1@example.com,attacker@bad.example.com</AddrObj:Address_Value>

        TODO: There are probably more occurrences of coma-separated values in Cybox.
        """

        #
        return (attr_info.get("apply_condition", False)
                # If there is a pattern type specified, then this is no case of comma separated values
                and not attr_info.get("pattern_type", False))


    def cybox_defined_object_in_fact_term_handler(self, enrichment, fact, attr_info, add_fact_kargs):
        """
        From CybOX 1.x to Cybox 2.0.0, there was a structural change in the way
        observable properties are included in the XML: in CybOX 1.x, they
        were embedded in an element called 'Defined_Object' -- since CybOX 2.x,
        we have the 'Properties' element. Here, we rename occurrences of 'Defined_Object'
        in a fact term with 'Properties'. As a result, fact terms for, e.g.,
        'Properties/Header/To/Recipient/AddressValue' for an Email object are the same
        for imports from Cybox 1.x and Cybox 2.x.
        """
        add_fact_kargs['fact_term_name'] = self.RE_DEFINED_OBJECT.sub('Properties', fact['term'])
        return True


    def cybox_defined_object_in_fact_term_predicate(self, fact, attr_info):
        """
        From CybOX 1.x to Cybox 2.0.0, there was a structural change in the way
        observable properties are included in the XML: in CybOX 1.x, they
        were embedded in an element called 'Defined_Object' -- since CybOX 2.x,
        we have the 'Properties' element. Here, we rename occurrences of 'Defined_Object'
        in a fact term with 'Properties'. As a result, fact terms for, e.g.,
        'Properties/Header/To/Recipient/AddressValue' for an Email object are the same
        for imports from Cybox 1.x and Cybox 2.x.
        """
        return self.RE_DEFINED_OBJECT.search(fact['term'])


    def attr_ignore_predicate(self, fact_dict):
        """
        The attr_ignore predicate is called for each fact that would be generated
        for an XML attribute. It takes a fact dictionary of the following form
        as input::
               { 'node_id': 'N001:L000:N000:A000',
                 'term': 'Hashes/Hash/Simple_Hash_Value',
                 'attribute': 'condition',
                 'value': u'Equals'
               }

        If the predicate returns 'False, the fact is *not* created. Note that, nevertheless,
        during import, the information about this attribute is available to
        the attributed fact as part of the 'attr_dict' that is generated for the creation
        of each fact and passed to the handler functions called for the fact.

        """
        if '@' in fact_dict['attribute']:
            # We remove all attributes added by Dingo during import
            return True

        attr_key = fact_dict['attribute']

        cybox_attr_ignore_list = [# we drop id-attributes:
                                  # everything that has an identifier gives rise to a new object and
                                  # the identifier is used then and there,
                                  'id',
                                  'object_reference',
                                  'idref',
                                  # Type information we have already read and treated,
                                  # so no need to keep it around
                                  'xsi:type',
                                  'datatype',
                                  'type',
                                  # value_set attributes are treated by a special handler
                                  'value_set',
                                  # no need to retain the schemaLocation info on top-level.
                                  'xsi:schemaLocation'
        ]

        if attr_key in cybox_attr_ignore_list:
            return True
        return False


    def fact_handler_list(self):
        return [
            # We write the content of elements with "Raw" in the fact term to disk
            # rather than storing them in the database.
            (lambda fact, attr_info: (not fact['attribute']) and "Raw_" in fact['term'],
             self.cybox_RAW_ft_handler),
            # When we find a reference, we either retrieve the referenced object from
            # the database (if it exists) or we generate a PLACEHOLDER object
            (lambda fact, attr_info: "idref" in attr_info,
             self.reference_handler),
            # We normalize elements containing comma-separated values
            (self.cybox_csv_predicate, self.cybox_csv_handler),
            # We also normalize comma-separated values in value-set attributes
            (lambda fact, attr_info: 'value_set' in attr_info, self.cybox_valueset_fact_handler),
            # We rename 'Defined_Object' in fact terms from Cybox 1.0 to 'Properties' of Cybox 2.0
            (self.cybox_defined_object_in_fact_term_predicate, self.cybox_defined_object_in_fact_term_handler),

        ]


    #
    # Finally: we define the function that takes a fact with associated
    # attribute information and determines the fact data type for this
    # fact.
    #

    def cybox_datatype_extractor(self, enrichment, fact, attr_info, namespace_mapping, add_fact_kargs):
        """

        The datatype extractor is called for each fact with the aim of determining the fact's datatype.
        The extractor function has the following signature:

        - Inputs:
          - info_object: the information object to which the fact is to be added
          - fact: the fact dictionary of the following form::
               { 'node_id': 'N001:L000:N000:A000',
                 'term': 'Hashes/Hash/Simple_Hash_Value',
                 'attribute': 'condition' / False,
                 'value': u'Equals'
               }
          - attr_info:
            A dictionary with mapping of XML attributes concerning the node in question
            (note that the keys do *not* have a leading '@' unless it is an internally
            generated attribute by Dingo.
          - namespace_mapping:
            A dictionary containing the namespace mapping extracted from the imported XML file.
          - add_fact_kargs:
            The arguments with which the fact will be generated after all handler functions
            have been called. The dictionary contains the following keys::

                'fact_dt_kind' : <FactDataType.NO_VOCAB/VOCAB_SINGLE/...>
                'fact_dt_namespace_name': <human-readable shortname for namespace uri>
                'fact_dt_namespace_uri': <namespace uri for datataype namespace>
                'fact_term_name' : <Fact Term such as 'Header/Subject/Address'>
                'fact_term_attribute': <Attribute key such as 'category' for fact terms describing an attribute>
                'values' : <list of FactValue objects that are the values of the fact to be generated>
                'node_id_name' : <node identifier such as 'N000:N000:A000'

        Just as the fact handler functions, the datatype extractor can change the add_fact_kargs dictionary
        and thus change the way in which the fact is created -- usually, this ability is used to change
        the following items in the dictionary:

        - fact_dt_name
        - fact_dt_namespace_uri
        - fact_dt_namespace_name (optional -- the defining part is the uri)
        - fact_dt_kind

        The extractor returns "True" if datatype info was found; otherwise, False is returned
        """

        if "idref" in attr_info:
            # Set up the fact data type as a data type that expresses
            # the referencing that is going on
            embedded_type_info = attr_info.get('@embedded_type_info', None)
            logger.debug("Embedded type info %s" % embedded_type_info)
            type_info = self.derive_iobject_type(attr_info["@ns"],
                                                 embedded_type_info,
                                                 fact['term'].split('/')[-1])

            add_fact_kargs['fact_dt_name'] = type_info['iobject_type_name']
            add_fact_kargs['fact_dt_namespace_uri'] = type_info['iobject_type_namespace_uri']
            add_fact_kargs['fact_dt_kind'] = FactDataType.REFERENCE

            return True

        if "xsi:type" in attr_info:
            # Use xsi:type attribute
            add_fact_kargs['fact_dt_name'] = attr_info["xsi:type"]

        elif "datatype" in attr_info and fact['node_id'] in attr_info["datatype"]:
            # Use 'datatype' attribute
            add_fact_kargs['fact_dt_name'] = attr_info["datatype"]
        else:
            return False

        # It may be the case that the datatype information contains namespace info
        if ':' in add_fact_kargs['fact_dt_name']:
            add_fact_kargs['fact_dt_kind'] = FactDataType.VOCAB_SINGLE
            add_fact_kargs['fact_dt_namespace_name'] = add_fact_kargs['fact_dt_name'].split(':')[0]
            add_fact_kargs['fact_dt_name'] = add_fact_kargs['fact_dt_name'].split(':')[1]

            add_fact_kargs['fact_dt_namespace_uri'] = namespace_mapping.get(add_fact_kargs['fact_dt_namespace_name'],
                                                                            '%s/%s' % (DINGOS_NAMESPACE_URI, (
                                                                                enrichment.iobject_family.name)))

        return True


    def split_qname(self, cybox_id):
        """
        Separate the namespace from the identifier in a qualified name and lookup the namespace URI associated
        with the given namespace.
        """
        if ':' in cybox_id:
            (namespace, uid) = cybox_id.split(':', 1)
        else:
            namespace = None
            uid = cybox_id

        if namespace and namespace in self.namespace_dict:
            namespace_uri = self.namespace_dict[namespace]
        else:
            logger.warning("Could not retrieve namespace for identifer %s" % (cybox_id))
            # TODO: Introduce configurable URI
            namespace_uri = None

        if not namespace_uri:
            if self.default_identifier_ns_uri:
                namespace_uri = self.default_identifier_ns_uri
            else:
                namespace_uri = "%s/%s" % (DINGOS_MISSING_ID_NAMESPACE_URI_PREFIX, namespace)

        return (namespace, namespace_uri, uid)

    def derive_iobject_type(self, embedding_ns, embedded_ns, elt_name):
        """
        Derive type of information object stemming from an embedded element
        based on namespace information of embedding element, the embedded
        element itself, and the name of the element.

        """


        # Extract namespace-information

        ns_info = search_by_re_list(self.RE_LIST_NS_TYPE_FROM_NS_URL, self.namespace_dict.get(embedding_ns, ""))

        if not ns_info:
            ns_info = {}

        # This should yield the following information:
        # - For namespace of an Cybox Object such as http://cybox.mitre.org/objects#AddressObject-2:
        #   - iotype_ns = http://cybox.mitre.org/objects#AddressObject
        #   - family = cybox.mitre.org
        #   - family_tag = cybox
        #   - type = AddressObject
        #   - revision = 2
        # - For a base namespace such as http://cybox.mitre.org/common-2:
        #   - iotype_ns = http://cybox.mitre.org/common
        #   - family = cybox.mitre.org
        #   - family_tag = cybox
        #   - type = common
        #   - revision = 2

        iobject_family_name = ns_info.get('family',None)
        if not iobject_family_name:
            iobject_family_name = ""
        family_info = {}

        if ns_info.get('family_tag',None) in ['stix', 'cybox']:
            family_info = search_by_re_list(self.RE_LIST_NS_TYPE_FROM_NS_URL,
                                            self.namespace_dict.get(ns_info['family_tag'], ""))
            iobject_family_revision_name = family_info["revision"]

        else:
            iobject_family_revision_name = ns_info.get("revision",None)
        if not iobject_family_revision_name:
            iobject_family_revision_name = ''

        # We take the object type from the ``xsi:type`` attribute
        # given as in the following example::
        #    <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
        #    <cybox:Properties xsi:type="AddrObj:AddressObjectType" category="ipv4-addr">
        #
        if embedded_ns:
            namespace_uri = self.namespace_dict.get(embedded_ns, "")
            type_info = search_by_re_list(self.RE_LIST_NS_TYPE_FROM_NS_URL, namespace_uri)
            if type_info['type'] in ['common', 'cybox', 'stix']:
                iobject_type_name = elt_name
                iobject_type_namespace_uri = ns_info['iotype_ns']
                iobject_type_revision_name = ns_info['revision']
            else:
                iobject_type_namespace_uri = type_info['iotype_ns']
                iobject_type_name = type_info.get('type')#.split('Object')[0]
                iobject_type_revision_name = type_info['revision']
        else:
            iobject_type_name = elt_name
            iobject_type_revision_name = iobject_family_revision_name
            iobject_type_namespace_uri = ns_info.get("iotype_ns", "")

        if not iobject_type_revision_name:
            iobject_type_revision_name = ''

        logger.debug("Results of datatype extraction for ns %s, embedded ns %s and element name %s" % (
        embedding_ns, embedded_ns, elt_name))
        logger.debug("Family Name: %s" % iobject_family_name)
        logger.debug("Family Revision %s" % iobject_family_revision_name)
        logger.debug("Type Name %s" % iobject_type_name)
        logger.debug("Type NS URI %s" % iobject_type_namespace_uri)
        logger.debug("Type Revision %s" % iobject_type_revision_name)

        return {'iobject_type_name': iobject_type_name,
                'iobject_type_revision_name': iobject_type_revision_name,
                'iobject_type_namespace_uri': iobject_type_namespace_uri,
                'iobject_family_name': iobject_family_name,
                'iobject_family_revision_name': iobject_family_revision_name}


    def xml_import(self,
                   filepath="",
                   xml_content=None,
                   markings=None,
                   identifier_ns_uri=None,
                   **kwargs):
        """
         Import a STIX or CybOX xml  from file <filepath>.
         You can provide:

         - a list of markings with which all generated Information Objects
            will be associated (e.g., in order to provide provenance function)

         The kwargs are not read -- they are present to allow the use of the
         DingoImportCommand class for easy definition of commandline import commands
         (the class passes all command line arguments to the xml_import function, so
         without the **kwargs parameter, an error would occur.
         """

        self.default_identifier_ns_uri = identifier_ns_uri

        if not markings:
            markings = []

        # Clear internal state such that same object can be reused for
        # multiple imports.

        self.__init__()


        # Use the generic XML import customized for STIX/CybOX import
        # to turn XML into DingoObjDicts

        import_result = MantisImporter.xml_import(xml_fname=filepath,
                                                  xml_content=xml_content,
                                                  ns_mapping=self.namespace_dict,
                                                  embedded_predicate=self.stix_embedding_pred,
                                                  id_and_revision_extractor=self.id_and_revision_extractor)

        id_and_rev_info = import_result['id_and_rev_info']
        elt_name = import_result['elt_name']
        elt_dict = import_result['dict_repr']
        file_content = import_result['file_content']
        embedded_objects = import_result['embedded_objects']
        unprocessed_list = import_result['unprocessed']






        # TODO: Below not needed?!
        #toplevel_attribute_keys = filter(lambda x: x[0] == '@', elt_dict.keys())

        #for key in toplevel_attribute_keys:
        #    self.toplevel_attrs[key] = elt_dict[key]


        pending_stack = [(id_and_rev_info, elt_name, elt_dict)]

        for embedded_object in embedded_objects:
            id_and_rev_info = embedded_object['id_and_rev_info']
            elt_name = embedded_object['elt_name']
            elt_dict = embedded_object['dict_repr']
            pending_stack.append((id_and_rev_info, elt_name, elt_dict))

        for (id_and_rev_info, elt_name, elt_dict) in pending_stack:
            self.iobject_import(id_and_rev_info,
                                elt_name,
                                elt_dict,
                                markings=markings)

        for unprocessed_elt in unprocessed_list:
            (id_and_rev_info,typeinfo,xml_node) = unprocessed_elt
            processor_class = self.processors.get(id_and_rev_info['defer_processing']['processor'],None)
            if processor_class:
                processor = processor_class(namespace_dict=self.namespace_dict)

                processor.xml_import(self,
                                     xml_content=xml_node,
                                     markings=markings,
                                     identifier_ns_uri=self.namespace_dict[id_and_rev_info['id'].split(':')[0]]
                )
            else:
                logger.error("Did not find a processor for %s" % id_and_rev_info['defer_processing']['processor'])



    def iobject_import(self,
                       id_and_rev_info,
                       elt_name,
                       obj_dict,
                       markings=None,
                       cybox_id=None):
        """


        """

        iobject_type_ns = None

        # Derive the namespace information
        if ('@xsi:type' in obj_dict or
                    '@@embedded_type_info' in obj_dict or
                    '@xsi:type' in obj_dict.get('Properties', {}) or
                    '@xsi:type' in obj_dict.get('Defined_Object', {}) ):
            if '@xsi:type' in obj_dict:
                iobject_type_ns = obj_dict['@xsi:type'].split(':')[0]
            elif '@xsi:type' in obj_dict.get('Properties', {}):
                iobject_type_ns = obj_dict['Properties']['@xsi:type'].split(':')[0]
            elif '@xsi:type' in obj_dict.get('Defined_Object', {}):
                iobject_type_ns = obj_dict['Defined_Object']['@xsi:type'].split(':')[0]
            else:
                iobject_type_ns = obj_dict['@@embedded_type_info']

        # Find out what the type of the Information Object to be created should be
        type_info = self.derive_iobject_type(obj_dict['@@ns'], iobject_type_ns, elt_name)

        if not id_and_rev_info['id']:
            logger.error("Attempt to import object (element name %s) without id -- object is ignored" % elt_name)
            return
            #cybox_id = gen_cybox_id(iobject_type_name)

        (namespace, namespace_uri, uid) = self.split_qname(id_and_rev_info['id'])

        (info_obj, existed) = MantisImporter.create_iobject(iobject_family_name=type_info['iobject_family_name'],
                                                            iobject_family_revision_name=type_info[
                                                                'iobject_family_revision_name'],
                                                            iobject_type_name=type_info['iobject_type_name'],
                                                            iobject_type_namespace_uri=type_info[
                                                                'iobject_type_namespace_uri'],
                                                            iobject_type_revision_name=type_info[
                                                                'iobject_type_revision_name'],
                                                            iobject_data=obj_dict,
                                                            uid=uid,
                                                            identifier_ns_uri=namespace_uri,
                                                            timestamp=self.import_data['last_timestamp'],
                                                            create_timestamp=self.create_timestamp,
                                                            markings=markings,
                                                            config_hooks={
                                                            'special_ft_handler': self.fact_handler_list(),
                                                            'datatype_extractor': self.cybox_datatype_extractor,
                                                            'attr_ignore_predicate': self.attr_ignore_predicate},
                                                            namespace_dict=self.namespace_dict,
        )

        return (info_obj, existed)








