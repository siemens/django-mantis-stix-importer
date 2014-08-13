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

import StringIO
import networkx
from dingos.models import InfoObject,InfoObject2Fact
from dingos.core.utilities import set_dict, get_dict
from django.core.urlresolvers import reverse



class InfoObjectDetails(object):


    def __init__(self,*args,**kwargs):
        self.object_list = kwargs.pop('object_list',[])
        self.graph = kwargs.pop('graph',None)

        self.iobject_map = None
        self.io2fs = []

        self.node_map = None



        if self.object_list:
            self.io2fs = self._get_io2fs(map(lambda o:o.pk,list(self.object_list)))
            self.set_iobject_map()

        elif self.graph:
            self.io2fs = self._get_io2fs(self.graph.nodes())



    def _get_io2fs(self,object_pks):

        io2fs= InfoObject2Fact.objects.filter(iobject__id__in=object_pks).prefetch_related( 'iobject',
                                                                                                'iobject__identifier',
                                                                                                'iobject__identifier__namespace',
                                                                                                'iobject__iobject_family',
                                                                                                'iobject__iobject_type',
                                                                                                'fact__fact_term',
                                                                                                'fact__fact_values',
                                                                                                'fact__fact_values__fact_data_type',
                                                                                                'fact__value_iobject_id',
                                                                                                'fact__value_iobject_id__latest',
                                                                                                'fact__value_iobject_id__latest__iobject_type',
                                                                                                'node_id').order_by('iobject__id','node_id__name')

        return io2fs

    def _annotate_graph(self,G):
        for fact in self.io2fs:
            G.node[fact.iobject.id]['iobject'] = fact.iobject
            G.node[fact.iobject.id]['facts'].append(fact)
        self.iobject_map = G.node


    def set_iobject_map(self):

        if self.iobject_map == None:
            self.iobject_map = {}
            for io2f in self.io2fs:
                set_dict(self.iobject_map,io2f.iobject,'set', io2f.iobject.id, 'iobject')
                set_dict(self.iobject_map,io2f,'append', io2f.iobject.id,'facts')

            for obj_pk in self.iobject_map:
                node_dict = self.iobject_map[obj_pk]
                try:
                    url = reverse('url.dingos.view.infoobject', args=[obj_pk])
                except:
                    url = None
                node_dict['url'] = url
                node_dict['identifier_ns'] =  node_dict['iobject'].identifier.namespace.uri
                node_dict['identifier_uid'] =  node_dict['iobject'].identifier.uid
                node_dict['name'] = node_dict['iobject'].name
                node_dict['iobject_type'] = node_dict['iobject'].iobject_type.name
                node_dict['iobject_type_family'] = node_dict['iobject'].iobject_type.iobject_family.name



    def set_node_map(self):

        if self.node_map == None:
            self.node_map = {}

            for io2f in self.io2fs:

                set_dict(self.node_map,io2f.fact,'set_value', io2f.iobject.id, *io2f.node_id.name.split(':'))

    def get_attributes(self,io2f):
        self.set_node_map()
        node_id = io2f.node_id.name.split(':')
        results = {}

        def get_attributes_rec(node_id,walker,results):
            for child_key in walker:
                if child_key[0] == 'A':
                    if node_id and child_key == node_id[0]:
                        continue
                    else:
                        attribute_fact = walker[child_key]['_value']
                        set_dict(results, (attribute_fact.fact_values.all()[0].value,attribute_fact.fact_term.term), 'append', attribute_fact.fact_term.attribute)
            if node_id != []:
                return get_attributes_rec(node_id[1:],walker[node_id[0]],results)
            else:
                return results
        return get_attributes_rec(node_id,self.node_map[io2f.iobject.id],results)

    def get_siblings(self,io2f):
        self.set_node_map()
        node_id = io2f.node_id.name.split(':')
        results = []
        if node_id:
            parent_id = node_id[0:-1]
            self_id = node_id[-1]

            print parent_id
            sibling_dict = get_dict(self.node_map[io2f.iobject.pk],*parent_id)
            print sibling_dict
            if sibling_dict:
                for key in sibling_dict:
                    if key[0] == self_id[0] and key != self_id:
                        sibling = sibling_dict[key].get('_value',None)
                        if sibling:
                            results.append(sibling)
        return results



def extract_ips(object_list,*args,**kwargs):

    io2f_repr = InfoObjectDetails(object_list=object_list) # get_io2fs(map(lambda o:o.pk,list(object_list)))

    result = StringIO.StringIO()


    result.write(io2f_repr.iobject_map)

    for io2f in io2f_repr.io2fs:
        if 'Value' in io2f.fact.fact_term.term:
            for fact_value in io2f.fact.fact_values.all():
                result.write("%s: %s\n" %  (io2f.fact.fact_term,fact_value.value))
            result.write("Attributes: %s\n" % io2f_repr.get_attributes(io2f))
            result.write("Siblings: %s\n" % io2f_repr.get_siblings(io2f))

    counter = 0
    for object in io2f_repr.iobject_map:
        result.write('%s --- %s\n' % (counter,io2f_repr.iobject_map[object]['iobject'].name))
        counter += 1
        for io2f in io2f_repr.iobject_map[object]['facts']:
            result.write("%s: %s\n" % (io2f.fact.fact_term.term,io2f.fact.fact_values.all()[0]))

    return ('text',"%s"% result.getvalue())



def extract_ips(graph_or_object_list,*args,**kwargs):

    # Retrieve details about InfoObjects contained in graph
    # or object_list (whatever has been passed to the function

    if isinstance(graph_or_object_list,networkx.MultiDiGraph):
        iobject_details = InfoObjectDetails(graph=graph_or_object_list)
    else:
        iobject_details = InfoObjectDetails(object_list=graph_or_object_list)

    # Now we have the following we can work with:
    # - iobject_details.io2fs:
    #    List of all InfoObject2Fact instances contained in any of the objects
    #    passed to the function (either as graph or object list).
    #    We work with this directly if we do not care about the objects
    #    to which a fact belongs. This is the case for extractors that
    #    simply try to extract all information of a certain kind
    #    (e.g., all hash values) that are contained in the list of objects
    # - iobject_details.iobject_map:
    #    A mapping of object primary keys to a structure of the following form::
    #       {'identifier_ns': <identifier namespace uri>,
    #        'identifier_uid': <identifier uid>,
    #        'name': <object name>,
    #        'iobject_type': <info object type, eg.g 'WinExecutableFile'>
    #        'iobject_type_family': <info object type family, e.g. 'cybox.mitre.org'>,
    #        'iobject': <InfoObject instance>
    #        'url': <url under which object can be viewed: '/mantis/View/InfoObject/<pk>/'>,
    #        'facts': <list of InfoObject2Fact instances contained in info object>
    #       }
    #
    #   The same information is available in the graph node (if a graph has been passed)
    #   and can be access via 'graph.node[<pk>]

    # We decide to extract all hash-values along with their hash type

    results = []
    for io2f in iobject_details.io2fs:
        if 'Simple_Hash_Value' in io2f.fact.fact_term.term:
            hash_value = io2f.fact.fact_values.all()[0]
            siblings = iobject_details.get_siblings(io2f)
            for sibling in siblings:
                hash_type = None
                if 'Hash/Type' in sibling.fact_term.term:
                    hash_type = sibling.fact_values.all()[0].value
                    break
            results.append({'hash_type':hash_type,
                            'hash_value':hash_value.value,
                            'uri': iobject_details.iobject_map[io2f.iobject.pk]['url']})
    return ('text',"%s"% results)










