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

from django import template


from dingos import DINGOS_TEMPLATE_FAMILY


register = template.Library()

from dingos import graph_utils

# Below we register template tags that display
# certain aspects of an InformationObject.

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Indicator_View_standard.html'% DINGOS_TEMPLATE_FAMILY,takes_context=True)
def show_Indicator(context,graph,
                   indicator_node,
                   stand_alone=False):
    indicator_node_data = graph.node[indicator_node]
    indicator_data = {'node' : indicator_node_data,
                      'title' : "Indicator: %s" % indicator_node_data['name'] }

    obj_pk_list = list(graph_utils.dfs_preorder_nodes(graph,
                                                      source=int(indicator_node),
                                                      edge_pred= (lambda x : not 'Related' in x['term'][0])
    )
    )
    obj_list = []
    for obj_pk in obj_pk_list:

        obj_node_data = graph.node[obj_pk]
        if 'Object' in obj_node_data['iobject_type']:
            obj_data = {'node': obj_node_data,
                        'title': "%s: %s" % (obj_node_data['iobject_type'].replace('Object',''),obj_node_data['name'])}
            obj_data['filter'] =  [(lambda x: not 'Related' in x.fact.fact_term.term)]
            obj_list.append(obj_data)

    indicator_data['objects'] = obj_list
    indicator_data['filter'] =  [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['indicator'] = indicator_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Observable_View_standard.html'% DINGOS_TEMPLATE_FAMILY,takes_context=True)
def show_Observable(context,graph,
                   observable_node,
                   stand_alone=False):
    observable_node_data = graph.node[observable_node]
    observable_data = {'node' : observable_node_data,
                      'title' : "%s" % observable_node_data['name'] }

    obj_pk_list = list(graph_utils.dfs_preorder_nodes(graph,
                                                      source=int(observable_node),
                                                      edge_pred= (lambda x : not 'Related' in x['term'][0])
    )
    )
    obj_list = []
    for obj_pk in obj_pk_list:

        obj_node_data = graph.node[obj_pk]
        if 'Object' in obj_node_data['iobject_type']:
            obj_data = {'node': obj_node_data,
                        'title': "%s: %s" % (obj_node_data['iobject_type'].replace('Object',''),obj_node_data['name'])}
            obj_data['filter'] =  [(lambda x: not 'Related' in x.fact.fact_term.term)]
            obj_list.append(obj_data)

    observable_data['objects'] = obj_list
    observable_data['filter'] =  [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['observable'] = observable_data
    context['stand_alone'] = stand_alone
    return context






__author__ = 'root'
