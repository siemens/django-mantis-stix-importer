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
from dingos import graph_utils
from mantis_stix_importer import STIX_OBJECTTYPE_ICON_MAPPING


register = template.Library()



# Below we register template tags that display
# certain aspects of an InformationObject.

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Indicator_View_standard.html'% DINGOS_TEMPLATE_FAMILY,takes_context=True)
def show_Indicator(context,graph,
                   indicator_node,
                   stand_alone=False):
    indicator_node_data = graph.node[indicator_node]
    indicator_data = {'node' : indicator_node_data,
                      'pk': indicator_node,
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
                        'pk': obj_pk,
                        'title': "%s: %s" % (obj_node_data['iobject_type'].replace('Object',''),obj_node_data['name'])}
            obj_data['filter'] =  [(lambda x: not 'Related' in x.fact.fact_term.term)]
            obj_list.append(obj_data)

    indicator_data['objects'] = obj_list
    indicator_data['filter'] =  [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['indicator'] = indicator_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_TTP_View_standard.html'% DINGOS_TEMPLATE_FAMILY, takes_context=True)
def show_TTP(context,graph,
             ttp_node,
             stand_alone=False):
    ttp_node_data = graph.node[ttp_node]
    ttp_data = {'node' : ttp_node_data,
                'pk': ttp_node,
                         'title' : "TTP: %s" % ttp_node_data['name'] }
    ttp_data['filter'] = [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['ttp'] = ttp_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Incident_View_standard.html'% DINGOS_TEMPLATE_FAMILY, takes_context=True)
def show_Incident(context,graph,
             incident_node,
             stand_alone=False):
    incident_node_data = graph.node[incident_node]
    incident_data = {'node' : incident_node_data,
                     'pk': incident_node,
                         'title' : "Incident: %s" % incident_node_data['name'] }
    incident_data['filter'] = [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['incident'] = incident_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Course_Of_Action_View_standard.html'% DINGOS_TEMPLATE_FAMILY, takes_context=True)
def show_Course_Of_Action(context,graph,
             course_of_action_node,
             stand_alone=False):
    course_of_action_node_data = graph.node[course_of_action_node]
    course_of_action_data = {'node' : course_of_action_node_data,
                             'pk': course_of_action_node,
                         'title' : "Course of action: %s" % course_of_action_node_data['name'] }
    course_of_action_data['filter'] = [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['course_of_action'] = course_of_action_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Campaign_View_standard.html'% DINGOS_TEMPLATE_FAMILY, takes_context=True)
def show_Campaign(context,graph,
             campaign_node,
             stand_alone=False):
    campaign_node_data = graph.node[campaign_node]
    campaign_data = {'node' : campaign_node_data,
                     'pk': campaign_node,
                         'title' : "Campaign: %s" % campaign_node_data['name'] }
    campaign_data['filter'] = [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['campaign'] = campaign_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Threat_Actor_View_standard.html'% DINGOS_TEMPLATE_FAMILY, takes_context=True)
def show_Threat_Actor(context,graph,
                      threat_actor_node,
                      stand_alone=False):
    threat_actor_node_data = graph.node[threat_actor_node]
    threat_actor_data = {'node' : threat_actor_node_data,
                         'pk': threat_actor_node,
                         'title' : "Threat actor: %s" % threat_actor_node_data['name'] }
    threat_actor_data['filter'] = [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['threat_actor'] = threat_actor_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Observable_View_standard.html'% DINGOS_TEMPLATE_FAMILY,takes_context=True)
def show_Observable(context,graph,
                   observable_node,
                   stand_alone=False):
    observable_node_data = graph.node[observable_node]
    observable_data = {'node' : observable_node_data}

    if observable_node_data['name']:
        observable_data['title'] = "%s" % observable_node_data['name']
    else:
        observable_data['title'] = observable_node_data['identifier_uid']

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
                        'pk': obj_pk,
                        'title': "%s: %s" % (obj_node_data['iobject_type'].replace('Object',''),obj_node_data['name'])}
            obj_data['filter'] =  [(lambda x: not 'Related' in x.fact.fact_term.term)]
            obj_list.append(obj_data)

    observable_data['objects'] = obj_list
    observable_data['filter'] =  [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['observable'] = observable_data
    context['stand_alone'] = stand_alone
    return context

@register.inclusion_tag('mantis_stix_importer/%s/includes/_Observable_View_details.html'% DINGOS_TEMPLATE_FAMILY,takes_context=True)
def show_ObservableDetails(context,graph, observable_node, stand_alone=False):
    observable_node_data = graph.node[observable_node]
    observable_data = {
        'node': observable_node_data,
        'pk': obj_pk,
        'title': "%s" % observable_node_data['name'],
    }

    obj_pk_list = list(graph_utils.dfs_preorder_nodes(
        graph,
        source=int(observable_node),
        edge_pred=(lambda x: not 'Related' in x['term'][0])
    ))
    obj_list = []
    for obj_pk in obj_pk_list:
        obj_node_data = graph.node[obj_pk]
        if 'Object' in obj_node_data['iobject_type']:
            obj_list.append({
                'node': obj_node_data,
                'pk': obj_pk,
                'title': "%s: %s" % (obj_node_data['iobject_type'].replace('Object', ''), obj_node_data['name']),
                'filter': [(lambda x: not 'Related' in x.fact.fact_term.term)],
            })

    observable_data['objects'] = obj_list
    observable_data['filter'] = [(lambda x: 'Description' in x.fact.fact_term.term)]

    context['observable'] = observable_data
    context['stand_alone'] = stand_alone

    return context


@register.simple_tag
def get_StixIcon(icon_name, icon_namespace=False):
    """
    Returns the icon for a icon_name. Return first found icon name
    """

    if icon_namespace and icon_namespace in STIX_OBJECTTYPE_ICON_MAPPING:
        el = STIX_OBJECTTYPE_ICON_MAPPING[icon_namespace].get(icon_name, {})
        return el.get('xlink:href', '')

    for ns, icon_ns in STIX_OBJECTTYPE_ICON_MAPPING.iteritems():
        for icon, icon_prop in icon_ns.iteritems():
            if icon==icon_name:
                return icon_prop['xlink:href']
    return ''
