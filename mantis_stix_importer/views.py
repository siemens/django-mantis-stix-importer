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

from dingos import graph_utils

from dingos import DINGOS_TEMPLATE_FAMILY

from dingos.models import InfoObject,Identifier

from dingos.views import InfoObjectView,getTags

class IndicatorView(InfoObjectView):

    model = InfoObject

    template_name = 'mantis_stix_importer/%s/details/IndicatorView.html' % DINGOS_TEMPLATE_FAMILY

    title = 'Indicator'

    def get_context_data(self, **kwargs):

        context = super(IndicatorView, self).get_context_data(**kwargs)

        graph = InfoObject.annotated_graph([self.object.pk])
        context['graph'] = graph

        io2fvs  = graph.graph['io2fvs']
        context['io2fvs'] = io2fvs

        identifier_list = set([x.identifier.id for x in io2fvs])

        context['tag_dict'] = getTags(identifier_list,complex=True,model=Identifier)

        context['show_datatype'] = self.request.GET.get('show_datatype',False)
        context['show_NodeID'] = self.request.GET.get('show_nodeid',False)

        try:
            context['highlight'] = self.request.GET['highlight']
        except KeyError:
            context['highlight'] = None

        return context


class ObservableView(InfoObjectView):

    model = InfoObject

    template_name = 'mantis_stix_importer/%s/details/ObservableView.html' % DINGOS_TEMPLATE_FAMILY

    title = 'Observable'

    def get_context_data(self, **kwargs):

        context = super(ObservableView, self).get_context_data(**kwargs)

        graph = InfoObject.annotated_graph([self.object.pk])
        context['graph'] = graph

        io2fvs  = graph.graph['io2fvs']
        context['io2fvs'] = io2fvs

        identifier_list = set([x.identifier.id for x in io2fvs])

        context['tag_dict'] = getTags(identifier_list,complex=True,model=Identifier)

        context['show_datatype'] = self.request.GET.get('show_datatype',False)
        context['show_NodeID'] = self.request.GET.get('show_nodeid',False)

        try:
            context['highlight'] = self.request.GET['highlight']
        except KeyError:
            context['highlight'] = None

        return context


class StixPackageView(InfoObjectView):

    model = InfoObject

    template_name = 'mantis_stix_importer/%s/details/StixPackageView.html' % DINGOS_TEMPLATE_FAMILY

    title = 'STIX Package'


    def get_context_data(self, **kwargs):

        context = super(StixPackageView, self).get_context_data(**kwargs)

        # Generate graph starting with this object

        obj_pk = self.object.id

        graph = InfoObject.annotated_graph([obj_pk])
        context['graph'] = graph

        io2fvs  = graph.graph['io2fvs']
        context['io2fvs'] = io2fvs

        identifier_list = set([x.identifier.id for x in io2fvs])

        context['tag_dict'] = getTags(identifier_list,complex=True,model=Identifier)

        # get all edges that originate from this object

        edges_from_top = graph.edges(nbunch=[obj_pk], data = True)


        edges_from_top.sort(key= lambda x : x[2]['fact_node_id'])

        # show edges to/from top-level object in console to see what
        # they look like

        # We want to center this view around indicators. So let us
        # view which indicators are on top-level of the report

        # get Package Info

        package_node_data = graph.node[obj_pk]

        context['package'] = {'node' : package_node_data,
                              'filter' : [(lambda x: 'STIX_Header' in x.term)]}

        # extract cyber threat information nodes
        observable_info = []
        indicator_info = []
        ttp_info = []
        incident_info = []
        course_of_action_info = []
        campaign_info = []
        threat_actor_info = []
        for e in edges_from_top:
            data = {'pk': e[1]}
            if "Observable" in e[2]['term'][0]:
                observable_info.append(data)
            elif "Indicator" in e[2]['term'][0]:
                indicator_info.append(data)
            elif "TTP" in e[2]['term'][0]: #todo
                ttp_info.append(data)
            elif "Incident" in e[2]['term'][0]: #todo
                incident_info.append(data)
            elif "Course_Of_Action" in e[2]['term'][0]: #todo
                course_of_action_info.append(data)
            elif "Campaign" in e[2]['term'][0]: #todo
                campaign_info.append(data)
            elif "Threat_Actor" in e[2]['term'][0]:
                threat_actor_info.append(data)
        context['observables'] = observable_info
        context['indicators'] = indicator_info
        context['ttps'] = ttp_info
        context['incidents'] = incident_info
        context['courses_of_action'] = course_of_action_info
        context['campaigns'] = campaign_info
        context['threat_actors'] = threat_actor_info

        context['graph'] = graph

        context['show_datatype'] = self.request.GET.get('show_datatype',False)
        context['show_NodeID'] = self.request.GET.get('show_nodeid',False)

        try:
            context['highlight'] = self.request.GET['highlight']
        except KeyError:
            context['highlight'] = None

        return context
