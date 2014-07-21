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

from dingos.models import InfoObject

from dingos.view_classes import BasicDetailView

class IndicatorView(BasicDetailView):

    model = InfoObject

    template_name = 'mantis_stix_importer/%s/details/IndicatorView.html' % DINGOS_TEMPLATE_FAMILY

    title = 'Indicator'

    def get_context_data(self, **kwargs):

        context = super(IndicatorView, self).get_context_data(**kwargs)

        context['graph'] = InfoObject.annotated_graph([self.object.pk])

        context['show_datatype'] = self.request.GET.get('show_datatype',False)
        context['show_NodeID'] = self.request.GET.get('show_nodeid',False)

        try:
            context['highlight'] = self.request.GET['highlight']
        except KeyError:
            context['highlight'] = None

        return context



class StixPackageView(BasicDetailView):

    model = InfoObject

    template_name = 'mantis_stix_importer/%s/details/StixPackageView.html' % DINGOS_TEMPLATE_FAMILY

    title = 'STIX Package'


    def get_context_data(self, **kwargs):

        context = super(StixPackageView, self).get_context_data(**kwargs)

        # Generate graph starting with this object

        obj_pk = self.object.id

        graph = InfoObject.annotated_graph([obj_pk])

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
                              'filter' : [(lambda x: 'STIX_Header' in x.fact.fact_term.term)]}



        # extract nodes that are 'Indicators'
        indicator_nodes =  [e[1] for e in edges_from_top if "Indicator" in e[2]['term'][0]]
        print indicator_nodes

        indicator_info = []

        for indicator_node in indicator_nodes:
            indicator_data = {
                'pk' : indicator_node,
                }
            indicator_info.append(indicator_data)

        context['indicators'] = indicator_info

        context['graph'] = graph

        context['show_datatype'] = self.request.GET.get('show_datatype',False)
        context['show_NodeID'] = self.request.GET.get('show_nodeid',False)

        try:
            context['highlight'] = self.request.GET['highlight']
        except KeyError:
            context['highlight'] = None

        return context

