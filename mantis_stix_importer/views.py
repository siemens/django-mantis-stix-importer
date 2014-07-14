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
            indicator_node_data = graph.node[indicator_node]
            indicator_data = {'node' : indicator_node_data,
                              'title' : "Indicator: %s" % indicator_node_data['name'] }

            # calculate reachable objects

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

            indicator_info.append(indicator_data)

        context['indicators'] = indicator_info



        context['show_datatype'] = self.request.GET.get('show_datatype',False)
        context['show_NodeID'] = self.request.GET.get('show_nodeid',False)

        try:
            context['highlight'] = self.request.GET['highlight']
        except KeyError:
            context['highlight'] = None

        return context

