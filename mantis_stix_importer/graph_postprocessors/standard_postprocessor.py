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

def process(graph):
    """
    Merges Observables with the connected InfoObjects if only one InfoObject is referenced by the affected Observable
    """

    # Collect unnecessary Observables
    observables = {}
    for node in graph.nodes():
        if 'Observable' in graph.node[node]['iobject_type']:
            if graph.out_degree(node) == 1:
                outgoing_edge = graph.out_edges(node)[0]
                if not 'Observable' in graph.node[outgoing_edge[1]]['iobject_type']:
                    observables[node] = {}
                    observables[node]['outgoing_edge'] = graph.out_edges(node)[0]
                    observables[node]['ingoing_edges'] = graph.in_edges(node)

    # Add new and delete unnecessary references
    for key in observables.keys():
        observable = observables[key]
        outgoing_edge = observable['outgoing_edge']
        for ingoing_edge in observable['ingoing_edges']:
            # Add bridge from incoming to outgoing neighbor of Observable
            graph.add_edge(ingoing_edge[0], outgoing_edge[1])
            # Remove old connection of observable
            graph.remove_edge(ingoing_edge[0], ingoing_edge[1])

    # Delete unnecessary Observables
    for node in graph.nodes():
        if 'Observable' in graph.node[node]['iobject_type']:
            if len(graph.in_edges(node)) == 0:
                graph.remove_node(node)

    return graph
