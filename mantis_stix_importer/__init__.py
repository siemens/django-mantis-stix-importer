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

__version__ = '0.3.0'


RAW_DATA_TO_DB_FOR_LENGTH_LESS_THAN = 256

STIX_POSTPROCESSOR_REGISTRY = {'hashes':{'module':'mantis_stix_importer.postprocessors',
                                         'class' : 'hashes',
                                         'name' : 'CybOX Hash Value Export'},
                               'ips':{'module': 'mantis_stix_importer.postprocessors',
                                      'class': 'ips',
                                      'name' : 'CybOX IP Export'},
                               'fqdns':{'module': 'mantis_stix_importer.postprocessors',
                                        'class': 'fqdns',
                                        'name' : 'CybOX FQDN Export'},
                               'email_addresses':{'module': 'mantis_stix_importer.postprocessors',
                                        'class': 'email_addresses',
                                        'name' : 'CybOX Email Address Export'},
                               'cybox_all' : {# To combine several exporters into one,
                                              # define a predicate that takes a pair consisting
                                              # of the key (e.g., 'hashes') and the
                                              # associated dictionary value and returns True or False.
                                              # If True is returned for a particular entry
                                              # of the postprocessor registry, then
                                              # the importer is added to the list of importers
                                              # represented by the present entry.
                                              'postprocessor_predicate' :
                                              (lambda x,y: 'mantis_stix_importer' in y.get('module','')),
                                          'name': 'CybOX Combined Export'},
                               'csv': {'module': 'dingos.core.extractors',
                                        'class': 'csv_export',
                                        'name' : 'Generic CSV export',
                                        'search_only' : True},
                               'json': {'module': 'dingos.core.extractors',
                                        'class': 'json_export',
                                        'name' : 'Generic JSON export',
                                        'search_only' : True},
                               'table': {'module': 'dingos.core.extractors',
                                         'class': 'table_view',
                                        'name' : 'Table View',
                                        'search_only' : True},
                               }

STIX_OBJECTTYPE_VIEW_MAPPING = {
    'stix.mitre.org': {
        'STIX_Package': 'url.mantis_stix_importer.view.details.stix_package.standard',
        'Indicator':    'url.mantis_stix_importer.view.details.indicator.standard',
        'Observable':   'url.mantis_stix_importer.view.details.observable.standard'
    },
    'cybox.mitre.org': {
        'Observable':   'url.mantis_stix_importer.view.details.observable.standard'
    },
}


STIX_OBJECTTYPE_ICON_MAPPING = {'stix.mitre.org':
                                    {'STIX_Package' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/stix.png",
                                          'x': -15,
                                          'y': -15,
                                          'width': 30,
                                          'height' : 30
                                         },
                                      'Incident' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/incident.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Indicator' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/indicator.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Campaign' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/campaign.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'TTP' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/ttp.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'CourseOfAction' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/course_of_action.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'ThreatActor' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/threat_actor.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Exploit_Target' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/exploit_target.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observable' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observables' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                    },
                                'cybox.mitre.org':
                                    {'Observable' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observable_w_single_obj' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/observable_mix.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observables' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     },
                                'data-marking.mitre.org':
                                    {'Marking' :
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/data_marking.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                    },
                                'ioc.mandiant.com':
                                    {'ioc' : 
                                         {'xlink:href': "/static/mantis_stix_importer/img/icons/open_ioc.png",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     },

}



STIX_OBJECTTYPE_ICON_RELIST_MAPPING = {}


