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

__version__ = '0.2.0'


RAW_DATA_TO_DB_FOR_LENGTH_LESS_THAN = 256


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
                                         {'xlink:href': "/static/img/icons/stix.png",
                                          'x': -15,
                                          'y': -15,
                                          'width': 30,
                                          'height' : 30
                                         },
                                      'Incident' :
                                         {'xlink:href': "/static/img/icons/incident.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Indicator' :
                                         {'xlink:href': "/static/img/icons/indicator.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Campaign' :
                                         {'xlink:href': "/static/img/icons/campaign.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'TTP' :
                                         {'xlink:href': "/static/img/icons/ttp.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'CourseOfAction' :
                                         {'xlink:href': "/static/img/icons/course_of_action.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'ThreatActor' :
                                         {'xlink:href': "/static/img/icons/threat_actor.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Exploit_Target' :
                                         {'xlink:href': "/static/img/icons/exploit_target.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observable' :
                                         {'xlink:href': "/static/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observables' :
                                         {'xlink:href': "/static/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                    },
                                'cybox.mitre.org':
                                    {'Observable' :
                                         {'xlink:href': "/static/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     'Observables' :
                                         {'xlink:href': "/static/img/icons/observable.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     },
                                'data-marking.mitre.org':
                                    {'Marking' :
                                         {'xlink:href': "/static/img/icons/data_marking.svg",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                    },
                                'ioc.mandiant.com':
                                    {'ioc' : 
                                         {'xlink:href': "/static/img/icons/open_ioc.png",
                                          'x': -8,
                                          'y': -8,
                                          'width': 16,
                                          'height' : 16
                                         },
                                     },

}



STIX_OBJECTTYPE_ICON_RELIST_MAPPING = {}


