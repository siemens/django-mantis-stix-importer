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
from dingos.models import InfoObject


def iobject2facts(object):
    return object.fact_thru.all().prefetch_related(
        'fact__fact_term',
        'fact__fact_values',
        'fact__fact_values__fact_data_type',
        'fact__value_iobject_id',
        'fact__value_iobject_id__latest',
        'fact__value_iobject_id__latest__iobject_type',
        'node_id')

def xiobject2facts(object):
    return object.fact_thru.all().values_list(
        'fact__fact_term__term',
        'fact__fact_term__attribute',
        'fact__fact_values',
        'fact__fact_values__fact_data_type',
        'fact__value_iobject_id',
        'fact__value_iobject_id__latest',
        'fact__value_iobject_id__latest__iobject_type',
        'node_id')


def extract_ips(object_list,*args,**kwargs):
    object_fact_mapping = {}
    for object in object_list:
        object_fact_mapping[object.pk] = iobject2facts(object)

    result = StringIO.StringIO()
    for io2f_list in object_fact_mapping.values():
        pass
        #result.write("%s" % io2f_list.filter(fact__fact_term__term__icontains='Data'))
        #for io2f in io2f_list:
        #    result.write("%s\n" % io2f.fact.fact_term.term)
        #result.write(map(lambda x : x.value, (list(fact_list[0].fact.fact_values.all()))))

    return ('text',"%s"% result.getvalue())
