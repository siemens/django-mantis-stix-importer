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


from django.conf.urls import patterns, url
from django.core.urlresolvers import reverse
from django.shortcuts import redirect

from . import views

from dingos.view_classes import SimpleMarkingAdditionView



urlpatterns = patterns('',

                       url(r'^View/InfoObject/(?P<pk>\d*)/specific/stix_package$',
                           views.StixPackageView.as_view(),
                           name= "url.mantis_stix_importer.view.details.stix_package.standard"),

                       url(r'^View/InfoObject/(?P<pk>\d*)/specific/indicator$',
                           views.IndicatorView.as_view(),
                           name= "url.mantis_stix_importer.view.details.indicator.standard"),

    )

