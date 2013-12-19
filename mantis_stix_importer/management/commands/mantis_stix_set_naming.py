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

import sys

import pprint

from django.core.management.base import BaseCommand, CommandError
from optparse import make_option

from dingos.models import InfoObjectType, InfoObjectNaming

from dingos.management.commands.dingos_manage_naming_schemas import Command as ManageCommand


schema_list = [

    [
        "ioc",
        "ioc.mandiant.com",
        "http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1",
        [
            "[short_description]",
        ]
    ],


    [
        "STIX_Package",
        "stix.mitre.org",
        "http://stix.mitre.org/stix",
        [
            "[STIX_Header/Title] ([Package_Intent])",
            "[STIX_Header/Title]",
            "[STIX_Header/Description] ([Package_Intent])",
            "[STIX_Header/Description]"
        ]
    ],
    [
        "Marking",
        "data-marking.mitre.org",
        "http://data-marking.mitre.org/Marking",
        [
            "[Marking_Structure@color]",
            "[Marking_Structure/Statement]"
        ]
    ],
    [
        "Indicator",
        "stix.mitre.org",
        "http://stix.mitre.org/Indicator",
        [
            "[Title]",
            "[Description]"
        ]
    ],
    [
        "WinExecutableFileObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinExecutableFileObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinRegistryKeyObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinRegistryKeyObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinServiceObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinServiceObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinProcessObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinProcessObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinDriverObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinDriverObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "ProcessObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#ProcessObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "APIObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#APIObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "AccountObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#AccountObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "AddressObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#AddressObject",
        [
            "[Properties/Address_Value] (category [Properties/Address_Value@category]) ([fact_count] facts)"
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "ArtifactObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#ArtifactObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "CodeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#CodeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "CustomObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#CustomObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "DNSCacheObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#DNSCacheObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "DNSQueryObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#DNSQueryObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "DNSRecordObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#DNSRecordObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "DeviceObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#DeviceObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "DiskObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#DiskObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "DiskPartitionObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#DiskPartitionObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "EmailMessageObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#EmailMessageObject",
        [
            "Subject: [Properties/Header/Subject] ([fact_count] facts)",
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "GUIDialogboxObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#GUIDialogboxObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "GUIObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#GUIObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "GUIWindowObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#GUIWindowObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "HTTPSessionObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#HTTPSessionObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "LibraryObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#LibraryObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "LinkObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#LinkObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "LinuxPackageObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#LinuxPackageObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "MemoryObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#MemoryObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "MutexObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#MutexObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkConnectionObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkConnectionObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkFlowObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkFlowObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkPacketObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkPacketObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkRouteEntryObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkRouteEntryObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkRouteObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkRouteObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkSocketObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkSocketObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "NetworkSubnetObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#NetworkSubnetObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "PDFFileObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#PDFFileObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "PipeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#PipeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "PortObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#PortObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "ProductObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#ProductObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "SemaphoreObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#SemaphoreObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "SocketAddressObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#SocketAddressObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "SystemObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#SystemObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "URIObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#URIObject",
        [
            "[Properties/Value] ([fact_count] facts)",
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UnixFileObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UnixFileObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UnixNetworkRouteEntryObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UnixNetworkRouteEntryObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UnixPipeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UnixPipeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UnixProcessObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UnixProcessObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UnixUserAccountObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UnixUserAccountObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UnixVolumeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UnixVolumeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UserAccountObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UserAccountObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "UserSessionObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#UserSessionObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "VolumeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#VolumeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WhoisObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WhoisObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinComputerAccountObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinComputerAccountObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinCriticalSectionObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinCriticalSectionObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinEventLogObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinEventLogObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinEventObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinEventObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinFileObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinFileObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinHandleObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinHandleObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinKernelHookObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinKernelHookObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinKernelObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinKernelObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinMailslotObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinMailslotObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinMemoryPageRegionObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinMemoryPageRegionObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinMutexObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinMutexObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinNetworkRouteEntryObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinNetworkRouteEntryObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinNetworkShareObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinNetworkShareObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinPipeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinPipeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinPrefetchObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinPrefetchObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinSemaphoreObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinSemaphoreObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinSystemObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinSystemObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinSystemRestoreObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinSystemRestoreObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinTaskObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinTaskObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinThreadObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinThreadObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinUserAccountObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinUserAccountObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinVolumeObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinVolumeObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "WinWaitableTimerObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#WinWaitableTimerObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "X509CertificateObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#X509CertificateObject",
        [
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "FileObject",
        "cybox.mitre.org",
        "http://cybox.mitre.org/objects#FileObject",
        [
            "[Properties/File_Name] ([fact_count] facts)",
            "[Properties/Hashes/Hash/Type]:[Properties/Hashes/Hash/Simple_Hash_Value] ([fact_count] facts)",
            "[fact_count_equal_1?][term_of_fact_num_0] = [value_of_fact_num_0]"
        ]
    ],
    [
        "Observable",
        "cybox.mitre.org",
        "http://cybox.mitre.org/cybox",
        [
            "[Object]",
            "[Observable_Composition@operator] (... ([fact_count] facts)"
        ]
    ],
    [
        "TTP",
        "stix.mitre.org",
        "http://stix.mitre.org/TTP",
        [
            "[Title]"
        ]
    ],
    [
        "Kill_Chain_Phase",
        "stix.mitre.org",
        "http://stix.mitre.org/common",
        [
            "[@ordinality]: [@name]"
        ]
    ],
    [
        "Kill_Chain",
        "stix.mitre.org",
        "http://stix.mitre.org/common",
        [
            "[@name] ([@definer])",
            "[@name]"
        ]
    ],
    [
        "ThreatActor",
        "stix.mitre.org",
        "http://stix.mitre.org/ThreatActor",
        [
            "[Identity/Specification/PartyName/OrganisationName/NameElement]",
            "[Identity/Name]",
            "[Identity/Specification/PartyName/PersonName/NameElement]"
        ]
    ]
]

manage_command = ManageCommand()

pp = pprint.PrettyPrinter(indent=2)

class Command(ManageCommand):
    """

    """
    args = ''
    help = 'Set standard naming schema for InfoObjects from OpenIOC import'

    option_list = BaseCommand.option_list

    def __init__(self, *args, **kwargs):
        kwargs['schemas'] = schema_list
        super(Command,self).__init__(*args,**kwargs)


    def handle(self, *args, **options):
        options['input_list'] = self.schemas
        #manage_command.handle(*args,**options)
        super(Command,self).handle(*args,**options)

