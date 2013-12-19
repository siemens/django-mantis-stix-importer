============
Installation
============

At the command line::

    $ pip install django-mantis-stix-importer

Once this is done, you can include ``mantis_stix_importer`` as app in your Django settings,
together with the apps ``dingos`` and ``mantis_core`` on which ``mantis_stix_importer`` depends::

    INSTALLED_APPS_list = [
                           ...,
                           'dingos',
                           'mantis_core',
			   'mantis_openioc_importer',
                           'mantis_stix_importer',
                           ]
