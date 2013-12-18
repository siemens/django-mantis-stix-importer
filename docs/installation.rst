============
Installation
============

At the command line::

    $ easy_install django-mantis-stix-importer

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv django-mantis-stix-importer
    $ pip install django-mantis-stix-importer

Once this is done, you can include 'mantis_iodef_importer' as app in your Django settings,
together with the apps ``dingos`` and ``mantis_core`` on which ``mantis_stix_importer`` depends::

    INSTALLED_APPS_list = [
                           ...,
                           'dingos',
                           'mantis_core',
                           'mantis_stix_importer',
                           ]
