# Code below taken from https://djangosnippets.org/snippets/2843/

from django.core.management import call_command
from django.db.models import loading
from django.test import TestCase
from django.test.utils import override_settings


class CustomSettingsTestCase(TestCase):
    """
    A TestCase which makes extra models available in the Django project, just for testing.
    Based on http://djangosnippets.org/snippets/1011/ in Django 1.4 style.
    """
    new_settings = {}
    _override = None


    @classmethod
    def setUpClass(cls):
        cls._override = override_settings(**cls.new_settings)
        cls._override.enable()
        if 'INSTALLED_APPS' in cls.new_settings:
            cls.syncdb()


    @classmethod
    def tearDownClass(cls):
        cls._override.disable()
        if 'INSTALLED_APPS' in cls.new_settings:
            cls.syncdb()


    @classmethod
    def syncdb(cls):
        loading.cache.loaded = False
        call_command('syncdb', verbosity=0)
