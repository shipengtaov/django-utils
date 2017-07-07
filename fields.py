# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models


class MySQLTextField(models.TextField):
    def db_type(self, connection):
        if connection.settings_dict['ENGINE'] == 'django.db.backends.mysql':
            return 'text'
        return super(MySQLTextField, self).db_type(connection)
