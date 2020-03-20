from .base import *

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = '@xn8l3lq=05u^i47a^dnrpr86qen0$-#@y^i0@l*+c9#_l0x^f'

DEBUG = True

ALLOWED_HOSTS = ['api-skin-cancer.herokuapp.com']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'skin_cancer',
        'USER': 'skincanceruser',
        'PASSWORD': 'dj',
        'HOST': 'localhost',
        'PORT': '',
    }
}

MIDDLEWARE += ['whitenoise.middleware.WhiteNoiseMiddleware']
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_ROOT = os.path.join(PROJECT_ROOT, 'staticfiles')
STATIC_URL = '/static/'

# Extra lookup directories for collectstatic to find static files
STATICFILES_DIRS = (
    os.path.join(PROJECT_ROOT, 'static'),
)

#  Add configuration for static files storage using whitenoise
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

import dj_database_url

prod_db = dj_database_url.config(conn_max_age=500)
DATABASES['default'].update(prod_db)
