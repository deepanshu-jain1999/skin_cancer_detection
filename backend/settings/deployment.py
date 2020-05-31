import os
from .base import *

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


SECRET_KEY = "@xn8l3lq=05u^i47a^dnrpr86qen0$-#@y^i0@l*+c9#_l0x^f"

DEBUG = True

ALLOWED_HOSTS = ["skin-cancer-detect-api.herokuapp.com", "localhost"]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'dj',
        'USER': 'password'
    }
}
import dj_database_url

prod_db = dj_database_url.config(conn_max_age=500)
DATABASES["default"].update(prod_db)
