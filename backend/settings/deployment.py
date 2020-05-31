import os
from .base import *

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


SECRET_KEY = "@xn8l3lq=05u^i47a^dnrpr86qen0$-#@y^i0@l*+c9#_l0x^f"

DEBUG = True

ALLOWED_HOSTS = ["192.168.43.185", "localhost", "127.0.0.1"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "skin_cancer",
        "USER": "skincanceruser",
        "PASSWORD": "dj",
        "HOST": "localhost",
        "PORT": "",
    }
}
