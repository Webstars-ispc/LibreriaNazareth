from pathlib import Path
import os
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / '.env')

# SECRET_KEY se obtiene SIEMPRE de variables de entorno.
# Si falta, el proyecto no arranca (fail fast) en lugar de usar claves inseguras.
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ImproperlyConfigured(
        "SECRET_KEY no está definida. Copiá "
        f"{BASE_DIR / '.env_modelo'} a {BASE_DIR / '.env'} y completá los valores."
    )

# En desarrollo local se puede setear DEBUG=True en .env.
# Por defecto FALSO para no exponer información sensible en producción.
DEBUG = os.getenv('DEBUG', 'False') == 'True'

# Hosts permitidos separados por coma, por ejemplo: "localhost,127.0.0.1,api.ejemplo.com"
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv('ALLOWED_HOSTS', '').split(',')
    if host.strip()
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework', 
    'rest_framework_simplejwt',
    'corsheaders',
    'api',
    'usuarios',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# CORS controlado: solo orígenes autorizados (nunca CORS_ALLOW_ALL_ORIGINS en producción).
# En .env se define CORS_ALLOWED_ORIGINS como lista separada por comas.
CORS_ALLOW_ALL_ORIGINS = os.getenv('CORS_ALLOW_ALL_ORIGINS', 'False') == 'True'
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:4200').split(',')
    if origin.strip()
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('DB_NAME', 'librerianazareth'),
        # USER/PASSWORD se leen siempre desde .env, sin valores por defecto en el código.
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST', '127.0.0.1'),
        'PORT': os.getenv('DB_PORT', '3306'),
        'OPTIONS': {
            'charset': 'utf8mb4',
        },
    }
}

if (DATABASES['default']['ENGINE'].endswith('mysql')
        and not DATABASES['default'].get('USER')):
    raise ImproperlyConfigured(
        "DB_USER no está definida. Completá el archivo .env (ver .env_modelo)."
    )

# SQLite config (dev sin MySQL)
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTHENTICATION_BACKENDS = [
    'usuarios.email_backend.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'EXCEPTION_HANDLER': 'config.exception_handler.excepciones_de_seguridad',
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
}

LANGUAGE_CODE = 'es-ar'

TIME_ZONE = 'America/Argentina/Buenos_Aires'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ============================================================
# LOG DE SEGURIDAD
# Registra eventos de seguridad (403, 401, intentos denegados)
# con fecha/hora, usuario, acción, recurso y resultado.
# NUNCA loguea contraseñas, tokens ni datos sensibles.
# ============================================================
LOGGING_DIR = BASE_DIR / 'logs'
LOGGING_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'seguridad': {
            'format': '[%(asctime)s] %(levelname)s | usuario=%(usuario)s | '
                      'accion=%(accion)s | recurso=%(recurso)s | resultado=%(resultado)s '
                      '| ip=%(ip)s | msg=%(mensaje)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'simple': {
            'format': '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file_seguridad': {
            'class': 'logging.FileHandler',
            'filename': str(LOGGING_DIR / 'seguridad.log'),
            'encoding': 'utf-8',
            'formatter': 'seguridad',
        },
    },
    'loggers': {
        'seguridad': {
            'handlers': ['console', 'file_seguridad'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# from django.db.backends.mysql.base import DatabaseWrapper
# DatabaseWrapper.features_class.can_return_columns_from_insert = False
# DatabaseWrapper.features_class.can_return_rows_from_bulk_insert = False
# from django.db.backends.base.base import BaseDatabaseWrapper
# BaseDatabaseWrapper.check_database_version_supported = lambda self: None
