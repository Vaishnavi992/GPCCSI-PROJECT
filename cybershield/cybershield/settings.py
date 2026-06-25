import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = 'cybershield-dev-key-change-in-production-xyz789abc'
DEBUG      = True
ALLOWED_HOSTS = ALLOWED_HOSTS = [
    'gpccsi-project-production.up.railway.app',
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
    'security',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'cybershield.urls'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [
        'django.template.context_processors.debug',
        'django.template.context_processors.request',
        'django.contrib.auth.context_processors.auth',
        'django.contrib.messages.context_processors.messages',
    ]},
}]

WSGI_APPLICATION = 'cybershield.wsgi.application'

DATABASES = {'default': {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': BASE_DIR / 'db.sqlite3',
}}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ   = True

STATIC_URL  = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL   = '/media/'
MEDIA_ROOT  = BASE_DIR / 'media'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ── Django REST Framework ──────────────────────────────────────────────────────
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

# ── JWT ────────────────────────────────────────────────────────────────────────
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME':  timedelta(hours=2),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS':  True,
}

# ── CORS — allow React dev server ─────────────────────────────────────────────
CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:3000',
    'http://127.0.0.1:5173',
]
CORS_ALLOW_CREDENTIALS = True

# ── ML Paths ───────────────────────────────────────────────────────────────────
ML_MODEL_PATH         = BASE_DIR / 'ml_engine' / 'saved_models' / 'ensemble_model.pkl'
ML_SCALER_PATH        = BASE_DIR / 'ml_engine' / 'saved_models' / 'scaler.pkl'
ML_LABEL_ENCODER_PATH = BASE_DIR / 'ml_engine' / 'saved_models' / 'label_encoder.pkl'
DATASET_PATH          = BASE_DIR / 'dataset' / 'combined_dataset.csv'

# ── Threat Intel API Keys ─────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY         = os.environ.get('VIRUSTOTAL_API_KEY',          '')
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY','')
ABUSEIPDB_API_KEY          = os.environ.get('ABUSEIPDB_API_KEY',           '')
URLSCAN_API_KEY            = os.environ.get('URLSCAN_API_KEY',             '')
PHISHTANK_API_KEY          = os.environ.get('PHISHTANK_API_KEY',           '')

RISK_WEIGHTS = {
    'ml_model': 0.40, 'virustotal': 0.25,
    'google_safe_browsing': 0.15, 'phishtank': 0.10,
    'abuseipdb': 0.05, 'urlscan': 0.05,
}

# ── Cache (file-based, no Redis needed) ───────────────────────────────────────
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': BASE_DIR / '.cache',
        'TIMEOUT': 3600,        # 1 hour — rescan same URL after 1 hour
        'OPTIONS': {'MAX_ENTRIES': 5000},
    }
}
SCAN_CACHE_SECONDS = 3600       # how long to cache identical URL results
