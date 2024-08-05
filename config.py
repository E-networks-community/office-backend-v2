import hashlib
import hmac
import os
import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session


class ApplicationConfig:

    redis_client = redis.Redis()

    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS")
    SQLALCHEMY_ECHO = os.environ.get("SQLALCHEMY_ECHO")
    SQLALCHEMY_POOL_SIZE = 20
    SQLALCHEMY_POOL_TIMEOUT = 3000
    SQLALCHEMY_POOL_RECYCLE = 36000

    SQLALCHEMY_DATABASE_URI = r"sqlite:///./db.sqlite"
    username = os.environ.get("USERNAME")
    password = os.environ.get("PASSWORD")
    localhost = os.environ.get("LOCALHOST")
    dbname = os.environ.get("DBNAME")
    # SQLALCHEMY_DATABASE_URI = "postgresql://postgres:oRFudttTNIpRLXpfNYTemrDjGjiQESOn@roundhouse.proxy.rlwy.net:33543/railway"
    # SQLALCHEMY_DATABASE_URI = "postgresql://postgres:rDyMvpTxGWRraErqeWbLUxOOghdtuAMA@roundhouse.proxy.rlwy.net:33149/railway"

    DATABASE_ENGINE = create_engine(SQLALCHEMY_DATABASE_URI)
    # REDIS_URL = "redis://default:fdMgaPnGoOkK12ig5kckE44iDMjFOPKK@monorail.proxy.rlwy.net:33538"
    # SESSION_REDIS = redis.from_url(REDIS_URL)
    SESSION_REDIS = redis_client
    SESSION_PERMANENT = os.environ.get("SESSION_PERMANENT")
    PERMANENT_SESSION_LIFETIME = 86400

    DATABASE_INITIALIZED = False

    JWT_ACCESS_TOKEN_EXPIRES = 43200

    SECRET_KEY = "KeyKeyAldoKeyKey"
    SESSION_KEY_PREFIX = "your_prefix_here"
    SESSION_TYPE = redis
    SESSION_USE_SIGNER = False
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = "jbgjgbgvhdgkbkjdn"
