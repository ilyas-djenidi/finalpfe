# wsgi.py
# Production entry point: gunicorn -w 4 -b 0.0.0.0:5000 wsgi:application
from app import app as application
