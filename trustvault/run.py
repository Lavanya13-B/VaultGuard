"""Dev server:  python run.py   (set TRUSTVAULT_INSECURE_COOKIES=1 if you browse over plain http,
e.g. Safari on localhost). In production run behind TLS with gunicorn: gunicorn 'run:app'."""
from trustvault import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
