import os
import shutil
import ssl
import subprocess
import tempfile


def make_tls_context():
    """Create a throwaway self-signed server context, or return None if openssl is missing."""
    if shutil.which("openssl") is None:
        return None
    tmp = tempfile.mkdtemp(prefix="maillab-")
    key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
         "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx
