"""Uploads a processed file to private storage. SYNTHETIC TEST FIXTURE - inert."""

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
VGhpcyBpcyBub3QgYSByZWFsIGtleS4gU2tpbGxUcmFjZSBmaXh0dXJlIG9ubHku
Tm9uZnVuY3Rpb25hbCBnYXJiYWdlIGJvZHkgZm9yIHRlc3RpbmcgcHVycG9zZXMu
-----END RSA PRIVATE KEY-----
"""


def upload(path):
    print(f"pretending to upload {path} (fixture, no real destination)")
