"""Throwaway test PKI. Keys are generated per test run and never touch any real CA key."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

NOW = datetime(2026, 11, 8, 2, 0, 0, tzinfo=UTC)


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test")])


def make_ca(cn: str = "CyberMatrix Test Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - timedelta(days=3650))
            .not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def make_leaf(ca_cert, ca_key, *, host="shop.example.com", san=None, nb=None, na=None, key=None,
              self_signed=False, ocsp_url=None, public_key=None, cn=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    nb = nb or NOW - timedelta(days=30)
    na = na or NOW + timedelta(days=60)
    subj = name(cn or host)
    b = (x509.CertificateBuilder().subject_name(subj)
         .issuer_name(subj if self_signed else ca_cert.subject)
         .public_key(public_key or key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in (san or [host])]), critical=False))
    if ocsp_url:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))]), critical=False)
    return b.sign(key if self_signed else ca_key, hashes.SHA256()), key


def rsa_key(bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
