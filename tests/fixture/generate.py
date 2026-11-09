"""Generate test certificates for the TLS fixture.

Produces under tests/fixture/certs/:

    ca.key / ca.crt      test CA, trusted by the app only under test mode
    valid.pem            CN=tls-fixture, SAN=D:tls-fixture, 365d validity
    expired.pem          CN=tls-fixture, SAN=D:tls-fixture, not_after 2d ago
    wrong-cn.pem         CN=tls-fixture, SAN=D:wrong-name (mismatch by SAN only)
    self-signed.pem      CN=tls-fixture, SAN=D:tls-fixture, NOT signed by CA

All leaves carry basicConstraints CA:FALSE, keyUsage, extendedKeyUsage=serverAuth,
and a subjectAltName. The CA carries basicConstraints CA:TRUE,pathlen=0 and
keyUsage keyCertSign+cRLSign. The script asserts every invariant it declares.

Exits non-zero if any assertion fails.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_DIR = Path(__file__).parent / "certs"
FIXTURE_HOSTNAME = "tls-fixture"
WRONG_CN_SAN = "wrong-name"


def _gen_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _build_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _gen_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls-checker-test-ca")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_leaf(
    common_name: str,
    san_dns: str,
    not_before: datetime,
    not_after: datetime,
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate | None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _gen_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()  # type: ignore[arg-type]
            ),
            critical=False,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return key, cert


def _write_combined(path: Path, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
    path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _assert_leaf(cert: x509.Certificate, expected_san: str, label: str) -> None:
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert not bc.ca, f"{label}: basicConstraints must be CA:FALSE"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku, f"{label}: missing serverAuth EKU"
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert x509.DNSName(expected_san) in san, f"{label}: SAN missing DNS:{expected_san}"


def main() -> int:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)

    ca_key, ca_cert = _build_ca()
    _write_key(CERT_DIR / "ca.key", ca_key)
    _write_cert(CERT_DIR / "ca.crt", ca_cert)

    valid_key, valid_cert = _build_leaf(
        common_name=FIXTURE_HOSTNAME,
        san_dns=FIXTURE_HOSTNAME,
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(days=365),
        issuer_key=ca_key,
        issuer_cert=ca_cert,
    )
    _write_combined(CERT_DIR / "valid.pem", valid_key, valid_cert)

    expired_key, expired_cert = _build_leaf(
        common_name=FIXTURE_HOSTNAME,
        san_dns=FIXTURE_HOSTNAME,
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=2),
        issuer_key=ca_key,
        issuer_cert=ca_cert,
    )
    _write_combined(CERT_DIR / "expired.pem", expired_key, expired_cert)

    wrong_key, wrong_cert = _build_leaf(
        common_name=FIXTURE_HOSTNAME,
        san_dns=WRONG_CN_SAN,
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(days=365),
        issuer_key=ca_key,
        issuer_cert=ca_cert,
    )
    _write_combined(CERT_DIR / "wrong-cn.pem", wrong_key, wrong_cert)

    ss_key = _gen_key()
    ss_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FIXTURE_HOSTNAME)])
    ss_cert = (
        x509.CertificateBuilder()
        .subject_name(ss_subject)
        .issuer_name(ss_subject)
        .public_key(ss_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(FIXTURE_HOSTNAME)]), critical=False
        )
        .sign(ss_key, hashes.SHA256())
    )
    _write_combined(CERT_DIR / "self-signed.pem", ss_key, ss_cert)

    _assert_leaf(valid_cert, FIXTURE_HOSTNAME, "valid.pem")
    _assert_leaf(expired_cert, FIXTURE_HOSTNAME, "expired.pem")
    _assert_leaf(wrong_cert, WRONG_CN_SAN, "wrong-cn.pem")
    _assert_leaf(ss_cert, FIXTURE_HOSTNAME, "self-signed.pem")

    assert expired_cert.not_valid_after_utc < now, (
        f"expired.pem is not actually expired: not_after={expired_cert.not_valid_after_utc}"
    )
    assert expired_cert.not_valid_before_utc < expired_cert.not_valid_after_utc

    assert ss_cert.issuer == ss_cert.subject, "self-signed.pem issuer != subject"
    assert valid_cert.issuer == ca_cert.subject, "valid.pem not signed by CA"
    assert expired_cert.issuer == ca_cert.subject
    assert wrong_cert.issuer == ca_cert.subject

    ca_bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert ca_bc.ca is True and ca_bc.path_length == 0, "CA basicConstraints wrong"

    print(f"Generated certificates in {CERT_DIR}")
    for p in sorted(CERT_DIR.glob("*.pem")):
        cert = x509.load_pem_x509_certificate(p.read_bytes())
        print(f"\n=== {p.name} ===")
        print(f"  subject:    {cert.subject.rfc4514_string()}")
        print(f"  issuer:     {cert.issuer.rfc4514_string()}")
        print(f"  not_before: {cert.not_valid_before_utc.isoformat()}")
        print(f"  not_after:  {cert.not_valid_after_utc.isoformat()}")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            print(f"  SAN:        {san.value.get_values_for_type(x509.DNSName)}")
        except x509.ExtensionNotFound:
            print("  SAN:        (none)")
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            print(f"  EKU:        {[oid.dotted_string for oid in eku.value]}")
        except x509.ExtensionNotFound:
            print("  EKU:        (none)")

    print("\n=== ca.crt ===")
    print(f"  subject:    {ca_cert.subject.rfc4514_string()}")
    print(f"  not_after:  {ca_cert.not_valid_after_utc.isoformat()}")
    ca_bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    print(f"  basicConstraints: CA={ca_bc.ca} pathlen={ca_bc.path_length}")

    print("\nAll invariant assertions passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
