#!/usr/bin/env python3

import re
from datetime import datetime
import base64
import OpenSSL.crypto

def extract_certificates(file_path):
    with open(file_path, "r") as f:
        content = f.read()

    # 文頭の空白を削除し証明書の内容を 1 行の文字列にする。
    content1 = re.sub('\n ', '', content).split('\n')
    certs = []

    for line in content1:
        if line.startswith('userCertificate:: '):
            cert = re.sub(r'userCertificate:: ', '', line)
            certs.append(cert)

    return certs

def parse_certificate(cert_b64):
    # 証明書をデコード
    cert_der = base64.b64decode(cert_b64)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)

    # SHA1 フィンガープリントを取得
    fingerprint = cert.digest("sha1").decode().upper()

    # 発行者情報
    issuer = ", ".join([f"{name[0].decode('utf-8')} = {name[1].decode('utf-8')}" for name in cert.get_issuer().get_components()])

    # サブジェクト情報
    subject = ", ".join([f"{name[0].decode('utf-8')} = {name[1].decode('utf-8')}" for name in cert.get_subject().get_components()])

    # 有効期間
    not_before = datetime.strptime(cert.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
    not_after = datetime.strptime(cert.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")

    # Serial Number
    serial = hex(cert.get_serial_number())
    serial = ':'.join(serial[i:i+2] for i in range(0, len(serial), 2))[3:]

    # 出力フォーマット
    result = f"""
SHA1 Fingerprint={fingerprint}
    Issuer: {issuer}
    Subject: {subject}
    Not Before: {not_before}
    Not After : {not_after}
    Serial Number: {serial}
    X509v3 Key Usage:"""

    # X509v3 Key Usage の取得
    key_usage = "N/A"
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        ext_str = f"""
        {ext.get_short_name().decode()}: {ext}"""
        result += ext_str

    return result

if __name__ == "__main__":
    file_path = "sts-certificates.txt"  # 読み込むファイルのパス
    certificates = extract_certificates(file_path)

    for c in certificates:
        result = parse_certificate(c)
        print(result)
