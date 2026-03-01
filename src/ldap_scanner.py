#!/usr/bin/env python3
####################
#
# Copyright (c) 2020 Romain Carnus / GoSecure (@romcar)
# (licence header preserved — see original for full text)
#
# Checks remotely LDAP signature requirement options
# Author: Romain Carnus (@romcar)
#
####################
import sys
import logging
import argparse
import codecs
import struct
import time
from impacket import version
from impacket.examples.logger import ImpacketFormatter
from impacket import ntlm
from impacket.ldap import ldap
from impacket.ntlm import (
    NTLMAuthNegotiate, AV_PAIRS, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS,
    NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,
    USE_NTLMv2, hmac_md5,
)


class checker(object):
    def __init__(self, username="", password="", domain="", port=None, hashes=None):
        self.__username = username
        self.__password = password
        self.__port     = port
        self.__domain   = domain
        self.__lmhash   = ""
        self.__nthash   = ""
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(":")

    def check(self, remote_host):
        try:
            ldapclient = ldap.LDAPConnection("ldap://%s" % remote_host)
        except Exception:
            return

        try:
            ldapclient.login(
                self.__username, self.__password,
                self.__domain, self.__lmhash, self.__nthash,
            )
            logging.info(
                "LDAP signature not required on target %s (authentication was accepted)",
                remote_host,
            )
        except ldap.LDAPSessionError as exc:
            if "strongerAuthRequired:" in str(exc):
                logging.info(
                    "LDAP signature was required on target %s (authentication was rejected)",
                    remote_host,
                )
            else:
                logging.warning(
                    "Unexpected Exception while authenticating to %s: %s",
                    remote_host, exc,
                )
        finally:
            ldapclient.close()


def main():
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # FIX: in Python 3, sys.stdout is a TextIOWrapper (not a raw binary stream).
    # Wrapping it with codecs.getwriter requires the underlying binary buffer.
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer)  # FIX: was sys.stdout (crashes in Py3)

    logging.info("LDAP security scanner by @romcar / GoSecure — Based on impacket by SecureAuth")

    parser = argparse.ArgumentParser(
        description="LDAP scanner — connects over LDAP and attempts to authenticate without signing."
    )
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )

    conn_group = parser.add_argument_group("connection")
    conn_group.add_argument(
        "-target-file",
        action="store",
        metavar="file",
        help="Use targets from a file instead of the command-line target",
    )

    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes in LMHASH:NTHASH format",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re
    domain, username, password, remote_name = re.compile(
        r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)"
    ).match(options.target).groups("")

    # Handle passwords containing '@'
    if "@" in remote_name:
        password    = password + "@" + remote_name.rpartition("@")[0]
        remote_name = remote_name.rpartition("@")[2]

    if domain is None:
        domain = ""

    if not password and not username:
        logging.error("Please supply a username/password (anonymous authentication is not supported)")
        return

    if not password and username and options.hashes is None:
        from getpass import getpass
        password = getpass("Password: ")

    remote_names = []
    if options.target_file is not None:
        with open(options.target_file, "r", encoding="utf-8") as inf:
            for line in inf:
                remote_names.append(line.strip())
    else:
        remote_names.append(remote_name)

    lookup = checker(username, password, domain, 389, options.hashes)
    for rn in remote_names:
        try:
            lookup.check(rn)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
