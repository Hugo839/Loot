#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

from core.libs.colors import paint

class COLOREDOUTPUT():

    INFO = paint.W+"[FOUND]"+paint.N+": "
    FAIL = paint.R+"[FAILED]"+paint.N+": "
    STATUS = paint.Y+"[RESULTS]"+paint.N+": "

notifications = COLOREDOUTPUT()

def Help():
    print """
    GrabME - Extract Sensitive information from a file.

    Usage: ./grabme -f [FILE] [CONTENT-OPTION]

    ./grabme -f [FILE] --btc | Grab bitcoin addresses if in file.

    ./grabme -f [FILE] --mac | Grab MAC addresses if any are in file.

    ./grabme -f [FILE] --iat | Grab instagram access tokens if any are in file.

    ./grabme -f [FILE] --ssn | Grab social security numbers if any are in file.

    ./grabme -f [FILE] --ccn | Grab credcard numbers if any are in file.

    ./grabme -f [FILE] --ipv6 | Grab IPv6 addresses if any are in file.

    ./grabme -f [FILE] --ipv4 | Grab IPv4 addresses if any are in file.

    ./grabme -f [FILE] --email | Grab Email addresses if any are in file.

    ./grabme -f [FILE] --hash | Grab hashes if any are in file.

    ./grabme -f [FILE] --phn | Grab phone numbers if any are in file.

    What can it extract ?:

    Links
    hash values
    email addresses
    ipv4, ipv6 addresses
    instagram access tokens
    bitcoin wallet addresses
    MAC addresses with : or - (deliminators)
    USA Based Telephone, Social Security and Major Credit Card numbers.
    """
