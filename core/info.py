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
    [GWF Certified] - https://twitter.com/GuerrillaWF

    GrabME - Extract Sensitive information from a file.

    Usage: ./grabme -f [FILE] [EXTRACT-OPTION]

    ./grabme -f [FILE] --btc | Grab bitcoin addresses if in file.

    ./grabme -f [FILE] --mac | Grab MAC addresses if any are in file.

    ./grabme -f [FILE] --iat | Grab instagram access tokens if any are in file.

    ./grabme -f [FILE] --ssn | Grab social security numbers if any are in file.

    ./grabme -f [FILE] --ccn | Grab credit card numbers if any are in file.

    ./grabme -f [FILE] --ipv6 | Grab IPv6 addresses if any are in file.

    ./grabme -f [FILE] --ipv4 | Grab IPv4 addresses if any are in file.

    ./grabme -f [FILE] --email | Grab Email addresses if any are in file.

    ./grabme -f [FILE] --hash | Grab hash values if any are in file.

    ./grabme -f [FILE] --phn | Grab phone numbers if any are in file.

    What can it extract ?:

    1. Links
    2. hash values
    3. email addresses
    4. ipv4, ipv6 addresses
    5. instagram access tokens
    6. bitcoin wallet addresses
    7. MAC addresses with : or - (deliminators)
    8. USA Based Telephone, Social Security and Major Credit Card numbers.
    """
