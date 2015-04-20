#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

# Linux Bound!
# Author: https://twitter.com/GuerrillaWF

# Native imports
import re
import sys
import getopt
from core.info import Help
from core.libs.process import output

# Support access token | github | facebook

# suppport a uniq option where the user uses their own regex to look for something.

# TO-DO List:
# Work on better case detection for diffent phone number formats
# Add other country SSN Number support, GrabSSN currently only supports USA SSNs
# Incorporate bitcoin pre-fixes into bitcoin grabbing function

# Bug Reports:
# Phone number false readings.

# Current Draw backs:
# Can not grab any Bitcoin wallet addresses that are 31 - 32 characters in length.

def main(IFNOARGEXISTS):

    try:
        options, arguements = getopt.getopt(sys.argv[1:], 'f: h a:', ['btc', 'iat', 'ipv4', 'ipv6', 'link', 'mac', 'ssn', 'ccn', 'hash', 'phn', 'email'])

        try:

            try:
                # Options w/1 arg.
                fstopt = options[0][0]
                fstarg = options[0][1]

                try:
                    sndopt = options[1][0]
                except IndexError:
                    pass

                if fstopt == '-h':
                    Help()

                if fstopt == '-f' and sndopt == '--btc':
                    output.BTCAddresses(fstarg)

                elif fstopt == '-f' and sndopt == '--iat':
                    output.InstagramAccessToken(fstarg)

                elif fstopt == '-f' and sndopt == '--ipv4':
                    output.IPv4Addresses(fstarg)

                elif fstopt == '-f' and sndopt == '--ipv6':
                    output.IPv6Addresses(fstarg)

                elif fstopt == '-f' and sndopt == '--link':
                    output.HyperLinks(fstarg)

                elif fstopt == '-f' and sndopt == '--mac':
                    output.MACAddresses(fstarg)

                elif fstopt == '-f' and sndopt == '--ssn':
                    output.SocialSecurityNumbers(fstarg)

                elif fstopt == '-f' and sndopt == '--ccn':
                    output.CreditCardNumbers(fstarg)

                elif fstopt == '-f' and sndopt == '--hash':
                    output.HashTypes(fstarg)

                elif fstopt == '-f' and sndopt == '--phn':
                    output.PhoneNumbers(fstarg)

                elif fstopt == '-f' and sndopt == '--email':
                    output.Emails(fstarg)

                elif fstopt == '-a':
                    output.Emails(fstarg)
                    output.HashTypes(fstarg)
                    output.HyperLinks(fstarg)
                    output.MACAddresses(fstarg)
                    output.BTCAddresses(fstarg)
                    output.PhoneNumbers(fstarg)
                    output.IPv4Addresses(fstarg)
                    output.IPv6Addresses(fstarg)
                    output.CreditCardNumbers(fstarg)
                    output.InstagramAccessToken(fstarg)
                    output.SocialSecurityNumbers(fstarg)
            except UnboundLocalError:
                Help()
        except IndexError:
            pass
    except getopt.GetoptError:
        Help()

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except IndexError:
        Help()
