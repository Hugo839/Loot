#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

import os
import sys

class Utilities():

    # Print data to the console
    def pi(self, pdata=''):
        print pdata

    def sabc(self, argnum):
        try:
            if sys.argv[argnum]:
                return True
        except Exception:
            return False

    # String boolean self-check.
    def sbc(self, fn, s): # Check if string is in a file.
        #return a NoneType if the string is not in the file.
        #.readlines() May be a problem is database files get too large.

        if os.path.exists(fn) is False:
            MakeFile = open(fn, 'a').close()

        if os.path.exists(fn) is True:
            pass

        f = open(fn, 'r')
        f = f.readlines()
        for i in f:
            i = i.replace("\n", '')
            if s.encode('utf-8') in i:
                return True

utilities = Utilities()
