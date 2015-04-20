#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

import datetime
from functions import utilities

class DatabaseOperations():

    def ExportFile(self, findings):
        ct = datetime.datetime.now().strftime("%I-%M%p_%B_%d_%Y")
        exportfile = 'bagged_goods' + "_" + str(ct) + '.txt'
        with open(exportfile, 'a+') as file:
            bc = utilities.sbc(exportfile, findings.decode('utf-8'))
            if bc is None:
                file.write(findings + "\n")

database = DatabaseOperations()
