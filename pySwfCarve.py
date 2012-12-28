#-------------------------------------------------------------------------------
# Name:        pySwfCarve
# Purpose:     Carve Embedded SWF Files
#
# Author:      Giuseppe evilcry Bonfa
#
# Created:     14/04/2011
# Copyright:   (c) evilcry 2011
# Licence:     GPL
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import os
import sys
import re

from optparse import OptionParser
from struct import unpack

def main():
    print("Looks for Embedded SWF and Carve it")

    usage = "%Prog suspect_file\n"
    description = "Carve SWF Files\n"
    parser = OptionParser(usage = usage, description = description,
    version = "0.0")
    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Please Specify a Source File")
        sys.exit(-1)
    else:
        print("[+] Looking for Flash File Presence")
        filename = args[0]
        try:
            fileflash = open(filename,'rb')
            mappedFile = fileflash.read()
            fileflash.close()

            flash_offset = swfScan(mappedFile)
            if flash_offset is 0:
                print("[-] No Flash Embedded in This File")
                sys.exit(1)
            else:
                print("[+] Embedded Flash at offset: " + hex(flash_offset))
                outfilename = os.path.basename(filename)
                outfilename = outfilename.partition('.')[0] + '.swf'
                carveSwf(mappedFile, flash_offset, outfilename)
                print("[+] Correctly Dumped As: " + outfilename)
        except:
            print("Error while parsing")
            sys.exit(-1)
    pass

def swfScan(mappedFile):
    match = re.search('FWS', mappedFile)
    if match is not None:
        return match.start()
    else:
        match = re.search('CWS', mappedFile)
        if match is not None:
            return match.start()
        else:
            return 0
    pass

def carveSwf(mappedFile, flash_offset, outfilename):
    swf_len = unpack('H', mappedFile[flash_offset+4:flash_offset+6])[0]
    fcarved = open(outfilename,'wb')
    fcarved.write(mappedFile[flash_offset:flash_offset + swf_len])
    fcarved.close()
    pass

if __name__ == '__main__':
    main()
