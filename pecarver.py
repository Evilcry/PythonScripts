#-------------------------------------------------------------------------------
# Name:     PECarver   
# Purpose:  Dump An Executable from a DataStream
#
# Author:      Giuseppe 'evilcry' Bonfa
#
# Created:     12/01/2011
# Copyright:   (c) evilcry 2011
# Licence:     GPL v3
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import os
import sys
import re

from struct import unpack
from optparse import OptionParser

def main():
    
    usage = "%Prog stream_file\n"
    description = "TEST\n"

    parser = OptionParser(usage = usage, description = description,
    version = "0.1")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Specify the stream file where to carve executable\n")
        sys.exit(-1)
    else:
        
        try:
            fmap = open(args[0],'rb')
            mappedFile = fmap.read()
            fmap.close()
            
            startMZ = embd_PE_File(mappedFile)
            
            if startMZ != 0:
                #dump executable
                print("[*] Executable Revealed at Offset= " + hex(startMZ))
                                                
                exeToCarve = mappedFile[startMZ:]
                
                if dumpExecutable(exeToCarve) is True:
                    print("[*] Executable Dumped")
                else:
                    print("[-] Not Dumped")
                
            else:
                print("[-] No Executable Revealed")
                sys.exit(1)
                
        except IOError:
            print("IO Error While Opening Stream File")
            sys.exit(-1)
        except:
            print("Generic Error Occurred While Processing Stream")
            sys.exit(-1)        

    sys.exit(1)
    
def embd_PE_File(mappedFile):

    match = re.search(b'MZ', mappedFile)
    if match is not None:
        startPEOffset = match.start()

        match = re.search(b'PE', mappedFile)
        if match is not None:

            match = re.search(b'This program ', mappedFile)
            if match is not None:
                return startPEOffset
            else:
                return 0
        else:
            return 0
    return 0
    
def dumpExecutable(exeToCarve):

    e_lfanew = unpack('B',exeToCarve[0x3C])[0]
    
    numberOfSections = unpack('B',exeToCarve[e_lfanew + 0x6])[0]
    
    offset_sizeOfOptHeader = e_lfanew + 0x14
    
    sizeOfOptionalHeader = unpack('B',exeToCarve[offset_sizeOfOptHeader])[0]
    
    startSectionHeader = (sizeOfOptionalHeader + 0x4) + offset_sizeOfOptHeader
    
    offset_sizeOfImage = offset_sizeOfOptHeader + 0x3C
    
    sizeOfImage = unpack('I', exeToCarve[offset_sizeOfImage:offset_sizeOfImage+4])[0]
    
    i = 0
    while ( i <= numberOfSections ):
        sectRawAddress = unpack('I',exeToCarve[startSectionHeader+0x14:startSectionHeader+0x18])[0]
        sectRawSize = unpack('I',exeToCarve[startSectionHeader+0x10:startSectionHeader+0x14])[0]

        nSection = sectRawSize + sectRawAddress

        if nSection > sizeOfImage:
            sizeOfImage = nSection

        i += 1
        startSectionHeader += 0x28
        continue

    carved = exeToCarve[:nSection]
    
    try:
        fexe = open('dumped.exe','wb')
        fexe.write(carved)
        fexe.close()
        
    except IOError:
        print("Cannot Dump the Executable")
        return False
    
    return True

if __name__ == '__main__':
    main()
