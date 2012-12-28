#!/usr/bin/env python
# -*- coding: Latin-1 -*-

#    Portable OLECanner v. 0.2
#
#    Copyright (C) 2010  Giuseppe 'Evilcry' Bonfa & Gunther
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# CHANGE LOG
#
# 09/01/2011 - Started ver. 0.2

import sys, os.path
import hashlib
import re
from itertools import izip, cycle
from struct import unpack

class pyOLEScanner:
    def __init__(self, filename):

        self.filename = filename
        try:
            fole = open(filename,'rb')
            self.mappedOLE = fole.read()
            fole.close()
        except IOError:
            print("An error Occurred While opening: " + filename)

    def xor_decrypt_data(self, data, key):
        return ''.join(chr(ord(x) ^ ord(y)) for(x,y) in izip(data,cycle(chr(key))))

    def known_api_revealer(self):
        mappedOle = self.mappedOLE
        apiOffset = list()

        match = re.search(b'CreateFile',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of CreateFile at offset:{0}".format(hex(match.start())))

        match = re.search(b'GetProcAddress',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of GetProcAddress at offset:{0}".format(hex(match.start())))

        match = re.search(b'LoadLibrary',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of LoadLibrary at offset:{0}".format(match.start()))

        match = re.search(b'WinExec',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of WinExec at offset:{0}".format(hex(match.start())))

        match = re.search(b'GetSystemDirectoryA',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of GetSystemDirectoryA at offset:{0}".format(hex(match.start())))

        match = re.search(b'WriteFile',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of WriteFile at offset:{0}".format(hex(match.start())))

        match = re.search(b'ShellExecute',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of ShellExecute at offset:{0}".format(hex(match.start())))

        match = re.search(b'GetWindowsDirectory',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of GetWindowsDirectory at offset:{0}".format(hex(match.start())))

        match = re.search(b'UrlDownloadToFile',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'IsBadReadPtr',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'IsBadWritePtr',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'CloseHandle',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'ReadFile',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'SetFilePointer',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'VirtualAlloc',mappedOle)
        if match is not None:
            apiOffset.append("Revealed presence of UrlDownloadToFile at offset:{0}".format(hex(match.start())))

        return apiOffset

    def embd_ole_scan(self):
        match = re.findall(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',self.mappedOLE)
        if match is not None:
            if len(match) == 1:
                return False
            else:
                return True
        else:
            return False
        pass

    def isOleFile(self):
        fole = open(self.filename,'rb')
        sig = fole.read(512)
        fole.close()

        if len(sig) != 512 or sig[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            return False
        else:
            return True
        pass

    def xor_bruteforcer(self):
        mappedOle = self.mappedOLE
        for i in range (256):
            print("Testing Key: ",hex(i))
            bruted = ''.join(chr(ord(x) ^ ord(y)) for(x,y) in izip(mappedOle,cycle(chr(i))))

            # START ---------------------------------- PE SEARCH
            match = re.search(b'MZ',bruted)
            if match is not None:
                startPEOffset = match.start()

                match = re.search(b'PE',bruted)
                if match is not None:
                    match = re.search(b'This program ',bruted)
                    if match is not None:
                        break
                    else:
                         startPEOffset = 0
                         continue # no 'This ..'
                else:
                    startPEOffset = 0
                    continue # no PE
            else:
                startPEOffset = 0
                continue # no MZ
            # END ---------------------------------- PE SEARCH

        if startPEOffset != 0:
            print("Discovered Embedded Executable matching with XOR Key: ",hex(i))
            print("\n==========================================\n")
            print("Warning File is Potentially INFECTED!!!!\n")
            print("Dumping Decoded File..\n")
            if self.dumpDecodedOle(bruted) is True:
                print("Done!")
            else:
                print("Error Occurred")
            return
        
        return

    def embd_pe(self):
        mappedOle = self.mappedOLE

        match = re.search(b'MZ',mappedOle)
        if match is not None:
            startPEOffset = match.start()

            match = re.search(b'PE',mappedOle)
            if match is not None:
                match = re.search(b'This program ',mappedOle)
                if match is not None:
                    return startPEOffset
                else:
                     return 0 # no 'This ..'
            else:
                return 0 # no PE
        else:
            return 0 # no MZ

        return 0

    def shellcode_scanner(self):
        mappedOle = self.mappedOLE
        shellcode_presence = list()

        match = re.search(b'\x64\x8b\x64',mappedOle)
        if match is not None:
            shellcode_presence.append("FS:[00] Shellcode at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x64\xa1\x00',mappedOle)
        if match is not None:
            shellcode_presence.append("FS:[00] Shellcode at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x64\xa1\x30',mappedOle)
        if match is not None:
            shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x64\x8b\x15\x30',mappedOle)
        if match is not None:
            shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x64\x8b\x35\x30',mappedOle)
        if match is not None:
            shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x64\x8b\x3d\x30',mappedOle)
        if match is not None:
            shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\x83\xc4',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\x81\xec',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\xe8',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\xe9',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))
            
        #new shellcodes
        
        match = re.search(b'\x55\x8b\xec\x83\xc4',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\x81\xec',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\xe8',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))

        match = re.search(b'\x55\x8b\xec\xe9',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Prolog at offset:{0}".format(hex(match.start())))
            
        match = re.search(b'\x90\x90\x90\x90',mappedOle)
        if match is not None:
            shellcode_presence.append("NOP Slide:{0}".format(hex(match.start())))
            
        match = re.search(b'\xd9\xee\xd9\x74\x24\xf4',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xe8\x00\x00\x00\x00\x58',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xe8\x00\x00\x00\x00\x59',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xe8\x00\x00\x00\x00\x5a',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
                   
        match = re.search(b'\xe8\x00\x00\x00\x00\x5e',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xe8\x00\x00\x00\x00\x5f',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xe8\x00\x00\x00\x00\x5d',mappedOle)
        if match is not None:
            shellcode_presence.append("Call Pop Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xd9\xee\xd9\x74\x24\xf4',mappedOle)
        if match is not None:
            shellcode_presence.append("Fldz Signature:{0}".format(hex(match.start())))
            
        match = re.search(b'\xac\xd0\xc0\xaa',mappedOle)
        if match is not None:
            shellcode_presence.append("LODSB/STOSB ROL decryption:{0}".format(hex(match.start())))
            
        match = re.search(b'\xac\xd0\xc8\xaa',mappedOle)
        if match is not None:
            shellcode_presence.append("LODSB/STOSB ROR decryption:{0}".format(hex(match.start())))
            
        match = re.search(b'\x66\xad\x66\x35',mappedOle)
        if match is not None:
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+6])[0] == 0x66 and
                 unpack('B',mappedOle[start_shcod+7])[0] == 0xAB ):
                     shellcode_presence.append("LODSW/STOSW XOR decryption signature:{0}".format(hex(start_shcod)))
            
        match = re.search(b'\x66\xad\x66\x05',mappedOle)
        if match is not None:
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+6])[0] == 0x66 and
                 unpack('B',mappedOle[start_shcod+7])[0] == 0xAB ):
                     shellcode_presence.append("LODSW/STOSW ADD decryption signature:{0}".format(hex(start_shcod)))
            
        match = re.search(b'\x66\xad\x66\x2d',mappedOle)
        if match is not None:
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+6])[0] == 0x66 and
                 unpack('B',mappedOle[start_shcod+7])[0] == 0xAB ):
                    shellcode_presence.append("LODSW/STOSW SUB decryption signature:{0}".format(hex(start_shcod)))
        
        match = re.search(b'\xac\xc0\xc0',mappedOle)
        if match is not None:
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+4])[0] == 0xAA ):
                shellcode_presence.append("LODSB/STOSB ROL decryption signature:{0}".format(hex(start_shcod)))            
                
        match = re.search(b'\xac\xc0\xc8',mappedOle)
        if match is not None:
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+4])[0] == 0xAA ):
                shellcode_presence.append("LODSB/STOSB ROR decryption signature:{0}".format(hex(start_shcod)))
                
        
        for match in re.finditer(b'\xac\x34',mappedOle):
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+3])[0] == 0xAA ):
                shellcode_presence.append("LODSB/STOSB XOR decryption signature:{0}".format(hex(start_shcod)))
                print("Shellcode XOR Key is: " + hex(unpack('B',mappedOle[start_shcod+2])[0]))
                
        for match in re.finditer(b'\xac\x04',mappedOle):
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+3])[0] == 0xAA ):
                shellcode_presence.append("LODSB/STOSB ADD decryption signature:{0}".format(hex(start_shcod)))
                print("Shellcode ADD Key is: " + hex(unpack('B',mappedOle[start_shcod+2])[0]))
                
        for match in re.finditer(b'\xac\x2c',mappedOle):
            start_shcod = match.start()
            if ( unpack('B',mappedOle[start_shcod+3])[0] == 0xAA ):
                shellcode_presence.append("LODSB/STOSB ADD decryption signature:{0}".format(hex(start_shcod)))
                print("Shellcode SUB Key is: " + hex(unpack('B',mappedOle[start_shcod+2])[0]))

        return shellcode_presence

    def scan_for_known_vulnerabilities(self, mappedOle):
        fileFormat_scanner(self.fileName, mappedOle)
        return

    def dumpDecodedOle(self, mappedOle):
        try:
            dump = open('decrypted','wb')
            dump.write(mappedOle)
            dump.close()
            return True
        except IOError as (errno,strerror):
            print("I/O Error: {1}".format(errno,strerror))
        except:
            print("Unexpected Error while Dumping Decoded File")
        return False

    def docx_deflater(self):
        try:
            if zipfile.is_zipfile(self.filename) == False:
                print("Invalid DOCX File Format")
                return False
            else:
                dire = os.curdir + "\\" + filename[:len(filename)-4]

                if not os.path.exists(dire):
                    os.mkdir(dire)
                    deflater = zipfile.ZipFile(filename)
                    deflater.printdir()
                    deflater.extractall(dire)
                    deflater.close()
                else:
                    print("Directory that belongs to that docx already exists\n")
                    return False

        except zipfile.BadZipfile:
            print("Bad docx File")
        except zipfile.LargeZipFile:
            print("LargeZip File Error")
        except:
            print("An error occurred during deflating")
        return False

def main():


    pass

if __name__ == '__main__':
    main()
