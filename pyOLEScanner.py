# OLEScanner v. 1.1 - Compound File Format Preliminar Inspector - 2010
#
# Author: Giuseppe 'Evilcry' Bonfa
# E-Mail: evilcry __at__ gmail __dot__ com
# Website: http://www.evilcodecave.blogspot.com
#          http://www.evilcry.netsons.org
#
# OLEScanner is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OLEScanner is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with OLEScanner.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------
#
# OLEScanner is inspired by OfficeMalScanner, here just a python (2.6) script
# that can be used also on Linux

#CHANGE LOG
#
# 18/08/2010 - Started ver. 1.1
# 18/08/2010 - Added dumpDecodedOle()
# 18/08/2010 - UrlDownloadToFile
# 18/08/2010 - docx/pptx/xlsx Deflater
# 21/08/2010 - MD5 and SHA-1 hash signature
# 03/08/2010 - Directory Scan

# Next Version
#
# Ole Dumper
# PE Dumper
# scan deflated docx/pptx/xlsx
# search for MACRO and VBMACROS
# dump blocks of shellcode
# dump blocks of api suspect

__author__ = 'Giuseppe (Evilcry) Bonfa / http://www.evilcodecave.blogspot.com'
__version__ = '1.1'
__license__ = 'GPL'

import sys, os.path
import string, struct
import array, math
import hashlib
import zipfile
import re

from itertools import izip, cycle
from optparse import OptionParser

#Start Global Vars

MAGIC_VALUE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

#End Global Vars

# ##############################################################################

def main():
    print("+-------------------------------+\n")
    print("| OLE Scanner v. 1.1\n")
    print("| by Giuseppe 'Evilcry' Bonfa\n")
    print("+-------------------------------+\n")

    usage = "%Prog suspect_file\n"
    description = "Basical Scan for Malicious Embedded objects\n"

    parser = OptionParser(usage = usage, description = description,
    version = "1.1")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Specify a suspect OLE file or directory with OLE files\n")
    else:
       # fileName = args[0]

        if os.path.isdir(args[0]) is True:
            if directory_scanner(args[0]) is True:
                print("Directory Scan Completed Please Look at DirScan.txt\n")
                pass
            else:
                print("Unable to complete Directory Scanning")
                pass

        elif os.path.isfile(args[0]) is True:
            fileName = args[0]
        else:
            print("Invalid Entry Specified\n")
            pass

        if fileName.endswith('.docx') or fileName.endswith('.pptx') or fileName.endswith('.xlsx'):
            print("Starting Deflate Procedure")
            docx_deflater(fileName)
            try:
                f = open(fileName,'rb')
                mappedDocx = f.read()
                f.close()
                obtain_hashes(mappedDocx)
            except IOError as err:
                print("I/O Error: {0}".format(err))
            except:
                print("Generic Error Happened\n")

        if isOleFile(fileName) == False:
            print("This is not a valid OLE File\n")
            exit
        else:
          print("[-] OLE File Seems Valid\n")
          try:
              f = open(args[0],'rb')
              mappedOle = f.read()
              f.close()
          except IOError as err:
              print("I/O Error: {0}".format(err))

          print("[+] Hash Informations\n")
          obtain_hashes(mappedOle)

          print("[+] Specific FileFormat Informations\n")
##          fileFormat_scanner(fileName, mappedOle)

          print("[+] Scanning for Embedded OLE in Clean\n")

          if embd_ole_scan(mappedOle) is True:
              print("Revealed presence of Embedded OLE \n")
          else:
              print("No Embeddd OLE Found \n")

          print("[+] Scanning for API presence in Clean\n")

          apiScan = known_api_revealer(mappedOle)

          if len(apiScan) == 0:
              print("No Embedded API Found\n")
          else:
              print("\n".join(apiScan))
              print("\n==========================================\n")
              print("Warning File is Potentially INFECTED!!!!\n")

          print("\n[+]Scanning for Embedded Executables - Clean Case\n")

          peInClean = embd_PE_File(mappedOle)

          if peInClean == 0:
              print("No Embedded Executables Found\n")
          else:
              print("Embedded Executable discovered at offset :", hex(peInClean), "\n")
              print("\n==========================================\n")
              print("Warning File is Potentially INFECTED!!!!\n")

              print("[+] Scanning for Shellcode Presence\n")

              shellcode_presence = shellcode_scanner(mappedOle)

              if len(shellcode_presence) == 0:
                  print("No Shellcode Revealed\n")
              else:
                  print("\n".join(shellcode_presence))
                  print("\n==========================================\n")
                  print("Warning File is Potentially INFECTED!!!!\n")

          print("[+] FileFormat Vulnerability Scanner\n")

##          scan_for_known_vulnerabilities(fileName, mappedOle)

          print("[+] Starting XOR Attack..\n")

          xor_bruteforcer(mappedOle)

          return

# ##############################################################################

def directory_scanner(dirToScan):
    Completed = False
    dirToScan = dirToScan + "\\"

    fdirScan = open("DirScan.txt",'w')
    fdirScan.write("OLE2 Directory Scan\n")
    fdirScan.write("=============================================\n")
    fdirScan.write("Scanned Directory: {0}".format(dirToScan))

    dirList = os.listdir(dirToScan)

    for fileName in dirList:
        pathFile = dirToScan + fileName

        #START docx pptx xlsx
        if fileName.endswith('.docx') or fileName.endswith('.pptx') or fileName.endswith('.xlsx'):
            fdirScan.write("Check Current Dir to Surf Deflated: {0}".format(fileName))

            print("Starting Deflate Procedure")
            docx_deflater(pathFile)
            try:
                f = open(pathFile,'rb')
                mappedDocx = f.read()
                f.close()
                obtain_hashes(mappedDocx)
            except IOError as err:
                print("I/O Error: {0}".format(err))
            except:
                print("Generic Error Happened\n")
        #END docx pptx xlsx

        #START OLE2 Validity Verification
        if isOleFile(pathFile) == False:
            fdirScan.write("\n=> {0}\n".format(fileName))
            fdirScan.write("This is not a valid OLE File\n")
            continue
        else:
          fdirScan.write("=> {0}".format(fileName))
          fdirScan.write("[-] OLE File Seems Valid\n")
          try:
              f = open(pathFile,'rb')
              mappedOle = f.read()
              f.close()
          except IOError as err:
              print("I/O Error: {0}".format(err))
              continue
          #END OLE2 Validity Verification

          #START Hash Calc 'n Dump
          fdirScan.write("[+] Hash Informations\n")
          fdirScan.write("{0}\n".format(hashlib.md5(mappedOle).hexdigest()))
          fdirScan.write("{0}\n".format(hashlib.sha1(mappedOle).hexdigest()))
          #END Hash Calc 'n Dump

          #START Specific FileFormat Infos - UNIMPLEMENTED
          fdirScan.write("[+] Specific FileFormat Informations\n")
         # fileFormat_scanner(fileName, mappedOle)
          #END Specific FileFormat Infos - UNIMPLEMENTED

          #START Scanning for Embedded OLE
          fdirScan.write("[+] Scanning for Embedded OLE in Clean\n")

          if embd_ole_scan(mappedOle) is True:
              fdirScan.write("Revealed presence of Embedded OLE \n")
          else:
              fdirScan.write("No Embeddd OLE Found \n")
          #END Scanning for Embedded OLE

          #START Scanning for API presence
          print("[+] Scanning for API presence in Clean\n")
          apiScan = known_api_revealer(mappedOle)

          if len(apiScan) == 0:
              fdirScan.write("No Embedded API Found\n")
          else:
              fdirScan.write("\n".join(apiScan))
              fdirScan.write("\n==========================================\n")
              fdirScan.write("Warning File is Potentially INFECTED!!!!\n")
          #END Scanning for API presence

          #START Scanning for Embedded Executables
          fdirScan.write("\n[+]Scanning for Embedded Executables - Clean Case\n")

          peInClean = embd_PE_File(mappedOle)

          if peInClean == 0:
              fdirScan.write("No Embedded Executables Found\n")
          else:
              fdirScan.write("Embedded Executable discovered at offset : {0} \n".format(hex(peInClean)))
              fdirScan.write("\n==========================================\n")
              fdirScan.write("Warning File is INFECTED!!!!\n")
          #END Scanning for Embedded Executables

          #START Scanning for Shellcode
          print("[+] Scanning for Shellcode Presence\n")

          shellcode_presence = shellcode_scanner(mappedOle)

          if len(shellcode_presence) == 0:
              fdirScan.write("No Shellcode Revealed\n")
          else:
              fdirScan.write("\n".join(shellcode_presence))
              fdirScan.write("\n==========================================\n")
              fdirScan.write("Warning File is Potentially INFECTED!!!!\n")
          #END Scanning for Shellcode


          #START XOR Attack
          fdirScan.write("[+] Starting XOR Attack..\n")
          for i in range (256):
            bruted = xor_decrypt_data(mappedOle, i)
            startPEOffset = embd_PE_File(bruted)
            if startPEOffset != 0:
                 fdirScan.write("Discovered Embedded Executable matching with XOR Key: ".format(hex(i)))
                 fdirScan.write("\n==========================================\n")
                 fdirScan.write("Warning File is Potentially INFECTED!!!!\n")
                 fdirScan.write("Dumping Decoded File..\n")

                 if dumpDecodedOle(bruted) is True:
                     print("Done!")
                 else:
                     print("Error Occurred")
                     continue
         #END XOR Attack

          fdirScan.write("[+] Scanning for Embedded OLE - XOR Case\n")
          if startPEOffset != 0:
              if embd_ole_scan(bruted) is True:
                  fdirScan.write("Embedded OLE Detected \n")

        fdirScan.write("\n########################################################\n")

    return True

def xor_decrypt_data(data, key):
    return ''.join(chr(ord(x) ^ ord(y)) for(x,y) in izip(data,cycle(chr(key))))

def known_api_revealer(mappedOle):

    apiOffset = list()

    match = re.search(b'CreateFileA',mappedOle)
    if match is not None:
        apiOffset.append("Revealed presence of CreateFileA at offset:{0}".format(hex(match.start())))

    match = re.search(b'GetProcAddress',mappedOle)
    if match is not None:
        apiOffset.append("Revealed presence of GetProcAddress at offset:{0}".format(hex(match.start())))

    match = re.search(b'LoadLibraryA',mappedOle)
    if match is not None:
        apiOffset.append("Revealed presence of LoadLibraryA at offset:{0}".format(match.start()))

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

    return apiOffset

def isOleFile(fileName):

    fole = open(fileName,'rb')
    sig = fole.read(512)
    fole.close()

    if len(sig) != 512 or sig[:8] != MAGIC_VALUE:
        return False
    else:
        return True

def embd_ole_scan(mappedOle):

    match = re.findall(MAGIC_VALUE,mappedOle)

    if match is not None:

        if len(match) == 1:
            return False
        else:
            return True
    else:
        return False

def xor_bruteforcer(mappedOle):

    for i in range (256):
        print("Testing Key: ",hex(i))
        bruted = xor_decrypt_data(mappedOle, i)
        startPEOffset = embd_PE_File(bruted)
        if startPEOffset != 0:
            print("Discovered Embedded Executable matching with XOR Key: ",hex(i))
            print("\n==========================================\n")
            print("Warning File is Potentially INFECTED!!!!\n")
            print("Dumping Decoded File..\n")
            if dumpDecodedOle(bruted) is True:
                print("Done!")
            else:
                print("Error Occurred")
            break

    print("[+] Scanning for Embedded OLE - XOR Case\n")
    if startPEOffset != 0:
        if embd_ole_scan(bruted) == True:
            print("Embedded OLE Detected \n")

    return

def shellcode_scanner(mappedOle):

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

    return shellcode_presence

##def scan_for_known_vulnerabilities(fileName, mappedOle):
##    fileFormat_scanner(fileName, mappedOle)
##    return

def embd_PE_File(mappedOle):

    match = re.search(b'MZ', mappedOle)

    if match is not None:
        startPEOffset = match.start()

        match = re.search(b'PE',mappedOle)
        if match is not None:

            match = re.search(b'This program ',mappedOle)
            if match is not None:
                return startPEOffset
            else:
                return 0
        else:
            return 0

    return 0

def obtain_hashes(mappedOle):

    md5 = hashlib.md5(mappedOle).hexdigest()
    sha1 = hashlib.sha1(mappedOle).hexdigest()

    print("MD5: {0}".format(md5))
    print("SHA-1: {0}".format(sha1))

    return


def dumpDecodedOle(mappedOle):

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

def docx_deflater(fileName):

    try:
        if zipfile.is_zipfile(fileName) == False:
            print("Invalid DOCX File Format")
            return False
        else:
            dire = os.curdir + "\\" + fileName[:len(fileName)-4]

            if not os.path.exists(dire):
                os.mkdir(dire)
                deflater = zipfile.ZipFile(fileName)
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

##def fileFormat_scanner(fileName, mappedOle):
##
##    if fileName.endswith('.ppt'):
##        match = re.search()
##        pass
##    elif fileName.endswith('.xls'):
##        match = re.search()
##        pass
##    else:
##        pass


    return

if __name__ == "__main__":
    main()