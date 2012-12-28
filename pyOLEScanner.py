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

# CHANGE LOG
#
# 18/08/2010 - Started ver. 1.1
# 18/08/2010 - Added dumpDecodedOle()
# 18/08/2010 - UrlDownloadToFile
# 18/08/2010 - docx/pptx/xlsx Deflater
# 21/08/2010 - MD5 and SHA-1 hash signature
# 03/08/2010 - Directory Scan
# 26/11/2010 - DB Support for Single File
# 27/11/2010 - Directory Scanner DB
# 28/11/2010 - Progress Bar
# 12/01/2011 - More API detection
# 13/01/2011 - More Shellcode FS[30h] / Call-Pop detection
# 13/01/2011 - More Shellcode XOR/ADD/SUB/ROL/ROR detection
# 14/01/2011 - More Shellcode XOR/ADD/SUB/ROL/ROR + decryption key
# 15/01/2011 - Progress Bar Activation Flag
# 16/01/2011 - String to Hex formatted Regex
# 16/01/2011 - RTF Scanner
# 16/01/2011 - Macro Detector for classical OLE2 files
# 16/01/2011 - fileFormat_scanner() added encryption detection for Word files
# 19/01/2011 - Office2007 VBA Macros Detector
# 20/01/2011 - zip_archive() added
#
# Next Version
#
# Ole Dumper
# PE Dumper
# search for MACRO and VBMACROS
# dump blocks of shellcode
# dump blocks of api suspect

# Working On
#
# OleFileIO_PL Integration
# CVE Detector
# RTF Scan
# zip archive support


__author__ = 'Giuseppe (Evilcry) Bonfa / http://www.evilcodecave.blogspot.com'
__version__ = '1.2'
__license__ = 'GPL'

import sys, os.path
import hashlib
import zipfile
import re

from struct import unpack
from itertools import izip, cycle
from optparse import OptionParser

try:
    import sqlite3
    from pbar import progressBar
    from OleFileIO_PL import OleFileIO
except ImportError:
    print("ImportError")
    sys.exit(-1)

#Start Global Vars

MAGIC_VALUE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

PBAR_ACTIVE = False

ZIP_SCAN = False

#End Global Vars

# ##############################################################################

def main():
    print("+-------------------------------+\n")
    print("| OLE Scanner v. 1.2\n")
    print("| by Giuseppe 'Evilcry' Bonfa\n")
    print("+-------------------------------+\n")

    usage = "%Prog suspect_file\n"
    description = "Basical Scan for Malicious Embedded objects\n"
    malicious_index = False

    parser = OptionParser(usage = usage, description = description,
    version = "1.2")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Specify a suspect OLE file or directory with OLE files\n")
    else:
       
        if os.path.isdir(args[0]) is True:
            if directory_scanner(args[0]) is True:
                print("Directory Scan Completed Please Look at DirScan.txt\n")
                sys.exit(1)
            else:
                print("Unable to complete Directory Scanning")
                sys.exit(-1)

        elif os.path.isfile(args[0]) is True:
            fileName = args[0]
        else:
            print("Invalid Entry Specified\n")
            pass
        
        if ZIP_SCAN is True:
            #START Zip Archive    
            if fileName.endswith('.zip'):
                print("[+] Zip Archive Detected, Scanning")
                if zip_archive(fileName) is True:
                    print("[+] Zip Archive Scan Completed")
                    sys.exit(1)
                else:
                    print("[-] Zip Archive Scan Failed")
                    sys.exit(-1)
            #END Zip Archive
        
        if fileName.endswith('.docx') or fileName.endswith('.pptx') or fileName.endswith('.xlsx'):
            print("Starting Deflate Procedure")
            docx_deflater(fileName)
            try:
                f = open(fileName,'rb')
                mappedDocx = f.read()
                f.close()
                print("\n==========================\n")
                obtain_hashes(mappedDocx)
                return
            except IOError as err:
                print("I/O Error: {0}".format(err))
            except:
                print("Generic Error Happened\n")

        if isOleFile(fileName) is False:
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
              
          #START RTF Case          
          if fileName.endswith('.rtf'):
              print("[*] Starting Scan for RTF Files")
              
              if rtf_scan(mappedOle) is True:
                  print("File Potentially INFECTED!!!!!")
              else:
                  print("File Appears CLEAN")
          #END RTF Case
          
          print("[+] Hash Informations\n")
          hashlist = obtain_hashes(mappedOle)
                    
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
              malicious_index = True

          print("\n[+] Scanning for Embedded Executables - Clean Case\n")

          peInClean = embd_PE_File(mappedOle)

          if peInClean == 0:
              print("No Embedded Executables Found\n")
          else:
              print("Embedded Executable discovered at offset :", hex(peInClean), "\n")
              print("\n==========================================\n")
              print("Warning File is Potentially INFECTED!!!!\n")
              malicious_index = True

          print("[+] Scanning for Shellcode Presence\n")

          shellcode_presence = shellcode_scanner(mappedOle)

          if len(shellcode_presence) == 0:
              print("No Shellcode Revealed\n")
          else:
              print("\n".join(shellcode_presence))
              print("\n==========================================\n")
              print("Warning File is Potentially INFECTED!!!!\n")
              malicious_index = True
              
          print("[+] Scanning for MACROs")
          
          if macro_detector(mappedOle) == True:
              print("\n==========================================\n")
              print("Warning File Contains MACROs\n")
          else:
              print("\n==========================================\n")
              print("No MACROs Revealed")                  
      
          # Database Update
                 
          if malicious_index == True:
              update_DB('ole2.sqlite', hashlist, os.path.getsize(args[0]), malicious_index) # Default DB Name assumed ole2.sqlite
              return
          else:
              print("[+] Starting XOR Attack..\n")
              malicious_index = xor_bruteforcer(mappedOle)
              update_DB('ole2.sqlite', hashlist, os.path.getsize(args[0]), malicious_index)              
              return
    return

# ##############################################################################

def macro_docx_scanner(folder, internal_ext):
    dirpath = os.listdir(folder + internal_ext)
    for fileName in dirpath:
        if fileName == 'vbaProject.bin':
            print("===> VBA Macro Revealed!")
            return True                        
    return False

def str2hexre (toConvert): #from string to hex based regexp    
    regex = r''
    for c in toConvert:
        code_lower = ord(c.lower())
        code_upper = ord(c.upper())
        regex += r'(?:%02X|%02X)' % (code_lower, code_upper)
    return regex

def rtf_scan(mappedOle):
    rtf_magic = str2hexre('Package')
    match = re.search(rtf_magic, mappedOle)
    if match is not None:
        print("[*] OLE Package Discovered, Potential Risk!")
        # other stuff
    else:
        print("[-] No OLE Package Revealed")        
    return True

def fileFormat_scanner(fileName):
    
    try:
        oleFile = OleFileIO(fileName)
        enum_streams = oleFile.listdir()
        
        for s in enum_streams:
            if s == ["\x05SummaryInformation"]:
                print("Summary Informations Available")
                properties = oleFile.getproperties(s)
                if 0x12 in properties:
                    appName = properties[0x12]
                if 0x13 in properties:
                    if properties[0x13] & 1:
                        print("Document is Encrypted")
                if s == ['WordDocument']:
                    s_word = oleFile.openstream(['WordDocument'])
                    s_word.read(10)
                    temp16 = unpack("H", s_word.read(2))[0]
                    fEncrypted = (temp16 & 0x0100) >> 8
                    if fEncrypted:
                        print("Word Document Encrypted")
                    s_word.close()                    
    except:
        print("Error While Processing OLE Streams")
        return False

    return True
    
def macro_detector(mappedOle):
    match = re.search(r'M\x00a\x00c\x00r\x00o\x00s',mappedOle)
    if match is not None:
        return True
    else:
        return False
    return

def directory_scanner(dirToScan):
    Completed = False
    malicious_index = False
    
    if os.name == 'nt':
        dirToScan = dirToScan + "\\"
    else:
        dirToScan = dirToScan + "/"

    fdirScan = open("DirScan.txt",'w')
    fdirScan.write("OLE2 Directory Scan\n")
    fdirScan.write("=============================================\n")
    fdirScan.write("Scanned Directory: {0} \n".format(dirToScan))

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
          fdirScan.write("\n[-] OLE File Seems Valid\n")
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
          hashlist = list()
          hashlist.append(hashlib.md5(mappedOle).hexdigest())
          hashlist.append(hashlib.sha1(mappedOle).hexdigest())
          #END Hash Calc 'n Dump

          #START Scanning for Embedded OLE
          fdirScan.write("[+] Scanning for Embedded OLE in Clean\n")

          if embd_ole_scan(mappedOle) is True:
              fdirScan.write("Revealed presence of Embedded OLE \n")
          else:
              fdirScan.write("No Embeddd OLE Found \n")
          #END Scanning for Embedded OLE

          #START Scanning for API presence
          print("\n[+] Scanning for API presence in Clean\n")
          apiScan = known_api_revealer(mappedOle)

          if len(apiScan) == 0:
              fdirScan.write("No Embedded API Found\n")
          else:
              fdirScan.write("\n".join(apiScan))
              fdirScan.write("\n==========================================\n")
              fdirScan.write("Warning File is Potentially INFECTED!!!!\n")
              malicious_index = True
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
              malicious_index = True
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
              malicious_index = True
          #END Scanning for Shellcode
          
          if malicious_index == True:
              update_DB('ole2.sqlite', hashlist, os.path.getsize(pathFile), malicious_index) # Default DB Name assumed ole2.sqlite

              fdirScan.write("[+] Scanning for Embedded OLE - XOR Case\n")
              if startPEOffset != 0:
                  if embd_ole_scan(bruted) is True:
                      fdirScan.write("Embedded OLE Detected \n")
              fdirScan.write("\n########################################################\n")

              continue
          
          #START XOR Attack
          if PBAR_ACTIVE == True:
              progBar = progressBar(0,256,50)
          else:
              print("[+] Please Wait - XOR Bruteforce Attack Started")
          fdirScan.write("[+] Starting XOR Attack..\n")
          for i in range (256):
            if PBAR_ACTIVE == True:
                progBar.updateAmount(i)
                print progBar, "\r",
                time.sleep(.05)
            bruted = xor_decrypt_data(mappedOle, i)
            startPEOffset = embd_PE_File(bruted)
            if startPEOffset != 0:
                 fdirScan.write("\nDiscovered Embedded Executable matching with XOR Key: {0}".format(hex(i)))
                 fdirScan.write("\n==========================================\n")
                 fdirScan.write("Warning File is Potentially INFECTED!!!!\n")
                 fdirScan.write("Dumping Decoded File..\n")
                 malicious_index = True
                 if dumpDecodedOle(bruted) is True:
                     print("\nDone!")
                 else:
                     print("Error Occurred")
                     continue
          #END XOR Attack
          
          #START UpdateDB          
          update_DB('ole2.sqlite', hashlist, os.path.getsize(pathFile), malicious_index) # Default DB Name assumed ole2.sqlite
          #END UpdateDB 

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

    match = re.search(b'GetSystemDirectory',mappedOle)
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
        
    match = re.search(b'GetTempPath',mappedOle)
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

    match = re.search(b'\x64\xa1\x30\x00\x00',mappedOle) 
    if match is not None:
        shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))
        
    match = re.search(b'\x64\x8b\x1d\x30\x00',mappedOle) 
    if match is not None:
        shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))
        
    match = re.search(b'\x64\x8b\x0d\x30\x00',mappedOle) 
    if match is not None:
        shellcode_presence.append("FS:[30h] Shellcode at offset:{0}".format(hex(match.start())))

    match = re.search(b'\x64\x8b\x15\x30\x00',mappedOle) 
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

def scan_for_known_vulnerabilities(fileName, mappedOle):
    fileFormat_scanner(fileName, mappedOle)
    return

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
    

def obtain_hashes(mappedOle): #on time hash calc -> list()
    hashlist = list()
    
    md5 = hashlib.md5(mappedOle).hexdigest()
    sha1 = hashlib.sha1(mappedOle).hexdigest()

    print("MD5: {0}".format(md5))
    print("SHA-1: {0}".format(sha1))
    
    hashlist.append(md5)
    hashlist.append(sha1)

    return hashlist

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
            print("Invalid Office2007 File Format")
            return False
        else:
            if os.name == 'nt':
                dire = os.curdir + "\\" + fileName[:len(fileName)-5]
                if fileName.endswith('docx'):
                    internal_ext = '\\word'
                elif fileName.endswith('pptx'):
                    internal_ext = '\\ppt'
                elif fileName.endswith('xlsx'):
                    internal_ext = '\\xl'
                
            elif os.name == 'posix':
                dire = os.curdir + "/" + fileName[:len(fileName)-5]
                if fileName.endswith('docx'):
                    internal_ext = '/word'
                elif fileName.endswith('pptx'):
                    internal_ext = '/ppt'
                elif fileName.endswith('xlsx'):
                    internal_ext = '/xl'

            if not os.path.exists(dire):
                os.mkdir(dire)
                deflater = zipfile.ZipFile(fileName)
                deflater.printdir()
                deflater.extractall(dire)
                deflater.close()
                
                # Check for malicious MACROs docx/pptx/xlsx
                if macro_docx_scanner(dire, internal_ext) is True:
                    print("File Contains MALICIOUS Macros!!!!")
                    print("[*] In Depth Analysis")
                    if office2007_details(dire, internal_ext) is True:
                        print("[*] Additional Details Correctly Dumped in Report")
                    else:
                        print("[-] Error While Producing Details Report")
                    return True
                else:
                    print("File Does not Contain Macros")
                    return True
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
    
def update_DB(databaseName, hashes, fileSize, bw_index):
    try:
        if bw_index == False:
            malicious_index = "No"
        else:
            malicious_index = "Yes"
        
        md5 = hashes[0]  # PRIMARY KEY (successively dropped)
        sha1 = hashes[1] # PRIMARY KEY
        
        connect = sqlite3.connect(databaseName)
        cursor = connect.cursor()
        tup = ( 'Null', md5, sha1, fileSize, malicious_index )
        cursor.execute('insert into BWList values(?,?,?,?,?)',tup)
        del tup
        connect.commit()
        cursor.close()       
        
        return
    except sqlite3.Error, e:
        print("An Error Occurred:", e.args[0])
        return
    except:
        print("Generic Error durig DB Update happened\n")
        return
        
def office2007_details(folder, internal_ext):
    # unimplemented
    return True

def zip_archive(fileName):
    
    try:
        if zipfile.is_zipfile(fileName) is True:
                                    
            if os.name == 'nt':
                temp_folder = os.curdir + "\\" + fileName[:len(fileName)-4]
            elif os.name == 'posix':
                temp_folder = os.curdir + "/" + fileName[:len(fileName)-4]                
                                        
            if not os.path.exists(temp_folder):
                os.mkdir(temp_folder)
                deflater = zipfile.ZipFile(fileName)
                deflater.printdir()
                deflater.extractall(temp_folder)
                deflater.close()
                
                if directory_scanner(temp_folder) is True:
                    print("Directory Scan Completed Please Look at DirScan.txt\n")
                    return True
                else:
                    print("Directory Scan Failed")
                    return False
            else:
                print("Temp Dir Already Exists")
                return False
            
        else:
            print("Invalid or Corrupted Zip Archive")
            return False
    except:
        print("Generic Error Happened While Deflating Archive")
    
    return True
    
if __name__ == "__main__":
    main()
