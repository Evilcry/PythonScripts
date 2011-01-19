# just an example
import os
import sys

from optparse import OptionParser
from classOLEScanner import pyOLEScanner


def main():
    usage = "%Prog suspect_file\n"
    description = "Basical Scan for Malicious Embedded objects\n"

    parser = OptionParser(usage = usage, description = description,
    version = "1.1")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Specify a suspect OLE file or directory with OLE files\n")
    else:
        oleScanner = pyOLEScanner(args[0])
        fole = open(args[0],'rb')
        mappedOle = fole.read()
        fole.close()
        
        api_list = oleScanner.known_api_revealer()
        eole = oleScanner.embd_ole_scan()
        isole = oleScanner.isOleFile()
        epe = oleScanner.embd_pe()
        shellc = oleScanner.shellcode_scanner()
        oleScanner.xor_bruteforcer()
        pass

if __name__ == '__main__':
    main()
