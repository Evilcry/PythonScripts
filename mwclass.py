#-------------------------------------------------------------------------------
# Name:        mwclassify
# Purpose: Malware Classifier based on Shadowserver Sandbox APIs
#
# Author:      Giuseppe 'evilcry' Bonfa
#
# Created:     14/08/2012
# Copyright:   (c) Giuseppe 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import os
import urllib2
import hashlib
import zipfile

class mwClassify():
    def __init__(self,dirtoscan):
        self.dirtoscan = dirtoscan

    def hashlist(self):
        dirlist = os.listdir(self.dirtoscan)
        f = open(self.dirtoscan + "-hash.txt", "w")
        for fname in dirlist:
            full_path = self.dirtoscan + "\\" + fname
            if zipfile.is_zipfile(full_path) is True:
                zipobj = zipfile.ZipFile(full_path)
                zipcont = zipobj.read(zipobj.namelist()[0])
                md5 = hashlib.md5(zipcont).hexdigest()
                f.write(fname + " -> " + zipobj.namelist()[0] + " -> " + md5 + "\n")
            else:
                ftohash = open(full_path, "rb")
                datatohash = ftohash.read()
                ftohash.close()
                md5 = hashlib.md5(datatohash).hexdigest()
                f.write(fname + " -> " + md5 + "\n")
        f.close()

    def purge_duplicates(self):
        unique = []
        for filename in os.listdir(self.dirtoscan):
                f = open(self.dirtoscan + "\\" + filename, "rb")
                content= f.read()
                f.close()
                md5 = hashlib.md5(content).hexdigest()
                if md5 not in unique:
                    unique.append(md5)
                else:
                    os.remove(self.dirtoscan + "\\" + filename)
                    print "Removed: %s with MD5 Hash: %s" % (filename, md5)

##def main():
##    mwClassifier = mwClassify("15-8-2012")
##    mwClassifier.hashlist()
##    mwClassifier.purge_duplicates()
##
##    pass
##if __name__ == '__main__':
##    main()
