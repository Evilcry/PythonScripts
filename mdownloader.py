#-------------------------------------------------------------------------------
# Name:        massdownloader
# Purpose: mass malware downloader
#
# Author:      Giuseppe 'evilcry' Bonfa
#
# Created:     12/08/2012
# Copyright:   (c) Giuseppe 2012
# Licence:  FATTI I CAZZI TOI - Cettolaqualunque 1.0
#-------------------------------------------------------------------------------

import os
import Queue
import threading
import urllib2
import hashlib
import datetime

# - MultiThreaded Queue based Downloader - START
class Downloader(threading.Thread):
    def __init__(self, queue, destdir):
        threading.Thread.__init__(self)
        self.queue = queue
        self.destdir = destdir

    def run(self):
        while True:
            url = self.queue.get()
            self.download_file(url, self.destdir)
            self.queue.task_done()

    def download_file(self, url, destdir):
        try:
            req = urllib2.urlopen(url)
            content = req.read()
            req.close()
        except urllib2.URLError, e:
            print "Skipping: %s Reason: %s" % (url, e.reason)
        fname = os.path.basename(url)
        try:
            f = open(destdir + "\\" + fname,'wb')
            if 'content' in locals():
                if len(content) is not 0:
                    f.write(content)
            f.close()
        except IOError, e:
            print "Skipping: %s" % fname
# - MultiThreaded Queue based Downloader - END

def daily_dir():
    now = datetime.datetime.now()
    actual_date = "%d-%d-%d" % (now.day, now.month, now.year)
    if os.path.exists(actual_date) is False:
        os.mkdir(actual_date)
    return actual_date

def get_daily_list(datelist):
    dwn_list = urllib2.urlopen("http://vxvault.siri-urz.net/URL_List.php")
    list_path = datelist + ".txt"
    f = open(list_path, "w")
    f.write(dwn_list.read())
    f.close()
    return list_path

def parse_list(list_path):
    f = open(list_path, "r")
    lines = f.readlines()
    f.close()
    lines[0:4] = []
    for i in range(len(lines)):
        lines[i] = lines[i].rstrip('\r\n')
    return lines

def main():
    print("Massive Downloader")
    download_dir = daily_dir()
    list_path = get_daily_list(download_dir)
    mal_url_list = parse_list(list_path)

    # Mass Download - START
    queue = Queue.Queue()

    for i in range(4):
        t = Downloader(queue, download_dir)
        t.setDaemon(True)
        t.start()

    for url in mal_url_list:
        queue.put(url)

    queue.join()
    # Mass Download - END

    pass

if __name__ == '__main__':
    main()
