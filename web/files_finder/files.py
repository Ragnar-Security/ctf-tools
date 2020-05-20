#!/usr/bin/env python3
# Author: WittsEnd2
# Contributors: 
import queue
import threading
import os
import urllib.request as urllib
import argparse
threads = 10
web_paths = queue.Queue()
target = ""
directory = ""
def test_remote():
    while not web_paths.empty():
        path = web_paths.get()
        url = "%s%s" % (target, path)
        request = urllib.Request(url)
        try:
            response = urllib.urlopen(request)
            content = response.read()
            print("[%d] => %s" % (response.code, path))
            response.close()

        except urllib.HTTPError as error:
            # print "Failed %s" % error.code
            pass

def main(t, d):
    target = t
    directory = d 
    if (directory != "" and target != ""):

        filters = [".jpg", ".gif", "png", ".css"]
        os.chdir(directory)
        for r, d, f in os.walk("."):
            for files in f:
                remote_path = "%s/%s" % (r, files)
            if remote_path.startswith("."):
                remote_path = remote_path[1:]
            if os.path.splitext(files)[1] not in filters:
                web_paths.put(remote_path)

        for i in range(threads):
            print("Spawning thread: %d" % i)
            t = threading.Thread(target=test_remote)
            t.start()
    else:
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyzes web target given a framework to base it off of.")
    parser.add_argument('-t', '--target', required=True, help="Enter a remote target to anlayze", nargs=1, metavar="REMOTE TARGET")
    parser.add_argument('-l', '--localdir',  required=True, help="Enter a local directory containing the template code (E.g. WordPress)", nargs=1, metavar="LOCAL DIRECTORY")
    args = parser.parse_args()
    print(args.target[0])
    main(args.target[0], args.localdir[0])