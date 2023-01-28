#!/usr/bin/env python3

from __future__ import division
from collections import Counter
import os
import sys
import argparse
import pyshark
import math

# From https://github.com/splunk/utbox/blob/main/utbox/bin/ut_shannon.py
def shannon(word, base=2):
    entropy = 0.0
    length = len(word)

    occ = {}
    for c in word:
        if not c in occ:
            occ[c] = 0
        occ[c] += 1

    for (k, v) in occ.items():
        p = float(v) / float(length)
        entropy -= p * math.log(p, base)

    return entropy

# From https://redcanary.com/blog/threat-hunting-entropy/
def relative_entropy(data, base=2):
        '''
        Calculate the relative entropy (Kullback-Leibler divergence) between data and expected values.
        '''
        entropy = 0.0
        length = len(data) * 1.0

        if length > 0:
            cnt = Counter(data)
            
            # These probability numbers were calculated from the Alexa Top
            # 1 million domains as of September 15th, 2017. TLDs and instances
            # of 'www' were removed so 'www.google.com' would be treated as
            # 'google' and 'images.google.com' would be 'images.google'.
            probabilities = {
                '-': 0.013342298553905901,
                '_': 9.04562613824129e-06,
                '0': 0.0024875471880163543,
                '1': 0.004884638114650296,
                '2': 0.004373560237839663,
                '3': 0.0021136613076357144,
                '4': 0.001625197496170685,
                '5': 0.0013070929769758662,
                '6': 0.0014880054997406921,
                '7': 0.001471421851820583,
                '8': 0.0012663876593537805,
                '9': 0.0010327089841158806,
                'a': 0.07333590631143488,
                'b': 0.04293204925644953,
                'c': 0.027385633133525503,
                'd': 0.02769469202658208,
                'e': 0.07086192756262588,
                'f': 0.01249653250998034,
                'g': 0.038516276096631406,
                'h': 0.024017645001386995,
                'i': 0.060447396668797414,
                'j': 0.007082725266242929,
                'k': 0.01659570875496002,
                'l': 0.05815885325582237,
                'm': 0.033884915513851865,
                'n': 0.04753175014774523,
                'o': 0.09413783122067709,
                'p': 0.042555148167356144,
                'q': 0.0017231917793349655,
                'r': 0.06460084667060655,
                's': 0.07214640647425614,
                't': 0.06447722311338391,
                'u': 0.034792493336388744,
                'v': 0.011637198026847418,
                'w': 0.013318176884203925,
                'x': 0.003170491961453572,
                'y': 0.016381628936354975,
                'z': 0.004715786426736459
            }

            for char, count in cnt.items():
                observed = count / length
                expected = probabilities[char]
                entropy += observed * math.log((observed / expected), base)
        return entropy

def main():
    parser = argparse.ArgumentParser(prog=__file__)
    parser.add_argument('--file', '-f')
    parser.add_argument('--count', '-c', type=int, default=5, help="Amount of suspisious nxdomains with given entropy before an alert is given")
    parser.add_argument('--entropy_treshold', '-et', type=float, default=3, help="Entropy Treshold KL")
    parser.add_argument('--entropy', '-e', default='shannon', help="Entropy, shannon or kl")
    parser.add_argument('--time_frame', '-t', type=int, default=60, help="Time frame treshold, in seconds")
    parser.add_argument('--verbose', '-v', action='store_true')
    params = parser.parse_args()    


    if params.entropy not in ['kl','shannon']:
        sys.stderr.write('Not a valid entropy option')
        sys.exit(1)

    try:
        pcap = pyshark.FileCapture(params.file, display_filter='dns.flags.rcode == 3 and (dns.qry.type == 1 or dns.qry.type == 28 or dns.qry.type == 5)', keep_packets=True)
    except Exception as e:
        sys.stderr.write('Failed to open pcapfile {0}: {1}'.format(params.file, e))
        sys.exit(1)

    data = {}
    alert = {}

    if params.verbose:
        print("START processing packets")
        print("-----------------------------")

    for pkt in pcap:
        #Check if ipv4 or ipv6
        try:
            src_ip = pkt.ip.dst
        except: 
            src_ip = pkt.ipv6.dst

        #if params.verbose:
            #print("Processing following packet | queryname: "+pkt.dns.qry_name+" src_ip: "+src_ip+" time: "+pkt.frame_info.time)
        #Get domain - tld
        domain = str(pkt.dns.qry_name.split('.', 1)[0])

        #Remove www. if it's there
        if domain.startswith('www.'):
            domain = re.sub(r'www.', '', domain)
        
        #Calculate entropy
        if params.entropy == "kl":
            entropy_score = relative_entropy(domain)
        elif params.entropy == "shannon":
            entropy_score = shannon(domain)

        #Check if entropy_score i above treshold.
        if entropy_score < params.entropy_treshold:
            #we wont proces this packet
            if params.verbose:
                print("NXDomain below entropy treshold | query: "+pkt.dns.qry_name+" src_ip: "+src_ip+" time: "+pkt.frame_info.time+" Entropy score: "+str(entropy_score))
        else:
            #Epoch is in nonaseconds with a dot in the middle (1654384424.204505000), lets normalize without the dot
            nano_epoch = int(pkt.frame_info.time_epoch.replace('.', ''))

            #Check if src ip excist in data dict, if not create it and initialize an empty list we can later append data to
            if src_ip not in data:
                data[src_ip] = []

            #Lets check if there are already X amount of queries in the data set within the time frame
            count = 0
            for entry in data[src_ip]:
                #Check how many packets are withing the time treshold, treshold is given in seconds, so at nine 0's te make it nanonseconds
                if nano_epoch - entry[2] < params.time_frame * 1000000000:
                    count +=1

            if params.verbose:
      	        print("Hit "+str(count)+" within timeframe. | Query: "+pkt.dns.qry_name+" src_ip: "+src_ip+" time: "+pkt.frame_info.time+" Entropy score: "+str(entropy_score))

            #Check if count above treshold, if so lets save it for an alert
            if count >= params.count:
                alert[src_ip] = 'alert'

            #Done proccessing this packet, append the data to the dataset
            data[src_ip].append([pkt.dns.qry_name, entropy_score, nano_epoch, pkt.frame_info.time, src_ip])

    #Processing every packet is done, lets summarize:
    if params.verbose:
        print("DONE Processing")
        print("-----------------------------")
    #If alert is empty dict, there are no alerts
    if not alert:
        print("no hits found with given tresholds")
    else:
        print("Possible C2 traffic detected coming from the following IP\'s:")
        for i in alert:
            print(i)
            if params.verbose:
                print("Detected based on the following queries:")
                for x in data[i]:
                    print(x)

    if params.verbose:
        print("Full data set with entropy_score above treshold:")
        for i in data:
            print(data[i])

if __name__ == '__main__':
    main()
