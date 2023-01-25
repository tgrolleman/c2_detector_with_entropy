# C2 Traffic detector
Script to detect C2 traffic of malware using a DGA Algorithm. Malware using a DGA algorithm generates a lot of domain names which it will try to contact which is called Domain Fluxing. This generates a lot DNS Queries resulting in a NXDomain. Because these domain names are generated they have a high "entropy". This script will extract NXDomains by source IP from the given pcap. And will calculate the randomness of the domain name with Shannon or with the Kullback–Leibler divergence. The scripts will give an alerts if there is a suspicion of malware trying to connect to a C2 server by domain fluxing. 
 
## Setup
`pip install -r requirements.txt`
 
 ## Usage
`./detector.py $parameters$` 
 
 ## Parameters
 `-f, --file | input pcapfile`
 `-c, --count | Amount of suspisious nxdomains with given entropy before an alert is given, defaults to 5`
 `-e, --entropy | Entropy algorithm used, kl or shannon, defaults to shannon`
 `-et, --entropy_treshold | Entropy Treshold`
 `-t, --time_frame | Time treshold in seconds, defaults to 60`
 `-v, --verbose | Verbose output`

 ## Example
`./detector.py -f test.pcap -c 5 -e kl -et 1.05 -t 300 -v` 
