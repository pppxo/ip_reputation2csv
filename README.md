# ip_reputation2csv
Python script to check the reputation of multiple IP addresses using 3 of biggest engines (Virus Total, IPviod and AbuseIPDB).

# Requirements
- All you need is python3 installed with the libraries:
  + BeautifulSoup4
  + requests
  + json
  + csv
  + os

# How to use
- Put the IP adresses directly in (IPs.txt) file seperated by new line.
- Use the CMD to run the command:
  > python main.py 
- A CSV file will be generated and opened with all IP reputation results.
