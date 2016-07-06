# CVE  
Repository for findings and work in CVE security part

## cve-search  
#### Setup guide (Ubuntu 14.04):
##### Requirements:  
* **Mongodb**  
`apt-get -y install mongodb`  
`echo "setParameter=textSearchEnabled=true" >> /etc/mongodb.conf`  
`service mongodb restart`  
* **redis**  
`apt-get -y install build-essential tcl8.5 redis-server`  
* **python3**  
Installed by default.  
* **pip3**  
`apt-get -y install python-dev libxml2-dev libxslt1-dev zlib1g-dev python3-pip
libffi-dev`  
* **git**  
`apt-get -y install git`  

##### Setup:  
###### Download:  
`git clone https://github.com/cve-search/cve-search.git`  
`cd cve-search`  
`cp etc/configuration.ini.sample etc/configuration.ini`  
###### Install pip requirements, populate and update data base:  
`pip3 install -r requirements.txt`  
`python3 ./sbin/db_mgmt_create_index.py`  
`python3 ./sbin/db_mgmt.py -p`  
`python3 ./sbin/db_mgmt_cpe_dictionary.py`  
`python3 ./sbin/db_mgmt_cpe_other_dictionary.py`  
`python3 ./sbin/db_updater.py -c`  

##### Use:  
General search script **search.py**(cve-search/bin):  
* `python3 search.py -p <something>` will return a list of CVE's that contains 
<something>, the script offer its own output format but you can use the 
option -o to obtain the output as JSON, HTML, CSV or XML. use the option -h 
to see all available options.  
      
Web interface script **index.py**(cve-search/web):  
* `python3 index.py` will host a web interface more user friendly to search 
for CVE's. by default it is hosted at http://localhost:5000/  This web interface
come with an API at http://localhost:5000/api you can use it to get CVE
information with "curl" for example:  
    - **/api/browse/microsoft/xbox_360** will return CVE info for that product.  
    - **/api/cve/cve-2015-0001** will return the info for the specific CVE.  
    - **/api/last**  will return the last CVE entries in the data base.  
The returned info is in JSON.  

You should make and update of the CVE's database everyday, to do that put the 
script **db_updater.py** in a cron job to run daily (as root) make the script 
updateCve.sh:  

`#!/bin/bash`  
`python3 <path_to_cve-search>/sbin/db_updater.py`

Put it here and give execution permission:  

`cp updateCve.sh /etc/cron.daily/`  
`chmod +x /etc/cron.daily/updateCve.sh`  

## cve-portal  
not working :fearful:

## cve-scan  
A tool that uses nmap to detect vulnerabilities in the localhost or network.  
#### Setup guide (Ubuntu 14.04):  
##### Requirements:  
* **nmap**
    `apt-get -y install nmap`
* **cve-search**
    A running instace of the web interface, cve-scan uses the API.  
    
##### Setup:  
###### Download:  
`git clone https://github.com/NorthernSec/CVE-Scan.git`  
`cd Cve-Scan/`  
###### Setup:
`pip3 install -r requirements.txt`  

##### Use:  
This is just some scripts (converter.py, analyzer.py, visualizer.py and 
Nmap2CVE−Search.py), to use them:  
1. Generate a nmap output:  
    `nmap −A −O <localhost> −oX output.xml`  
2. Convert the xml output to json format:  
    `python3 converter.py output.xml output.json`
3. Output and query cve-search API:  
    `phyton3 analyzer.py −j output.json output.analyzer`
4. Visualize:  
    `python3 visualizer.py output.analyzer`  
    The visualizer.py script puts the results by default in a web interface at 
    http://localhost:5050/ but you can use options to present the results on the
     console and even into a pdf file.  
5. All in 1:  
    `python3 Nmap2CVE−Search.py output.xml`  
    This will make the steps 2,3 and 4 in one
     go.  

## script  
A [script](https://gitlab.uni.lu/dlagunes/cve/tree/master/script) created to 
search for specific cve in a range of dates, Its propuse is to run every day and
 look for any new security vulnerabilities.  
 Every time it runs it will save the last run date and it will search for 
 vulnerabilities posted after the last date.  

