# cveScript  
Uses cve-search database and scripts to look for items inside a Yaml file like:  
1. operating system :
  * debian
  * ubuntu
2. software :
  * openssh
  * apache
3. equipment :
  * dell
  * netapp
4. last update :
  * ”2016−06−08T09:55:57+00:00”

It will print in stdout the results of the search like this:  
![alt text](script/output.png)  

To display a more detailed information for every cve use the --all option  

List of options:  
* -a, --all, shows all info
* -f, --file, pass a yaml file manually
* -s, --since, pass a date manually
* -d, --debian, shows Debian Security Advisories too
* --seq, execute the search in squential and not with threads
* -c, --check, check the software tag in the Yaml file and removes if not
 present at the system
* -v, --version, shows version
* -e, --example, shows an exemple Yaml file
* -h, --help, shows help


For make the search script work you need to copy  

**modifiedDatabaseLayer.py to cve-search/lib/**  
**modifiedSearch.py        to cve-search/bin/**  

and make them executables.