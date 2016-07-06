#!/usr/bin/env ruby
# The script uses the cve-search search.py script to search and print
# for some vulnerabilities that the user want to look for since a date
# it can be used to see if there are new security updates from the last
# time it was executed.
#
# Author::    Derick Lagunes  (mailto:dlagunes.datic@utez.edu.mx)
# Copyright:: 
# License::   

require 'yaml'
require 'optparse'
require 'ostruct'
require 'open-uri'
require 'csv'

#Parse parameters
param = OpenStruct.new
OptionParser.new do |opt|
        opt.banner = "Usage: search.rb [options]\n\n"
        opt.on('-f', '--file  PATH [String]', 'The path to the Yaml configuration file, if not passed the script will search for "list.yml" in the same directory by default') { |o| param.file = o }
        opt.on('-s', '--since DATE [DateTime]', 'Since when the search is going to look up, if not passed the script will use last_update data from the Yaml configuration program instead, you can enter: yyyy-mm-dd') { |o| param.since = o }
        opt.on('-d', '--debian', 'If this option is passed the result will add the DSA(Debian Security Advisories)') { |o| param.debian = o }
        opt.on('-a', '--all', 'Shows all available information at output') { |o| param.all = o }
        opt.on('--seq', 'Change to sequential execution (and not with threads)') { |o| param.seq = o }
        opt.on('-c', '--check', 'this option checks the Yaml file and copares it with your system, if it does not find something it will be ignored from the search') { |o| param.check = o }
        opt.on_tail('-v', '--version', 'Shows version') { puts "search.rb v0.9"; exit }
        opt.on_tail('-e', '--example', 'To see an example of a Yaml file (.yml)') { puts "---\noperating_system:\n- debian\n- centos\n- redhad\n- ubuntu\nsoftware:\n- openssh\n- apache\n- ejabberd\n- openldap\n- php\n- phpmyadmin\nequipment:\n- dell\n- nexsan\n- netapp\nlast_update: !ruby/object:DateTime 2010-06-14 13:04:30.060416709 +00:00"; exit }
        opt.on_tail('-h', '--help', 'Shows help') { puts "\n\nThis script uses the cve-search database and a list in a Yaml file(see -f) to search for the items in the list it will search the cve's from a date(see -s) and based in its severity level (cvss). It wll show the results in the screen, you should edit this script to modify the searchPath and severityLvl variables\n\n"; puts opt; puts "\n\n"; exit }
end.parse!

######################
# MUST SET VARIABLES #
######################
$searchPath = "/home/vagrant/git/cve-search/bin/"
$severityLvl = "7"

# init variables #
userDate = DateTime.new
lastDate = DateTime.new
useUserDate = false  				## Some flags to modify the output
all = false
if param.all then; all = true; end


####################### methods definitions ###########################
# Method to return the yaml file values as a hash
# Params:
# +f+:: type file, the yaml configuration file
def parse_yaml(f)
  return YAML.load_file(f)
end

# This method executes the external search command for the cve-search database
# it returns the output of the query from mongodb
# the query is:
# query={'last-modified': {'$gt': date} , "vulnerable_configuration": {"$regex": object} , "cvss": {'$gt':severityLvl}}
# Params:
# +object+:: The item to search, ex: debian
# +date+:: Type DateTime, the start date to begin the search 
# +type+:: Type of search, csv format:
# "",[item['id'], item['Published'], item['Modified'], item['cvss'], item['summary'], refs]
def startSearch(object, date, all)
	if all then
        	return "python3 #{$searchPath}modifiedSearch.py -p #{object} -d #{date} -lvl #{$severityLvl}"
	else
        	return "python3 #{$searchPath}modifiedSearch.py -o csv -p #{object} -d #{date} -lvl #{$severityLvl}"
	end
end

# Method to execute the search for every item in the list and populate a hash
# Params:
# +list+:: Type Array, an array of items to search
# +date+:: Type DateTime, The date to filter the search
# +all+:: Type boolean, flag to change the output
def itemSearch(list, date, all)
	hash = Hash.new
        list.each do |item|
		auxArray = Array.new
	        cmd = startSearch( item, date, all)
	        aux = `#{cmd}`
		if all and !aux.empty? then 				## Put all the info
	                auxArray << aux
			hash[item] = auxArray
		elsif !all and !aux.empty? then 			## Handle the csv format to get limited information
			cveArray = CSV.parse(aux, col_sep: '|')
			cveArray.each do |cve|	
				auxArray << [cve[0], cve[3]]
			end
			hash[item] = auxArray
		else							## There's no info for this item
	                hash[item] = ["No entries found for #{item}!"]
		end
        end
	return hash
end

# Method to print "nicely" the output of the search
# Params:
# +itemHash+:: Type hash, a hash of cve items separated by key items
# +all+:: Type boolean, flag to change the output
def printSearch(itemsHash, all)
	if all then 
		itemsHash.each do |key, info|
			puts "#########Search for #{key} start#########"
			puts info
			puts "#########Search for #{key} stop##########\n\n\n"
		end
	else
		itemsHash.each do |key, info|
			puts "#{key} :".rjust(20)
			puts '["    CVE ID   ","CVSS"]'.rjust(40)
			info.each do |cve|
				puts "#{cve}".rjust(40)
			end
			puts ""
		end
	end
end

# Method to print "nicely" the output of the DSA search
# Params:
# +itemHash+:: Type hash, a hash of cve items separated by key items
def printDsa(itemsHash)
	itemsHash.each do |key, info|
		puts "#{key} :".rjust(20)
		info.each do |dsa|
			puts "#{dsa}".rjust(40)
		end
		puts ""
	end
end



# This method open the url from the debian security list and looks for specific items
# it will search through 2 years range.
# Params:
# +list+:: list of items to search
# +ancientYear+:: start of time range
# +thisYear+:: end of time range
def dsaSearch(list, ancientYear, thisYear)
        hash = Hash.new
	list.each do |item|
		auxArray = Array.new
                for y in ancientYear..thisYear
                        file = open("https://lists.debian.org/debian-security-announce/#{y}/maillist.html")
                        page = file.read
			flag = false
                        page.each_line do |line|
                                if line.include?(item) then
                                        auxArray << " - https://lists.debian.org/debian-security-announce/#{y}/#{line[34..46]}"
                                end
                        end
                end
		hash[item] = auxArray
		if hash[item].empty? then
			hash[item] = ["No entries found for #{item}!"]
		end
        end
	return hash
end
################# End of methods #########################


# Start by getting the yaml file
file = 'list.yml'           #default value (same directory)
if param.file then          #if user pass the file
        file = param.file.to_s
end

# First check if yaml file is there
if !File.file?(file) then
        abort("Yaml file not found!, are you sure #{file} is accesible?")
else
        # open yaml file
        # get the hash from the yaml file
        items = parse_yaml(file)
	
	#  User wants to filter packages?
	## Check if the current system have yum, else it have apt
	if param.check then
		yum = false
		if File.file?("/etc/redhat-release") then
			yum = true
		end
		check = ""
		if yum then					## no other way?
			check = `yum list installed`
		else
			check = `dpkg -l`
		end
		
		puts "\nSearching for installed software...\n\n"	
		exclude = []
		items['software'].each do |soft|		## se if there are any matches
			if check.include?(soft) then 
				puts "#{soft} found!"
			else
				puts "#{soft} not found! Excluding from search..."  
				exclude << soft			## if not remove it from main list, later
			end
		end
		exclude.each { |ex| items['software'].delete(ex) }	## remove it here
		puts ""
	end	
################################
end

# Check for user defined date
if param.since then
        begin
                useUserDate = true
                userDate = DateTime.parse(param.since)
        rescue ArgumentError    ## if the date is bad
                abort("You entered a bad DateTime format, please enter a valid DateTime")
        end
end

# iterate the items and get values
# SO HW SW Date
if useUserDate then
        lastDate = userDate
else
        lastDate = items['last_update']
end
# convert DateTime to string for query
stringDate = lastDate.strftime("%Y-%m-%dT%H:%M:%S.%3N%:z")
soft = items['software']
hard = items['equipment']
system = items['operating_system']


## now proceed with the search
# Search if cve-search is available
if File.directory?($searchPath) then
        puts "cve-search found!"
        puts "now searching in cve-search data base for specified entries after #{stringDate}..."
else
        abort("cve-search/bin not found, check searchPath variable")
end

# use the script in /bin/modifiedSerach.py to search the specific things one by one
## threaded or sequential
if !param.seq then
	t1 = Thread.new{ printSearch(itemSearch(soft, stringDate, all),all) }
	t2 = Thread.new{ printSearch(itemSearch(hard, stringDate, all),all) }
	t3 = Thread.new{ printSearch(itemSearch(system, stringDate, all),all) }

	t1.join
	t2.join	
	t3.join
else
	printSearch(itemSearch(soft, stringDate, all),all) 
	printSearch(itemSearch(hard, stringDate, all),all)
	printSearch(itemSearch(system, stringDate, all),all)
end

# change lastDate in yaml file
# this command uses ruby inline file modifyation for over wrtie the date AND create a backup of the last file
#`ruby -p -i.back -e 'gsub("#{stringDate}","#{DateTime.now}")' #{file}`
# this to commands do the trick too but with no backup, personally i think the inline one is better
items['last_update'] = DateTime.now #Modify
File.open(file, 'w') {|f| f.write items.to_yaml } #Store


# if the user wants the DSA's
if param.debian then
        # For DSA (Debian Security Advisories) won't be better to suscribe to the mailing list?
        # anyway i guess the stand alone option woulb be to create a local DSA database which could be kind of hard, the other aproach would use internet to actually go and look up at https://lists.debian.org/debian-security-announce/yyyy/maillist.html

        # get data from lastDate and time
        year = lastDate.strftime("%Y")
        thisYear = DateTime.now.strftime("%Y")

        # system list does not apply for this search because all advisories are for "Debian"
	if !param.seq then
        	t1 = Thread.new{ printDsa( dsaSearch(soft, year, thisYear) ) }
	        t2 = Thread.new{ printDsa( dsaSearch(hard, year, thisYear) ) }
		t1.join
		t2.join
	else
        	printDsa( dsaSearch(soft, year, thisYear) )
	        printDsa( dsaSearch(hard, year, thisYear) )
	end
end

puts "Done"
