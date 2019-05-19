# Authors Alexey Titov and Shir Bentabou
# Version 1.0
# Date 05.2019

# libraries
import pyPdf
import re

# lists
port_good = [":443/",":80/",":8080/"]
bad_word = ["target","&","?","download","php","loader","login","=","+"]


uri = '/URI'
pdf = pyPdf.PdfFileReader(open("3.pdf"))
lst = list(pdf.pages) 				# Process all the objects.
pdfObjects  = pdf.resolvedObjects
set_urls = []
counter_urls = 0
counter_objects = 0
counter_badWORDS = 0
counter_ports = 0
counter_fileURL = 0
max_length = 0
counter_IP = 0
counter_secondLINK = 0
counter_encoded = 0
for key, value in pdfObjects.iteritems():
	for keyL, valueL in value.iteritems():
		u = valueL.getObject()
		counter_objects += 1
		try:
			if u.has_key(uri):
				counter_urls += 1
				# File:
				if(-1 != u[uri].find("File:") or -1 != u[uri].find("file:")):
					counter_fileURL += 1
					continue
				# url = re.search("(?P<url>https?://[^\s]+)", u[uri]).group("url")
				url = re.search("(?P<url>(?:http|ftp)s?://[^\s]+)", u[uri]).group("url")
				url = url.encode("ascii", "ignore")
				if not url in set_urls:
					set_urls.append(url)
					print(url)
		except:
 			continue
for url in set_urls:
	# second link
	if(re.search('((?:http|ftp)s?(%[0-9a-fA-F]+)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)', url)):
		counter_secondLINK += 1
	# encoded
	if(re.search("(%[0-9a-fA-F]+)", url)):
		counter_encoded += 1
	# IP
	if(re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)):
		counter_IP += 1
	# bad words
	for word in bad_word:
		if( -1 != url.find(word)):
			counter_badWORDS += 1
			break
	# ports
	if(re.search("(:\d{1,5}/)", url)):
		port = re.search("(:\d{1,5}/)", url).group()
		flag = True
		for p_g in port_good:
			if(port == p_g):
				flag = False
		if (flag):
			counter_ports += 1
	try:
		# length after second '/'
		substring = re.search('(?:http|ftp)s?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/',url).group()
		leng = len(url.replace(substring,''))
		if (leng > max_length):
			max_length = leng
	except:
		continue
#print("Objects: "+str(counter_objects))
print("URLs: "+str(counter_urls))
print("URLs set: "+str(len(set_urls)))
print("file urls: "+str(counter_fileURL))
print("max length= "+str(max_length))
print("second link= "+str(counter_secondLINK))
print("encoded= "+str(counter_encoded))
print("IP= "+str(counter_IP))
print("bad words= "+str(counter_badWORDS))
print("ports= "+str(counter_ports))
