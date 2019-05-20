# Authors Alexey Titov and Shir Bentabou
# Version 1.0
# Date 05.2019

# libraries
import pyPdf
import re
import sys

# lists
port_good = [":443/", ":80/", ":8080/"]
bad_word = ["target", "&", "?", "download", "php", "loader", "login", "=", "+"]

filename = sys.argv[1]
uri = '/URI'
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
try:
    pdf = pyPdf.PdfFileReader(file(filename))
    lst = list(pdf.pages) 									# Process all the objects.
    pdfObjects = pdf.resolvedObjects
    for key, value in pdfObjects.iteritems():
        for keyL, valueL in value.iteritems():
            u = valueL.getObject()
            counter_objects += 1
            try:
                if uri in u:
                    counter_urls += 1
                    # File:
                    if(-1 != u[uri].find("File:") or -1 != u[uri].find("file:")):
                        counter_fileURL += 1
                        continue
                    url = re.search(r"(?P<url>(?:http|ftp)s?://[^\s]+)",u[uri]).group("url")
                    url = url.encode("ascii", "ignore")
                    if url not in set_urls:
                        set_urls.append(url)
            except:
                continue
    for url in set_urls:
        # second link
        if(re.search(r'((?:http|ftp)s?(%[0-9a-fA-F]+)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)', url)):
            counter_secondLINK += 1
        # encoded
        if(re.search("(%[0-9a-fA-F]+)", url)):
            counter_encoded += 1
        # IP
        if(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)):
            counter_IP += 1
        # bad words
        for word in bad_word:
            if(-1 != url.find(word)):
                counter_badWORDS += 1
                break
        # ports
        if(re.search(r"(:\d{1,5}/)", url)):
            port = re.search(r"(:\d{1,5}/)", url).group()
            flag = True
            for p_g in port_good:
                if(port == p_g):
                    flag = False
            if (flag):
                counter_ports += 1
        try:
            # length after second '/'
            substring = re.search(r'(?:http|ftp)s?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/',url).group()
            leng = len(url.replace(substring, ''))
            if (leng > max_length):
                max_length = leng
        except:
            continue
    ans = [counter_urls, len(set_urls), counter_fileURL, max_length, counter_secondLINK, counter_encoded, counter_IP, counter_badWORDS, counter_ports]
    print(ans)
except Exception as e:
    ex = [-1, -1, -1, -1, -1, -1, -1, -1, -1]
    print(ex)
