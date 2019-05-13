# Authors Alexey Titov and Shir Bentabou
# Version 2.0
# Date 05.2019

# libraries
import subprocess
import os
import re
from collections import defaultdict

# /ObjStm counts the number of object streams. An object stream is a stream object that can contain other objects, and can therefor be used to obfuscate objects (by using different filters).

# /JS and /JavaScript indicate that the PDF document contains JavaScript.
# Almost all malicious PDF documents that I've found in the wild contain JavaScript (to exploit a JavaScript vulnerability and/or to execute a heap spray). 
# Of course, you can also find JavaScript in PDF documents without malicious intend.

# /AA and /OpenAction indicate an automatic action to be performed when the page/document is viewed. 
# All malicious PDF documents with JavaScript I've seen in the wild had an automatic action to launch the JavaScript without user interaction.
# The combination of automatic action  and JavaScript makes a PDF document very suspicious.

# /JBIG2Decode indicates if the PDF document uses JBIG2 compression. This is not necessarily and indication of a malicious PDF document, but requires further investigation.

# /Launch counts launch actions.

# /URI  urls
default_features = ["/ObjStm ", "/JS", "/JavaScript", "/AA", "/OpenAction", "/JBIG2Decode", "/Launch", "/URI"]

def defaultJS(filename, d):
    obj = 0
    endobj = 0
    stream = 0
    endstream = 0
    try:
	ans=[]
        p = subprocess.Popen(['python',
                            '/home/tzar/Desktop/Final_Project/phase4/pdfid_v0_2_5/pdfid.py',filename],stdout=subprocess.PIPE)
        for line in p.stdout:
            if '%PDF' in line or line.startswith('PDFiD'):
                continue
            pattern1 = "^\s*(\S+)\s+(\d+)"
            m = re.search(pattern1, line)
	    if m is not None:
                key = m.group(1)
                if key in default_features:
		    ans.append(int(m.group(2)))
		elif (key == "obj"):
			obj = int(m.group(2))
	   	elif (key == "endobj"):
			endobj = int(m.group(2))
		elif (key == "stream"):
			stream = int(m.group(2))
	   	elif (key == "endstream"):
			endstream = int(m.group(2))
			ans.append(obj - endobj)
			ans.append(stream - endstream)
        return ans
    except Exception:
	ex=[-1, -1, -1, -1, -1, -1, -1, -1, -1]
        return ex


if __name__ == '__main__':
    os.chdir('/home/tzar/Desktop/Final_Project/phase4/PDF')
    d = dict()
    for root, dirs, file_names in os.walk(os.getcwd()):
        for file in file_names:
            ans = defaultJS(file, d)
            print(ans)
