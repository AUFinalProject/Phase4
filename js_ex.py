# Authors Alexey Titov and Shir Bentabou
# Version 1.0
# Date 05.2019

# libraries
import subprocess
import os
import re


def ex_js(filename, samples_path):
	# PART create extractJS.txt
	f1 = open('./extractJS.txt', 'w+')   #open file
	catalog = os.getcwd()                #returns current working directory of process (codepath=catalog)
	f1.write('extract js > '+catalog+'/JSfromPDF.txt')   #write to file
	f1.close()                                           #close file

	# PART JS
	scriptpath = os.path.join('peepdf/', 'peepdf.py')    #joins to path
	Mypdf = samples_path+filename		     	     #mypdf creation
	CommandOfExtract = catalog+'/'+'extractJS.txt'
	p = subprocess.Popen(['python', scriptpath, '-l', '-f', '-s', CommandOfExtract, Mypdf])   #open subprocess and extract
	p.wait()


#relevant paths
samples_path = "/home/tzar/Desktop/Final_Project/phase4/samp/"			#path for pdf samples
code_path = "/home/tzar/Desktop/Final_Project/phase4/"				#path for code directory (and temp txt file and command file)	
texts_path = "/home/tzar/Desktop/Final_Project/phase4/texts"			#path for text files containing js
isjs_path = "/home/tzar/Desktop/Final_Project/phase4/JaSt-master/js/"		#path for is_js.py code
errorfile_path = "/home/tzar/Desktop/Final_Project/phase4/peepdf/errors.txt"    #path for error file (in case peepdf fails parsing)

for file_name in os.listdir(samples_path):

	print(file_name)
	ex_js(file_name, samples_path)
	

	#variables for features
	num_objects = 0
	num_js_lines = 0
	num_backslash = 0
	num_evals = 0
	num_slashx = 0
	num_slashu0 = 0
	no_js = 0       #is there really a reason to keep it?
	valid_js = 0
	malformed_js = 0

	#handling the case that previous file failed to parse
	errorfile = os.path.isfile(errorfile_path)      #holds boolean value
	if errorfile:
		os.remove(errorfile_path)
		print(file_name+" failed parsing!")
		features = [-1, -1, -1, -1, -1, -1, -1, -1, -1]
		print(features)
	else:
		fi_na = open(str(texts_path)+'/'+str(file_name)+'.txt', 'w+')    #open text file for current file
  	        temp_file = open(str(code_path)+'/JSfromPDF.txt', 'r')
		#copy content from temp file to text file
		for line in temp_file.readlines():
			fi_na.write(line)
			if "// peepdf comment: Javascript code located in object" in line:
				num_objects = num_objects + 1
			elif line != '\n':
				num_js_lines = num_js_lines + 1
			num_backslash = num_backslash + line.count("\\")    #string literal for backslash
			num_evals = num_evals + line.count("eval")
			num_slashx = num_slashx + line.count("\\x")
			num_slashu0 = num_slashu0 + line.count("\u0")
		temp_file.close()	
		fi_na.close()

		#check if valid JS or malformed JS
		if num_js_lines != 0:
			isjs = subprocess.Popen(['python', isjs_path+"is_js.py", "--f", texts_path+"/"+file_name],stdout=subprocess.PIPE)
        		for line in isjs.stdout:
            			if "malformed" in line:
					malformed_js = 100
				elif " valid" in line:
					valid_js = 50
		else:
			no_js = 0


		#save and print features
		features=[num_objects, num_js_lines, num_backslash, num_evals, num_slashx, num_slashu0, no_js, valid_js, malformed_js]
		print(features)
