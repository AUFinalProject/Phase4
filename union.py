# Authors Alexey Titov and Shir Bentabou
# Version 1.0
# Date 05.2019

# libraries
#import pyPdf
import PyPDF2
import re
import subprocess
import os
import numpy as np
from collections import defaultdict
import logging
import pandas as pd
from numpy import random
import gensim
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
from sklearn.pipeline import Pipeline
from sklearn.linear_model import SGDClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import GridSearchCV

# global lists
port_good = [":443/", ":80/", ":8080/"]
bad_word = ["target", "&", "?", "download", "php", "loader", "login", "=", "+"]
default_features = [
    "obj",
    "endobj",
    "stream",
    "endstream",
    "/ObjStm ",
    "/JS",
    "/JavaScript",
    "/AA",
    "/Launch",
    "/OpenAction",
    "/AcroForm",
    "/RichMedia"]
#                     0       1         2           3           4          5         6          7        11            8             9            10
# /ObjStm counts the number of object streams. An object stream is a stream object that can contain other objects, and can therefor be used to obfuscate objects (by using different filters).
# /JS and /JavaScript indicate that the PDF document contains JavaScript.
# Almost all malicious PDF documents that I've found in the wild contain JavaScript (to exploit a JavaScript vulnerability and/or to execute a heap spray).
# Of course, you can also find JavaScript in PDF documents without malicious intend.
# /AA and /OpenAction indicate an automatic action to be performed when the page/document is viewed.
# All malicious PDF documents with JavaScript I've seen in the wild had an automatic action to launch the JavaScript without user interaction.
# The combination of automatic action  and JavaScript makes a PDF document very suspicious.
# /RichMedia can imply presence of flash file.
# /Launch counts launch actions.
# /AcroForm this tag is defined if a document contains form fields, and is true if it uses XML Forms Architecture; not a real Tag ID

# global variables
uri = '/URI'
my_tags = ['0', '1']

# relevant paths
samples_path = "/home/tzar/Desktop/Final_Project/phase4/trainPDF/"  # path for pdf samples
# path for code directory (and temp txt file and command file)
code_path = "/home/tzar/Desktop/Final_Project/phase4"
# path for text files containing js
texts_path = "/home/tzar/Desktop/Final_Project/phase4/texts"
# path for is_js.py code
isjs_path = "/home/tzar/Desktop/Final_Project/phase4/JaSt-master/js/"
# path for error file (in case peepdf fails parsing)
errorfile_path = "/home/tzar/Desktop/Final_Project/phase4/peepdf/errors.txt"


# function extract JS from pdf using peepdf
def ex_js(filename):
    # run peepdf.py
    scriptpath = os.path.join(
        '/home/tzar/Desktop/Final_Project/phase4/peepdf/',
        'peepdf.py')  # joins to path
    Mypdf = samples_path + filename  # mypdf creation
    CommandOfExtract = code_path + '/' + 'extractJS.txt'
    p = subprocess.Popen(['python',
                          scriptpath,
                          '-l',
                          '-f',
                          '-s',
                          CommandOfExtract,
                          Mypdf])  # open subprocess and extract
    p.wait()

# function for part of JavaScript
# Sources:
# https://stackoverflow.com/questions/29342542/how-can-i-extract-a-javascript-from-a-pdf-file-with-a-command-line-tool
# js extraction code
# https://github.com/Aurore54F/JaSt
# JAST project
def pdfJS(filename):
    # variables for features
    num_objects = 0
    num_js_lines = 0
    num_backslash = 0
    num_evals = 0
    num_slashx = 0
    num_slashu0 = 0
    kind_js = 0  # no - 0, valid - 50, malformed - 100

    ex_js(filename)
    # handling the case that previous file failed to parse
    errorfile = os.path.isfile(errorfile_path)  # holds boolean value
    if errorfile:
        os.remove(errorfile_path)
        print(filename + " failed parsing!")
        features = [-1, -1, -1, -1, -1, -1, -1]
        return features
    else:
        fi_na = open(str(texts_path) + '/' + str(filename) +
                     '.txt', 'w+')  # open text file for current file
        temp_file = open(str(code_path) + '/JSfromPDF.txt', 'r')
        # copy content from temp file to text file
        try:
            for line in temp_file.readlines():
                fi_na.write(line)
                if "// peepdf comment: Javascript code located in object" in line:
                    num_objects = num_objects + 1
                elif line != '\n':
                    num_js_lines = num_js_lines + 1
                # string literal for backslash
                num_backslash = num_backslash + line.count("\\")
                num_evals = num_evals + line.count("eval")
                num_slashx = num_slashx + line.count("\\x")
                num_slashu0 = num_slashu0 + line.count("\\u")
        except:
            print(temp_file)
        temp_file.close()
        fi_na.close()

        # check if valid JS or malformed JS
        if num_js_lines != 0:
            isjs = subprocess.Popen(['python',
                                     isjs_path + "is_js.py",
                                     "--f",
                                     texts_path + "/" + filename],
                                    stdout=subprocess.PIPE)
            isjs.wait()
            for line in isjs.stdout:
                if "malformed" in str(line):
                    kind_js = 100
                elif " valid" in str(line):
                    kind_js = 50

        # save and print features
        features = [
            num_objects,
            num_js_lines,
            num_backslash,
            num_evals,
            num_slashx,
            num_slashu0,
            kind_js]
        return features

# function for part of Entropy
# ans[0] - total_entropy; ans[1] - entropy_inside; ans[2] - entropy_outside
# Source: https://github.com/hiddenillusion/AnalyzePDF
def entropy(filename):
    try:
        ans = []
        p = subprocess.Popen(
            [
                'python',
                '/home/tzar/Desktop/Final_Project/phase4/AnalyzePDF-master/AnalyzePDF.py',
                filename],
            stdout=subprocess.PIPE)
        for line in p.stdout:
            pattern = r"(\d+.\d+)"
            num = re.search(pattern, line).group()
            ans.append(float(num))
        return ans
    except Exception:
        ex = [-1, -1, -1]
        return ex

# function for part of pdfid.py
def defaultJS(filename):
    try:
        ans = []
        p = subprocess.Popen(['python',
                              '/home/tzar/Desktop/Final_Project/phase4/pdfid_v0_2_5/pdfid.py',
                              filename],
                             stdout=subprocess.PIPE)
        for line in p.stdout:
            if '%PDF' in line or line.startswith('PDFiD'):
                continue
            pattern1 = r"^\s*(\S+)\s+(\d+)"
            m = re.search(pattern1, line)
            if m is not None:
                key = m.group(1)
                if key in default_features:
                    ans.append(int(m.group(2)))
        return ans
    except Exception:
        ex = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
        return ex

# function for part of URLs
def URLs(filename):
    try:
        pdf = pyPdf.PdfFileReader(open(filename))
        lst = list(pdf.pages) 				# Process all the objects.
        pdfObjects = pdf.resolvedObjects
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
                    if uri in u:
                        counter_urls += 1
                        # File:
                        if(-1 != u[uri].find("File:") or -1 != u[uri].find("file:")):
                            counter_fileURL += 1
                            continue
                        url = re.search(
                            r"(?P<url>(?:http|ftp)s?://[^\s]+)",
                            u[uri]).group("url")
                        url = url.encode("ascii", "ignore")
                        if url not in set_urls:
                            set_urls.append(url)
                except BaseException:
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
                        break
                if (flag):
                    counter_ports += 1
            try:
                # length after second '/'
                substring = re.search(
                    r'(?:http|ftp)s?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+/',
                    url).group()
                leng = len(url.replace(substring, ''))
                if (leng > max_length):
                    max_length = leng
            except BaseException:
                continue
        ans = [
            counter_urls,
            len(set_urls),
            counter_fileURL,
            max_length,
            counter_secondLINK,
            counter_encoded,
            counter_IP,
            counter_badWORDS,
            counter_ports]
        return ans
    except Exception:
        ex = [-1, -1, -1, -1, -1, -1, -1, -1, -1]
        return ex


if __name__ == '__main__':
    # PART create extractJS.txt
    f1 = open('./extractJS.txt', 'w+')  # open file
    catalog = os.getcwd()  # returns current working directory of process (codepath=catalog)
    f1.write('extract js > ' + catalog + '/JSfromPDF.txt')  # write to file
    f1.close()  # close file

    os.chdir('/home/tzar/Desktop/Final_Project/phase4/trainPDF')
    d = dict()
    features = []
    labels = []
    for root, dirs, file_names in os.walk(os.getcwd()):
        for (i, file) in enumerate(file_names):
            if ("mal" == file.split(".")[0]):
                label = 1
            else:
                label = 0
            ans = defaultJS(file)
            urls = URLs(file)
            js = pdfJS(file)
            entropies = entropy(file)
            ans = ans + urls
            ans = ans + js
            ans = ans + entropies
            ans = np.array(ans)
            features.append(ans)
            labels.append(label)
            # show an update every 50 images
            if (i > 0 and i % 50 == 0):
                print("[INFO] processed {}/{}".format(i, len(file_names)))
    features = np.array(features)
    labels = np.array(labels)

    # partition the data into training and testing splits, using 75%
    # of the data for training and the remaining 25% for testing
    X_train, X_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.25, random_state=42)

    # Linear Support Vector Machine
    print("Linear Support Vector Machine")
    sgd = Pipeline([('clf',
                     SGDClassifier(loss='hinge',
                                   penalty='l2',
                                   alpha=1e-3,
                                   random_state=42,
                                   max_iter=200,
                                   tol=1e-3)),
                    ])
    sgd.fit(X_train, y_train)
    y_pred = sgd.predict(X_test)

    print('accuracy %s' % accuracy_score(y_pred, y_test))
    print(classification_report(y_test, y_pred, target_names=my_tags))
    cm = confusion_matrix(y_test, y_pred)
    # the count of true negatives is A00, false negatives is A10, true
    # positives is A11 and false positives is A01
    print('confusion matrix:\n %s' % cm)

    # Logistic Regression
    print("Logistic Regression")
    logreg = Pipeline([('clf', LogisticRegression(
        solver='lbfgs', multi_class='auto', max_iter=1000, n_jobs=1, C=1e5)), ])
    logreg.fit(X_train, y_train)
    y_pred = logreg.predict(X_test)

    print('accuracy %s' % accuracy_score(y_pred, y_test))
    print(classification_report(y_test, y_pred, target_names=my_tags))
    cm = confusion_matrix(y_test, y_pred)
    # the count of true negatives is A00, false negatives is A10, true
    # positives is A11 and false positives is A01
    print('confusion matrix:\n %s' % cm)

    # Random Forest
    print("Random Forest")
    ranfor = Pipeline([
        ('clf', RandomForestClassifier(
            n_estimators=30, random_state=0)),
    ])
    ranfor.fit(X_train, y_train)
    y_pred = ranfor.predict(X_test)

    print('accuracy %s' % accuracy_score(y_pred, y_test))
    print(classification_report(y_test, y_pred, target_names=my_tags))
    cm = confusion_matrix(y_test, y_pred)
    # the count of true negatives is A00, false negatives is A10, true
    # positives is A11 and false positives is A01
    print('confusion matrix:\n %s' % cm)
