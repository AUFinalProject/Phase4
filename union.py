# Authors Alexey Titov and Shir Bentabou
# Version 1.0
# Date 05.2019

# libraries
from PyPDF2 import PdfFileReader
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
    no_js = 1  # no - 0, valid - 50, malformed - 100
    valid_js = 0
    malformed_js = 0
    encoding = 0
    ex_js(filename)
    # handling the case that previous file failed to parse
    errorfile = os.path.isfile(errorfile_path)  # holds boolean value
    if errorfile:
        os.remove(errorfile_path)
        print(filename + " failed parsing!")
        features = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
        return False, features
    else:
        fi_na = open(str(texts_path) + '/' + str(filename) +'.txt', 'w+')  # open text file for current file
        temp_file = open(str(code_path) + '/JSfromPDF.txt', 'r')
        # copy content from temp file to text file
        try:
            for line in str(temp_file.readlines()):
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
            encoding = -1
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
                    malformed_js = 1
                    no_js = 0
                elif " valid" in str(line):
                    valid_js = 1
                    no_js = 0

        # save and print features
        features = [
            num_objects,
            num_js_lines,
            num_backslash,
            num_evals,
            num_slashx,
            num_slashu0,
            no_js,
            valid_js,
            malformed_js,
            encoding]
        return True, features

# function for part of Entropy
# ans[0] - total_entropy; ans[1] - entropy_inside; ans[2] - entropy_outside
# Source: https://github.com/hiddenillusion/AnalyzePDF
def entropy(filename):
    try:
        ans = []
        filename = samples_path+filename.replace('\n','')
        p = subprocess.Popen(['python', '/home/tzar/Desktop/Final_Project/phase4/AnalyzePDF-master/AnalyzePDF.py', filename], stdout=subprocess.PIPE)
        p.wait()
        for line in p.stdout:
            line = str(line)
            pattern = r"(\d+.\d+)"
            num = re.search(pattern, line).group()
            ans.append(float(num))
        return True, ans
    except Exception:
        ex = [-1, -1, -1]
        return False, ex

# function for part of pdfid.py
def defaultJS(filename):
    try:
        ans = []
        filename = samples_path+filename.replace('\n','')
        p = subprocess.Popen(['python', '/home/tzar/Desktop/Final_Project/phase4/pdfid_v0_2_5/pdfid.py', filename], stdout=subprocess.PIPE)
        p.wait()
        for line in p.stdout:
            line = str(line)
            if '%PDF' in line or line.startswith('PDFiD'):
                continue
            pattern1 = r"\s*(\S+)\s+(\d+)"
            m = re.search(pattern1, line)
            if m is not None:
                key = m.group(1)
                if key in default_features:
                    ans.append(int(m.group(2)))
        return True, ans
    except Exception:
        ex = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
        return False, ex

# function for part of URLs
def URLs(filename):
    try:
        filename = samples_path+filename.replace('\n','')
        p = subprocess.Popen(['python', '/home/tzar/Desktop/Final_Project/phase4/support_union.py', filename], stdout = subprocess.PIPE)
        p.wait()
        out, err = p.communicate()
        out = str(out)
        out = out.replace('b\'','').replace('\\n\'','').replace('[','').replace(']','').split(',')
        if ('-1' in out[0]):
            return False, list(map(int, out))
        out = list(map(int, out))
        return True, out
    except Exception as vv:
        print(vv)
        ex = [-1, -1, -1, -1, -1, -1, -1, -1, -1]
        return False, ex


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
    err = [0, 0, 0, 0, 0, 0, 0, 0]
    for root, dirs, file_names in os.walk(os.getcwd()):
        for (i, file) in enumerate(file_names):
            if ("mal" == file.split(".")[0]):
                label = 1
            else:
                label = 0
            flag, ans = defaultJS(file)
            if (not flag):
                err[0+label] += 1
            flag, urls = URLs(file)
            if (not flag):
                err[2+label] += 1
            flag, js = pdfJS(file)
            if (not flag):
                err[4+label] += 1
            flag, entropies = entropy(file)
            if (not flag):
                err[6+label] += 1
            ans = ans + urls
            ans = ans + js
            ans = ans + entropies
            ans = np.array(ans)
            features.append(ans)
            labels.append(label)
            # show an update every 50 pdfs
            if (i > 0 and i % 50 == 0):
                print("[INFO] processed {}/{}".format(i, len(file_names)))
    features = np.array(features)
    labels = np.array(labels)
    print("This is error--------------------------------------------------------")
    print(err)
    print("---------------------------------------------------------------------")
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

    # K-Nearest Neighbors
    print("K-Nearest Neighbors")
    knn = Pipeline([('clf', KNeighborsClassifier(n_neighbors=3)), ])
    knn.fit(X_train, y_train)
    y_pred = knn.predict(X_test)

    print('accuracy %s' % accuracy_score(y_pred, y_test))
    print(classification_report(y_test, y_pred, target_names=my_tags))
    cm = confusion_matrix(y_test, y_pred)
    # the count of true negatives is A00, false negatives is A10, true
    # positives is A11 and false positives is A01
    print('confusion matrix:\n %s' % cm)
    print("\n\n")

    # Multi-layer Perceptron
    print("Multi-layer Perceptron")
    mlp = Pipeline([('clf', MLPClassifier(activation='relu', solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(15,), random_state=1, tol=0.000000001)),])
    mlp.fit(X_train, y_train)
    y_pred = mlp.predict(X_test)

    print('accuracy %s' % accuracy_score(y_pred, y_test))
    print(classification_report(y_test, y_pred, target_names=my_tags))
    cm = confusion_matrix(y_test, y_pred)
    # the count of true negatives is A00, false negatives is A10, true
    # positives is A11 and false positives is A01
    print('confusion matrix:\n %s' % cm)
    print("\n\n")
