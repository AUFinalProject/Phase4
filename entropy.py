# Authors Alexey Titov and Shir Bentabou
# Version 2.0
# Date 05.2019

# libraries
import subprocess
import os
import re
from collections import defaultdict


# Source: https://github.com/hiddenillusion/AnalyzePDF
# function for part of Entropy
# ans[0] - total_entropy; ans[1] - entropy_inside; ans[2] - entropy_outside
def ENTROPY(filename):
    try:
	ans=[]
        p = subprocess.Popen(['python', '/home/tzar/Desktop/Final_Project/phase4/AnalyzePDF-master/AnalyzePDF.py',filename],stdout=subprocess.PIPE)
        for line in p.stdout:
            pattern1 = "(\d+.\d+)"
            num = re.search(pattern1, line).group()
	    ans.append(float(num))
        return ans
    except Exception:
	ex=[-1, -1, -1]
        return ex


if __name__ == '__main__':
    os.chdir('/home/tzar/Desktop/Final_Project/phase4/PDF')
    d = dict()
    for root, dirs, file_names in os.walk(os.getcwd()):
        for file in file_names:
            ans = ENTROPY(file)
            print(ans)
