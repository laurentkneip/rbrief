#! /usr/bin/env python

import numpy
import sys

fileName = 'test_pairs.txt';
tests = numpy.loadtxt(fileName, dtype=int)
bytes = int(sys.argv[1])

initcode = ''
initcode = initcode + '    pattern.resize(' + str(bytes*8) + ');';
initcode = initcode + '\n'

for i in range(bytes*8):
    x1, y1, x2, y2 = tests[i, :]
    initcode = initcode + '    pattern[' + str(i) + '].first.first = ' + str(x1) + '; pattern[' + str(i) + '].first.second = ' + str(y1) + '; '
    initcode = initcode + 'pattern[' + str(i) + '].second.first = ' + str(x2) + '; pattern[' + str(i) + '].second.second = ' + str(y2) + ';'
    initcode = initcode + '\n'

output = 'initcode_' + str(bytes) + '.i'
file = open(output, 'w')
file.write(initcode)
file.close()

code = ''
code = code + '    for (int i = 0; i < (int)keypoints.size(); ++i)'
code = code + '\n'
code = code + '    {'
code = code + '\n'
code = code + '        uchar* desc = descriptors.ptr(i);'
code = code + '\n'
code = code + '        const KeyPoint& pt = keypoints[i];'
code = code + '\n\n'

for byte in range(bytes):
    code = code + '        desc[' + str(byte) + '] ='
    for i in range(8):

        index = byte*8 + i;

        code = code + '((smoothedSum(sum, pt, pattern[' + str(index) + '].first.second, pattern[' + str(index) + '].first.first) < '
        code = code + 'smoothedSum(sum, pt, pattern[' + str(index) + '].second.second, pattern[' + str(index) + '].second.first)) << ' + str(7 - i) + ')'
        if i == 7:
            code = code + ';'
            code = code + '\n'
        else:
            code = code + ' +\n                '
code = code + '    }'

output = 'code_' + str(bytes) + '.i'
file = open(output, 'w')
file.write(code)
file.close()
