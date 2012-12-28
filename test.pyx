#!/usr/bin/env python2.6

import os
import re
import sys

def bruteforce_XOR_onebyte(toBrute):    
    mappedFile = toBrute
    bruted = bytearray()
    cdef int startMZ
    cdef int i
    
    for 1 <= i < 256:        
        for element in toBrute:
            bruted.append(ord(element)^i)
        print(hex(i))
        
        match = re.search('MZ', bruted)
        if match is not None:
            startMZ = match.start()
            if match is not None:
                match = re.search('PE',bruted)
                if match is not None:
                    match = re.search('This',bruted)
                    if match is not None:
                        print("EXEEEEEEEEEEEEEEEEE")
                        xor_data = {'xor_key':i, 'MZ_Start':startMZ}
                        return xor_data
                    else:
                        continue
                else:
                    continue
            else:
                continue
    xor_data = {'xor_key':0, 'MZ_Start':0}
    return xor_data
    
def bf_XOR_onebyte(toBrute, i): #ok       
    mappedFile = toBrute
    bruted = bytearray()    
    for element in mappedFile:
        bruted.append(ord(element)^i)
    return (bruted)        
    pass

