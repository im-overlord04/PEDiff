import sys
import argparse
import pefile
import os

class PEDiff:
    def __init__(self, samplepath1, samplepath2): 
        self.samplepath1=samplepath1
        self.samplepath2=samplepath2
        self.pe1=pefile.PE(samplepath1)
        self.pe2=pefile.PE(samplepath2)

def main():
    parser=argparse.ArgumentParser()
    target_type=parser.add_mutually_exclusive_group()
    target_type.add_argument('-f', '--files', help='compare a pair of files', action='store_true', dest='type', const='f', default='f')
    target_type.add_argument('-d', '--directory', help='compare ALL the files inside the directory', action='store_true', dest='type', const='d')
    pass

if __name__=='__main__':
    main()
    