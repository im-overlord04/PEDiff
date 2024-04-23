import argparse
import pefile
import lief
import csv
import warnings
import subprocess
from io import StringIO

DEFAULT_WEIGHTS={'ssdeep':0.357,
                'tlsh':0.238,
                'bitshred':0.405,
                'sdhash':0,
                'mrsh-v2':0}

class PEDiff:
    def __init__(self, samplepath1, samplepath2): 
        self.pe1=pefile.PE(samplepath1)
        self.pe2=pefile.PE(samplepath2)
        self.lief1=lief.parse(samplepath1)
        self.lief2=lief.parse(samplepath2)
        self.samplepath1=samplepath1
        self.samplepath2=samplepath2
    
    def run_command(command):
        try:
            stdout=subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            return stdout.stdout
        except subprocess.CalledProcessError as e:
            print("Error:", e)
            return None
    
    def get_ssdeep_score(self):
        stdout=PEDiff.run_command(f'ssdeep -c -d -a {self.samplepath1} {self.samplepath2}')        
        score=list(csv.reader(StringIO(stdout)))[0][2]
        return int(score)
    
    def get_tlsh_score(self):
        stdout=PEDiff.run_command(f'tlsh -c {self.samplepath1} -f {self.samplepath2}')
        distance=int(stdout.stdout.split('\t')[0])
        return max(0, (300-distance)/3.)
    
    def get_report(self):
        report={}
        report['ssdeep']=self.get_ssdeep_score()
        report['tlsh']

def compare_executables(EXE_1, EXE_2):
    print('compare executables', EXE_1, EXE_2)

def compare_directory(DIR):
    print('compare directory', DIR)

def main():

    warnings.filterwarnings('ignore')

    parser=argparse.ArgumentParser()

    parser.add_argument('-o', '--output', help='Destination csv file where the report will be saved', required=True, type=str, metavar='CSV')

    mode_group=parser.add_argument_group('Mode')
    target_type=mode_group.add_mutually_exclusive_group(required=True)
    target_type.add_argument('-f', '--files', help='compare the pair of files EXE_1 and EXE_2', nargs=2, metavar=('EXE_1', 'EXE_2'))
    target_type.add_argument('-d', '--directory', help='compare ALL the files inside the directory DIR', metavar=('DIR'), type=str)

    weights_group=parser.add_argument_group('Fuzzy hashes\' weights')
    for fuzzy, weight in DEFAULT_WEIGHTS.items():
        weights_group.add_argument(f'--{fuzzy}', help=f'Set the weight for {fuzzy} score (default: {round(weight, 3)})', type=float, default=weight, metavar=('WEIGHT'))

    args = parser.parse_args()

    if args.files:
        compare_executables(args.files[0], args.files[1])
    elif args.directory:
        compare_directory(args.directory)

if __name__=='__main__':
    main()
    