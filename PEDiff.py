import argparse
import pefile
import lief
import csv
import warnings
import subprocess
import sys
import os
from hashlib import sha256
from io import StringIO
sys.path.append(os.path.join(os.path.dirname(__file__), 'bitshred'))
from fingerprint_db import process_executable
from fingerprint import jaccard_distance

WEIGHTS={
    'ssdeep':0.357,
    'tlsh':0.238,
    'bitshred':0.405,
    'sdhash':0,
    'mrsh-v2':0
}

BITSHRED_SETTING={
    'shred_size':16,
    'window_size':12,
    'fp_size':32,
    'all_sec':False
}

class PEDiff:
    def __init__(self, samplepath1, samplepath2, family=''): 
        self.samplepath1=samplepath1
        self.samplepath2=samplepath2
        self.family=family
    
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
        distance=int(stdout.split('\t')[0])
        return max(0, (300-distance)/3.)

    def get_bitshred_score(self):
        exe1=process_executable(self.samplepath1, BITSHRED_SETTING['shred_size'], BITSHRED_SETTING['window_size'], BITSHRED_SETTING['fp_size'], BITSHRED_SETTING['all_sec'])
        exe2=process_executable(self.samplepath2, BITSHRED_SETTING['shred_size'], BITSHRED_SETTING['window_size'], BITSHRED_SETTING['fp_size'], BITSHRED_SETTING['all_sec'])
        return jaccard_distance(exe1, exe2)*100

    def get_sdhash_score(self):
        stdout=PEDiff.run_command(f'sdhash -b 0 -t -1 -g {self.samplepath1} {self.samplepath2}')
        return int(stdout.split('|')[2])
    
    def get_mrsh_score(self):
        stdout=PEDiff.run_command(f'mrsh -t 0 -c {self.samplepath1} {self.samplepath2}')
        return int(stdout.split('|')[2])

    def get_FUS_score(self, report):
        fus=0
        for fuzzy, weight in WEIGHTS.items():
            fus+=weight*report[fuzzy]
        return fus
    
    def get_truncated(path):
        pe=pefile.PE(path)
        max_section_offset=0
        for section in pe.sections:
            file_offset=section.PointerToRawData
            size=section.SizeOfRawData
            max_section_offset=max(max_section_offset, file_offset+size)
        file_size=len(pe.__data__)
        pe.close()
        return file_size<max_section_offset, max_section_offset, file_size
    
    def get_dos_header_sha256(path):
        with open(path, 'rb') as f:
            dos_header_bytes=f.read(64)
        return sha256(dos_header_bytes).hexdigest()
    
    def get_dh_sha256_similarity(self, sha_1=None, sha_2=None):
        if sha_1 is None:
            sha_1=PEDiff.get_dos_header_sha256(self.samplepath1)
        if sha_2 is None:
            sha_2=PEDiff.get_dos_header_sha256(self.samplepath2)
        return sha_1==sha_2
    
    def get_dh_fields_similarity(self):
        pe1=pefile.PE(self.samplepath1)
        pe2=pefile.PE(self.samplepath2)
        d1=pe1.DOS_HEADER.dump_dict()
        d2=pe2.DOS_HEADER.dump_dict()
        pe1.close()
        pe2.close()
        count=0
        for k in list(d1.keys())[1:]:
            if d1[k]['Value']==d2[k]['Value']:
                count+=1
        return count/(len(d1)-1)
    
    def get_report(self):
        report={}
        report['exe_1']=os.path.basename(self.samplepath1)
        report['exe_2']=os.path.basename(self.samplepath2)
        report['family']=self.family

        report['ssdeep']=self.get_ssdeep_score()
        report['tlsh']=self.get_tlsh_score()
        report['bitshred']=self.get_bitshred_score()
        report['sdhash']=self.get_sdhash_score()
        report['mrsh-v2']=self.get_mrsh_score()
        report['FUS']=self.get_FUS_score(report)

        is_truncated, max_section_offset, file_size=PEDiff.get_truncated(self.samplepath1)
        report['is_truncated_1']=is_truncated
        report['max_section_offset_1']=max_section_offset
        report['file_size_1']=file_size

        is_truncated, max_section_offset, file_size=PEDiff.get_truncated(self.samplepath2)
        report['is_truncated_2']=is_truncated
        report['max_section_offset_2']=max_section_offset
        report['file_size_2']=file_size

        report['dh_sha256_1']=PEDiff.get_dos_header_sha256(self.samplepath1)
        report['dh_sha256_2']=PEDiff.get_dos_header_sha256(self.samplepath2)
        report['dh_sha256']=self.get_dh_sha256_similarity(report['dh_sha256_1'], report['dh_sha256_2'])

        report['dh_fields']=self.get_dh_fields_similarity()

        return report

def compare_executables(EXE_1, EXE_2):
    print('compare executables', EXE_1, EXE_2)

def compare_directory(DIR):
    print('compare directory', DIR)

def main():

    global WEIGHTS
    global BITSHRED_SETTING

    warnings.filterwarnings('ignore')

    parser=argparse.ArgumentParser()

    parser.add_argument('-o', '--output', help='Destination csv file where the report will be saved', required=True, type=str, metavar='CSV')

    mode_group=parser.add_argument_group('Mode')
    target_type=mode_group.add_mutually_exclusive_group(required=True)
    target_type.add_argument('-f', '--files', help='compare the pair of files EXE_1 and EXE_2', nargs=2, metavar=('EXE_1', 'EXE_2'))
    target_type.add_argument('-d', '--directory', help='compare ALL the files inside the directory DIR', metavar=('DIR'), type=str)

    weights_group=parser.add_argument_group('FUS weights for fuzzy hashes\' scores')
    for fuzzy, weight in WEIGHTS.items():
        weights_group.add_argument(f'--{fuzzy}', help=f'Set the weight for {fuzzy} score (default: {round(weight, 3)})', type=float, default=weight, metavar=('WEIGHT'))

    bitshred_group=parser.add_argument_group('Bitshred settings')
    for setting, value in BITSHRED_SETTING.items():
        if setting=='all_sec':
            continue
        bitshred_group.add_argument(f'--{setting}', help=f'Bitshred parameter {setting} (default {value})', type=int, default=value, metavar='VALUE')

    args = parser.parse_args()

    for arg in weights_group._group_actions:
        fuzzy=arg.dest
        weight=getattr(args, fuzzy)
        if weight is not None:
            WEIGHTS[fuzzy]=weight

    for arg in bitshred_group._group_actions:
        option=arg.dest
        value=getattr(args, option)
        if value is not None:
            BITSHRED_SETTING[option]=value

    if args.files:
        compare_executables(args.files[0], args.files[1])
    elif args.directory:
        compare_directory(args.directory)

if __name__=='__main__':
    main()
    