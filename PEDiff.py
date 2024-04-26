import argparse
import pefile
import lief
import csv
import warnings
import subprocess
import sys
import os
import struct
import re
from hashlib import sha256
from io import StringIO
from rich import my_get_rich_info
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
    
    def set_jaccard_index(s1, s2):
        return len(s1.intersection(s2))/len(s1.union(s2)) if len(s1.union(s2))>0 else 1
    
    def dict_jaccard_index(d1, d2):
        ji=0
        for k, v in d1.items():
            if k in d2 and v==d2[k]:
                ji+=1
        ji/=len(set(d1.keys()).union(set(d2.keys))) if len(set(d1.keys()).union(set(d2.keys)))>0 else 1

    def list_jaccard_index(l1, l2):
        count=0
        for i in range(len(l1)):
            if l1[i]==l2[i]:
                count+=1
        return count/len(l1) if len(l1)>0 else 1
    
    def mangle_list(l):
        new_list=[]
        occurrences={}
        for e in l:
            if e not in occurrences:
                occurrences[e]=0
            occurrences[e]+=1
            new_element=e+bytes(str(occurrences[e]), 'ascii') if type(e)==bytes else e+str(occurrences[e])
            new_list.append(new_element)
        return new_list
    
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
    
    def get_dh_sha256_similarity(self):
        dh_1=PEDiff.get_dos_header_sha256(self.samplepath1)
        dh_2=PEDiff.get_dos_header_sha256(self.samplepath2)
        return dh_1, dh_2, dh_1==dh_2
    
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
    
    def byte_xor(ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def get_dos_stub_sha256(path):
        pe=pefile.PE(path, fast_load=True)
        coff_header_offset=pe.DOS_HEADER.e_lfanew
        with open(path, 'rb') as f:
            data=f.read(coff_header_offset)[64:]
        rich_header_signature_offset=data.find(b"Rich")
        has_rich_header=rich_header_signature_offset!=-1
        if has_rich_header:
            key = data[rich_header_signature_offset+4:rich_header_signature_offset+8]
            for i in range(0, len(data), 4):
                xor=PEDiff.byte_xor(data[i:i+4], key)
                if xor==b'DanS':
                    return sha256(data[:i]).hexdigest()
        return sha256(data).hexdigest()
    
    def get_rich_header(path):
        pe=pefile.PE(path, fast_load=True)
        coff_header_offset=pe.DOS_HEADER.e_lfanew
        with open(path, 'rb') as f:
            data=f.read(coff_header_offset)[64:]
        rich_header_signature_offset=data.find(b"Rich")
        has_rich_header=rich_header_signature_offset!=-1
        rich_header_start_offset=-1
        if has_rich_header:
            key = data[rich_header_signature_offset+4:rich_header_signature_offset+8]
            for i in range(0, len(data), 4):
                xor=PEDiff.byte_xor(data[i:i+4], key)
                if xor==b'DanS':
                    rich_header_start_offset=i
                    break
        if rich_header_start_offset==-1:
            return b''
        return data[i:rich_header_signature_offset+8]
    
    def my_parse_rich_header(rich_data):

        DANS = 0x536E6144 
        RICH = 0x68636952 
        rich_data = rich_data[: 4 * (len(rich_data) // 4)]
        data = list(struct.unpack("<{0}I".format(len(rich_data) // 4), rich_data))
        key = struct.pack("<L", data[data.index(RICH) + 1])
        result = {"key": key}

        raw_data = rich_data[: rich_data.find(b"Rich")]
        result["raw_data"] = raw_data

        ord_ = lambda c: ord(c) if not isinstance(c, int) else c

        clear_data = bytearray()
        for idx, val in enumerate(raw_data):
            clear_data.append((ord_(val) ^ ord_(key[idx % len(key)])))
        result["clear_data"] = bytes(clear_data)

        # the checksum should be present 3 times after the DanS signature
        #
        checksum = data[1]
        if data[0] ^ checksum != DANS or data[2] != checksum or data[3] != checksum:
            return None

        result["checksum"] = checksum
        headervalues = []
        result["values"] = headervalues

        data = data[4:]
        for i in range(len(data) // 2):
            # Stop until the Rich footer signature is found
            #
            if data[2 * i] == RICH:
                # it should be followed by the checksum
                #
                if data[2 * i + 1] != checksum:
                    print("Rich Header is malformed")
                break

            # header values come by pairs
            #
            headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]
        return result

    def get_ds_sha256_similarity(self):
        ds1=PEDiff.get_dos_stub_sha256(self.samplepath1)
        ds2=PEDiff.get_dos_stub_sha256(self.samplepath2)
        return ds1, ds2, ds1==ds2

    def get_rh_sha256_similarity(self):
        rh1=sha256(PEDiff.get_rich_header(self.samplepath1)).hexdigest()
        rh2=sha256(PEDiff.get_rich_header(self.samplepath2)).hexdigest()
        return rh1, rh2, rh1==rh2 
    
    def get_rich_header_fields(path):
        rich_header=PEDiff.get_rich_header(path)
        if rich_header==b'':
            return {}
        richpe=my_get_rich_info(PEDiff.my_parse_rich_header(rich_header))
        if richpe==None or richpe=='':
            return None
        entries=richpe.split('\n')
        compids={}
        for entry in entries:
            try:
                compid=entry.split(' count=')[0]
                count=entry.split(' count=')[1]
                compids[compid]=count
            except Exception as e:
                print(path)
                print(e)
                raise e
        return compids
    
    def get_rh_ids_counts_similarity(self):
        rh1=PEDiff.get_rich_header_fields(self.samplepath1)
        rh2=PEDiff.get_rich_header_fields(self.samplepath2)
        rh_ids=PEDiff.set_jaccard_index(set(rh1.keys()), set(rh2.keys()))
        rh_counts=PEDiff.dict_jaccard_index(rh1, rh2)
        return rh_ids, rh_counts
    
    def get_coff_header_sha256(path):
        pe=pefile.PE(path, fast_load=True)
        coff_header_offset=pe.DOS_HEADER.e_lfanew+4 # PE\x00\x00
        coff_header_bytes=pe.__data__[coff_header_offset:coff_header_offset+20]
        pe.close()
        return sha256(coff_header_bytes).hexdigest()

    def get_ch_sha256_similarity(self):
        ch1=PEDiff.get_coff_header_sha256(self.samplepath1)
        ch2=PEDiff.get_coff_header_sha256(self.samplepath2)
        return ch1, ch2, ch1==ch2
    
    def get_ch_fields_similarity(self):
        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        values1=[value['Value'] for value in list(pe1.FILE_HEADER.dump_dict().values())[2:]]
        values2=[value['Value'] for value in list(pe2.FILE_HEADER.dump_dict().values())[2:]]
        return PEDiff.list_jaccard_index(values1, values2)
    
    def get_optional_header_sha256(path):
        pe=pefile.PE(path, fast_load=True)
        optional_header_start_offset=pe.OPTIONAL_HEADER.get_file_offset()
        optional_header_bytes=pe.__data__[optional_header_start_offset:optional_header_start_offset+96]
        pe.close()
        return sha256(optional_header_bytes).hexdigest()
    
    def get_oh_sha256_similarity(self):
        oh1=PEDiff.get_optional_header_sha256(self.samplepath1)
        oh2=PEDiff.get_optional_header_sha256(self.samplepath2)
        return oh1, oh2, oh1==oh2
    
    def get_oh_fields_similarity(self):
        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        oh1 = {k:v['Value'] for k,v in pe1.OPTIONAL_HEADER.dump_dict().items() if k != 'Structure'}
        oh2 = {k:v['Value'] for k,v in pe2.OPTIONAL_HEADER.dump_dict().items() if k != 'Structure'}
        oh_fields=PEDiff.dict_jaccard_index(oh1, oh2)
        pe1.close()
        pe2.close()
        return oh_fields
    
    def get_data_directories_sha256(path):
        pe=pefile.PE(path, fast_load=True)
        data_directories_size=len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)*8
        data_directories_start_offset=pe.OPTIONAL_HEADER.get_file_offset()+96
        data_directories_bytes=pe.__data__[data_directories_start_offset:data_directories_start_offset+data_directories_size]
        return sha256(data_directories_bytes).hexdigest()
    
    def get_dd_sha256_similarity(self):
        dd1=PEDiff.get_data_directories_sha256(self.samplepath1)
        dd2=PEDiff.get_data_directories_sha256(self.samplepath2)
        return dd1, dd2, dd1==dd2
    
    def prepare_data_directories_dict(path):
        pe=pefile.PE(path, fast_load=True)
        dd_dict={}
        for dd in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            dd=dd.dump_dict()
            dd_dict[f'{dd["Structure"]}-VirtualAddress']=dd['VirtualAddress']['Value']
            dd_dict[f'{dd["Structure"]}-Size']=dd['Size']['Value']
        pe.close()
        return dd_dict

    def get_dd_fields_similarity(self):
        dd1=PEDiff.prepare_data_directories_dict(self.samplepath1)
        dd2=PEDiff.prepare_data_directories_dict(self.samplepath2)
        dd_fields=PEDiff.dict_jaccard_index(dd1, dd2)
        return dd_fields
    
    def get_section_table_sha256(path):
        pe=pefile.PE(path, fast_load=True)
        section_table_start_offset=pe.OPTIONAL_HEADER.get_file_offset()+96+len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)*8
        section_table_size=len(pe.sections)*40
        section_table_bytes=pe.__data__[section_table_start_offset:section_table_start_offset+section_table_size]
        return sha256(section_table_bytes).hexdigest()
    
    def get_st_sha256_similarity(self):
        st1=PEDiff.get_section_table_sha256(self.samplepath1)
        st2=PEDiff.get_section_table_sha256(self.samplepath2)
        return st1, st2, st1==st2
    
    def get_sorted_section_names(path):
        pe=pefile.PE(path, fast_load=True)
        dict_sections={}
        for section in pe.sections:
            dict_sections[section.Name]=section.PointerToRawData
        sorted_sections = dict(sorted(dict_sections.items(), key=lambda item: item[1]))
        pe.close()
        return set(PEDiff.mangle_list(dict_sections.keys())), b''.join(sorted_sections.keys())
    
    def get_st_sorted_sections_names_sha256_similarity(self):
        section_names1, sorted_section_names1=PEDiff.get_sorted_section_names(self.samplepath1)
        section_names2, sorted_section_names2=PEDiff.get_sorted_section_names(self.samplepath2)
        return sorted_section_names1, sorted_section_names2, PEDiff.set_jaccard_index(section_names1, section_names2), sorted_section_names1==sorted_section_names2
    
    def get_section_containing_address(pe, address):
        for section in pe.sections:
            start=section.VirtualAddress
            end=start+section.Misc_VirtualSize
            if address>=start and address<end:
                return section
        return None
    
    def get_section_loaded_padding_bytes(section):
        data=section.get_data()
        return data[:section.VirtualSize], data[section.VirtualSize:]
    
    def replace_printable_ascii_strings(binary_data, min_length=5):
        regex = re.compile(b'[\x20-\x7E]{%d,}' % min_length)
        replaced_data = regex.sub(b'', binary_data)
        return replaced_data
    
    def replace_printable_wide_strings(binary_data, min_length=5):
        regex = re.compile(b'([\x20-\x7E]\x00){%d,}' % min_length)
        replaced_data = regex.sub(b'', binary_data)
        return replaced_data

    def remove_strings_from_data(data):
        data=PEDiff.replace_printable_ascii_strings(data)
        data=PEDiff.replace_printable_wide_strings(data)
        return data
    
    def get_entrypoint_section_features(path):
        pe=pefile.PE(path, fast_load=True)
        section=PEDiff.get_entrypoint_section(pe)
        if section==None:
            pe.close()
            empty_sha=sha256().hexdigest()
            return empty_sha, empty_sha, empty_sha, empty_sha
        es_sha256=sha256(section.get_data()).hexdigest()
        loaded, padding=PEDiff.get_section_loaded_padding_bytes(section)
        es_loaded_sha256=sha256(loaded).hexdigest()
        es_padding_sha256=sha256(padding).hexdigest()
        nostrings=PEDiff.remove_strings_from_data(section.get_data())
        es_nostrings_sha256=sha256(nostrings).hexdigest()
        pe.close()
        return es_sha256, es_loaded_sha256, es_padding_sha256, es_nostrings_sha256

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

        dh1, dh2, dh_sha256=self.get_dh_sha256_similarity()
        report['has_dos_header_1']=dh1!=sha256().hexdigest()
        report['has_dos_header_2']=dh2!=sha256().hexdigest()
        report['dh_sha256_1']=dh1
        report['dh_sha256_2']=dh2
        report['dh_sha256']=dh_sha256
        report['dh_fields']=self.get_dh_fields_similarity()

        ds1, ds2, ds_sha256=self.get_ds_sha256_similarity()
        report['has_dos_stub_1']=ds1!=sha256().hexdigest()
        report['has_dos_stub_2']=ds2!=sha256().hexdigest()
        report['ds_sha256_1']=ds1
        report['ds_sha256_2']=ds2
        report['ds_sha256']=ds_sha256

        rh1, rh2, rh_sha256=self.get_rh_sha256_similarity()
        report['has_rich_header_1']=rh1!=sha256().hexdigest()
        report['has_rich_header_2']=rh2!=sha256().hexdigest()
        report['rh_sha256_1']=rh1
        report['rh_sha256_2']=rh2
        report['rh_sha256']=rh_sha256

        rh_ids, rh_counts=self.get_rh_ids_counts_similarity()
        report['rh_ids']=rh_ids
        report['rh_counts']=rh_counts

        ch1, ch2, ch_sha256=self.get_ch_sha256_similarity()
        report['has_coff_header_1']=ch1!=sha256().hexdigest()
        report['has_coff_header_2']=ch2!=sha256().hexdigest()
        report['ch_sha256_1']=ch1
        report['ch_sha256_2']=ch2
        report['ch_sha256']=ch_sha256

        report['ch_fields']=self.get_ch_fields_similarity()
        
        oh1, oh2, oh_sha256=self.get_oh_sha256_similarity()
        report['has_optional_header_1']=oh1!=sha256().hexdigest()
        report['has_optional_header_2']=oh2!=sha256().hexdigest()
        report['oh_sha256_1']=oh1
        report['oh_sha256_2']=oh2
        report['oh_sha256']=oh_sha256

        report['oh_fields']=self.get_oh_fields_similarity()

        dd1, dd2, dd_sha256=self.get_dd_sha256_similarity()
        report['has_data_directories_1']=dd1!=sha256().hexdigest()
        report['has_data_directories_2']=dd2!=sha256().hexdigest()
        report['dd_sha256_1']=dd1
        report['dd_sha256_2']=dd2
        report['dd_sha256']=dd_sha256

        report['dd_fields']=self.get_dd_fields_similarity()

        st1, st2, st_sha256=self.get_st_sha256_similarity()
        report['has_section_table_1']=st1!=sha256().hexdigest()
        report['has_section_table_2']=st2!=sha256().hexdigest()
        report['st_sha256_1']=st1
        report['st_sha256_2']=st2
        report['st_sha256']=st_sha256

        st_sorted_names1, st_sorted_names2, st_section_names, st_sorted_names=self.get_st_sorted_sections_names_sha256_similarity()
        report['st_sorted_names_sha256_1']=st_sorted_names1
        report['st_sorted_names_sha256_2']=st_sorted_names2
        report['st_sections_names_sha256']=st_section_names
        report['st_sorted_names_sha256']=st_sorted_names


        es_sha256_1, es_loaded_sha256_1, es_padding_sha256_1, es_nostrings_sha256_1=PEDiff.get_entrypoint_section_features(self.samplepath1)
        es_sha256_2, es_loaded_sha256_2, es_padding_sha256_2, es_nostrings_sha256_2=PEDiff.get_entrypoint_section_features(self.samplepath2)
        report['es_sha256_1']=es_sha256_1
        report['es_sha256_2']=es_sha256_2
        report['es_loaded_sha256_1']=es_loaded_sha256_1
        report['es_loaded_sha256_2']=es_loaded_sha256_2
        report['es_padding_sha256_1']=es_padding_sha256_1
        report['es_padding_sha256_2']=es_padding_sha256_2
        report['es_nostrings_sha256_1']=es_nostrings_sha256_1
        report['es_nostrings_sha256_2']=es_nostrings_sha256_2
        report['es_sha256']=es_sha256_1==es_sha256_2
        report['es_loaded_sha256']=es_loaded_sha256_1==es_loaded_sha256_2
        report['es_padding_sha256']=es_padding_sha256_1==es_padding_sha256_2
        report['es_nostrings_sha256']=es_nostrings_sha256_1==es_nostrings_sha256_2

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
    