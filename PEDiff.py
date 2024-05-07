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
import tqdm
import pandas as pd
from hashlib import sha256
from io import StringIO
from rich import my_get_rich_info
from multiprocessing import Pool
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
    def __init__(self, samplepath1, samplepath2): 
        self.samplepath1=samplepath1
        self.samplepath2=samplepath2
    
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
        ji/=len(set(d1.keys()).union(set(d2.keys()))) if len(set(d1.keys()).union(set(d2.keys())))>0 else 1
        return ji
    
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

    def get_FUS_score(self, report=None):
        if report is None:
            report={}
            report['ssdeep']=self.get_ssdeep_score()
            report['tlsh']=self.get_tlsh_score()
            report['bitshred']=self.get_bitshred_score()
            report['sdhash']=self.get_sdhash_score()
            report['mrsh-v2']=self.get_mrsh_score()
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
    
    def get_dos_header_features(self):
        dh_sha256_1=PEDiff.get_dos_header_sha256(self.samplepath1)
        dh_sha256_2=PEDiff.get_dos_header_sha256(self.samplepath2)
        dh_sha256=dh_sha256_1==dh_sha256_2
        dh_fields=self.get_dh_fields_similarity()
        return dh_sha256_1, dh_sha256_2, dh_sha256, dh_fields

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

    def get_dos_stub_features(self):
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
        return data[:section.Misc_VirtualSize], data[section.Misc_VirtualSize:]
    
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

    def get_section_features(path, va):
        pe=pefile.PE(path, fast_load=True)
        section=PEDiff.get_section_containing_address(pe, va)
        if section==None:
            pe.close()
            empty_sha=sha256().hexdigest()
            return empty_sha, empty_sha, empty_sha, empty_sha
        s_sha256=sha256(section.get_data()).hexdigest()
        loaded, padding=PEDiff.get_section_loaded_padding_bytes(section)
        s_loaded_sha256=sha256(loaded).hexdigest()
        s_padding_sha256=sha256(padding).hexdigest()
        nostrings=PEDiff.remove_strings_from_data(section.get_data())
        s_nostrings_sha256=sha256(nostrings).hexdigest()
        pe.close()
        return s_sha256, s_loaded_sha256, s_padding_sha256, s_nostrings_sha256
    
    def get_resources(pe):
        resources={}
        for r_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for r_name in r_type.directory.entries:
                for r_lang in r_name.directory.entries:
                    _t = str(r_type.id) if r_type.id is not None else r_type.name.decode()
                    _n = str(r_name.id) if r_name.id is not None else r_name.name.decode()
                    _l = str(r_lang.id) if r_lang.id is not None else r_lang.name.decode()
                    offset_to_data=r_lang.data.struct.OffsetToData
                    size=r_lang.data.struct.Size
                    resources[f'{_t}.{_n}.{_l}']=(pe.get_memory_mapped_image()[offset_to_data:offset_to_data+size], offset_to_data)
        resources=dict(sorted(resources.items(), key=lambda item: item[1][1]))
        resources={k:v[0] for k, v in resources.items()}
        return resources

    def get_resources_features(self):
        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe1.parse_data_directories(2)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        pe2.parse_data_directories(2)

        if not hasattr(pe1, 'DIRECTORY_ENTRY_RESOURCE'):
            resources1={}
        else:
            resources1=PEDiff.get_resources(pe1)

        if not hasattr(pe2, 'DIRECTORY_ENTRY_RESOURCE'):
            resources2={}
        else:
            resources2=PEDiff.get_resources(pe2)

        rs_resources_sha256_1=sha256(b''.join(resources1.values())).hexdigest()
        rs_resources_sha256_2=sha256(b''.join(resources2.values())).hexdigest()
        rs_resources_sha256=rs_resources_sha256_1==rs_resources_sha256_2
        names1=set(PEDiff.mangle_list(list(resources1.keys())))
        names2=set(PEDiff.mangle_list(list(resources2.keys())))
        rs_resources_names=PEDiff.set_jaccard_index(names1, names2)
        ress_1=set(PEDiff.mangle_list(list(resources1.values())))
        ress_2=set(PEDiff.mangle_list(list(resources2.values())))
        rs_resources_values=PEDiff.set_jaccard_index(ress_1, ress_2)
        return rs_resources_sha256_1, rs_resources_sha256_2, rs_resources_sha256, rs_resources_names, rs_resources_values
    
    def is_address_in_section(address, section):
        start=section.VirtualAddress
        end=start+section.Misc_VirtualSize
        return address>=start and address<end

    def get_other_sections(pe):
        aep=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        r_va=pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>2 else 0
        sections=[]
        names=[]
        for section in pe.sections:
            if PEDiff.is_address_in_section(aep, section) or PEDiff.is_address_in_section(r_va, section):
                continue
            sections.append((section.get_data(), section.PointerToRawData))
            names.append((section.Name, section.PointerToRawData))
        sections=list(sorted(sections, key=lambda item: item[1]))
        sections=[el[0] for el in sections]
        names=list(sorted(names, key=lambda item: item[1]))
        names=[el[0] for el in names]
        return sections, names
    
    def get_other_sections_features(self):
        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        sections1, names1=PEDiff.get_other_sections(pe1)
        sections2, names2=PEDiff.get_other_sections(pe2)
        loaded1=[]
        loaded2=[]
        padding1=[]
        padding2=[]
        nostring1=[]
        nostring2=[]

        for section in pe1.sections:
            if section.Name not in names1:
                continue
            loaded, padding=PEDiff.get_section_loaded_padding_bytes(section)
            nostring=PEDiff.remove_strings_from_data(section.get_data())
            loaded1.append(loaded)
            padding1.append(padding)
            nostring1.append(nostring)

        for section in pe2.sections:
            if section.Name not in names2:
                continue
            loaded, padding=PEDiff.get_section_loaded_padding_bytes(section)
            nostring=PEDiff.remove_strings_from_data(section.get_data())
            loaded2.append(loaded)
            padding2.append(padding)
            nostring2.append(nostring)

        pe1.close()
        pe2.close()
        os_sorted_sections_sha256_1=sha256(b''.join(sections1)).hexdigest()
        os_sorted_sections_sha256_2=sha256(b''.join(sections2)).hexdigest()
        os_sorted_sections_sha256=os_sorted_sections_sha256_1==os_sorted_sections_sha256_2
        sections1=PEDiff.mangle_list(sections1)
        sections2=PEDiff.mangle_list(sections2)
        loaded1=PEDiff.mangle_list(loaded1)
        loaded2=PEDiff.mangle_list(loaded2)
        padding1=PEDiff.mangle_list(padding1)
        padding2=PEDiff.mangle_list(padding2)
        nostring1=PEDiff.mangle_list(nostring1)
        nostring2=PEDiff.mangle_list(nostring2)
        os_sections=PEDiff.set_jaccard_index(set(sections1), set(sections2))
        os_sections_loaded=PEDiff.set_jaccard_index(set(loaded1), set(loaded2))
        os_sections_padding=PEDiff.set_jaccard_index(set(padding1), set(padding2))
        os_sections_nostrings=PEDiff.set_jaccard_index(set(nostring1), set(nostring2))
        os_sorted_names_sha256_1=sha256(b''.join(names1)).hexdigest()
        os_sorted_names_sha256_2=sha256(b''.join(names2)).hexdigest()
        os_sorted_names_sha256=os_sorted_names_sha256_1==os_sorted_names_sha256_2
        return os_sorted_sections_sha256_1, os_sorted_sections_sha256_2, os_sorted_sections_sha256, os_sections, os_sections_loaded, os_sections_padding, os_sections_nostrings, os_sorted_names_sha256_1, os_sorted_names_sha256_2, os_sorted_names_sha256
    
    def get_ct_sha256(pe):
        ct_offset=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4 else 0
        ct_size=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4 else 0
        ct_sha256=sha256(pe.get_data()[ct_offset:ct_offset+ct_size]).hexdigest()
        return ct_sha256
    
    def get_ct_entries(pe):
        entries=[]
        ct_offset=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4 else 0
        ct_size=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4 else 0
        if ct_offset==0 or ct_size==0:
            return entries
        while True:
            length=int.from_bytes(pe.__data__[ct_offset:ct_offset+4], 'little')
            if length==0:
                break
            entries.append(pe.__data__[ct_offset+8:ct_offset+length])
            ct_offset=ct_offset+length
            ct_offset=ct_offset+8-ct_offset%8 if ct_offset%8!=0 else ct_offset
            if ct_offset >= len(pe.__data__):
                break
        return entries
    
    def convert_der_to_pkcs7(entries):
        pkcs7=[]
        for entry in entries:
            tmp=f'/tmp/{sha256(entry).hexdigest()}_{os.getpid()}'
            with open(tmp, 'wb') as f:
                f.write(entry)
            output=PEDiff.run_command(f'openssl pkcs7 -in {tmp} -inform DER')
            pkcs7.append(sha256(output).hexdigest())
            os.remove(tmp)
        return pkcs7
    
    def get_certificates_subjects_issuers(entries):
        subjects=[]
        issuers=[]
        for entry in entries:
            tmp=f'/tmp/{sha256(entry).hexdigest()}_{os.getpid()}'
            with open(tmp, 'wb') as f:
                f.write(entry)
            output=PEDiff.run_command(f'openssl pkcs7 -in {tmp} -inform DER -print_certs')
            os.remove(tmp)
            for line in output.split('\n'):
                if line.startswith('subject='):
                    subjects.append(line[8:])
                elif line.startswith('issuer='):
                    issuers.append(line[7:])
        return subjects, issuers
    
    def get_authentihash_from_ct(entries):
        authentihashes=[]
        for entry in entries:
            tmp=f'/tmp/{sha256(entry).hexdigest()}_{os.getpid()}'
            with open(tmp, 'wb') as f:
                f.write(entry)
            output=PEDiff.run_command(f'openssl asn1parse -in {tmp} -inform DER | grep -oP \'(?<=\[HEX DUMP\]:)[0-9A-Fa-f]+\' | head -1').strip()
            os.remove(tmp)
            authentihashes.append(output)
        return authentihashes

    def get_certificate_table_features(self):
        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        ct_sha256_1=PEDiff.get_ct_sha256(pe1)
        ct_sha256_2=PEDiff.get_ct_sha256(pe2)
        ct_sha256=ct_sha256_1==ct_sha256_2
        entries1=PEDiff.get_ct_entries(pe1)
        entries2=PEDiff.get_ct_entries(pe2)
        ct_entries_1=PEDiff.mangle_list([sha256(entry).hexdigest() for entry in entries1])
        ct_entries_2=PEDiff.mangle_list([sha256(entry).hexdigest() for entry in entries2])
        ct_entries=PEDiff.set_jaccard_index(set(ct_entries_1), set(ct_entries_2))
        pkcs7_1=PEDiff.mangle_list(PEDiff.convert_der_to_pkcs7(entries1))
        pkcs7_2=PEDiff.mangle_list(PEDiff.convert_der_to_pkcs7(entries2))
        ct_pkcs7=PEDiff.set_jaccard_index(set(pkcs7_1), set(pkcs7_2))
        subject1, issuers1=PEDiff.get_certificates_subjects_issuers(entries1)
        subject2, issuers2=PEDiff.get_certificates_subjects_issuers(entries2)
        subject1=PEDiff.mangle_list(subject1)
        subject2=PEDiff.mangle_list(subject2)
        issuers1=PEDiff.mangle_list(issuers1)
        issuers2=PEDiff.mangle_list(issuers2)
        ct_subjects=PEDiff.set_jaccard_index(set(subject1), set(subject2))
        ct_issuers=PEDiff.set_jaccard_index(set(issuers1), set(issuers2))
        ct_authentihash_1=PEDiff.mangle_list(PEDiff.get_authentihash_from_ct(entries1))
        ct_authentihash_2=PEDiff.mangle_list(PEDiff.get_authentihash_from_ct(entries2))
        ct_authentihash=PEDiff.set_jaccard_index(set(ct_authentihash_1), set(ct_authentihash_2))
        return ct_sha256_1, ct_sha256_2, ct_sha256, ct_entries, ct_pkcs7, ct_subjects, ct_issuers, ct_authentihash

    def compute_authentihash(path):
        pe=lief.parse(path)
        return pe.authentihash(lief.PE.ALGORITHMS.SHA_256).hex()
    
    def get_overlay(path):
        truncated, _, _=PEDiff.get_truncated(path)
        pe=pefile.PE(path, fast_load=True)
        overlay_offset=pe.get_overlay_data_start_offset()
        data=b''
        if overlay_offset is not None and not truncated:
            ct_offset=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4 else 0
            ct_size=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>4 else 0
            if ct_offset>0 and ct_size>0:
                overlay_offset=max(ct_offset+ct_size, overlay_offset)
            data=pe.__data__[overlay_offset:]
        else:
            overlay_offset=len(pe.__data__)
        return data, overlay_offset


    def get_overlay_features(self):
        overlay1, offset1=PEDiff.get_overlay(self.samplepath1)
        overlay2, offset2=PEDiff.get_overlay(self.samplepath2)
        ov_sha256_1=sha256(overlay1).hexdigest()
        ov_sha256_2=sha256(overlay2).hexdigest()
        ov_sha256=ov_sha256_1==ov_sha256_2
        nostrings1=PEDiff.remove_strings_from_data(overlay1)
        nostrings2=PEDiff.remove_strings_from_data(overlay2)
        ov_nostrings_sha256_1=sha256(nostrings1).hexdigest()
        ov_nostrings_sha256_2=sha256(nostrings2).hexdigest()
        ov_nostrings_sha256=ov_nostrings_sha256_1==ov_nostrings_sha256_2
        with open(self.samplepath1, 'rb') as f:
            no_overlay_sha256_1=sha256(f.read(offset1)).hexdigest()
        with open(self.samplepath2, 'rb') as f:
            no_overlay_sha256_2=sha256(f.read(offset2)).hexdigest()
        return ov_sha256_1, ov_sha256_2, ov_sha256, ov_nostrings_sha256_1, ov_nostrings_sha256_2, ov_nostrings_sha256, no_overlay_sha256_1, no_overlay_sha256_2, no_overlay_sha256_1==no_overlay_sha256_2

    def get_report(self, family_1='', family_2=''):
        report={}
        report['exe_1']=os.path.basename(self.samplepath1)
        report['exe_2']=os.path.basename(self.samplepath2)
        report['family_1']=family_1
        report['family_2']=family_2

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

        dh_sha256_1, dh_sha256_2, dh_sha256, dh_fields=self.get_dos_header_features()
        report['has_dos_header_1']=dh_sha256_1!=sha256().hexdigest()
        report['has_dos_header_2']=dh_sha256_2!=sha256().hexdigest()
        report['dh_sha256_1']=dh_sha256_1
        report['dh_sha256_2']=dh_sha256_2
        report['dh_sha256']=dh_sha256
        report['dh_fields']=dh_fields

        ds1, ds2, ds_sha256=self.get_dos_stub_features()
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

        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        aep1=pe1.OPTIONAL_HEADER.AddressOfEntryPoint
        aep2=pe1.OPTIONAL_HEADER.AddressOfEntryPoint
        pe1.close()
        pe2.close()
        es_sha256_1, es_loaded_sha256_1, es_padding_sha256_1, es_nostrings_sha256_1=PEDiff.get_section_features(self.samplepath1, aep1)
        es_sha256_2, es_loaded_sha256_2, es_padding_sha256_2, es_nostrings_sha256_2=PEDiff.get_section_features(self.samplepath2, aep2)
        report['has_entrypoint_section_1']=es_sha256_1!=sha256().hexdigest()
        report['has_entrypoint_section_2']=es_sha256_2!=sha256().hexdigest()
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

        pe1=pefile.PE(self.samplepath1, fast_load=True)
        pe2=pefile.PE(self.samplepath2, fast_load=True)
        r_va1=pe1.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress if len(pe1.OPTIONAL_HEADER.DATA_DIRECTORY)>2 else 0
        r_va2=pe2.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress if len(pe2.OPTIONAL_HEADER.DATA_DIRECTORY)>2 else 0
        pe1.close()
        pe2.close()
        rs_sha256_1, rs_loaded_sha256_1, rs_padding_sha256_1, rs_nostrings_sha256_1=PEDiff.get_section_features(self.samplepath1, r_va1)
        rs_sha256_2, rs_loaded_sha256_2, rs_padding_sha256_2, rs_nostrings_sha256_2=PEDiff.get_section_features(self.samplepath2, r_va2)
        rs_resources_sha256_1, rs_resources_sha256_2, rs_resources_sha256, rs_resources_names, rs_resources_values=self.get_resources_features()
        report['has_resource_section_1']=rs_sha256_1!=sha256().hexdigest()
        report['has_resource_section_2']=rs_sha256_2!=sha256().hexdigest()
        report['rs_sha256_1']=rs_sha256_1
        report['rs_sha256_2']=rs_sha256_2
        report['rs_loaded_sha256_1']=rs_loaded_sha256_1
        report['rs_loaded_sha256_2']=rs_loaded_sha256_2
        report['rs_padding_sha256_1']=rs_padding_sha256_1
        report['rs_padding_sha256_2']=rs_padding_sha256_2
        report['rs_nostrings_sha256_1']=rs_nostrings_sha256_1
        report['rs_nostrings_sha256_2']=rs_nostrings_sha256_2
        report['rs_sha256']=rs_sha256_1==rs_sha256_2
        report['rs_loaded_sha256']=rs_loaded_sha256_1==rs_loaded_sha256_2
        report['rs_padding_sha256']=rs_padding_sha256_1==rs_padding_sha256_2
        report['rs_nostrings_sha256']=rs_nostrings_sha256_1==rs_nostrings_sha256_2
        report['rs_resources_sha256_1']=rs_resources_sha256_1
        report['rs_resources_sha256_2']=rs_resources_sha256_2
        report['rs_resources_sha256']=rs_resources_sha256
        report['rs_resources_names']=rs_resources_names
        report['rs_resources_values']=rs_resources_values

        os_sorted_sections_sha256_1, os_sorted_sections_sha256_2, os_sorted_sections_sha256, os_sections, os_sections_loaded, os_sections_padding, os_sections_nostrings, os_sorted_names_sha256_1, os_sorted_names_sha256_2, os_sorted_names_sha256=self.get_other_sections_features()
        report['has_other_sections_1']=os_sorted_sections_sha256_1!=sha256().hexdigest()
        report['has_other_sections_2']=os_sorted_sections_sha256_2!=sha256().hexdigest()
        report['os_sorted_sections_sha256_1']=os_sorted_sections_sha256_1
        report['os_sorted_sections_sha256_2']=os_sorted_sections_sha256_2
        report['os_sorted_sections_sha256']=os_sorted_sections_sha256
        report['os_sections']=os_sections
        report['os_sections_loaded']=os_sections_loaded
        report['os_sections_padding']=os_sections_padding
        report['os_sections_nostrings']=os_sections_nostrings
        report['os_sorted_names_sha256_1']=os_sorted_names_sha256_1
        report['os_sorted_names_sha256_2']=os_sorted_names_sha256_2
        report['os_sorted_names_sha256']=os_sorted_names_sha256

        ct_sha256_1, ct_sha256_2, ct_sha256, ct_entries, ct_pkcs7, ct_subjects, ct_issuers, ct_authentihash=self.get_certificate_table_features()
        real_authentihash_1=PEDiff.compute_authentihash(self.samplepath1)
        real_authentihash_2=PEDiff.compute_authentihash(self.samplepath2)
        report['has_certificate_table_1']=ct_sha256_1!=sha256().hexdigest()
        report['has_certificate_table_2']=ct_sha256_2!=sha256().hexdigest()
        report['ct_sha256_1']=ct_sha256_1
        report['ct_sha256_2']=ct_sha256_2
        report['ct_sha256']=ct_sha256
        report['ct_entries']=ct_entries
        report['ct_pkcs7']=ct_pkcs7
        report['ct_subjects']=ct_subjects
        report['ct_issuers']=ct_issuers
        report['ct_authentihash']=ct_authentihash
        report['real_authentihash_1']=real_authentihash_1
        report['real_authentihash_2']=real_authentihash_2
        report['real_authentihash_match']=real_authentihash_1==real_authentihash_2

        ov_sha256_1, ov_sha256_2, ov_sha256, ov_nostrings_sha256_1, ov_nostrings_sha256_2, ov_nostrings_sha256, no_overlay_sha256_1, no_overlay_sha256_2, no_overlay_sha256=self.get_overlay_features()
        report['has_overlay_1']=ov_sha256_1!=sha256().hexdigest()
        report['has_overlay_2']=ov_sha256_2!=sha256().hexdigest()
        report['ov_sha256_1']=ov_sha256_1
        report['ov_sha256_2']=ov_sha256_2
        report['ov_sha256']=ov_sha256
        report['ov_nostrings_sha256_1']=ov_nostrings_sha256_1
        report['ov_nostrings_sha256_2']=ov_nostrings_sha256_2
        report['ov_nostrings_sha256']=ov_nostrings_sha256
        report['no_overlay_sha256_1']=no_overlay_sha256_1
        report['no_overlay_sha256_2']=no_overlay_sha256_2
        report['no_overlay_sha256']=no_overlay_sha256

        return report

def compare_executables(EXE_1, EXE_2):
    pair=PEDiff(EXE_1, EXE_2)
    report=pair.get_report()
    return report

def dispatch_pair(args):
    return compare_executables(*args)

def compare_directory(DIR):
    EXEs=os.listdir(DIR)
    pairs=[(os.path.join(DIR, exe1), os.path.join(exe2)) for i, exe1 in enumerate(EXEs[:-1]) for exe2 in EXEs[i+1:]]
    with Pool() as pool:
        reports=list(tqdm(pool.map(dispatch_pair, pairs), total=len(pairs)))
    return reports

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
            WEIGHTS[fuzzy.replace('_', '-')]=weight

    for arg in bitshred_group._group_actions:
        option=arg.dest
        value=getattr(args, option)
        if value is not None:
            BITSHRED_SETTING[option]=value

    if args.files:
        report=[compare_executables(args.files[0], args.files[1])]
    elif args.directory:
        report=compare_directory(args.directory)
    df=pd.DataFrame(report)
    df.to_csv(args.output)

if __name__=='__main__':
    main()
    