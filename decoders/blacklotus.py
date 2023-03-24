#!/bin/env python
####
#
# Created by ZeraSec
# 
# Requires BinaryNinja API
####
import binaryninja
import re
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import math
import collections
from pprint import pprint


def entropy(byte_sequence):
    m = len(byte_sequence)
    bases = collections.Counter([tmp_base for tmp_base in byte_sequence])

    shannon_entropy_value = 0
    for base in bases:
        n_i = bases[base]
        p_i = n_i / float(m)
        entropy_i = p_i * (math.log(p_i, 2))
        shannon_entropy_value += entropy_i

    return shannon_entropy_value * -1

def unmask(x):
    if x <= 0x7f:
        return x
    return x-0x60

def decrypt_string(cipher_bytes, raw_length=-1):
    # is cipher_bytes a string
    if isinstance(cipher_bytes, str):
        cipher_bytes = bytearray.fromhex(cipher_bytes)
    if raw_length == -1:
        raw_length = len(cipher_bytes)//2
    else:
        cipher_bytes = cipher_bytes[:raw_length*2]
    wchars = [int.from_bytes(cipher_bytes[2*i:2*i+2], 'little') for i in range(raw_length)]
    decrypted = [0]*(raw_length+1)
    for i in range(raw_length):
        xor_key = unmask(wchars[-(i+1)])
        decrypted[-(i+2)] = decrypted[-(i+1)] ^ xor_key
    for j in range(0, raw_length-1, 2):
        decrypted[j], decrypted[j+1] = decrypted[j+1], decrypted[j]
    for k in range(raw_length//2):
        tmp = decrypted[k]
        decrypted[k] = decrypted[raw_length-(1+k)]
        decrypted[raw_length-1-k] = tmp
    tmp = b''.join(x.to_bytes(2, 'little') for x in decrypted)
    return tmp[:-2].decode('utf-16')[:-1]

def decrypt_bytes(cipher_bytes, raw_length=-1):
    # if cipher_bytes a string
    if isinstance(cipher_bytes, str):
        cipher_bytes = bytearray.fromhex(cipher_bytes)

    if raw_length == -1:
        raw_length = len(cipher_bytes)
    else:
        cipher_bytes = cipher_bytes[:raw_length]

    decrypted = [0]*(raw_length+1)

    for i in range(raw_length): # xor
        xor_key = unmask(cipher_bytes[-(i+1)])
        decrypted[-(i+2)] = decrypted[-(i+1)] ^ xor_key
    
    for j in range(0, raw_length-1, 2): # byte swap
        decrypted[j], decrypted[j+1] = decrypted[j+1], decrypted[j]

    for k in range(raw_length//2): #reverse
        tmp = decrypted[k]
        decrypted[k] = decrypted[raw_length-(1+k)]
        decrypted[raw_length-1-k] = tmp
    tmp = b''.join(x.to_bytes(1, 'little') for x in decrypted)
    return tmp[:-2]

def bootkit_decryptor(function):
    caller_sites = list(function.caller_sites)
    upper_call = caller_sites[0]
    try:
        params = upper_call.mlil.params
        arg1 = int(params[0].value)
        arg2 = int(params[1].value)
        return arg1, arg2
    except Exception as e:
        print(e)

def decrypt_file(data, key, iv=b'\x00'*16):

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    out_data = unpad(cipher.decrypt(data), AES.block_size)
    sha56_hash = hashlib.sha256(out_data).hexdigest()
    return (str(sha56_hash), out_data)

def main(bv):
    str_decrypt_function = None
    byte_decrypt_function = None

    for function in list(bv.functions):
        function_bytes = bv.read(function.lowest_address, function.total_bytes)
        if re.search(b'\x66\x83.\x7F', function_bytes, flags=re.DOTALL):
            str_decrypt_function = function.lowest_address
        if re.search(b'\x80\xF9.\x8D\x41\xA0\x44\x0F\xB6\xC0\x8D\x42\xFF\x44\x0F\x46\xC1', function_bytes, flags=re.DOTALL):
            byte_decrypt_function = function.lowest_address
    
    string_list = None
    if str_decrypt_function != None:
        caller_sites = bv.get_code_refs(str_decrypt_function)
        string_list = list()
        for site in list(caller_sites):
            try:
                params = site.mlil.params
                arg1 = params[0].constant
                arg2 = params[1].constant
                data = bv.read(arg1, arg2*2)
                string_list.append((hex(site.address), decrypt_string(data)))
            except AttributeError:
                continue
    else:
        return None

    key_list = None
    if byte_decrypt_function != None:
        caller_sites = bv.get_code_refs(byte_decrypt_function)
        key_list = list()
        for site in list(caller_sites):
            try:
                params = site.mlil.params
                arg1 = params[0].constant
                arg2 = params[1].constant
                data = bv.read(arg1, arg2)
                key_list.append((decrypt_bytes(data), site.address))
            except AttributeError:
                continue
    else:
        return None

    file_list = list()
    for key, address in key_list:
        if len(key) >= 16:
            function = bv.get_functions_containing(address)[0]
            call_sites = function.call_sites
            found_call = None
            for site in call_sites:
                if site.address == address:
                    found_call = 1
                    continue
                if found_call:
                    try:
                        params = site.mlil.params
                        arg1 = int(params[0].value)
                        arg2 = int(params[1].value)
                        arg3 = int(params[2].value)
                        argsize = arg2 if arg2 > arg3 else arg3
                        if argsize < 1000:
                            arg1, argsize = bootkit_decryptor(function)
                        data = bv.read(arg1, argsize)
                        sha256_hash, out_data = decrypt_file(data, key)
                        if entropy(out_data) <= 7.90:
                            with open(sha256_hash, 'wb') as f:
                                f.write(out_data)
                            file_list.append(sha256_hash)
                    except Exception as e:
                        print(e)
                    break



    if string_list != None: 
        pprint(string_list)
    if key_list != None:
        pprint(key_list)
    if file_list:
        pprint(file_list)
    return file_list
    

def validate_binary(data):
    if data[0:2] == b'MZ' and b'This program cannot be run in DOS mode' in data:
        return data
    elif data[0:2] != b'MZ' and b'This program cannot be run in DOS mode' in data:
        fixed_header = bytearray(b'MZ')
        fixed_header.extend(data[2:])
        return fixed_header
    else:
        return None

def analyze_files(bv, file_list):
    if not file_list:
        return
    for file in file_list:
        file_bytes = open(file, 'rb').read()
        current_file = validate_binary(file_bytes)
        if current_file != None:
            bv = binaryninja.binaryview.BinaryViewType.load(current_file)
            bv.reanalyze()
            time.sleep(3)
            analyze_files(bv, main(bv))

if __name__ == "__main__":
    start_time = time.time()
    bin_file = open(sys.argv[1], 'rb').read()
    bv = binaryninja.binaryview.BinaryViewType.load(validate_binary(bin_file))
    bv.reanalyze()
    time.sleep(3)
    analyze_files(bv, main(bv))
    print(f"--- {time.time() - start_time} seconds ---")
