#!/usr/bin/python3

from binascii import hexlify
from assets.functions import * 
import base64, sys, re, os, time 
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

timestr = time.strftime("%Y%m%d-%H%M%S")
ks_re = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\)'

ks_struct = {
    'id': None,
    'password_hash': None,
    'password_cipher': None,
    'hash_round': None,
    'salt': None,
    'config_hash': None,
    'dict': None
}

def parse_vmx_keysafe(file, verbose=False): 
    try:
        with open(file, 'r') as data:
            lines = data.readlines()
    except (OSError, IOError):
        sys.exit('[-] Cannot read from file ' + data)

    name = "Unknown"
    keysafe = None

    for line in lines:
        if 'encryption.keySafe' in line:
            keysafe = line
        if "displayName" in line:
            name = line.split(" = ")[1].rstrip().strip('"')

    keysafe = unquote(keysafe)
    match = re.match(ks_re, keysafe)
    if not match:
        msg = 'Unsupported format of the encryption.keySafe line:\n' + keysafe
        raise ValueError(msg)

    vmx_ks = ks_struct

    # vmx_ks['id'] = hexlify(base64.b64decode(match.group(1)))
    vmx_ks['password_hash'] = match.group(2)
    vmx_ks['password_cipher'] = match.group(3)
    vmx_ks['hash_round'] = int(match.group(4))
    vmx_ks['salt'] = base64.b64decode(unquote(match.group(5)))
    vmx_ks['config_hash'] = match.group(6)
    vmx_ks['dict'] = base64.b64decode(match.group(7))
    vmx_ks['name'] = name
    
    if verbose == True : 
        print ("[*] Verbose mode\n")
        print (f"",
            "VM Name                           : ",vmx_ks['name'],"\n",
            "Symetric-key algorithm encryption : ",vmx_ks['password_cipher'],"\n",
            "Hash algorithm                    : ",vmx_ks['password_hash'],"\n",
            "Hash Salt                         : ",hexlify(vmx_ks['salt']).decode(),"\n",
            "Hash round                        : ",vmx_ks['hash_round'],"\n",
            "Final Hash                        : ",hexlify(vmx_ks['dict']).decode(),"\n"
        )
        print ("[*] End of Verbose mode\n")
    return vmx_ks

def vmx_to_john(vmx_file, output, verbose):
    try:
        vmx_ks = parse_vmx_keysafe(vmx_file, verbose)
        salt = hexlify(vmx_ks['salt']).decode()
        final_hash = hexlify(vmx_ks['dict']).decode()

        formatted_hash = ""+os.path.basename(vmx_file)+"-"+vmx_ks['name']+":$vmx$1$0$0$"+str(vmx_ks['hash_round'])+"$"+salt+"$"+final_hash
        
        file_name = save_formatted_hash_to_file(formatted_hash, output)
        print("[*] Try to break it with the following command: john --format=vmx --wordlist=/usr/share/wordlists/rockyou.txt " + file_name)
            
    except Exception as e:
        return "Unable to parse correctly the .vmx file. Are you currently editing it ? Error : " + str(e)



def vmx_to_hashcat(vmx_file, output, verbose):
    
    try:
        vmx_ks = parse_vmx_keysafe(vmx_file, verbose)
        salt = hexlify(vmx_ks['salt']).decode()
        final_hash = hexlify(vmx_ks['dict']).decode()[:64] # Hashcat only require the first 64 chars for VMware VM's final hash
        
        formatted_hash = f"$vmx$0${vmx_ks['hash_round']}${salt}${final_hash}"
        
        file_name = save_formatted_hash_to_file(formatted_hash,output)
        print("[*] Try to break it with the following command: hashcat -m 27400 -a 0 "+file_name+" /usr/share/wordlists/rockyou.txt")

    except Exception as e:
        return "Unable to parse correctly the .vmx file. Are you currently editing it ? Error : "+str(e)