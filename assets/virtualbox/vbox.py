#!/usr/bin/python3

import xml.dom.minidom, base64
from binascii import hexlify
from struct import unpack
from assets.functions import * 

keystore_struct = {
    'FileHeader': None,
    'Version': None,
    'EVP_Algorithm': None,
    'PBKDF2_Hash': None,
    'Key_Length': None,
    'Final_Hash': None,
    'KL2_PBKDF2': None,
    'Salt2_PBKDF2': None,
    'Iteration2_PBKDF2': None,
    'Salt1_PBKDF2': None,
    'Iteration1_PBKDF2': None,
    'EVP_Length': None,
    'Enc_Password': None
}

tweak = 16 * b'\x00'

def parse_keystore(filename, verbose):
    try:
        fh_vbox = xml.dom.minidom.parse(filename)
    except IOError:
        print('[x] Cannot open:', filename)
        exit(1)

    hds = fh_vbox.getElementsByTagName("HardDisk")

    if len(hds) == 0:
        print('[x] No hard drive found')
        exit(1)

    keystore = None
    for disk in hds:
        is_enc = disk.getElementsByTagName("Property")
        if is_enc:
            # print('[*] Encrypted drive found : ', disk.getAttribute("location"))
            data = disk.getElementsByTagName("Property")[1]
            keystore = data.getAttribute("value")

    raw_ks = base64.decodebytes(keystore.encode())
    unpkt_ks = unpack('<4sxb32s32sI32sI32sI32sII64s', raw_ks)

    ks = keystore_struct
    for key, value in zip(ks.keys(), unpkt_ks):
        ks[key] = value


    if verbose == True : 
        print ("[*] Verbose mode\n")
        print (f"Symetric-key algorithm encryption        : ",ks['EVP_Algorithm'].rstrip(b'\x00').decode(),"\n"
                "Key lenght                               : ",str(ks['Key_Length']),"\n"
                "Hash algorithm                           : ",ks['PBKDF2_Hash'].rstrip(b'\x00').decode(),"\n"
                "KDF lenght                               : ",str(ks['KL2_PBKDF2']),"\n"
                "Salt 1                                   : ",hexlify(ks['Salt1_PBKDF2']).decode(), "\n"
                "Hash round (iteration 1)                 : ",str(ks['Iteration1_PBKDF2']), "\n"
                "Enc. pass used in the 2nd call to PBKDF2 : ",hexlify(ks['Enc_Password'].rstrip(b'\x00')).decode(), "\n"
                "Salt 2                                   : ",hexlify(ks['Salt2_PBKDF2']).decode(), "\n"
                "Hash round (iteration 2)                 : ",str(ks['Iteration2_PBKDF2']),"\n"
                "Final Hash                               : ",hexlify(ks['Final_Hash'].rstrip(b'\x00')).decode(), "\n"
        
        )
        print ("[*] End of Verbose mode\n")
    return ks

def vbox_to_hashcat(keystore, output, verbose): 
    
    try: 
        keystore = parse_keystore(keystore, verbose)
        formatted_hash =  ("$vbox$0$"+str(keystore['Iteration1_PBKDF2'])+
                           "$"+hexlify(keystore['Salt1_PBKDF2']).decode()+
                           "$"+str(int(keystore['Key_Length'] / 4))+ # Key_Lenght need to be divide by 4 to match hashcat format requirements
                           "$"+hexlify(keystore['Enc_Password'][0:keystore['Key_Length']]).decode()+
                           "$"+str(keystore['Iteration2_PBKDF2'])+
                           "$"+hexlify(keystore['Salt2_PBKDF2']).decode()+
                           "$"+hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode()
        )
        file_name = save_formatted_hash_to_file(formatted_hash, output)
        if len(formatted_hash) >= 347 : 
            print ("[*] Mode of encryption AES-XTS256-PLAIN64")
            print ("[*] Try to break it : hashcat -m 27600 -a 0 "+file_name+" /usr/share/wordlists/rockyou.txt")
        else : 
            print ("[*] Mode of encryption AES-XTS128-PLAIN64")
            print ("[*] Try to break it : hashcat -m 27500 -a 0 "+file_name+" /usr/share/wordlists/rockyou.txt")            
    except Exception as e : 
        print("Unable to parse correctly the .vbox file. Are you currently editing it ? Error : "+str(e))
        
def vbox_to_john(keystore, output, verbose): 
    
    try: 
        keystore = parse_keystore(keystore, verbose)
        pre_formatted_hash = (str(keystore['Iteration1_PBKDF2'])+
                              "$"+str(keystore['Iteration2_PBKDF2'])+
                              "$"+str(keystore['EVP_Length'])+
                              "$"+str(int(keystore['Key_Length']))+
                              "$"+hexlify(keystore['Salt1_PBKDF2']).decode()+
                              "$"+hexlify(keystore['Salt2_PBKDF2']).decode()+
                              "$"+hexlify(keystore['Enc_Password'][0:keystore['Key_Length']]).decode()+
                              "$"+hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode()
        
        )
        if len(pre_formatted_hash) >= 342 : # AES-XTS256-PLAIN64 
            print ("[*] Mode of encryption AES-XTS256-PLAIN64")
            formatted_hash = ("$vdi$aes-xts256$sha256$"+str(keystore['Iteration1_PBKDF2'])+
                              "$"+str(keystore['Iteration2_PBKDF2'])+
                              "$"+str(keystore['EVP_Length'])+
                              "$"+str(int(keystore['Key_Length'] / 2))+  # Key_Lenght need to be divide by 2 to match john format requirements
                              "$"+hexlify(keystore['Salt1_PBKDF2']).decode()+
                              "$"+hexlify(keystore['Salt2_PBKDF2']).decode()+
                              "$"+hexlify(keystore['Enc_Password'][0:keystore['Key_Length']]).decode()+
                              "$"+hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode()
            )
        else : # AES-XTS128-PLAIN64 
            print ("[*] Mode of encryption AES-XTS128-PLAIN64")
            formatted_hash = ("$vdi$aes-xts128$sha256$"+str(keystore['Iteration1_PBKDF2'])+
                              "$"+str(keystore['Iteration2_PBKDF2'])+
                              "$"+str(keystore['EVP_Length'])+
                              "$"+str(int(keystore['Key_Length']))+
                              "$"+hexlify(keystore['Salt1_PBKDF2']).decode()+
                              "$"+hexlify(keystore['Salt2_PBKDF2']).decode()+
                              "$"+hexlify(keystore['Enc_Password'][0:keystore['Key_Length']]).decode()+
                              "$"+hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode()
            )
        file_name = save_formatted_hash_to_file(formatted_hash, output)
        print(f"[*] Try to break it : john --wordlist=/usr/share/wordlists/rockyou.txt "+file_name+"")
    except Exception as e : 
        print("Unable to parse correctly the .vbox file. Are you currently editing it ? Error : "+str(e))