#!/usr/bin/python3

import argparse
from assets.virtualbox.vbox import *
from assets.vmware.vmx import * 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False, description="The aim of this tool is to Extracting encryption metadata and credentials from encrypted Virtual Machines (VirtualBox and VMware) is the primary goal. This involves obtaining crucial encryption details such as symmetric encryption, hash algorithms, iterations, hash rounds, and salts. VM-Password-Extractor effectively organizes this data in a structured format aligned with the specifications used by hashcat and John the Ripper")
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,help='Help menu')
    parser.add_argument("--vbox", help="Virtualbox VM configuration file. (.vbox extension)")
    parser.add_argument("--vmx", help="VMware VM configuration file. (.vmx extension)")
    parser.add_argument("--vmx-password-hash-to-hashcat", action='store_true', help="Use the power of hashcat to try to break the password hash.")
    parser.add_argument("--vmx-password-hash-to-john", action='store_true', help="Use the power of john to try to break the password hash.")
    parser.add_argument("--vbox-password-hash-to-hashcat", action='store_true', help="Use the power of hashcat to try to break the password hash.")
    parser.add_argument("--vbox-password-hash-to-john", action='store_true', help="Use the power of john to try to break the password hash. (!!! less efficient than hashcat !!!)")
    parser.add_argument("-o","--output", default="hash", help="Output the hash in a hash.txt file.", type=str)
    parser.add_argument("-v","--verbose",action='store_true', help="Verbose mode.")

    args = parser.parse_args()

    if args.vmx and args.vmx_password_hash_to_hashcat : 
        vmx_to_hashcat(args.vmx, args.output, args.verbose)
    elif args.vmx and args.vmx_password_hash_to_john: 
        vmx_to_john(args.vmx, args.output, args.verbose)
    elif args.vbox and args.vbox_password_hash_to_hashcat: 
        vbox_to_hashcat(args.vbox, args.output, args.verbose)
    elif args.vbox and args.vbox_password_hash_to_john: 
        vbox_to_john(args.vbox, args.output, args.verbose)
    else:
        parser.print_help()
        exit(1)