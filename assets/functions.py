#!/usr/bin/python3
import time

def save_formatted_hash_to_file(formatted_hash, output): 
    timestr = time.strftime("%Y%m%d-%H%M%S")
    try: 
        if output : 
            output = output+"."+timestr+".txt"
            with open(output, "w") as file:
                file.write(formatted_hash)
            print((
                    f"[+] Hash succefully formatted : {formatted_hash}\n"
                    f"[*] "+output+" has been created." 
            ))
        return output
    except Exception as e : 
        print ("Error :"+str(e))