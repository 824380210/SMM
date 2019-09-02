#!/usr/bin/env python3.5
import subprocess
import logging
import sys
import time
import socket
import argparse
import os
#cmdline parameters
parser = argparse.ArgumentParser(description='Query or Set the information to the Lenovo System Management Module(SMM).')
parser.add_argument('-U','--USER', dest='username',default='USERID',help='specify the usernane to use to access the SMM')
parser.add_argument('-P','--PASS', dest='password',default='PASSW0RD',help='specify the password to use to access the SMM')
parser.add_argument('-H','--host', dest='host',default='192.168.0.100',help='specify the IP Address or hostname of the target SMM')
#parser.add_argument('-D','--debug', dest='debug',default=None,choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'],help='print more info in Debug mode')
parser.add_argument('--set_smm_led', dest='set_smm_led',default=None,choices=['on','off','blink'],help='Identify the SMM by turn on /off the Location LED')
parser.add_argument('-i','--get_smm_ip', dest='get_smm_ip',action="store_true",default=False,help="read the SMM IP from the compute node's XCC  in the same chassis")
parser.add_argument('-r','--reset_smm', dest='reset_smm',action="store_true",default=False,help="reset SMM / reboot SMM")
parser.add_argument('--enable_smm', dest='enable_smm',action="store_true",default=False,help="send command to XCC to Enable the SMM Network function")
parser.add_argument('--disable_smm', dest='disable_smm',action="store_true",default=False,help="send command to XCC to Disable the SMM Network function")
parser.add_argument('--query_smm', dest='query_smm',action="store_true",default=False,help="send command to XCC to Query the SMM Network function")
parser.add_argument('--set_NTP1', dest='NTP1',default=None,help="set NTP server 1")
parser.add_argument('--set_NTP2', dest='NTP2',default=None,help="set NTP server 2")
parser.add_argument('--set_NTP3', dest='NTP3',default=None,help="set NTP server 3")
parser.add_argument('--set_NTP_mode', dest='ntp_mode',default=None,choices=['Disabled','Daemon','Requested'],help="set NTP working Mode")
parser.add_argument('--get_NTP', dest='get_ntp',action="store_true",default=False,help="get NTP server settings")
#parser.add_argument('--get_smm_status', dest='get_smm_status',action="store_true",default=False,help="get SMM LED Status")
parser.add_argument('--get_domainname', dest='get_domainname',action="store_true",default=False,help="get SMM Domain Name")
parser.add_argument('--get_hostname', dest='get_hostname',action="store_true",default=False,help="get the SMM hostname")
parser.add_argument('--set_hostname', dest='set_hostname',default=None,help="set the SMM hostname")
parser.add_argument('--set_domainname', dest='set_domainname',default=None,help="set the SMM domainname")
parser.add_argument('--set_smm_date', dest='set_smm_date',default=None,help="set the SMM date with format yyyy-mm-dd HH:MM:SS")
parser.add_argument('--reset_xcc', dest='reset_xcc',default=None,choices=['1','2','3','4'],help="reset the XCC by send CMD to SMM")
parser.add_argument('--reseat_node', dest='reseat_node',default=None,choices=['1','2','3','4'],help="reseat the node by send CMD to SMM /AC Cycling")
parser.add_argument('--get_psu_policy', dest='get_psu_policy',action="store_true",default=False,help="get the SMM PSU policy and OverSubscription")
parser.add_argument('--get_smm_mode', dest='get_smm_mode',action="store_true",default=False,help="get the SMM working Mode")
parser.add_argument('--set_smm_mode', dest='set_smm_mode',default=False,choices=['Normal','Shared'],help="set the SMM working Mode")
#parser.add_argument('-v','--get_smm_ver', dest='get_smm_ver',action="store_true",default=False,help="get the SMM version")
#parser.add_argument('-v','--get_smm_ver', dest='get_smm_ver',action="store_true",default=False,help="get the SMM version")
parser.add_argument('-v','--get_smm_ver', dest='get_smm_ver',action="store_true",default=False,help="get the SMM version")
parser.add_argument('--dump_smm_ffdc', dest='dump_smm_ffdc',default=None,help="dump the SMM FFDC log to the TFTP server")
args = parser.parse_args()
if os.environ.get('enable_debug'):
    print(args)
# support SMM ipmi command
support_SMM_cmd = {}
support_SMM_cmd["reset_SMM"]=" 0x6 0x2"
#config loggin
logfile='/var/log/lenovo_SMM.log'
#print(loglevel)
#sys.exit(0)
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(levelname)-8s %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
                filename=logfile,
                filemode='w')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s  %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
logging.debug(args)
#
#logging.info("this is the end")
#sys.exit(0)
ipmicmd = "ipmitool -I lanplus -H  {}   -U  {}  -P {} ".format(args.host,args.username,args.password)
logging.info("Start to run SMM tools for query / settings some parameters!!!")
def runcmd(cmd,timeout=None):
    """
    run command for subprocess and return the output 
    """
    if not timeout:
        timeout = 30
    proc = subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if proc.returncode != 0:
        raise Exception("cmd run failed with {}".format(cmd))
    else:
        return(proc.stdout)
#
def to_red(str):
    new_str = "\033[31m " + str + "\033[0m"
    return new_str
# Get the IP of hostname from socket
def get_IP(host):
    addrs = socket.getaddrinfo(host, None)
    return addrs[0][4][0]
# read the mac of the SMM

def get_smm_mac():
    cmd = "ipmitool -I lanplus -H  {}   -U  {}  -P {} lan print 1 | grep 'MAC Address'".format(args.host,args.username,args.password)
    result = runcmd(cmd)
    str = ':'.join(result.decode().split(':')[1:])
    return str.strip()
#smm_mac = get_smm_mac()
#
# get the SMM IP from the XCC in the same chassis 
def get_smm_ip(xcc_host):
    raw_cmd = 'raw 0x3A 0xC4 0x00 0x00 0x14 0x93 0x2F 0x76 0x32 0x2F 0x69 0x62 0x6D 0x63 0x2F 0x73 0x6D 0x6D 0x2F 0x73 0x6D 0x6D 0x5F 0x69 0x70'
    cmd = ipmicmd + raw_cmd
    logging.debug(cmd)
    result = runcmd(cmd)
    # result = "00 00 05 44 85 67 1e ac"
    logging.info(result.decode().split()[-4:])
    smm_ip = reversed(result.decode().split()[-4:])
    ip_str = []
    #print(smm_ip)
    for digit in smm_ip:
        ip_str.append(str(int("0x"+digit,16)))
        #print(ip_str)
    smm_ip_str = '.'.join(ip_str)
    return smm_ip_str     
def reset_smm():
    if args.reset_smm:
        msg = "Request to reset the SMM, and the SMM is [{}]".format(args.host)
        logging.info(msg)
    raw_cmd = "raw 0x6 0x2"
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    msg     = "Reset SMM [{}] is done ,please wait 60 seconds !!!".format(args.host)
    logging.info(msg)
def set_ntp():
    if args.NTP1:
        ntp_host1 = translate_str(args.NTP1)
        raw_cmd = " raw  0x32 0xb4 0x1 " + ntp_host1 
        cmd     = ipmicmd + raw_cmd
        result  = runcmd(cmd)
        msg     = "set NTP Server 1 to {}".format(args.NTP1)
        logging.info(msg)
    if args.NTP2:
        ntp_host2 = translate_str(args.NTP2)
        raw_cmd = " raw  0x32 0xb4 0x2 " + ntp_host2
        cmd     = ipmicmd + raw_cmd
        result  = runcmd(cmd)
        msg     = "set NTP Server 2 to {}".format(args.NTP2)
        logging.info(msg)

    if args.NTP3:
        ntp_host3 = translate_str(args.NTP3)
        raw_cmd = " raw  0x32 0xb4 0x3 " + ntp_host3
        cmd     = ipmicmd + raw_cmd
        result  = runcmd(cmd)
        msg     = "set NTP Server 3 to {}".format(args.NTP3)
        logging.info(msg)
    if args.ntp_mode:
        if args.ntp_mode == 'Disabled':
            raw_cmd = "raw 0x32 0xb4 0x0 0x0"
            cmd     =  ipmicmd + raw_cmd
            result  =  runcmd(cmd)
            msg     =  " Set SMM NTP work mode to Disabled"
            logging.info(msg)
        if args.ntp_mode == 'Daemon':
            raw_cmd = "raw 0x32 0xb4 0x0 0x1"
            cmd     =  ipmicmd + raw_cmd
            result  =  runcmd(cmd)
            msg     =  " Set SMM NTP work mode to Daemon Mode"
            logging.info(msg)
        if args.ntp_mode == 'Requested':
            raw_cmd = "raw 0x32 0xb4 0x0 0x2"
            cmd     =  ipmicmd + raw_cmd
            result  =  runcmd(cmd)
            msg     =  " Set SMM NTP work mode to Requested Mode"
            logging.info(msg)
#:
def get_ntp():
    if args.get_ntp:
        msg = "Start to check the NTP working Mode in SMM {}".format(args.host)
        logging.info(msg)
        raw_cmd = " raw 0x32 0xb5 0x0 " 
        cmd     = ipmicmd + raw_cmd
        result  = runcmd(cmd)
        index   = result.decode().split()[-1]
        mode    = ['Disabled','Daemon','Requested']
        mymode  = mode[int(index)]
        msg     = "SMM {} is working is {} Mode now!!!".format(args.host,mymode)
        logging.info(msg)
        if mymode != 'Disabled':
            msg = "Start to check the NTP server settings"
            logging.info(msg)
            for i in range(1,4):
                msg = "Start to check the NTP Server {}".format(str(i))
                logging.info(msg)
                raw_cmd = "raw 0x32 0xb5 0x{}".format(i)
                cmd     = ipmicmd + raw_cmd
                result  = runcmd(cmd)
                res     = result.decode().split()
                if res[1] != '00':
                    ntp_server = ascii2str(res[2:])
                    msg = "the NTP Server {} is set to {}".format(str(i),ntp_server)
                    logging.info(msg)
                else:
                    msg = "the NTP Server {} is not set ".format(str(i))
                    logging.info(msg)
                
if args.reset_smm:
    reset_smm()
    sys.exit(0)
if args.get_smm_ip:
    xcc_host = args.host
    smm_ip = get_smm_ip(xcc_host)
    msg = "The compute node with XCC [ {} ]   know the SMM IP is  [ {} ]".format(xcc_host,smm_ip)
    logging.info(msg)
    sys.exit(0)

def set_smm_led():
    info = """
    SetSySLED	0x32	0x97	Request:
    Byte 1: Input type	
	1: SysLocater LED
	2: CheckLog LED
    Byte 2:
	0: Disable , 
	1: Enable ,
	2 blink (SysLocater only)
    Response:
    Byte 1 – completion code (0x00)
    PARAM_OUT_OF_RANGE (0xC9)	This command is used to get the SMM LED status.
    0: Off
    1: On
    2: Blink (Locater only)


    """
    if args.set_smm_led and args.set_smm_led == "on":
        status = 0x1
    elif args.set_smm_led and args.set_smm_led == "off":
        status = 0x0
    elif args.set_smm_led and args.set_smm_led == "blink":
        status = 0x2
    else:
        logging.info("not support command")
        sys.exit(1)
    raw_cmd = " raw 0x32 0x97 0x1 {}".format(status)
    cmd     = ipmicmd + raw_cmd
    msg     = "Start to set the SMM Locater LED to \033[31m[ {} ]\033[0m".format(args.set_smm_led)
    logging.info(msg)
    runcmd(cmd)
    msg     = "SMM Locater LED to [ {} ] is Done".format(args.set_smm_led)
    logging.info(msg)
#
#
def enable_smm():
    xcc_ip = args.host
    if check_pingable(xcc_ip):
        msg  = "start to send command to XCC [{}] to Enable the SMM network function".format(xcc_ip)
        logging.info(msg)
    raw_cmd = " raw 0x3A 0xF1 0x01 "
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    msg     =  "Enable SMM done in XCC [{}]".format(xcc_ip)
    logging.info(msg)

def disable_smm():
    xcc_ip = args.host
    if check_pingable(xcc_ip):
        msg  = "start to send command to XCC [{}] to Disable the SMM network function".format(xcc_ip)
        logging.info(msg)
    raw_cmd = " raw 0x3A 0xF1 0x02 "
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    msg     =  "Disable SMM done in XCC [{}]".format(xcc_ip)
    logging.info(msg)

def query_smm():
    xcc_ip = args.host
    if check_pingable(xcc_ip):
        msg  = "start to send command to XCC: {} to Query the SMM network function".format(to_red(xcc_ip))
        logging.info(msg)
    raw_cmd = " raw 0x3A 0xF1 0x00 "
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    msg     =  "Query SMM done in XCC: {} ".format(to_red(xcc_ip))
    logging.info(msg)
    query_state = result.decode().strip()
    print(query_state)
    if query_state == '01':
        state = "Enable"
    if query_state == '02':
        state = 'Disable' 
    msg     = "Now SMM is in {} State".format(state)
    logging.info(msg)

# 
def get_smm_status():
    if args.get_smm_status:
        raw_cmd = "raw 0x32 0x96 "
        cmd     = ipmicmd + raw_cmd
        result  = runcmd(cmd)
        res     = result.decode().split()
        if res[1] == '00':
            status = "OFF"
        if res[1] == '01':
            status = "ON"
        if res[1] == '02':
            status = "Blinking"
        else:
            status = "Unknown status"
    msg =  "the current SMM LED is {}".format(status) 
    logging.info(msg)

#
def translate_str(str1,length=True):
    str = str1.strip()
    newstr = []
    if length:
        newstr.append(" 0x{:x} ".format(len(str)))
    for i in str:
        newstr.append(" 0x{:x} ".format(ord(i)))
    mystr = ' '.join(newstr)
    return mystr

def translate_str1(str1):
    str = str1.strip()
    newstr = []
    for i in str:
        newstr.append(" 0x{:x} ".format(ord(i)))
    mystr = ' '.join(newstr)
    return mystr

def ascii2str(mylist):
    newstr = []
    for i in mylist:
        newstr.append(chr(int("0x{}".format(i),16)))
    mystr = ''.join(newstr)
    return mystr

def set_hostname():
    str = translate_str(args.set_hostname)
    cmd = " ipmitool -I lanplus -H {}   -U {}  -P {} raw 0x0c 0x01 0x01 0xc3  ".format(args.host,args.username,args.password) + str
    logging.debug(cmd)
    runcmd(cmd)
    msg = "hostanme set to {} Done".format(args.set_hostname)
    logging.info(msg)

def set_domainname():
    str = translate_str(args.set_domainname)
    cmd = " ipmitool -I lanplus -H {}   -U {}  -P {} raw 0x0c 0x01 0x01 0xc4   ".format(args.host,args.username,args.password) + str
    runcmd(cmd)
    msg = "domain set to {} Done".format(args.set_domainname)
    logging.info(msg)
#
#
def get_domainname():
    raw_cmd = " raw 0x0c 0x02 0x01 0xc4 0x00 0x00"
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    mydomain = result.decode().split()
    #
    domainname = ascii2str(mydomain[2:])
    msg = "get the SMM Domain Name is :\t {}".format(domainname)
    logging.info(msg)
    return domainname
       
def get_hostname():
    raw_cmd = " raw 0x0c 0x02 0x01 0xc3 0x00 0x00"
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    myhostname = result.decode().split()
    #
    hostname   = ascii2str(myhostname[2:])
    msg = "get the SMM Host Name is :\t {}".format(hostname)
    logging.info(msg)
    return hostname

#
msg = "Start to check the configure parameter "
def check_pingable(host):
    cmd = "ping -c 1 {}".format(host)
    result = runcmd(cmd)
    return True
def dump_smm_ffdc():
    #
    msg = "Get request to dump the SMM FFDC log to TFTP Server [{}]".format(args.dump_smm_ffdc)
    logging.info(msg)
    host_ip = get_IP(args.dump_smm_ffdc)
    if check_pingable(host_ip):
        msg = "TFTP Server is reachable !!!"
        logging.info(msg)
    else:
        msg = "TFTP Server is not reachable!!!"
        logging.info(msg)
        sys.exit(0)
    msg = "start to told the SMM about the TFTP server IP"
    logging.info(msg)
    raw_cmd  = " raw 0x32 0xB1 0x1 "
    hex_tftp_server = translate_str(host_ip,length=False)
    raw_cmd += hex_tftp_server
    cmd      = ipmicmd + raw_cmd
    result   = runcmd(cmd)
    time.sleep(1)
    msg      = "start to dump the FFDC log"
    logging.info(msg)
    raw_cmd  = " raw 0x32 0xB1 "
    cmd      = ipmicmd + raw_cmd
    result   = runcmd(cmd)
    msg      =  "wait 120 or seconds to wait for SMM FFDC log dump complete "
    logging.info(msg)
    time.sleep(60)
    msg      =  "please check your TFTP server {} root directory to chekc the SMM FFDC log "  
    logging.info(msg)
    msg      =  "FFDC Example:\tSMM-0894EF6CBBF5-FFDC-190828-081320.tgz "  
    logging.info(msg)
    
def check_date_str(str):
    valid_yy  =  ["20"]
    valid_mm  =  ["{0:02d}".format(i) for i in range(60)]
    valid_yy1 =  valid_mm[:38] 
    valid_dd  =  valid_mm[1:32]
    valid_hh  =  valid_mm[:24]
    valid_MM  =  valid_mm[:13]
    valid_ss  =   valid_mm
    msg1 ="wrong Date format ,it must be YYYY-MM-DD hh:mm:ss"
    if len(str) <19:
        logging.info(msg1)
        msg = "Make usre the YYYY is 4 digit and MM is 2 digit ..."
        logging.info(msg)
        sys.exit(2)
    else:
        if '-' not in str and ':' not in str:
            logging.info(msg1)
            msg = "Make usre Years is connect to the Month with '-',and Hours is connect ot Mimutes with ':'..."
            logging.info(msg)
            sys.exit(2)
        else:
            dateinfo = str.strip().split()
            yy  = dateinfo[0][:2]
            yy1 = dateinfo[0][2:4]
            MM  = dateinfo[0].split('-')[1]
            dd  = dateinfo[0].split('-')[2]
            hh  = dateinfo[1].split(':')[0]
            mm  = dateinfo[1].split(':')[1]
            ss  = dateinfo[1].split(':')[2]
            if yy not in valid_yy or yy1 not in valid_yy1 or MM not in valid_MM or dd not in valid_dd :
                logging.info(msg1)
                mystr = "Year is {}{} , Month is {} and Day is {},which is \033[31mWRONG\033[0m".format(yy,yy1,MM,dd)
                logging.info(mystr)
                sys.exit(2)
            elif hh not in valid_hh or mm not in valid_mm or ss not in valid_ss:
                logging.info(msg1)
                mystr = "Hours is {} , Minutes is {} and Seconds is {},which is \033[31mWRONG\033[0m".format(hh,mm,ss)
                logging.info(mystr)
                sys.exit(2)
  
            else: 
                msg = "date info is valid ,start to set the SMM date"
                logging.info(msg)
                mystr = "0x{} 0x{} 0x{} 0x{} 0x{} 0x{} 0x{}  ".format(yy,yy1,mm,dd,hh,MM,ss)
                logging.info(mystr)
                return mystr
def set_smm_date():
    raw_cmd = " raw 0x32 0xA1 "
    raw_cmd += check_date_str(args.set_smm_date)
    cmd = ipmicmd + raw_cmd
    runcmd(cmd)
    msg = "SMM date set done with {}".format(args.set_smm_date)
    logging.info(msg)


def get_psu_policy():
    msg = "Start to read the PSU policy in the SMM"
    logging.info(msg)
    raw_cmd = " raw 0x32 0xA2"
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    answer  = result.decode().split()
    if answer[0] == '00':
        psu_policy = "No Redundant"
    elif answer[0] == '01':
        psu_policy = "N+1 Redundant"
    
    
    if answer[1] == '00':
        ovs = "Disable"
    elif answer[1] == '01':
        ovs = "Enable"
    msg = "PSU Power policy is \033[31m {} \033[0m and Over Subscription is \033[31m {} \033[0m ".format(psu_policy,ovs)
    logging.info(msg)

def set_psu_policy():
    pass

def reset_node_xcc(reseat=False):
    node = {'1':'0x1','2':'0x2','3':'0x3','4':'0x4'}
    mynode  = node[args.reset_xcc]
    if args.reset_xcc:
        raw_cmd = "raw 0x32 0xA4 {} 0x1".format(mynode)
        msg = "reset the node\033[31m [ slot {} ]\033[0m XCC by SMM done ".format(args.reset_xcc)
    if args.reseat_node and reseat:
        raw_cmd = "raw 0x32 0xA4 {} 0x2".format(mynode)
        msg = "reseat the node\033[31m [ slot {} ]\033[0m  by SMM done ".format(args.reseat_node)

    cmd = ipmicmd + raw_cmd
    result =runcmd(cmd)
    logging.info(msg)

def reseat_node():
    reset_node_xcc(reseat=True) 

#

def get_smm_version():
    raw_cmd   = " raw 0x32 0xA8"
    cmd       = ipmicmd + raw_cmd
    result    = runcmd(cmd)
    answer    = result.decode().split()
    smm_main  = str(int(answer[0])) 
    smm_minor = answer[1]
    psoc_main = str(int(answer[2]))
    psoc_minor= str(int(answer[3]))
    smm_ver   = smm_main  + '.' + smm_minor
    psoc_ver  = psoc_main + '.' + psoc_minor
    smm_str   = ascii2str(answer[5:])
    msg       = "SMM  Version is {}\t[{}]".format(smm_ver,smm_str)
    msg1      = "PSOC Version is {}".format(psoc_ver)
    logging.info(msg)
    logging.info(msg1)

def get_smm_mode():
    raw_cmd = "raw 0x32 0xC5 0x01"
    cmd     = ipmicmd + raw_cmd
    result  = runcmd(cmd)
    answer  = result.decode().strip()
    if answer   == "01":
        mode    = "Normal"
    elif answer == "02":
        mode    = "Shared I/O"
    else:
        mode    = "Not Support SMM "
    msg = "The SMM is work in the \033[31m {} \033[0m Mode".format(mode)
    logging.info(msg)

def set_smm_mode():
    if args.set_smm_mode == "Shared":
        raw_cmd = " raw 0x32 0xC5 0x00 0x02"
    elif args.set_smm_mode == "Normal":
        raw_cmd = " raw 0x32 0xC5 0x00 0x01"
    cmd = ipmicmd + raw_cmd
    result = runcmd(cmd)
    msg = "Update SMM to the work mode is \033[31m {} \033[0m".format(args.set_smm_mode)
    logging.info(msg)


#
#
def main():
    if args.set_domainname:
        msg = "found domain name {} to be set in this SMM".format(args.set_domainname)
        logging.info(msg)
        set_domainname()
    if args.set_hostname:
        msg = "found host name {} to be set in this SMM".format(args.set_hostname)
        logging.info(msg)
        set_hostname()
    if args.NTP1 or args.NTP2 or args.NTP3 or args.ntp_mode:
        set_ntp()
    if args.get_ntp:
        get_ntp()        
    if args.dump_smm_ffdc:
        dump_smm_ffdc()
    if args.get_domainname:
        get_domainname()
    if args.get_hostname:
        get_hostname()
    if args.query_smm:
        query_smm()
    if args.disable_smm:
        disable_smm()
    if args.enable_smm:
        enable_smm()
    if args.set_smm_led:
        set_smm_led()
    if args.set_smm_date:
        set_smm_date()
    if args.get_psu_policy:
        get_psu_policy()
    if args.reset_xcc:
        reset_node_xcc()
    if args.reseat_node:
        reseat_node()
    if args.get_smm_ver:
        get_smm_version()
    if args.get_smm_mode:
        get_smm_mode()
    if args.set_smm_mode:
        set_smm_mode()
    
if __name__ == "__main__":
    main()    
