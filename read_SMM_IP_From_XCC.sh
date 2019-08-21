#!/bin/bash
#
# get the XCC IP from command line
XCC_IP=$1
result=$(ipmitool -I lanplus -H ${XCC_IP} -U USERID -P PASSW0RD raw 0x3A 0xC4 0x00 0x00 0x14 0x93 0x2F 0x76 0x32 0x2F 0x69 0x62 0x6D 0x63 0x2F 0x73 0x6D 0x6D 0x2F 0x73 0x6D 0x6D 0x5F 0x69 0x70)
#
# result example:  00 00 05 44 83 67 1e ac
SMM_16base=$(echo $result| cut -d' ' -f5-)
rev_SMM_IP=$(
for line in $SMM_16base
do
let num=16#$line
echo $num
done  | tac 
)
SMM_IP=$(echo $rev_SMM_IP|tr ' ' '.')
echo -e "From XCC:\t$XCC_IP \tGet SMM IP:\t$SMM_IP"
echo
