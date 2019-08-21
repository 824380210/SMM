# Example of Readh SMM IP from XCC 
# usage:
```
[root@mgt ~]#  bash -x read_SMM_IP_From_XCC.sh n03-bmc
+ XCC_IP=n03-bmc
++ ipmitool -I lanplus -H n03-bmc -U USERID -P PASSW0RD raw 0x3A 0xC4 0x00 0x00 0x14 0x93 0x2F 0x76 0x32 0x2F 0x69 0x62 0x6D 0x63 0x2F 0x73 0x6D 0x6D 0x2F 0x73 0x6D 0x6D 0x5F 0x69 0x70
+ result=' 00 00 05 44 85 67 1e ac'
++ echo 00 00 05 44 85 67 1e ac
++ cut '-d ' -f5-
+ SMM_16base='85 67 1e ac'
++ for line in '$SMM_16base'
++ let num=16#85
++ tac
++ echo 133
++ for line in '$SMM_16base'
++ let num=16#67
++ echo 103
++ for line in '$SMM_16base'
++ let num=16#1e
++ echo 30
++ for line in '$SMM_16base'
++ let num=16#ac
++ echo 172
+ rev_SMM_IP='172
30
103
133'
++ echo 172 30 103 133
++ tr ' ' .
+ SMM_IP=172.30.103.133
+ echo -e 'From XCC:\tn03-bmc \tGet SMM IP:\t172.30.103.133'
From XCC:       n03-bmc         Get SMM IP:     172.30.103.133
+ echo



```
# Bash version source code 
```
[root@mgt ~]# cat read_SMM_IP_From_XCC.sh
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
```
# md5 sum 
```
[root@mgt ~]# md5sum read_SMM_IP_From_XCC.sh
d94896ef746d80de8fada6a655058d48  read_SMM_IP_From_XCC.sh

```
