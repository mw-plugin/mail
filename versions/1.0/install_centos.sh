#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

curPath=`pwd`
rootPath=$(dirname "$curPath")
rootPath=$(dirname "$rootPath")
serverPath=$(dirname "$rootPath")

cpu_arch=`arch`
if [[ $cpu_arch != "x86_64" ]];then
  echo 'Does not support non-x86 system installation'
  exit 0
fi


OSNAME_ID=`cat /etc/*-release | grep VERSION_ID | awk -F = '{print $2}' | awk -F "\"" '{print $2}'`

Install_centos8()
{
    yum install epel-release -y
    # 卸载系统自带的postfix
    if [[ $cpu_arch = "x86_64" && $postfixver != "3.4.9" ]];then
        yum remove postfix -y
        rm -rf /etc/postfix
    fi

    yum install sqlite -y

    # 安装postfix和postfix-sqlite
    if [[ ! -f "/usr/sbin/postfix" ]]; then
        yum install postfix -y
        yum install postfix-sqlite -y
    fi

    # 安装dovecot和dovecot-sieve
    yum install dovecot-pigeonhole -y
    if [[ ! -f "/usr/sbin/dovecot" ]]; then
        yum install dovecot -y
    fi


    # 安装rspamd                                     
    wget -O /etc/yum.repos.d/rspamd.repo --no-check-certificate https://rspamd.com/rpm-stable/centos-8/rspamd.repo
    rpm --import https://rspamd.com/rpm-stable/gpg.key
    yum makecache

    yum install rspamd -y
    yum install cyrus-sasl-plain -y
}

Install_centos7() {

    cp -rf $curPath/conf/centos7gf.repo /etc/yum.repos.d/
    yum makecache

    yum install epel-release -y
    # 卸载系统自带的postfix
    # if [[ $cpu_arch = "x86_64" && $postfixver != "3.4.7" ]];then
    #     yum remove postfix -y
    #     rm -rf /etc/postfix
    # fi

    # 安装postfix和postfix-sqlite
    if [ ! -f /usr/sbin/postfix ]; then
        yum install postfix3 -y
        yum install postfix3-sqlite -y
    fi

    # inet_interfaces = localhost
    sed -i 's/^inet_interfaces\ =\ localhost/inet_interfaces = all/g' /etc/postfix/main.cf

    # 安装dovecot和dovecot-sieve
    yum install dovecot-pigeonhole -y
    if [[ ! -f /usr/sbin/dovecot ]]; then
        yum install dovecot -y
    fi

    # 安装rspamd
    yum install -y ca-certificates
    wget -O /etc/yum.repos.d/rspamd.repo --no-check-certificate https://rspamd.com/rpm-stable/centos-7/rspamd.repo
    rpm --import https://rspamd.com/rpm-stable/gpg.key

    # wget -O /tmp/cacert.pem --no-check-certificate http://curl.haxx.se/ca/cacert.pem
    # cat /tmp/cacert.pem > /etc/pki/tls/certs/ca-bundle.crt

    yum makecache
    yum install rspamd -y
    yum install cyrus-sasl-plain -y

}

Install_App() {
    if [ "$OSNAME_ID" == "7" ];then
        Install_centos7
    elif [ "$OSNAME_ID" == "8" ];then
        Install_centos8
    fi
}

Uninstall_App()
{
    yum remove postfix -y
    yum remove dovecot -y
    yum remove opendkim -y
    yum remove rspamd -y
    yum remove dovecot-pigeonhole -y
}


action=$1
if [ "${1}" == 'install' ];then
  Install_App
else
  Uninstall_App
fi