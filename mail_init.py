# coding:utf-8

import sys
import io
import os
import time
import re
import json

# https://www.freesion.com/article/6078447161/


sys.path.append(os.getcwd() + "/class/core")

import mw
app_debug = False
if mw.isAppleSystem():
    app_debug = True


class mail_init:

    def __init__(self):
        self.logfile = '/tmp/mail_init.log'

    def write_logs(self, content, emtpy=None):
        if emtpy:
            mw.writeFile(self.logfile, '')
        if '\n' not in content:
            content += '\n'
        mw.writeFile(self.logfile, content)

    def returnData(self, status, msg, data=None):
        data = mw.returnData(status, msg, data)
        return json.loads(data)

    def __release_port(self, port):
        from collections import namedtuple
        try:
            import firewall_api
            firewall_api.firewall_api().addAcceptPortArgs(port, 'Mail-Server', 'port')
            return port
        except Exception as e:
            return "Release failed {}".format(e)

    def check_env(self):
        data = {}
        data['HostName'] = self.check_hostname()
        data['Postfix-install'] = {"status": True, "msg": "Postfix已经安装"} if os.path.exists(
            '/usr/sbin/postfix') else {"status": False, "msg": "Postfix未安装,请点击修复按钮"}
        data['Postfix-Version'] = self.check_postfix_ver()

        data['Dovecot-install'] = {"status": True, "msg": "Deovecot已经安装"} if os.path.exists(
            '/usr/sbin/dovecot') or os.path.exists('/usr/local/opt/dovecot/sbin/dovecot') else {"status": False, "msg": "Dovecot未安装,请点击修复按钮"}
        data['Redis-install'] = {"status": True, "msg": "Redis已经安装"} if os.path.exists(
            mw.getServerDir() + '/redis/bin/redis-server') else {"status": False, "msg": "请到软件商店内安装Redis"}
        data['Redis-Passwd'] = self.check_redis_passwd(data['Redis-install'])
        data['Rspamd-install'] = {"status": True, "msg": "Rspamd已经安装"} if os.path.exists(
            '/usr/bin/rspamd') or os.path.exists(
            '/opt/local/bin/rspamd') else {"status": False, "msg": "Rspamd未安装,请点击修复按钮"}
        data['Sqlite-support'] = self.check_sqlite()
        data['SElinux'] = {"status": True, "msg": "SElinux已经禁用"} if not 'enforcing' in mw.execShell(
            'getenforce')[0].lower() else {"status": False, "msg": "请先禁用SElinux"}
        return data

    def setup_mail(self):

        self.write_logs(
            '|-Set up the postfix service to listen to all network cards...')
        mw.execShell('postconf -e "inet_interfaces = all"')
        self.write_logs('|-Checking system key directory permissions...')
        self.write_logs('|-Initializing...')

        self.prepare_work()

        conf_postfix_data = self.conf_postfix()
        print(conf_postfix_data)
        print(json.loads(conf_postfix_data))
        if not self.conf_postfix()['status']:
            return mw.returnJson(False, 'Postfix配置失败！')
        if not self.conf_dovecot():
            return mw.returnJson(False, 'Dovecot配置失败！')

        if not self.conf_dovecot():
            return mw.returnJson(False, 'Dovecot配置失败！')

        self.write_logs('|{}'.format("-" * 60))
        self.write_logs('|-Initialized successfully!')
        return mw.returnJson(True, 'SUCCESS_INSTALL')

    def prepare_work(self):
        '''
        安装前的准备工作
        :return:
        '''
        shell_str = '''
useradd -r -u 150 -g mail -d /www/vmail -s /sbin/nologin -c "Virtual Mail User" vmail
mkdir -p /www/vmail
chmod -R 770 /www/vmail
chown -R vmail:mail /www/vmail
'''
        self.write_logs('', emtpy=True)
        self.write_logs('|-Adding user: vmail')
        self.write_logs('|-Create mail storage directory: /www/vmail')
        self.write_logs('|-Set directory permissions: 770')
        self.write_logs('|-Set directory owner: vmail:mail')

        mw.execShell(shell_str)
        for i in ["25", "110", "143", "465", "995", "993", "587"]:
            self.write_logs('|-Releasing port: {}'.format(i))
            self.__release_port(i)
        return True

    def __check_sendmail(self):
        pid = '/run/sendmail/mta/sendmail.pid'
        if os.path.exists(pid):
            self.write_logs(
                '|-Check that there is an additional mail service aaa, which is stopping')
            mw.execShell(
                'systemctl stop sendmail && systemctl disable sendmail')

    def conf_postfix(self):
        '''
        安装，配置postfix服务, postfix提供发信功能
        :return:
        '''
        # 检查sendmail服务，如果有则停止
        self.__check_sendmail()

        self.write_logs('|-Initializing postfix...')
        edit_postfix_conf_shell = '''
postconf -e "myhostname = $(hostname)"
postconf -e "inet_interfaces = all"
postconf -e "mydestination ="

postconf -e "virtual_mailbox_domains = sqlite:/etc/postfix/sqlite_virtual_domains_maps.cf"
postconf -e "virtual_alias_maps =  sqlite:/etc/postfix/sqlite_virtual_alias_maps.cf, sqlite:/etc/postfix/sqlite_virtual_alias_domain_maps.cf, sqlite:/etc/postfix/sqlite_virtual_alias_domain_catchall_maps.cf"
postconf -e "virtual_mailbox_maps = sqlite:/etc/postfix/sqlite_virtual_mailbox_maps.cf, sqlite:/etc/postfix/sqlite_virtual_alias_domain_mailbox_maps.cf"

postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"

postconf -e "smtpd_use_tls = yes"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtpd_tls_security_level = may"

postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
postconf -e "smtpd_milters = inet:127.0.0.1:11332"
postconf -e "non_smtpd_milters = inet:127.0.0.1:11332"
postconf -e "milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}"
postconf -e "milter_protocol = 6"
postconf -e "milter_default_action = accept"
postconf -e "message_size_limit = 102400000"
'''
        mw.execShell(edit_postfix_conf_shell)
        self.write_logs('|-Downloading additional configuration files...')

#         download_sql_conf_shell = '''

# '''.format(download_conf_url=download_url, logfile=self.logfile)
#         mw.execShell(download_sql_conf_shell)

        result = mw.readFile("/etc/postfix/sqlite_virtual_mailbox_maps.cf")
        if not result or not re.search(r"\n*query\s*=\s*", result):
            self.write_logs(
                '|- Read file content {}: Failed'.format("/etc/postfix/sqlite_virtual_mailbox_maps.cf"))
            return mw.returnJson(False, "获取邮局配置失败！")

        restart_service_shell = 'systemctl enable postfix && systemctl restart postfix'
        self.write_logs('|-Restarting postfix service...')
        mw.execShell(restart_service_shell)
        return self.returnData(True, "配置成功！")

    def conf_dovecot(self):
        '''
        安装，配置dovecot服务, dovecot提供收信功能
        :return:
        '''
        self.write_logs('|-Initializing dovecot...')
        self.write_logs('|-Downloading additional configuration files...')
#         download_conf_shell = '''
# wget "{download_conf_url}/mail_sys/dovecot/dovecot-sql.conf.ext" -O /etc/dovecot/dovecot-sql.conf.ext -T 10 >> {logfile} 2>&1
# '''.format(download_conf_url=download_url, logfile=self.logfile)
#         mw.execShell(download_conf_shell)
        result = mw.readFile("/etc/dovecot/dovecot.conf")
        if not result or not re.search(r"\n*protocol\s+imap", result):
            self.write_logs(
                '|-Read file content {}: Failed'.format("/etc/dovecot/dovecot.conf"))
            return False

        # 关闭protocols注释
        dovecot_conf = mw.readFile("/etc/dovecot/dovecot.conf")
        dovecot_conf = re.sub(r"#protocols\s*=\s*imap\s*pop3\s*lmtp",
                              "protocols = imap pop3 lmtp", dovecot_conf)
        mw.writeFile("/etc/dovecot/dovecot.conf", dovecot_conf)

        if not os.path.exists('/etc/pki/dovecot/private/dovecot.pem') or not os.path.exists(
                '/etc/pki/dovecot/certs/dovecot.pem'):
            self.create_ssl()
        restart_service_shell = '''
chown -R vmail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot

systemctl enable dovecot
systemctl restart  dovecot
'''
        self.write_logs('|-Restarting dovecot...')
        mw.execShell(restart_service_shell)
        return True

    def setup_rspamd(self):
            # 修改postfix配置
        self.write_logs('|-Initializing rspamd...')
        edit_postfix_conf_shell = '''
postconf -e "smtpd_milters = inet:127.0.0.1:11332"
postconf -e "non_smtpd_milters = inet:127.0.0.1:11332"
postconf -e "milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}"
postconf -e "milter_protocol = 6"
postconf -e "milter_default_action = accept"
'''
        mw.execShell(edit_postfix_conf_shell)
        self.write_logs('|-Downloading additional configuration files...')
        get_rspamd_conf_shell = """
mkdir -p /usr/lib/dovecot/sieve
wget -O /etc/rspamd/worker-normal.inc {download_conf_url}/mail_sys/rspamd/worker-normal.inc -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/worker-fuzzy.inc {download_conf_url}/mail_sys/rspamd/worker-fuzzy.inc -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/statistic.conf {download_conf_url}/mail_sys/rspamd/statistic.conf -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/local.d/worker-controller.inc {download_conf_url}/mail_sys/rspamd/worker-controller.inc -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/worker-proxy.inc {download_conf_url}/mail_sys/rspamd/worker-proxy.inc -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/local.d/dkim_signing.conf {download_conf_url}/mail_sys/rspamd/modules.d/dkim_signing_bt.conf -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/local.d/milter_headers.conf {download_conf_url}/mail_sys/rspamd/modules.d/milter_headers_bt.conf -T 5 >> {logfile} 2>&1
wget -O /etc/rspamd/local.d/redis.conf {download_conf_url}/mail_sys/rspamd/modules.d/redis_bt.conf -T 5 >> {logfile} 2>&1

wget -O /usr/lib/dovecot/sieve/report-ham.sieve {download_conf_url}/mail_sys/dovecot/lib/report-ham.sieve -T 5 >> {logfile} 2>&1
wget -O /usr/lib/dovecot/sieve/report-spam.sieve {download_conf_url}/mail_sys/dovecot/lib/report-spam.sieve -T 5 >> {logfile} 2>&1
wget -O /usr/lib/dovecot/sieve/spam-to-folder.sieve {download_conf_url}/mail_sys/dovecot/lib/spam-to-folder.sieve -T 5 >> {logfile} 2>&1
wget -O /usr/lib/dovecot/sieve/sa-learn-spam.sh {download_conf_url}/mail_sys/dovecot/lib/sa-learn-spam.sh -T 5 >> {logfile} 2>&1
wget -O /usr/lib/dovecot/sieve/sa-learn-ham.sh {download_conf_url}/mail_sys/dovecot/lib/sa-learn-ham.sh -T 5 >> {logfile} 2>&1
sievec /usr/lib/dovecot/sieve/spam-to-folder.sieve
sievec /usr/lib/dovecot/sieve/report-spam.sieve
sievec /usr/lib/dovecot/sieve/report-ham.sieve
chmod +x /usr/lib/dovecot/sieve/sa-learn-spam.sh
chmod +x /usr/lib/dovecot/sieve/sa-learn-ham.sh
""".format(download_conf_url=download_url, logfile=self.logfile)
        mw.execShell(get_rspamd_conf_shell)
        # 生成web端管理密码
        self.write_logs('|-Generating rspamd management password...')
        passwd = mw.getRandomString(8)
        passwd_en = mw.execShell(
            'rspamadm pw -p "{}"'.format(passwd))[0].strip('\n')
        mw.writeFile('/etc/rspamd/passwd', passwd)
        worker_controller_path = '/etc/rspamd/local.d/worker-controller.inc'
        worker_controller = mw.readFile(worker_controller_path)
        if worker_controller:
            if 'BT_PASSWORD' in worker_controller:
                worker_controller = worker_controller.replace('password = "MW_PASSWORD";',
                                                              'password = "{}";'.format(passwd_en))
                mw.writeFile(worker_controller_path, worker_controller)
        # 设置rspamd redis密码
        rspamd_redis_path = '/etc/rspamd/local.d/redis.conf'
        rspamd_redis = mw.readFile(rspamd_redis_path)
        if rspamd_redis:
            if 'BT_REDIS_PASSWD' in rspamd_redis:
                rspamd_redis = rspamd_redis.replace('password = "MW_REDIS_PASSWD";',
                                                    'password = "{}";'.format(self.get_redis_passwd()))
                mw.writeFile(rspamd_redis_path, rspamd_redis)
        self.write_logs('|-Restarting rspamd...')
        mw.execShell('systemctl restart rspamd postfix dovecot')
        return True

        # 自签证书
    def create_ssl(self, get=None):
        import OpenSSL
        mw.backFile('/etc/pki/dovecot/certs/dovecot.pem')
        mw.backFile('/etc/pki/dovecot/private/dovecot.pem')
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        cert = OpenSSL.crypto.X509()
        cert.set_serial_number(0)
        cert.get_subject().CN = mw.getLocalIp()
        cert.set_issuer(cert.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_pubkey(key)
        cert.sign(key, 'md5')
        cert_ca = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        private_key = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key)
        if not isinstance(cert_ca, str):
            cert_ca = cert_ca.decode()
        if not isinstance(private_key, str):
            private_key = private_key.decode()
        if len(cert_ca) > 100 and len(private_key) > 100:
            mw.writeFile('/etc/pki/dovecot/certs/dovecot.pem', cert_ca)
            mw.writeFile('/etc/pki/dovecot/private/dovecot.pem', private_key)
            return True
        else:
            mw.restoreFile(
                '/etc/pki/dovecot/certs/dovecot.pem')
            mw.restoreFile('/etc/pki/dovecot/private/dovecot.pem')
            return False

    def get_redis_passwd(self):
        redis_path = '/www/server/redis/redis.conf'
        redis_conf = mw.readFile(redis_path)
        passwd = re.search('\n\s*requirepass\s+(.*)', redis_conf)
        if passwd:
            return passwd.groups(0)[0]
        return False

    def check_hostname(self):
        import socket
        rep = '^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$'
        hostname = socket.gethostname()
        if re.search(rep, hostname):
            return mw.returnData(True, 'success')
        return mw.returnData(False, '你的主机名 ({}) 不合规定, 需要是完整域名'
                             '你可以通过以下命令修复你的主机名 '
                             '在ssh终端执行 \'hostnamectl set-hostname --static mail.example.com\''.format(hostname))

    def check_postfix_ver(self):
        postfix_version = mw.execShell(
            "postconf mail_version | awk -F '=' '{print $2}'")[0].strip()
        if postfix_version.startswith('3'):
            return mw.returnData(True, postfix_version)
        else:
            return mw.returnData(False, "当前版本不支持或Postfix没有安装成功：{}".format(postfix_version))

    def check_redis_passwd(self, redis_install):
        redis_conf = mw.readFile(mw.getServerDir() + '/redis/redis.conf')
        if redis_install['status']:
            if re.search('\n\s*requirepass', redis_conf):
                return mw.returnData(True, "Redis已经设置密码")
        return mw.returnData(False, "请到Redis管理器设置密码！")

    def check_sqlite(self):
        if not mw.execShell('postconf -m | grep sqlite')[0].strip():
            return self.returnData(False, "Postfix不支持Sqlite")
        return mw.returnData(True, "Postfix已支持Sqlite")


if __name__ == "__main__":
    '''
    cd /www/server/mdserver-web && python3 /www/server/mdserver-web/plugins/mail/mail_init.py
    '''

    '''


    && bash install.sh install 1.0


    cd /www/server/mdserver-web/plugins && \
    rm -rf mail && git clone https://github.com/mw-plugin/mail && cd mail && rm -rf .git && \
    cd /www/server/mdserver-web/plugins/mail  && \
    cd /www/server/mdserver-web && python3 /www/server/mdserver-web/plugins/mail/mail_init.py
    '''
    t = mail_init().setup_mail()
    print(t)
