# coding:utf-8

import sys
import io
import os
import time
import re
import socket

from datetime import datetime

sys.path.append(os.getcwd() + "/class/core")

import mw


try:
    import dns.resolver
except:
    if os.path.exists(os.getcwd() + '/bin'):
        mw.execShell(os.getcwd() + '/bin/pip install dnspython')
    else:
        mw.execShell('pip install dnspython')
    import dns.resolver


app_debug = False
if mw.isAppleSystem():
    app_debug = True

import mail_init as mi


class App:
    __setupPath = '/www/server/mail'
    __session_conf = __setupPath + '/session.json'
    postfix_main_cf = "/etc/postfix/main.cf"

    _check_time = 86400

    def __init__(self):
        self.__setupPath = self.getServerDir()
        self._session = self.__get_session()

    def getArgs(self):
        args = sys.argv[3:]
        tmp = {}
        args_len = len(args)

        if args_len == 1:
            t = args[0].strip('{').strip('}')
            t = t.split(':')
            tmp[t[0]] = t[1]
        elif args_len > 1:
            for i in range(len(args)):
                t = args[i].split(':')
                tmp[t[0]] = t[1]

        return tmp

    def check_mail(self):
        args = self.getArgs()

        if os.path.exists('/etc/postfix/sqlite_virtual_domains_maps.cf'):
            mw.execShell(
                '/sbin/postconf -e "message_size_limit = 102400000"')
            # 修改postfix mydestination配置项
            result = mw.readFile(self.postfix_main_cf)
            if not result:
                return mw.returnJson(False, "找不到postfix配置文件")
            result = re.search(r"\n*mydestination\s*=(.+)", result)
            if not result:
                return mw.returnJson(False, "postfix配置文件中找不到mydestination配置项")
            result = result.group(1)
            if 'localhost' in result or '$myhostname' in result or '$mydomain' in result:
                mw.execShell(
                    '/sbin/postconf -e "mydestination =" && systemctl restart postfix')
            # 修改dovecot配置
            dovecot_conf = mw.readFile("/etc/dovecot/dovecot.conf")
            if not dovecot_conf or not re.search(r"\n*protocol\s*imap", dovecot_conf):
                return mw.returnJson(False, '配置dovecot失败')
            # 修复之前版本未安装opendkim的问题
            # if not (os.path.exists("/usr/sbin/opendkim") and os.path.exists("/etc/opendkim.conf") and os.path.exists("/etc/opendkim")):
            #     if not self.setup_opendkim():
            # return mw.returnMsg(False, 'Failed to configure opendkim 1')

            return mw.returnJson(True, '邮局系统已经存在，重装之前请先卸载!')
        else:
            return mw.returnJson(False, '之前没有安装过邮局系统，请放心安装!')

    def __get_session(self):
        session = mw.readFile(self.__session_conf)
        if session:
            session = json.loads(session)
        else:
            session = {}
        return session

    def __get_dkim_value(self, domain):
        '''
        解析/etc/opendkim/keys/domain/default.txt得到域名要设置的dkim记录值
        :param domain:
        :return:
        '''
        if not os.path.exists("/www/server/dkim/{}".format(domain)):
            os.makedirs("/www/server/dkim/{}".format(domain))
        rspamd_pub_file = '/www/server/dkim/{}/default.pub'.format(domain)
        opendkim_pub_file = '/etc/opendkim/keys/{0}/default.txt'.format(domain)
        if os.path.exists(opendkim_pub_file) and not os.path.exists(rspamd_pub_file):
            opendkim_pub = mw.readFile(opendkim_pub_file)
            mw.writeFile(rspamd_pub_file, opendkim_pub)

            rspamd_pri_file = '/www/server/dkim/{}/default.private'.format(
                domain)
            opendkim_pri_file = '/etc/opendkim/keys/{}/default.private'.format(
                domain)
            opendkim_pri = mw.readFile(opendkim_pri_file)
            mw.writeFile(rspamd_pri_file, opendkim_pri)

        if not os.path.exists(rspamd_pub_file):
            return ''
        file_body = mw.readFile(rspamd_pub_file).replace(
            ' ', '').replace('\n', '').split('"')
        value = file_body[1] + file_body[3]
        return value

    def __check_mx(self, domain):
        '''
        检测域名是否有mx记录
        :param domain:
        :return:
        '''
        a_record = self.M('domain').where(
            'domain=?', (domain,)).field('a_record').find()['a_record']
        key = '{0}:{1}'.format(domain, 'MX')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                try:
                    result = resolver.resolve(domain, 'MX')
                except:
                    result = resolver.query(domain, 'MX')

                value = str(result[0].exchange).strip('.')
            if not a_record:
                a_record = value
                self.M('domain').where('domain=?', (domain,)).save(
                    'a_record', (a_record,))
            if value == a_record:
                self._session[key] = {"status": 1,
                                      "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            # print(mw.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query names exist:{}".format(domain)}
            return False

    def __check_spf(self, domain):
        '''
        检测域名是否有spf记录
        :param domain:
        :return:
        '''
        key = '{0}:{1}'.format(domain, 'TXT')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                # try:
                result = resolver.resolve(domain, 'TXT')
                # except:
                #     result = resolver.query(domain, 'TXT')

                for i in result.response.answer:
                    for j in i.items:
                        value += str(j).strip()
            if 'v=spf1' in value.lower():
                self._session[key] = {"status": 1,
                                      "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            # print(mw.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query spf exist:{}".format(domain)}
            return False

    def __check_dkim(self, domain):
        '''
        检测域名是否有dkim记录
        :param domain:
        :return:
        '''
        origin_domain = domain
        domain = 'default._domainkey.{0}'.format(domain)
        key = '{0}:{1}'.format(domain, 'TXT')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                result = resolver.resolve(domain, 'TXT')
                for i in result.response.answer:
                    for j in i.items:
                        value += str(j).strip()
            new_v = self._get_dkim_value(origin_domain)
            if new_v and new_v in value:
                self._session[key] = {"status": 1,
                                      "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            # print(mw.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query names exist:{}".format(domain)}
            return False

    def __check_dmarc(self, domain):
        '''
        检测域名是否有dmarc记录
        :param domain:
        :return:
        '''
        domain = '_dmarc.{0}'.format(domain)
        key = '{0}:{1}'.format(domain, 'TXT')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1

                result = resolver.resolve(domain, 'TXT')

                for i in result.response.answer:
                    for j in i.items:
                        value += str(j).strip()
            if 'v=dmarc1' in value.lower():
                self._session[key] = {"status": 1,
                                      "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            # print(mw.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query names exist:{}".format(domain)}
            return False

    def __gevent_jobs(self, domain, a_record):
        from gevent import monkey
        # monkey.patch_all()
        import gevent
        gevent.joinall([
            gevent.spawn(self.__check_mx, domain),
            gevent.spawn(self.__check_spf, domain),
            gevent.spawn(self.__check_dkim, domain),
            gevent.spawn(self.__check_dmarc, domain),
            gevent.spawn(self.__check_a, a_record),
        ])

        return True

    def getInitDFile(self):
        if app_debug:
            return '/tmp/' + getPluginName()
        return '/etc/init.d/' + getPluginName()

    def getPluginName(self):
        return 'mail'

    def getPluginDir(self):
        return mw.getPluginDir() + '/' + self.getPluginName()

    def getServerDir(self):
        return mw.getServerDir() + '/' + self.getPluginName()

    def M(self, dbname='domain'):
        file = self.getServerDir() + '/postfixadmin.db'
        name = 'mail'
        if not os.path.exists(file):
            conn = mw.M(dbname).dbPos(self.getServerDir(), name)
            csql = mw.readFile(self.getPluginDir() + '/conf/postfixadmin.sql')
            csql_list = csql.split(';')
            for index in range(len(csql_list)):
                conn.execute(csql_list[index], ())
        else:
            # 现有run
            # conn = mw.M(dbname).dbPos(getServerDir(), name)
            # csql = mw.readFile(getPluginDir() + '/conf/mysql.sql')
            # csql_list = csql.split(';')
            # for index in range(len(csql_list)):
            #     conn.execute(csql_list[index], ())
            conn = mw.M(dbname).dbPos(self.getServerDir(), name)
        return conn

    def status(self):
        return 'start'

    def get_domains(self):
        args = self.getArgs()

        p = int(args['p']) if 'p' in args else 1
        rows = int(args['size']) if 'size' in args else 10
        callback = args['callback'] if 'callback' in args else ''
        count = self.M('domain').count()

        data = {}
        # 获取分页数据
        _page = {}
        _page['count'] = count
        _page['p'] = p
        _page['row'] = rows
        _page['tojs'] = callback
        data['page'] = mw.getPage(_page)

        start_pos = (_page['p'] - 1) * _page['row']

        data_list = self.M('domain').order('created desc').limit(
            str(start_pos) + ',' + str(_page['row'])).field('domain,a_record,created,active').select()

        for item in data_list:

            try:
                if os.path.exists("/usr/bin/rspamd"):
                    self.set_rspamd_dkim_key(item['domain'])
                if os.path.exists("/usr/sbin/opendkim"):
                    self._gen_dkim_key(item['domain'])
            except Exception as e:
                return mw.returnJson(False, '请检查rspamd服务状态是否正常' + str(e))

            if not os.path.exists(self.__session_conf):
                self.__gevent_jobs(item['domain'], item['a_record'])
                item = self.get_record_in_cache(item)
            else:
                item = self.get_record_in_cache(item)

            item['mx_record'] = item['a_record']

            item['dmarc_value'] = 'v=DMARC1;p=quarantine;rua=mailto:admin@{0}'.format(item[
                                                                                      'domain'])
            # item['ssl_status'] = self._get_multiple_certificate_domain_status(item[
            #                                                                   'domain'])
            item['catch_all'] = self._get_catchall_status(item['domain'])
            item['ssl_info'] = self.get_ssl_info(item['domain'])

        mw.writeFile(self.__session_conf, json.dumps(self._session))

        return mw.returnJson(True, 'ok', {'data': data_list, 'page': data['page']})

    def _get_catchall_status(self, domain):
        """
            @name 获取某个域名下catchall是否开启
            @param domain 需要捕获的域名
        """
        domain = '@' + domain.strip()
        conf = mw.readFile(self.postfix_main_cf)
        reg = r'virtual_alias_maps\s*=\s*sqlite:/etc/postfix/rule.cf'
        if not conf:
            return False
        catchall_exist = re.search(reg, conf)
        if not catchall_exist:
            return False
        result = self.M('alias').where('address=?', domain).select()
        if result:
            return True
        return False

    def _get_multiple_certificate_domain_status(self, domain):
        path = '/www/server/mail/cert/{}/fullchain.pem'.format(
            domain)
        ssl_conf = mw.readFile('/etc/postfix/vmail_ssl.map')
        if not os.path.exists(path):
            return False
        if not ssl_conf or domain not in ssl_conf:
            return False
        return True

    def get_record_in_cache(self, item):
        try:
            item['mx_status'] = self._session['{0}:{1}'.format(item['domain'], 'MX')][
                "status"]
            item['spf_status'] = self._session['{0}:{1}'.format(item['domain'], 'TXT')][
                "status"]
            item['dkim_status'] = self._session['{0}:{1}'.format(
                "default._domainkey." + item['domain'], 'TXT')]["status"]
            item['dmarc_status'] = self._session['{0}:{1}'.format(
                "_dmarc." + item['domain'], 'TXT')]["status"]
            item['a_status'] = self._session['{0}:{1}'.format(item['a_record'], 'A')][
                "status"]
            print(item)
        except:
            self.__gevent_jobs(item['domain'], item['a_record'])
            # self.get_record_in_cache(item)
        return item

    def _build_dkim_sign_content(self, domain, dkim_path):
        dkim_signing_conf = """#{domain}_DKIM_BEGIN
  {domain} {{
    selectors [
     {{
       path: "{dkim_path}/default.private";
       selector: "default"
     }}
   ]
 }}
#{domain}_DKIM_END
""".format(domain=domain, dkim_path=dkim_path)
        return dkim_signing_conf

    def check_domain_in_rspamd_dkim_conf(self, domain):
        sign_path = '/etc/rspamd/local.d/dkim_signing.conf'
        sign_conf = mw.readFile(sign_path)
        if not sign_conf:
            mw.writeFile(
                sign_conf, "#MW_DOMAIN_DKIM_BEGIN\n#MW_DOMAIN_DKIM_END")
            sign_conf = """
domain {
#MW_DOMAIN_DKIM_BEGIN
#MW_DOMAIN_DKIM_END
}
            """
        rep = '#MW_DOMAIN_DKIM_BEGIN((.|\n)+)#MW_DOMAIN_DKIM_END'
        sign_domain = re.search(rep, sign_conf)
        if not sign_domain:
            return False
        if domain in sign_domain.group(1):
            return False
        return {"rep": rep, "sign_domain": sign_domain, 'sign_conf': sign_conf, 'sign_path': sign_path}

    def _dkim_sign(self, domain, dkim_sign_content):
        res = self.check_domain_in_rspamd_dkim_conf(domain)
        if not res:
            return False
        sign_domain = '#MW_DOMAIN_DKIM_BEGIN{}#MW_DOMAIN_DKIM_END'.format(
            res['sign_domain'].group(1) + dkim_sign_content)
        sign_conf = re.sub(res['rep'], sign_domain, res['sign_conf'])
        mw.writeFile(res['sign_path'], sign_conf)
        return True

    def set_rspamd_dkim_key(self, domain):
        dkim_path = '/www/server/mail/dkim/{}'.format(domain)
        if not dkim_path:
            os.makedirs(dkim_path)
        if not os.path.exists('{}/default.pub'.format(dkim_path)):
            dkim_shell = """
    mkdir -p {dkim_path}
    rspamadm dkim_keygen -s 'default' -b 1024 -d {domain} -k /www/server/mail/dkim/{domain}/default.private > /www/server/mail/dkim/{domain}/default.pub
    chmod 755 -R /www/server/mail/dkim/{domain}
    """.format(dkim_path=dkim_path, domain=domain)
            mw.execShell(dkim_shell)
        dkim_sign_content = self._build_dkim_sign_content(domain, dkim_path)
        if self._dkim_sign(domain, dkim_sign_content):
            mw.execShell('systemctl reload rspamd')
        return True

    def runLog(self):
        path = '/var/log/maillog'
        # if "ubuntu" in:
        #     path = '/var/log/mail.log'
        return path

    def add_domain(self):
        args = self.getArgs()

        if 'domain' not in args:
            return mw.returnJson(False, '请传入域名')

        domain = args['domain']
        a_record = args['a_record']

        if not a_record.endswith(domain):
            return mw.returnJson(False, 'A记录 [{}] 不属于该域名'.format(a_record))

        if not mw.isDebugMode():
            check = self.__check_a(a_record)
            if not check[0]:
                return mw.returnJson(False, 'A记录解析失败<br>域名：{}<br>IP：{}'.format(a_record, check[1]['value']))

        if self.M('domain').where("domain=?", (domain,)).count() > 0:
            return mw.returnJson(False, '该域名已存在')

        cur_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            self.M('domain').add('domain,a_record,created',
                                 (domain, a_record, cur_time))
        except:
            return mw.returnJson(False, '邮局没有初始化成功！<br>'
                                 '请尝试重新初始化,<br>'
                                 '如果以下端口没访问将无法初始化 <br>port 25 [outbound direction]<br> '
                                 '你可以尝试执行以下命令测试端口是否开启:<br><br> [ telnet gmail-smtp-in.l.google.com 25 ] <br> ')

        # 在虚拟用户家目录创建对应域名的目录
        if os.path.exists('/www/vmail'):
            if not os.path.exists('/www/vmail/{0}'.format(domain)):
                os.makedirs('/www/vmail/{0}'.format(domain))
            mw.execShell('chown -R vmail:mail /www/vmail/{0}'.format(domain))
        return mw.returnJson(False, 'OK')

    def __check_a(self, hostname):
        key = '{0}:{1}'.format(hostname, 'A')
        now = int(time.time())

        value = ""
        error_ip = ""

        ipaddress = mw.getLocalIp()
        if not ipaddress:
            return False, {"status": 0, "v_time": now, "value": error_ip}

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1
            try:
                result = resolver.resolve(hostname, 'A')
            except:
                result = resolver.query(hostname, 'A')

            for i in result.response.answer:
                for j in i.items:
                    error_ip = j
                    if str(j).strip() in ipaddress:
                        value = str(j).strip()

            if value:
                return True, {"status": 1, "v_time": now, "value": value}
            return False, {"status": 0, "v_time": now, "value": error_ip}
        except Exception as e:
            raise e
        return False, {"status": 0, "v_time": now, "value": error_ip}

    def flush_domain_record(self):
        '''
        手动刷新域名记录
        domain all/specify.com
        :param args:
        :return:
        '''
        args = self.getArgs()

        if args['domain'] == 'all':
            data_list = self.M('domain').order('created desc').field(
                'domain,a_record,created,active').select()
            for item in data_list:
                # try:
                #     if os.path.exists("/usr/bin/rspamd"):
                #         self.set_rspamd_dkim_key(item['domain'])
                #     if os.path.exists("/usr/sbin/opendkim"):
                #         self._gen_dkim_key(item['domain'])
                # except:
                #     return mw.returnJson(False, '请检查Rspamd服务器是否已经启动！')
                self.__gevent_jobs(item['domain'], item['a_record'])
        # else:
        #     try:
        #         if os.path.exists("/usr/bin/rspamd"):
        #             self.set_rspamd_dkim_key(args.domain)
        #         if os.path.exists("/usr/sbin/opendkim"):
        #             self._gen_dkim_key(args.domain)
        #     except:
        #         return mw.returnJson(False, '请检查Rspamd服务器是否已经启动！')
        #     self._gevent_jobs(args['domain'], None)  # 不需要验证A记录

        # mw.writeFile(self._session_conf, json.dumps(self._session))

        return mw.returnJson(True, '刷新成功！')

    def check_mail_env(self):
        data = mi.mail_init().check_env()
        return mw.returnJson(True, 'ok', data)

    def change_hostname(self):
        '''
        mac
        sudo scutil --set HostName mac_hostname.vm
        '''
        args = self.getArgs()
        hostname = args['hostname']
        rep_domain = "^(?=^.{3,255}$)[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62}(\.[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62})+$"
        if not re.search(rep_domain, hostname):
            return mw.returnJson(False, "请输入完整域名，例如 mail.bt.com),")
        mw.execShell('hostnamectl set-hostname --static {}'.format(hostname))
        h = socket.gethostname()
        if h == hostname:
            return mw.returnJson(True, "设置成功！")
        return mw.returnJson(False, "设置失败！")

        # 安装并配置postfix, dovecot
    def setup_mail(self):
        '''
        安装邮局系统主函数
        :param args:
        :return:
        '''
        return mi.mail_init().setup_mail()


if __name__ == "__main__":
    func = sys.argv[1]
    classApp = App()
    try:
        data = eval("classApp." + func + "()")
        print(data)
    except Exception as e:
        print('error:' + str(e))
