# mail
简单邮件服务器



# 快捷安装
```
cd /www/server/mdserver-web/plugins && rm -rf mail && git clone https://github.com/mw-plugin/mail && cd mail && rm -rf .git && cd /www/server/mdserver-web/plugins/mail && bash install.sh install 1.0 && python3 /www/server/mdserver-web/plugins/mail/index.py get_mailboxs 1.0 {"domain":"biqu.xyz","p":1,"size":10}
```


python3 /www/server/mdserver-web/plugins/mail/index.py get_domains 1.0 {"p":1,"size":10}
python3 /www/server/mdserver-web/plugins/mail/index.py get_mailboxs 1.0 {"domain":"biqu.xyz","p":1,"size":10}

# Gitee快捷安装
```
cd /www/server/mdserver-web/plugins && rm -rf mail && git clone https://gitee.com/mw-plugin/mail && cd mail && rm -rf .git && cd /www/server/mdserver-web/plugins/mail && bash install.sh install 1.0 && python3 /www/server/mdserver-web/plugins/mail/index.py get_mailboxs 1.0 {"domain":"biqu.xyz","p":1,"size":10}
```