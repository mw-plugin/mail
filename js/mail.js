var mail  = {
    plugin_name: 'mail',
    post_env_list:['HostName','Postfix-Version','Postfix-install','Sqlite-support','Dovecot-install','Redis-install','Redis-Passwd','Rspamd-install','SElinux'],
    post_env_text:['主机名','Postfix版本','Postfix安装','Sqlite支持','Dovecot安装','Redis安装','Redis密码','Rspamd','SElinux'],
    init: function () {
        var _this = this;

        this.event();

        $('.layui-layer-page').hide();

        setTimeout(function () {
            var win = $(window),
                layer = $('.layui-layer-page');
            layer.show();
            layer.css({
                    'width':'1080px',
                    'top':((win.height()-layer.height())/2)+'px',
                    'left':((win.width()-1000)/2)+'px',
                    'zIndex':'999'
            });
            $('.layui-layer-shade').css('zIndex', '998');
        }, 200);


        _this.check_mail({
            tips: '正在检查邮局服务是否正常,请稍后....',
            hostname: ''
        }, function (res) {
            if (res.status == false && res.msg == '之前没有安装过邮局系统，请放心安装!') {
                layer.confirm('当前未设置邮局服务，是否现在设置?', {
                    icon: 0,
                    title: '邮局初始化',
                    btn: ['设置', '取消'], //按钮
                    cancel: function () {
                        layer.closeAll();
                    }
                }, function (index) {
                    _this.check_post_env('setup_mail');
                }, function () {
                    layer.closeAll();
                });
            } else {
                _this.create_domain_list();
                // $('.tasklist .tab-nav span:first').click(); // 初始化
                // _this.loadScript('/static/ckeditor/ckeditor.js', function () {
                //     CKEDITOR.replace('editor1', {
                //         customConfig: '/static/ckeditor/config.js?v1.0'
                //     })
                // });
            }
        });

        // _this.create_domain_list();
    },
    event: function () {
        var _this = this;

        $('.bt-w-main .bt-w-menu p').click(function () {
            var index = $(this).index();
            $(this).addClass('on').siblings().removeClass('on');
            $('.soft-man-con .task_block').eq(index).show().siblings().hide();

            switch (index) {
                case 0:
                    _this.create_domain_list();
                    // _this.get_mailSSL_status(function (res) {
                    //     $('#certificateSSL').prop("checked", res);
                    // });
                    break;
            }
        });


        $('#domain_list').on('click', '.edit_ground_domain', function () {
            var domain = $(this).attr('data-domain');
            var index = $(this).attr('data-index');
            var hostname = $(this).attr('data-hostname');
            if (_this.domain_list[index].mx_status == 0 && _this.domain_list[index].mx_status == 0) {
                layer.msg('当前域名未设置或暂未生效或记录多于一条', {
                    icon: 0
                })
                return false;
            }

            layer.open({
                type: 1,
                title: '[' + domain + ']用户管理',
                area: ['600px', '500px'],
                closeBtn: 1,
                content: '<div class="pd15 user_info">\
                            <button class="btn btn-sm btn-success mb15" style="margin-right:10px;" onclick="mail.edit_mailboxs_view(true)">添加用户</button>\
                            <div class="member_table divtable">\
                                <table class="table table-hover">\
                                    <thead><tr><th>邮箱</th><th>姓名</th><th>邮箱容量</th><th>类型</th><th>状态</th><th style="text-align: right;">操作</th></tr></thead>\
                                    <tbody id="mailboxs_list"></tbody>\
                                </table>\
                                <div class="page" id="mailboxs_page"></div>\
                            </div>\
                            <ul class="help-info-text c7 mlr20">\
                                <li>注意事项:当前邮件服务器支持IMAP/POP3/SMTP/HTTP协议&nbsp;<a href="javascript:;" class="btlink open_btlink_down">下载HTTP-API文档</a>&nbsp;</li>\
                                <li>POP服务【服务地址：<b>&nbsp;' + hostname + '&nbsp;</b>、端口：<b>&nbsp;110&nbsp;</b>】</li>\
                                <li>IMAP服务【服务地址：<b>&nbsp;' + hostname + '&nbsp;</b>、端口：<b>&nbsp;143&nbsp;</b>】</li>\
                                <li>SMTP服务【服务地址：<b>&nbsp;' + hostname + '&nbsp;</b>、端口：<b>&nbsp;25&nbsp;</b>】</li>\
                            </ul>\
                        </div>',
                success: function () {
                    $('.open_btlink_down').click(function () {
                        window.open('/download?filename=' + encodeURIComponent('/www/server/mdserver-web/plugins/mail/static/api.zip'));
                    });

                    _this.create_mailboxs_list({
                        domain: domain
                    });
                    $('#mailboxs_list').on('click', '.open-switch-active', function () {
                        var checked = $(this).prop('checked');
                        var index = $(this).attr('data-index');
                        var _form = _this.mailboxs_list[index];
                        var quota = _form.quota / 1024 / 1024;
                        var unit = ' MB';
                        if(quota > 1024) {
                            quota = quota / 1024;
                            unit = ' GB'
                        }
                        _this.updatae_mailboxs({
                            quota: quota + unit,
                            username: _form.username,
                            password: _form.password,
                            quote: _form.quote,
                            full_name: _form.full_name,
                            active: checked ? 1 : 0,
                            is_admin: _form.is_admin
                        }, function (res) {
                            layer.msg(res.msg, {icon: 1});
                        });
                    });
                    $('#mailboxs_list').on('click', '.edit_mailboxs', function () {
                        var _index = $(this).attr('data-index');
                        var _form = _this.mailboxs_list[_index];
                        _this.edit_mailboxs_view(false, _form);
                    });
                    $('#mailboxs_list').on('click', '.del_mailboxs', function () {
                        var username = $(this).attr('data-username');
                        layer.confirm('是否删除【' + username + '】成员', {icon: 0,closeBtn: 2,title: '删除成员'}, function (index) {
                            _this.del_mailboxs({username: username}, function (res) {
                                _this.create_mailboxs_list({
                                    domain: domain
                                }, function () {
                                    layer.msg(res.msg, {icon: 1});
                                });
                            });
                        });
                    });
                }
            });
        });
        

        console.log(_this);
    },

    // 创建邮件用户列表 -方法
    create_mailboxs_list: function (obj, callback) {
        var _this = this;
        this.get_mailboxs_list(obj, function (res) {
            console.log('create_mailboxs_list:',res);

            var _tbody = '';
            var rdata = res.data;
            _this.mailboxs_list = rdata;
            _this._domain_name = obj.domain;
            if (rdata.length > 0) {
                for (var i = 0; i < rdata.length; i++) {
                    var quota_size = (rdata[i].quota / 1024 / 1024 / 1024) < 1 ? (rdata[i].quota /
                        1024 / 1024) + 'MB' : (rdata[i].quota / 1024 / 1024 / 1024) + 'GB';
                    _tbody += '<tr><td>' + rdata[i].username + '</td><td>' + rdata[i].full_name +
                        '</td><td>' + quota_size + '</td><td>' + (!rdata[i].is_admin ? '普通用户' :
                            '管理员') +
                        '</td><td><div class="index-item"><input class="btswitch btswitch-ios open-switch-active" id="is_active_' +
                        i + '" type="checkbox" ' + (rdata[i].active == 1 ? "checked" : "") +
                        ' data-index="' + i + '"><label class="btswitch-btn" for="is_active_' + i +
                        '"></label></div></td><td style="text-align: right;"><a href="javascript:;" class="btlink edit_mailboxs" data-index="' +
                        i +
                        '">编辑</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="javascript:;" class="btlink red del_mailboxs" data-username="' +
                        rdata[i].username + '">删除</a></td></tr>';
                };
            }
            $('#mailboxs_list').html(_tbody);
            $('#mailboxs_page').html(res.page);
            $('#mailboxs_page a').click(function (e) {
                _this.create_mailboxs_list({
                    domain: _this._domain_name,
                    p: $(this).attr('href').split('p=')[1],
                })
                e.stopPropagation();
                e.preventDefault();
            })
            if (callback) callback(res);
        });
    },

    // 编辑添加邮箱用户视图-方法
    edit_domain_view: function (type, obj) {
        var _this = this;
        if (obj == undefined) {
            obj = {
                domain: '',
                company_name: '',
                admin_name: '',
                admin_phone: ''
            }
        }
    
        layer.open({
            type: 1,
            title: type ? '添加邮箱域名' : '编辑邮箱域名',
            area: '500px',
            closeBtn: 1,
            btn: [type ? '提交' : '保存', '取消'],
            content: "<div class='bt-form pd20'>\
                <div class='line'>\
                    <span class='tname'>邮箱域名</span>\
                    <div class='info-r c4'>\
                        <input class='bt-input-text mr5' type='text' name='domain'  " + (!type ? "readonly='readonly'" : "") +
                "    value='" + obj.domain + "' placeholder='请输入域名，例如demo.cn' style='width:320px;' />\
                    </div>\
                </div>\
                <div class='line'>\
                    <span class='tname'>A记录</span>\
                    <div class='info-r c4'>\
                        <input class='bt-input-text mr5' type='text' name='a_record'  " + (!type ? "readonly='readonly'" : "") +
                "    value='" + obj.domain + "' placeholder='请输入A记录,例如:mail.demo.cn' style='width:320px;' />\
                    </div>\
                </div>\
                <div class='line'>\
                    <ul class='help-info-text c7 mlr20' style='margin-top: 0px'>\
                        <li style='color: red;'>当前邮箱域名仅支持一级域名</li>\
                        <li>A记录解析参数[主机记录：mail或其他字符]、[记录值：当前服务器IP]</li>\
                        <li>A记录需要解析当前域名A记录，A记录=主机记录值+当前域名</li>\
                    </ul>\
                </div>\
            </div>",
            yes: function (index, layers) {
                var array = [
                        ['domain', '邮箱域名不能为空！', 'a_record', 'A记录值不能为空!']
                    ],
                    _form = {},
                    tel_reg = /^[1][3,4,5,6,7,8,9][0-9]{9}$/;
                for (var i = 0; i < array.length; i++) {
                    if ($('[name="' + array[i][0] + '"]').val() == '') {
                        layer.msg(array[i][1], {
                            icon: 2
                        });
                        return false;
                    } else if (array[i][0] == 'admin_phone' && !tel_reg.test($('[name="' + array[i]
                            [0] + '"]').val())) {
                        layer.msg('管理手机号码格式错误，请重试！', {
                            icon: 2
                        });
                        return false;
                    }
                    _form[array[i][0]] = $('[name="' + array[i][0] + '"]').val();
                    _form[array[i][2]] = $('[name="' + array[i][2] + '"]').val();
                }
                if (type) {
                    _this.add_domain(_form, function (res) {
                        if (!res.status){
                            layer.msg(res.msg);
                            return;
                        }

                        _this.create_domain_list({
                            page: 1,
                            size: 10
                        }, function (res) {
                            var rdata = res.msg.data,
                                hostname = rdata;
                            for (var i = 0; i < rdata.length; i++) {
                                if (rdata[i].domain == _form['domain']) hostname =
                                    rdata[i]['domain']
                            }
                            layer.close(index);
                        });
                    });
                } else {
                    _form['active'] = obj.active;
                    _this.update_domain(_form, function (res) {
                        _this.create_domain_list({
                            page: 1,
                            size: 10
                        }, function (res) {
                            layer.msg(res.msg, {
                                icon: 1
                            });
                            layer.close(index);
                        });
                    });
                }
            }
        })
    },

    // 添加域名_请求
    add_domain: function (obj, callback) {
        this.send({
            tips: '正在添加域名，请稍候...',
            method: 'add_domain',
            data: {
                domain: obj.domain,
                a_record: obj.a_record,
                company_name: obj.company_name,
                admin_name: obj.admin_name,
                admin_phone: obj.admin_phone
            },
            success: function (res) {
                if (callback) callback(res);
            }
        });
    },
    // 获取域名列表_请求
    get_domain_list: function (obj, callback) {
        this.send({
            tips: '正在获取域名列表,请稍候....',
            method: 'get_domains',
            data: {
                p: obj.page,
                size: obj.size
            },
            success: function (res) {
                if (callback) callback(res);
            }
        })
    },

    flush_domain_record: function(obj,callback){
        var _this = this;
        this.send({
            tips: obj == 'all'?'正在刷新所有域名记录，刷新时间视域名数量而定，请稍后...':'Refresh domain record, please wait...',
            method: 'flush_domain_record',
            data: {
                domain: obj
            },
            success: function (res) {
                console.log(res);
                if(res.status) _this.create_domain_list();
                if (callback) callback(res);
            }
        });
    },

    // 创建域名列表-方法
    create_domain_list: function (obj, callback) {
        if (obj == undefined) obj = {
            page: 1,
            size: 10
        }
        var _this = this;
        this.get_domain_list(obj, function (res) {
            if (!res.status){
                layer.msg(res.msg,{icon:2});
            }

            var _tbody = '';
            var rdata = res.data.data;
            _this.domain_list = rdata;
            if (rdata.length > 0) {
                for (var i = 0; i < rdata.length; i++) {
                    _tbody += '<tr>\
                      <td>' + rdata[i].domain + '</td>\
                      <td>' + (rdata[i].mx_status ?
                        '<div style="color:#20a53a;"><span class="glyphicon glyphicon-ok" style="margin-right: 7px;"></span>已设置</div>' :
                        '<div style="color:red;display: inline-block;"><span class="glyphicon glyphicon-remove" style="margin-right: 7px;"></span><a href="javascript:;" style="color:red" onclick="mail.set_analysis_mail(\'' +
                        rdata[i].dkim_value + '\',\'' + rdata[i].dmarc_value + '\',\'' + rdata[i]
                        .domain + '\',\'' + rdata[i].mx_record + '\')">未设置记录值</a></div>') + '</td>\
                      <td>' + (rdata[i].a_status ?
                        '<div style="color:#20a53a;"><span class="glyphicon glyphicon-ok" style="margin-right: 7px;"></span>已设置</div>' :
                        '<div style="color:red;display: inline-block;"><span class="glyphicon glyphicon-remove" style="margin-right: 7px;"></span><a href="javascript:;" style="color:red" onclick="mail.set_analysis_mail(\'' +
                        rdata[i].dkim_value + '\',\'' + rdata[i].dmarc_value + '\',\'' + rdata[i]
                        .domain + '\',\'' + rdata[i].mx_record + '\')">未设置记录值</a></div>') + '</td>\
                      <td>' + (rdata[i].spf_status ?
                        '<div style="color:#20a53a;"><span class="glyphicon glyphicon-ok" style="margin-right: 7px;"></span>已设置</span></div>' :
                        '<div style="color:red;display: inline-block;"><span class="glyphicon glyphicon-remove" style="margin-right: 7px;"></span><a href="javascript:;" style="color:red" onclick="mail.set_analysis_mail(\'' +
                        rdata[i].dkim_value + '\',\'' + rdata[i].dmarc_value + '\',\'' + rdata[i]
                        .domain + '\',\'' + rdata[i].mx_record + '\')">未设置记录值</a></div>') + '</td>\
                      <td>' + (rdata[i].dkim_status ?
                        '<div style="color:#20a53a;"><span class="glyphicon glyphicon-ok" style="margin-right: 7px;"></span>已设置</span></div>' :
                        '<div style="color:red;display: inline-block;"><span class="glyphicon glyphicon-remove" style="margin-right: 7px;"></span><a href="javascript:;" style="color:red" onclick="mail.set_analysis_mail(\'' +
                        rdata[i].dkim_value + '\',\'' + rdata[i].dmarc_value + '\',\'' + rdata[i]
                        .domain + '\',\'' + rdata[i].mx_record + '\')">未设置记录值</a></div>') + '</td>\
                      <td>' + (rdata[i].dmarc_status ?
                        '<div style="color:#20a53a;"><span class="glyphicon glyphicon-ok" style="margin-right: 7px;"></span>已设置</span></div>' :
                        '<div style="color:red;display: inline-block;"><span class="glyphicon glyphicon-remove" style="margin-right: 7px;"></span><a href="javascript:;" style="color:red" onclick="mail.set_analysis_mail(\'' +
                        rdata[i].dkim_value + '\',\'' + rdata[i].dmarc_value + '\',\'' + rdata[i]
                        .domain + '\',\'' + rdata[i].mx_record + '\')">未设置记录值</a></div>') + '</td>\
                      <td><div><input type="checkbox" id="'+ rdata[i].domain +'" '+(rdata[i].catch_all ? 'checked':'')+' class="btswitch btswitch-ios catch_all"><label for="'+ rdata[i].domain +'" class="btswitch-btn"></label></div></td>\
                         <td><a href="javascript:;" class="btlink add_certificate" data-index='+i+'>'+(rdata[i].ssl_status?('到期时间: '+rdata[i].ssl_info.notAfter):'添加证书')+'</a></td>\
                      <td style="text-align: right;">' + (rdata[i].mx_status ? (
                        '<a href="javascript:;" class="btlink edit_ground_domain" data-hostname="' +
                        rdata[i].mx_record + '" data-domain="' + rdata[i].domain +
                        '" data-index="' + i + '">用户管理</a>') : (
                        '<a href="javascript:;" class="btlink" onclick="mail.set_analysis_mail(\'' +
                        rdata[i].dkim_value + '\',\'' + rdata[i].dmarc_value + '\',\'' + rdata[
                            i].domain + '\',\'' + rdata[i].mx_record + '\')">添加记录值</a>')) + '&nbsp;|&nbsp;\
                          <a href="javascript:;" class="btlink red del_domain" data-domain="' + rdata[i].domain + '">删除</a>\
                      </td>\
                      </tr>';
                };
            }
            $('#domain_list').html(_tbody);
            $('#domain_page').html(res.page);
            $('#domain_page a').click(function (e) {
                _this.create_domain_list({
                    page: $(this).attr('href').split('p=')[1],
                    size: 10,
                })
                e.stopPropagation();
                e.preventDefault();
            })



            $('#flush_domain_record').unbind().on('click',function(e){
                _this.flush_domain_record('all',function(res){
                    layer.msg(res.msg, { icon: res.status ? 1 : 2 });
                });
            })
            $('.add_certificate').unbind().on('click',function(){
                var index = $(this).attr('data-index')
                _this.open_certificate_view(rdata[index].ssl_status, rdata[index].domain, rdata[index].ssl_info.dns, index)
            })
            $('.catch_all').click(function (e) {
                e.preventDefault();
                var _catch = $(this),
                _status = $(this).prop('checked'),
                _html = _status ? '<div style="font-size: 12px;"><span>邮件转寄</span><input class="bt-input-text mr5 catchall" type="text" name="catchall" placeholder="捕获不存在的邮箱，转发到此邮箱" style="width:275px;margin-left: 10px;"></div>' : '确认关闭此功能?',
                loadT = layer.confirm(_html, {title:'CatchAll设置', closeBtn: 2, area: '500'},function(){
                    var _email = _status ? $(".catchall").val() : '',
                    loadS = bt.load();
                    _this.enable_catchall({domain:_catch.attr('id'), email: _email},function(res){
                        loadS.close();
                        if(res.status) _catch.prop('checked', _status);
                        layer.msg(res.msg, { icon: res.status ? 1 : 2 });
                        loadT.close();
                    })
                });
            });
            if (callback) callback(res);
        });
    },

    // 获取邮箱用户列表_请求
    get_mailboxs_list: function (obj, callback) {
        this.send({
            tips: '正在获取用户列表,请稍后...',
            method: 'get_mailboxs',
            data: {
                domain: obj.domain || '',
                p: obj.p || 1,
                size: obj.size || 10
            },
            check: true,
            success: function (res) {
                if (callback) callback(res);
            }
        });
    },

    // 获取邮箱服务是否正常_请求
    check_mail: function (obj, callback) {
        this.send({
            tips: obj.tips,
            method: 'check_mail',
            data: {
                hostname: obj.hostname
            },
            check: true,
            success: function (res) {
                if (callback) callback(res);
            }
        })
    },

    // 获取安装邮局服务
    setup_mail: function (obj, callback) {
        this.send({
            tips: obj.tips,
            method: 'setup_mail',
            data: {
                hostname: obj.hostname
            },
            success: function (res) {
                if (callback) callback(res);
            }
        })
    },

    // 检查邮箱环境
    check_mail_env:function(callback){
        this.send({
            tips: '正在检查邮局环境，请稍候...',
            method: 'check_mail_env',
            success: function (res) {
                if (callback) callback(res);
            }
        })
    },

    //检查邮局环境
    check_post_env:function (name) {
        var _this = this;
        var layerE =  layer.open({
            skin:"",
            type: 1,
            closeBtn:1,
            title:'检查邮局环境',
            area: ['600px','520px'], //宽高
            btn: ['提交','取消','刷新列表'],
            content:'\
            <div class="pd20 mlr20 bt-mail-index" accept-charset="utf-8">\
                <div id="checkPostEnv">\
                    <div class="divtable" style="max-height:auto;">\
                        <table class="table table-hover">\
                            <thead style="position:relative;z-index:1;">\
                                <tr>\
                                    <th><span>环境</span></th>\
                                    <th><span>详情</span></th>\
                                    <th><span>操作</span></th>\
                                </tr>\
                            </thead>\
                            <tbody>\
                            </tbody>\
                        </table>\
                    </div>\
                </div>\
                <ul class="help-info-text c7 mlr20">\
                    <li>如果邮局环境异常，请先排除故障。 请在所有异常修复完成后执行下一步操作</li>\
                </ul>\
            </div>',
            success:function(index){
                _this.create_post_env_table();
            },
            cancel:function(){
                layer.closeAll();
            },
            yes:function(){
                if($('#checkPostEnv').find('.set_mail_key').length > 0){
                    layer.msg('请修复好所有的异常再提交');
                }else{
                    switch (name){
                        case 'setup_mail':
                            _this.setup_mail({tips:'正在初始化邮局...'},function(res){
                                if (res.status){
                                    layer.close(layerE);
                                    showMsg(res.msg,function(){
                                        _this.create_domain_list();
                                    },{icon:1},2000);
                                } else{
                                    layer.msg(res.msg,{icon:2});
                                }
                            });
                            break;
                        case 'change_to_rspamd':
                            _this.change_to_rspamd(function(res){
                                layer.close(layerE)
                                layer.msg(res.msg,{icon:res.status?1:2});
                                _this.create_server_status_table();
                            })
                            break;
                    }
                }
            },
            btn3: function(index, layero){
                _this.create_post_env_table();
                return false;
            },
            btn2: function(index, layero){
                name == 'change_to_rspamd'?layer.close(layerE):layer.closeAll();
            },
           
        })
    },

    // 设置解析邮箱-方法
    set_analysis_mail: function (dkim_value, dmarc_value, domain, hostname) {
        var _this = this;
        layer.open({
            type: 1,
            title: '【' + domain + '】添加记录值',
            area: '750px;',
            closeBtn: 2,
            content: "<div class='bt-body divtable pd20'>\
                <div class='bt_tips'>第一步:添加MX记录</div>\
                <div class='bt_conter'>\
                    <div class='bt_vice_tips'>登录域名服务商，添加记录类型为MX的记录，用于邮箱服务(解析MX记录之前要先解析A记录)</div>\
                    <div class='bt_vice_conter'>\
                        <table class='table table-hover'>\
                            <thead><tr><th>记录类型</th><th>主机记录</th><th>记录值</th><th>MX优先级</th></tr></thead>\
                            <tbody>\
                              <tr><td>MX</td><td>@</td><td>" + hostname + "</td><td>10</td></tr>\
                            </tbody>\
                        </table>\
                    </div>\
                </div>\
                <div class='bt_tips'>第二步:添加TXT记录</div>\
                <div class='bt_conter'>\
                    <div class='bt_vice_tips'>添加记录类型为TXT的记录，用于邮箱反垃圾(请直接复制下列参数)</div>\
                    <div class='bt_vice_conter'>\
                        <table class='table table-hover'>\
                            <thead><tr><th>记录类型</th><th>主机记录</th><th>记录值</th></tr></thead>\
                            <tbody>\
                              <tr><td>TXT</td><td>@</td><td>v=spf1 a mx ~all&nbsp;<a href='javascript:;' class='btlink btn_copy' data-clipboard-text='v=spf1 a mx ~all'>(复制)</a>&nbsp;</td></tr>\
                              <tr><td>TXT</td><td>default._domainkey</td><td><span style='width:150px;word-break:break-all;'>" + dkim_value +
                                "</span>&nbsp;<a href='javascript:;' class='btlink btn_copy' data-clipboard-text='" + dkim_value + "'>(复制)</a>&nbsp;</td></tr>\
                              <tr><td>TXT</td><td>_dmarc</td><td>" + dmarc_value + "&nbsp;<a href='javascript:;' class='btlink btn_copy' data-clipboard-text='" +dmarc_value + "'>(复制)</a>&nbsp;</td></tr>\
                            </tbody>\
                        </table>\
                    </div>\
                </div>\
                <div class='bt_center'><button class='btn btn-success btn-sm btn_set_analysis'>已设置，验证域名解析</button></div>\
            </div>",
            success: function (layers, index) {
                var copyBtn = new ClipboardJS('.btn_copy');
                copyBtn.on("success", function (e) {
                    layer.msg('复制成功！', {
                        icon: 1
                    })
                    e.clearSelection();
                });
                copyBtn.on("error", function (e) {
                    layer.msg('复制失败，请手动复制文本！', {
                        icon: 2
                    })
                });
                $('.btn_set_analysis').click(function () {
                    _this.delete_mx_txt_cache({
                        domain: domain
                    }, function (res) {
                        _this.create_domain_list();
                        layer.close(index);
                    });
                });
            }
        });
    },

    //删除max记录和txt记录-请求
    delete_mx_txt_cache: function (obj, callback) {
        this.send({
            tips: '正在清除MAX记录和TXT记录缓存，请稍候...',
            method: 'delete_mx_txt_cache',
            data: {
                domain: obj.domain
            },
            success: function (res) {
                if (callback) callback(res);
            }
        })
    },

    //创建邮局环境列表
    create_post_env_table:function (callback){
        var _this = this;
        _this.check_mail_env(function(rdata){
            var res = rdata.data;
            $('#checkPostEnv tbody').empty();
            $.each(_this.post_env_list,function(index,item){
                var list = [];
                var noOperList = ['Redis-install', 'Redis-Passwd', 'SElinux'];
                if(res[item].msg && noOperList.includes(item)){
                    $('#checkPostEnv tbody').append($('<tr><td>'+_this.post_env_text[index] +'</td><td title="'+res[item].msg.toString()+'" class="'+(res[item].status?'green':'set_mail_key red')+'">'+(res[item].status?"就绪":(res[item].msg.toString().length>30?res[item].msg.toString().substring(0,30)+'...':res[item].msg.toString()))+'</td><td>无操作</td></tr>'))
                }else{
                    $('#checkPostEnv tbody').append($(`<tr><td>`+_this.post_env_text[index] +`</td><td title="`+res[item].msg+`" class="${(res[item].status?"green":"red")}">${(res[item].status?"就绪":(res[item].msg !=''?(res[item].msg.toString().length>30?res[item].msg.toString().substring(0,30)+'...':res[item].msg.toString()):"异常"))}</td><td>${(res[item].status?"无操作":"<a href='javascript:;' class='btlink set_mail_key' data-keys= "+ item+" >修复</a>")}</td></tr>`))
                }
                $('#checkPostEnv .divtable').removeClass('mtb10');
            });
        });

        $('#checkPostEnv').unbind().on('click','a',function(){
           var key = $(this).attr('data-keys');
           var confirmA = layer.confirm('是否修复邮局环境?', {
               title: '修复邮局环境',
               icon: 3,
               closeBtn:2,
               btn: ['确定', '取消'],
           },function(index, layero){
                _this.repair_mail_env(key);
            });
       })
       if(callback) callback()
    },

    //修复邮局环境
    repair_mail_env: function (key) {
        var _this = this,_key;
        switch(key) {
            case 'Postfix-Version':
            case 'Postfix-install':
            case 'Sqlite-support':
                _key = 'repair_postfix';
                break;
            case 'Rspamd-install':
                _key = 'install_rspamd';
                break;
            case 'Dovecot-install':
                _key = 'repair_dovecot';
                break;
            case 'HostName':
                _key = 'repair_host_name';
                break;
        }
        if (key == 'HostName'){
            this.repair_host_name();
            return;
        }
        
        this.send({
            tips: '正在修复' + key + ',请稍候...',
            method: _key,
            success: function (res) {
                layer.msg(res.msg, { icon: res.status?1:2 });
                _this.create_post_env_table();
            }
        })
    },

    // 修复hostname
    repair_host_name: function () {
        var _this = this;
        layer.open({
            type: 1,
            shift: 5,
            closeBtn: 1,
            shadeClose: false,
            title: '修复【主机名】',
            btn: ['确定', '取消'],
            area: "400px",
            content: '\
            <div class="bt-form pd20">\
                <div class="line">\
                    <span class="tname">域名</span>\
                    <div class="info-r" style="margin-left: 102px;">\
                        <input class="bt-input-text" type="text" name="hostname" style="width: 190px" />\
                    </div>\
                </div>\
                <ul class="help-info-text c7">\
                    <li>请输入你的完整域名，如：mail.mw.cn</li>\
                </ul>\
            </div>',
            success: function ($layer, index) {
            },
            yes: function(index){
                var hostname = $('input[name="hostname"]').val().trim();
                if (hostname === '') {
                    layer.msg('请输入你的完整域名', { icon: 2, closeBtn: true });
                    return
                }
                _this.change_hostname({
                    hostname: hostname,
                }, function (res) {
                    layer.close(index);
                    _this.create_post_env_table();
                    layer.msg(res.msg, { icon: res.status ? 1 : 5 });
                });
            }
        });
    },
    
    // 一键修复主机名
    change_hostname: function(data, callback){
        this.send({
            tips: '正在获取修复主机名, 请稍候...',
            method: 'change_hostname',
            data: data,
            success: function (res) {
                if (callback) callback(res);
            }
        });
    },
       
    str2Obj:function(str){
        var data = {};
        kv = str.split('&');
        for(i in kv){
            v = kv[i].split('=');
            data[v[0]] = v[1];
        }
        return data;
    },

    send:function(info){
        var tips = info['tips'];
        var method = info['method'];
        var args = info['data'];
        var callback = info['success'];

        var loadT = layer.msg(tips, { icon: 16, time: 0, shade: 0.3 });

        var data = {};
        data['name'] = 'mail';
        data['func'] = method;
        data['version'] = $('.plugin_version').attr('version');
     
        if (typeof(args) == 'string'){
            data['args'] = JSON.stringify(this.str2Obj(args));
        } else {
            data['args'] = JSON.stringify(args);
        }

        $.post('/plugins/run', data, function(res) {
            layer.close(loadT);
            if (!res.status){
                layer.msg(res.msg,{icon:2,time:10000});
                return;
            }

            var ret_data = $.parseJSON(res.data);
            console.log("send:",ret_data);
            // if (!ret_data.status){
            //     layer.msg(ret_data.msg,{icon:2,time:2000});
            //     return;
            // }

            // console.log("send2:",ret_data);

            if(typeof(callback) == 'function'){
                callback(ret_data);
            }
        },'json'); 
    },
    postCallback:function(info){
        var tips = info['tips'];
        var method = info['method'];
        var args = info['data'];
        var callback = info['success'];
        
        var loadT = layer.msg(tips, { icon: 16, time: 0, shade: 0.3 });

        var data = {};
        data['name'] = 'mail';
        data['func'] = method;
        data['version'] = $('.plugin_version').attr('version');
     
        if (typeof(args) == 'string'){
            data['args'] = JSON.stringify(this.str2Obj(args));
        } else {
            data['args'] = JSON.stringify(args);
        }

        $.post('/plugins/callback', data, function(res) {

            layer.close(loadT);
            if (!res.status){
                layer.msg(res.msg,{icon:2,time:10000});
                return;
            }

            var ret_data = $.parseJSON(res.data);
              if (!ret_data.status){
                layer.msg(ret_data.msg,{icon:2,time:2000});
                return;
            }

            if(typeof(callback) == 'function'){
                callback(res);
            }
        },'json');
    }
}
