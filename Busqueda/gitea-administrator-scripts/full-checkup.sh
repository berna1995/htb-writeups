#!/bin/bash

/usr/bin/echo '[=] Docker conteainers'

/usr/bin/docker ps -s -q|/usr/bin/xargs -I {} /usr/bin/docker inspect --format='{ {{json .Name}} : {{json .State.Status}} }' {}|/usr/bin/jq
/usr/bin/echo ''

/usr/bin/echo '[=] Docker port mappings'

/usr/bin/docker inspect gitea --format='{{json .NetworkSettings.Ports}}'|/usr/bin/jq
/usr/bin/echo ''
#!/bin/bash

/usr/bin/echo '[=] Apache webhosts'
/usr/bin/wget http://searcher.htb/ -T 3 -O /dev/null -q
if [[ $? -eq "0" ]]; then
	/usr/bin/echo '[+] searcher.htb is up'
else
	/usr/bin/echo '[-] searcher.htb is down'
fi

/usr/bin/wget http://gitea.searcher.htb/ -T 3 -O /dev/null -q
if [[ $? -eq "0" ]]; then
        /usr/bin/echo '[+] gitea.searcher.htb is up'
else
        /usr/bin/echo '[-] gitea.searcher.htb is down'
fi
/usr/bin/echo ''

/usr/bin/echo '[=] PM2 processes'
/usr/local/bin/pm2 list
