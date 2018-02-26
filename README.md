Service Scanner
===

## Features

* Auto scan the listen port on host by nmap tool and reported by NEW/MISSING.
* Whitelist supported
* Send warning messaging by command line tool(eg:mail)

## Install

* Build the binary package by `pkg.sh`
* Run `sscanner` command or make it as service

## Usage

* Whitelist example

```.text
[loc.m]
ranges=70-81    #the port ranges to scan.
80/tcp  open    #http
180/tcp  open   #http

#all host to scann
[hosts]
loc.m
```

* Configure example

```.txt
[loc]
listen=:8231 #web listen port
enable_tcp=1 #enable tcp scan
enable_udp=1 #enable udp scan
delay=60000  #the scan delay
#the warning command.
warner=echo $SS_HOST $SS_PROTO $SS_NEW $SS_NEW_LEN $SS_MISSING $SS_MISSING_LEN $SS_ERROR

#load the whitelist configure.
@l:sscanner-hosts.conf
```