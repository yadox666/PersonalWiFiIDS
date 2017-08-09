Personal Wi-Fi IDS
=============================================
(Personal Wireless Intrussion Detection System)

This Python script mainly uses the Scapy library for detecting and
warning all the typical Wi-Fi attacks ran by Wi-Fi hackers that,
try to deauthenticate you from your legit Wi-Fi APs to bring your
laptop to a Fake Wi-Fi network in which you'll be full nude in terms
of IT security.

It will detect the main attacks that are ran from applications like
aireplay-ng and other deauth samples. It will also warn about unknown
devices that try to connect to your home or SOHO networks. To achieve
it you have to make a list of your trusted devices, like your laptop, 
smartphone, tablet or your family/friends/colleagues devices. If any
device that's not in the whitelist tries to connect to your Wi-Fi net,
you'll get probably warned about it.


Requirements
============
* Python 2.7
* Python Scapy 2.3 or newer
* Python gi library to notify on Desktop
* WiFi Monitor Mode compatible card (TP-LINK TL-WN722N v.1, Edimax)
* The script must be run with root privileges because of monitor mode


Libnotify
=========
* apt-get --reinstall install libnotify-bin
* apt-get --reinstall install  notification-daemon
* nano  /etc/xdg/autostart/update-notifier.desktop
* nano  /etc/xdg/autostart/notification-daemon.desktop
* /usr/lib/notification-daemon/notification-daemon &
* notify-send hello


Configuration
=============
You have to create a file named .macs2protect on your home directory,
This file contains a list of all the Wi-Fi MAC addresses in which you
can trust (BSSIDS, ESSID, Station MACs)

Just enter one per line after the mac or essid.

If run as root, the file must reside in:
/root/.macs2protect

* You can insert any Whitelisted MAC address (one in each line)
* Insert any SSID to Whitelist file (one in each line)
* You can also add comments after each item using comment " #"


Example (/root/.macs2protect):
==============================
00:18:39:AE:88:58   # my laptop mac

76:3C:18:DA:8E:AB   # my smartphone mac

C0:EE:FB:47:E8:05   # my tablet mac

ONO_E1F1  # my home WiFi

