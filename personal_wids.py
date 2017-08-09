#!/usr/bin/python
# -*- coding: utf-8 -*-​
# Personal Wireless IDS
# Insert MAC addresses of your AP and clients in the whitelist
# file: /root/.macs2protect

import sys, os, logging, fcntl, threading
from threading import Thread, Lock
from signal import SIGINT, signal
from platform import system
from netaddr import *
from netaddr.core import NotRegisteredError
import logging.handlers
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


### User variables
intfparent='wlan1'  ## Wireless card to use as monitor mode parent (wlan1)
notify=1  ## try to notify on gnome, dependant of libnotify
savecap=1  ## will save captured packets from attack
verbose=1  ## Debug level to use for programmer (0-2)

### System variables
intfmain='wlan0'  ## interface in managed mode connected to wifi APs
channel=8  ## default standby channel
duration=6  ## attack duration in seconds to avoid be notified again
capfile=os.path.expanduser('~') + '/attack_pkts.cap' ## directory and file name to save captured packets
whitelistfile=os.path.expanduser('~') + '/.macs2protect'
whitelist=set()
lastdeauth=lastassoc=lastauth=lastproberesp=time.time()-duration
intfmon=''
risk2str=['None','Low','Medium','High','Critical']
slogger=None
keeprunning=1
freq=''
actualfreq=''
actualchannel=''


### Check if OS is linux
def oscheck():
    osversion = system()
    slogger.debug("Operating System: %s" % osversion)
    if osversion != 'Linux':
        slogger.error("This script only works on Linux OS! Exitting!")
        exit(1)


### Init any Wi-Fi adapter monitor mode VAP
def initmon(interface):
    global intfmon, whitelist
    slogger.debug("Wi-Fi interface to use: %s" %interface)
    if not os.path.isdir("/sys/class/net/" + interface):
        slogger.error("WiFi parent interface %s does not exist! Cannot continue!" % interface)
        exit(1)
    else:
        intfmon = 'mon' + intfparent[-1]
        if os.path.isdir("/sys/class/net/" + intfmon):
            slogger.debug("WiFi interface %s exists! Deleting it!" % (intfmon))
            try:
                # create monitor interface using iw
                os.system("iw dev %s del" % intfmon)
                time.sleep(0.5)
            except OSError as oserr:
                slogger.error("Could not delete monitor interface %s. %s" % (intfmon, oserr.message))
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
        try:
            # create monitor interface using iw
            os.system("ifconfig %s down" % interface)
            time.sleep(0.3)
            os.system("iwconfig %s mode monitor" % interface)
            time.sleep(0.3)
            os.system("iw dev %s interface add %s type monitor" % (interface, intfmon))
            time.sleep(0.3)
            os.system("ifconfig %s up" % intfmon)
            slogger.debug("Creating monitor VAP %s for parent %s..." % (intfmon, interface))
        except OSError as oserr:
            slogger.error("Could not create monitor %s. %s" % (intfmon, oserr.message))
            os.kill(os.getpid(), SIGINT)
            sys.exit(1)
        # Get actual MAC addresses
        macaddr1 = GetMAC(interface).upper()
	whitelist.add(macaddr1)
        slogger.info("Found MAC (%s): %s [%.18s]. Adding it!" %(interface,macaddr1,get_oui(macaddr1)))
        macaddr = GetMAC(intfmon).upper()
        if macaddr1 != macaddr:
            whitelist.add(macaddr);
            slogger.info("Found MAC (%s): %s [%.18s]. Adding it!" %(intfmon,macaddr,get_oui(macaddr)))


### Get the MAC address of any adapter
def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac


### Function to get manufacturer from MAC address
def get_oui(mac):
    try:
	maco = EUI(mac)
        manuf = maco.oui.registration().org.replace(',',' ')
    except NotRegisteredError:
        manuf = "n/a"
    return manuf


### Packet handler or parse function
def PacketHandler(pkt):
    global lastdeauth,lastassoc,lastauth,duration,savecap, lastproberesp

    if pkt.haslayer(Dot11Deauth):
	if (pkt.addr1.upper() in whitelist or pkt.addr2.upper() in whitelist or pkt.addr3.upper() in whitelist) and time.time() > (lastdeauth+duration):
	    risklevel=2
	    lastdeauth=time.time()
	    sta_manuf = get_oui(pkt.addr1)
	    if sta_manuf == "n/a": risklevel += 1	
	    if pkt.sprintf("%Dot11Deauth.reason%").startswith('class3-from-nonass'): risklevel += 1
	    message=pkt.sprintf("Deauth detected! \n from: %Dot11.addr1% \n to: %Dot11.addr2% \n Reason: %Dot11Deauth.reason%\n")
	    message+=" Source: %s (%s)\n" %(pkt.addr1,sta_manuf)
	    message+=' RISK: ' + risk2str[risklevel]+'\n'
	    if notify: notifypopup(message)
	    slogger.critical('WIDS:'+ message)
	    if savecap: 
		try:
		    writer = PcapWriter(capfile, append=True)
		    writer.write(pkt)
		    writer.close()
		except:
		    savecap=0

    elif pkt.haslayer(Dot11AssoReq):
	if (pkt.addr1.upper() in whitelist and not pkt.addr2.upper() in whitelist) and time.time() > (lastassoc+duration):
	    risklevel=1
	    lastassoc=time.time()
	    sta_manuf = get_oui(pkt.addr2)
	    if sta_manuf == "n/a": risklevel += 1	
	    message=pkt.sprintf("Association detected! \n Client %Dot11.addr2%  \n AP: %Dot11Elt.info% \n BSSID: %Dot11.addr1% \n ")
	    message+=" Source: %s (%s)\n" %(pkt.addr1,sta_manuf)
            message+=' RISK: '+risk2str[risklevel]+'\n'
	    if notify and time.time() > (lastauth+duration): notifypopup(message)
	    slogger.warn('WIDS:'+ message)
	    if savecap: 
		try:
		    writer = PcapWriter(capfile, append=True)
		    writer.write(pkt)
		    writer.close()
		except:
		    savecap=0

    elif pkt.haslayer(Dot11Auth):
	if (pkt.addr1.upper() in whitelist and not pkt.addr2.upper() in whitelist) and time.time() > (lastauth+duration):
	    risklevel=1
	    lastauth=time.time()
	    sta_manuf = get_oui(pkt.addr2)
	    if sta_manuf == "n/a": risklevel += 1	
	    message=pkt.sprintf("Authentication detected! \n Client: %Dot11.addr2% \n AP: %Dot11.addr1% \n")
	    message+=" Source: %s (%s)\n" %(pkt.addr1,sta_manuf)
            message+=' RISK: '+risk2str[risklevel]+'\n'
	    if notify and time.time() > (lastassoc+duration): notifypopup(message)
	    slogger.warn('WIDS:'+ message) ## to-do: have to subst \n by comma
	    if savecap: 
		try:
		    writer = PcapWriter(capfile, append=True)
		    writer.write(pkt)
		    writer.close()
		except:
		    savecap=0

    elif pkt.haslayer(Dot11ProbeResp):   ### ojo
	probe=pkt.sprintf("%Dot11Elt.info%").strip()
	if probe != '':
	    if not probe in whitelist: return
	if (pkt.addr3.upper() in whitelist) and time.time() > (lastproberesp+duration):
	    risklevel=1
	    lastproberesp=time.time()
	    sta_manuf = get_oui(pkt.addr2)
	    if sta_manuf == "n/a": risklevel += 1	
	    message=pkt.sprintf("A possible FAKEAP detected! \n Client: %Dot11.addr2% \n AP: %Dot11.addr1% \n")
	    message+=" Source: %s (%s)\n" %(pkt.addr1,sta_manuf)
            message+=' RISK: '+risk2str[risklevel]+'\n'
	    if notify and time.time() > (lastproberesp+duration): notifypopup(message)
	    slogger.warn('WIDS:'+ message)
	    if savecap:
		try:
		    writer = PcapWriter(capfile, append=True)
		    writer.write(pkt)
		    writer.close()
		except:
		    savecap=0


### Init notify settings
def startNotify():
    global notify
    try:
        import gi
        gi.require_version('Notify', '0.7')
        from gi.repository import Notify
        Notify.init("WiFi Alert!")
    except:
        slogger.error("Have to install gi library for Python!")
        try:
            os.system("pip install gi")
            import gi
        except OsError as e:
            slogger.error("Could not auto install it! Please try yourself! Disabling notifications!!!")
            notify=0


### Send a notification to desktop
def notifypopup(message):
    try:
	popup=Notify.Notification.new('WiFi Alert:', message, "dialog-alert")
	popup.show()
    except:
	pass


### Set Wi-Fi channel if requested
def SetChannel(channel):
    global actualfreq
    cmd0 = 'ifconfig %s up >/dev/null 2>&1' % (intfmon)
    if int(channel) in range(1,14):
        cmd1 = 'iw dev %s set channel %s >/dev/null 2>&1' % (intfmon, channel)
        msg = "Setting %s to channel: %s" %(intfmon,channel)
    elif int(channel) in range(2412,5899):
        cmd1 = 'iw dev %s set freq %s >/dev/null 2>&1' % (intfmon, channel)
        msg = "Setting %s to frequency: %s MHz (Channel: %s)" %(intfmon,channel,((int(channel)-2412)/5)+1)
    else:
        slogger.error("Error setting channel for %s to %s" %(intfmon,channel))
        msg = "Setting %s to channel: %s" %(intfmon,channel)
    try:
        os.system(cmd0)
        os.system(cmd1)
	actualfreq = channel
        slogger.info(msg)
    except:
        slogger.error("Error setting %s to: %s" %(intfmon,channel))


### Get the main Wi-Fi Channel
def GetFreq(interface):
    try:
        import iwlib
 	freq = iwlib.get_iwconfig(interface)['Frequency']
        slogger.debug("Main Wi-Fi interface (%s) in Freq: %s" %(interface,freq))
	freq = ''.join(x for x in freq if x.isdigit())
	return freq
    except:
	return 0


### Change channel if necessary when roaming 
def checkChannel(ch):
    global keeprunning,freq, actualfreq
    while keeprunning:
        freq = GetFreq(intfmain)
        if freq:
	    if freq != actualfreq:
                SetChannel(freq)
	        slogger.info("Looking for suspicious packets in frequency %s MHz" %freq)
        else:
            if type(ch)=='int': ch=str(channel)
	    if ch != actualfreq:
                SetChannel(ch)
        time.sleep(15)


### Parse whitelist file for macs and essids
def parseWhiteList():
    try:
	slogger.info("Adding protected objects to Whitelist!")
        macfile = open(whitelistfile, 'r')
        for line in macfile.readlines():
            if not line.strip() or line[0:1] == "#":
		slogger.debug("Empty line. Discarding it!")
                continue
            else:
		line=line.split('#')[0].strip()
		# Parse mac address
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", line.lower()):
		    line=line.upper()
		    slogger.info("Found MAC: %s [%.18s]. Adding it!" %(line,get_oui(line)))
	            whitelist.add(line)
		# or essid
		else:
		    slogger.info("Found SSID: %s. Adding it!" %line)
		    whitelist.add(line)
    except IOError:
        slogger.error('Cannot open Whitelist file %s, exiting!' %whitelistfile)
        exit()


### Init syslog settings
def startLog():
    global slogger,logging
    try:
	slogger = logging.getLogger(__name__)
	shandler = logging.FileHandler('/var/log/wids.log')
	if verbose > 1: 
		logging.basicConfig(level=logging.DEBUG)
	elif verbose > 0: 
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.ERROR)
	slogger.addHandler(shandler)
    except Exception as e:
	print "Logging error: %s" %e.message
	logging=0


### End execution when requested
def end_execution(signal, frame):
    global keeprunning
    keeprunning=0
    time.sleep(1)
    sys.exit('CTRL+C pressed, exitting!')


### Stop scapy sniff cleanly (sometimes)
def stopsniff(pkt):
    global keeprunning
    if keeprunning:
	return False
    else:
	return True



# main routine
if __name__ == "__main__":

    # Print init banner
    if verbose:
        print "\n================================================"
        print "      ▛▀▖                  ▜    ▌ ▌▜▘▛▀▖▞▀▖"
        print "      ▙▄▘▞▀▖▙▀▖▞▀▘▞▀▖▛▀▖▝▀▖▐    ▌▖▌▐ ▌ ▌▚▄ "
        print "      ▌  ▛▀ ▌  ▝▀▖▌ ▌▌ ▌▞▀▌▐    ▙▚▌▐ ▌ ▌▖ ▌"
        print "      ▘  ▝▀▘▘  ▀▀ ▝▀ ▘ ▘▝▀▘ ▘   ▘ ▘▀▘▀▀ ▝▀ "
        print "      Wireless Intrussion Detection System"
        print "================================================\n"

    # Interrupt handler to exit
    signal(SIGINT, end_execution)

    ### Start syslog handler
    startLog()

    # Check for root privileges
    if os.geteuid() != 0:
        slogger.error("You need to be root to run this script!")
        exit()
    else:
        slogger.debug("You are running this script as root!")

    # Check if OS is linux:
    oscheck()

    ### If need to notify, import python gi library
    #if notify: startNotify()
    try:
        import gi
        gi.require_version('Notify', '0.7')
        from gi.repository import Notify
        Notify.init("WiFi Alert!")
    except:
        slogger.error("Have to install gi library for Python!")
        try:
            os.system("pip install gi")
            import gi
        except OsError as e:
            slogger.error("Could not auto install it! Please try yourself! Disabling notifications!!!")
            notify=0


    ### Open file with MAC addresses whitelist
    parseWhiteList()

    # Add main WLAN MAC address to list to protect
    macaddr = GetMAC(intfmain).upper()
    whitelist.add(macaddr)
    slogger.info("Found MAC (%s): %s [%.18s]. Adding it!" %(intfmain,macaddr,get_oui(macaddr)))

    # Check if monitor device exists or create it
    initmon(intfparent)

    # Need to save cap?
    if savecap: slogger.info("Capture option enabled: saved cap stored in: %s" %(capfile))

    # start new Thread to change frequency when needed (if you roam)
    checkchannel = Thread(target=checkChannel, args=str(channel))
    checkchannel.daemon = True
    checkchannel.start()

    if notify: notifypopup("Starting WIDS...")

    # Start sniffing now
    slogger.info("Starting sniffer proccess in %s." %intfmon)
    try:
        sniff(iface=intfmon, prn=PacketHandler, stop_filter=stopsniff, store=False, lfilter=lambda pkt:Dot11 in pkt)
    except Exception as e:
        slogger.error("Cannot sniff packets! %s" %e.message)
    	exit(-1)
