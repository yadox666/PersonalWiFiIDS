from pythonwifi.iwlibs import Wireless

wifi = Wireless('wlan1')
num_frequencies, channels = wifi.getChannelInfo()
current_freq = wifi.getFrequency()
# Only for 2.4 GHz
print channels.index(current_freq) + 1
