# PRISVC
PRISVC is a demo of the scheme in the paper "PriSvc: Private Service Discovery with Bilateral Control Employing Anonymous Credential Based Matchmaking Encryption". The implementation of PRISVC uses several open source frameworks, including "Miracl"(https://github.com/miracl/MIRACL) and "Wifi"(https://w1.fi/).


## build Dependencies

* OS: Ubuntu 20.04 LTS.
* make,gcc,g++
* 2 wifi interfaces


## install prisvc
Compile Miracl and PriSVC algorithm code and copy the generated library files (libprisvc.so) to directory (/usr/local/lib). Hostapd and wpa_supplicant are compiled using libprisvc.so
```sh
make algorithm
make test
sudo make install
```

# hostapd

## build dependencies
```sh
sudo apt-get install libssl-dev libnl-3-dev libnl-genl-3-dev
```

## build hostapd
```sh
make hostapd
```
## sets the wifi interface to use
open hostapd/hostapd/hostapd.conf, set wifi interface to the value of "interface" 
> #sets the wifi interface to use
> interface=wlp0s20f3

> Note: `interface` should not connect to any ssid.

## run hostapd
```sh
cd hostapd/hostapd
sudo ./hostapd hostapd.conf -dd -t -f hostapd.log
```


# wpa_supplicant
## build dependencies
```sh
sudo apt-get install libssl-dev libnl-3-dev libnl-genl-3-dev libdbus-1-dev
```

## build wpa_supplicant
```sh
make wpa_supplicant
```

## run wpa_supplicant
```sh
cd hostapd/hostapd
sudo ./wpa_supplicant -c wpa_supplicant.vendor_test -i wifi_interface -t -dd -f wpa_supplicant.log
```
> Note: `-i wifi_interface` is required for wifi interface .

> Note: `wifi_interface` should not connect to any ssid, and should net the same as interface which hostapd has used. You can use two wifi interface or two computer for this.

