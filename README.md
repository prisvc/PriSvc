# PRISVC
PRISVC is a demo of the scheme in the paper "PriSvc: Private Service Discovery with Bilateral Control Employing Anonymous Credential Based Matchmaking Encryption". The implementation of PRISVC uses several open source frameworks, including "Miracl"(https://github.com/miracl/MIRACL).


## build Dependencies

* OS: Ubuntu 20.04 LTS.
* make,gcc,g++



## install prisvc
Compile Miracl and PriSVC algorithm code and copy the generated library files (libprisvc.so) to directory (/usr/local/lib). Hostapd and wpa_supplicant are compiled using libprisvc.so
```sh
make algorithm
make test
sudo make install
```


