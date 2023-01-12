export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
LIB_PATH=/usr/local/lib
.PHONY: algorithm hostapd wpa_supplicant

algorithm:	
	make -C Algorithm -B

hostapd:
	make -C hostapd/hostapd

wpa_supplicant:
	make -C wpa_supplicant/wpa_supplicant

install:
	cp ./Algorithm/libprisvc.so ${LIB_PATH} 

uninstall:
	rm -f ${LIB_PATH}/libprisvc.so

clean:
	rm -f ${LIB_PATH}/libprisvc.so
	cd Algorithm/ && make clean && cd ../ 
	cd hostapd/hostapd && make clean && cd ../..
	cd wpa_supplicant/wpa_supplicant && make clean && cd ../..
test:
	cd Algorithm/ && make test && cd ../
