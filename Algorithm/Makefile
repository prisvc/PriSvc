export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	make -C MIRACL
	${CXX} -o test_abct test_abct.cpp abct.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_lss_nc test_lss_nc.cpp lss_nc.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_cp_abe test_cp_abe.cpp cp_abe.cpp lss_nc.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_mac_ddh test_mac_ddh.cpp macddh.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_acme test_acme.cpp acme.cpp abct.cpp lss_nc.cpp cp_abe.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_prisvc test_prisvc.cpp prisvc.cpp macddh.cpp acme.cpp abct.cpp lss_nc.cpp cp_abe.cpp bn_pair.cpp   bn_transfer.cpp miracl.a -g -w
#	${CXX} -o test_BNT  test_bn_transfer.cpp bn_transfer.cpp bn_pair.cpp  miracl.a
#	${CXX} -o test_cxx test_so.c prisvc_export.cpp bn_transfer.cpp prisvc.cpp macddh.cpp acme.cpp abct.cpp lss_nc.cpp cp_abe.cpp bn_pair.cpp   miracl.a -g -w 
	${CXX} -o libprisvc.so -fPIC -shared prisvc_export.cpp bn_transfer.cpp prisvc.cpp macddh.cpp acme.cpp abct.cpp lss_nc.cpp cp_abe.cpp bn_pair.cpp   miracl.a -O2 -w 
	${CC} -o test_so test_so.c -L. -lprisvc -w
clean:
	rm -f *.a *.so 
	rm -f test_abct
	rm -f test_lss_nc
	rm -f test_cp_abe
	rm -f test_mac_ddh
	rm -f test_acme
	rm -f test_acme
	rm -f test_prisvc
test:
	./test_abct
	./test_lss_nc
	./test_cp_abe
	./test_mac_ddh
	./test_acme
	./test_prisvc
	./test_so


