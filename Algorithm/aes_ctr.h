#ifndef AES_CTR_H
#define AES_CTR_H
#include "miracl.h"
#include "pairing_3.h"

class AES_CTR
{
    aes state;
public:
    AES_CTR();
    int init(char *key,char *iv);
    int encrypt_add(Big &Data);
    int encrypt_add(G1 &Data);
    int encrypt_add(G2 &Data);
    int encrypt_add(GT &Data);
    int decrypt_red(Big &Data);
    int decrypt_red(G1 &Data);
    int decrypt_red(G2 &Data);
    int decrypt_red(GT &Data);
    int finish();
};

#endif // AES_CTR_H
