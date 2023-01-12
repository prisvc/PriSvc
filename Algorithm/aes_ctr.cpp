#include "aes_ctr.h"
#define AES_NK 16
AES_CTR::AES_CTR()
{

}
int AES_CTR::init(char *key,char *iv)
{
    return aes_init(&state,MR_ECB,AES_NK,key,iv);
}
