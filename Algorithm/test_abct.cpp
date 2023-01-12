#include"abct.h"

#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    ABCT abct(&pfc);
    int ret =0;
    ABCT_CRED_KEY cred_key;
    ret = abct.CredKeyGen(cred_key);
    if(ret != 0)
    {
        printf("abct.CredKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.CredKeyGen pass\n");
    //cout<< cred_key.pk.W.g<<endl;

    ABCT_USER_KEY user_key;
    ret= abct.UserKeyGen(user_key);
    if(ret != 0)
    {
        printf("abct.UserKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.UserKeyGen pass\n");
    USER_ATTR attr;
    Big uid;
    ABCT_SPK1 spk1;
    ret = abct.IssueUser_Send(user_key, attr, uid,spk1);
    if(ret != 0)
    {
        printf("abct.IssueUser_Send Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.IssueUser_Send pass\n");
    ABCT_CRED_U cred_u;
    ret = abct.IssueIssuer(cred_key,attr,uid,spk1, user_key.upk,cred_u);
    if(ret != 0)
    {
        printf("abct.IssueIssuer Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.IssueIssuer pass\n");

    ret= abct.IssueUser_Verify(cred_key.pk,cred_u,attr,uid,user_key);
    if(ret != 0)
    {
        printf("abct.IssueUser_Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.IssueUser_Verify pass\n");

    ABCT_TOK tok;
    Big m;
    pfc.random(m);//ramdom m test
    ABCT_USER_DISCLOSE_ATTR disclose;
    ret= abct.Show(cred_key.pk,cred_u,attr,disclose,uid,user_key,tok,m);
    if(ret != 0)
    {
        printf("abct.Show Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.Show pass\n");
    ret= abct.Verify(cred_key.pk,tok,m,disclose);
    if(ret != 0)
    {
        printf("abct.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.Verify pass\n");
    //Trace
    ret= abct.Trace(cred_key,tok,uid);
    if(ret != 0)
    {
        printf("abct.Trace Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("abct.Trace  pass\n");

    return 0;
}
#include <ctime>
#include <time.h>
#define TEST_TIME 1
int speed_test()
{
    int i;
    clock_t start,finish;
    double sum;

    PFC pfc(AES_SECURITY);
    ABCT abct(&pfc);
    int ret =0;
    ABCT_CRED_KEY cred_key;
    printf("#################test abct speed start#######################\n");
    printf("The number of user attributes `n` is %d \n",ABCT_PARA_N);
    printf("The number of disclose attributes is %d \n",ABCT_PARA_D);

    //1. basic
    //G1
    start=clock();
    for(int k=0;k<TEST_TIME;k++)
    {
        G1 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G1 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_1 ret : %d time =%f sec\n",ret,sum);

    //G2
    start=clock();
    for(int k=0;k<TEST_TIME;k++)
    {
        G2 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G2 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_2 ret : %d time =%f sec\n",ret,sum);

    //e
    start=clock();
    for(int k=0;k<TEST_TIME;k++)
    {
        G1 G;
        G2 H;
        pfc.random(G);
        pfc.random(H);
        GT T=pfc.pairing(H,G);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_p ret : %d time =%f sec\n",ret,sum);


    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = abct.CredKeyGen(cred_key);
        if(ret != 0)
        {
            printf("abct.CredKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.CredKeyGen ret : %d time =%f sec\n",ret,sum);
    ABCT_USER_KEY user_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= abct.UserKeyGen(user_key);
        if(ret != 0)
        {
            printf("abct.UserKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.UserKeyGen ret : %d time =%f sec\n",ret,sum);
    USER_ATTR attr;
    Big uid;
    ABCT_SPK1 spk1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = abct.IssueUser_Send(user_key, attr, uid,spk1);
        if(ret != 0)
        {
            printf("abct.IssueUser_Send Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.IssueUser_Send ret : %d time =%f sec\n",ret,sum);
    ABCT_CRED_U cred_u;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = abct.IssueIssuer(cred_key,attr,uid,spk1, user_key.upk,cred_u);
        if(ret != 0)
        {
            printf("abct.IssueIssuer Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.IssueIssuer ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= abct.IssueUser_Verify(cred_key.pk,cred_u,attr,uid,user_key);
        if(ret != 0)
        {
            printf("abct.IssueUser_Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.IssueUser_Verify ret : %d time =%f sec\n",ret,sum);

    ABCT_TOK tok;
    Big m;
    pfc.random(m);//ramdom m test
    ABCT_USER_DISCLOSE_ATTR disclose;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= abct.Show(cred_key.pk,cred_u,attr,disclose,uid,user_key,tok,m);
        if(ret != 0)
        {
            printf("abct.Show Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.Show ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= abct.Verify(cred_key.pk,tok,m,disclose);
        if(ret != 0)
        {
            printf("abct.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.Verify ret : %d time =%f sec\n",ret,sum);
    //Trace
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= abct.Trace(cred_key,tok,uid);
        if(ret != 0)
        {
            printf("abct.Trace Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("abct.Trace ret : %d time =%f sec\n",ret,sum);
     printf("#################test abct speed end#######################\n");

    return 0;
}
int main()
{
    //return correct();
    return speed_test();

}
