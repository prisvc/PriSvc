#ifndef ABCT_H
#define ABCT_H
#include <list>
#include <iostream>
#include "pairing_3.h"

#define ABCT_PARA_N 5 //parameter n [1,n]
#define ABCT_PARA_D 2 //parameter |I| [1,|I|]
struct ABCT_PP
{

};
struct ABCT_CRED_KEY_SK
{
    Big x;
    Big y[ABCT_PARA_N+2];

};
struct ABCT_CRED_KEY_PK
{
    G1 W;
    G2 X[ABCT_PARA_N+2];
    G1 Y[ABCT_PARA_N+2];
    G1 Z[ABCT_PARA_N+2][ABCT_PARA_N+2];

};

struct ABCT_USER_SK
{
    Big usk;
};
struct ABCT_USER_PK
{
    G2 upk1;
    G1 upk2;
};
struct USER_ATTR
{
    Big x[ABCT_PARA_N+2];

};
struct ABCT_USER_DISCLOSE_ATTR
{
    Big x[ABCT_PARA_D];

};
struct ABCT_USER_KEY
{
    ABCT_USER_SK usk;
    ABCT_USER_PK upk;
};
struct ABCT_SPK1
{
    Big c,s;
    G2 gam1;
    G1 gam2;
};
struct ABCT_USER_OWN
{
    ABCT_USER_KEY user_key;
    USER_ATTR attr;
    Big uid;
    ABCT_SPK1 spk1;
};
struct ABCT_CRED_U
{
    G2 sigma1,sigma2;
};
struct ABCT_SPK2
{
    Big c,sd,sk;
    GT gama;
};
struct ABCT_TOK
{
    G1 T1,T2;
    G2 sigma1,sigma2;
    ABCT_SPK2 spk2;
};
struct ABCT_ST_UNIT
{
    Big uid;
    USER_ATTR attr;
    ABCT_USER_PK upk;
    ABCT_CRED_U cred_u;
};
typedef list <ABCT_ST_UNIT> ABCT_ST;
//typedef list <ABCT_ST_UNIT*> ABCT_ST;
struct ABCT_CRED_KEY
{
    ABCT_CRED_KEY_SK sk;
    ABCT_CRED_KEY_PK pk;
    ABCT_ST st;
};

class ABCT
{
private:
    PFC *pfc;
#if 0
    G1 g;
    G2 h;
#endif


public:
    ABCT(PFC *p);
    ~ABCT();
//    int SetUp(ABCT_PP &abct_pp);
    //key generate
    int CredKeyGen(ABCT_CRED_KEY &cred_key);
    int UserKeyGen(ABCT_USER_KEY &user_key);
    //issuecred_u
    int IssueUser_Send(ABCT_USER_KEY &user_key,USER_ATTR &attr,Big &uid,ABCT_SPK1 &spk1);
    int IssueIssuer(ABCT_CRED_KEY &cred_key,USER_ATTR &attr,Big &uid,ABCT_SPK1 &spk1,ABCT_USER_PK &upk,ABCT_CRED_U &cred_u);
    int IssueUser_Verify(ABCT_CRED_KEY_PK &pk,ABCT_CRED_U &cred_u,USER_ATTR &attr,Big &uid,ABCT_USER_KEY &user_key);
    //Show
    int Show(ABCT_CRED_KEY_PK &pk,ABCT_CRED_U &cred_u,USER_ATTR &attr,ABCT_USER_DISCLOSE_ATTR &disclose,Big &uid,ABCT_USER_KEY &user_key,ABCT_TOK &tok,Big &m);
    int Verify(ABCT_CRED_KEY_PK &pk,ABCT_TOK &tok,Big &m,ABCT_USER_DISCLOSE_ATTR &disclose);
    //Trace
    int Trace(ABCT_CRED_KEY &cred_key,ABCT_TOK &tok,Big &uid);


};
#endif // ABCT_H
