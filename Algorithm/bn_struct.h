#ifndef BN_STRUCT_H
#define BN_STRUCT_H

#define WLEN 4
struct Big_C
{
    unsigned int len;
    unsigned long w[WLEN];
};
struct G1_C
{
    struct Big_C X;
    struct Big_C Y;
    struct Big_C Z;
};
struct G2_C
{
    struct Big_C Xa,Xb;
    struct Big_C Ya,Yb;
    struct Big_C Za,Zb;
};
struct GT_C
{
    struct Big_C Aaa,Aab,Aba,Abb;
   // bool Aunitary;
    struct Big_C Baa,Bab,Bba,Bbb;
   // bool Bunitary;
    struct Big_C Caa,Cab,Cba,Cbb;
   // bool Cunitary;
};

#define CP_ABE_PARA_K 3
#define CP_ABE_PARA_N 3
#define ABCT_PARA_N 5 //parameter n [1,n]
#define ABCT_PARA_D 2 //parameter |I| [1,|I|]
#define LSS_NC_PARA_N 3//= CP_ABE_PARA_N
#define LSS_NC_SHARE_NUM 9
#define MACddh_PARA_N 7

struct ACME_MPK_C
{
    struct G1_C A1[CP_ABE_PARA_K][2*CP_ABE_PARA_K];
    struct G1_C AU01[CP_ABE_PARA_K][CP_ABE_PARA_K];
    struct G1_C AW1[CP_ABE_PARA_N][CP_ABE_PARA_K][CP_ABE_PARA_K];
    struct G2_C V2[2*CP_ABE_PARA_K];
    struct GT_C eAV[CP_ABE_PARA_K];

};
struct ACME_MSK_C
{
    struct Big_C A[CP_ABE_PARA_K][2*CP_ABE_PARA_K];
    struct Big_C B[CP_ABE_PARA_K][CP_ABE_PARA_K];
    struct Big_C U0[2*CP_ABE_PARA_K][CP_ABE_PARA_K];
    struct Big_C W[CP_ABE_PARA_N][2*CP_ABE_PARA_K][CP_ABE_PARA_K];
    struct Big_C V[2*CP_ABE_PARA_K];

};
struct ABCT_CRED_KEY_SK_C
{
    struct Big_C x;
    struct Big_C y[ABCT_PARA_N+2];

};
struct ABCT_CRED_KEY_PK_C
{
    struct G1_C W;
    struct G2_C X[ABCT_PARA_N+2];
    struct G1_C Y[ABCT_PARA_N+2];
    struct G1_C Z[ABCT_PARA_N+2][ABCT_PARA_N+2];
};

struct ACME_CRED_KEY_C
{
    struct ABCT_CRED_KEY_SK_C sk;
    struct ABCT_CRED_KEY_PK_C pk;

};
struct ABCT_USER_SK_C
{
    struct Big_C usk;
};
struct ABCT_USER_PK_C
{
    struct G2_C upk1;
    struct G1_C upk2;
};

struct ACME_USER_KEY_C
{
    struct ABCT_USER_SK_C usk;
    struct ABCT_USER_PK_C upk;
};

struct USER_ATTR_C
{
    struct Big_C x[ABCT_PARA_N+2];

};
struct ACME_SPK1_C
{
    struct Big_C c,s;
    struct G2_C gam1;
    struct G1_C gam2;
};

struct ACME_USER_PK_C
{
    struct ABCT_USER_PK_C upk;

};
struct ACME_CRED_U_C
{
    struct G2_C sigma1,sigma2;

};
struct ACME_CRED_KEY_PK_C
{
    struct ABCT_CRED_KEY_PK_C pk;

};
struct ACME_X_C
{
    int x[CP_ABE_PARA_N];//={1,0,1};
};

struct CP_ABE_SK_C
{
    struct G2_C sk1[2*CP_ABE_PARA_K];
    struct G2_C sk2[CP_ABE_PARA_K];
    struct G2_C sk3[2*CP_ABE_PARA_K];
};
struct ACME_ABE_DK_X_REC_C
{
    struct CP_ABE_SK_C sk;
};
struct CP_ABE_SHARE_INFO_C
{
    int rou[LSS_NC_SHARE_NUM];
    int w[LSS_NC_SHARE_NUM];
    int fMatrix[LSS_NC_PARA_N+1][LSS_NC_SHARE_NUM];
};
struct ACME_ABE_DK_f_REC_C
{
    struct G2_C dk[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    struct G2_C dk_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    struct CP_ABE_SHARE_INFO_C share;

};
struct ABCT_SPK2_C
{
    struct Big_C c,sd,sk;
    struct GT_C gama;
};
struct ABCT_TOK_C
{
    struct G1_C T1,T2;
    struct G2_C sigma1,sigma2;
    struct ABCT_SPK2_C spk2;
};
struct ABCT_USER_DISCLOSE_ATTR_C
{
    struct Big_C x[ABCT_PARA_D];

};
#if 0
struct ACME_CIPHER_CC
{
    struct GT_C ct0;
    struct G1_C ct1_[2*CP_ABE_PARA_K];
    struct G1_C ct2_[CP_ABE_PARA_K];
    struct G1_C ct1[2*CP_ABE_PARA_K];
    struct G1_C ct2[LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    struct G1_C ct_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][CP_ABE_PARA_K];

};
#endif
struct ACME_CIPHER_C
{
    struct GT_C ct0;
    struct G1_C ct1_[2*CP_ABE_PARA_K];
    struct G1_C ct2_[CP_ABE_PARA_K];
    struct G1_C ct1[2*CP_ABE_PARA_K];
    struct G1_C ct2[LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    struct G1_C ct_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
#if 1 //test
    struct GT_C K;
#endif
    struct Big_C cipher_M;
    struct ABCT_TOK_C cipher_tok;

    struct ABCT_USER_DISCLOSE_ATTR_C disclose;
    struct CP_ABE_SHARE_INFO_C share;

};

struct PriSvc_MSG_B_C
{
    struct Big_C bid;
    struct Big_C Service_type;
    struct Big_C Service_par;
    struct G2_C Z;

};
struct MACddh_SK_C
{
    struct Big_C x[MACddh_PARA_N+1];
    struct Big_C y[MACddh_PARA_N+1];
    struct Big_C z;
};
struct PriSvc_M_C_C
{
    struct Big_C bid;
    struct Big_C sid;
    struct G1_C X1;
    struct G2_C X2,Z;
};
struct PriSvc_MSG_C_C
{
    struct MACddh_SK_C K_c;
    struct ABCT_TOK_C tok_c;
    struct ABCT_USER_DISCLOSE_ATTR_C Disclose_c;
    struct PriSvc_M_C_C M_c;
};
struct MACddh_MAC_C
{
    struct G1_C sig_x,sig_y,sig_z,sig_w;
};
struct PriSvc_C1_C
{
    struct Big_C x1,x2;
    struct ACME_CIPHER_C CT;
    struct PriSvc_MSG_C_C msg_c;
    struct MACddh_MAC_C sigma_c;
};
struct PriSvc_MSG_S_C
{
    struct MACddh_SK_C Ks;
    struct ABCT_TOK_C toks;
    struct ABCT_USER_DISCLOSE_ATTR_C Disclose_s;
};
struct PriSvc_S_C
{
    struct Big_C bid;
    struct Big_C sid;
    struct G1_C Y;
    struct ACME_CIPHER_C CT;
    struct PriSvc_MSG_S_C msg_s;
    struct MACddh_MAC_C sigma_s;

};

struct PriSvc_SSK_C
{
    struct Big_C ssk;

};
struct ACME_TOK_C
{
    struct ABCT_TOK_C tok;

};

#endif // BN_STRUCT_H
