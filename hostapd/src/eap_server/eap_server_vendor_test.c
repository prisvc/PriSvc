/*
 * hostapd / Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "prisvc_export.h"

#define EAP_VENDOR_ID EAP_VENDOR_HOSTAP
#define EAP_VENDOR_TYPE 0xfcfbfaf9

/* EAP PRISVC Flags */
#define EAP_PRISVC_FLAGS_LENGTH_INCLUDED 0x80
#define EAP_PRISVC_FLAGS_MORE_FRAGMENTS 0x40
#define EAP_PRISVC_FLAGS_START 0x20

#define EAP_PRISVC_SEND_LIMIT 1470 /*报文发送长度限制*/

struct eap_vendor_test_data
{
	enum
	{
		INIT,
		Broadcast_MSG,
		Broadcast_CONFIRM,
		AMA_Cinit_MSG,
		AMA_S_MSG,
		AMA_S_CONFIRM,
		AMA_Cverify_MSG, /*可能用不上*/
		SUCCESS,
		FAILURE
	} state;
	enum
	{
		MSG,
		FRAG_ACK,
		WAIT_FRAG_ACK

	} prisvc_state; /*用于标示需要分片发送数据包时的发送状态*/
	/**
	 * prisvc_out - prisvc message to be sent out in fragments
	 */
	struct wpabuf *prisvc_out;

	/**
	 * prisvc_out_pos - The current position in the outgoing prisvc message
	 */
	size_t prisvc_out_pos;

	/**
	 * prisvc_out_limit - Maximum fragment size for outgoing prisvc messages
	 */
	size_t prisvc_out_limit;

	/**
	 * prisvc_in - Received prisvc message buffer for re-assembly
	 */
	struct wpabuf *prisvc_in;

	/**
	 * prisvc_in_left - Number of remaining bytes in the incoming prisvc message
	 */
	size_t prisvc_in_left;

	/**
	 * prisvc_in_total - Total number of bytes in the incoming prisvc message
	 */
	size_t prisvc_in_total;

	struct ACME_MPK_C *mpk;
	struct ACME_MSK_C *msk;
	struct ACME_CRED_KEY_C *cred_key;
	struct ACME_CRED_KEY_PK_C *cred_key_pk;
	struct ACME_USER_KEY_C *service_key;
	struct USER_ATTR_C *service_attr;
	struct Big_C *bid;
	struct ACME_SPK1_C *spk1;
	struct ACME_CRED_U_C *cred_s;
	struct ACME_USER_PK_C *service_key_upk;
	struct ACME_X_C *X_s;
	struct ACME_ABE_DK_X_REC_C *Dk_S_xrec;
	struct ACME_ABE_DK_f_REC_C *DK_S_frec;
	struct Big_C *z;
	struct ACME_CIPHER_C *cipher;
	struct PriSvc_MSG_B_C *msg_b;
	struct PriSvc_S_C *S_msg;
	struct PriSvc_SSK_C *ssk_s;
	struct PriSvc_C1_C *C1_msg;
	struct ACME_X_C *X_c;
	struct timeval tv;

	struct os_time tv_total_start; //总过程的起始时间 
	struct os_time tv_total_end;   //总过程的结束时间

	struct os_time tv_Broadcast_start; // Broadcast过程的起始时间
	struct os_time tv_Broadcast_end;   // Broadcast过程的结束时间

	struct os_time tv_Broadcast_comm_start; // Broadcast包发送的起始时间
	struct os_time tv_Broadcast_comm_end;	// Broadcast包发送的结束时间

	struct os_time tv_AMA_S_start; // AMA_S过程的起始时间
	struct os_time tv_AMA_S_end;   // AMA_S过程的结束时间

	struct os_time tv_AMA_S_comm_start; // AMA_S包发送的起始时间
	struct os_time tv_AMA_S_comm_end;	// AMA_S包发送的结束时间
};

static const char *eap_vendor_test_state_txt(int state)
{
	switch (state)
	{
	case INIT:
		return "INIT";
	case Broadcast_MSG:
		return "Broadcast_MSG";
	case Broadcast_CONFIRM:
		return "Broadcast_CONFIRM,";
	case AMA_Cinit_MSG:
		return "AMA_Cinit_MSG";
	case AMA_S_MSG:
		return "AMA_S_MSG";
	case AMA_S_CONFIRM:
		return "AMA_S_CONFIRM";
	case AMA_Cverify_MSG:
		return "AMA_Cverify_MSG";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}

static void eap_vendor_test_state(struct eap_vendor_test_data *data,
								  int state)
{
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: %s -> %s",
			   eap_vendor_test_state_txt(data->state),
			   eap_vendor_test_state_txt(state));
	data->state = state;
}

static void *eap_vendor_test_init(struct eap_sm *sm)
{
	struct eap_vendor_test_data *data;
	int ret;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;

	// system init
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST://///////////// system setup  ////////////////////\n");
	struct ACME_MPK_C *mpk = (struct ACME_MPK_C *)malloc(sizeof(struct ACME_MPK_C));
	struct ACME_MSK_C *msk = (struct ACME_MSK_C *)malloc(sizeof(struct ACME_MSK_C));
	ret = SetUp(mpk, msk);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.SetUp Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.SetUp pass\n");

	data->mpk = mpk;
	data->msk = msk;

	struct ACME_CRED_KEY_C *cred_key = (struct ACME_CRED_KEY_C *)malloc(sizeof(struct ACME_CRED_KEY_C));
	ret = CredKeyGen(cred_key);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.CredKeyGen Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.CredKeyGen pass\n");
	data->cred_key = cred_key;

	struct ACME_CRED_KEY_PK_C *cred_key_pk = (struct ACME_CRED_KEY_PK_C *)malloc(sizeof(struct ACME_CRED_KEY_PK_C));
	memcpy(&(cred_key_pk->pk), &(cred_key->pk), sizeof(struct ABCT_CRED_KEY_PK_C));
	data->cred_key_pk = cred_key_pk;

	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: /////////////// server setup  ////////////////////\n");

	// server init
	struct ACME_USER_KEY_C *service_key = (struct ACME_USER_KEY_C *)malloc(sizeof(struct ACME_USER_KEY_C));
	ret = UserKeyGen(service_key);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.service_key KeyGen Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.service_key KeyGen pass\n");
	data->service_key = service_key;

	struct USER_ATTR_C *service_attr = (struct USER_ATTR_C *)malloc(sizeof(struct USER_ATTR_C));
	struct Big_C *bid = (struct Big_C *)malloc(sizeof(struct Big_C));
	struct ACME_SPK1_C *spk1 = (struct ACME_SPK1_C *)malloc(sizeof(struct ACME_SPK1_C));
	ret = Issue_Send(service_key, service_attr, bid, spk1);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Issue_Send service Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Issue_Send service pass\n");

	data->service_attr = service_attr;
	data->bid = bid;
	data->spk1 = spk1;

	struct ACME_CRED_U_C *cred_s = (struct ACME_CRED_U_C *)malloc(sizeof(struct ACME_CRED_U_C));
	struct ACME_USER_PK_C *service_key_upk = (struct ACME_USER_PK_C *)malloc(sizeof(struct ACME_USER_PK_C));
	memcpy(&(service_key_upk->upk), &(service_key->upk), sizeof(struct ABCT_USER_PK_C));
	ret = Issue_Issuer(cred_key, service_attr, bid, spk1, service_key_upk, cred_s);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Issue_Issuer service Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Issue_Issuer service pass\n");

	data->cred_s = cred_s;
	data->service_key_upk = service_key_upk;

	ret = Issue_Verify(cred_key_pk, cred_s, service_attr, bid, service_key);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Issue_Verify service Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Issue_Verify service pass\n");

	struct ACME_X_C *X_s = (struct ACME_X_C *)malloc(sizeof(struct ACME_X_C));

	struct ACME_ABE_DK_X_REC_C *Dk_S_xrec = (struct ACME_ABE_DK_X_REC_C *)malloc(sizeof(struct ACME_ABE_DK_X_REC_C));

	ret = DKeyGen(msk, X_s, Dk_S_xrec);

	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.DKeyGen service Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.DKeyGen service pass\n");

	data->X_s = X_s;
	data->Dk_S_xrec = Dk_S_xrec;

	struct ACME_ABE_DK_f_REC_C *DK_S_frec = (struct ACME_ABE_DK_f_REC_C *)malloc(sizeof(struct ACME_ABE_DK_f_REC_C));
	ret = PolGen(msk, DK_S_frec);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.PolGen service Erro ret =%d\n", ret);
		return 1;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.PolGen service pass\n");
	data->DK_S_frec = DK_S_frec;

	data->prisvc_out = NULL;
	data->prisvc_in = NULL;
	data->prisvc_out_pos = 0;
	data->prisvc_out_limit = EAP_PRISVC_SEND_LIMIT;

	data->prisvc_in_left = 0;
	data->prisvc_in_total = 0;

	data->state = INIT;

	return data;
}

static void eap_vendor_test_reset(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	os_free(data->mpk);
	os_free(data->msk);
	os_free(data->cred_key);
	os_free(data->cred_key_pk);
	os_free(data->service_key);
	os_free(data->service_attr);
	os_free(data->bid);
	os_free(data->spk1);
	os_free(data->cred_s);
	os_free(data->service_key_upk);
	os_free(data->X_s);
	os_free(data->Dk_S_xrec);
	os_free(data->DK_S_frec);
	os_free(data->z);
	os_free(data->cipher);
	os_free(data->msg_b);
	os_free(data->S_msg);
	os_free(data->ssk_s);
	os_free(data->C1_msg);
	os_free(data->X_c);
	eap_peer_vendor_test_reset_input(data);
	eap_peer_vendor_test_reset_output(data);
	os_free(data);
}

struct wpabuf *eap_server_vendor_test_build_msg(struct eap_sm *sm, struct eap_vendor_test_data *data,
												u8 id)
{
	struct wpabuf *req;
	u8 flags;
	size_t send_len, plen;

	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Generating Request");
	if (data->prisvc_out == NULL)
	{
		wpa_printf(MSG_ERROR, "EAP-VENDOR-TEST: prisvc_out NULL in %s", __func__);
		return NULL;
	}

	flags = 0;
	send_len = wpabuf_len(data->prisvc_out) - data->prisvc_out_pos;
	if (1 + send_len > data->prisvc_out_limit)
	{
		send_len = data->prisvc_out_limit - 1;
		flags |= EAP_PRISVC_FLAGS_MORE_FRAGMENTS;
		if (data->prisvc_out_pos == 0)
		{
			flags |= EAP_PRISVC_FLAGS_LENGTH_INCLUDED;
			send_len -= 4;
		}
	}

	plen = 1 + send_len;
	if (flags & EAP_PRISVC_FLAGS_LENGTH_INCLUDED)
		plen += 4;
	/*该处分配的内存似乎是由框架在发送数据后来负责回收？*/
	req = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE,
						plen, EAP_CODE_REQUEST, id);
	if (req == NULL)
		return NULL;

	wpabuf_put_u8(req, flags); /* Flags */
	if (flags & EAP_PRISVC_FLAGS_LENGTH_INCLUDED)
		wpabuf_put_be32(req, wpabuf_len(data->prisvc_out));

	wpa_hexdump(MSG_MSGDUMP, "EAP-VENDOR-TEST: prisvc data",
				wpabuf_head_u8(data->prisvc_out) + data->prisvc_out_pos, send_len);

	wpabuf_put_data(req, wpabuf_head_u8(data->prisvc_out) + data->prisvc_out_pos,
					send_len);

	data->prisvc_out_pos += send_len;

	if (data->prisvc_out_pos == wpabuf_len(data->prisvc_out))
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Sending out %lu bytes "
							  "(message sent completely)",
				   (unsigned long)send_len);
		wpabuf_free(data->prisvc_out);
		data->prisvc_out = NULL;
		data->prisvc_out_pos = 0;
		data->prisvc_state = MSG;
		// comm time end - wpa init time
		if (data->state == Broadcast_MSG)
		{
			os_get_time(&data->tv_Broadcast_comm_end);
		}
		else if (data->state == AMA_S_MSG)
		{
			os_get_time(&data->tv_AMA_S_comm_end);
		}
	}
	else
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Sending out %lu bytes "
							  "(%lu more to send)",
				   (unsigned long)send_len,
				   (unsigned long)wpabuf_len(data->prisvc_out) -
					   data->prisvc_out_pos);
		data->prisvc_state = WAIT_FRAG_ACK;
	}

	return req;
}

static struct wpabuf *eap_vendor_test_buildReq(struct eap_sm *sm, void *priv,
											   u8 id)
{
	struct eap_vendor_test_data *data = priv;

	int iret;
	/*wpabuf_put_u8(req, data->state == INIT ? 1 : 3);*/
	if (data->state == INIT)
	{
		// total time start
		os_get_time(&data->tv_total_start);
		/*初始化需要发送的broadcast数据*/
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Generating Broadcast Request");
		if (data->prisvc_out == NULL)
		{
			wpa_printf(MSG_ERROR, "EAP-VENDOR-TEST: prisvc_out NULL in %s, start to generate Broadcast", __func__);

			int out_len = 1 + sizeof(struct ACME_X_C) + sizeof(struct ACME_CIPHER_C) +
						  sizeof(struct PriSvc_MSG_B_C);

			data->prisvc_out = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE,
											 out_len, EAP_CODE_REQUEST, id);
			if (data->prisvc_out == NULL)
			{
				wpa_printf(MSG_ERROR, "EAP-VENDOR-TEST: Failed to allocate "
									  "memory for request");
				return NULL;
			}

			data->z = (struct Big_C *)malloc(sizeof(struct Big_C));
			wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST://///////////// server broadcast  ////////////////////\n");
			data->cipher = (struct ACME_CIPHER_C *)malloc(sizeof(struct ACME_CIPHER_C));
			data->msg_b = (struct PriSvc_MSG_B_C *)malloc(sizeof(struct PriSvc_MSG_B_C));
			//local time start
			os_get_time(&data->tv_Broadcast_start);
			iret = Broadcast(data->mpk, data->cred_key, data->cred_s, data->service_key,
							data->service_attr, data->bid, data->X_s, data->cipher,
							data->msg_b, data->z);
			if (iret != 0)
			{
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
						"prisvc.Broadcast  Erro iret =%d\n", iret);
				return NULL;
			}
			else
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc.Broadcast  pass\n");
			//local time end
			os_get_time(&data->tv_Broadcast_end);
			char buf_send[65536];
			int len_send;
			memset(buf_send, 0x00, sizeof(buf_send));
			len_send = 0;
			buf_send[len_send] = 0x01;
			len_send += 1;
			memcpy(buf_send + len_send, data->X_s, sizeof(struct ACME_X_C));
			len_send += sizeof(struct ACME_X_C);
			memcpy(buf_send + len_send, data->cipher, sizeof(struct ACME_CIPHER_C));
			len_send += sizeof(struct ACME_CIPHER_C);
			memcpy(buf_send + len_send, data->msg_b, sizeof(struct PriSvc_MSG_B_C));
			len_send += sizeof(struct PriSvc_MSG_B_C);
			// wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc_out_pos has %d bytes, used %d bytes\n", 
			// 	data->prisvc_out->size, data->prisvc_out->used);
			wpabuf_put_data(data->prisvc_out, buf_send, len_send);
			data->prisvc_out_pos = 0;
			wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: after Broadcast, "
					"%d bytes need to be sent\n", len_send);
			// wpa_hexdump(MSG_MSGDUMP, "EAP-VENDOR-TEST: prisvc data：", buf_send, 1400);
			// wpa_hexdump(MSG_MSGDUMP, "EAP-VENDOR-TEST: wpabuf_head_u8(data->prisvc_out)：",
			// 		wpabuf_head_u8(data->prisvc_out), 1400);
		}

		eap_vendor_test_state(data, Broadcast_MSG);
		// comm start
		os_get_time(&data->tv_Broadcast_comm_start);
		return eap_server_vendor_test_build_msg(sm, data, id);
	}
	else if (data->state == AMA_Cinit_MSG)
	{
		/*已收到完整的AMA_Cinit包，数据已放入data中，并生成AMA_S数据用于发送*/
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Generating AMA_S Request");
		if (data->prisvc_out == NULL)
		{
			wpa_printf(MSG_ERROR, "EAP-VENDOR-TEST: prisvc_out NULL in %s, start to generate AMA_S", __func__);

			/*int out_len = 1 + sizeof(struct PriSvc_S_C) + sizeof(struct PriSvc_SSK_C);*/
			int out_len = 1 + sizeof(struct PriSvc_S_C);

			data->prisvc_out = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE,
											 out_len, EAP_CODE_REQUEST, id);
			if (data->prisvc_out == NULL)
			{
				wpa_printf(MSG_ERROR, "EAP-VENDOR-TEST: Failed to allocate "
									  "memory for request");
				return NULL;
			}

			wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: "
					"/////////////// service receive and kaa  ////////////////////\n");
			data->S_msg = (struct PriSvc_S_C *)malloc(sizeof(struct PriSvc_S_C));
			data->ssk_s = (struct PriSvc_SSK_C *)malloc(sizeof(struct PriSvc_SSK_C));
			//local time start
			os_get_time(&data->tv_AMA_S_start);
			iret = AMA_S(data->mpk, data->cred_key, data->cred_s, data->service_key,
						data->z, data->service_attr, data->bid, data->Dk_S_xrec, data->DK_S_frec,
						data->X_s, data->X_c, data->C1_msg, data->S_msg, data->ssk_s);
			if (iret != 0)
			{
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.AMA_S  Erro iret =%d\n", iret);
				return NULL;
			}
			else
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.AMA_S  pass\n");
			//local time end
			os_get_time(&data->tv_AMA_S_end);
			char buf_send[65536];
			int len_send;
			memset(buf_send, 0x00, sizeof(buf_send));
			len_send = 0;
			buf_send[len_send] = 0x03;
			len_send += 1;
			memcpy(buf_send + len_send, data->S_msg, sizeof(struct PriSvc_S_C));
			len_send += sizeof(struct PriSvc_S_C);
			//delete ssk_s
			/*
			memcpy(buf_send + len_send, data->ssk_s, sizeof(struct PriSvc_SSK_C));
			len_send += sizeof(struct PriSvc_SSK_C);*/
			wpabuf_put_data(data->prisvc_out, buf_send, len_send);
			data->prisvc_out_pos = 0;
			wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: after AMA_S() %d bytes need to be sent\n", len_send);
		}

		eap_vendor_test_state(data, AMA_S_MSG);
		// comm2 start
		os_get_time(&data->tv_AMA_S_comm_start);
		return eap_server_vendor_test_build_msg(sm, data, id);
	}
	else if (data->state == Broadcast_MSG || data->state == AMA_S_MSG)
	{
		return eap_server_vendor_test_build_msg(sm, data, id);
	}
	else if (data->state == Broadcast_CONFIRM || data->state == AMA_S_CONFIRM) /*接收分片数据的状态*/
	{
		/*告知对方已收到数据，还有分片数据需要接收，简单反馈数据即可*/
		struct wpabuf *req;

		req = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, 1,
							EAP_CODE_REQUEST, id);
		if (req == NULL)
		{
			wpa_printf(MSG_ERROR, "EAP-VENDOR-TEST: Failed to allocate "
								  "memory for request");
			return NULL;
		}
		wpabuf_put_u8(req, data->state == Broadcast_CONFIRM ? 1 : 3);
		return req;
	}

	return NULL;
}

static Boolean eap_vendor_test_check(struct eap_sm *sm, void *priv,
									 struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;
	struct eap_vendor_test_data *data = priv;

	pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, respData, &len);
	if (pos == NULL || len < 1)
	{
		wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: Invalid frame");
		return TRUE;
	}
	/*
	if (*pos == '2')
	{
		if (len < (1 + sizeof(struct PriSvc_C1_C) + sizeof(struct ACME_X_C)))
		{
			wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: Invalid frame 2");
			return TRUE;
		}
		int len_recv = 1;
		memcpy(data->C1_msg, pos + len_recv, sizeof(struct PriSvc_C1_C));
		len_recv += sizeof(struct PriSvc_C1_C);
		memcpy(data->X_c, pos + len_recv, sizeof(struct ACME_X_C));
		len_recv += sizeof(struct ACME_X_C);
	}
	else if (*pos == '4')
	{
		if (len < (1 + sizeof(struct PriSvc_SSK_C)))
		{
			wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: Invalid frame 2");
			return TRUE;
		}
	}
*/
	return FALSE;
}

const u8 *eap_peer_vendor_test_process_init(struct eap_sm *sm, struct eap_vendor_test_data *data,
											struct wpabuf *respData, size_t *len, u8 *flags)
{
	const u8 *pos;
	size_t left;
	unsigned int msg_len;

	pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, respData, &left);
	if (pos == NULL)
	{
		return NULL;
	}
	if (left == 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Invalid prisvc message: no Flags "
							  "octet included");

		return NULL;
	}
	else
	{
		*flags = *pos++;
		left--;
	}

	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Received packet(len=%lu) - "
						  "Flags 0x%02x",
			   (unsigned long)wpabuf_len(respData),
			   *flags);
	if (*flags & EAP_PRISVC_FLAGS_LENGTH_INCLUDED)
	{
		if (left < 4)
		{
			wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: Short frame with prisvc "
								 "length");
			return NULL;
		}
		msg_len = WPA_GET_BE32(pos);
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: prisvc Message Length: %d",
				   msg_len);
		if (data->prisvc_in_left == 0)
		{
			data->prisvc_in_total = msg_len;
			data->prisvc_in_left = msg_len;
			wpabuf_free(data->prisvc_in);
			data->prisvc_in = NULL;
		}
		pos += 4;
		left -= 4;

		if (left > msg_len)
		{
			wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: prisvc Message Length (%d "
								 "bytes) smaller than this fragment (%d "
								 "bytes)",
					   (int)msg_len, (int)left);
			return NULL;
		}
	}

	*len = left;
	return pos;
}

/**
 * eap_peer_vendor_test_reset_input - Reset input buffers
 * @data: Data for prisvc processing
 *
 * This function frees any allocated memory for input buffers and resets input
 * state.
 */
void eap_peer_vendor_test_reset_input(struct eap_vendor_test_data *data)
{
	data->prisvc_in_left = data->prisvc_in_total = 0;
	wpabuf_free(data->prisvc_in);
	data->prisvc_in = NULL;
}

/**
 * eap_peer_vendor_test_reset_output - Reset output buffers
 * @data: Data for prisvc processing
 *
 * This function frees any allocated memory for output buffers and resets output
 * state.
 */
void eap_peer_vendor_test_reset_output(struct eap_vendor_test_data *data)
{
	data->prisvc_out_pos = 0;
	wpabuf_free(data->prisvc_out);
	data->prisvc_out = NULL;
}

/**
 * eap_server_vendor_test_build_msg - Reassemble a received fragment
 * @data: Data for VENDOR_TOR processing
 * @in_data: Next incoming PRISVC segment
 * Returns: 0 on success, 1 if more data is needed for the full message, or
 * -1 on error
 */
static int eap_peer_vendor_test_reassemble_fragment(struct eap_vendor_test_data *data,
													const struct wpabuf *in_data)
{
	size_t prisvc_in_len, in_len;

	prisvc_in_len = data->prisvc_in ? wpabuf_len(data->prisvc_in) : 0;
	in_len = in_data ? wpabuf_len(in_data) : 0;

	if (prisvc_in_len + in_len == 0)
	{
		/* No message data received?! */
		wpa_printf(MSG_WARNING, "EAP-VENDOR-TEST: Invalid reassembly state: "
								"prisvc_in_left=%lu prisvc_in_len=%lu in_len=%lu",
				   (unsigned long)data->prisvc_in_left,
				   (unsigned long)prisvc_in_len,
				   (unsigned long)in_len);
		eap_peer_vendor_test_reset_input(data);
		return -1;
	}

	if (prisvc_in_len + in_len > 65536)
	{
		/*
		 * Limit length to avoid rogue servers from causing large
		 * memory allocations.
		 */
		wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: Too long prisvc fragment (size over "
							 "64 kB)");
		eap_peer_vendor_test_reset_input(data);
		return -1;
	}

	if (in_len > data->prisvc_in_left)
	{
		/* Sender is doing something odd - reject message */
		wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: more data than prisvc message length "
							 "indicated");
		eap_peer_vendor_test_reset_input(data);
		return -1;
	}

	if (wpabuf_resize(&data->prisvc_in, in_len) < 0)
	{
		wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: Could not allocate memory for prisvc "
							 "data");
		eap_peer_vendor_test_reset_input(data);
		return -1;
	}
	if (in_data)
		wpabuf_put_buf(data->prisvc_in, in_data);
	data->prisvc_in_left -= in_len;

	if (data->prisvc_in_left > 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Need %lu bytes more input "
							  "data",
				   (unsigned long)data->prisvc_in_left);
		return 1;
	}

	return 0;
}

/**
 * eap_peer_vendor_test_data_reassemble - Reassemble prisvc data
 * @data: Data for prisvc processing
 * @in_data: Next incoming prisvc segment
 * @need_more_input: Variable for returning whether more input data is needed
 * to reassemble this prisvc packet
 * Returns: Pointer to output data, %NULL on error or when more data is needed
 * for the full message (in which case, *need_more_input is also set to 1).
 *
 * This function reassembles prisvc fragments. Caller must not free the returned
 * data buffer since an internal pointer to it is maintained.
 */
static const struct wpabuf *eap_peer_vendor_test_data_reassemble(
	struct eap_vendor_test_data *data, const struct wpabuf *in_data,
	int *need_more_input)
{
	*need_more_input = 0;

	if (data->prisvc_in_left > wpabuf_len(in_data) || data->prisvc_in)
	{
		/* Message has fragments */
		int res = eap_peer_vendor_test_reassemble_fragment(data, in_data);
		if (res)
		{
			if (res == 1)
				*need_more_input = 1;
			return NULL;
		}

		/* Message is now fully reassembled. */
	}
	else
	{
		/* No fragments in this message, so just make a copy of it. */
		data->prisvc_in_left = 0;
		data->prisvc_in = wpabuf_dup(in_data);
		if (data->prisvc_in == NULL)
			return NULL;
	}

	return data->prisvc_in;
}

/**
 * eap_vendor_test_process_input - Process incoming prisvc message
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Data for prisvc processing
 * @in_data: Message received from the server/peer
 * @out_data: Buffer for returning a pointer to application data (if available)
 * Returns: 0 on success, 1 if more input data is needed,  -1 on failure
 */
static int eap_vendor_test_process_input(struct eap_sm *sm,
										 struct eap_vendor_test_data *data,
										 const struct wpabuf *in_data,
										 struct wpabuf **out_data)
{
	const struct wpabuf *msg;
	int need_more_input;

	msg = eap_peer_vendor_test_data_reassemble(data, in_data, &need_more_input);
	/*when Message is fully reassembled, msg is not null*/
	if (msg == NULL)
		return need_more_input ? 1 : -1;

	/* Full  message reassembled*/
	if (data->prisvc_out)
	{
		/* This should not happen.. */
		wpa_printf(MSG_INFO, "EAP-VENDOR-TEST: eap_vendor_test_process_input - pending "
							 "prisvc_out data");
		wpabuf_free(data->prisvc_out);
		WPA_ASSERT(data->prisvc_out == NULL);
	}
	/*
	eap_peer_vendor_test_reset_input(data);*/

	return 0;
}

static void eap_vendor_test_process(struct eap_sm *sm, void *priv,
									struct wpabuf *respData)
{
	struct eap_vendor_test_data *data = priv;
	const u8 *pos;
	size_t len;
	size_t left;
	u8 flags;
	struct wpabuf msg;
	struct wpabuf *resp;
	/*如果是第一个分片，则会将总长度保存到prisvc_in_total中
	所有情况下：
	返回的pos为真实数据的其实位置，即flag之后的数据
	left为未接收的数据长度（不含本次接收的数据）
	*/
	pos = eap_peer_vendor_test_process_init(sm, data, respData,
											&left, &flags);

	/*在flag之后，没有其他数据，则为分片数据的响应报文，
	表示还需要继续发送分片报文，此处直接返回，通过状态机，进入buildReq方法继续发送数据
	当然还有可能是出现异常了，这里暂不考虑*/
	if (pos == NULL || left < 1)
		return;

	wpabuf_set(&msg, pos, left);
	resp = NULL;
	/*将收到的分片数据合并到prisvc_in中
	res返回1：还有分片数据未接收。-1：接收到的数据异常。0：已接收到所有分片数据
	*/
	int iret;
	iret = eap_vendor_test_process_input(sm, data, &msg, &resp);
	if (iret < 0)
	{
		wpa_printf(MSG_DEBUG,
				   "EAP-VENDOR-TEST: process input processing failed");
		return;
	}
	else if (iret == 0) /*数据已接收完整*/
	{
		const u8 *in_pos;
		const u8 *in_pos2;
		in_pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, data->prisvc_in, &len);
		if (in_pos == NULL || len < 1)
			return;
		if (data->state == Broadcast_CONFIRM) /**/
		{
			if (*in_pos == 2)
			{
				wpa_printf(MSG_DEBUG,
				   "EAP-VENDOR-TEST: receive all data,length is %d", len);
				data->C1_msg = (struct PriSvc_C1_C *)malloc(sizeof(struct PriSvc_C1_C));
				data->X_c = (struct ACME_X_C *)malloc(sizeof(struct ACME_X_C));
				/*收到完整数据，将数据放入到data中*/
				int len_recv = 1;
				memcpy(data->C1_msg, in_pos + len_recv, sizeof(struct PriSvc_C1_C));
				len_recv += sizeof(struct PriSvc_C1_C);
				memcpy(data->X_c, in_pos + len_recv, sizeof(struct ACME_X_C));
				len_recv += sizeof(struct ACME_X_C);
				eap_vendor_test_state(data, AMA_Cinit_MSG);
				eap_peer_vendor_test_reset_input(data);
			}
			else
				eap_vendor_test_state(data, FAILURE);
		}
		else if (data->state == AMA_S_MSG)
		{
			if (*in_pos == 4)
			{
				// total time end - wpa init time
				os_get_time(&data->tv_total_end);
				//完成全部数据的交互，计算各时间段消耗
				struct os_time tv_total_diff;		   /*总过程的时间消耗*/
				struct os_time tv_Broadcast_diff;	   /*Broadcast过程的时间消耗*/
				struct os_time tv_Broadcast_comm_diff; /*Broadcast包发送的时间消耗*/
				struct os_time tv_AMA_S_diff;		   /*AMA_S过程的时间消耗*/
				struct os_time tv_AMA_S_comm_diff;	   /*AMA_S包发送的时间消耗*/
				os_time_sub(&data->tv_total_end, &data->tv_total_start, &tv_total_diff);
				os_time_sub(&data->tv_Broadcast_end, &data->tv_Broadcast_start, &tv_Broadcast_diff);
				os_time_sub(&data->tv_Broadcast_comm_end, &data->tv_Broadcast_comm_start, &tv_Broadcast_comm_diff);
				os_time_sub(&data->tv_AMA_S_end, &data->tv_AMA_S_start, &tv_AMA_S_diff);
				os_time_sub(&data->tv_AMA_S_comm_end, &data->tv_AMA_S_comm_start, &tv_AMA_S_comm_diff);
				wpa_printf(MSG_DEBUG,
						   "EAP-VENDOR-TEST: "
							"   tv_total_diff is %ld seconds %ld microseconds,"
						   "tv_Broadcast_diff is %ld seconds %ld microseconds,"
						   "tv_Broadcast_comm_diff is % ld seconds %ld microseconds,"
						   "tv_AMA_S_diff is %ld seconds %ld microseconds,"
						   "tv_AMA_S_comm_diff is %ld seconds %ld microseconds ", 	
						   tv_total_diff.sec, tv_total_diff.usec,
						tv_Broadcast_diff.sec, tv_Broadcast_diff.usec,
						   tv_Broadcast_comm_diff.sec, tv_Broadcast_comm_diff.usec,
						   tv_AMA_S_diff.sec, tv_AMA_S_diff.usec,
						   tv_AMA_S_comm_diff.sec, tv_AMA_S_comm_diff.usec);
				/*收到完整数据，进入SUCCESS状态*/
				eap_vendor_test_state(data, SUCCESS);
			}
			else
				eap_vendor_test_state(data, FAILURE);
		}
		else
			eap_vendor_test_state(data, FAILURE);
	}
	else
	{
		/*还有分片数据未接收，此时状态应该是Broadcast_MSG或者AMA_S_MSG，
		可以将状态修改为CONFIRM后，直接返回，进入buildReq方法组织数据，返回给对端，等待进一步的数据*/
		if (data->state == Broadcast_MSG) /**/
		{
			eap_vendor_test_state(data, Broadcast_CONFIRM);
		}
		else if (data->state == AMA_S_MSG)
		{ /*sta在执行AMA_Cverify()后，需要发送的数据量比较小，无需分片，因此没有这种情况*/
			eap_vendor_test_state(data, AMA_S_CONFIRM);
		}
		return;
	}
}

static Boolean eap_vendor_test_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	return data->state == SUCCESS;
}

static u8 *eap_vendor_test_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_vendor_test_data *data = priv;
	u8 *key;
	const int key_len = 64;

	if (data->state != SUCCESS)
		return NULL;

	key = os_malloc(key_len);
	if (key == NULL)
		return NULL;

	os_memset(key, 0x11, key_len / 2);
	os_memset(key + key_len / 2, 0x22, key_len / 2);
	*len = key_len;

	return key;
}

static Boolean eap_vendor_test_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	return data->state == SUCCESS;
}

int eap_server_vendor_test_register(void)
{
	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
								  EAP_VENDOR_ID, EAP_VENDOR_TYPE,
								  "VENDOR-TEST");
	if (eap == NULL)
		return -1;

	eap->init = eap_vendor_test_init;
	eap->reset = eap_vendor_test_reset;
	eap->buildReq = eap_vendor_test_buildReq;
	eap->check = eap_vendor_test_check;
	eap->process = eap_vendor_test_process;
	eap->isDone = eap_vendor_test_isDone;
	eap->getKey = eap_vendor_test_getKey;
	eap->isSuccess = eap_vendor_test_isSuccess;

	return eap_server_method_register(eap);
}
