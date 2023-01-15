/*
 * EAP peer method: Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements a vendor specific test method using EAP expanded types.
 * This is only for test use and must not be used for authentication since no
 * security is provided.
 */

#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "eloop.h"
#include "prisvc_export.h"

#define EAP_VENDOR_ID EAP_VENDOR_HOSTAP
#define EAP_VENDOR_TYPE 0xfcfbfaf9

/* EAP PRISVC Flags */
#define EAP_PRISVC_FLAGS_LENGTH_INCLUDED 0x80
#define EAP_PRISVC_FLAGS_MORE_FRAGMENTS 0x40
#define EAP_PRISVC_FLAGS_START 0x20

#define EAP_PRISVC_SEND_LIMIT 1470

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
		AMA_Cverify_MSG, 
		SUCCESS,
		FAILURE
	} state;
	int first_try;
	int test_pending_req;
	enum
	{
		MSG,
		FRAG_ACK,
		WAIT_FRAG_ACK

	} prisvc_state;/*用于标示需要分片发送数据包时的发送状态*/
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
	struct ACME_USER_KEY_C *client_key;
	struct USER_ATTR_C *client_attr;
	struct Big_C *sid;
	struct ACME_SPK1_C *spk1;
	struct ACME_CRED_U_C *cred_c;
	struct ACME_USER_PK_C *client_key_upk;
	struct ACME_X_C *X_s;
	struct ACME_ABE_DK_X_REC_C *Dk_C_xrec;
	struct ACME_ABE_DK_f_REC_C *DK_C_frec;
	struct Big_C *z;
	struct ACME_CIPHER_C *cipher;
	struct PriSvc_MSG_B_C *msg_b;
	struct PriSvc_S_C *S_msg;
	struct PriSvc_SSK_C *ssk_c;
	struct PriSvc_SSK_C *ssk_s;
	struct PriSvc_C1_C *C1_msg;
	struct ACME_X_C *X_c;
	struct os_time tv_init_start;//init的起始时间
struct os_time tv_init_end;//init的结束时间

struct os_time tv_AMA_Cinit_start;//AMA_C过程的起始时间
struct os_time tv_AMA_Cinit_end;//AMA_C过程的结束时间

struct os_time tv_AMA_Cverify_start;//AMA_Cverify过程的起始时间
struct os_time tv_AMA_Cverify_end;//AMA_Cverify过程的结束时间
};

static void *eap_vendor_test_init(struct eap_sm *sm)
{
	
	
	struct eap_vendor_test_data *data;
	const u8 *password;
	size_t password_len;
	int ret;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	//wpa init time start
	os_get_time(&data->tv_init_start);
	// system init
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
		"/////////////// system setup  ////////////////////\n");
	struct ACME_MPK_C *mpk = (struct ACME_MPK_C *)malloc(sizeof(struct ACME_MPK_C));
	struct ACME_MSK_C *msk = (struct ACME_MSK_C *)malloc(sizeof(struct ACME_MSK_C));

	ret = SetUp(mpk, msk);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
			"prisvc.SetUp Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
			"prisvc.SetUp pass\n");

	data->mpk = mpk;
	data->msk = msk;

	struct ACME_CRED_KEY_C *cred_key = (struct ACME_CRED_KEY_C *)malloc(sizeof(struct ACME_CRED_KEY_C));
	ret = CredKeyGen(cred_key);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
			"prisvc.CredKeyGen Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
			"prisvc.CredKeyGen pass\n");
	data->cred_key = cred_key;

	struct ACME_CRED_KEY_PK_C *cred_key_pk = (struct ACME_CRED_KEY_PK_C *)malloc(sizeof(struct ACME_CRED_KEY_PK_C));
	memcpy(&(cred_key_pk->pk), &(cred_key->pk), sizeof(struct ABCT_CRED_KEY_PK_C));
	data->cred_key_pk = cred_key_pk;

	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
			"/////////////// client setup  ////////////////////\n");

	struct ACME_USER_KEY_C *client_key = (struct ACME_USER_KEY_C *)malloc(sizeof(struct ACME_USER_KEY_C));
	ret = UserKeyGen(client_key);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.client_key KeyGen Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.client_key KeyGen pass\n");

	data->client_key = client_key;

	struct USER_ATTR_C *client_attr = (struct USER_ATTR_C *)malloc(sizeof(struct USER_ATTR_C));
	struct Big_C *sid = (struct Big_C *)malloc(sizeof(struct Big_C));
	struct ACME_SPK1_C *spk1 = (struct ACME_SPK1_C *)malloc(sizeof(struct ACME_SPK1_C));
	ret = Issue_Send(client_key, client_attr, sid, spk1);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.Issue_Send client Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.Issue_Send client pass\n");

	data->client_attr = client_attr;
	data->sid = sid;
	data->spk1 = spk1;

	struct ACME_CRED_U_C *cred_c = (struct ACME_CRED_U_C *)malloc(sizeof(struct ACME_CRED_U_C));
	struct ACME_USER_PK_C *client_key_upk = (struct ACME_USER_PK_C *)malloc(sizeof(struct ACME_USER_PK_C));
	memcpy(&(client_key_upk->upk), &(client_key->upk), sizeof(struct ABCT_USER_PK_C));
	ret = Issue_Issuer(cred_key, client_attr, sid, spk1, client_key_upk, cred_c);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.Issue_Issuer client Erro ret =%d\n", ret);
		return 1;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.Issue_Issuer client pass\n");

	data->cred_c = cred_c;
	data->client_key_upk = client_key_upk;

	ret = Issue_Verify(cred_key_pk, cred_c, client_attr, sid, client_key);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.Issue_Verify client Erro ret =%d\n", ret);
		return 1;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.Issue_Verify client pass\n");
	struct ACME_X_C *X_c = (struct ACME_X_C *)malloc(sizeof(struct ACME_X_C));
	struct ACME_ABE_DK_X_REC_C *Dk_C_xrec = (struct ACME_ABE_DK_X_REC_C *)malloc(sizeof(struct ACME_ABE_DK_X_REC_C));
	ret = DKeyGen(msk, X_c, Dk_C_xrec);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.DKeyGen client Erro ret =%d", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.DKeyGen client pass\n");

	data->X_c = X_c;
	data->Dk_C_xrec = Dk_C_xrec;

	struct ACME_ABE_DK_f_REC_C *DK_C_frec = (struct ACME_ABE_DK_f_REC_C *)malloc(sizeof(struct ACME_ABE_DK_f_REC_C));
	ret = PolGen(msk, DK_C_frec);
	if (ret != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
				"prisvc.PolGen client Erro ret =%d\n", ret);
		return NULL;
	}
	else
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.PolGen client pass\n");

	data->DK_C_frec = DK_C_frec;

	data->state = INIT;
	data->first_try = 1;

	password = eap_get_config_password(sm, &password_len);
	data->test_pending_req = password && password_len == 7 &&
							 os_memcmp(password, "pending", 7) == 0;
	//wpa init time end
	os_get_time(&data->tv_init_end);
	return data;
}

static void eap_vendor_test_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	os_free(data->mpk);
	os_free(data->msk);
	os_free(data->cred_key);
	os_free(data->cred_key_pk);
	os_free(data->client_key);
	os_free(data->client_attr);
	os_free(data->sid);
	os_free(data->spk1);
	os_free(data->cred_c);
	os_free(data->client_key_upk);
	os_free(data->X_s);
	os_free(data->Dk_C_xrec);
	os_free(data->DK_C_frec);
	os_free(data->z);
	os_free(data->cipher);
	os_free(data->msg_b);
	os_free(data->S_msg);
	os_free(data->ssk_c);
	os_free(data->ssk_s);
	os_free(data->C1_msg);
	os_free(data->X_c);
	eap_peer_vendor_test_reset_input(data);
	eap_peer_vendor_test_reset_output(data);
	os_free(data);
}

static void eap_vendor_ready(void *eloop_ctx, void *timeout_ctx)
{
	struct eap_sm *sm = eloop_ctx;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Ready to re-process pending "
						  "request");
	eap_notify_pending(sm);
}

/**
 * eap_peer_vendor_test_build_ack - Build a prisvc ACK frame
 * @data:
 * @reqData: input
 * Returns: Pointer to the allocated ACK frame or %NULL on failure
 */
struct wpabuf *eap_peer_vendor_test_build_ack(struct eap_vendor_test_data *data,
											  const struct wpabuf *reqData)
{
	struct wpabuf *resp;
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, 1,
						 EAP_CODE_RESPONSE, eap_get_id(reqData));

	if (resp == NULL)
		return NULL;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:: Building ACK (type=%d id=%d)",
			   (int)EAP_VENDOR_TYPE, eap_get_id(reqData));
	wpabuf_put_u8(resp, data->state == INIT ? 1 : 3);
	return resp;
}



struct wpabuf *eap_vendor_test_build_msg(struct eap_sm *sm, struct eap_vendor_test_data *data,
												const struct wpabuf *reqData)
{
	struct wpabuf *resp;
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
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, plen,
						 EAP_CODE_RESPONSE, eap_get_id(reqData));
	if (resp == NULL)
		return NULL;

	wpabuf_put_u8(resp, flags); /* Flags */
	if (flags & EAP_PRISVC_FLAGS_LENGTH_INCLUDED)
		wpabuf_put_be32(resp, wpabuf_len(data->prisvc_out));

	wpabuf_put_data(resp, wpabuf_head_u8(data->prisvc_out) + data->prisvc_out_pos,
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
		/*全部发送完成后，更新状态*/
		data->state = data->state == AMA_Cinit_MSG ? AMA_S_MSG:SUCCESS;
		if(data->state == SUCCESS)
		{
			//完成全部数据的交互，计算各时间段消耗
				struct os_time tv_init_diff;/*init的时间消耗*/
				struct os_time tv_AMA_Cinit_diff;/*AMA_Cinit过程的时间消耗*/
				struct os_time tv_AMA_Cverify_diff;/*AMA_Cverify过程的时间消耗*/
				os_time_sub(&data->tv_init_end, &data->tv_init_start, &tv_init_diff);
				os_time_sub(&data->tv_AMA_Cinit_end, &data->tv_AMA_Cinit_start, &tv_AMA_Cinit_diff);
				os_time_sub(&data->tv_AMA_Cverify_end, &data->tv_AMA_Cverify_start, &tv_AMA_Cverify_diff);
				wpa_printf(MSG_DEBUG,
				   "EAP-VENDOR-TEST: "
				   		"tv_init_diff is %ld seconds %ld microseconds,"
						"tv_AMA_Cinit_diff is %ld seconds %ld microseconds,"
						"tv_AMA_Cverify_diff is %ld seconds %ld microseconds"
				   , 	tv_init_diff.sec, tv_init_diff.usec,
				   		tv_AMA_Cinit_diff.sec, tv_AMA_Cinit_diff.usec,
						tv_AMA_Cverify_diff.sec, tv_AMA_Cverify_diff.usec);
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

	return resp;
}


const u8 *eap_vendor_test_process_init(struct eap_sm *sm, struct eap_vendor_test_data *data,
											 struct eap_method_ret *ret,
											 const struct wpabuf *reqData,
											 size_t *len, u8 *flags)
{
	const u8 *pos;
	size_t left;
	unsigned int msg_len;

	pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, reqData, &left);
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
			   (unsigned long)wpabuf_len(reqData),
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
 * eap_peer_tls_reset_input - Reset input buffers
 * @data: Data for TLS processing
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
		/* Message has fragments 
		0 on success, 1 if more data is needed for the full message, or
 		* -1 on error	*/
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
 * Returns: 0 on success(Message is fully reassembled), 1 if more input data is needed,  -1 on failure
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
	/*msg is not null, Message is fully reassembled, 
	data->prisvc_in can free
	eap_peer_vendor_test_reset_input(data);*/

	return 0;
}

static struct wpabuf *eap_vendor_test_process(struct eap_sm *sm, void *priv,
											  struct eap_method_ret *ret,
											  const struct wpabuf *reqData)
{
	struct eap_vendor_test_data *data = priv;
	struct wpabuf *resp;
	const u8 *pos;
	size_t len;
	size_t left;
	struct wpabuf msg;
	u8 flags;
	/*
	pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, reqData, &len);
	if (pos == NULL || len < 1)
	{
		ret->ignore = TRUE;
		return NULL;
	}*/

	/*如果是第一个分片，则会将总长度保存到prisvc_in_total中
	所有情况下：
	返回的pos为真实数据的其实位置，即flag之后的数据
	left为未接收的数据长度（不含本次接收的数据）
	*/
	pos = eap_vendor_test_process_init(sm, data, EAP_TYPE_PEAP, reqData,
											 &left, &flags);

	/*在flag之后，没有其他数据，则为分片数据的响应报文，
	表示还需要继续发送分片报文
	当然还有可能是出现异常了，这里暂不考虑*/
	if (pos == NULL || left < 1)
	{
		if(data->prisvc_state == WAIT_FRAG_ACK)
		{
			/*发送AMA_Cinit()、AMA_Cverify()执行后数据的分片包*/
			return eap_vendor_test_build_msg(sm ,data, reqData);
		}
		ret->ignore = TRUE;
		return NULL;
	}

	wpabuf_set(&msg, pos, left);
	resp = NULL;
	/*将收到的分片数据合并到prisvc_in中
	res返回1：还有分片数据未接收。-1：接收到的数据异常。0：已接收到所有分片数据
	*/
	int res;
	res = eap_vendor_test_process_input(sm, data, &msg, &resp);
	//
	if (res < 0)
	{
		/*接收到的数据异常*/
		wpa_printf(MSG_DEBUG,
				   "EAP-VENDOR-TEST: process input failed");
		ret->ignore = TRUE;
		return NULL;
	}
	else if (res == 0) /*数据已接收完整*/
	{
		const u8 *in_pos;
		in_pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, data->prisvc_in, &len);
		if (in_pos == NULL || len < 1)
		{
			ret->ignore = TRUE;
			return NULL;
		}
		// wpa_hexdump(MSG_MSGDUMP, "in_pos:",
		//     	in_pos, 100);
		if (data->state == Broadcast_CONFIRM) /**/
		{
			// wpa_hexdump(MSG_MSGDUMP, "data->prisvc_in",
		    // 	wpabuf_head(data->prisvc_in), 100);
			// wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: size is : %d, used: %d", 
			// 	wpabuf_size(data->prisvc_in),wpabuf_len(data->prisvc_in));

			if (*in_pos == 1)
			{
				/*收到完整数据，将数据放入到data中，并生成数据准备用于发送*/
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
						"/////////////// client receive and init  ////////////////////\n");
				data->X_s = (struct ACME_X_C *)malloc(sizeof(struct ACME_X_C));
				data->cipher = (struct ACME_CIPHER_C *)malloc(sizeof(struct ACME_CIPHER_C));
				data->msg_b = (struct PriSvc_MSG_B_C *)malloc(sizeof(struct PriSvc_MSG_B_C));
				int len_recv = 1;
				memcpy(data->X_s, in_pos + len_recv, sizeof(struct ACME_X_C));
				len_recv += sizeof(struct ACME_X_C);
				memcpy(data->cipher, in_pos + len_recv, sizeof(struct ACME_CIPHER_C));
				len_recv += sizeof(struct ACME_CIPHER_C);
				memcpy(data->msg_b, in_pos + len_recv, sizeof(struct PriSvc_MSG_B_C));
				len_recv += sizeof(struct PriSvc_MSG_B_C);

				eap_peer_vendor_test_reset_input(data);

				data->C1_msg = (struct PriSvc_C1_C *)malloc(sizeof(struct PriSvc_C1_C));
				//local time start
				os_get_time(&data->tv_AMA_Cinit_start);
				int iret = AMA_Cinit(data->mpk, data->cred_key, data->cred_c, data->client_key,
									 data->Dk_C_xrec, data->DK_C_frec, data->X_s, data->X_c, data->client_attr,
									 data->sid, data->cipher, data->msg_b, data->C1_msg);
				if (iret != 0)
				{
					wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
							"prisvc.AMA_Cinit  Erro iret =%d\n", iret);
					ret->ignore = TRUE;
					return NULL;
				}
				else
					wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
							"prisvc.AMA_Cinit  pass\n");
				//local time end
				os_get_time(&data->tv_AMA_Cinit_end);
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Generating Response");

				char buf_send[65536];
				int len_send;
				int outlen = 1 + sizeof(struct PriSvc_C1_C) + sizeof(struct ACME_X_C);
				ret->allowNotifications = TRUE;
				data->prisvc_out = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, outlen,
									 EAP_CODE_RESPONSE, eap_get_id(reqData));

				memset(buf_send, 0x00, sizeof(buf_send));
				buf_send[0] = 0x02;
				len_send = 1;
				memcpy(buf_send + len_send, data->C1_msg, sizeof(struct PriSvc_C1_C));
				len_send += sizeof(struct PriSvc_C1_C);
				memcpy(buf_send + len_send, data->X_c, sizeof(struct ACME_X_C));
				len_send += sizeof(struct ACME_X_C);
				wpabuf_put_data(data->prisvc_out, buf_send, len_send);
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: "
						"after AMA_Cinit() %d bytes need to be sent\n", len_send);
				data->prisvc_out_limit = EAP_PRISVC_SEND_LIMIT;
				data->prisvc_out_pos = 0;

				data->state = AMA_Cinit_MSG;/*开始发送数据*/
				ret->methodState = METHOD_CONT;
				ret->decision = DECISION_FAIL;
				/*返回第一个分包数据*/
				return eap_vendor_test_build_msg(sm, data, reqData);
			}
			else
			{
				ret->ignore = TRUE;
				return NULL;
			}
		}
		else if (data->state == AMA_S_CONFIRM)
		{
			// wpa_hexdump(MSG_MSGDUMP, "EAP-VENDOR-TEST: data->prisvc_in 2",
		    // 	wpabuf_head(data->prisvc_in), 100);
			
			if (*in_pos == 3)
			{
				/*收到完整数据，将数据放入到data中，并生成数据准备用于发送*/
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
						"/////////////// client receive and kaa  ////////////////////\n");
				data->S_msg = (struct PriSvc_S_C *)malloc(sizeof(struct PriSvc_S_C));
				/*data->ssk_s = (struct PriSvc_SSK_C *)malloc(sizeof(struct PriSvc_SSK_C));*/

				int len_recv = 1;
				memcpy(data->S_msg, in_pos + len_recv, sizeof(struct PriSvc_S_C));
				len_recv += sizeof(struct PriSvc_S_C);
				/*
				memcpy(data->ssk_s, in_pos + len_recv, sizeof(struct PriSvc_SSK_C));
				len_recv += sizeof(struct PriSvc_SSK_C);*/

				data->ssk_c = (struct PriSvc_SSK_C *)malloc(sizeof(struct PriSvc_SSK_C));
				//local time start
				os_get_time(&data->tv_AMA_Cverify_start);
				int iret = AMA_Cverify(data->mpk, data->cred_key, data->cred_c, data->client_key,
						  data->Dk_C_xrec, data->DK_C_frec, data->X_s, data->X_c, data->client_attr,
						  data->sid, data->C1_msg, data->S_msg, data->ssk_c);
				if (iret != 0)
				{
					wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
							"prisvc.AMA_Cverify  Erro iret =%d\n", iret);
					ret->ignore = TRUE;
					return NULL;
				}
				else
					wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
							"prisvc.AMA_Cverify  pass\n");
				//local time end
				os_get_time(&data->tv_AMA_Cverify_end);
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Generating Response");

				char buf_send[65536];
				int len_send;
				int ilen = 1 + sizeof(struct PriSvc_SSK_C);
				ret->allowNotifications = TRUE;
				data->prisvc_out = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, ilen,
									 EAP_CODE_RESPONSE, eap_get_id(reqData));

				memset(buf_send, 0x00, sizeof(buf_send));
				buf_send[0] = 0x04;
				len_send = 1;
				memcpy(buf_send + len_send, data->ssk_c, sizeof(struct PriSvc_SSK_C));
				len_send += sizeof(struct PriSvc_SSK_C);
				wpabuf_put_data(data->prisvc_out, buf_send, len_send);
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:"
						"after AMA_Cverify() %d bytes need to be sent\n", len_send);
				/*
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:
						/////////////// key  ////////////////////\n");
				for (int i = 0; i < 4; i++)
				{
					if (data->ssk_c->ssk.w[i] != data->ssk_s->ssk.w[i])
						wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:kaa erro!\n");
				}
				wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST:prisvc.Kaa success!\n");
				*/
				data->prisvc_out_limit = EAP_PRISVC_SEND_LIMIT;
				data->prisvc_out_pos = 0;

				data->state = AMA_Cverify_MSG;/*开始发送数据*/
				ret->methodState = METHOD_CONT;
				ret->decision = DECISION_FAIL;
				/*返回第一个分包数据，实际上无须分包*/
				data->state = SUCCESS;
				ret->methodState = METHOD_DONE;
				ret->decision = DECISION_UNCOND_SUCC;
				return eap_vendor_test_build_msg(sm, data, reqData);
			}
			else
				data->state = FAILURE;
		}
		else
			data->state = FAILURE;
	}
	else
	{
		/*还有分片数据未接收，此时状态应该是INIT或者Broadcast_MSG，
		可以将状态修改为Broadcast_CONFIRM后，直接组织数据返回给对端，等待进一步的数据*/
		if (data->state == INIT || data->state == Broadcast_CONFIRM) /**/
		{
			data->state = Broadcast_CONFIRM;
			return eap_peer_vendor_test_build_ack(data, reqData);
		}
		else if (data->state == AMA_S_MSG || data->state == AMA_S_CONFIRM) /**/
		{
			data->state = AMA_S_CONFIRM;
			return eap_peer_vendor_test_build_ack(data, reqData);
		}
		
		return NULL;
	}

	return resp;
}

static Boolean eap_vendor_test_isKeyAvailable(struct eap_sm *sm, void *priv)
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

int eap_peer_vendor_test_register(void)
{
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
								EAP_VENDOR_ID, EAP_VENDOR_TYPE,
								"VENDOR-TEST");
	if (eap == NULL)
		return -1;

	eap->init = eap_vendor_test_init;
	eap->deinit = eap_vendor_test_deinit;
	eap->process = eap_vendor_test_process;
	eap->isKeyAvailable = eap_vendor_test_isKeyAvailable;
	eap->getKey = eap_vendor_test_getKey;

	return eap_peer_method_register(eap);
}
