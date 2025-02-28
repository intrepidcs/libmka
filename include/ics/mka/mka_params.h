/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ICS_MKA_PARAMS_H
#define ICS_MKA_PARAMS_H

#include "ics/mka/mka_utility.h"
#include "ics/mka/mka_result.h"
#include "ics/mka/mka_state.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mka_params_type {
	MKA_PARAMS_BASIC = 0,
	MKA_PARAMS_ACTIVE_LIST = 1,
	MKA_PARAMS_POTENTIAL_LIST = 2,
	MKA_PARAMS_SAK_USE = 3,
	MKA_PARAMS_DISTRIBUTED_SAK = 4,
	MKA_PARAMS_DISTRIBUTED_CAK = 5,
	MKA_PARAMS_KMD = 6,
	MKA_PARAMS_ANNOUNCEMENT = 7,
	MKA_PARAMS_XPN = 8,
	MKA_PARAMS_ICV_INDICATOR = 255
} mka_params_type_t;

typedef enum mka_announcement_type {
	MKA_ANNOUNCEMENT_CIPHER_SUITE = 112,
} mka_announcement_type_t;

typedef struct mka_params_info {
	u16 length;
	u16 offset;
	bool found;
	mka_params_type_t type;
} mka_params_info_t;

typedef struct mka_basic_params {
	u8 version;
	u8 priority;
	union {
		struct {
			u8 : 4;
			u8 macsec_capability : 2;
			u8 macsec_desired : 1;
			u8 key_server : 1;
		} flags;
		u8 data; 
	} attribs;
	u64 sci;
	mka_actor_id_t id;
	u32 message_id;
	u32 algorithm_agility;
	u16 ckn_length;
	const u8* ckn;
} mka_basic_params_t;

typedef struct mka_peer_list {
	u8 ssci;
	u16 count;
	const u8* list_start; // This is just a pointer to the latest ether frame
} mka_peer_list_t;

typedef struct mka_sak_use {
	union {
		struct {
			u8 old_key_rx : 1;
			u8 old_key_tx : 1;
			u8 old_key_an : 2;
			u8 latest_key_rx : 1;
			u8 latest_key_tx : 1;
			u8 latest_key_an : 2;
			u8 : 4;
			u8 delay_protect : 1;
			u8 : 1;
			u8 plain_rx : 1;
			u8 plain_tx : 1;
		} flags;
		u8 data[2]; 
	} attribs;
	mka_actor_id_t latest_key_server_id;
	u32 latest_key_number;
	u32 latest_lapn; // lapn = lowest acceptable PN
	mka_actor_id_t old_key_server_id;
	u32 old_key_number;
	u32 old_lapn; // lapn = lowest acceptable PN
} mka_sak_use_t;

typedef struct mka_distributed_sak {
	union {
		struct {
			u8 : 4;
			u8 confidentiality_offset : 2;
			u8 distributed_an : 2;
		} flags;
		u8 data; 
	} attribs;
	u32 key_number;
	u64 cipher_suite;
	mka_wrapped_sak_t sak; // The AES encoded SAK	
} mka_distributed_sak_t;

typedef struct mka_distributed_cak {
	mka_wrapped_cak_t cak;
	u16 ckn_length;
	const u8* ckn;
} mka_distributed_cak_t;

typedef struct mka_kmd {
	u16 kmd_length;
	const u8* kmd;		
} mka_kmd_t;

typedef struct mka_announcement {
	u16 tlvs_length;
	const u8* tlvs;	
} mka_announcement_t;

typedef struct mka_xpn {
	u8 mka_suspension_time;
	u32 latest_lapn;
	u32 old_lapn; // msb lapn = lowest acceptable PN
} mka_xpn_t;

typedef struct mka_params {
	mka_params_type_t type;
	union {
		mka_basic_params_t basic;
		mka_peer_list_t peer_list;
		mka_sak_use_t sak_use;
		mka_distributed_sak_t distributed_sak;
		mka_distributed_cak_t distributed_cak;
		mka_kmd_t kmd;
		mka_announcement_t announcement;
		mka_xpn_t xpn;
	} body;
} mka_params_t;

extern mka_params_type_t idx_to_params_type[MKA_PARAMS_TYPE_COUNT];

mka_result_t ics_mka_decode_params_size(const u8* packet_body, u16 length, u16* size);
mka_result_t ics_mka_decode_params(const mka_state_t* state, const u8* packet_body, u16 length, u16* length_read, mka_params_t* params, bool is_basic);
mka_result_t ics_mka_encode_params(const mka_state_t* state, u8* packet_body, u16 length, u16* length_wrote, mka_params_type_t type);
u16 ics_mka_encoded_length(const mka_state_t* state, mka_params_type_t type);
mka_result_t ics_mka_read_basic_params(const mka_state_t* state, const mka_eth_message_t* msg, mka_params_t* basic_params, u16* cur);
mka_result_t ics_mka_get_params_info(const mka_eth_message_t* msg, mka_params_info_t info[MKA_PARAMS_TYPE_COUNT]);


#ifdef __cplusplus
}
#endif
#endif