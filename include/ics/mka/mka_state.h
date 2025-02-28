/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ICS_MKA_STATE_H
#define ICS_MKA_STATE_H

#include "ics/mka/mka_utility.h"

#define MKA_EAPOL_TYPE 5
#define MKA_EAPOL_HEADER_LENGTH 4
#define MKA_HEADER_LENGTH 4
#define MKA_MAX_PARAM_BODY 1492 // This is the maximum that the parameter body can be
#define MKA_MTU_ETHERNET 1500

#ifndef MKA_MAX_NUM_PEERS
#define MKA_MAX_NUM_PEERS 30  
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef u64 mka_cipher_suite_t;

#define	MKA_UNENCRYPTED 0ull
#define MKA_GCM_AES_128 0x0080C20001000001ull
#define MKA_GCM_AES_256 0x0080C20001000002ull
#define MKA_GCM_AES_XPN_128 0x0080C20001000003ull
#define MKA_GCM_AES_XPN_256 0x0080C20001000004ull

#define MKA_MAX_CKN_LENGTH 64

#ifndef MKA_MAX_NUM_CAKS
#define MKA_MAX_NUM_CAKS 8
#endif
typedef struct mka_cak_info {
	mka_cak_t cak;
	u8 ckn[MKA_MAX_CKN_LENGTH];
	u8 cak_length;
	u16 ckn_length;
} mka_cak_info_t;

typedef struct mka_cak_list {
	mka_cak_info_t caks[MKA_MAX_NUM_CAKS];
	u16 num_caks;
} mka_cak_list_t;

typedef struct mka_sa {
	mka_sak_t sak;
	u8 sak_length;
	mka_cipher_suite_t cipher_suite;
	union {
		struct {
			u8 old_rx : 1;
			u8 old_tx : 1;
			u8 old_key_an : 2;
			u8 latest_rx : 1;
			u8 latest_tx : 1;
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
	u64 latest_lapn; // lapn = lowest acceptable PN
	mka_actor_id_t old_key_server_id;
	u32 old_key_number;
	u64 old_lapn; // lapn = lowest acceptable PN
} mka_sa_t;

typedef enum mka_version {
	MKA_VERSION_1 = 1,
	MKA_VERSION_3 = 3
} mka_version_t;

typedef enum mka_eapol_version {
	MKA_EAPOL_1 = 1,
	MKA_EAPOL_2 = 2,
	MKA_EAPOL_3 = 3
} mka_eapol_version_t;

typedef enum mka_macsec_capability {
	MKA_MACSEC_UNIMPLEMENTED = 0,
	MKA_MACSEC_INTEGRITY_NO_CONFIDENTIALITY = 1,
	MKA_MACSEC_INTEGRITY_AND_CONFIDENTIALITY = 2,
	MKA_MACSEC_INTEGRITY_AND_CONFIDENTIALITY_OFFSET = 3
} mka_macsec_capability_t;

typedef enum mka_status {
	MKA_STATUS_UNKNOWN = 0,
	MKA_STATUS_ACTIVE = 1,
	MKA_STATUS_POTENTIAL = 2
} mka_status_t;

typedef struct mka_participant {
	mka_actor_id_t id;
	u32 message_id;
	mka_status_t status;
	u64 last_tick;
	u8 key_server_priority;
	u64 sci;
	u32 key_number;
	u64 lapn;
	struct {
		u8 rx : 1;
		u8 tx : 1;
		u8 an : 2;
	} attribs;
	bool sak_in_use;
	mka_actor_id_t key_server;
} mka_participant_t;

typedef struct mka_new_sa {
	mka_sak_t sak;
	u8 sak_length;
	mka_cipher_suite_t cipher_suite;
	u8 an;
	u32 key_number;
	u64 pn;
	mka_salt_t salt;
	mka_hash_t hash;
	mka_participant_t* key_server;
	struct {
		mka_participant_t* peers;
		u16 max_peers;
	} peer_list;
} mka_new_sa_t;

typedef enum mka_confidentiality_offset {
	MKA_NO_CONFIDENTIALITY = 0,
	MKA_CONFIDENTIALITY_NO_OFFSET = 1,
	MKA_CONFIDENTIALITY_OFFSET_30 = 2,
	MKA_CONFIDENTIALITY_OFFSET_50 = 3
} mka_confidentiality_offset_t;

typedef struct mka_settings_t {
	bool plain_rx;
	bool plain_tx;
	bool macsec_desired;
	mka_confidentiality_offset_t confidentiality_offset;
	void (*sa_installer)(const mka_new_sa_t* sa, void* user_data);
	void* user_data;
	mka_cipher_suite_t cipher_suite;
	const char* kmd;
	char mac_addr[6];
	u16 port_id;
	u8 key_server_priority;
	mka_version_t version;
	mka_eapol_version_t eapol_version;
	mka_macsec_capability_t capability;
	u32 replay_window;
	struct {
		u64 (*get_current_ms)();
		u64 (*entropy)();
	} opt;
	mka_cak_list_t cak_list;
} mka_settings_t;


typedef struct mka_state {
	mka_settings_t settings;
	mka_sa_t sa; // Secure association
	mka_actor_id_t id;
	u32 message_id;
	u32 key_number;
	int current_cak;
	u8 key_server_ssci;
	u8 kek[32];
	u8 ick[32];
	mka_participant_t peers[MKA_MAX_NUM_PEERS];
	u16 num_active;
	u16 num_potential;
	u8 seed[16];
	u64 last_tick;
	bool send_response;
	bool sak_in_use;
	bool distributing_sak;
	bool negotiating;
	bool rx_key_server;
} mka_state_t;

u64 ics_mka_get_current_state_time(const mka_state_t* state);
void ics_mka_encode_sci(const mka_state_t* state, u8* packet_body);
u8 ics_mka_get_sak_length(mka_cipher_suite_t cipher_suite);
int ics_mka_get_cak_index(const mka_state_t* state, const u8* ckn, u16 ckn_length);
bool ics_mka_is_key_server(const mka_state_t* state);

#ifdef __cplusplus
}
#endif
#endif
