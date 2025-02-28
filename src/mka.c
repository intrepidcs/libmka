/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka.h"
#include "ics/mka/mka_crypt.h"
#include "ics/mka/mka_pdu.h"

#include <string.h>
#include <stdlib.h>

#ifdef ICS_MKA_LOG_RESULT
#include <stdio.h>
#endif

#ifndef ICS_MKA_RESULT_LEVEL
#define ICS_MKA_RESULT_LEVEL 0
#endif

static mka_result_t handle_result(mka_result_t result) {
	int result_level = ics_mka_result_get_level(result);

	if(result_level >= ICS_MKA_RESULT_LEVEL) {
		return MKA_SUCCESS;
	}

#ifdef ICS_MKA_LOG_RESULT
	if(result_level != MKA_SUCCESS) {
		printf("MKA result code: %d, message: %s\n", (int)result, ics_mka_result_get_message(result));
	}
#endif	

	return result;
} 

static mka_actor_id_t zero_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static u64 get_sci(mka_state_t* state) {
	u64 res;
	u8* buf = (u8*)&res;
	memcpy(buf, state->settings.mac_addr, 6);
	ics_write_be16(buf + 6, state->settings.port_id);
	return res;
}

static u8 calculate_ssci(mka_state_t* state) {
	u8 ssci = 0x01;
	u64 state_sci;

	ics_mka_encode_sci(state, (u8*)&state_sci);
	u64 state_sci_be = ics_read_be64((u8*)&state_sci);

	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer = &state->peers[i];
		u64 peer_sci_be = ics_read_be64((u8*)&peer->sci);
		if(peer_sci_be > state_sci_be && peer->status == MKA_STATUS_ACTIVE) {
			ssci++;
		}
	}

	return ssci;
}

static u8 calculate_peer_ssci(mka_state_t* state, mka_participant_t* peer) {
	u8 ssci = 0x01;
	u64 state_sci;

	ics_mka_encode_sci(state, (u8*)&state_sci);
	u64 state_sci_be = ics_read_be64((u8*)&state_sci);
	u64 peer_sci_be = ics_read_be64((u8*)&peer->sci);

	if(state_sci_be < peer_sci_be) {
		ssci++;
	}

	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer2 = &state->peers[i];
		u64 peer_sci_be2 = ics_read_be64((u8*)&peer2->sci);

		if(peer_sci_be2 > state_sci_be && peer->status == MKA_STATUS_ACTIVE) {
			ssci++;
		}
	}

	return ssci;
}

static void peer_init(mka_state_t* state, mka_participant_t* peer, const mka_actor_id_t id) {
	memcpy(peer->id, id, MKA_ACTOR_ID_LENGTH);
	peer->message_id = 0;
	peer->status = MKA_STATUS_POTENTIAL;
	peer->key_server_priority = 0xFF;
	peer->sci = 0x00;
	peer->attribs.tx = 0;
	peer->attribs.rx = 0;
	peer->last_tick = ics_mka_get_current_state_time(state);
}

static mka_result_t set_cak(mka_state_t* state, int cak_index) {
	state->current_cak = cak_index;
	const mka_cak_info_t* current_cak = &state->settings.cak_list.caks[cak_index];
	if(!ics_mka_gen_ick(current_cak, state->ick)) {
		return MKA_ICK_GENERATION_ERROR;
	}

	if(!ics_mka_gen_kek(current_cak, state->kek)) {
		return MKA_KEK_GENERATION_ERROR;
	}

	return MKA_SUCCESS;
}

static int param_type_to_idx(mka_params_type_t type) {
	switch(type) {
		case MKA_PARAMS_BASIC:
			return 0;
		case MKA_PARAMS_ACTIVE_LIST:
			return 1;
		case MKA_PARAMS_POTENTIAL_LIST:
			return 2;
		case MKA_PARAMS_SAK_USE:
			return 3;
		case MKA_PARAMS_DISTRIBUTED_SAK:
			return 4;
		case MKA_PARAMS_DISTRIBUTED_CAK:
			return 5;
		case MKA_PARAMS_KMD:
			return 6;
		case MKA_PARAMS_ANNOUNCEMENT:
			return 7;
		case MKA_PARAMS_XPN:
			return 8;
		case MKA_PARAMS_ICV_INDICATOR:
			return 9;
	}
	// does not get here
	return 0;
}

static mka_result_t get_params_from_info(
	mka_state_t* state,
	const mka_eth_message_t* msg,
	mka_params_t* params,
	const mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT],
	mka_params_type_t type
) {
	const mka_params_info_t* info = &params_info[param_type_to_idx(type)];

	u16 length_read;
	mka_result_t res = ics_mka_decode_params(
		state,
		msg->packet + info->offset,
		info->length,
		&length_read,
		params,
		info->type == MKA_PARAMS_BASIC
	);

	if(res != MKA_SUCCESS) {
		return res;
	}

	if(length_read != info->length) {
		return MKA_ERROR;
	}

	return MKA_SUCCESS;
}

static bool has_params(const mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT], mka_params_type_t type) {
	return params_info[param_type_to_idx(type)].found;
}

static bool peer_is_key_server(mka_state_t* state, mka_participant_t* peer) {
	if(state->num_potential != 0) {
		return false;
	}

	if(peer->key_server_priority == 0xFF || peer->status != MKA_STATUS_ACTIVE) {
		return false;
	}
	u64 sci;
	ics_mka_encode_sci(state, (u8*)&sci);
	u64 sci_be = ics_read_be64((u8*)&sci);
	u64 peer_sci_be = ics_read_be64((u8*)&peer->sci);

	if(
		state->settings.key_server_priority != 0xFF &&
		(state->settings.key_server_priority < peer->key_server_priority ||
		(peer->key_server_priority == state->settings.key_server_priority && sci_be < peer_sci_be))
	) {
		return false;
	}
	
	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer2 = &state->peers[i];
		u64 peer_sci_be2 = ics_read_be64((u8*)&peer2->sci);
		if(
			peer2->status == MKA_STATUS_ACTIVE &&
			peer2->key_server_priority != 0xFF &&
			(peer2->key_server_priority < peer->key_server_priority ||
			(peer2->key_server_priority == peer->key_server_priority && peer_sci_be2 > peer_sci_be))
		) {
			return false;
		}
	}

	return true;
}

mka_result_t add_cak_internal(mka_settings_t* settings, const u8* cak, u8 cak_length, const u8* ckn, u8 ckn_length) {
	if(settings == NULL)  {
		return MKA_INVALID_ARG;
	}

	if(cak == NULL || ckn == NULL) {
		return MKA_INVALID_ARG;
	}

	if(cak_length != 16 && cak_length != 32) {
		return MKA_INVALID_CAK_LENGTH;
	}

	if(ckn_length > MKA_MAX_CKN_LENGTH) {
		return MKA_INVALID_CKN_LENGTH;
	}

	if(settings->cak_list.num_caks >= MKA_MAX_NUM_CAKS) {
		return MKA_CAK_LIST_CAPACITY_REACHED;
	}

	mka_cak_info_t* next_cak = &settings->cak_list.caks[settings->cak_list.num_caks];
	next_cak->cak_length = cak_length;
	memcpy(next_cak->cak, cak, cak_length);
	next_cak->ckn_length = ckn_length;
	memcpy(next_cak->ckn, ckn, ckn_length);
	settings->cak_list.num_caks++;

	return MKA_SUCCESS;
}

static mka_status_t get_peer_status(mka_state_t* state, mka_actor_id_t id, int* first_available) {
	*first_available = -1;
	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer = &state->peers[i];

		if(peer->status != MKA_STATUS_UNKNOWN) {
			if(!memcmp(peer->id, id, MKA_ACTOR_ID_LENGTH)) {
				*first_available = i;
				return peer->status;		
			}
		} else if(*first_available == -1) {
			*first_available = i;
		}
	}

	return MKA_STATUS_UNKNOWN;
}

static bool is_in_peer_list(mka_state_t* state, mka_peer_list_t* p_list) {
	const u8* list = p_list->list_start;

	for(u16 i = 0; i < p_list->count; i++, list += 16) {
		if(!memcmp(list, state->id, MKA_ACTOR_ID_LENGTH)) {
			return true;
		}
	}

	return false;
}

static bool adjust_list(mka_state_t* state, mka_peer_list_t* p_list) {
	const u8* list = p_list->list_start;
	
	for(u16 i = 0; i < p_list->count; i++, list += 16) {
		if(!memcmp(list, state->id, MKA_ACTOR_ID_LENGTH)) {
			continue;
		}
		
		bool found = false;
		int first_available = -1;

		for(u16 j = 0; j < MKA_MAX_NUM_PEERS; j++) {
			mka_participant_t* peer = &state->peers[j];

			if(!memcmp(list, peer->id, MKA_ACTOR_ID_LENGTH) && peer->status != MKA_STATUS_UNKNOWN) {
				found = true;
				break;
			} else if(peer->status == MKA_STATUS_UNKNOWN && first_available == -1) {
				first_available = j;
			}
		}

		if(!found) {
			if(first_available != -1) {
				mka_participant_t* new_peer = &state->peers[first_available];
				peer_init(state, new_peer, list);
				new_peer->message_id = ics_read_be32(list + MKA_ACTOR_ID_LENGTH);
				state->num_potential++;
			} else {
				return false;
			}
		}
	}

	return true;
}

static mka_result_t adjust_state_lists(mka_state_t* state, const mka_eth_message_t* msg, const mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT]) {
	mka_params_t params;

	if(has_params(params_info, MKA_PARAMS_ACTIVE_LIST)) {
		mka_result_t res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_ACTIVE_LIST);
		if(res != MKA_SUCCESS) {
			return res;
		}
		mka_peer_list_t* p_list = (mka_peer_list_t*)(&params.body);
		if(!adjust_list(state, p_list)) {
			return MKA_ERROR_PEER_LIST_FULL;
		}
	}

	if(has_params(params_info, MKA_PARAMS_POTENTIAL_LIST)) {
		mka_result_t res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_POTENTIAL_LIST);
		if(res != MKA_SUCCESS) {
			return res;
		}
		mka_peer_list_t* p_list = (mka_peer_list_t*)(&params.body);
		if(!adjust_list(state, p_list)) {
			return MKA_ERROR_PEER_LIST_FULL;
		}
	}

	return MKA_SUCCESS;
}

static bool can_tx(mka_state_t* state) {
	if(!state->rx_key_server) {
		return false;
	}
	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer = &state->peers[i];

		if(
			(peer->status == MKA_STATUS_ACTIVE) && 
			(
				memcmp(peer->key_server, state->sa.latest_key_server_id, MKA_ACTOR_ID_LENGTH) || 
				(peer->attribs.an != state->sa.attribs.flags.latest_key_an) ||
				(peer->key_number != state->sa.latest_key_number) || 
				(!peer->attribs.rx)
			)
		) {
			return false;
		}
	}
	return true;
}

static bool is_distributed(mka_state_t* state) {
	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer = &state->peers[i];

		if(peer->status == MKA_STATUS_ACTIVE) {
			if(!memcmp(state->sa.latest_key_server_id, zero_id, MKA_ACTOR_ID_LENGTH)) {
				if(
					memcmp(peer->key_server, state->id, MKA_ACTOR_ID_LENGTH) || 
					(peer->attribs.an != state->sa.attribs.flags.old_key_an) ||
					(peer->key_number != state->sa.old_key_number) ||
					!peer->attribs.rx
				) {
					return false;
				}
			} else if(
				memcmp(peer->key_server, state->id, MKA_ACTOR_ID_LENGTH) || 
				(peer->attribs.an != state->sa.attribs.flags.latest_key_an) ||
				(peer->key_number != state->sa.latest_key_number) ||
				!peer->attribs.rx
			) {
				return false;
			}
		}
	}
	return true;	
}

static void check_liveness(mka_state_t* state) {
	u16 prev_active = state->num_active;
	u64 current_time = ics_mka_get_current_state_time(state);
	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer = &state->peers[i];
		if(peer->status != MKA_STATUS_UNKNOWN && 
			current_time > (peer->last_tick + (u64)MKA_LIFE_TIME)) {
			if(peer->status == MKA_STATUS_ACTIVE) {
				state->num_active--;
			} else if(peer->status == MKA_STATUS_POTENTIAL) {
				state->num_potential--;
			}
			peer->status = MKA_STATUS_UNKNOWN;
		}
	}
	
	if(state->num_active == 0 && prev_active > 0)  {
		// Reset secure association and sync states
		memset(&state->sa, 0, sizeof(mka_sa_t));
		state->distributing_sak = false;
		state->sak_in_use = false;
		state->negotiating = false;
		state->send_response = true;
		state->rx_key_server = false;
	}
}

static bool peer_has_new_key(mka_state_t* state, mka_participant_t* peer, mka_distributed_sak_t* sak_dist) {
	if(!memcmp(state->sa.latest_key_server_id, zero_id, MKA_ACTOR_ID_LENGTH)) {
		return memcmp(state->sa.old_key_server_id, peer->id, MKA_ACTOR_ID_LENGTH) || (sak_dist->key_number > state->sa.old_key_number);
	}
	return memcmp(state->sa.latest_key_server_id, peer->id, MKA_ACTOR_ID_LENGTH) || (sak_dist->key_number > state->sa.latest_key_number);
}

static bool init_new_sa(mka_state_t* state, mka_new_sa_t* new_sa, mka_participant_t* key_server) {
	bool ret = true;
	memset(new_sa, 0, sizeof(mka_new_sa_t));
	memcpy(new_sa->sak, state->sa.sak, state->sa.sak_length);
	new_sa->sak_length = state->sa.sak_length;
	new_sa->cipher_suite = state->sa.cipher_suite;
	new_sa->pn = state->sa.latest_lapn;
	new_sa->key_number = state->sa.latest_key_number;
	new_sa->an = state->sa.attribs.flags.latest_key_an;
	new_sa->peer_list.peers = state->peers;
	new_sa->peer_list.max_peers = MKA_MAX_NUM_PEERS;
	new_sa->key_server = key_server;
	ret = ret && ics_mka_gen_hash(new_sa->hash, new_sa->sak, new_sa->sak_length);

	mka_actor_id_t* key_server_id = key_server ? &key_server->id : &state->id;
	const u8* key_number = (const u8*)(&new_sa->key_number);
	int i = 0;
	for(; i < 8; i++) {
		new_sa->salt[i] = (*key_server_id)[i];
	}
	new_sa->salt[i] = (*key_server_id)[i] ^ key_number[3];
	i++;
	new_sa->salt[i] = (*key_server_id)[i] ^ key_number[2];
	i++;
	new_sa->salt[i] = (*key_server_id)[i] ^ key_number[1];
	i++;
	new_sa->salt[i] = (*key_server_id)[i] ^ key_number[0];

	return ret;
}

static mka_result_t update_peer_key_server(
	mka_state_t* state,
	mka_participant_t* peer,
	const mka_eth_message_t* msg,
	mka_basic_params_t* basic_params,
	const mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT]
) {
	mka_params_t params;
	mka_result_t res;

	state->distributing_sak = false;
	// Use the same CAK as the key server
	
	int cak_index = ics_mka_get_cak_index(state, basic_params->ckn, basic_params->ckn_length);
	set_cak(state, cak_index); // This will generate a new KEK and ICK

	state->key_server_ssci = calculate_peer_ssci(state, peer);

	if(has_params(params_info, MKA_PARAMS_DISTRIBUTED_CAK)) {
		res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_DISTRIBUTED_CAK);
		if(res != MKA_SUCCESS) {
			return res;
		}
		// Install this new CAK
		mka_distributed_cak_t* cak_dist = (mka_distributed_cak_t*)&params.body;
		if(state->settings.cak_list.num_caks < MKA_MAX_NUM_CAKS) {
			mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];
			u8 kek_length = cak_info->cak_length;
			mka_cak_info_t* next_cak = &state->settings.cak_list.caks[state->settings.cak_list.num_caks];
			if(!ics_mka_aes_key_unwrap(next_cak->cak, cak_dist->cak, kek_length, state->kek, kek_length)) {
				return MKA_ERROR_AES_KEY_UNWRAP_CAK;
			}
			res = add_cak_internal(&state->settings, cak_dist->cak, cak_info->cak_length, cak_dist->ckn, (u8)cak_dist->ckn_length);
			if(res != MKA_SUCCESS) {
				return res;
			}
		} else {
			// TODO: Should probably return something to the user here
		}
	}

	bool has_sak_use = has_params(params_info, MKA_PARAMS_SAK_USE);
	bool has_sak_dist = has_params(params_info, MKA_PARAMS_DISTRIBUTED_SAK);

	if(has_sak_use && has_sak_dist) {
		mka_params_t sak_use_params;
		res = get_params_from_info(state, msg, &sak_use_params, params_info, MKA_PARAMS_SAK_USE);
		if(res != MKA_SUCCESS) {
			return res;
		}
		res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_DISTRIBUTED_SAK);
		if(res != MKA_SUCCESS) {
			return res;
		}
		
		mka_sak_use_t* sak_use = (mka_sak_use_t*)(&sak_use_params.body);
		mka_distributed_sak_t* sak_dist = (mka_distributed_sak_t*)&params.body;

		if(peer_has_new_key(state, peer, sak_dist)) {
			// Save the SAK
			state->sa.cipher_suite = sak_dist->cipher_suite;

			if(state->sa.cipher_suite != MKA_UNENCRYPTED) {
				mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];
				u8 kek_length = cak_info->cak_length;
				u8 sak_length = ics_mka_get_sak_length(sak_dist->cipher_suite);
				u8 wrapped_sak_length = sak_length + 8;

				if(!ics_mka_aes_key_unwrap(state->sa.sak, sak_dist->sak, wrapped_sak_length, state->kek, kek_length)) {
					return MKA_ERROR_AES_KEY_UNWRAP_SAK;
				}

				u64 msb_latest_lapn = 0;
				u64 msb_old_lapn = 0;
				if(
					sak_dist->cipher_suite == MKA_GCM_AES_XPN_128 || 
					sak_dist->cipher_suite == MKA_GCM_AES_XPN_256
				) {
					if(state->settings.version == MKA_VERSION_1) {
						return MKA_UNSUPPORTED_VERSION_RECEIVED;
					}
					if(!has_params(params_info, MKA_PARAMS_XPN)) {
						return MKA_XPN_NOT_FOUND;
					}

					mka_params_t xpn_params;
					mka_xpn_t* xpn = (mka_xpn_t*)&xpn_params.body;
					res = get_params_from_info(state, msg, &xpn_params, params_info, MKA_PARAMS_XPN);
					if(res != MKA_SUCCESS) {
						return res;
					}

					msb_latest_lapn = (u64)(xpn->latest_lapn) << 32;
					msb_old_lapn = (u64)(xpn->old_lapn) << 32;;
				}

				state->sa.sak_length = sak_length;
				state->sa.cipher_suite = sak_dist->cipher_suite;

				state->sa.attribs.flags.latest_rx = 1;
				state->sa.attribs.flags.latest_tx = 0;
				state->sa.latest_key_number = sak_dist->key_number;
				state->sa.latest_lapn = sak_use->latest_lapn | msb_old_lapn;
				state->sa.attribs.flags.latest_key_an = sak_dist->attribs.flags.distributed_an;
				memcpy(state->sa.latest_key_server_id, peer->id, MKA_ACTOR_ID_LENGTH);

				for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
					mka_participant_t* peer2 = &state->peers[i];
					if(peer == peer2) {
						peer->attribs.tx = sak_use->attribs.flags.latest_key_tx;
						peer->attribs.rx = sak_use->attribs.flags.latest_key_rx;
						peer->attribs.an = sak_use->attribs.flags.latest_key_an;
						peer->key_number = sak_use->latest_key_number;
						peer->lapn  = sak_use->latest_lapn | msb_latest_lapn;
						memcpy(peer->key_server, peer->id, MKA_ACTOR_ID_LENGTH);
					} else {
						peer2->attribs.tx = 0;
						peer2->attribs.rx = 0;
					}
				}
			}

			if(state->settings.sa_installer) {
				mka_new_sa_t new_sa;
				if(!init_new_sa(state, &new_sa, peer)) {
					return MKA_FAILED_TO_INIT_SA;
				}
				state->settings.sa_installer(&new_sa, state->settings.user_data);
			}

			state->sak_in_use = true;
			state->send_response = true;
			state->negotiating = true;
			state->distributing_sak = false;
			state->rx_key_server = false;
		}
	} else if(has_sak_use) {
		res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_SAK_USE);
		if(res != MKA_SUCCESS) {
			return res;
		}
		mka_sak_use_t* sak_use = (mka_sak_use_t*)(&params.body);

		u64 msb_latest_lapn = 0;
		u64 msb_old_lapn = 0;

		if(has_params(params_info, MKA_PARAMS_XPN)) {
			mka_params_t xpn_params;
			mka_xpn_t* xpn = (mka_xpn_t*)&xpn_params.body;
			res = get_params_from_info(state, msg, &xpn_params, params_info, MKA_PARAMS_XPN);
			if(res != MKA_SUCCESS) {
				return res;
			}
			msb_latest_lapn = (u64)(xpn->latest_lapn) << 32;
			msb_old_lapn = (u64)(xpn->old_lapn) << 32;;
		}

		if(memcmp(sak_use->latest_key_server_id, zero_id, MKA_ACTOR_ID_LENGTH)) {
			peer->attribs.tx = sak_use->attribs.flags.latest_key_tx;
			peer->attribs.rx = sak_use->attribs.flags.latest_key_rx;
			peer->attribs.an = sak_use->attribs.flags.latest_key_an;
			peer->key_number = sak_use->latest_key_number;
			peer->lapn  = sak_use->latest_lapn | msb_latest_lapn;
			memcpy(peer->key_server, sak_use->latest_key_server_id, MKA_ACTOR_ID_LENGTH);
		} else {
			peer->attribs.tx = sak_use->attribs.flags.old_key_tx;
			peer->attribs.rx = sak_use->attribs.flags.old_key_rx;
			peer->attribs.an = sak_use->attribs.flags.old_key_an;
			peer->key_number = sak_use->old_key_number;
			peer->lapn = sak_use->old_lapn | msb_old_lapn;
			memcpy(peer->key_server, sak_use->old_key_server_id, MKA_ACTOR_ID_LENGTH);	
		}
	}

	return MKA_SUCCESS;
}

static mka_result_t update_peer(
	mka_state_t* state,
	mka_participant_t* peer,
	const mka_eth_message_t* msg,
	const mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT]
) {
	if(has_params(params_info, MKA_PARAMS_SAK_USE)) {
		mka_result_t res;
		mka_params_t params;
		res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_SAK_USE);
		if(res != MKA_SUCCESS) {
			return res;
		}
		mka_sak_use_t* sak_use = (mka_sak_use_t*)(&params.body);

		u64 msb_latest_lapn = 0;
		u64 msb_old_lapn = 0;
		if(has_params(params_info, MKA_PARAMS_XPN)) {
			mka_params_t xpn_params;
			mka_xpn_t* xpn = (mka_xpn_t*)&xpn_params.body;
			res = get_params_from_info(state, msg, &xpn_params, params_info, MKA_PARAMS_XPN);
			if(res != MKA_SUCCESS) {
				return res;
			}
			msb_latest_lapn = (u64)(xpn->latest_lapn) << 32;
			msb_old_lapn = (u64)(xpn->old_lapn) << 32;;
		}

		if(memcmp(sak_use->latest_key_server_id, zero_id, MKA_ACTOR_ID_LENGTH)) {
			peer->attribs.tx = sak_use->attribs.flags.latest_key_tx;
			peer->attribs.rx = sak_use->attribs.flags.latest_key_rx;
			peer->attribs.an = sak_use->attribs.flags.latest_key_an;
			peer->key_number = sak_use->latest_key_number;
			peer->lapn = sak_use->latest_lapn | msb_latest_lapn;
			memcpy(peer->key_server, sak_use->latest_key_server_id, MKA_ACTOR_ID_LENGTH);
		} else {
			peer->attribs.tx = sak_use->attribs.flags.old_key_tx;
			peer->attribs.rx = sak_use->attribs.flags.old_key_rx;
			peer->attribs.an = sak_use->attribs.flags.old_key_an;
			peer->key_number = sak_use->old_key_number;
			peer->lapn = sak_use->old_lapn | msb_old_lapn;
			memcpy(peer->key_server, sak_use->old_key_server_id, MKA_ACTOR_ID_LENGTH);
		}
	}

	return MKA_SUCCESS;
}

static bool last_key_server_was_state(mka_state_t* state) {
	return !memcmp(state->sa.latest_key_server_id, state->id, MKA_ACTOR_ID_LENGTH) ||
		(!memcmp(state->sa.latest_key_server_id, zero_id, MKA_ACTOR_ID_LENGTH) &&
		!memcmp(state->sa.old_key_server_id, state->id, MKA_ACTOR_ID_LENGTH));
}


static mka_result_t station_key_server_action(mka_state_t* state, u16 prev_active) {
	state->key_server_ssci = calculate_ssci(state);
	if(
		!state->distributing_sak && 
		(!last_key_server_was_state(state) || 
		((state->num_active > prev_active) && state->num_potential == 0)))
	{
		
		state->sa.cipher_suite = state->settings.cipher_suite;
		state->sa.sak_length = ics_mka_get_sak_length(state->sa.cipher_suite);
		ics_mka_gen_sak(state);

		state->sa.attribs.flags.latest_rx = 1;
		state->sa.attribs.flags.latest_tx = state->sak_in_use ? 0 : 1;
		if(state->sak_in_use) {
			if(state->sa.attribs.flags.old_key_an == 3) {
				state->sa.attribs.flags.latest_key_an = 0;
			} else {
				state->sa.attribs.flags.latest_key_an = state->sa.attribs.flags.old_key_an + 1;
			}
		} else {
			state->sa.attribs.flags.latest_key_an = 0;
		}
		state->sa.latest_key_number = state->key_number;
		state->sa.latest_lapn = 0x01; // TODO: Max this not fixed
		memcpy(state->sa.latest_key_server_id, state->id, MKA_ACTOR_ID_LENGTH);

		if(!state->sak_in_use) {
			state->sa.attribs.flags.latest_tx = 1;

			state->distributing_sak = true;
			state->negotiating = false;
			state->sak_in_use = true;
			state->send_response = true;
			state->rx_key_server = true;
		} else {
			state->distributing_sak = true;
			state->negotiating = true;
			state->sak_in_use = true;
			state->send_response = true;
			state->rx_key_server = true;			
		}

		if(state->settings.sa_installer) {
			mka_new_sa_t new_sa;
			if(!init_new_sa(state, &new_sa, NULL)) {
				return MKA_FAILED_TO_INIT_SA;
			}
			state->settings.sa_installer(&new_sa, state->settings.user_data);
		}
		for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
			mka_participant_t* peer2 = &state->peers[i];
			peer2->attribs.tx = 0;
			peer2->attribs.rx = 0;
		}
	}
	return MKA_SUCCESS;
}

static mka_result_t update_peer_status(
	mka_state_t* state,
	mka_participant_t* peer,
	const mka_eth_message_t* msg,
	mka_basic_params_t* basic_params,
	mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT]
) {
	mka_result_t res;

	if(peer->status == MKA_STATUS_UNKNOWN) {
		// TODO: Check to see if we can use our current actor id
		peer_init(state, peer, basic_params->id);
		state->num_potential++;
		return MKA_SUCCESS;
	}

	if(peer->status == MKA_STATUS_POTENTIAL) {
		if(has_params(params_info, MKA_PARAMS_ACTIVE_LIST)) {
			mka_params_t params;
			res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_ACTIVE_LIST);
			if(res != MKA_SUCCESS) {
				return res;
			}
			mka_peer_list_t* active_list = (mka_peer_list_t*)(&params.body);
			if(is_in_peer_list(state, active_list)) {
				state->num_potential--;				
				peer->status = MKA_STATUS_ACTIVE;
				state->num_active++;
			}
		}
		if(has_params(params_info, MKA_PARAMS_POTENTIAL_LIST)) {
			mka_params_t params;
			res = get_params_from_info(state, msg, &params, params_info, MKA_PARAMS_POTENTIAL_LIST);
			if(res != MKA_SUCCESS) {
				return res;
			}
			mka_peer_list_t* potential_list = (mka_peer_list_t*)(&params.body);
			if(is_in_peer_list(state, potential_list)) {
				state->num_potential--;
				peer->status = MKA_STATUS_ACTIVE;
				state->num_active++;
			}
		}
	}

	if(peer->status == MKA_STATUS_ACTIVE) {
		res = adjust_state_lists(state, msg, params_info);
		if(res != MKA_SUCCESS) {
			return res;
		}
	}

	return MKA_SUCCESS;
}

static bool compete_for_id(mka_state_t* state, u32 peer_message_id) {
	if(state->message_id < peer_message_id) {
		ics_mka_gen_id(state);
		state->distributing_sak = false;
		state->sak_in_use = false;
		memset(&state->sa, 0, sizeof(mka_sa_t));

		for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
			mka_participant_t* peer = &state->peers[i];
			if(peer->status == MKA_STATUS_ACTIVE) {
				peer->status = MKA_STATUS_POTENTIAL;
			}
		}
		return false;
	}

	return true;
}

#define MKA_MACSEC_TCI_ES (1 << 6) 
#define MKA_MACSEC_TCI_SC (1 << 5)
static mka_result_t handle_macsec(mka_state_t* state, const mka_eth_message_t* msg) {
	if(!state->rx_key_server && state->sak_in_use) {
		static u16 macsec_header_len = 14;
		u8 tci = msg->packet[0];
		if(!(tci & MKA_MACSEC_TCI_SC)) {
			// There is no SCI in this message
			return MKA_SUCCESS;
		}

		if(msg->length >= macsec_header_len) {

			u64 msg_sci;
			int idx;
			get_peer_status(state, state->sa.latest_key_server_id, &idx);
			if(idx < 0) {
				// Should never happen
				return MKA_ERROR;
			}
			memcpy(&msg_sci, &msg->packet[6], sizeof(u64)); // SCI is offset by 6 bytes in this header
			mka_participant_t* key_server_peer = &state->peers[idx];
			if(!(MKA_MACSEC_TCI_ES & tci)) {
				memcpy(&msg_sci, msg->src, 6);
			}

			if(msg_sci == key_server_peer->sci) {
				state->rx_key_server = true;
			}
		} else {
			return MKA_INVALID_MACSEC_LENGTH;
		}

		if(can_tx(state)) {
			state->sa.attribs.flags.latest_tx = 1;
			state->negotiating = false;
			state->distributing_sak = false;
			state->send_response = true;
		}
	}
	return MKA_SUCCESS;
}

static mka_result_t handle_message(mka_state_t* state, const mka_eth_message_t* msg) {
	if(msg->eth_type == MKA_ETHER_TYPE_MACSEC) {
		return handle_macsec(state, msg);
	}

	if(msg->length < MKA_EAPOL_HEADER_LENGTH || msg->eth_type != MKA_ETHER_TYPE_EAPOL) {
		return MKA_SUCCESS;
	}

	u8 type = msg->packet[1];
	if(type != MKA_EAPOL_TYPE) {
		return MKA_SUCCESS;
	}

	u16 cur = MKA_EAPOL_HEADER_LENGTH;
	mka_params_t b_params;
	mka_result_t res;

	res = ics_mka_read_basic_params(state, msg, &b_params, &cur);

	if(res != MKA_SUCCESS) {
		return res;
	}

	mka_basic_params_t* basic_params = (mka_basic_params_t*)&b_params.body;
	u64 sci = get_sci(state);

	int index;
	get_peer_status(state, basic_params->id, &index);
	if(index < 0) {
		// This peer is unknown and there are not enough buckets left in the list
		return MKA_ERROR_PEER_LIST_FULL;
	}

	mka_participant_t* peer = &state->peers[index];
	if(peer->status != MKA_STATUS_UNKNOWN && basic_params->message_id <= peer->message_id) {
		return MKA_ERROR_OLD_FRAME;
	}

	if(!memcmp(state->id, basic_params->id, MKA_ACTOR_ID_LENGTH)) {
		if(basic_params->sci == sci) {
			return MKA_SUCCESS;
		} else if(compete_for_id(state, basic_params->message_id)) {
			return MKA_SUCCESS; // We won the ID competition, so we return success here and ignore this message
		}
	}

	mka_params_info_t params_info[MKA_PARAMS_TYPE_COUNT];
	res = ics_mka_get_params_info(msg, params_info);
	if(res != MKA_SUCCESS) {
		return res;
	}

	/**
	 * Cache the currently active, we will use this to determine whether
	 * a new active member has been added, in that case we might perform
	 * a key server operation
	 * 
	 * See update_peer_status and station_key_server_action
	 */
	res = update_peer_status(state, peer, msg, basic_params, params_info);
	if(res != MKA_SUCCESS) {
		return res;
	}

	u16 prev_active = state->num_active; 

	/**
	 * Populate fields from basic params, last_tick is especially important
	 * to update here since we call check_liveness directly after, which will
	 * mark anyone who hasn't messaged since MKA_HELLO_TIME as inactive
	 */
	peer->last_tick = ics_mka_get_current_state_time(state);
	peer->key_server_priority = basic_params->priority;
	peer->sci = basic_params->sci;
	peer->message_id = basic_params->message_id;

	check_liveness(state);
	if(peer_is_key_server(state, peer)) {
		res = update_peer_key_server(state, peer, msg, basic_params, params_info);
		if(res != MKA_SUCCESS) {
			return res;
		}
	} else if(peer->status == MKA_STATUS_ACTIVE) {
		res = update_peer(state, peer, msg, params_info);
		if(res != MKA_SUCCESS) {
			return res;
		}
	}

	if(ics_mka_is_key_server(state)) {
		res = station_key_server_action(state, prev_active);
		if(res != MKA_SUCCESS) {
			return res;
		}
		if(state->distributing_sak) {
			if(is_distributed(state)) {
				if(memcmp(state->sa.latest_key_server_id, zero_id, MKA_ACTOR_ID_LENGTH)) {
					state->sa.attribs.flags.latest_tx = 1;
				}
				state->negotiating = false;
				state->distributing_sak = false;
				state->send_response = true;
			}
		}
	} else {
		if(state->negotiating) {
			if(can_tx(state)) {
				state->sa.attribs.flags.latest_tx = 1;
				state->negotiating = false;
				state->distributing_sak = false;
				state->send_response = true;
			}
		}
	}

	return MKA_SUCCESS;
}

mka_result_t ics_mka_cleanup(mka_state_t* state) {
	if(state == NULL) {
		return MKA_INVALID_ARG;
	}

	// TODO: Currently nothing to clean up, so just return MKA_SUCCESS
	return MKA_SUCCESS;	
}

mka_result_t ics_mka_process_message(mka_state_t* state, const u8* eth_packet, u16 length) {
	if(state == NULL || eth_packet == NULL)  {
		return handle_result(MKA_INVALID_ARG);
	}

	if(state->settings.cak_list.num_caks == 0) {
		return handle_result(MKA_NO_CAK);
	}

	if(length < 14) {
		return handle_result(MKA_INVALID_ARG);
	}

	mka_eth_message_t msg;
	memcpy(msg.dest, eth_packet, 6);
	memcpy(msg.src, eth_packet + 6, 6);
	msg.eth_type = ics_read_be16(eth_packet + 12);
	msg.length = length - 14;
	msg.packet = eth_packet + 14;

	return handle_result(handle_message(state, &msg));
}

mka_result_t ics_mka_next_pdu_length(mka_state_t* state, u16* length_out) {

	if(state == NULL || length_out == NULL)  {
		return handle_result(MKA_INVALID_ARG);
	}
	check_liveness(state);
	mka_params_set_t param_set;
	memset(param_set, 0, sizeof(mka_params_set_t));

	param_set[0] = 1;
	param_set[1] = 1;
	param_set[2] = 1;
	if(state->sak_in_use) {
		param_set[3] = 1;

		if(state->sa.cipher_suite == MKA_GCM_AES_XPN_128 || state->sa.cipher_suite == MKA_GCM_AES_XPN_256) {
			param_set[8] = 1; // Add extended packet numberings
		}
	}

	if(state->distributing_sak) {
		param_set[4] = 1;
	}

	if(state->settings.version == MKA_VERSION_3) {
		param_set[7] = 1;
	}

	u16 result = 0;
	for(int i = 0; i < MKA_PARAMS_TYPE_COUNT; i++) {
		if(param_set[i]) {
			result += ics_mka_encoded_length(state, idx_to_params_type[i]);
		}
	}

	*length_out = 14 + MKA_EAPOL_HEADER_LENGTH + result;

	return MKA_SUCCESS;
}

mka_result_t ics_mka_next_pdu(mka_state_t* state, u8* eth_packet_out, u16* length_out, u64 next_pn) {
	if(state == NULL || eth_packet_out == NULL)  {
		return handle_result(MKA_INVALID_ARG);
	}

	if(state->settings.cak_list.num_caks == 0) {
		return handle_result(MKA_NO_CAK);
	}

	check_liveness(state);

	mka_params_set_t param_set;
	memset(param_set, 0, sizeof(mka_params_set_t));

	param_set[0] = 1;
	param_set[1] = 1;
	param_set[2] = 1;
	if(state->sak_in_use) {
		param_set[3] = 1;

		if(state->sa.cipher_suite == MKA_GCM_AES_XPN_128 || state->sa.cipher_suite == MKA_GCM_AES_XPN_256) {
			param_set[8] = 1; // Add extended packet numberings
		}
	}

	if(state->distributing_sak) {
		param_set[4] = 1;
	}

	if(state->settings.version == MKA_VERSION_3) {
		param_set[7] = 1;
	}

	u64 lapn = next_pn >= state->settings.replay_window ? next_pn - state->settings.replay_window : 0x01;
	if(state->sa.attribs.flags.latest_rx) {
		state->sa.latest_lapn = lapn;
	} else {
		state->sa.latest_lapn = 0x01;
		state->sa.old_lapn = lapn;
	}

	char broadcast[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
	memcpy(eth_packet_out, broadcast, 6);
	memcpy(eth_packet_out + 6, state->settings.mac_addr, 6);
	ics_write_be16(eth_packet_out + 12, MKA_ETHER_TYPE_EAPOL);

	mka_result_t res = ics_mka_encode_pdu(state, eth_packet_out + 14, length_out, broadcast, param_set);
	if(res != MKA_SUCCESS) {
		return handle_result(res);
	}

	state->send_response = false;
	state->message_id++;
	if(length_out) {
		*length_out = *length_out + 14;
	}

	if(state->sa.attribs.flags.latest_rx && state->sa.attribs.flags.latest_tx && !state->negotiating) {
		// We don't need to store this data anymore			
		state->sa.attribs.flags.old_rx = state->sa.attribs.flags.latest_rx;
		state->sa.attribs.flags.old_tx = state->sa.attribs.flags.latest_tx;
		state->sa.attribs.flags.old_key_an = state->sa.attribs.flags.latest_key_an;
		state->sa.old_key_number = state->sa.latest_key_number;
		state->sa.old_lapn = state->sa.latest_lapn;
		
		memcpy(state->sa.old_key_server_id, state->sa.latest_key_server_id, MKA_ACTOR_ID_LENGTH);

		state->sa.attribs.flags.latest_tx = 0;
		state->sa.attribs.flags.latest_rx = 0;
		state->sa.attribs.flags.latest_key_an = 0;
		state->sa.latest_key_number = 0;
		state->sa.latest_lapn = 0;
		memset(state->sa.latest_key_server_id, 0, MKA_ACTOR_ID_LENGTH);
	}

	state->last_tick = ics_mka_get_current_state_time(state);
	return MKA_SUCCESS;
}

mka_result_t ics_mka_settings_init(mka_settings_t* settings) {
	memset(&settings->cak_list, 0, sizeof(mka_cak_list_t));
	memset(settings->mac_addr, 0, 6);
	settings->cipher_suite = MKA_GCM_AES_128;
	settings->confidentiality_offset = MKA_NO_CONFIDENTIALITY;
	settings->kmd = NULL;
	settings->macsec_desired = false;
	settings->plain_rx = false;
	settings->plain_tx = false;
	settings->capability = MKA_MACSEC_UNIMPLEMENTED;
	settings->replay_window = 0;
	settings->sa_installer = NULL;
	settings->user_data = NULL;
	settings->version = MKA_VERSION_3;
	settings->eapol_version = MKA_EAPOL_3;
	settings->port_id = 1;
	settings->key_server_priority = 0xFFu;
	settings->opt.get_current_ms = NULL;
	settings->opt.entropy = NULL;

	return MKA_SUCCESS;
}

mka_result_t ics_mka_add_cak(mka_settings_t* settings, const u8* cak, u8 cak_length, const u8* ckn, u8 ckn_length) {
	return handle_result(add_cak_internal(settings, cak, cak_length, ckn, ckn_length));
}

mka_result_t ics_mka_has_response(mka_state_t* state) {
	u64 current_time = ics_mka_get_current_state_time(state);
	return state->send_response || ((state->last_tick + MKA_HELLO_TIME) <= current_time);
}

void ics_mka_validate_key_server_rx(mka_state_t* state) {
	state->rx_key_server = true;
}

mka_result_t ics_mka_init(mka_state_t* state, mka_settings_t* settings) {
	if(state == NULL)  {
		return handle_result(MKA_INVALID_ARG);
	}

	if(settings != NULL) {
		if(settings->port_id == 0) {
			// Port ID must be greater than or equal to 0x01
			return handle_result(MKA_INVALID_ARG);
		}

		if(settings->cak_list.num_caks == 0) {
			// Must have at least one CAK
			return handle_result(MKA_INVALID_ARG);
		}

		if(settings->version != MKA_VERSION_1 && settings->version != MKA_VERSION_3) {
			// We don't support this version
			return handle_result(MKA_INVALID_ARG);
		}

		if(settings->version == MKA_VERSION_1 && (settings->cipher_suite == MKA_GCM_AES_XPN_128 || settings->cipher_suite == MKA_GCM_AES_XPN_256)) {
			// Can't have XPN
			return handle_result(MKA_INVALID_ARG);
		}

		memcpy(&state->settings, settings, sizeof(mka_settings_t));
	} else {
		return handle_result(MKA_INVALID_ARG);
	}
	memset(&state->sa, 0, sizeof(mka_sa_t));

	state->message_id = 1;
	state->key_number = 0;
	state->num_active = 0;
	state->num_potential = 0;
	state->last_tick = 0;
	state->send_response = true;
	state->sak_in_use = false;
	state->distributing_sak = false;
	state->negotiating = false;
	state->rx_key_server = false;
	state->sa.attribs.flags.plain_rx = state->settings.plain_rx;
	state->sa.attribs.flags.plain_tx = state->settings.plain_tx;

	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		state->peers[i].status = MKA_STATUS_UNKNOWN;
		state->peers[i].attribs.tx = 0;
		state->peers[i].attribs.rx = 0;
	}


	mka_result_t res = set_cak(state, 0);
	if(res != MKA_SUCCESS) {
		return handle_result(res);
	}

	if(!ics_mka_gen_id(state)) {
		// TODO: Better error checking
		return handle_result(MKA_ERROR);
	}

	u64 time1 = ics_mka_get_current_state_time(state);
	u64 time2 = ics_mka_get_current_state_time(state);
	memcpy(state->seed, (void*)&time1, 8);
	memcpy(state->seed + 8, (void*)&time2, 8);

	return MKA_SUCCESS;
}

