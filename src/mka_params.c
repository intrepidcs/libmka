/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka_params.h"
#include "ics/mka/mka_crypt.h"
#include <string.h>

mka_params_type_t idx_to_params_type[MKA_PARAMS_TYPE_COUNT] = {
	MKA_PARAMS_BASIC,
	MKA_PARAMS_ACTIVE_LIST,
	MKA_PARAMS_POTENTIAL_LIST,
	MKA_PARAMS_SAK_USE,
	MKA_PARAMS_DISTRIBUTED_SAK,
	MKA_PARAMS_DISTRIBUTED_CAK,
	MKA_PARAMS_KMD,
	MKA_PARAMS_ANNOUNCEMENT,
	MKA_PARAMS_XPN,
	MKA_PARAMS_ICV_INDICATOR
};

static void sort_peers_helper(const mka_participant_t* peers, u32* indices, u32 begin, u32 end) {
	if((end - begin) < 2) {
		return;
	} else if((end - begin) == 2) {
		u64 sci1 = ics_read_be64((u8*)(&(peers[indices[begin]].sci)));
		u64 sci2 = ics_read_be64((u8*)(&(peers[indices[begin + 1]].sci)));
		
		if(sci1 < sci2) {
			u32 temp = indices[begin];
			indices[begin] = indices[begin + 1];
			indices[begin + 1] = temp;
		}
		return;
	}

	u64 pivot_sci_be = ics_read_be64((u8*)(&(peers[indices[begin]].sci)));
	u32 next_highest = begin + 1;
	u32 next_lowest = end - 1;

	for(u32 sub_index = begin + 1; sub_index < end; sub_index++) {
		u32 index = indices[sub_index];
		u64 sci_be = ics_read_be64((u8*)(&(peers[index].sci)));
		if(sci_be > pivot_sci_be) {
			indices[sub_index] = indices[next_highest];
			indices[next_highest] = index;
			next_highest++;
		} else {
			indices[sub_index] = indices[next_lowest];
			indices[next_lowest] = index;
			next_lowest--;
		}
	}

	u32 temp = indices[next_highest - 1];
	indices[next_highest - 1] = indices[begin];
	indices[begin] = temp;

	sort_peers_helper(peers, indices, 0, next_highest - 1);
	sort_peers_helper(peers, indices, next_highest, end);
}

static void sort_peers(const mka_participant_t* peers, u32* indices, u32 length) {
	sort_peers_helper(peers, indices, 0, length);
}

mka_result_t ics_mka_decode_params_size(const u8* packet_body, u16 length, u16* size) {
	if(length < MKA_HEADER_LENGTH) {
		return MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH1;
	}

	u16 body_length = (((packet_body[2] & 0x0F) << 8) | packet_body[3]);
	u16 param_len = body_length + MKA_HEADER_LENGTH; // The packet body + 4 for the header
	if(param_len > length) {
		if(packet_body[0] != MKA_PARAMS_ICV_INDICATOR) {
			return MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH2;
		} else {
			// If this packet is an ICV_INDICATOR, then we can continue
			// This is because in this case the body_length encoded
			// in the packet is 16 (the size of the ICV). However
			// the variable "length" does not include the size of the ICV

			// Set the body length as zero, since we won't read the ICV in this function
			param_len = MKA_HEADER_LENGTH;
			body_length = 0;
		}
	}
	*size = MKA_ROUND_NEXT_MULTIPLE(param_len, 4);

	if(*size > length) {
		return MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH3;
	}

	return MKA_SUCCESS;
}

mka_result_t ics_mka_decode_params(const mka_state_t* state, const u8* packet_body, u16 length, u16* length_read, mka_params_t* params, bool is_basic) {
	if(length < 4) {
		return MKA_DECODE_INSUFFICIENT_LENGTH1;
	}

	u16 body_length = (((packet_body[2] & 0x0F) << 8) | packet_body[3]);
	u16 param_len = body_length + MKA_HEADER_LENGTH; // The packet body + 4 for the header
	if(param_len > length) {
		if(packet_body[0] != MKA_PARAMS_ICV_INDICATOR) {
			return MKA_DECODE_INSUFFICIENT_LENGTH2;
		} else if(packet_body[0] == MKA_PARAMS_ICV_INDICATOR && body_length == 16) {
			// If this packet is an ICV_INDICATOR, then we can continue
			// This is because in this case the body_length encoded
			// in the packet is 16 (the size of the ICV). However
			// the variable "length" does not include the size of the ICV

			// Set the body length as zero, since we won't read the ICV in this function
			param_len = MKA_HEADER_LENGTH;
			body_length = 0; 
		}
	}

	mka_params_type_t type;
	if(is_basic) {
		type = MKA_PARAMS_BASIC;
	} else {
		type = (mka_params_type_t)packet_body[0];
	}
	params->type = type;
	
	u16 cur = 1;
	switch(type) {
		case MKA_PARAMS_ACTIVE_LIST:
		case MKA_PARAMS_POTENTIAL_LIST: {
			params->body.peer_list.ssci = packet_body[cur++];
			cur += 2;
			if(body_length % 16 != 0) {
				return MKA_DECODE_INVALID_ALIGN1;
			}
			params->body.peer_list.count = param_len / 16;
			params->body.peer_list.list_start = (packet_body + cur);
			break;
		}
		case MKA_PARAMS_SAK_USE: {
			params->body.sak_use.attribs.data[0] = packet_body[cur++];
			params->body.sak_use.attribs.data[1] = packet_body[cur++];
			cur++;
			memcpy(params->body.sak_use.latest_key_server_id, packet_body + cur, MKA_ACTOR_ID_LENGTH);
			cur += MKA_ACTOR_ID_LENGTH;
			params->body.sak_use.latest_key_number = ics_read_be32(packet_body + cur);
			cur += 4;
			params->body.sak_use.latest_lapn = ics_read_be32(packet_body + cur);
			cur += 4;
			memcpy(params->body.sak_use.old_key_server_id, packet_body + cur, MKA_ACTOR_ID_LENGTH);
			cur += MKA_ACTOR_ID_LENGTH;
			params->body.sak_use.old_key_number = ics_read_be32(packet_body + cur);
			cur += 4;
			params->body.sak_use.old_lapn = ics_read_be32(packet_body + cur);

			break;
		}
		case MKA_PARAMS_DISTRIBUTED_SAK: {
			params->body.distributed_sak.attribs.data = packet_body[cur++];
			cur += 2;
			
			bool includes_cipher_suite;
			if(body_length == 36 || body_length == 52) {
				includes_cipher_suite = true;
			} else if(body_length == 28) {
				includes_cipher_suite = false;
			} else if(body_length == 0) {
				includes_cipher_suite = false;
				params->body.distributed_sak.cipher_suite = MKA_UNENCRYPTED;
				break;
			} else {
				return MKA_DECODE_INSUFFICIENT_LENGTH3;
			}
			
			params->body.distributed_sak.key_number = ics_read_be32(packet_body + cur);
			cur += 4;
			
			if(includes_cipher_suite) {
				params->body.distributed_sak.cipher_suite = ics_read_be64(packet_body + cur);
				cur += 8;
			} else {
				params->body.distributed_sak.cipher_suite = MKA_GCM_AES_128;
			}

			u8 sak_length = ics_mka_get_sak_length(params->body.distributed_sak.cipher_suite);
			u8 wrapped_sak_length = sak_length + 8;

			if(sak_length == 0) {
				return MKA_DECODE_INVALID_CIPHER_SUITE1;
			}

			if(wrapped_sak_length == MKA_MAX_WRAPPED_SAK_LENGTH && body_length != 52) {
				return MKA_DECODE_INSUFFICIENT_LENGTH5;
			}

			memcpy(params->body.distributed_sak.sak, packet_body + cur, wrapped_sak_length);
			break;
		}
		case MKA_PARAMS_DISTRIBUTED_CAK: {
			u8 cak_length = state->settings.cak_list.caks[state->current_cak].cak_length;
			u8 wrapped_cak_length = cak_length + 8;

			if(body_length <= wrapped_cak_length) {
				return MKA_DECODE_INSUFFICIENT_LENGTH6;
			}

			cur += 3;
			memcpy(params->body.distributed_cak.cak, packet_body + cur, wrapped_cak_length);
			cur += wrapped_cak_length;
			params->body.distributed_cak.ckn = packet_body + cur;			
			params->body.distributed_cak.ckn_length = body_length - wrapped_cak_length;
			break;
		}
		case MKA_PARAMS_KMD: {
			cur += 3;
			params->body.kmd.kmd_length = body_length;
			params->body.kmd.kmd = packet_body + cur;
			break;
		}
		case MKA_PARAMS_ANNOUNCEMENT: {
			cur += 3;
			params->body.announcement.tlvs_length = body_length;
			params->body.announcement.tlvs = packet_body + cur;
			break;
		}
		case MKA_PARAMS_XPN: {
			params->body.xpn.mka_suspension_time = packet_body[cur++];
			cur += 2;
			params->body.xpn.latest_lapn = ics_read_be32(packet_body + cur);
			cur += 4;
			params->body.xpn.old_lapn = ics_read_be32(packet_body + cur);
			break;
		}
		case MKA_PARAMS_ICV_INDICATOR: {
			break;
		}
		case MKA_PARAMS_BASIC: {
			// Anything else is MKA_PARAMS_BASIC type, the spec does not specify
			// a specific integer for this type

			params->type = MKA_PARAMS_BASIC; 
			params->body.basic.version = packet_body[0]; // In this case, the first byte is the MKA version instead of the type 

			params->body.basic.priority = packet_body[cur++];
			params->body.basic.attribs.data = packet_body[cur++];
			cur++;
			params->body.basic.sci = *(u64*)(packet_body + cur);
			cur += 8;

			memcpy(params->body.basic.id, packet_body + cur, MKA_ACTOR_ID_LENGTH);
			cur += MKA_ACTOR_ID_LENGTH;
			params->body.basic.message_id = ics_read_be32(packet_body + cur);
			cur += 4;
			params->body.basic.algorithm_agility = ics_read_be32(packet_body + cur);
			cur += 4;
			params->body.basic.ckn_length = body_length - 28;
			int res = ics_mka_get_cak_index(state, &packet_body[cur], params->body.basic.ckn_length);

			if(res == -1) {
				return MKA_DECODE_INVALID_CAK;
			}
			const mka_cak_info_t* cak_info = &state->settings.cak_list.caks[res];
			params->body.basic.ckn = cak_info->ckn;
			break;
		}		
	}

	u16 padded_length = MKA_HEADER_LENGTH + MKA_ROUND_NEXT_MULTIPLE(body_length, 4);

	if(padded_length > length) {
		return MKA_DECODE_INSUFFICIENT_LENGTH4;
	}

	*length_read = padded_length;
	return MKA_SUCCESS;
}

u16 ics_mka_encoded_length(const mka_state_t* state, mka_params_type_t type) {
	switch(type) {
		case MKA_PARAMS_ACTIVE_LIST:
			return MKA_HEADER_LENGTH + state->num_active * 16;
		case MKA_PARAMS_POTENTIAL_LIST:
			return MKA_HEADER_LENGTH + state->num_potential * 16;
		case MKA_PARAMS_SAK_USE:
			return MKA_HEADER_LENGTH + 40;
		case MKA_PARAMS_KMD:
			return state->settings.kmd ? (u16)(MKA_HEADER_LENGTH + strlen(state->settings.kmd)) : 0;
		case MKA_PARAMS_DISTRIBUTED_SAK: {
			switch(state->sa.cipher_suite) {
				case MKA_GCM_AES_128:
				case MKA_GCM_AES_256:
					return MKA_HEADER_LENGTH + 24;
				case MKA_GCM_AES_XPN_128:
				case MKA_GCM_AES_XPN_256:
					return MKA_HEADER_LENGTH + 40;
			}
		}
		case MKA_PARAMS_DISTRIBUTED_CAK: {
			// TODO
			return 0;
		}
		case MKA_PARAMS_ICV_INDICATOR: {
			// TODO
			return 0;
		}
		case MKA_PARAMS_ANNOUNCEMENT: {
			// TODO handle more announcement cases
			// This only handles the only static case we support, which
			// is advertising available cipher suites
			return MKA_HEADER_LENGTH + 42;
		}
		case MKA_PARAMS_BASIC: {
			const mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];
			return MKA_HEADER_LENGTH + 28 + cak_info->ckn_length;
		}
		case MKA_PARAMS_XPN: {
			return MKA_HEADER_LENGTH + 8;
		}
	}
	// Never gets here
	return 0;
}

mka_result_t ics_mka_encode_params(const mka_state_t* state, u8* packet_body, u16 length, u16* length_wrote, mka_params_type_t type) {
	if(length < MKA_HEADER_LENGTH) {
		return MKA_ENCODE_INSUFFICIENT_LENGTH1;
	} 

	packet_body[2] = 0; // Every params type has this byte as a flag, zero it out

	u16 cur = 0;
	switch(type) {
		case MKA_PARAMS_ACTIVE_LIST:
		case MKA_PARAMS_POTENTIAL_LIST: {
			if(state->num_active == 0 && type == MKA_PARAMS_ACTIVE_LIST) {
				if(length_wrote) {
					*length_wrote = 0;
				}
				return MKA_SUCCESS;
			} else if(state->num_potential == 0 && type == MKA_PARAMS_POTENTIAL_LIST) {
				if(length_wrote) {
					*length_wrote = 0;
				}
				return MKA_SUCCESS;
			}

			packet_body[cur++] = (u8)type;
			u32 list_size = 0;
			u32 peer_indices[MKA_MAX_NUM_PEERS];
			u32 next_index = 0;
			if(type == MKA_PARAMS_POTENTIAL_LIST) {
				packet_body[cur++] = 0;
				for(u32 i = 0; i < MKA_MAX_NUM_PEERS; i++) {
					const mka_participant_t* peer = &state->peers[i];
					if(peer->status == MKA_STATUS_POTENTIAL) {
						list_size++;
						peer_indices[next_index++] = i;
					}			
				}
			} else {
				if(
					state->settings.version >= MKA_VERSION_3 &&
					(state->settings.cipher_suite == MKA_GCM_AES_XPN_128 || state->settings.cipher_suite == MKA_GCM_AES_XPN_256) && 
					state->distributing_sak) {
					packet_body[cur++] = state->key_server_ssci;
				} else {
					packet_body[cur++] = 0;
				}
				for(u32 i = 0; i < MKA_MAX_NUM_PEERS; i++) {
					const mka_participant_t* peer = &state->peers[i];
					if(peer->status == MKA_STATUS_ACTIVE) {
						list_size++;
						peer_indices[next_index++] = i;
					}
				}
				sort_peers(state->peers, peer_indices, list_size); // MKA version 3 or above requires sorted peers
			}

			cur += 2; // Skip the param length portion
			u16 bytes_left = length - cur;
			for(u32 sub_index = 0; sub_index < list_size; sub_index++) {
				u32 index = peer_indices[sub_index];
				const mka_participant_t* peer = &state->peers[index];
				if(bytes_left < (MKA_ACTOR_ID_LENGTH + 4)) {
					return MKA_ENCODE_INSUFFICIENT_LENGTH2;
				}
				memcpy(packet_body + cur, peer->id, MKA_ACTOR_ID_LENGTH);
				cur += MKA_ACTOR_ID_LENGTH;
				ics_write_be32(packet_body + cur, peer->message_id);
				cur += 4;
				bytes_left -= MKA_ACTOR_ID_LENGTH + 4;
			}
			
			break;
		}
		case MKA_PARAMS_SAK_USE: {
			packet_body[cur++] = MKA_PARAMS_SAK_USE;
			packet_body[cur++] = state->sa.attribs.data[0];
			packet_body[cur++] = state->sa.attribs.data[1];
			cur++;

			if(length < MKA_HEADER_LENGTH + 40) {
				return MKA_ENCODE_INSUFFICIENT_LENGTH3;
			}

			memcpy(packet_body + cur, state->sa.latest_key_server_id, MKA_ACTOR_ID_LENGTH);
			cur += MKA_ACTOR_ID_LENGTH;
			ics_write_be32(packet_body + cur, state->sa.latest_key_number);
			cur += 4;
			ics_write_be32(packet_body + cur, (u32)(state->sa.latest_lapn & 0xFFFFFFFFu));
			cur += 4;
			memcpy(packet_body + cur, state->sa.old_key_server_id, MKA_ACTOR_ID_LENGTH);
			cur += MKA_ACTOR_ID_LENGTH;
			ics_write_be32(packet_body + cur, state->sa.old_key_number);
			cur += 4;
			ics_write_be32(packet_body + cur, (u32)(state->sa.old_lapn & 0xFFFFFFFFu));
			cur += 4;

			break;
		}
		case MKA_PARAMS_DISTRIBUTED_SAK: {
			packet_body[cur++] = MKA_PARAMS_DISTRIBUTED_SAK;
			
			u8 flag_bits;
			if(state->settings.version >= MKA_VERSION_3) {
				flag_bits = (state->sa.attribs.flags.latest_key_an << 6) | ((u8)(state->settings.confidentiality_offset) << 4);
			} else {
				flag_bits = (state->sa.attribs.flags.latest_key_an << 6);
			}
			packet_body[cur++] = flag_bits;
			cur += 2;

			if(state->sa.cipher_suite != MKA_UNENCRYPTED) {

				u8 sak_length = ics_mka_get_sak_length(state->sa.cipher_suite);
				u8 wrapped_sak_length = sak_length + 8;

				if(sak_length == 0) {
					return MKA_DECODE_INVALID_CIPHER_SUITE3;
				}

				u64 req_length = MKA_HEADER_LENGTH + wrapped_sak_length + 4;
				if(state->sa.cipher_suite != MKA_GCM_AES_128) {
					req_length += 8;
				}

				if(length < req_length) {
					return MKA_ENCODE_INSUFFICIENT_LENGTH6;
				}
				
				ics_write_be32(packet_body + cur, state->key_number);
				cur += 4;
				
				if(state->sa.cipher_suite != MKA_GCM_AES_128) {
					ics_write_be64(packet_body + cur, state->settings.cipher_suite);
					cur += 8;
				}
				const mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];
				u8 kek_length = cak_info->cak_length;
				if(!ics_mka_aes_key_wrap(state->sa.sak, sak_length, packet_body + cur, state->kek, kek_length)) {
					return MKA_ERROR_AES_KEY_WRAP_SAK;
				}
				cur += wrapped_sak_length;
			}
			break;
		}
		case MKA_PARAMS_DISTRIBUTED_CAK: {			
			// TODO: Currently does not distribute CAK
			break;
		}
		case MKA_PARAMS_KMD: {
			packet_body[cur++] = MKA_PARAMS_KMD;
			cur += 3;

			u16 kmd_len = (u16)strlen(state->settings.kmd);
			memcpy(packet_body + cur, state->settings.kmd, kmd_len);

			cur += kmd_len;
			break;
		}
		case MKA_PARAMS_ANNOUNCEMENT: {
			// TODO handle more announcement cases
			//static const u8 max_announcement_len = 127u;
			static const mka_cipher_suite_t ciphers[4] = { MKA_GCM_AES_128, MKA_GCM_AES_256, MKA_GCM_AES_XPN_128, MKA_GCM_AES_XPN_256 };

			u8 announcement_type = 112; // TODO make this not static

			packet_body[cur++] = MKA_PARAMS_ANNOUNCEMENT;
			packet_body[cur++] = 0;
			packet_body[cur++] = 0;
			packet_body[cur++] = 0;

			u16 announcement_header_start = cur;
			packet_body[cur++] = announcement_type << 1;
			packet_body[cur++] = 0;

			u16 announcement_len = 0;
			for(int i = 0; i < 4; i++) {
				u16 capability = (u16)state->settings.capability;
				ics_write_be16(&packet_body[cur], capability);
				cur += 2;
				announcement_len += 2;
				ics_write_be64(&packet_body[cur], (u64)ciphers[i]);
				cur += 8;
				announcement_len += 8;
			}

			if(announcement_len >= 256) {
				packet_body[announcement_header_start] |= 1u;
			}

			packet_body[announcement_header_start + 1] = announcement_len & 0xFFu;
			break;
		}
		case MKA_PARAMS_XPN: {
			if(length < MKA_HEADER_LENGTH + 8) {
				return MKA_ENCODE_INSUFFICIENT_LENGTH7;
			}
			packet_body[cur++] = MKA_PARAMS_XPN;
			packet_body[cur++] = 0; // TODO: MKA suspension time goes here
			cur += 2;

			u32 msb_lpn = (u32)((state->sa.latest_lapn >> 32) & 0xFFFFFFFFu); 
			u32 msb_opn = (u32)((state->sa.old_lapn >> 32) & 0xFFFFFFFFu);

			ics_write_be32(packet_body + cur, msb_lpn);
			cur += 4;

			ics_write_be32(packet_body + cur, msb_opn);
			cur += 4;

			break;
		}
		case MKA_PARAMS_ICV_INDICATOR: {
			packet_body[cur++] = MKA_PARAMS_ICV_INDICATOR;
			packet_body[cur++] = 0;
			packet_body[cur++] = 0;
			packet_body[cur++] = 0;
			break;
		}
		case MKA_PARAMS_BASIC: {
			// Basic param type
			packet_body[cur++] = state->settings.version == MKA_VERSION_3 ? 3 : 1;
			packet_body[cur++] = state->settings.key_server_priority;
			packet_body[cur++] = 
				(((!state->sak_in_use || ics_mka_is_key_server(state)) ? 1 : 0) << 7) | 
				(state->settings.macsec_desired << 6) | 
				(((u8)state->settings.capability) << 4);

			cur++; // Length gets set later
			const mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];

			if(length < (MKA_HEADER_LENGTH + 28 + cak_info->ckn_length)) {
				return MKA_ENCODE_INSUFFICIENT_LENGTH4;
			}

			ics_mka_encode_sci(state, packet_body + cur);
			cur += 8;
			memcpy(packet_body + cur, state->id, MKA_ACTOR_ID_LENGTH);
			cur += MKA_ACTOR_ID_LENGTH;
			ics_write_be32(packet_body + cur, state->message_id);
			cur += 4;

			packet_body[cur++] = 0x00;
			packet_body[cur++] = 0x80;
			packet_body[cur++] = 0xc2;
			packet_body[cur++] = 0x01;

			memcpy(packet_body + cur, cak_info->ckn, cak_info->ckn_length);
			cur += cak_info->ckn_length;
			break;
		}		
	}
	
	u16 body_length = cur - MKA_HEADER_LENGTH;
	
	if(body_length >= (1 << 12)) {
		return MKA_ENCODE_LENGTH_LIMIT_EXCEEDED1;
	}

	// Write the length bytes
	packet_body[2] |= (body_length >> 8) & 0x0F;
	packet_body[3] = body_length & 0xFF; 

	u16 padded_length = MKA_ROUND_NEXT_MULTIPLE(cur, 4);

	if(padded_length > length) {
		return MKA_ENCODE_INSUFFICIENT_LENGTH5;
	}

	for(;cur < padded_length;) {
		packet_body[cur++] = 0x00;
	}

	if(length_wrote) {
		*length_wrote = padded_length;
	}
	return MKA_SUCCESS;
}

mka_result_t ics_mka_read_basic_params(const mka_state_t* state, const mka_eth_message_t* msg, mka_params_t* basic_params, u16* cur) {
	u16 length_read;
	mka_result_t res = ics_mka_decode_params(state, msg->packet + *cur, (u16)msg->length - *cur, &length_read, basic_params, true);

	if(res != MKA_SUCCESS) {
		return res;
	}

	*cur += length_read;
	if(basic_params->type != MKA_PARAMS_BASIC) {
		return MKA_EXPECTED_BASIC_PARAMS1;
	}

	const u8* peer_ckn = basic_params->body.basic.ckn;
	int cak_index = ics_mka_get_cak_index(state, peer_ckn, basic_params->body.basic.ckn_length);
	if(cak_index < 0) {
		return MKA_UNKNOWN_CAK;
	}
	const mka_cak_info_t* peer_cak = &state->settings.cak_list.caks[cak_index];

	u8 icv[MKA_ICV_LENGTH];
	u8 peer_ick[32];
	u16 ick_length = peer_cak->cak_length;
	if(!ics_mka_gen_ick(peer_cak, peer_ick)) {
		/**
		 * TODO: Better error checking here
		*/
		return MKA_ERROR;
	}

	if(!ics_mka_gen_icv(peer_ick, ick_length, msg->src, msg->dest, msg->packet, (u16)msg->length - MKA_ICV_LENGTH, icv)) {
		return MKA_ICV_GENERATION_ERROR;
	}

	if((*cur + MKA_ICV_LENGTH) >= (u16)msg->length) {
		return MKA_MISSING_ICV;
	}

	if(memcmp(icv, &(msg->packet[msg->length - MKA_ICV_LENGTH]), MKA_ICV_LENGTH)) {
		return MKA_INTEGRITY_CHECK_FAIL;
	}

	return MKA_SUCCESS;
}

mka_result_t ics_mka_get_params_info(const mka_eth_message_t* msg, mka_params_info_t info[MKA_PARAMS_TYPE_COUNT]) {
	memset(info, 0, sizeof(mka_params_info_t) * MKA_PARAMS_TYPE_COUNT);
	u16 cur = MKA_EAPOL_HEADER_LENGTH;
	u16 bytes_left = (u16)msg->length - cur - MKA_ICV_LENGTH;
	int current_params_idx = 0;
	u16 length;

	while((bytes_left > 0) && (current_params_idx < MKA_PARAMS_TYPE_COUNT)) {
		mka_params_type_t cur_type = current_params_idx > 0 ? (mka_params_type_t)msg->packet[cur] : MKA_PARAMS_BASIC;
		mka_result_t res;
		for(;current_params_idx < MKA_PARAMS_TYPE_COUNT && cur_type != idx_to_params_type[current_params_idx]; current_params_idx++) {
			info[current_params_idx].found = false;
		}
		if(current_params_idx == MKA_PARAMS_TYPE_COUNT) {
			return MKA_SUCCESS;
		}
		res = ics_mka_decode_params_size(msg->packet + cur, bytes_left, &length);
		if(res != MKA_SUCCESS) {
			return res;
		}

		info[current_params_idx].type = cur_type;
		info[current_params_idx].found = true;
		info[current_params_idx].offset = cur;
		info[current_params_idx].length = length;

		cur += length;
		bytes_left -= length;
		current_params_idx++;
	}
	if(bytes_left > 0) {
		for(;current_params_idx < MKA_PARAMS_TYPE_COUNT; current_params_idx++) {
			info[current_params_idx].found = false;
		}
	}
	return MKA_SUCCESS;
}
