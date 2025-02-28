/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka_state.h"
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static u64 get_current_time() {
	FILETIME ft;
	ULARGE_INTEGER li;
	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;

	return (u64)((li.QuadPart - 116444736000000000LL) / 10000);
}
#else
#include <sys/time.h>
static u64 get_current_time() {
	struct timeval point;
	gettimeofday(&point, NULL);

	return (u64)((u64)(point.tv_sec) * 1000ull + (u64)(point.tv_usec) / 1000ull);;
}
#endif

u64 ics_mka_get_current_state_time(const mka_state_t* state) {
	if(state->settings.opt.get_current_ms) {
		return state->settings.opt.get_current_ms();
	}
	return get_current_time();
}

void ics_mka_encode_sci(const mka_state_t* state, u8* packet_body) {
	memcpy(packet_body, state->settings.mac_addr, 6);
	packet_body += 6;

	ics_write_be16(packet_body, state->settings.port_id);
}

u8 ics_mka_get_sak_length(mka_cipher_suite_t cipher_suite) {
	switch(cipher_suite) {
		case MKA_GCM_AES_128:
		case MKA_GCM_AES_XPN_128: {
			return 16;
		}
		case MKA_GCM_AES_256:
		case MKA_GCM_AES_XPN_256: {
			return 32;
		}
		case MKA_UNENCRYPTED: {
			return 0;
		}
	}
	return 0;
}

int ics_mka_get_cak_index(const mka_state_t* state, const u8* ckn, u16 ckn_length) {

	for(int i = 0; i < (int)state->settings.cak_list.num_caks; i++) {
		const mka_cak_info_t* cak_info = &state->settings.cak_list.caks[i];
		if(cak_info->ckn_length == ckn_length) {
			if(!memcmp(cak_info->ckn, ckn, ckn_length)) {
				return i;
			}
		}
	}

	return -1;
}

bool ics_mka_is_key_server(const mka_state_t* state) {
	if(state->settings.key_server_priority == 0xFF) {
		return false;
	}

	if(state->num_potential != 0 || state->num_active == 0) {
		return false;
	}

	u64 sci;
	ics_mka_encode_sci(state, (u8*)&sci);

	for(int i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		const mka_participant_t* peer = &state->peers[i];

		u64 sci_be = ics_read_be64((u8*)&sci);
		u64 peer_sci_be = ics_read_be64((u8*)&peer->sci);
		if(
			peer->status == MKA_STATUS_ACTIVE &&
			peer->key_server_priority != 0xFF &&
			(peer->key_server_priority < state->settings.key_server_priority ||
			(peer->key_server_priority == state->settings.key_server_priority && peer_sci_be < sci_be))
		) {
			return false;
		}
	}

	return true;
}