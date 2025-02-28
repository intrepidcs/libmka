/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka_pdu.h"
#include "ics/mka/mka_crypt.h"
#include <string.h>

mka_result_t ics_mka_encode_pdu(const mka_state_t* state, u8* payload, u16* length_wrote, const char* dest_addr, const mka_params_set_t param_set) {	
	u16 cur = 0;
	payload[cur++] = (u8)state->settings.eapol_version;
	payload[cur++] = MKA_EAPOL_TYPE;
	cur += 2; // Skip length until the end.

	for(u16 i = 0; i < MKA_PARAMS_TYPE_COUNT; i++) {
		if(param_set[i]) {
			u16 params_length_wrote;
			mka_result_t res = ics_mka_encode_params(state, payload + cur, MKA_MTU_ETHERNET - cur, &params_length_wrote, idx_to_params_type[i]);
			if(res != MKA_SUCCESS) {
				return res;
			}

			cur += params_length_wrote;
		}
	}

	ics_write_be16(payload + 2, cur + MKA_ICV_LENGTH - MKA_EAPOL_HEADER_LENGTH); // Now write length (the length will include the ICV and exclude the header)
	if(!ics_mka_gen_icv2(state, state->settings.mac_addr, dest_addr, payload, cur, payload + cur)) {
		/**
		 * TODO: Better error checking
		*/
		return MKA_ERROR;
	}

	cur += MKA_ICV_LENGTH;

	if(length_wrote) {
		*length_wrote = cur;
	}
	return MKA_SUCCESS;
}

