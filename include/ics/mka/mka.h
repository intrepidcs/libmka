/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ICS_MKA_API_H
#define ICS_MKA_API_H

#include "ics/mka/mka_state.h"
#include "ics/mka/mka_result.h"

// Timeout values given in milliseconds
#define MKA_HELLO_TIME 2000
#define MKA_BOUNDED_HELLO_TIME 500
#define MKA_LIFE_TIME 6000
#define MKA_SUSPENSION_LIMIT 120000

#ifdef __cplusplus
extern "C" {
#endif

mka_result_t ics_mka_settings_init(mka_settings_t* settings);
mka_result_t ics_mka_add_cak(mka_settings_t* settings, const u8* cak, u8 cak_length, const u8* ckn, u8 ckn_length);

mka_result_t ics_mka_init(mka_state_t* state, mka_settings_t* settings);
mka_result_t ics_mka_cleanup(mka_state_t* state);
mka_result_t ics_mka_get_settings(mka_state_t* state, mka_settings_t** settings);

mka_result_t ics_mka_process_message(mka_state_t* state, const u8* eth_packet, u16 length);
mka_result_t ics_mka_next_pdu_length(mka_state_t* state, u16* length_out);
mka_result_t ics_mka_next_pdu(mka_state_t* state, u8* eth_packet_out, u16* length_out, u64 next_pn);
mka_result_t ics_mka_has_response(mka_state_t* state);
void ics_mka_validate_key_server_rx(mka_state_t* state);

#ifdef __cplusplus
}
#endif

#endif

