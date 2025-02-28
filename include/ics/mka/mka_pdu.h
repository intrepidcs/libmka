/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ICS_MKA_PDU_H
#define ICS_MKA_PDU_H

#include "ics/mka/mka_params.h"

#ifdef __cplusplus
extern "C" {
#endif

mka_result_t ics_mka_encode_pdu(const mka_state_t* state, u8* payload, u16* length_wrote, const char* dest_addr, const mka_params_set_t param_set);

#ifdef __cplusplus
}
#endif
#endif
