/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ICS_MKA_CRYPT_H
#define ICS_MKA_CRYPT_H

#include "ics/mka/mka_utility.h"
#include "ics/mka/mka_state.h"

#ifdef __cplusplus
extern "C" {
#endif

// ieee 802.1x
bool ics_mka_kdf(const u8* key, const u8* label, const u8* context, u32 key_len, u32 label_len, u32 context_len, u16 length, u8* result);
bool ics_mka_gen_ick(const mka_cak_info_t* cak_info, u8* result);
bool ics_mka_gen_kek(const mka_cak_info_t* cak_info, u8* result);
bool ics_mka_gen_icv(const u8* ick, u16 ick_length, const char* src_addr, const char* dest_addr, const u8* packet, u16 length, u8* result);
bool ics_mka_gen_icv2(const mka_state_t* state, const char* src_addr, const char* dest_addr, const u8* packet, u16 length, u8* result);
bool ics_mka_gen_sak(mka_state_t* state);
bool ics_mka_gen_id(mka_state_t* state);
bool ics_mka_aes_key_wrap(const u8* raw_sak, u8 raw_sak_length, u8* encrypted_sak, const u8* kek, u8 kek_length);
bool ics_mka_aes_key_unwrap(u8* raw_sak, const u8* encrypted_sak, u8 encrypted_sak_length, const u8* kek, u8 kek_length);
bool ics_mka_gen_hash(u8* hash, const u8* sak, u8 sak_length);

#ifdef __cplusplus
}
#endif
#endif