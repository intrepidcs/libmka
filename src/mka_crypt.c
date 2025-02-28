/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka_crypt.h"
#include <string.h>
#ifdef ICS_MKA_LOG_RESULT
#include <stdio.h>
#endif
#include <stdlib.h>
#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include "mbedtls/nist_kw.h"

static bool aes_prf(mka_state_t* state, u8* out) {
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);

	int res = mbedtls_aes_setkey_enc(&ctx, state->seed, 128);
	if(res != 0) {
		return false;
	}
	u64 current_time = ics_mka_get_current_state_time(state);
	u8* current_time_buf = (u8*)&current_time;
	u8 txt[16];

	for(int i = 0; i < 16; i++) {
		txt[i] = current_time_buf[i % 8] ^ state->id[i % MKA_ACTOR_ID_LENGTH];
	}

	u8 temp_seed[16];
	memcpy(temp_seed, state->seed, 16);
	res = 0;
	res |= mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, txt, out);
	res |= mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, state->seed, temp_seed);
	mbedtls_aes_free(&ctx);

	if(res == 0) {
		memcpy(state->seed, temp_seed, 16);
	}

	return (res == 0);
}

bool ics_mka_aes_key_wrap(const u8* raw_sak, u8 raw_sak_length, u8* encrypted_sak, const u8* kek, u8 kek_length) {
	mbedtls_nist_kw_context ctx;
	mbedtls_nist_kw_init(&ctx);
	mbedtls_nist_kw_setkey(
		&ctx, 
		(mbedtls_cipher_id_t)MBEDTLS_CIPHER_AES_128_ECB, // Not sure why, but the Novus is only happy when we use AES128 here
		kek,
		kek_length * 8,
		1
	);

	size_t out_len;
	mbedtls_nist_kw_wrap(
		&ctx,
		MBEDTLS_KW_MODE_KW,
		raw_sak,
		raw_sak_length,
		encrypted_sak,
		&out_len,
		MKA_MAX_WRAPPED_SAK_LENGTH
	);
	mbedtls_nist_kw_free(&ctx);

	return out_len == (raw_sak_length + 8);

}

bool ics_mka_aes_key_unwrap(u8* raw_sak, const u8* encrypted_sak, u8 encrypted_sak_length, const u8* kek, u8 kek_length) {
	mbedtls_nist_kw_context ctx;
	mbedtls_nist_kw_init(&ctx);
	mbedtls_nist_kw_setkey(
		&ctx, 
		(mbedtls_cipher_id_t)MBEDTLS_CIPHER_AES_128_ECB, // Not sure why, but the Novus is only happy when we use AES128 here
		kek,
		kek_length * 8,
		0
	);

	size_t out_len;
	int ret = mbedtls_nist_kw_unwrap(
		&ctx,
		MBEDTLS_KW_MODE_KW,
		encrypted_sak,
		encrypted_sak_length,
		raw_sak,
		&out_len,
		MKA_MAX_SAK_LENGTH
	);
	mbedtls_nist_kw_free(&ctx);

	return ((out_len + 8) == encrypted_sak_length) && (ret == 0);
}

bool ics_mka_kdf(const u8* key, const u8* label, const u8* context, u32 key_len, u32 label_len, u32 context_len, u16 length, u8* result) {
	u16 encoded_length;
	
	if(ics_is_little_endian()) {
		encoded_length = bswap16(length * 8);
	} else {
		encoded_length = length * 8;
	}


	u32 iterations = (length + (MKA_CMAC_OUTPUT_LEN - 1)) / MKA_CMAC_OUTPUT_LEN; 

	if(iterations > UINT8_MAX) {
		return false;
	}

	mbedtls_cipher_context_t ctx;
	const mbedtls_cipher_info_t* cipher;

	cipher = mbedtls_cipher_info_from_type(key_len == 16 ? MBEDTLS_CIPHER_AES_128_ECB : MBEDTLS_CIPHER_AES_256_ECB);
	mbedtls_cipher_init(&ctx);
	mbedtls_cipher_setup(&ctx, cipher);
	mbedtls_cipher_cmac_starts(&ctx, key, key_len * 8);

	u8 zeroOctet = 0x00;
	u16 bytes_left = length;
	for(u8 i = 1; i <= iterations; i++) {
		u8 cmac_result[16];
		mbedtls_cipher_cmac_update(&ctx, &i, 1);
		mbedtls_cipher_cmac_update(&ctx, label, label_len);
		mbedtls_cipher_cmac_update(&ctx, &zeroOctet, 1);
		mbedtls_cipher_cmac_update(&ctx, context, context_len);
		mbedtls_cipher_cmac_update(&ctx, (u8*)&encoded_length, 2);
		mbedtls_cipher_cmac_finish(&ctx, cmac_result);
		mbedtls_cipher_cmac_reset(&ctx);

		u16 num_to_copy = MKA_MIN(bytes_left, 16);
		memcpy(result + (i - 1) * 16, cmac_result, num_to_copy);
		bytes_left -= num_to_copy;
	}

	mbedtls_cipher_free(&ctx);
	return true; 
}


bool ics_mka_gen_ick(const mka_cak_info_t* cak_info, u8* result) {
	u8 ckn_trunc[16];
	memset(ckn_trunc, 0, 16);
	memcpy(ckn_trunc, cak_info->ckn, MKA_MIN(16, cak_info->ckn_length));

	return ics_mka_kdf(cak_info->cak, (u8*)("IEEE8021 ICK"), ckn_trunc, cak_info->cak_length, 12, 16, cak_info->cak_length, result);
}

bool ics_mka_gen_kek(const mka_cak_info_t* cak_info, u8* result) {
	u8 ckn_trunc[16];
	memset(ckn_trunc, 0, 16);
	memcpy(ckn_trunc, cak_info->ckn, MKA_MIN(16, cak_info->ckn_length));
	return ics_mka_kdf(cak_info->cak, (u8*)("IEEE8021 KEK"), ckn_trunc, cak_info->cak_length, 12, 16, cak_info->cak_length, result);
}

bool ics_mka_gen_icv(const u8* ick, u16 ick_length, const char* src_addr, const char* dest_addr, const u8* packet, u16 length, u8* result) {
	u8 eapol_ether_type[2] = {0x88, 0x8E};

	mbedtls_cipher_context_t ctx;
	const mbedtls_cipher_info_t* cipher;

	cipher = mbedtls_cipher_info_from_type(ick_length == 16 ? MBEDTLS_CIPHER_AES_128_ECB : MBEDTLS_CIPHER_AES_256_ECB);
	mbedtls_cipher_init(&ctx);
	mbedtls_cipher_setup(&ctx, cipher);
	mbedtls_cipher_cmac_starts(&ctx, ick, ick_length * 8);
	mbedtls_cipher_cmac_update(&ctx, (u8*)dest_addr, 6);
	mbedtls_cipher_cmac_update(&ctx, (u8*)src_addr, 6);
	mbedtls_cipher_cmac_update(&ctx, (u8*)eapol_ether_type, 2);
	mbedtls_cipher_cmac_update(&ctx, packet, length);
	mbedtls_cipher_cmac_finish(&ctx, result);
	mbedtls_cipher_free(&ctx);
	/**
	 * TODO: Error checking with crypto API calls
	*/
	return true;
}

bool ics_mka_gen_icv2(const mka_state_t* state, const char* src_addr, const char* dest_addr, const u8* packet, u16 length, u8* result) {
	const mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];
	u16 ick_length = cak_info->cak_length;
	return ics_mka_gen_icv(state->ick, ick_length, src_addr, dest_addr, packet, length, result);
}

#define MKA_MAX_CONTEXT_LEN ((MKA_MAX_NUM_PEERS) * 4 + 32 + 4) 
bool ics_mka_gen_sak(mka_state_t* state) {
	// TODO: We might want to generate the SAK using the KDF like the spec
	u8 sak_length = ics_mka_get_sak_length(state->sa.cipher_suite);

	if(sak_length == 0) {
		return false;
	}

	u8 context[MKA_MAX_CONTEXT_LEN];
	memset(context, 0, MKA_MAX_CONTEXT_LEN);
	u64 context_len = 0;

	if(state->settings.opt.entropy) {
		for(int i = 0; i < sak_length; i++) {
			context[i] = (u8)(state->settings.opt.entropy() % (0xFFu));
		}
	} else {
		if(sak_length == 32) {
			if(!aes_prf(state, &context[0])) {
				return false;
			}
			if(!aes_prf(state, &context[16])) {
				return false;
			}
		} else if(sak_length == 16) {
			if(!aes_prf(state, &context[0])) {
				return false;
			}
		}
	}

	context_len += sak_length;
	for(u32 i = 0; i < MKA_MAX_NUM_PEERS; i++) {
		mka_participant_t* peer = &state->peers[i];
		memcpy(&context[context_len], &peer->message_id, 4);
		context_len += 4;
	}
	
	u32 next_key_number = state->key_number + 1;
	memcpy(&context[context_len], &next_key_number, 4);
	context_len += 4;

	mka_cak_info_t* cak_info = &state->settings.cak_list.caks[state->current_cak];
	u8 temp_sak[32];
	if(!ics_mka_kdf(
		cak_info->cak,
		(u8*)("IEEE8021 SAK"),
		context,
		cak_info->cak_length,
		12,
		(u32)context_len,
		sak_length,
		temp_sak
	)) {
		return false;
	}
	memcpy(state->sa.sak, temp_sak, sak_length);
	state->key_number++;
	return true;
}

bool ics_mka_gen_hash(u8* hash, const u8* sak, u8 sak_length) {
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	
	int res = mbedtls_aes_setkey_enc(&ctx, sak, sak_length * 8);
	if(res) {
		return false;
	}

	static u8 zero_vec[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	res = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, zero_vec, hash);
	mbedtls_aes_free(&ctx);

	return res == 0;
}

bool ics_mka_gen_id(mka_state_t* state) {
	if(state->settings.opt.entropy) {
		for(int i = 0; i < MKA_ACTOR_ID_LENGTH; i++) {
			state->id[i] = (u8)(state->settings.opt.entropy() % (0xFFu));
		}
		return true;
	} else {
		u8 result[16];
		if(aes_prf(state, result)) { 
			memcpy(state->id, result, MKA_ACTOR_ID_LENGTH);
			return true;
		}
	}
	return false;
}
