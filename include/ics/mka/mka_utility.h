/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef ICS_MKA_UTILITY_H
#define ICS_MKA_UTILITY_H

#include <stdint.h>
#include <stdbool.h>

#define MKA_MAX_WRAPPED_SAK_LENGTH 40
#define MKA_MAX_WRAPPED_CAK_LENGTH 40
#define MKA_ACTOR_ID_LENGTH 12
#define MKA_MAX_SAK_LENGTH 32
#define MKA_MAX_CAK_LENGTH 32
#define MKA_SALT_LENGTH 12
#define MKA_HASH_LENGTH 16
#define MKA_PARAMS_TYPE_COUNT 10

#define MKA_ETHER_TYPE_EAPOL 0x888E
#define MKA_ETHER_TYPE_MACSEC 0x88E5
#define MKA_ICV_LENGTH 16
#define MKA_CMAC_OUTPUT_LEN 16
#define MKA_ROUND_NEXT_MULTIPLE(num, mult) (mult) * (((num) + (mult) - 1) / (mult)) 

#define MKA_MAX(a, b) ((a) > (b) ? (a) : (b))
#define MKA_MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef bswap16
#define bswap16(num) ((num) >> 8) | (((num) & (UINT8_MAX)) << 8)
#endif

#ifndef bswap32
#define bswap32(num) (((bswap16(((num) >> 16))) & (UINT16_MAX))) | ((bswap16(((num) & (UINT16_MAX)))) << 16)
#endif

#ifndef bswap64
#define bswap64(num) (((bswap32(((num) >> 32))) & (UINT32_MAX))) | ((bswap32(((num) & (UINT32_MAX)))) << 32)
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef u8 mka_actor_id_t[MKA_ACTOR_ID_LENGTH];

typedef u8 mka_sak_t[MKA_MAX_SAK_LENGTH];
typedef u8 mka_wrapped_sak_t[MKA_MAX_WRAPPED_SAK_LENGTH];
typedef u8 mka_wrapped_cak_t[MKA_MAX_WRAPPED_CAK_LENGTH];
typedef u8 mka_cak_t[MKA_MAX_CAK_LENGTH];

typedef u8 mka_params_set_t[MKA_PARAMS_TYPE_COUNT]; // Passed into functions to encode into PDU

typedef u8 mka_hash_t[MKA_HASH_LENGTH];
typedef u8 mka_salt_t[MKA_SALT_LENGTH];


typedef struct mka_eth_message {
	uint16_t eth_type;
	char src[6];
	char dest[6];
	const uint8_t* packet;
	uint32_t length;
} mka_eth_message_t;

#ifdef __cplusplus
extern "C" {
#endif

bool ics_is_little_endian();

u16 ics_read_be16(const u8* buf);
u32 ics_read_be32(const u8* buf);
u64 ics_read_be64(const u8* buf);

void ics_write_be16(u8* buf, u16 num);
void ics_write_be32(u8* buf, u32 num);
void ics_write_be64(u8* buf, u64 num);

u16 ics_read_le16(const u8* buf);
u32 ics_read_le32(const u8* buf);
u64 ics_read_le64(const u8* buf);

void ics_write_le16(u8* buf, u16 num);
void ics_write_le32(u8* buf, u32 num);
void ics_write_le64(u8* buf, u64 num);

#ifdef __cplusplus
}
#endif

#endif

