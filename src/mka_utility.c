/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka_utility.h"
#include <string.h>

bool ics_is_little_endian() {
	u32 val = 1;

	return *(u8*)(&val) == 1;
}

u16 ics_read_be16(const u8* buf) {
	if(ics_is_little_endian()) {
		u16 num = *(u16*)(buf);
		return bswap16(num);
	}

	return *(u16*)buf;
}

u32 ics_read_be32(const u8* buf) {
	if(ics_is_little_endian()) {
		u32 num = *(u32*)(buf);
		return bswap32(num);
	}

	return *(u32*)buf;
}

u64 ics_read_be64(const u8* buf) {
	if(ics_is_little_endian()) {
		u64 num = *(u64*)(buf);
		return bswap64(num);
	}

	return *(u64*)buf;
}

void ics_write_be16(u8* buf, u16 num) {
	if(ics_is_little_endian()) {
		num = bswap16(num);
	}

	memcpy((void*)buf, (void*)(&num), sizeof(u16));
}

void ics_write_be32(u8* buf, u32 num) {
	if(ics_is_little_endian()) {
		num = bswap32(num);
	}

	memcpy((void*)buf, (void*)(&num), sizeof(u32));
}

void ics_write_be64(u8* buf, u64 num) {
	if(ics_is_little_endian()) {
		num = bswap64(num);
	}

	memcpy((void*)buf, (void*)(&num), sizeof(u64));
}

u16 ics_read_le16(const u8* buf) {
	if(!ics_is_little_endian()) {
		u16 num = *(u16*)(buf);
		return bswap16(num);
	}

	return *(u16*)buf;
}

u32 ics_read_le32(const u8* buf) {
	if(!ics_is_little_endian()) {
		u32 num = *(u32*)(buf);
		return bswap32(num);
	}

	return *(u32*)buf;
}

u64 ics_read_le64(const u8* buf) {
	if(!ics_is_little_endian()) {
		u64 num = *(u64*)(buf);
		return bswap64(num);
	}

	return *(u64*)buf;
}

void ics_write_le16(u8* buf, u16 num) {
	if(!ics_is_little_endian()) {
		num = bswap16(num);
	}

	memcpy((void*)buf, (void*)(&num), sizeof(u16));
}

void ics_write_le32(u8* buf, u32 num) {
	if(!ics_is_little_endian()) {
		num = bswap32(num);
	}

	memcpy((void*)buf, (void*)(&num), sizeof(u32));
}

void ics_write_le64(u8* buf, u64 num) {
	if(!ics_is_little_endian()) {
		num = bswap64(num);
	}

	memcpy((void*)buf, (void*)(&num), sizeof(u64));
}

