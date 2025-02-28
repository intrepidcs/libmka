/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>

#pragma pack(push, 1)
struct pcapng_shb {
	u32 block_type;
	u32 block_length;
	u32 magic_num;
	u16 major_version;
	u16 minor_version;
	u64 section_length;
	u32 block_length2;
};

struct pcapng_interface_description {
	u32 block_type;
	u32 block_length;
	u16 link_type;
	u16 reserved;
	u32 snap_length;
	u32 block_length2;
};

struct pcapng_pdu_header {
	u32 block_type;
	u32 block_length;
	u32 interface_id;
	u32 seconds;
	u32 useconds;
	u32 captured_length;
	u32 length;
};
#pragma pack(pop)

void write_pcap_header(std::ofstream& file) {
	pcapng_shb shb;
	shb.block_type = 0x0a0d0d0a;
	shb.block_length = sizeof(pcapng_shb);
	shb.magic_num = 0x1a2b3c4du;
	shb.major_version = 1;
	shb.minor_version = 0;
	shb.section_length = 0xFFFFFFFFFFFFFFFFu;
	shb.block_length2 = shb.block_length;

	file.write(reinterpret_cast<const char*>(&shb), sizeof(pcapng_shb));

	pcapng_interface_description desc;
	desc.block_type = 0x00000001u;
	desc.block_length = sizeof(pcapng_interface_description);
	desc.link_type = 0x01u;
	desc.reserved = 0;
	desc.snap_length = 0x0000FFFF;
	desc.block_length2 = desc.block_length;

	file.write(reinterpret_cast<const char*>(&desc), desc.block_length);
}

void write_pdu(std::ofstream& file, u8* pdu, u16 length, u64 usec) {
	pcapng_pdu_header header;
	header.block_type = 0x00000006;
	header.block_length = sizeof(pcapng_pdu_header) + 4 + length;
	u32 padding = MKA_ROUND_NEXT_MULTIPLE(header.block_length, 4) - header.block_length;
	header.block_length += padding;
	header.interface_id = 0;
	header.seconds = usec / 100000u;
	header.useconds = usec % 100000u;
	header.captured_length = length;
	header.length = length;

	file.write(reinterpret_cast<const char*>(&header), sizeof(pcapng_pdu_header));
	file.write(reinterpret_cast<const char*>(pdu), length);
	for(auto i = 0; i < padding; i++) file.put(0);
	file.write(reinterpret_cast<const char*>(&header.block_length), 4);
}

int main(int argc, char** argv) {
    u8 cak[] = {0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    u8 ckn[] = {0x96, 0x43, 0x7a, 0x93, 0xcc, 0xf1, 0x0d, 0x9d, 0xfe, 0x34, 0x78, 0x46, 0xcc, 0xe5, 0x2c, 0x7d};

	mka_state station1;
	mka_state station2;

	mka_settings_t settings1;
	ics_mka_settings_init(&settings1);
	settings1.cipher_suite = MKA_GCM_AES_128;
	settings1.plain_rx = true;
	settings1.plain_tx = true;
	settings1.macsec_desired = true;
	settings1.kmd = "ICS Example Station 1";
	memset(settings1.mac_addr, 0x03, 6);
	settings1.port_id = 0x01;
	settings1.key_server_priority = 0x02;
	settings1.version = MKA_VERSION_3;
	settings1.capability = MKA_MACSEC_INTEGRITY_AND_CONFIDENTIALITY_OFFSET;

	mka_settings_t settings2;
	ics_mka_settings_init(&settings2);
	settings2.cipher_suite = MKA_GCM_AES_128;
	settings2.plain_rx = true;
	settings2.plain_tx = true;
	settings2.macsec_desired = true;
	settings2.kmd = "ICS Example Station 2";
	memset(settings2.mac_addr, 0x04, 6);
	settings2.port_id = 0x01;
	settings2.key_server_priority = 0x03;
	settings2.version = MKA_VERSION_3;
	settings2.capability = MKA_MACSEC_INTEGRITY_AND_CONFIDENTIALITY_OFFSET;

	ics_mka_add_cak(&settings1, cak, 16, ckn, 16);
	ics_mka_add_cak(&settings2, cak, 16, ckn, 16);

	u64 next_pn = 0;

	if(auto res = ics_mka_init(&station1, &settings1); res != MKA_SUCCESS) {
		std::cout << "Error initializing station 1" << std::endl;
		std::cout << "Error code: " << (int)res << std::endl;

		return EXIT_FAILURE;
	}

	if(auto res = ics_mka_init(&station2, &settings2); res != MKA_SUCCESS) {
		std::cout << "Error initializing station 2" << std::endl;
		std::cout << "Error code: " << (int)res << std::endl;

		return EXIT_FAILURE;
	}


	u8 pdu[1600];
	u16 length;
	std::ofstream file("mka_example.pcapng", std::ios::binary);

	if(file.bad()) {
		std::cout << "File bad" << std::endl;

		return EXIT_FAILURE;
	} 

	write_pcap_header(file);

	auto start = std::chrono::high_resolution_clock::now();

	for(int i = 0; i < 60; i++) {
		bool send_response;
		if(i != 0) {
			if(auto res = ics_mka_process_message(&station1, pdu, length); res != MKA_SUCCESS) {
				std::cout << "Error processing message 1" << std::endl;
				std::cout << "Error code: " << (int)res << std::endl;

				return EXIT_FAILURE;
			}
		}

		if(auto res = ics_mka_next_pdu(&station1, pdu, &length, next_pn); res != MKA_SUCCESS) {
			std::cout << "Error getting next pdu 1" << std::endl;
			std::cout << "Error code: " << (int)res << std::endl;

			return EXIT_FAILURE;
		}

		auto elapsed = std::chrono::high_resolution_clock::now() - start;
		u64 usec = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
		write_pdu(file, pdu, length, usec);

		if(auto res = ics_mka_process_message(&station2, pdu, length); res != MKA_SUCCESS) {
			std::cout << "Error processing message 2" << std::endl;
			std::cout << "Error code: " << (int)res << std::endl;

			return EXIT_FAILURE;
		}

		if(auto res = ics_mka_next_pdu(&station2, pdu, &length, next_pn); res != MKA_SUCCESS) {
			std::cout << "Error getting next pdu 2" << std::endl;
			std::cout << "Error code: " << (int)res << std::endl;

			return EXIT_FAILURE;
		}

		elapsed = std::chrono::high_resolution_clock::now() - start;
		usec = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
		write_pdu(file, pdu, length, usec);
	}

	return EXIT_SUCCESS;
}

