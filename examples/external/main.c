/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka.h"
#include <stdio.h>
#include <string.h>
#include <pcap_internal.h>

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

	return (u64)(point.tv_sec * 1000 + point.tv_usec / 1000);
}
#endif

pcap_t* get_pcap_handle() {
	pcap_if_t* alldevs;
	pcap_if_t* pcap_if;
	pcap_t* pcap_handle;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	int pcap_res = pcap_findalldevs_internal(&alldevs, errbuf);

	if(pcap_res < 0) {
		printf("Failed to get pcap devices");
		return NULL;
	}

	int i = 0;
	for(pcap_if_t* dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++i, dev->name);
		if (dev->description) {
			printf(" (%s)\n", dev->description);
		} else {
			printf(" (No description available)\n");
		}
	}

	if(i==0) {
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return NULL;
	}

	int selection;
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &selection);

	if(selection < 1 || selection > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs_internal(alldevs);
		return NULL;
	}

	for(pcap_if = alldevs, i = 0; i < (selection - 1); pcap_if = pcap_if->next, i++);

	errbuf[0] = '\0';
	pcap_handle = pcap_open_live_internal(pcap_if->name, 65536, -1, 200, errbuf);

	if(pcap_handle == NULL) {
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", pcap_if->name);
		pcap_freealldevs_internal(alldevs);
		return NULL;
	}

	printf("\nlistening on %s...\n", pcap_if->description);
	pcap_freealldevs_internal(alldevs);

	return pcap_handle;	
}

int pcap_recv(pcap_t* handle, u8** buf, u16* size) {
	struct pcap_pkthdr* header;
	int res = pcap_next_ex_internal(handle, &header, (const u_char**)buf);
	if(res < 0) {
		return res;
	}

	*size = (u16)header->len;
	return res;
}

int pcap_send(pcap_t* handle, u8* buf, u16 size) {
	return pcap_sendpacket_internal(handle, buf, size);
}

void sa_installer(const mka_sa_t* sa, void* user_data) {
	printf("\nSAK received:\n");
	for(int i = 0; i < sa->sak_length; i++) {
		printf("%02x", sa->sak[i]);
		if(i != (sa->sak_length - 1)) {
			printf(":");
		}
	}
}

int main(int argc, char** argv) {

	initialize_pcap_dll();

	u8 cak[] = {0x1a, 0x5b, 0x7a, 0x3f, 0x54, 0x9c, 0x7c, 0xa4, 0x47, 0x2d, 0x66, 0x9d, 0x16, 0x4d, 0xec, 0x27};
	u8 ckn[] = {0x45, 0x0c, 0x82, 0xb7, 0x8a, 0xf6, 0x59, 0x3c, 0x67, 0xa5, 0x5d, 0x48, 0x0f,
		0x03, 0xe5, 0x02, 0xa1, 0x2c, 0x04, 0x37, 0x50, 0xb8, 0xe0, 0x11, 0xdd, 0xa3, 0xc9, 0x21, 0x62, 0xbe, 0x68, 0x2b};

	u8 mac_addr[] = {0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB};

	mka_state_t state = {0};
	mka_settings_t settings = {0};
	ics_mka_settings_init(&settings);
	settings.plain_rx = false;
	settings.plain_tx = false;
	settings.confidentiality_offset = MKA_NO_CONFIDENTIALITY;
	settings.macsec_desired = true;
	settings.cipher_suite = MKA_GCM_AES_128;
	settings.key_server_priority = 130;
	settings.port_id = 0x01;
	settings.sa_installer = sa_installer;
	settings.version = MKA_VERSION_3;
	settings.capability = MKA_MACSEC_INTEGRITY_AND_CONFIDENTIALITY_OFFSET;
	memcpy(settings.mac_addr, mac_addr, 6);
	ics_mka_add_cak(&settings, cak, 16, ckn, 32);

	mka_result_t res = ics_mka_init(&state, &settings);
	if(res != MKA_SUCCESS) {
		printf("Error initializing mka_state_t, error_code: %d\n", (int)res);
		close_pcap_dll();
		return -1;
	}

	
	pcap_t* pcap_handle = get_pcap_handle();
	if(pcap_handle == NULL) {
		close_pcap_dll();
		return -1;
	}

	int pcap_res = 0;
	u8* received_data;
	u16 received_size;
	u8 out_data[1514];
	u16 out_size;
	u64 next_pn = 0;
	while((pcap_res = pcap_recv(pcap_handle, &received_data, &received_size)) >= 0) {
		if(pcap_res != 0) {
			res = ics_mka_process_message(&state, received_data, received_size);
			if(res != MKA_SUCCESS) {
				printf("Error processing message, error_code: %d\n", (int)res);
			}
		}
		if((ics_mka_has_response(&state)) {
			res = ics_mka_next_pdu(&state, out_data, &out_size, next_pn);
			if(res != MKA_SUCCESS) {
				printf("Error getting next pdu, error_code: %d\n", (int)res);
			}

			pcap_res = pcap_send(pcap_handle, out_data, out_size);

			if(pcap_res != 0) {
				printf("Error sending packet\n");
				pcap_close_internal(pcap_handle);
				close_pcap_dll();
				return -1;
			}
		}
	}

	printf("Closing...\n");
	pcap_close_internal(pcap_handle);
	close_pcap_dll();
	return 0;
}
