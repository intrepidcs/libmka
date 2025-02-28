/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <pcap_internal.h>

typedef int	(*pcap_findalldevs_internal_t)(pcap_if_t**, char*);
typedef void (*pcap_freealldevs_internal_t)(pcap_if_t*);
typedef pcap_t* (*pcap_open_live_internal_t)(const char*, int, int, int, char*);
typedef void (*pcap_close_internal_t)(pcap_t*);
typedef int	(*pcap_sendpacket_internal_t)(pcap_t*, const u_char*, int);
typedef int (*pcap_next_ex_internal_t)(pcap_t*, struct pcap_pkthdr**, const u_char**);

#ifdef _WIN32
typedef struct pcap_dll {
	pcap_findalldevs_internal_t findalldevs;
	pcap_freealldevs_internal_t freealldevs;
	pcap_open_live_internal_t open_live;
	pcap_close_internal_t close;
	pcap_sendpacket_internal_t sendpacket;
	pcap_next_ex_internal_t next_ex;
	HINSTANCE dll;
} pcap_dll_t;

static pcap_dll_t pcap_dll;
#endif

void initialize_pcap_dll() {
	#ifdef _WIN32
	pcap_dll.dll = LoadLibrary(TEXT("wpcap.dll"));

	if(pcap_dll.dll == NULL) {
		close_pcap_dll();
	}
	pcap_dll.findalldevs = (pcap_findalldevs_internal_t)GetProcAddress(pcap_dll.dll, "pcap_findalldevs");
	pcap_dll.freealldevs = (pcap_freealldevs_internal_t)GetProcAddress(pcap_dll.dll, "pcap_freealldevs");
	pcap_dll.open_live = (pcap_open_live_internal_t)GetProcAddress(pcap_dll.dll, "pcap_open_live");
	pcap_dll.close = (pcap_close_internal_t)GetProcAddress(pcap_dll.dll, "pcap_close");
	pcap_dll.sendpacket = (pcap_sendpacket_internal_t)GetProcAddress(pcap_dll.dll, "pcap_sendpacket");
	pcap_dll.next_ex = (pcap_next_ex_internal_t)GetProcAddress(pcap_dll.dll, "pcap_next_ex");

	#endif
}

void close_pcap_dll() {
	#ifdef _WIN32
	if (pcap_dll.dll) {
		FreeLibrary(pcap_dll.dll);
	}

	pcap_dll.dll = NULL;	
	#endif	
}

int pcap_findalldevs_internal(pcap_if_t** alldevsp, char* errbuf) {
	#ifdef _WIN32
	return pcap_dll.findalldevs(alldevsp, errbuf);
	#else
	return pcap_findalldevs(alldevsp, errbuf);
	#endif
}

void pcap_freealldevs_internal(pcap_if_t* alldevs) {
	#ifdef _WIN32
	pcap_dll.freealldevs(alldevs);
	#else
	pcap_freealldevs(alldevs);
	#endif
}

pcap_t* pcap_open_live_internal(const char* device, int snaplen, int promisc, int to_ms, char* errbuf) {
	#ifdef _WIN32
	return pcap_dll.open_live(device, snaplen, promisc, to_ms, errbuf);
	#else
	return pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
	#endif
}

void pcap_close_internal(pcap_t* p) {
	#ifdef _WIN32
	pcap_dll.close(p);
	#else
	pcap_close(p);
	#endif
}

int pcap_sendpacket_internal(pcap_t* p, const u_char* buf, int size) {
	#ifdef _WIN32
	return pcap_dll.sendpacket(p, buf, size);
	#else
	return pcap_sendpacket(p, buf, size);
	#endif
}

int pcap_next_ex_internal(pcap_t* p, struct pcap_pkthdr** pkt_header, const u_char** pkt_data) {
	#ifdef _WIN32
	return pcap_dll.next_ex(p, pkt_header, pkt_data);
	#else
	return pcap_next_ex(p, pkt_header, pkt_data);
	#endif
}


