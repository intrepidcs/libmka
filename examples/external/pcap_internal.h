/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifdef _WIN32
#include <pcap.h>

#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define LAM_DEFINED
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#ifdef LAM_DEFINED
#undef LAM_DEFINED
#undef WIN32_LEAN_AND_MEAN
#endif
#undef NOMINMAX
#else
#include <netpacket/packet.h>
#include <pcap.h>

#endif

void initialize_pcap_dll();
void close_pcap_dll();

int pcap_findalldevs_internal(pcap_if_t**, char*);
void pcap_freealldevs_internal(pcap_if_t*);

pcap_t* pcap_open_live_internal(const char*, int, int, int, char*);
void pcap_close_internal(pcap_t*);

int pcap_sendpacket_internal(pcap_t*, const u_char*, int);
int pcap_next_ex_internal(pcap_t*, struct pcap_pkthdr**, const u_char**);
