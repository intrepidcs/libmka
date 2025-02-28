/*
 * Copyright (c) 2025 Intrepid Control Systems, Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ics/mka/mka_result.h"

int ics_mka_result_get_level(mka_result_t type) {
    switch(type) {
        case MKA_SUCCESS:
        case MKA_ERROR:
        case MKA_ICK_GENERATION_ERROR:
        case MKA_KEK_GENERATION_ERROR:
        case MKA_ICV_GENERATION_ERROR:
        case MKA_ENCODE_INSUFFICIENT_LENGTH1:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH2:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH3:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH4:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH5:
        case MKA_ENCODE_INSUFFICIENT_LENGTH6:
        case MKA_ENCODE_INSUFFICIENT_LENGTH7:
	    case MKA_ENCODE_LENGTH_LIMIT_EXCEEDED1:
        case MKA_ERROR_PEER_LIST_FULL:
        case MKA_ERROR_AES_KEY_WRAP_SAK:
        case MKA_INVALID_CAK_LENGTH:
        case MKA_INVALID_CKN_LENGTH:
        case MKA_INVALID_ARG:
        case MKA_CAK_LIST_CAPACITY_REACHED:
        case MKA_NO_CAK:
        case MKA_UNSUPPORTED_VERSION_RECEIVED:
        case MKA_FAILED_TO_INIT_SA:
            return 0;
        case MKA_DECODE_INSUFFICIENT_LENGTH1:
	    case MKA_DECODE_INSUFFICIENT_LENGTH2:
	    case MKA_DECODE_INSUFFICIENT_LENGTH3:
        case MKA_DECODE_INSUFFICIENT_LENGTH4:
        case MKA_DECODE_INSUFFICIENT_LENGTH5:
	    case MKA_DECODE_INSUFFICIENT_LENGTH6:
        case MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH1:
	    case MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH2:
	    case MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH3:
        case MKA_DECODE_INVALID_ALIGN1:
        case MKA_DECODE_INVALID_CAK:
        case MKA_EXPECTED_BASIC_PARAMS1:
        case MKA_UNKNOWN_CAK:
        case MKA_XPN_NOT_FOUND:
        case MKA_ERROR_AES_KEY_UNWRAP_SAK:
        case MKA_ERROR_AES_KEY_UNWRAP_CAK:
        case MKA_MISSING_ICV:
        case MKA_INTEGRITY_CHECK_FAIL:
	    case MKA_DECODE_INVALID_CIPHER_SUITE1:
	    case MKA_DECODE_INVALID_CIPHER_SUITE2:
	    case MKA_DECODE_INVALID_CIPHER_SUITE3:
        case MKA_ERROR_OLD_FRAME:
        case MKA_INVALID_MACSEC_LENGTH:
            return 1;
        default:
            return 1;
    }
}

const char* ics_mka_result_get_message(mka_result_t type) {
    switch(type) {
        case MKA_SUCCESS:
            return "success";
        case MKA_ERROR:
            return "error";
        case MKA_ICK_GENERATION_ERROR:
            return "failed to generate ICK";
        case MKA_KEK_GENERATION_ERROR:
            return "failed to generate KEK";
        case MKA_ICV_GENERATION_ERROR:
            return "failed to generate ICV";
        case MKA_ENCODE_INSUFFICIENT_LENGTH1:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH2:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH3:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH4:
	    case MKA_ENCODE_INSUFFICIENT_LENGTH5:
        case MKA_ENCODE_INSUFFICIENT_LENGTH6:
        case MKA_ENCODE_INSUFFICIENT_LENGTH7:
            return "packet length given was insufficient, larger size required";
	    case MKA_ENCODE_LENGTH_LIMIT_EXCEEDED1:
            return "the encoded packet is too large";
        case MKA_ERROR_PEER_LIST_FULL:
            return "the peer list is full";
        case MKA_ERROR_AES_KEY_WRAP_SAK:
            return "failed to AES wrap SAK";
        case MKA_INVALID_CAK_LENGTH:
            return "an invalid CAK length was given";
        case MKA_INVALID_CKN_LENGTH:
            return "an invalid CKN length was given";
        case MKA_INVALID_ARG:
            return "invalid arguments were passed to the API";
        case MKA_CAK_LIST_CAPACITY_REACHED:
            return "attempted to injest distributed CAK but CAK list was full";
        case MKA_NO_CAK:
            return "no CAK has been added";
        case MKA_UNSUPPORTED_VERSION_RECEIVED:
            return "a key server tried to enable a feature which is not supported by this MKA version";
        case MKA_FAILED_TO_INIT_SA:
            return "failed to initialize SA";
        case MKA_DECODE_INSUFFICIENT_LENGTH1:
	    case MKA_DECODE_INSUFFICIENT_LENGTH2:
	    case MKA_DECODE_INSUFFICIENT_LENGTH3:
        case MKA_DECODE_INSUFFICIENT_LENGTH4:
        case MKA_DECODE_INSUFFICIENT_LENGTH5:
	    case MKA_DECODE_INSUFFICIENT_LENGTH6:
            return "the state machine could not decode the message based on the length, message malformed";
        case MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH1:
	    case MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH2:
	    case MKA_DECODE_PARAMS_SIZE_INSUFFICIENT_LENGTH3:
            return "the state machine could not deduce the message length";
        case MKA_DECODE_INVALID_ALIGN1:
            return "invalid rx message alignment";
        case MKA_DECODE_INVALID_CAK:
            return "invalid CAK received";
        case MKA_EXPECTED_BASIC_PARAMS1:
            return "basic parameters not encoded at the start of the packet";
        case MKA_UNKNOWN_CAK:
            return "an unknown CAK has been received";
        case MKA_XPN_NOT_FOUND:
            return "state failed to resolve XPN parameters";
        case MKA_ERROR_AES_KEY_UNWRAP_SAK:
            return "failed to unwrap SAK";
        case MKA_ERROR_AES_KEY_UNWRAP_CAK:
            return "failed to unwrap CAK";
        case MKA_MISSING_ICV:
            return "received message is missing an ICV";
        case MKA_INTEGRITY_CHECK_FAIL:
            return "failed to integrity check received message";
	    case MKA_DECODE_INVALID_CIPHER_SUITE1:
	    case MKA_DECODE_INVALID_CIPHER_SUITE2:
	    case MKA_DECODE_INVALID_CIPHER_SUITE3:
            return "invalid cipher suite received for this MKA version";
        case MKA_ERROR_OLD_FRAME:
            return "peer message id was older than what is cached";
        case MKA_INVALID_MACSEC_LENGTH:
            return "failed to resolve received macsec message length";
        default:
            return "an internal error has occured";
    }
}