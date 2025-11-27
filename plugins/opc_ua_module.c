// opc_ua_module.c
#include "fuzzer_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#define OPC_UA_HEADER_SIZE 8
#define OPC_UA_HEL_MESSAGE_SIZE 32
#define OPC_UA_OPN_MESSAGE_SIZE 64
#define OPC_UA_MSG_MESSAGE_SIZE 128
#define OPC_UA_MAX_CHUNK_SIZE 65536
#define OPC_UA_SECURITY_HEADER_OFFSET 8

// Safe type punning functions
static inline void write_uint32_as_bytes(uint8_t *dest, uint32_t value) {
    memcpy(dest, &value, sizeof(uint32_t));
}

static inline void write_uint64_as_bytes(uint8_t *dest, uint64_t value) {
    memcpy(dest, &value, sizeof(uint64_t));
}

static inline void write_double_as_bytes(uint8_t *dest, double value) {
    memcpy(dest, &value, sizeof(double));
}

static inline uint32_t read_uint32_from_bytes(const uint8_t *src) {
    uint32_t value;
    memcpy(&value, src, sizeof(uint32_t));
    return value;
}

typedef struct {
    uint8_t message_types[8];
    uint8_t chunk_types[4];
    uint8_t security_policies[8];
    uint8_t security_modes[4];
    uint8_t node_id_types[8];
    uint8_t data_values[16];
    uint8_t status_codes[16];
    uint8_t diagnostic_masks[8];
} opc_ua_dictionary_t;

static const uint8_t MESSAGE_TYPES[] = {'H', 'E', 'L', 'F', 'O', 'P', 'N', 'F', 'M', 'S', 'G', 'F', 'C', 'L', 'O', 'F'};
static const uint8_t CHUNK_TYPES[] = {'A', 'C', 'F', 'E'};
static const uint32_t SECURITY_POLICIES[] = {0, 1, 2, 0xFFFFFFFF, 0xFFFFFFFE, 0x7FFFFFFF, 0x80000000, 0x12345678};
static const uint32_t SECURITY_MODES[] = {1, 2, 3, 0, 0xFFFFFFFF, 0xFFFFFFFE};
static const uint8_t NODE_ID_TYPES[] = {0, 1, 2, 3, 4, 0xFF, 0xFE, 0x7F};

static void init_opc_ua_dictionary(opc_ua_dictionary_t *dict) {
    memcpy(dict->message_types, MESSAGE_TYPES, sizeof(MESSAGE_TYPES));
    memcpy(dict->chunk_types, CHUNK_TYPES, sizeof(CHUNK_TYPES));
    
    for (int i = 0; i < 8; i++) {
        dict->security_policies[i] = SECURITY_POLICIES[i] & 0xFF;
    }
    
    for (int i = 0; i < 4; i++) {
        dict->security_modes[i] = SECURITY_MODES[i] & 0xFF;
    }
    
    memcpy(dict->node_id_types, NODE_ID_TYPES, sizeof(NODE_ID_TYPES));
    
    uint8_t data_vals[] = {
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00
    };
    memcpy(dict->data_values, data_vals, sizeof(data_vals));
    
    uint8_t status_codes[] = {
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00
    };
    memcpy(dict->status_codes, status_codes, sizeof(status_codes));
    
    uint8_t diag_masks[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
    memcpy(dict->diagnostic_masks, diag_masks, sizeof(diag_masks));
}

static void build_opc_ua_header(uint8_t *packet, const char *msg_type, uint32_t message_size, uint8_t chunk_type) {
    memcpy(packet, msg_type, 3);
    packet[3] = chunk_type;
    // FIXED: Use safe type writing instead of pointer casting
    write_uint32_as_bytes(packet + 4, htonl(message_size));
}

static void build_hello_message(uint8_t *packet, size_t *len, session_context_t *session) {
    (void)session; // Mark unused parameter
    
    build_opc_ua_header(packet, "HEL", OPC_UA_HEL_MESSAGE_SIZE, 'F');
    
    // FIXED: Use safe type writing instead of pointer casting
    write_uint32_as_bytes(packet + 8, htonl(0));
    write_uint32_as_bytes(packet + 12, htonl(65536));
    write_uint32_as_bytes(packet + 16, htonl(65536));
    write_uint32_as_bytes(packet + 20, htonl(0));
    write_uint32_as_bytes(packet + 24, htonl(0));
    write_uint32_as_bytes(packet + 28, htonl(0));
    
    *len = OPC_UA_HEL_MESSAGE_SIZE;
}

static void build_open_message(uint8_t *packet, size_t *len, session_context_t *session) {
    build_opc_ua_header(packet, "OPN", OPC_UA_OPN_MESSAGE_SIZE, 'F');
    
    // FIXED: Use safe type writing instead of pointer casting
    write_uint32_as_bytes(packet + 8, htonl(session ? session->session_id : 1));
    write_uint32_as_bytes(packet + 12, htonl(0));
    write_uint32_as_bytes(packet + 16, htonl(0));
    write_uint32_as_bytes(packet + 20, htonl(0));
    write_uint32_as_bytes(packet + 24, htonl(session ? session->transaction_id : 1));
    write_uint32_as_bytes(packet + 28, htonl(1));
    write_uint32_as_bytes(packet + 32, htonl(0x454D4F43));
    
    *len = OPC_UA_OPN_MESSAGE_SIZE;
}

static void build_data_message(uint8_t *packet, size_t *len, int read_only, session_context_t *session) {
    build_opc_ua_header(packet, "MSG", OPC_UA_MSG_MESSAGE_SIZE, 'F');
    
    // FIXED: Use safe type writing instead of pointer casting
    write_uint32_as_bytes(packet + 8, htonl(session ? session->session_id : 1));
    write_uint32_as_bytes(packet + 12, htonl(1));
    write_uint32_as_bytes(packet + 16, htonl(session ? session->transaction_id : 1));
    write_uint32_as_bytes(packet + 20, htonl(session ? session->transaction_id : 1));
    write_uint32_as_bytes(packet + 24, htonl(read_only ? 0x444152 : 0x445752));
    write_uint32_as_bytes(packet + 28, htonl(2));
    write_uint32_as_bytes(packet + 32, htonl(0));
    write_uint32_as_bytes(packet + 36, htonl(1234));
    
    *len = OPC_UA_MSG_MESSAGE_SIZE;
}

static void opc_ua_generate_packet(uint8_t *packet, size_t *len, int is_initial, int read_only, session_context_t *session) {
    if (is_initial) {
        build_hello_message(packet, len, session);
    } else {
        if (rand() % 3 == 0) {
            build_open_message(packet, len, session);
        } else {
            build_data_message(packet, len, read_only, session);
        }
    }
    
    if (session) {
        session->transaction_id++;
    }
}

static void mutate_opc_ua_specific(uint8_t *packet, size_t *len, enum strategy strat, float rate) {
    opc_ua_dictionary_t dict;
    init_opc_ua_dictionary(&dict);
    
    if (*len < OPC_UA_HEADER_SIZE) return;
    
    switch (strat) {
        case RANDOM:
            if (*len >= 4) {
                packet[0] = dict.message_types[rand() % 8];
                packet[1] = dict.message_types[rand() % 8 + 8];
                packet[3] = dict.chunk_types[rand() % 4];
            }
            break;
            
        case BITFLIP:
            for (size_t i = 0; i < *len && i < 16; i++) {
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= (1 << (rand() % 8));
                }
            }
            break;
            
        case OVERFLOW:
            if (*len >= 8) {
                // FIXED: Use safe type writing instead of pointer casting
                write_uint32_as_bytes(packet + 4, htonl(0xFFFFFFFF));
            }
            if (*len >= 16) {
                write_uint32_as_bytes(packet + 12, htonl(0xFFFFFFFF));
            }
            break;
            
        case DICTIONARY:
            if (*len >= 8) {
                packet[3] = dict.chunk_types[rand() % 4];
            }
            if (*len >= 12) {
                write_uint32_as_bytes(packet + 8, htonl(SECURITY_POLICIES[rand() % 8]));
            }
            break;
            
        case FORMAT_STRING:
            if (*len >= 32) {
                const char *format_strings[] = {
                    "opc.tcp://%s%s%s%s:4840",
                    "urn:%s%s%s%s:OPCUA",
                    "ns=%u;%s%s%s%s"
                };
                const char *inject = format_strings[rand() % 3];
                size_t inject_len = strlen(inject);
                if (28 + inject_len < *len) {
                    memcpy(packet + 28, inject, inject_len);
                }
            }
            break;
            
        case TYPE_CONFUSION:
            if (*len >= 20) {
                // FIXED: Use safe type conversion instead of pointer casting
                uint64_t int64_val;
                memcpy(&int64_val, packet + 12, sizeof(uint64_t));
                double double_val = (double)int64_val;
                write_double_as_bytes(packet + 12, double_val);
            }
            break;
            
        case TIME_BASED:
            if (*len >= 24) {
                uint64_t timestamp = time(NULL) + (rand() % 1000000);
                write_uint64_as_bytes(packet + 16, timestamp);
            }
            break;
            
        case SEQUENCE_VIOLATION:
            if (*len >= 20) {
                write_uint32_as_bytes(packet + 16, htonl(0xFFFFFFFF));
            }
            break;
            
        default:
            // Handle any unhandled strategies
            break;
    }
}

static void inject_node_id_attack(uint8_t *packet, size_t *len) {
    if (*len < 32) return;
    
    uint8_t attack_type = rand() % 4;
    
    switch (attack_type) {
        case 0:
            write_uint32_as_bytes(packet + 28, htonl(0xFFFFFFFF));
            break;
        case 1:
            write_uint32_as_bytes(packet + 28, htonl(0x00000000));
            break;
        case 2:
            if (*len >= 40) {
                write_uint32_as_bytes(packet + 32, htonl(0xFFFFFFFF));
            }
            break;
        case 3:
            if (*len >= 36) {
                write_uint32_as_bytes(packet + 32, htonl(0xFFFFFFFE));
            }
            break;
    }
}

static void inject_security_token_attack(uint8_t *packet, size_t *len) {
    if (*len < 16) return;
    
    uint8_t attack_type = rand() % 3;
    
    switch (attack_type) {
        case 0:
            write_uint32_as_bytes(packet + 12, htonl(0));
            break;
        case 1:
            write_uint32_as_bytes(packet + 12, htonl(0xFFFFFFFF));
            break;
        case 2:
            write_uint32_as_bytes(packet + 12, htonl(rand() % 1000));
            break;
    }
}

static void inject_message_size_attack(uint8_t *packet, size_t *len) {
    if (*len < 8) return;
    
    uint8_t attack_type = rand() % 4;
    
    switch (attack_type) {
        case 0:
            write_uint32_as_bytes(packet + 4, htonl(0));
            break;
        case 1:
            write_uint32_as_bytes(packet + 4, htonl(0xFFFFFFFF));
            break;
        case 2:
            write_uint32_as_bytes(packet + 4, htonl(*len + 1000000));
            break;
        case 3:
            write_uint32_as_bytes(packet + 4, htonl(1));
            break;
    }
}

static void opc_ua_mutate_packet(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    mutate_opc_ua_specific(packet, len, strat, rate);
    
    opc_ua_dictionary_t dict;
    init_opc_ua_dictionary(&dict);
    
    for (size_t i = 0; i < *len && i < BUF_SIZE; i++) {
        if ((float)rand() / RAND_MAX >= rate) continue;
        
        switch (strat) {
            case RANDOM:
                packet[i] = rand() % 256;
                break;
                
            case BITFLIP:
                packet[i] ^= (1 << (rand() % 8));
                break;
                
            case OVERFLOW:
                if (i >= 4 && i <= 7) {
                    packet[i] = 0xFF;
                } else if (i >= 12 && i <= 15) {
                    packet[i] = 0xFF;
                } else {
                    packet[i] = (packet[i] + 200) % 256;
                }
                break;
                
            case DICTIONARY:
                if (i < 4) packet[i] = dict.message_types[rand() % 16];
                else if (i == 3) packet[i] = dict.chunk_types[rand() % 4];
                else if (i >= 8 && i < 16) packet[i] = dict.security_policies[rand() % 8];
                else if (i >= 28 && i < 36) packet[i] = dict.node_id_types[rand() % 8];
                else packet[i] = dict.data_values[rand() % 16];
                break;
                
            case FORMAT_STRING:
                if (i < *len - 20) {
                    const char *ua_formats[] = {
                        "ns=%d;s=%s%s%s%s", "i=%lu%s%s%s%s", "g=%08x%s%s%s%s",
                        "opc.tcp://[%s]:%d/%s", "https://%s/%s%s%s%s"
                    };
                    const char *inject = ua_formats[rand() % 5];
                    size_t inject_len = strlen(inject);
                    if (i + inject_len < *len) {
                        memcpy(&packet[i], inject, inject_len);
                        i += inject_len - 1;
                    }
                }
                break;
                
            case TYPE_CONFUSION:
                if (i < *len - 8) {
                    // FIXED: Use safe type conversion instead of pointer casting
                    uint64_t large_int = 0xFFFFFFFFFFFFFFFFULL;
                    double large_float;
                    memcpy(&large_float, &large_int, sizeof(uint64_t));
                    write_double_as_bytes(&packet[i], large_float);
                    i += 7;
                }
                break;
                
            case TIME_BASED:
                if (i < *len - 8) {
                    uint64_t future_time = 0xFFFFFFFFFFFFFFFFULL - (time(NULL) % 1000000);
                    write_uint64_as_bytes(&packet[i], future_time);
                    i += 7;
                }
                break;
                
            case SEQUENCE_VIOLATION:
                if (i >= 16 && i <= 23) {
                    packet[i] = (i == 16 || i == 20) ? 0xFE : 0xFF;
                }
                break;
                
            case PROTOCOL_FUZZING:
                packet[i] ^= 0xAA;
                break;
                
            case COMBINATORIAL:
                packet[i] = (dict.message_types[rand() % 8] ^ 
                           dict.chunk_types[rand() % 4]) + 
                           dict.node_id_types[rand() % 8];
                break;
                
            default:
                // Default mutation for any unhandled strategies
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= 0x55;
                }
                break;
        }
    }
    
    if (rand() % 4 == 0) {
        inject_node_id_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_security_token_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_message_size_attack(packet, len);
    }
    
    if (rand() % 5 == 0) {
        size_t new_len = rand() % BUF_SIZE;
        if (new_len > OPC_UA_HEADER_SIZE) *len = new_len;
    }
    
    if (*len >= 8) {
        write_uint32_as_bytes(packet + 4, htonl(*len));
    }
}

static int analyze_opc_ua_response(uint8_t *response, int len, session_context_t *session) {
    if (len <= 0) return -1;
    
    if (len < OPC_UA_HEADER_SIZE) return 1;
    
    if (response[0] != 'H' && response[0] != 'O' && 
        response[0] != 'M' && response[0] != 'C' && 
        response[0] != 'A' && response[0] != 'E') {
        return 2;
    }
    
    if (len >= 8) {
        // FIXED: Use safe type reading instead of pointer casting
        uint32_t declared_size = ntohl(read_uint32_from_bytes(response + 4));
        if (len != (int)declared_size && declared_size != 0) {
            return 3;
        }
    }
    
    if (len > OPC_UA_MAX_CHUNK_SIZE) {
        return 4;
    }
    
    if (response[0] == 'E' && response[1] == 'R' && response[2] == 'R') {
        return 5;
    }
    
    if (response[3] != 'F' && response[3] != 'C' && response[3] != 'A') {
        return 6;
    }
    
    for (int i = 0; i < len - 4; i++) {
        if (response[i] == 0xBA && response[i+1] == 0xAD && 
            response[i+2] == 0xF0 && response[i+3] == 0x0D) {
            return 7;
        }
    }
    
    if (len >= 16) {
        uint32_t secure_channel_id = ntohl(read_uint32_from_bytes(response + 8));
        if (secure_channel_id == 0 || secure_channel_id == 0xFFFFFFFF) {
            return 8;
        }
    }
    
    if (len >= 20) {
        uint32_t token_id = ntohl(read_uint32_from_bytes(response + 12));
        if (token_id == 0 || token_id == 0xFFFFFFFF) {
            return 9;
        }
    }
    
    if (len >= 24) {
        uint32_t sequence_number = ntohl(read_uint32_from_bytes(response + 16));
        if (sequence_number == 0xFFFFFFFF) {
            return 10;
        }
        
        if (session) {
            session->last_response = time(NULL);
            session->transaction_id = sequence_number;
        }
    }
    
    return 0;
}

static protocol_ops_t opc_ua_ops = {
    .generate_packet = opc_ua_generate_packet,
    .mutate_packet = opc_ua_mutate_packet,
    .analyze_response = analyze_opc_ua_response
};

protocol_ops_t *get_protocol_ops(void) {
    return &opc_ua_ops;
}
