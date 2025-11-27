// s7comm_module.c
#include "fuzzer_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#define S7COMM_TPKT_HEADER_SIZE 4
#define S7COMM_COTP_HEADER_SIZE 7
#define S7COMM_S7_HEADER_SIZE 12
#define S7COMM_PARAMETER_HEADER_SIZE 4
#define S7COMM_DATA_HEADER_SIZE 4
#define S7COMM_READ_REQUEST_SIZE 32
#define S7COMM_WRITE_REQUEST_SIZE 64
#define S7COMM_SETUP_REQUEST_SIZE 28
#define S7COMM_MAX_PDU_LENGTH 480

// Safe type punning functions
static inline void write_float_as_bytes(uint8_t *dest, float value) {
    memcpy(dest, &value, sizeof(float));
}

static inline void write_uint32_as_bytes(uint8_t *dest, uint32_t value) {
    memcpy(dest, &value, sizeof(uint32_t));
}

static inline void write_uint64_as_bytes(uint8_t *dest, uint64_t value) {
    memcpy(dest, &value, sizeof(uint64_t));
}

static inline float bytes_to_float(const uint8_t *src) {
    float value;
    memcpy(&value, src, sizeof(float));
    return value;
}

typedef struct {
    uint8_t rosctr_types[8];
    uint8_t function_codes[16];
    uint8_t error_classes[8];
    uint8_t error_codes[16];
    uint8_t area_types[12];
    uint8_t transport_sizes[8];
    uint8_t data_types[16];
    uint8_t block_types[8];
} s7comm_dictionary_t;

static const uint8_t ROSCTR_TYPES[] = {0x01, 0x02, 0x03, 0x07, 0x00, 0xFF, 0xFE, 0x7F};
static const uint8_t FUNCTION_CODES[] = {0x04, 0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x00, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9};
static const uint8_t ERROR_CLASSES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE};
static const uint8_t ERROR_CODES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
static const uint8_t AREA_TYPES[] = {0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x1C, 0x1D, 0x1E, 0x1F, 0x00};
static const uint8_t TRANSPORT_SIZES[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00};
static const uint8_t DATA_TYPES[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00};
static const uint8_t BLOCK_TYPES[] = {0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00};

static void init_s7comm_dictionary(s7comm_dictionary_t *dict) {
    memcpy(dict->rosctr_types, ROSCTR_TYPES, sizeof(ROSCTR_TYPES));
    memcpy(dict->function_codes, FUNCTION_CODES, sizeof(FUNCTION_CODES));
    memcpy(dict->error_classes, ERROR_CLASSES, sizeof(ERROR_CLASSES));
    memcpy(dict->error_codes, ERROR_CODES, sizeof(ERROR_CODES));
    memcpy(dict->area_types, AREA_TYPES, sizeof(AREA_TYPES));
    memcpy(dict->transport_sizes, TRANSPORT_SIZES, sizeof(TRANSPORT_SIZES));
    memcpy(dict->data_types, DATA_TYPES, sizeof(DATA_TYPES));
    memcpy(dict->block_types, BLOCK_TYPES, sizeof(BLOCK_TYPES));
}

static uint16_t calculate_s7comm_crc(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc;
}

static void recalc_s7comm_checksum(uint8_t *packet, size_t *len) {
    if (*len >= S7COMM_TPKT_HEADER_SIZE) {
        uint16_t total_length = *len;
        packet[2] = (total_length >> 8) & 0xFF;
        packet[3] = total_length & 0xFF;
    }
    
    if (*len >= S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE) {
        uint16_t s7_length = *len - S7COMM_TPKT_HEADER_SIZE - S7COMM_COTP_HEADER_SIZE;
        packet[S7COMM_TPKT_HEADER_SIZE + 1] = s7_length & 0xFF;
    }
    
    if (*len >= 6) {
        uint16_t crc = calculate_s7comm_crc(packet, *len - 2);
        packet[*len - 2] = crc & 0xFF;
        packet[*len - 1] = (crc >> 8) & 0xFF;
    }
}

static void build_tpkt_header(uint8_t *packet, uint16_t length) {
    packet[0] = 0x03;
    packet[1] = 0x00;
    packet[2] = (length >> 8) & 0xFF;
    packet[3] = length & 0xFF;
}

static void build_cotp_header(uint8_t *packet, uint8_t pdu_type, uint16_t src_ref, uint16_t dst_ref) {
    packet[0] = 0x11;
    packet[1] = pdu_type;
    packet[2] = 0x00;
    packet[3] = 0x00;
    packet[4] = (src_ref >> 8) & 0xFF;
    packet[5] = src_ref & 0xFF;
    packet[6] = (dst_ref >> 8) & 0xFF;
    packet[7] = dst_ref & 0xFF;
}

static void build_s7_header(uint8_t *packet, uint8_t rosctr, uint16_t pdu_ref, uint16_t param_len, uint16_t data_len) {
    packet[0] = 0x32;
    packet[1] = rosctr;
    packet[2] = (pdu_ref >> 8) & 0xFF;
    packet[3] = pdu_ref & 0xFF;
    packet[4] = (param_len >> 8) & 0xFF;
    packet[5] = param_len & 0xFF;
    packet[6] = (data_len >> 8) & 0xFF;
    packet[7] = data_len & 0xFF;
    packet[8] = 0x00;
    packet[9] = 0x00;
    packet[10] = 0x00;
    packet[11] = 0x00;
}

static void build_read_parameter(uint8_t *packet, size_t *offset, uint8_t function, uint8_t item_count) {
    packet[*offset] = function;
    packet[*offset + 1] = item_count;
    *offset += 2;
}

static void build_read_item(uint8_t *packet, size_t *offset, uint8_t area, uint8_t transport_size, uint16_t db_number, uint32_t address, uint16_t length) {
    packet[*offset] = 0x12;
    packet[*offset + 1] = transport_size;
    packet[*offset + 2] = (length >> 8) & 0xFF;
    packet[*offset + 3] = length & 0xFF;
    packet[*offset + 4] = (db_number >> 8) & 0xFF;
    packet[*offset + 5] = db_number & 0xFF;
    packet[*offset + 6] = area;
    packet[*offset + 7] = (address >> 16) & 0xFF;
    packet[*offset + 8] = (address >> 8) & 0xFF;
    packet[*offset + 9] = address & 0xFF;
    *offset += 10;
}

static void build_write_parameter(uint8_t *packet, size_t *offset, uint8_t function, uint8_t item_count) {
    packet[*offset] = function;
    packet[*offset + 1] = item_count;
    *offset += 2;
}

static void build_write_item(uint8_t *packet, size_t *offset, uint8_t area, uint8_t transport_size, uint16_t db_number, uint32_t address, uint16_t length, const uint8_t *data) {
    packet[*offset] = 0x12;
    packet[*offset + 1] = transport_size;
    packet[*offset + 2] = (length >> 8) & 0xFF;
    packet[*offset + 3] = length & 0xFF;
    packet[*offset + 4] = (db_number >> 8) & 0xFF;
    packet[*offset + 5] = db_number & 0xFF;
    packet[*offset + 6] = area;
    packet[*offset + 7] = (address >> 16) & 0xFF;
    packet[*offset + 8] = (address >> 8) & 0xFF;
    packet[*offset + 9] = address & 0xFF;
    *offset += 10;
    
    if (data && length > 0) {
        memcpy(packet + *offset, data, length > 16 ? 16 : length);
        *offset += (length > 16 ? 16 : length);
    }
}

static void s7comm_generate_read_packet(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_tpkt_header(packet, S7COMM_READ_REQUEST_SIZE);
    offset += S7COMM_TPKT_HEADER_SIZE;
    
    build_cotp_header(packet + offset, 0xF0, session ? session->session_id : 1, session ? session->transaction_id : 1);
    offset += S7COMM_COTP_HEADER_SIZE;
    
    build_s7_header(packet + offset, 0x01, session ? session->transaction_id : 1, 14, 0);
    offset += S7COMM_S7_HEADER_SIZE;
    
    build_read_parameter(packet, &offset, 0x04, 1);
    
    build_read_item(packet, &offset, 0x84, 0x02, 1, 0, 4);
    
    *len = offset;
    recalc_s7comm_checksum(packet, len);
}

static void s7comm_generate_write_packet(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    uint8_t write_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    
    build_tpkt_header(packet, S7COMM_WRITE_REQUEST_SIZE);
    offset += S7COMM_TPKT_HEADER_SIZE;
    
    build_cotp_header(packet + offset, 0xF0, session ? session->session_id : 1, session ? session->transaction_id : 1);
    offset += S7COMM_COTP_HEADER_SIZE;
    
    build_s7_header(packet + offset, 0x01, session ? session->transaction_id : 1, 14, 6);
    offset += S7COMM_S7_HEADER_SIZE;
    
    build_write_parameter(packet, &offset, 0x05, 1);
    
    build_write_item(packet, &offset, 0x84, 0x02, 1, 0, 4, write_data);
    
    *len = offset;
    recalc_s7comm_checksum(packet, len);
}

static void s7comm_generate_setup_packet(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_tpkt_header(packet, S7COMM_SETUP_REQUEST_SIZE);
    offset += S7COMM_TPKT_HEADER_SIZE;
    
    build_cotp_header(packet + offset, 0xE0, session ? session->session_id : 1, 0);
    offset += S7COMM_COTP_HEADER_SIZE;
    
    build_s7_header(packet + offset, 0x01, session ? session->transaction_id : 1, 8, 0);
    offset += S7COMM_S7_HEADER_SIZE;
    
    packet[offset++] = 0xF0;
    packet[offset++] = 0x00;
    packet[offset++] = 0x00;
    packet[offset++] = 0x01;
    packet[offset++] = 0x00;
    packet[offset++] = 0x01;
    packet[offset++] = 0x03;
    packet[offset++] = 0xC0;
    
    *len = offset;
    recalc_s7comm_checksum(packet, len);
}

static void s7comm_generate_packet(uint8_t *packet, size_t *len, int is_initial, int read_only, session_context_t *session) {
    if (is_initial) {
        s7comm_generate_setup_packet(packet, len, session);
    } else {
        if (read_only) {
            s7comm_generate_read_packet(packet, len, session);
        } else {
            if (rand() % 2) {
                s7comm_generate_read_packet(packet, len, session);
            } else {
                s7comm_generate_write_packet(packet, len, session);
            }
        }
    }
    
    if (session) {
        session->transaction_id++;
    }
}

static void mutate_s7comm_specific(uint8_t *packet, size_t *len, enum strategy strat, float rate) {
    s7comm_dictionary_t dict;
    init_s7comm_dictionary(&dict);
    
    if (*len < S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE) return;
    
    size_t s7_header_offset = S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE;
    
    switch (strat) {
        case RANDOM:
            if (*len >= s7_header_offset + 2) {
                packet[s7_header_offset + 1] = dict.rosctr_types[rand() % 8];
            }
            if (*len >= s7_header_offset + S7COMM_S7_HEADER_SIZE + 2) {
                packet[s7_header_offset + S7COMM_S7_HEADER_SIZE] = dict.function_codes[rand() % 16];
            }
            break;
            
        case BITFLIP:
            for (size_t i = s7_header_offset; i < *len && i < s7_header_offset + 16; i++) {
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= (1 << (rand() % 8));
                }
            }
            break;
            
        case OVERFLOW:
            if (*len >= 4) {
                packet[2] = 0xFF;
                packet[3] = 0xFF;
            }
            if (*len >= s7_header_offset + 6) {
                packet[s7_header_offset + 4] = 0xFF;
                packet[s7_header_offset + 5] = 0xFF;
                packet[s7_header_offset + 6] = 0xFF;
                packet[s7_header_offset + 7] = 0xFF;
            }
            break;
            
        case DICTIONARY:
            if (*len >= s7_header_offset + 2) {
                packet[s7_header_offset + 1] = dict.rosctr_types[rand() % 8];
            }
            if (*len >= s7_header_offset + S7COMM_S7_HEADER_SIZE + 1) {
                packet[s7_header_offset + S7COMM_S7_HEADER_SIZE] = dict.function_codes[rand() % 16];
            }
            break;
            
        case FORMAT_STRING:
            if (*len >= s7_header_offset + S7COMM_S7_HEADER_SIZE + 20) {
                const char *s7_formats[] = {
                    "DB%d.%s%s%s%s", "M%d.%s%s%s%s", "I%d.%s%s%s%s", "Q%d.%s%s%s%s"
                };
                const char *inject = s7_formats[rand() % 4];
                size_t inject_len = strlen(inject);
                if (s7_header_offset + S7COMM_S7_HEADER_SIZE + 10 + inject_len < *len) {
                    memcpy(packet + s7_header_offset + S7COMM_S7_HEADER_SIZE + 10, inject, inject_len);
                }
            }
            break;
            
        case TYPE_CONFUSION:
            if (*len >= s7_header_offset + S7COMM_S7_HEADER_SIZE + 8) {
                // FIXED: Use safe type conversion instead of pointer casting
                uint32_t address = 0xFFFFFFFF;
                float float_val;
                memcpy(&float_val, &address, sizeof(uint32_t));
                write_float_as_bytes(packet + s7_header_offset + S7COMM_S7_HEADER_SIZE + 6, float_val);
            }
            break;
            
        case TIME_BASED:
            if (*len >= s7_header_offset + 12) {
                uint64_t timestamp = time(NULL) ^ 0xFFFFFFFF;
                write_uint64_as_bytes(packet + s7_header_offset + 8, timestamp);
            }
            break;
            
        case SEQUENCE_VIOLATION:
            if (*len >= s7_header_offset + 4) {
                packet[s7_header_offset + 2] = 0xFF;
                packet[s7_header_offset + 3] = 0xFF;
            }
            break;
            
        default:
            // Handle any unhandled strategies
            break;
    }
}

static void inject_tpkt_attack(uint8_t *packet, size_t *len) {
    if (*len < S7COMM_TPKT_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 5;
    
    switch (attack_type) {
        case 0:
            packet[0] = 0x00;
            break;
        case 1:
            packet[0] = 0xFF;
            break;
        case 2:
            packet[2] = 0xFF;
            packet[3] = 0xFF;
            break;
        case 3:
            packet[2] = 0x00;
            packet[3] = 0x04;
            break;
        case 4:
            packet[1] = 0xFF;
            break;
    }
}

static void inject_cotp_attack(uint8_t *packet, size_t *len) {
    if (*len < S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE) return;
    
    size_t cotp_offset = S7COMM_TPKT_HEADER_SIZE;
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            packet[cotp_offset] = 0x00;
            break;
        case 1:
            packet[cotp_offset] = 0xFF;
            break;
        case 2:
            packet[cotp_offset + 1] = 0x00;
            break;
        case 3:
            packet[cotp_offset + 1] = 0xFF;
            break;
        case 4:
            packet[cotp_offset + 4] = 0xFF;
            packet[cotp_offset + 5] = 0xFF;
            break;
        case 5:
            packet[cotp_offset + 6] = 0xFF;
            packet[cotp_offset + 7] = 0xFF;
            break;
    }
}

static void inject_s7_header_attack(uint8_t *packet, size_t *len) {
    if (*len < S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE + S7COMM_S7_HEADER_SIZE) return;
    
    size_t s7_offset = S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE;
    uint8_t attack_type = rand() % 8;
    
    switch (attack_type) {
        case 0:
            packet[s7_offset] = 0x00;
            break;
        case 1:
            packet[s7_offset] = 0xFF;
            break;
        case 2:
            packet[s7_offset + 1] = 0x00;
            break;
        case 3:
            packet[s7_offset + 1] = 0xFF;
            break;
        case 4:
            packet[s7_offset + 4] = 0xFF;
            packet[s7_offset + 5] = 0xFF;
            break;
        case 5:
            packet[s7_offset + 6] = 0xFF;
            packet[s7_offset + 7] = 0xFF;
            break;
        case 6:
            packet[s7_offset + 8] = 0xFF;
            break;
        case 7:
            packet[s7_offset + 9] = 0xFF;
            packet[s7_offset + 10] = 0xFF;
            packet[s7_offset + 11] = 0xFF;
            break;
    }
}

static void inject_parameter_attack(uint8_t *packet, size_t *len) {
    size_t param_offset = S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE + S7COMM_S7_HEADER_SIZE;
    if (*len < param_offset + 2) return;
    
    uint8_t attack_type = rand() % 4;
    
    switch (attack_type) {
        case 0:
            packet[param_offset] = 0x00;
            break;
        case 1:
            packet[param_offset] = 0xFF;
            break;
        case 2:
            packet[param_offset + 1] = 0x00;
            break;
        case 3:
            packet[param_offset + 1] = 0xFF;
            break;
    }
}

static void inject_data_item_attack(uint8_t *packet, size_t *len) {
    size_t item_offset = S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE + S7COMM_S7_HEADER_SIZE + 2;
    if (*len < item_offset + 10) return;
    
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            packet[item_offset] = 0x00;
            break;
        case 1:
            packet[item_offset] = 0xFF;
            break;
        case 2:
            packet[item_offset + 1] = 0x00;
            break;
        case 3:
            packet[item_offset + 1] = 0xFF;
            break;
        case 4:
            packet[item_offset + 4] = 0xFF;
            packet[item_offset + 5] = 0xFF;
            break;
        case 5:
            packet[item_offset + 6] = 0x00;
            break;
    }
}

static void s7comm_mutate_packet(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    mutate_s7comm_specific(packet, len, strat, rate);
    
    s7comm_dictionary_t dict;
    init_s7comm_dictionary(&dict);
    
    for (size_t i = 2; i < *len && i < BUF_SIZE; i++) {
        if ((float)rand() / RAND_MAX >= rate) continue;
        
        switch (strat) {
            case RANDOM:
                packet[i] = rand() % 256;
                break;
                
            case BITFLIP:
                packet[i] ^= (1 << (rand() % 8));
                break;
                
            case OVERFLOW:
                if (i >= 2 && i <= 3) {
                    packet[i] = 0xFF;
                } else if (i >= 18 && i <= 19) {
                    packet[i] = 0xFF;
                } else {
                    packet[i] = (packet[i] + 200) % 256;
                }
                break;
                
            case DICTIONARY:
                if (i == 5) packet[i] = dict.rosctr_types[rand() % 8];
                else if (i == 17) packet[i] = dict.function_codes[rand() % 16];
                else if (i >= 20 && i < 30) packet[i] = dict.area_types[rand() % 12];
                else if (i >= 30 && i < 38) packet[i] = dict.transport_sizes[rand() % 8];
                else packet[i] = dict.data_types[rand() % 16];
                break;
                
            case FORMAT_STRING:
                if (i < *len - 15) {
                    const char *s7_strings[] = {
                        "DB%d.DBX%d.%d", "M%d.%d", "I%d.%d", "Q%d.%d",
                        "P#%s.%s%s%s", "L#%s%s%s%s", "B#%s%s%s%s"
                    };
                    const char *inject = s7_strings[rand() % 7];
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
                    uint32_t int_val = 0xDEADBEEF;
                    float float_val;
                    memcpy(&float_val, &int_val, sizeof(uint32_t));
                    write_float_as_bytes(&packet[i], float_val);
                    i += 3;
                }
                break;
                
            case TIME_BASED:
                if (i < *len - 8) {
                    uint64_t system_time = time(NULL) ^ 0xAAAAAAAA;
                    write_uint64_as_bytes(&packet[i], system_time);
                    i += 7;
                }
                break;
                
            case SEQUENCE_VIOLATION:
                if (i >= 8 && i <= 11) {
                    packet[i] = (i == 8 || i == 10) ? 0xFE : 0xFF;
                }
                break;
                
            case PROTOCOL_FUZZING:
                packet[i] ^= 0x55;
                break;
                
            case COMBINATORIAL:
                packet[i] = (dict.function_codes[rand() % 16] ^ 
                           dict.area_types[rand() % 12]) + 
                           dict.transport_sizes[rand() % 8];
                break;
                
            default:
                // Default mutation for any unhandled strategies
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= 0x77;
                }
                break;
        }
    }
    
    if (rand() % 3 == 0) {
        inject_tpkt_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_cotp_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_s7_header_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_parameter_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_data_item_attack(packet, len);
    }
    
    if (rand() % 5 == 0) {
        size_t new_len = rand() % BUF_SIZE;
        if (new_len > S7COMM_TPKT_HEADER_SIZE) *len = new_len;
    }
    
    recalc_s7comm_checksum(packet, len);
}

static int analyze_s7comm_response(uint8_t *response, int len, session_context_t *session) {
    if (len <= 0) return -1;
    
    if (len < S7COMM_TPKT_HEADER_SIZE) return 1;
    
    if (response[0] != 0x03) return 2;
    
    if (len >= S7COMM_TPKT_HEADER_SIZE) {
        uint16_t declared_length = (response[2] << 8) | response[3];
        if (len != (int)declared_length) return 3;
    }
    
    if (len > S7COMM_MAX_PDU_LENGTH + S7COMM_TPKT_HEADER_SIZE) return 4;
    
    if (len >= S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE) {
        if (response[S7COMM_TPKT_HEADER_SIZE] != 0x11) return 5;
        if (response[S7COMM_TPKT_HEADER_SIZE + 1] != 0xF0 && 
            response[S7COMM_TPKT_HEADER_SIZE + 1] != 0xD0 &&
            response[S7COMM_TPKT_HEADER_SIZE + 1] != 0x80) {
            return 6;
        }
    }
    
    size_t s7_offset = S7COMM_TPKT_HEADER_SIZE + S7COMM_COTP_HEADER_SIZE;
    if (len >= (int)(s7_offset + S7COMM_S7_HEADER_SIZE)) {
        if (response[s7_offset] != 0x32) return 7;
        
        uint8_t rosctr = response[s7_offset + 1];
        if (rosctr == 0x03 || rosctr == 0x07) return 8;
        
        uint16_t error_class = response[s7_offset + 8];
        uint16_t error_code = response[s7_offset + 9];
        if (error_class != 0x00 || error_code != 0x00) return 9;
    }
    
    for (int i = 0; i < len - 4; i++) {
        if (response[i] == 0xBA && response[i+1] == 0xAD && 
            response[i+2] == 0xF0 && response[i+3] == 0x0D) {
            return 10;
        }
    }
    
    if (len >= 6) {
        uint16_t calculated_crc = calculate_s7comm_crc(response, len - 2);
        uint16_t received_crc = (response[len - 1] << 8) | response[len - 2];
        if (calculated_crc != received_crc) return 11;
    }
    
    if (session) {
        session->last_response = time(NULL);
        if (len >= (int)(s7_offset + 4)) {
            uint16_t pdu_ref = (response[s7_offset + 2] << 8) | response[s7_offset + 3];
            session->transaction_id = pdu_ref;
        }
    }
    
    return 0;
}

static protocol_ops_t s7comm_ops = {
    .generate_packet = s7comm_generate_packet,
    .mutate_packet = s7comm_mutate_packet,
    .analyze_response = analyze_s7comm_response
};

protocol_ops_t *get_protocol_ops(void) {
    return &s7comm_ops;
}
