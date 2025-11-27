#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <syslog.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <dlfcn.h>
#include <pcap.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "fuzzer_protocol.h"
#include "grammar_fieldmap.h"
#define BUF_SIZE 4096
#define MAX_THREADS 64
#define TIMEOUT_SEC 2
#define DEFAULT_PORT 502
#define PLUGIN_DIR "./plugins/"
// Global stats
atomic_int packets_sent = 0;
atomic_int anomalies = 0;
atomic_int crashes = 0;
atomic_int timeouts = 0;
int verbose = 0;
FILE *log_file = NULL;
FILE *json_file = NULL;
pcap_t *pcap_handle = NULL;
pcap_dumper_t *pcap_dumper = NULL;
int read_only = 0;
int max_rate = 0;
int passive_mode = 0;
char *interface = NULL;
char *grammar_pcap = NULL;
char *replay = NULL;
uint32_t seed = 0;
// Enhanced grammar templates with field mapping
grammar_template_t grammar_templates[10];
int grammar_count = 0;
// Thread args struct
struct thread_args {
    const char *ip;
    int port;
    float rate;
    enum strategy strat;
    protocol_ops_t *ops;
    int iters;
    int stateful;
    int delay;
    int thread_id;
};
// Signal handler
void sig_handler(int signo) {
    if (signo == SIGINT) {
        printf("\n=== FUZZING SUMMARY ===\n");
        printf("Packets sent: %d\n", atomic_load(&packets_sent));
        printf("Anomalies detected: %d\n", atomic_load(&anomalies));
        printf("Potential crashes: %d\n", atomic_load(&crashes));
        printf("Timeouts: %d\n", atomic_load(&timeouts));
       
        if (log_file) {
            fprintf(log_file, "=== SESSION END ===\n");
            fclose(log_file);
        }
        if (json_file) {
            fprintf(json_file, "]\n");
            fclose(json_file);
        }
        if (pcap_dumper) pcap_dump_close(pcap_dumper);
        if (pcap_handle) pcap_close(pcap_handle);
        exit(0);
    }
}
// Field-aware mutation
void mutate_with_grammar(uint8_t *packet, size_t *len, float mut_rate, enum strategy strat, grammar_template_t *tmpl) {
    (void)strat;  // Mark unused parameter
    // Field-aware mutation
    for (int i = 0; i < tmpl->field_count; i++) {
        field_descriptor_t *f = &tmpl->fields[i];
        if ((float)rand() / RAND_MAX > mut_rate) continue;
        switch (f->type) {
            case FIELD_FUNC_CODE:
                if (f->length == 1) {
                    packet[f->offset] = 0xFF; // invalid function
                }
                break;
            case FIELD_LEN:
                for (size_t j = 0; j < f->length; j++) {
                    packet[f->offset + j] = 0xFF;
                }
                break;
            case FIELD_ADDR:
                for (size_t j = 0; j < f->length; j++) {
                    packet[f->offset + j] = (j == f->length - 1) ? 0xFF : 0x00;
                }
                break;
            case FIELD_PAYLOAD:
                for (size_t j = 0; j < f->length; j++) {
                    packet[f->offset + j] = rand() % 256;
                }
                break;
            case FIELD_CRC:
                for (size_t j = 0; j < f->length; j++) {
                    packet[f->offset + j] = rand() % 256;
                }
                break;
            default:
                if (f->length == 1 && (float)rand() / RAND_MAX < 0.1) {
                    packet[f->offset] ^= 0x01;
                }
                break;
        }
    }
   
    // Additional byte-level mutation
    for (size_t i = 0; i < *len && i < BUF_SIZE; i++) {
        if ((float)rand() / RAND_MAX < mut_rate * 0.1) {
            packet[i] ^= (1 << (rand() % 8));
        }
    }
}
// Protocol detection and field mapping
int detect_and_map_protocol_fields(grammar_template_t *tmpl, const u_char *packet, size_t len) {
    // Modbus TCP detection
    if (len >= 12) {
        uint16_t proto_id = (packet[2] << 8) | packet[3];
        if (proto_id == 0x0000) {
            tmpl->field_count = 5;
            tmpl->fields[0] = (field_descriptor_t){0, 2, FIELD_CONST};
            tmpl->fields[1] = (field_descriptor_t){2, 2, FIELD_CONST};
            tmpl->fields[2] = (field_descriptor_t){4, 2, FIELD_LEN};
            tmpl->fields[3] = (field_descriptor_t){6, 1, FIELD_CONST};
            tmpl->fields[4] = (field_descriptor_t){7, 1, FIELD_FUNC_CODE};
            return 1;
        }
    }
   
    // DNP3 detection
    if (len >= 10) {
        uint16_t start_bytes = (packet[0] << 8) | packet[1];
        if (start_bytes == 0x0564) {
            tmpl->field_count = 4;
            tmpl->fields[0] = (field_descriptor_t){0, 2, FIELD_CONST};
            tmpl->fields[1] = (field_descriptor_t){2, 1, FIELD_LEN};
            tmpl->fields[2] = (field_descriptor_t){8, 2, FIELD_CRC};
            tmpl->fields[3] = (field_descriptor_t){10, 1, FIELD_FUNC_CODE};
            return 1;
        }
    }
   
    // S7COMM detection
    if (len >= 4 && packet[0] == 0x03 && packet[1] == 0x00) {
        tmpl->field_count = 3;
        tmpl->fields[0] = (field_descriptor_t){2, 2, FIELD_LEN};
        tmpl->fields[1] = (field_descriptor_t){5, 1, FIELD_FUNC_CODE};
        tmpl->fields[2] = (field_descriptor_t){11, 1, FIELD_FUNC_CODE};
        return 1;
    }
   
    return 0;
}
// Enhanced grammar loading with field mapping
void load_grammar(const char *file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(file, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        exit(1);
    }
    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL && grammar_count < 10) {
        grammar_template_t *tmpl = &grammar_templates[grammar_count];
        size_t pkt_len = (header.len < BUF_SIZE) ? header.len : BUF_SIZE;
        memcpy(tmpl->template_data, packet, pkt_len);
        tmpl->template_len = pkt_len;
        if (detect_and_map_protocol_fields(tmpl, packet, pkt_len)) {
            if (verbose) printf("Loaded structured template with %d fields\n", tmpl->field_count);
        } else {
            tmpl->field_count = 0;
            if (verbose) printf("Loaded template with unknown protocol format\n");
        }
        grammar_count++;
    }
    pcap_close(handle);
    printf("Loaded %d structured templates from PCAP\n", grammar_count);
}
// Crash packet saving
void save_crash_packet(uint8_t *packet, size_t len, int anomaly_level,
                      enum strategy strat, float mut_rate, int grammar_used,
                      grammar_template_t *tmpl) {
    struct stat st = {0};
    if (stat("crashes", &st) == -1) {
        mkdir("crashes", 0700);
    }
    char fname[256];
    time_t now = time(NULL);
    const char *strategy_names[] = {
        "RANDOM", "BITFLIP", "OVERFLOW", "DICTIONARY",
        "FORMAT_STRING", "TYPE_CONFUSION", "TIME_BASED",
        "SEQUENCE_VIOLATION", "PROTOCOL_FUZZING", "COMBINATORIAL"
    };
    // Save binary packet
    snprintf(fname, sizeof(fname), "crashes/crash_%ld.bin", now);
    FILE *f = fopen(fname, "wb");
    if (f) {
        fwrite(packet, 1, len, f);
        fclose(f);
        printf("Crash packet saved to %s\n", fname);
    }
    // Save metadata
    snprintf(fname, sizeof(fname), "crashes/crash_%ld.meta", now);
    f = fopen(fname, "w");
    if (f) {
        fprintf(f, "timestamp=%ld\n", now);
        fprintf(f, "anomaly_level=%d\n", anomaly_level);
        fprintf(f, "strategy=%s\n", strategy_names[strat]);
        fprintf(f, "mutation_rate=%.2f\n", mut_rate);
        fprintf(f, "packet_length=%zu\n", len);
        fprintf(f, "grammar_used=%d\n", grammar_used);
        fprintf(f, "seed=%u\n", seed);
       
        if (grammar_used && tmpl) {
            fprintf(f, "template_field_count=%d\n", tmpl->field_count);
            for (int i = 0; i < tmpl->field_count; i++) {
                fprintf(f, "field_%d: offset=%zu, length=%zu, type=%d\n",
                        i, tmpl->fields[i].offset, tmpl->fields[i].length, tmpl->fields[i].type);
            }
        }
        fclose(f);
    }
    // Save as PCAP
    snprintf(fname, sizeof(fname), "crashes/crash_%ld.pcap", now);
    pcap_t *pcap = pcap_open_dead(DLT_RAW, BUF_SIZE);
    pcap_dumper_t *dumper = pcap_dump_open(pcap, fname);
    if (dumper) {
        struct pcap_pkthdr hdr;
        gettimeofday(&hdr.ts, NULL);
        hdr.caplen = len;
        hdr.len = len;
        pcap_dump((u_char *)dumper, &hdr, packet);
        pcap_dump_close(dumper);
    }
    pcap_close(pcap);
}
// Passive sniffer handler
void passive_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;  // Mark unused parameter
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(log_file, "[%s] Captured packet (len: %d): ", timestamp, header->len);
    for (bpf_u_int32 i = 0; i < (header->len < 32 ? header->len : 32); i++) {
        fprintf(log_file, "%02X ", packet[i]);
    }
    fprintf(log_file, "\n");
    fflush(log_file);
    if (pcap_dumper) pcap_dump((u_char *)pcap_dumper, header, packet);
}
// Passive mode function
void run_passive(const char *dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(1);
    }
    struct bpf_program fp;
    char filter[] = "tcp port 502 or tcp port 20000 or tcp port 102 or tcp port 2404";
    if (pcap_compile(pcap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(pcap_handle));
    }
    printf("Sniffing on %s...\n", dev);
    pcap_loop(pcap_handle, 0, passive_handler, NULL);
}
// Enhanced fuzzing with grammar support
int send_fuzzed_packet(const char *target_ip, int port, float mut_rate, enum strategy strat,
                      protocol_ops_t *ops, int stateful, session_context_t *session) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);
    struct timeval tv = {TIMEOUT_SEC, 0};
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) { close(sock); return 1; }
        if (select(sock + 1, NULL, &fdset, NULL, &tv) <= 0) {
            close(sock);
            atomic_fetch_add(&timeouts, 1);
            return 1;
        }
    }
    uint8_t packet[BUF_SIZE];
    size_t len = 0;
    int use_grammar = 0;
    grammar_template_t *used_template = NULL;
    if (grammar_count > 0 && (rand() % 100) < 70) {
        int idx = rand() % grammar_count;
        used_template = &grammar_templates[idx];
        memcpy(packet, used_template->template_data, used_template->template_len);
        len = used_template->template_len;
        use_grammar = 1;
       
        mutate_with_grammar(packet, &len, mut_rate, strat, used_template);
    } else {
        ops->generate_packet(packet, &len, stateful, read_only, session);
        ops->mutate_packet(packet, &len, strat, mut_rate, session);
    }
    if (pcap_dumper) {
        struct pcap_pkthdr hdr;
        gettimeofday(&hdr.ts, NULL);
        hdr.caplen = len;
        hdr.len = len;
        pcap_dump((u_char *)pcap_dumper, &hdr, packet);
    }
    int send_result = send(sock, packet, len, 0);
    if (send_result < 0) {
        close(sock);
        return 1;
    }
    atomic_fetch_add(&packets_sent, 1);
    uint8_t resp[BUF_SIZE];
    int recv_len = 0;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    if (select(sock + 1, &fdset, NULL, NULL, &tv) > 0) {
        recv_len = recv(sock, resp, BUF_SIZE, 0);
    }
    if (pcap_dumper && recv_len > 0) {
        struct pcap_pkthdr hdr;
        gettimeofday(&hdr.ts, NULL);
        hdr.caplen = recv_len;
        hdr.len = recv_len;
        pcap_dump((u_char *)pcap_dumper, &hdr, resp);
    }
    int anomaly = ops->analyze_response(resp, recv_len, session);
   
    // Enhanced crash detection and saving
    if (anomaly >= 2) {
        atomic_fetch_add(&crashes, 1);
        save_crash_packet(packet, len, anomaly, strat, mut_rate, use_grammar, used_template);
    }
    if (anomaly > 0) {
        atomic_fetch_add(&anomalies, 1);
        if (json_file) {
            fprintf(json_file, "{\"anomaly_level\": %d, \"time\": %ld, \"grammar_used\": %d}",
                    anomaly, time(NULL), use_grammar);
            // Add comma for JSON array except for last element
            static int first_json = 1;
            if (first_json) {
                first_json = 0;
            } else {
                fprintf(json_file, ",");
            }
            fprintf(json_file, "\n");
        }
    }
    close(sock);
    return 0;
}
// Thread worker
void *fuzzer_thread(void *arg) {
    struct thread_args *args = (struct thread_args *)arg;
    int delay = args->delay;
    if (max_rate > 0) delay = 1000000 / max_rate;
   
    session_context_t thread_session;
    memset(&thread_session, 0, sizeof(thread_session));
    thread_session.session_id = time(NULL) ^ args->thread_id;
    thread_session.transaction_id = 1;
   
    for (int i = 0; i < args->iters; i++) {
        send_fuzzed_packet(args->ip, args->port, args->rate, args->strat, args->ops, args->stateful, &thread_session);
        usleep(rand() % delay * 1000);
       
        if (verbose && args->thread_id == 0 && i % 100 == 0) {
            printf("Progress: %d/%d packets, %d anomalies, %d crashes\n",
                   atomic_load(&packets_sent), args->iters * args->thread_id,
                   atomic_load(&anomalies), atomic_load(&crashes));
        }
    }
    free(args);
    return NULL;
}
int main(int argc, char *argv[]) {
    char *target_ip = "127.0.0.1";
    int port = 0;
    char *protocol_str = "modbus";
    int iterations = 100;
    float mut_rate = 0.05;
    enum strategy strat = RANDOM;
    int threads = 1;
    int stateful = 0;
    int delay_ms = 100;
    char *log_path = "fuzz.log";
    char *out_pcap = NULL;
    char *out_json = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "t:P:p:i:m:s:T:Sd:l:vI:g:r:o:j:R:e:M:")) != -1) {
        switch (opt) {
            case 't': target_ip = optarg; break;
            case 'P': port = atoi(optarg); break;
            case 'p': protocol_str = optarg; break;
            case 'i': iterations = atoi(optarg); break;
            case 'm': mut_rate = atof(optarg); break;
            case 's':
                if (strcmp(optarg, "random") == 0) strat = RANDOM;
                else if (strcmp(optarg, "bitflip") == 0) strat = BITFLIP;
                else if (strcmp(optarg, "overflow") == 0) strat = OVERFLOW;
                else if (strcmp(optarg, "dictionary") == 0) strat = DICTIONARY;
                else if (strcmp(optarg, "format") == 0) strat = FORMAT_STRING;
                else if (strcmp(optarg, "type") == 0) strat = TYPE_CONFUSION;
                else if (strcmp(optarg, "time") == 0) strat = TIME_BASED;
                else if (strcmp(optarg, "sequence") == 0) strat = SEQUENCE_VIOLATION;
                else if (strcmp(optarg, "protocol") == 0) strat = PROTOCOL_FUZZING;
                else if (strcmp(optarg, "combinatorial") == 0) strat = COMBINATORIAL;
                break;
            case 'T': threads = atoi(optarg); if (threads > MAX_THREADS) threads = MAX_THREADS; break;
            case 'S': stateful = 1; break;
            case 'd': delay_ms = atoi(optarg); break;
            case 'l': log_path = optarg; break;
            case 'v': verbose = 1; break;
            case 'I': passive_mode = 1; interface = optarg; break;
            case 'g': grammar_pcap = optarg; break;
            case 'r': replay = optarg; break;
            case 'o': out_pcap = optarg; break;
            case 'j': out_json = optarg; break;
            case 'R': read_only = 1; break;
            case 'e': seed = strtoul(optarg, NULL, 0); break;
            case 'M': max_rate = atoi(optarg); break;
            default:
                fprintf(stderr, "Usage: %s [options]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, " -t target_ip Target IP address\n");
                fprintf(stderr, " -P port Target port\n");
                fprintf(stderr, " -p protocol Protocol (modbus, dnp3, s7, iec104, opcua)\n");
                fprintf(stderr, " -i iterations Number of iterations\n");
                fprintf(stderr, " -m rate Mutation rate (0.0-1.0)\n");
                fprintf(stderr, " -s strategy Fuzzing strategy\n");
                fprintf(stderr, " -T threads Number of threads\n");
                fprintf(stderr, " -S Stateful mode\n");
                fprintf(stderr, " -d delay_ms Delay between packets (ms)\n");
                fprintf(stderr, " -l log_file Log file path\n");
                fprintf(stderr, " -v Verbose output\n");
                fprintf(stderr, " -I interface Passive mode (sniff interface)\n");
                fprintf(stderr, " -g pcap_file Load grammar from PCAP\n");
                fprintf(stderr, " -r crash_file Replay crash packet\n");
                fprintf(stderr, " -o out_pcap Output PCAP file\n");
                fprintf(stderr, " -j out_json Output JSON file\n");
                fprintf(stderr, " -R Read-only mode\n");
                fprintf(stderr, " -e seed Random seed\n");
                fprintf(stderr, " -M max_rate Maximum packets per second\n");
                exit(1);
        }
    }
    srand(time(NULL) ^ getpid());
    if (seed) srand(seed);
    signal(SIGINT, sig_handler);
    // Create crashes directory
    struct stat st = {0};
    if (stat("crashes", &st) == -1) {
        mkdir("crashes", 0700);
    }
    log_file = fopen(log_path, "w");
    if (!log_file) {
        perror("Log open failed");
        exit(1);
    }
    fprintf(log_file, "=== OT ADVANCED FUZZING SESSION STARTED ===\n");
    fprintf(log_file, "Target: %s:%d, Protocol: %s\n", target_ip, port, protocol_str);
    // Enhanced replay mode
    if (replay) {
        printf("Replay mode: Loading packet from %s\n", replay);
       
        FILE *f = fopen(replay, "rb");
        if (!f) {
            char bin_name[256];
            snprintf(bin_name, sizeof(bin_name), "%s.bin", replay);
            f = fopen(bin_name, "rb");
        }
       
        if (!f) {
            fprintf(stderr, "Replay file open failed: %s\n", replay);
            exit(1);
        }
        uint8_t packet[BUF_SIZE];
        size_t len = fread(packet, 1, BUF_SIZE, f);
        fclose(f);
        // Load metadata
        char meta_name[256];
        snprintf(meta_name, sizeof(meta_name), "%s.meta", replay);
        FILE *meta_f = fopen(meta_name, "r");
        if (meta_f) {
            char line[256];
            printf("Replay metadata:\n");
            while (fgets(line, sizeof(line), meta_f)) {
                printf(" %s", line);
            }
            fclose(meta_f);
        }
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            exit(1);
        }
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
            perror("Invalid target IP");
            close(sock);
            exit(1);
        }
        struct timeval tv = {TIMEOUT_SEC, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("Connect failed");
            close(sock);
            exit(1);
        }
        printf("Sending %zu bytes to %s:%d\n", len, target_ip, port);
       
        printf("Packet hex dump (first 64 bytes):\n");
        for (size_t i = 0; i < (len < 64 ? len : 64); i++) {
            printf("%02X ", packet[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
        ssize_t sent = send(sock, packet, len, 0);
        if (sent < 0 || (size_t)sent != len) {
            perror("Send failed");
        } else {
            printf("Packet sent successfully\n");
           
            uint8_t response[BUF_SIZE];
            ssize_t recv_len = recv(sock, response, BUF_SIZE, 0);
            if (recv_len > 0) {
                printf("Received %zd byte response\n", recv_len);
            } else if (recv_len == 0) {
                printf("Connection closed by peer\n");
            } else {
                perror("Receive failed");
            }
        }
        close(sock);
        return 0;
    }
    if (grammar_pcap) load_grammar(grammar_pcap);
    if (passive_mode) {
        run_passive(interface);
        return 0;
    }
    if (out_pcap) {
        pcap_handle = pcap_open_dead(DLT_RAW, BUF_SIZE);
        pcap_dumper = pcap_dump_open(pcap_handle, out_pcap);
        if (!pcap_dumper) {
            fprintf(stderr, "pcap_dump_open failed\n");
            exit(1);
        }
    }
    if (out_json) {
        json_file = fopen(out_json, "w");
        if (!json_file) {
            perror("JSON open failed");
            exit(1);
        }
        fprintf(json_file, "[\n");
    }
    // Load protocol module
    char so_path[256];
    snprintf(so_path, sizeof(so_path), "%slibprot_%s.so", PLUGIN_DIR, protocol_str);
    void *handle = dlopen(so_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        exit(1);
    }
   
    typedef protocol_ops_t *(*get_ops_func)(void);
    get_ops_func get_ops = (get_ops_func)dlsym(handle, "get_protocol_ops");
    if (!get_ops) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        exit(1);
    }
   
    protocol_ops_t *ops = get_ops();
    if (port == 0) port = DEFAULT_PORT;
    printf("Starting advanced OT fuzzer...\n");
    printf("Target: %s:%d\n", target_ip, port);
    printf("Protocol: %s, Strategy: %d\n", protocol_str, strat);
    printf("Threads: %d, Iterations: %d\n", threads, iterations);
    pthread_t thread_ids[MAX_THREADS];
    for (int t = 0; t < threads; t++) {
        struct thread_args *args = malloc(sizeof(struct thread_args));
        args->ip = target_ip;
        args->port = port;
        args->rate = mut_rate;
        args->strat = strat;
        args->ops = ops;
        args->iters = iterations / threads + (t < iterations % threads ? 1 : 0);
        args->stateful = stateful;
        args->delay = delay_ms;
        args->thread_id = t;
        pthread_create(&thread_ids[t], NULL, fuzzer_thread, args);
    }
   
    for (int t = 0; t < threads; t++) {
        pthread_join(thread_ids[t], NULL);
    }
    // Final summary
    printf("\n=== FUZZING COMPLETED ===\n");
    printf("Total packets sent: %d\n", atomic_load(&packets_sent));
    printf("Anomalies detected: %d\n", atomic_load(&anomalies));
    printf("Potential crashes: %d\n", atomic_load(&crashes));
    printf("Timeouts: %d\n", atomic_load(&timeouts));
    fprintf(log_file, "=== SESSION COMPLETED ===\n");
    fprintf(log_file, "Total: %d packets, %d anomalies, %d crashes, %d timeouts\n",
            atomic_load(&packets_sent), atomic_load(&anomalies),
            atomic_load(&crashes), atomic_load(&timeouts));
    // Cleanup
    dlclose(handle);
    if (log_file) fclose(log_file);
    if (json_file) {
        fprintf(json_file, "]\n");
        fclose(json_file);
    }
    if (pcap_dumper) pcap_dump_close(pcap_dumper);
    if (pcap_handle) pcap_close(pcap_handle);
    return 0;
}
