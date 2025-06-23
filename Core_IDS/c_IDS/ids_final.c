#define _DEFAULT_SOURCE // For usleep and SO_REUSEPORT, and u_int/u_char types
#define __FAVOR_BSD     // To ensure IP_HL and TH_OFF macros are defined on some systems

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // Required for u_int, u_short, u_char types - MUST be before pcap.h
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h> // For non-blocking socket
#include <errno.h> // For errno
#include <signal.h> // For signal() function and SIGINT, SIGTERM
#include <net/if.h> // Required for IF_NAMESIZE

// Include cJSON (make sure cJSON.h and cJSON.c are in your project and compiled)
#include "cJSON.h"

#define MAX_PAYLOAD_SNIPPET 200
// ETHER_HDR_LEN is already defined in <net/ethernet.h> as ETH_HLEN, which is typically 14.

// --- Existing Structure Definitions ---
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol;
    unsigned int packet_length;
    unsigned char tcp_flags;
    unsigned char icmp_type;
    unsigned char icmp_code;
    int has_payload;
    unsigned int payload_length;
    char payload_str[MAX_PAYLOAD_SNIPPET + 1];
} PacketDetails;

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned short src_port;
    unsigned short dst_port;
    time_t last_packet_time;
    unsigned int packet_count;
    unsigned int syn_count;
    unsigned int ack_count;
    int is_established;
    int unique_dst_ports[65536]; // Simple array to mark seen ports, not count
    unsigned char protocol;
    int unique_dst_ports_count;
} FlowStats;

typedef struct {
    char name[64];
    char description[256];
    char severity[16];
    char condition[512]; // Condition as a string for dynamic evaluation
} Signature;

typedef struct {
    char interface[IF_NAMESIZE]; // e.g., "eth0"
    char alert_log_file[256];
    int cooldown_period_seconds;
    int syn_flood_packet_rate;
    int port_scan_packet_rate;
    int udp_flood_packet_rate;
    int icmp_flood_packet_rate;
    int xmas_fin_null_scan_packet_rate;
    int large_packet_bytes;
    int invalid_tcp_flags_count;
    int gui_listen_port; // Port for GUI communication
} GlobalConfig;

// --- Global Variables (Protected by Mutexes) ---
#define MAX_FLOWS 100000
static FlowStats *flows[MAX_FLOWS];
static pthread_mutex_t flow_mutex;
static unsigned long flow_index = 0; // Simple incrementing index for new flows

#define MAX_SIGNATURES 100
static Signature signatures[MAX_SIGNATURES];
static pthread_mutex_t signatures_mutex;
static int num_signatures = 0;

static GlobalConfig global_config;
static pthread_mutex_t config_mutex;

static FILE *alert_log_fp;
static pthread_mutex_t log_mutex;

static pcap_t *handle; // Packet capture handle
static pthread_mutex_t sniff_start_mutex; // For controlling sniffing thread start/stop
static pthread_cond_t sniff_start_cond;
static volatile int sniffing_active = 1; // 0: paused, 1: active, 2: terminating

// Global variable for live log client file descriptor and its mutex
static int live_log_client_fd = -1;
static pthread_mutex_t live_log_client_mutex;
// NEW: Global flag to control live log streaming to GUI
volatile int gui_live_log_active = 0; // 0: inactive, 1: active

// Function Prototypes
void cleanup(int signum);
// Modified log_alert prototype
void log_alert(const char *severity, const char *alert_name, const char *description,
               const char *src_ip, unsigned short src_port,
               const char *dst_ip, unsigned short dst_port,
               unsigned char protocol_num, float confidence);
void load_config();
void load_signatures(const char *json_string);
cJSON_bool evaluate_condition(const char *condition_str, const PacketDetails *details, const FlowStats *flow_stats);
void initialize_flow_stats(FlowStats *flow, const char *src_ip, const char *dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char protocol);
FlowStats *get_or_create_flow(const char *src_ip, const char *dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char protocol);
void update_flow_stats(FlowStats *flow, const PacketDetails *details);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void analyze_packet(const struct pcap_pkthdr *header, const u_char *packet);
void *sniffing_thread(void *arg);
void *gui_communication_thread(void *arg);
// NEW: Function to send data over socket, handling EINTR
ssize_t send_all(int socket, const void *buffer, size_t length, int flags) {
    size_t total_sent = 0;
    const char *ptr = buffer;
    while (total_sent < length) {
        ssize_t bytes_sent = send(socket, ptr + total_sent, length - total_sent, flags);
        if (bytes_sent == -1) {
            if (errno == EINTR) {
                continue; // Interrupted system call, try again
            } else {
                return -1; // Other error
            }
        }
        total_sent += bytes_sent;
    }
    return total_sent;
}


// --- Function Implementations ---

// NEW: Modified log_alert function to send to GUI
void log_alert(const char *severity, const char *alert_name, const char *description,
               const char *src_ip, unsigned short src_port,
               const char *dst_ip, unsigned short dst_port,
               unsigned char protocol_num, float confidence) {
    char timestamp[30];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char alert_msg[1024]; // Ensure this buffer is large enough
    snprintf(alert_msg, sizeof(alert_msg),
             "[%s] ALERT: %s (Severity: %s) - %s | Source: %s:%d -> Destination: %s:%d | Protocol: %hhu | Confidence: %.2f\n",
             timestamp, alert_name, severity, description,
             src_ip, src_port, dst_ip, dst_port,
             protocol_num, confidence);

    // Log to file (existing logic)
    pthread_mutex_lock(&log_mutex);
    if (alert_log_fp) {
        fprintf(alert_log_fp, "%s", alert_msg);
        fflush(alert_log_fp); // Ensure it's written immediately
    }
    pthread_mutex_unlock(&log_mutex);

    // Print to terminal (existing logic)
    printf("%s", alert_msg);

    // NEW: Send to GUI client if active
    pthread_mutex_lock(&live_log_client_mutex);
    if (live_log_client_fd != -1 && gui_live_log_active) {
        // Use your send_all function for robustness
        ssize_t bytes_sent = send_all(live_log_client_fd, alert_msg, strlen(alert_msg), 0);
        if (bytes_sent == -1) {
            perror("Failed to send live log to GUI");
            // Consider setting gui_live_log_active = 0 here or closing socket if persistent error
        }
    }
    pthread_mutex_unlock(&live_log_client_mutex);
}

void load_config() {
    FILE *fp = fopen("config.json", "r");
    if (!fp) {
        perror("Failed to open config.json, using default values");
        // Set default values if config.json is not found
        strncpy(global_config.interface, "eth0", IF_NAMESIZE); // Default interface
        strncpy(global_config.alert_log_file, "ids_alerts.log", 256);
        global_config.cooldown_period_seconds = 10;
        global_config.syn_flood_packet_rate = 80;
        global_config.port_scan_packet_rate = 50;
        global_config.udp_flood_packet_rate = 90;
        global_config.icmp_flood_packet_rate = 70;
        global_config.xmas_fin_null_scan_packet_rate = 40;
        global_config.large_packet_bytes = 2000;
        global_config.invalid_tcp_flags_count = 7;
        global_config.gui_listen_port = 8888;
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_string = malloc(fsize + 1);
    fread(json_string, 1, fsize, fp);
    fclose(fp);
    json_string[fsize] = 0;

    cJSON *json = cJSON_Parse(json_string);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        fprintf(stderr, "Failed to parse config.json, using default values.\n");
        // Set default values if parsing fails
        strncpy(global_config.interface, "eth0", IF_NAMESIZE);
        strncpy(global_config.alert_log_file, "ids_alerts.log", 256);
        global_config.cooldown_period_seconds = 10;
        global_config.syn_flood_packet_rate = 80;
        global_config.port_scan_packet_rate = 50;
        global_config.udp_flood_packet_rate = 90;
        global_config.icmp_flood_packet_rate = 70;
        global_config.xmas_fin_null_scan_packet_rate = 40;
        global_config.large_packet_bytes = 2000;
        global_config.invalid_tcp_flags_count = 7;
        global_config.gui_listen_port = 8888;
        free(json_string);
        return;
    }

    cJSON *interface_item = cJSON_GetObjectItemCaseSensitive(json, "interface");
    if (cJSON_IsString(interface_item) && (interface_item->valuestring != NULL)) {
        strncpy(global_config.interface, interface_item->valuestring, IF_NAMESIZE);
    } else {
        strncpy(global_config.interface, "eth0", IF_NAMESIZE); // Default
    }

    cJSON *alert_log_file_item = cJSON_GetObjectItemCaseSensitive(json, "alert_log_file");
    if (cJSON_IsString(alert_log_file_item) && (alert_log_file_item->valuestring != NULL)) {
        strncpy(global_config.alert_log_file, alert_log_file_item->valuestring, 256);
    } else {
        strncpy(global_config.alert_log_file, "ids_alerts.log", 256); // Default
    }

    cJSON *cooldown_item = cJSON_GetObjectItemCaseSensitive(json, "cooldown_period_seconds");
    if (cJSON_IsNumber(cooldown_item)) {
        global_config.cooldown_period_seconds = cooldown_item->valueint;
    } else {
        global_config.cooldown_period_seconds = 10;
    }
    // ... parse other rate limits similarly ...
    cJSON *syn_flood_item = cJSON_GetObjectItemCaseSensitive(json, "syn_flood_packet_rate");
    if (cJSON_IsNumber(syn_flood_item)) {
        global_config.syn_flood_packet_rate = syn_flood_item->valueint;
    } else {
        global_config.syn_flood_packet_rate = 80;
    }

    cJSON *port_scan_item = cJSON_GetObjectItemCaseSensitive(json, "port_scan_packet_rate");
    if (cJSON_IsNumber(port_scan_item)) {
        global_config.port_scan_packet_rate = port_scan_item->valueint;
    } else {
        global_config.port_scan_packet_rate = 50;
    }

    cJSON *udp_flood_item = cJSON_GetObjectItemCaseSensitive(json, "udp_flood_packet_rate");
    if (cJSON_IsNumber(udp_flood_item)) {
        global_config.udp_flood_packet_rate = udp_flood_item->valueint;
    } else {
        global_config.udp_flood_packet_rate = 90;
    }

    cJSON *icmp_flood_item = cJSON_GetObjectItemCaseSensitive(json, "icmp_flood_packet_rate");
    if (cJSON_IsNumber(icmp_flood_item)) {
        global_config.icmp_flood_packet_rate = icmp_flood_item->valueint;
    } else {
        global_config.icmp_flood_packet_rate = 70;
    }

    cJSON *xmas_fin_null_scan_item = cJSON_GetObjectItemCaseSensitive(json, "xmas_fin_null_scan_packet_rate");
    if (cJSON_IsNumber(xmas_fin_null_scan_item)) {
        global_config.xmas_fin_null_scan_packet_rate = xmas_fin_null_scan_item->valueint;
    } else {
        global_config.xmas_fin_null_scan_packet_rate = 40;
    }

    cJSON *large_packet_bytes_item = cJSON_GetObjectItemCaseSensitive(json, "large_packet_bytes");
    if (cJSON_IsNumber(large_packet_bytes_item)) {
        global_config.large_packet_bytes = large_packet_bytes_item->valueint;
    } else {
        global_config.large_packet_bytes = 2000;
    }

    cJSON *invalid_tcp_flags_item = cJSON_GetObjectItemCaseSensitive(json, "invalid_tcp_flags_count");
    if (cJSON_IsNumber(invalid_tcp_flags_item)) {
        global_config.invalid_tcp_flags_count = invalid_tcp_flags_item->valueint;
    } else {
        global_config.invalid_tcp_flags_count = 7;
    }

    cJSON *gui_port_item = cJSON_GetObjectItemCaseSensitive(json, "gui_listen_port");
    if (cJSON_IsNumber(gui_port_item)) {
        global_config.gui_listen_port = gui_port_item->valueint;
    } else {
        global_config.gui_listen_port = 8888; // Default
    }


    cJSON_Delete(json);
    free(json_string);
}


// This function loads signatures from a JSON string provided by the GUI
void load_signatures(const char *json_string) {
    pthread_mutex_lock(&signatures_mutex);
    cJSON *json = cJSON_Parse(json_string);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error parsing signatures JSON: %s\n", error_ptr);
        }
        pthread_mutex_unlock(&signatures_mutex);
        return;
    }

    if (!cJSON_IsArray(json)) {
        fprintf(stderr, "Signatures JSON is not an array.\n");
        cJSON_Delete(json);
        pthread_mutex_unlock(&signatures_mutex);
        return;
    }

    num_signatures = 0; // Clear existing signatures
    cJSON *signature_item;
    cJSON_ArrayForEach(signature_item, json) {
        if (num_signatures >= MAX_SIGNATURES) {
            fprintf(stderr, "Max signatures reached, skipping.\n");
            break;
        }

        cJSON *name = cJSON_GetObjectItemCaseSensitive(signature_item, "name");
        cJSON *description = cJSON_GetObjectItemCaseSensitive(signature_item, "description");
        cJSON *severity = cJSON_GetObjectItemCaseSensitive(signature_item, "severity");
        cJSON *condition = cJSON_GetObjectItemCaseSensitive(signature_item, "condition");

        if (cJSON_IsString(name) && name->valuestring != NULL &&
            cJSON_IsString(description) && description->valuestring != NULL &&
            cJSON_IsString(severity) && severity->valuestring != NULL &&
            cJSON_IsString(condition) && condition->valuestring != NULL) {

            strncpy(signatures[num_signatures].name, name->valuestring, sizeof(signatures[num_signatures].name) - 1);
            signatures[num_signatures].name[sizeof(signatures[num_signatures].name) - 1] = '\0';
            strncpy(signatures[num_signatures].description, description->valuestring, sizeof(signatures[num_signatures].description) - 1);
            signatures[num_signatures].description[sizeof(signatures[num_signatures].description) - 1] = '\0';
            strncpy(signatures[num_signatures].severity, severity->valuestring, sizeof(signatures[num_signatures].severity) - 1);
            signatures[num_signatures].severity[sizeof(signatures[num_signatures].severity) - 1] = '\0';
            strncpy(signatures[num_signatures].condition, condition->valuestring, sizeof(signatures[num_signatures].condition) - 1);
            signatures[num_signatures].condition[sizeof(signatures[num_signatures].condition) - 1] = '\0';

            num_signatures++;
        } else {
            fprintf(stderr, "Skipping malformed signature entry.\n");
        }
    }

    cJSON_Delete(json);
    pthread_mutex_unlock(&signatures_mutex);
    printf("Signatures loaded successfully. Total: %d\n", num_signatures);
}

// Function to evaluate conditions dynamically (simplified example)
cJSON_bool evaluate_condition(const char *condition_str, const PacketDetails *details, const FlowStats *flow_stats) {
    // This is a highly simplified example. A real implementation would involve a proper
    // expression parser and evaluator (e.g., using a library like muparser or writing one).
    // For now, it only checks for direct string matches representing conditions.

    if (strcmp(condition_str, "syn_flood_attack") == 0) {
        return flow_stats && flow_stats->syn_count > global_config.syn_flood_packet_rate;
    } else if (strcmp(condition_str, "tcp_port_scan_low_ports") == 0) {
        return flow_stats && flow_stats->unique_dst_ports_count > global_config.port_scan_packet_rate && details->dst_port <= 1023;
    } else if (strcmp(condition_str, "tcp_port_scan_high_ports") == 0) {
        return flow_stats && flow_stats->unique_dst_ports_count > global_config.port_scan_packet_rate && details->dst_port > 1023;
    } else if (strcmp(condition_str, "udp_flood_attack") == 0) {
        return flow_stats && flow_stats->packet_count > global_config.udp_flood_packet_rate && details->protocol == IPPROTO_UDP;
    } else if (strcmp(condition_str, "icmp_flood_attack") == 0) {
        return flow_stats && flow_stats->packet_count > global_config.icmp_flood_packet_rate && details->protocol == IPPROTO_ICMP;
    } else if (strcmp(condition_str, "xmas_scan") == 0) {
        // FIN, URG, PUSH flags set, no SYN, ACK, RST
        return (details->protocol == IPPROTO_TCP &&
                (details->tcp_flags & (TH_FIN | TH_URG | TH_PUSH)) == (TH_FIN | TH_URG | TH_PUSH) &&
                !(details->tcp_flags & (TH_SYN | TH_ACK | TH_RST)));
    } else if (strcmp(condition_str, "fin_scan") == 0) {
        // Only FIN flag set, no SYN, ACK, RST, URG, PSH
        return (details->protocol == IPPROTO_TCP &&
                (details->tcp_flags & TH_FIN) &&
                !(details->tcp_flags & (TH_SYN | TH_ACK | TH_RST | TH_URG | TH_PUSH)));
    } else if (strcmp(condition_str, "null_scan") == 0) {
        // No flags set (all zero)
        return (details->protocol == IPPROTO_TCP &&
                details->tcp_flags == 0);
    } else if (strcmp(condition_str, "syn_ack_no_syn") == 0) {
        // SYN-ACK without prior SYN from this flow (implies checking flow->is_established and syn_count)
        return (details->protocol == IPPROTO_TCP &&
                (details->tcp_flags & TH_SYN) && (details->tcp_flags & TH_ACK) &&
                !flow_stats->is_established && flow_stats->syn_count == 0);
    } else if (strcmp(condition_str, "rst_flood_attack") == 0) {
        return flow_stats && flow_stats->packet_count > global_config.icmp_flood_packet_rate && details->protocol == IPPROTO_TCP && (details->tcp_flags & TH_RST);
    }
    // Add more complex conditions based on your needs

    return cJSON_False;
}

void initialize_flow_stats(FlowStats *flow, const char *src_ip, const char *dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char protocol) {
    memset(flow, 0, sizeof(FlowStats));
    strncpy(flow->src_ip, src_ip, INET_ADDRSTRLEN - 1);
    strncpy(flow->dst_ip, dst_ip, INET_ADDRSTRLEN - 1);
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->protocol = protocol;
    flow->last_packet_time = time(NULL);
}

FlowStats *get_or_create_flow(const char *src_ip, const char *dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char protocol) {
    pthread_mutex_lock(&flow_mutex);
    for (unsigned long i = 0; i < flow_index; i++) {
        FlowStats *flow = flows[i];
        if (flow && strcmp(flow->src_ip, src_ip) == 0 &&
            strcmp(flow->dst_ip, dst_ip) == 0 &&
            flow->src_port == src_port &&
            flow->dst_port == dst_port &&
            flow->protocol == protocol) {

            // Check for cooldown period
            time_t current_time = time(NULL);
            if ((current_time - flow->last_packet_time) > global_config.cooldown_period_seconds) {
                // If cooldown passed, reset flow for new analysis (optional, depending on desired behavior)
                initialize_flow_stats(flow, src_ip, dst_ip, src_port, dst_port, protocol);
            }
            pthread_mutex_unlock(&flow_mutex);
            return flow;
        }
    }

    // Flow not found, create a new one
    if (flow_index < MAX_FLOWS) {
        FlowStats *new_flow = (FlowStats *)malloc(sizeof(FlowStats));
        if (new_flow == NULL) {
            fprintf(stderr, "Failed to allocate memory for new flow.\n");
            pthread_mutex_unlock(&flow_mutex);
            return NULL;
        }
        initialize_flow_stats(new_flow, src_ip, dst_ip, src_port, dst_port, protocol);
        flows[flow_index++] = new_flow;
        pthread_mutex_unlock(&flow_mutex);
        return new_flow;
    } else {
        fprintf(stderr, "Flow table full. Cannot create new flow.\n");
        pthread_mutex_unlock(&flow_mutex);
        return NULL;
    }
}

void update_flow_stats(FlowStats *flow, const PacketDetails *details) {
    if (!flow) return;
    flow->packet_count++;
    flow->last_packet_time = time(NULL);

    if (details->protocol == IPPROTO_TCP) {
        if (details->tcp_flags & TH_SYN) {
            flow->syn_count++;
        }
        if (details->tcp_flags & TH_ACK) {
            flow->ack_count++;
        }
        // Simple check for established flow: SYN-ACK received after SYN
        if ((details->tcp_flags & TH_SYN) && (details->tcp_flags & TH_ACK) && flow->syn_count > 0 && !flow->is_established) {
            flow->is_established = 1;
        }

        // For port scanning: Mark unique destination ports
        if (details->dst_port < 65536) {
            if (flow->unique_dst_ports[details->dst_port] == 0) {
                flow->unique_dst_ports[details->dst_port] = 1;
                flow->unique_dst_ports_count++;
            }
        }
    }
    // Add more protocol-specific updates as needed
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Unused argument

    pthread_mutex_lock(&sniff_start_mutex);
    if (!sniffing_active) {
        pthread_mutex_unlock(&sniff_start_mutex);
        return; // Do not process if sniffing is paused
    }
    pthread_mutex_unlock(&sniff_start_mutex);

    // Placeholder for packet processing (e.g., parsing, flow tracking)
    // This is where you would extract details and update flow statistics
    analyze_packet(header, packet);
}

void analyze_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    const struct iphdr *ip_header;
    const struct tcphdr *tcp_header;
    const struct udphdr *udp_header;
    const struct icmphdr *icmp_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned short src_port = 0, dst_port = 0;
    unsigned int ip_header_len;
    unsigned int payload_offset = 0;
    PacketDetails details;
    memset(&details, 0, sizeof(PacketDetails));

    // 1. Ethernet Header
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // 2. IP Header
        ip_header = (struct iphdr *)(packet + ETH_HLEN);
        ip_header_len = ip_header->ihl * 4;
        inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

        details.protocol = ip_header->protocol;
        details.packet_length = header->len; // Total packet length captured
        strncpy(details.src_ip, src_ip, sizeof(details.src_ip) - 1);
        strncpy(details.dst_ip, dst_ip, sizeof(details.dst_ip) - 1);

        // 3. Transport Layer Header
        payload_offset = ETH_HLEN + ip_header_len;

        if (ip_header->protocol == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)(packet + payload_offset);
            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
            details.tcp_flags = tcp_header->th_flags;
            details.src_port = src_port;
            details.dst_port = dst_port;
            details.has_payload = (header->len - (payload_offset + (tcp_header->doff * 4))) > 0;
            details.payload_length = header->len - (payload_offset + (tcp_header->doff * 4));

        } else if (ip_header->protocol == IPPROTO_UDP) {
            udp_header = (struct udphdr *)(packet + payload_offset);
            src_port = ntohs(udp_header->source);
            dst_port = ntohs(udp_header->dest);
            details.src_port = src_port;
            details.dst_port = dst_port;
            details.has_payload = (header->len - (payload_offset + sizeof(struct udphdr))) > 0;
            details.payload_length = header->len - (payload_offset + sizeof(struct udphdr));

        } else if (ip_header->protocol == IPPROTO_ICMP) {
            icmp_header = (struct icmphdr *)(packet + payload_offset);
            details.icmp_type = icmp_header->type;
            details.icmp_code = icmp_header->code;
            details.has_payload = (header->len - (payload_offset + sizeof(struct icmphdr))) > 0;
            details.payload_length = header->len - (payload_offset + sizeof(struct icmphdr));
        }

        // Get or create flow stats
        FlowStats *current_flow = get_or_create_flow(src_ip, dst_ip, src_port, dst_port, ip_header->protocol);
        if (current_flow) {
            update_flow_stats(current_flow, &details);

            // 4. Rule Matching and Alerting
            pthread_mutex_lock(&signatures_mutex);
            for (int i = 0; i < num_signatures; i++) {
                if (evaluate_condition(signatures[i].condition, &details, current_flow)) {
                    log_alert(signatures[i].severity, signatures[i].name, signatures[i].description,
                              src_ip, src_port, dst_ip, dst_port,
                              ip_header->protocol, 1.0); // Confidence placeholder
                    // Optional: Reset flow stats after an alert to prevent repeated alerts for the same continuous event within cooldown
                    // initialize_flow_stats(current_flow, src_ip, dst_ip, src_port, dst_port, ip_header->protocol);
                    break; // Log only one alert per packet for simplicity, remove if multiple matches are desired
                }
            }
            pthread_mutex_unlock(&signatures_mutex);
        }
    }
}

void *sniffing_thread(void *arg) {
    (void)arg;
    char errbuf[PCAP_ERRBUF_SIZE];

    pthread_mutex_lock(&sniff_start_mutex);
    // Wait until sniffing_active is 1 (signaled by GUI thread)
    while (sniffing_active == 0) {
        pthread_cond_wait(&sniff_start_cond, &sniff_start_mutex);
    }
    pthread_mutex_unlock(&sniff_start_mutex);

    handle = pcap_open_live(global_config.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", global_config.interface, errbuf);
        sniffing_active = 2; // Indicate termination
        return NULL;
    }

    printf("Sniffing on interface %s...\n", global_config.interface);

    // Loop forever, processing packets
    pcap_loop(handle, -1, process_packet, NULL);

    pcap_close(handle);
    printf("Sniffing stopped.\n");
    return NULL;
}


// --- GUI Communication Thread ---
void *gui_communication_thread(void *arg) {
    (void)arg;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    ssize_t valread;

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address and port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    pthread_mutex_lock(&config_mutex); // Lock config to read gui_listen_port
    address.sin_port = htons(global_config.gui_listen_port);
    pthread_mutex_unlock(&config_mutex);

    // Bind the socket to the specified port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("GUI communication server listening on port %d\n", ntohs(address.sin_port));

    while (sniffing_active != 2) { // Keep running until main signals termination
        // Accept a new connection
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("accept");
            continue; // Continue listening for other connections
        }
        char *client_ip = inet_ntoa(address.sin_addr);
        int client_port = ntohs(address.sin_port);
        printf("GUI client connected: %s:%d\n", client_ip, client_port);

        // Read command from GUI
        valread = read(new_socket, buffer, sizeof(buffer) - 1);

        if (valread > 0) {
            buffer[valread] = '\0';
            printf("Received from GUI: %s\n", buffer);

            if (strncmp(buffer, "GET_IDS_STATUS", strlen("GET_IDS_STATUS")) == 0) {
                // Send IDS status response
                char status_msg[256];
                int active_status;
                pthread_mutex_lock(&sniff_start_mutex);
                active_status = sniffing_active;
                pthread_mutex_unlock(&sniff_start_mutex);

                if (active_status == 1) {
                    snprintf(status_msg, sizeof(status_msg), "Running on interface %s", global_config.interface);
                } else if (active_status == 0) {
                    snprintf(status_msg, sizeof(status_msg), "Paused on interface %s", global_config.interface);
                } else {
                    snprintf(status_msg, sizeof(status_msg), "ERROR: Sniffing not active or unknown state");
                }
                send_all(new_socket, status_msg, strlen(status_msg), 0);
                close(new_socket); // Close after response for status
            } else if (strncmp(buffer, "UPLOAD_SIGNATURES", strlen("UPLOAD_SIGNATURES")) == 0) {
                printf("Processing UPLOAD_SIGNATURES command...\n");
                // Skip command and newline, then pass the rest as JSON string
                char *json_start = strstr(buffer, "\n");
                if (json_start) {
                    load_signatures(json_start + 1); // Skip the newline
                    send_all(new_socket, "SIGNATURES_UPLOADED_OK\n", strlen("SIGNATURES_UPLOADED_OK\n"), 0);
                } else {
                    send_all(new_socket, "ERROR: Invalid UPLOAD_SIGNATURES format\n", strlen("ERROR: Invalid UPLOAD_SIGNATURES format\n"), 0);
                }
                close(new_socket); // Close after response for upload
            } else if (strncmp(buffer, "START_SNIFFING", strlen("START_SNIFFING")) == 0) {
                pthread_mutex_lock(&sniff_start_mutex);
                if (sniffing_active == 0) {
                    sniffing_active = 1;
                    pthread_cond_signal(&sniff_start_cond); // Signal sniffing thread to start
                    send_all(new_socket, "Sniffing started.\n", strlen("Sniffing started.\n"), 0);
                    printf("Sniffing started by GUI command.\n");
                } else {
                    send_all(new_socket, "Sniffing already active.\n", strlen("Sniffing already active.\n"), 0);
                    printf("Sniffing already active, GUI command ignored.\n");
                }
                pthread_mutex_unlock(&sniff_start_mutex);
                close(new_socket);
            } else if (strncmp(buffer, "STOP_SNIFFING", strlen("STOP_SNIFFING")) == 0) {
                pthread_mutex_lock(&sniff_start_mutex);
                if (sniffing_active == 1) {
                    sniffing_active = 0;
                    send_all(new_socket, "Sniffing stopped.\n", strlen("Sniffing stopped.\n"), 0);
                    printf("Sniffing stopped by GUI command.\n");
                } else {
                    send_all(new_socket, "Sniffing already inactive.\n", strlen("Sniffing already inactive.\n"), 0);
                    printf("Sniffing already inactive, GUI command ignored.\n");
                }
                pthread_mutex_unlock(&sniff_start_mutex);
                close(new_socket);
            } else if (strncmp(buffer, "START_LOG_STREAM", strlen("START_LOG_STREAM")) == 0) {
                pthread_mutex_lock(&live_log_client_mutex);
                if (live_log_client_fd != -1 && live_log_client_fd != new_socket) {
                    // There's already an active live log client. Close the old one.
                    printf("Closing previous live log client (fd %d) to accept new one.\n", live_log_client_fd);
                    close(live_log_client_fd);
                    gui_live_log_active = 0; // Deactivate the old stream
                }
                live_log_client_fd = new_socket; // Store the socket for live logs
                gui_live_log_active = 1; // Activate live log streaming
                printf("Live log stream started for client %d.\n", new_socket);
                // IMPORTANT: DO NOT CLOSE new_socket here. It needs to stay open for continuous streaming.
            } else if (strncmp(buffer, "STOP_LOG_STREAM", strlen("STOP_LOG_STREAM")) == 0) {
                pthread_mutex_lock(&live_log_client_mutex);
                if (live_log_client_fd != -1) {
                    printf("Stopping live log stream for client %d.\n", live_log_client_fd);
                    close(live_log_client_fd); // Close the *stored* live log socket
                    live_log_client_fd = -1;
                }
                gui_live_log_active = 0; // Deactivate live log streaming
                pthread_mutex_unlock(&live_log_client_mutex);
                close(new_socket); // Close the socket that sent the STOP command (it's a control command)
            } else {
                printf("Unknown command: %s\n", buffer);
                send_all(new_socket, "UNKNOWN_COMMAND\n", strlen("UNKNOWN_COMMAND\n"), 0);
                close(new_socket); // Close unknown command socket
            }
        } else if (valread == 0) {
            // Client gracefully disconnected.
            printf("GUI client disconnected.\n");
            // If the disconnected client was the live log client, reset globals.
            pthread_mutex_lock(&live_log_client_mutex);
            if (new_socket == live_log_client_fd) {
                printf("Live log client disconnected unexpectedly.\n");
                live_log_client_fd = -1;
                gui_live_log_active = 0;
            }
            pthread_mutex_unlock(&live_log_client_mutex);
            close(new_socket);
        } else { // valread < 0 (error)
            perror("read failed");
            // If read fails, assume connection is bad and close it.
            // Check if it was the live log client before closing.
            pthread_mutex_lock(&live_log_client_mutex);
            if (new_socket == live_log_client_fd) {
                 printf("Live log client read error or unexpected disconnection.\n");
                 live_log_client_fd = -1;
                 gui_live_log_active = 0;
            }
            pthread_mutex_unlock(&live_log_client_mutex);
            close(new_socket);
        }
    }
    close(server_fd); // This line is unreachable in the provided snippet but good practice
    return NULL;
}

void cleanup(int signum) {
    printf("\nReceived signal %d, performing cleanup...\n", signum);

    pthread_mutex_lock(&sniff_start_mutex);
    sniffing_active = 2; // Signal sniffing thread to terminate
    pthread_cond_signal(&sniff_start_cond); // Wake up sniffing thread if it's waiting
    pthread_mutex_unlock(&sniff_start_mutex);

    // Give some time for threads to clean up
    sleep(1);

    if (handle) {
        pcap_breakloop(handle); // Break pcap_loop immediately
        pcap_close(handle);
        handle = NULL;
    }

    pthread_mutex_lock(&log_mutex);
    if (alert_log_fp) {
        fclose(alert_log_fp);
        alert_log_fp = NULL;
    }
    pthread_mutex_unlock(&log_mutex);

    // Clean up flows
    pthread_mutex_lock(&flow_mutex);
    for (unsigned long i = 0; i < flow_index; i++) {
        free(flows[i]);
        flows[i] = NULL;
    }
    flow_index = 0;
    pthread_mutex_unlock(&flow_mutex);

    // Destroy mutexes and condition variables (done in main after join)
    // pthread_mutex_destroy(&log_mutex);
    // pthread_mutex_destroy(&flow_mutex);
    // pthread_mutex_destroy(&signatures_mutex);
    // pthread_mutex_destroy(&config_mutex);
    // pthread_mutex_destroy(&sniff_start_mutex);
    // pthread_cond_destroy(&sniff_start_cond);
    // pthread_mutex_destroy(&live_log_client_mutex);

    printf("Cleanup complete. Exiting.\n");
    exit(0);
}

int main() {
    // 1. Initialize mutexes and condition variable
    pthread_mutex_init(&log_mutex, NULL);
    pthread_mutex_init(&flow_mutex, NULL);
    pthread_mutex_init(&signatures_mutex, NULL);
    pthread_mutex_init(&config_mutex, NULL);
    pthread_mutex_init(&sniff_start_mutex, NULL);
    pthread_cond_init(&sniff_start_cond, NULL);
    pthread_mutex_init(&live_log_client_mutex, NULL); // Initialize live log mutex

    // 2. Register signal handlers for graceful shutdown
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // 3. Load configuration from config.json
    pthread_mutex_lock(&config_mutex);
    load_config();
    pthread_mutex_unlock(&config_mutex);
    printf("Configuration loaded. GUI Listen Port: %d\n", global_config.gui_listen_port);

    // 4. Open alert log file
    pthread_mutex_lock(&log_mutex);
    alert_log_fp = fopen(global_config.alert_log_file, "a");
    if (alert_log_fp == NULL) {
        perror("Failed to open alert log file");
        // Non-fatal, continue without file logging
    } else {
        printf("Alerts will be logged to %s\n", global_config.alert_log_file);
    }
    pthread_mutex_unlock(&log_mutex);

    // 5. Start GUI communication thread
    pthread_t gui_thread_id;
    if (pthread_create(&gui_thread_id, NULL, gui_communication_thread, NULL) != 0) {
        perror("Failed to create GUI communication thread");
        return 1;
    }

    // 6. Start Sniffing thread (initially paused, waiting for signal from GUI)
    pthread_t sniffing_thread_id;
    // The sniffing thread will wait on a condition variable until the GUI signals it to start.
    if (pthread_create(&sniffing_thread_id, NULL, sniffing_thread, NULL) != 0) {
        perror("Failed to create sniffing thread");
        // If GUI thread created, should clean up. For now, exit.
        return 1;
    }

    // Main thread can now do other things or simply wait.
    pthread_join(gui_thread_id, NULL); // Wait for GUI thread (will run indefinitely)
    // If GUI thread exits, then the sniffing thread should also be terminated.
    // pthread_cancel(sniffing_thread_id); // Not using pthread_cancel for safer shutdown
    pthread_join(sniffing_thread_id, NULL); // Wait for sniffing thread to finish after GUI signals stop or exits

    // Final cleanup (if threads exited normally, though cleanup() signal handler is primary)
    pthread_mutex_destroy(&log_mutex);
    pthread_mutex_destroy(&flow_mutex);
    pthread_mutex_destroy(&signatures_mutex);
    pthread_mutex_destroy(&config_mutex);
    pthread_mutex_destroy(&sniff_start_mutex);
    pthread_cond_destroy(&sniff_start_cond);
    pthread_mutex_destroy(&live_log_client_mutex); // Destroy live log mutex

    // Close alert log file if not already closed by cleanup
    if (alert_log_fp) {
        fclose(alert_log_fp);
    }

    return 0;
}
