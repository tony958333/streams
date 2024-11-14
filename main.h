#define __FAVOR_BSD
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include "stdbool.h"
#include "math.h"
#include "unistd.h"
#include "sys/ioctl.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "sys/poll.h"
#include "linux/if_packet.h"
#include "netinet/in.h"
#include "netinet/if_ether.h"
//#include "netinet/ether.h"
#include "netinet/ip_icmp.h"
#include "netinet/ip.h"
#include "linux/ipv6.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "net/ethernet.h"
#include "net/if.h"
//#include "net/if_arp.h"
//#include "net/if_packet.h"
#include "netdb.h"
#include "errno.h"
#include "arpa/inet.h"
#include "signal.h"
#include "sys/time.h"
#include "cjson/cJSON.h"
//sudo apt install libcjson-dev
#include "mysql/mysql.h"
//sudo apt install mysql-server
//sudo apt install libmysqlclient-dev
//sudo mysql
//set global validate_password.policy='LOW';
//ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Cxx12345';
//FLUSH PRIVILEGES;

#define nullptr NULL

//待处理的tcpdump文件名
char g_szDumpFileName[1024]="dump.pcap";
char g_SNI[128]="";
long long g_pktno; //paket no in pcap file
long long g_pktdrop=0;
long long g_pktdropIPv4=0;
long long g_pktdropIPv6=0;
long long g_pktdropICMP=0;

/* 接收缓冲区 */
char *g_pBuff;

char HEX[16]="0123456789abcdef";
/*以太网帧封装的协议类型 */
const int g_iEthProId[] = {
    ETHERTYPE_PUP,
    ETHERTYPE_SPRITE,
    ETHERTYPE_IP,
    ETHERTYPE_ARP,
    ETHERTYPE_REVARP,
    ETHERTYPE_AT,
    ETHERTYPE_AARP,
    ETHERTYPE_VLAN,
    ETHERTYPE_IPX,
    ETHERTYPE_IPV6,
    ETHERTYPE_LOOPBACK
};
//协议类型名字
const char g_szProName[][24] = { "none", "xerox pup", "sprite", "ip","arp","rarp", "apple-protocol","apple-arp","802.1q", "ipx","ipv6", "loopback"};

//类型定义
typedef unsigned char u_int8;
typedef unsigned short u_int16;
typedef unsigned int u_int32;
typedef unsigned long long u_int64;
//pacp文件头结构体
struct pcap_file_header {
    u_int32 magic;				//识别文件和字节顺序：小端/大端模式
    u_int16 version_major;		//主版本号
    u_int16 version_minor;		//次版本号
    u_int32 thiszone;			//当地的标准时间
    u_int32 sigfigs;			//时间戳精度
    u_int32 snaplen;			//最大的存储长度
    u_int32 linktype;			//链路类型
};
//时间戳
struct time_val {
    u_int32 tv_sec;					//时间戳高位，精确到seconds
    u_int32 tv_usec;				//时间戳低位，精确到microseconds
};
//pcap file global header
struct pcap_file_header g_pcapFileHeader;
//pcap数据包头结构体
struct pcap_pkthdr {
    struct time_val ts;			//捕获时间
    u_int32 caplen;				//数据帧/区的长度
    u_int32 len;				//离线数据长度
};
/*------ TCP stream management ------*/
#define STREAM_TABLE_SIZE 65536

#define PKTINFO_SIZE 1024
union ipaddr {
    u_int32 ip32;
    u_int16 ip16[2];
};
struct pktinfo_t {
    int32_t pktlen;
    u_int32 pcappktno; // packet number in pcap file
    struct time_val ts;// 包捕获时间戳
};
struct streamHeader {
    u_int16 hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
    u_int16 num;  //该表项包含多少个流
    struct streamHeader *next; //hash碰撞后的流表项；
    //
    u_int8 ipv; //ip version, 4 or 6
    union ipaddr sip,dip; //table streams field 3,5
    struct in6_addr sip6,dip6;
    char sipstr[40],dipstr[40];
    u_int16 sport,dport;  //table streams field 4,6
    u_int8 protocol;      //table streams field 7
    struct time_val ts;			//首包捕获时间戳
    struct time_val te;			//尾包捕获时间戳
    u_int64 upstreamlen;  //上行数据包总长度
    u_int64 downstreamlen;  //下行数据包总长度
    u_int64 streamlen;    //上下行数据包总长度
    u_int32 pktInfoSize; //包长序列当前容量，初始为0
    u_int32 up_pktNumber;//收到的上行包数
    u_int32 down_pktNumber;//收到的下行包数
    u_int32 pktNumber;   //收到的上下行总包数 table streams field 8
    u_int16 CipherSuiteLen; //client hello CipherSuiteLen
    char CipherSuite[128];  //client hello CipherSuiteLen
    char SNI[128];// "sina.com.cn"
    char tlsv[8]; // tls version "SSL3.0","TLS1.0","TLS1.1","TLS1.2","TLS1.3"
    struct pktinfo_t *pktInfo; //保存包特征序列，初始大小PKTINFO_SIZE，可以倍增法扩容
};
struct streamHeader g_streamHdr[STREAM_TABLE_SIZE];

/*---- config ----*/
struct config {
    struct in_addr mysqlIP;
    u_int16 mysqlPort;
    char mysqlIPString[64];
    char mysqlUserName[128];
    char mysqlPassword[128];
    char mysqlDB[128];
    char mysqlStreamsTbl[128];
    char mysqlPktInfoTbl[128];
    char mysqlDNSTbl[128];
    bool vxlan; //if true , pcap file need parse vxlan head
    bool writePktInfo; // if true write to pktinfo, otherwise not
    bool collectDNS;   // if parse DNS datagram or not
} g_cfg;
MYSQL *g_mysql;
char g_sql[2048];
#define min(a, b) ((a) < (b) ? (a) : (b))
#define error1(title,s1) printf("\033[1;31;40m[%s Error]\033[0m%s\n",title,s1)
#define error2(title,s1,s2) printf("\033[1;31;40m[%s Error]\033[0m%s:%s\n",title,s1,s2)
unsigned int g_streamTblFieldsNum=9;
unsigned int g_pktinfoTblFieldsNum=4;

// utilities functions
void streams_stats() {
    struct streamHeader *st;
    long long streamNum=0;
    struct in_addr sip,dip;
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        if (st->num>0) {
            while (st != nullptr) {
                sip.s_addr=st->sip.ip32;
                dip.s_addr=st->dip.ip32;
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET,&sip, str, sizeof(str));
                printf("%lld:hash %x, \033[1;32;40m%s\033[0m:%d",++streamNum,st->hash,str,ntohs(st->sport));
                inet_ntop(AF_INET,&dip, str, sizeof(str));
                printf(" -> \033[1;32;40m%s\033[0m:%d,pkt number(%d).\n",str,ntohs(st->dport),st->pktNumber);
                /*
                for (int j=0;j<st->pktNumber;j++)
                    printf("%d ",st->pktInfo[j].pktlen);
                printf("\n");
                */
                st=st->next;
            }
        }
    }
}
bool ip6e(const struct in6_addr *sip6,const struct in6_addr *dip6) {
    for (int i=0;i<4;i++) {
        if (sip6->__in6_u.__u6_addr32[i]!=dip6->__in6_u.__u6_addr32[i])
            return false;
    }
    return true;
}
void getTLSV(char *tlsv,int tlsVersion) {
    if (tlsVersion==0x300) strcpy(tlsv,"SSL3.0");
    else if (tlsVersion==0x301) strcpy(tlsv,"TLS1.0");
    else if (tlsVersion==0x302) strcpy(tlsv,"TLS1.1");
    else if (tlsVersion==0x303) strcpy(tlsv,"TLS1.2");
    else if (tlsVersion==0x304) strcpy(tlsv,"TLS1.3");
    else strcpy(tlsv,"");
}
void toLowerCase(char *str) {
    for (int i = 0; i < strlen(str); i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] += 32;
        }
    }
}
int readconfig() {
    // 读取JSON文件
    FILE *file = fopen("config.json", "r");
    if (file == NULL) {
        perror("config file open");
        return -1;
    }
    fseek(file, 0, SEEK_END);
    const long int n1=ftell(file);
    rewind(file);
    char *readBuffer = (char *)malloc(n1+16);
    if (readBuffer == NULL) {
        perror("buffer malloc");
        return -1;
    }
    const unsigned long int n=fread(readBuffer, 1, n1, file);
    if (n != n1) {
        perror("config file read");
        free(readBuffer);
        return -1;
    }
    // 解析JSON文件
    cJSON *cfg = cJSON_Parse(readBuffer);
    if (cfg == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "json error: %s\n", error_ptr);
        }
        fclose(file);
        free(readBuffer);
        return -1;
    }
    // 关闭文件
    fclose(file);
    free(readBuffer);
    // 读取JSON数据
    cJSON *item;

    strcpy(g_cfg.mysqlIPString,"127.0.0.1");
    inet_pton(AF_INET,g_cfg.mysqlIPString,&g_cfg.mysqlIP);
    if (item=cJSON_GetObjectItem(cfg,"mysqlIPString")) {
        strcpy(g_cfg.mysqlIPString, item->valuestring);
        inet_pton(AF_INET,g_cfg.mysqlIPString,&g_cfg.mysqlIP);
    }
    g_cfg.mysqlPort=3306;
    if (item=cJSON_GetObjectItem(cfg,"mysqlPort")) {
        g_cfg.mysqlPort=item->valueint;
    }
    strcpy(g_cfg.mysqlUserName,"root");
    if (item=cJSON_GetObjectItem(cfg,"mysqlUserName")) {
        strcpy(g_cfg.mysqlUserName, item->valuestring);
    }
    strcpy(g_cfg.mysqlPassword,"Cxx12345");
    if (item=cJSON_GetObjectItem(cfg, "mysqlPassword")) {
        strcpy(g_cfg.mysqlPassword, item->valuestring);
    }
    strcpy(g_cfg.mysqlDB,"streams");
    if (item=cJSON_GetObjectItem(cfg, "mysqlDB")) {
        strcpy(g_cfg.mysqlDB, item->valuestring);
    }
    strcpy(g_cfg.mysqlStreamsTbl,"streams");
    if (item=cJSON_GetObjectItem(cfg,"mysqlStreamsTbl")) {
        strcpy(g_cfg.mysqlStreamsTbl, item->valuestring);
    }
    strcpy(g_cfg.mysqlPktInfoTbl,"pktinfo");
    if (item=cJSON_GetObjectItem(cfg,"mysqlPktInfoTbl")) {
        strcpy(g_cfg.mysqlPktInfoTbl, item->valuestring);
    }
    strcpy(g_cfg.mysqlDNSTbl,"dns");
    if (item=cJSON_GetObjectItem(cfg,"mysqlDNSTbl")) {
        strcpy(g_cfg.mysqlDNSTbl, item->valuestring);
    }
    g_cfg.vxlan=false;
    if (item=cJSON_GetObjectItem(cfg,"vxlan")) {
        toLowerCase(item->valuestring);
        if (strcmp(item->valuestring, "yes") == 0) {
            g_cfg.vxlan=true;
        } else {
            g_cfg.vxlan=false;
        }
    }
    g_cfg.writePktInfo=false;
    if (item=cJSON_GetObjectItem(cfg,"writePktInfo")) {
        toLowerCase(item->valuestring);
        if (strcmp(item->valuestring, "yes") == 0) {
            g_cfg.writePktInfo=true;
        } else {
            g_cfg.writePktInfo=false;
        }
    }
    g_cfg.collectDNS=false;
    if (item=cJSON_GetObjectItem(cfg,"collectDNS")) {
        toLowerCase(item->valuestring);
        if (strcmp(item->valuestring, "yes") == 0) {
            g_cfg.collectDNS=true;
        } else {
            g_cfg.collectDNS=false;
        }
    }
    // clear
    cJSON_Delete(cfg);
    return 0;
}
int saveconfig() {
    //save configuration to config.json
    cJSON *root;
    root=cJSON_CreateObject();                     // 创建根数据对象
    cJSON_AddStringToObject(root,"mysqlIPString",g_cfg.mysqlIPString);
    cJSON_AddNumberToObject(root,"mysqlPort",g_cfg.mysqlPort);
    cJSON_AddStringToObject(root,"mysqlUserName",g_cfg.mysqlUserName);
    cJSON_AddStringToObject(root,"mysqlPassword",g_cfg.mysqlPassword);
    cJSON_AddStringToObject(root, "mysqlDB",g_cfg.mysqlDB);
    //cJSON_AddStringToObject(root,"mysqlStreamsTbl",g_cfg.mysqlStreamsTbl);
    //cJSON_AddStringToObject(root,"mysqlPktInfoTbl",g_cfg.mysqlPktInfoTbl);
    cJSON_AddStringToObject(root,"vxlan",(g_cfg.vxlan?"yes":"no"));
    cJSON_AddStringToObject(root,"writePktInfo",(g_cfg.writePktInfo?"yes":"no"));
    cJSON_AddStringToObject(root,"collectDNS",(g_cfg.collectDNS?"yes":"no"));

    char *out = cJSON_Print(root);   // 将json形式转换成字符串
    // write to config.json
    FILE *file = fopen("config.json", "w");
    if (file == NULL) {
        perror("config file open");
        return -1;
    }
    const unsigned long int n=fwrite(out, 1, strlen(out), file);
    if (n != strlen(out)) {
        perror("config file write");
        return -1;
    }
    // 关闭文件
    fclose(file);
    // clear
    free(out);
    cJSON_Delete(root);
    return 0;
}
