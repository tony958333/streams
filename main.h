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
//ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Cxx12345';
//FLUSH PRIVILEGES;

#define nullptr NULL
/* 接收缓冲区大小 */
#define RCV_BUF_SIZE     1514*1

//待处理的tcpdump文件名
char g_szDumpFileName[1024]="dump.pcap";
long long g_pktno; //paket no in pcap file

/* 接收缓冲区 */
char *g_pBuff;

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
    u_int32 tv_usec;				//时间戳地位，精确到microseconds
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
    int32_t pcappktno; // packet number in pcap file
};
struct streamHeader {
    u_int16 hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
    union ipaddr sip,dip;
    u_int16 sport,dport;
    u_int16 num;  //该表项包含多少个流
    struct streamHeader *next; //hash碰撞后的流表项；
    u_int32 pktInfoSize; //包长序列当前容量，初始为0
    u_int32 pktNumber;//收到的包数
    struct pktinfo_t *pktInfo; //保存包特征序列，初始大小PKTINFO_SIZE，可以倍增法扩容
};
struct streamHeader g_streamHdr[STREAM_TABLE_SIZE];
/*---- mysql config ----*/
struct config {
    struct in_addr mysqlIP;
    u_int16 mysqlPort;
    char mysqlIPString[64];
    char mysqlUserName[128];
    char mysqlPassword[128];
    char mysqlDB[128];
    char mysqlStreamsTbl[128];
    char mysqlPktInfoTbl[128];
} g_cfg;
MYSQL *g_mysql;
char g_sql[2048];
#define error1(title,s1) printf("\033[1;31;40m[%s Error]\033[0m%s\n",title,s1)
