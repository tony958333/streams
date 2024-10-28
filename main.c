#include "main.h"
#include "plot.h"

/* 输出MAC地址 */
static void ethdump_showMac(const int iType, const char acHWAddr[])
{
    int i = 0;
    if (0 == iType)    {
        printf("SMAC=[");
    }
    else {
        printf("DMAC=[");
    }

    for(i = 0; i < ETHER_ADDR_LEN - 1; i++) {
        printf("%02x:", *((unsigned char *)&(acHWAddr[i])));
    }
    printf("%02x] ", *((unsigned char *)&(acHWAddr[i])));
}

/* 获取L2帧封装的协议类型 */
static char *ethdump_getProName(const int iProNum)
{
    int iIndex = 0;
    for(iIndex = 0; iIndex < sizeof(g_iEthProId) / sizeof(g_iEthProId[0]); iIndex++) {
        if (iProNum == g_iEthProId[iIndex]) {
            break;
        }
    }
    return (char *)(g_szProName[iIndex + 1]);
}

/* 解析IPv6数据包头 */
static int ethdump_parseIpv6Head(const struct ipv6hdr *pstIpv6Head)
{
    int iRet=-1;
    if (nullptr == pstIpv6Head) {
        return -1;
    }
    printf("IPv6-Pkt:");
    uint16_t *sa=(uint16_t *)&(pstIpv6Head->saddr.__in6_u.__u6_addr16);
    uint16_t *da=(uint16_t *)&(pstIpv6Head->daddr.__in6_u.__u6_addr16);
    printf("SAddr=[%x:%x:%x:%x:%x:%x:%x:%x] ", ntohs(sa[0]), ntohs(sa[1]), ntohs(sa[2]),ntohs(sa[3]), ntohs(sa[4]), ntohs(sa[5]), ntohs(sa[6]), ntohs(sa[7]));
    printf("DAddr=[%x:%x:%x:%x:%x:%x:%x:%x]\n",ntohs(da[0]), ntohs(da[1]), ntohs(da[2]),ntohs(da[3]), ntohs(da[4]), ntohs(da[5]), ntohs(da[6]), ntohs(da[7]));
    return iRet;
}

/* 解析ICMP数据包头 */
static int ethdump_parseIcmpHead(const struct icmphdr *pstIcmpHead)
{
    if (nullptr == pstIcmpHead) {
        return -1;
    }
    printf("ICMP-Pkt:");
    printf("Type=[%d] ", ntohs(pstIcmpHead->type));
    printf("Code=[%d]\n", ntohs(pstIcmpHead->code));
    return 0;
}

/* 解析UDP数据包头 */
static int ethdump_parseUdpHead(const struct udphdr *pstUdpHead)
{
    if (nullptr == pstUdpHead) {
        return -1;
    }
    printf("UDP-Pkt:");
    printf("SPort=[%d] ", ntohs(pstUdpHead->uh_sport));
    printf("DPort=[%d]\n", ntohs(pstUdpHead->uh_dport));
    return 0;
}

/* 解析TCP数据包头 */
static int ethdump_parseTcpHead(const struct tcphdr *pstTcpHead,const struct ip *pstIpHead)
{
    int iRet=-1;
    if (nullptr == pstTcpHead) {
        return iRet;
    }
    printf("TCP-Pkt:");
    printf("SPort=[%d] ", ntohs(pstTcpHead->th_sport));
    printf("DPort=[%d]\n", ntohs(pstTcpHead->th_dport));
    //流表处理
    struct pcap_pkthdr *hdr=(struct pcap_pkthdr *)g_pBuff;
    union ipaddr *sip=(union ipaddr *)&(pstIpHead->ip_src);
    union ipaddr *dip=(union ipaddr *)&(pstIpHead->ip_dst);
    bool bDownStream=false; //上行流还是下行流
    //计算hash，即流表索引
    u_int16 hash=sip->ip16[0]^sip->ip16[1]^dip->ip16[0]^dip->ip16[1]^pstTcpHead->th_sport^pstTcpHead->th_dport;
    struct streamHeader *st=g_streamHdr+hash;
    if (st->num==0) {
        //新hash值，直接建新流
        st->num=1; //该表项包含多少个流
        st->hash=hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
        st->sip=*sip;
        st->dip=*dip;
        st->sport=pstTcpHead->th_sport;
        st->dport=pstTcpHead->th_dport;
        st->next=nullptr; //hash碰撞后的流表项；
        st->pktNumber=0;//收到的包数
        st->pktInfoSize=0;//包长序列当前容量，初始为0
        st->pktInfo=nullptr; //保存包长序列，初始大小PKTINFO_SIZE，倍增法扩容
    }else {
        //hash已存在，查找是否已存在旧流
        while (st!=nullptr) {
            if (st->sip.ip32==sip->ip32 && st->dip.ip32==dip->ip32 && st->sport==pstTcpHead->th_sport && st->dport==pstTcpHead->th_dport) {
                bDownStream=false;
                break;
            }
            if (st->sip.ip32==dip->ip32 && st->dip.ip32==sip->ip32 && st->sport==pstTcpHead->th_dport && st->dport==pstTcpHead->th_sport) {
                bDownStream=true;
                break;
            }
            st=st->next;
        }
        if (st==nullptr) {
            //新流,插入到最前面（假设新建的流访问频率高，老流访问频率低）
            st=malloc(sizeof(struct streamHeader));
            if (st==nullptr) {
                perror("malloc new streamHeader");
                return iRet;
            }
            memset(st,0,sizeof(struct streamHeader));
            st->next=(g_streamHdr+hash)->next;
            (g_streamHdr+hash)->next=st;
            st->num=1; //该表项包含多少个流
            st->hash=hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
            st->sip=*sip;
            st->dip=*dip;
            st->sport=pstTcpHead->th_sport;
            st->dport=pstTcpHead->th_dport;
            st->next=nullptr; //hash碰撞后的流表项；
            st->pktNumber=0;//收到的包数
            st->pktInfoSize=0;
            st->pktInfo=nullptr; //保存包长序列，初始大小PKTINFO_SIZE
        }else {
            //旧流，st指向流表项
        }
    }
    //处理包长序列，当前st指向待处理的流表项
    if (st->pktNumber==0) {
        //新流初始化包长序列
        st->pktInfo=malloc(sizeof(u_int32)*PKTINFO_SIZE);
        if (st->pktInfo==nullptr) {
            perror("malloc new pktInfo");
            return iRet;
        }
        memset(st->pktInfo,0,sizeof(u_int32)*PKTINFO_SIZE);
        st->pktInfoSize=PKTINFO_SIZE;
    }else if (st->pktNumber==st->pktInfoSize) {
        //包长序列容量已满，扩增容量
        st->pktInfo=realloc(st->pktInfo,sizeof(u_int32)*(st->pktInfoSize+PKTINFO_SIZE));
        if (st->pktInfo==nullptr) {
            perror("realloc pktInfo");
            return iRet;
        }
        st->pktInfoSize+=PKTINFO_SIZE;
    }
    if (bDownStream)
        st->pktInfo[st->pktNumber++]=-hdr->len;
    else
        st->pktInfo[st->pktNumber++]=hdr->len;
    iRet=0;
    return iRet;
}

/* 解析IP数据包头 */
static int ethdump_parseIpHead(const struct ip *pstIpHead)
{
    int iRet=-1;
    struct protoent *pstIpProto = nullptr;
    if (nullptr == pstIpHead) {
        return -1;
    }

    /* 协议类型、源IP地址、目的IP地址 */
    pstIpProto = getprotobynumber(pstIpHead->ip_p);
    if(nullptr != pstIpProto) {
        printf("IP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, pstIpProto->p_name);
    }
    else {
        printf("IP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, "None");
    }
    printf("SAddr=[%s] ", inet_ntoa(pstIpHead->ip_src));
    printf("DAddr=[%s]\n", inet_ntoa(pstIpHead->ip_dst));
    switch (pstIpHead->ip_p) {
        case IPPROTO_UDP:
            struct udphdr *pstUdpHdr = (struct udphdr *)(pstIpHead+1);
            iRet = ethdump_parseUdpHead(pstUdpHdr);
            break;
        case IPPROTO_TCP:
            struct tcphdr *pstTcpHdr = (struct tcphdr *)(pstIpHead+1);
            iRet = ethdump_parseTcpHead(pstTcpHdr,pstIpHead);
            break;
        case IPPROTO_ICMP:
            struct icmphdr *pstIcmpHdr = (struct icmphdr *)(pstIpHead+1);
            iRet = ethdump_parseIcmpHead(pstIcmpHdr);
            break;
        default:
            break;
    }
    return iRet;
}

/* 解析Ethernet帧首部 */
static int ethdump_parseEthHead(const struct ether_header *pstEthHead)
{
    int iRet = -1;
    unsigned short usEthPktType;
    if (nullptr == pstEthHead) {
        return -1;
    }
    /* 协议类型、源MAC、目的MAC */
    //
    usEthPktType = ntohs(pstEthHead->ether_type);
    printf("Eth-Pkt-Type:0x%04x(%s) ", usEthPktType, ethdump_getProName(usEthPktType));
    ethdump_showMac(0, pstEthHead->ether_shost);
    ethdump_showMac(1, pstEthHead->ether_dhost);
    printf("\n");
    //
    switch (usEthPktType) {
        case ETHERTYPE_IP:
            /* IP数据包类型 */
            struct ip *pstIpHead = nullptr;
            pstIpHead  = (struct ip *)(pstEthHead + 1);
            iRet = ethdump_parseIpHead(pstIpHead);
            break;
        case ETHERTYPE_IPV6:
            /* IPv6数据包类型 */
            struct ipv6hdr *pstIpv6Head = nullptr;
            pstIpv6Head  = (struct ipv6hdr *)(pstEthHead + 1);
            iRet = ethdump_parseIpv6Head(pstIpv6Head);
            break;
        default:
            break;
    }
    return iRet;
}

/* 数据帧解析函数 */
static int ethdump_parseFrame(const char *pcFrameData)
{
    int iRet = -1;
    struct ether_header *pstEthHead = nullptr;

    /* Ethnet帧头解析 */
    pstEthHead = (struct ether_header*)pcFrameData;
    iRet = ethdump_parseEthHead(pstEthHead);
    return iRet;
}

/* Main */
int main(int argc, char *argv[]) {
    int iRet = -1;
    FILE *fd   = nullptr;
    int n;

    //初始化流表
    memset(g_streamHdr,0,STREAM_TABLE_SIZE);
    //处理命令行参数
    if (argc>1) {
        strcpy(g_szDumpFileName,argv[1]); //tcpdump file name ,e.g. "dump.pcap"
    } else {
        printf("\nUsage: %s [<pcap file name>]\n",argv[0]);
        printf("       <pcap file name> - default: dump.pcap\n\n");
    }
    /* 打开 pcap文件 */
    fd = fopen(g_szDumpFileName,"rb");
    if(!fd) {
        perror("[Error]Cannot open pcap file ");
        return -1;
    }
    //处理pcap文件头
    n=fread(&g_pcapFileHeader,sizeof(g_pcapFileHeader),1,fd);
    if (n>0) {
        printf("magic: %x\n",g_pcapFileHeader.magic);
        printf("major: %x\n",g_pcapFileHeader.version_major);
        printf("minor: %x\n",g_pcapFileHeader.version_minor);
        printf("thisz: %x\n",g_pcapFileHeader.thiszone);
        printf("sigfi: %x\n",g_pcapFileHeader.sigfigs);
        printf("snapl: %x\n",g_pcapFileHeader.snaplen);
        printf("ltype: %x\n",g_pcapFileHeader.linktype);
    }else{
        perror("[Error]Cannot read pcap file ");
        fclose(fd);
        return 0;
    }
    /* 处理数据包 */
    long long pktNo=0;
    g_pBuff = (char *)malloc(g_pcapFileHeader.snaplen+sizeof(struct pcap_pkthdr));
    if (g_pBuff == nullptr) {
        perror("[Error]Cannot malloc pcap packet buffer");
        fclose(fd);
        return 0;
    }
    char *buff=g_pBuff;
    while (!feof(fd)) {
        //read a packet header
        buff=g_pBuff;
        n=fread(buff,sizeof(struct pcap_pkthdr),1,fd);
        if (n==0) {
            printf("%lld packets processed.\n",pktNo);
            break;
        }else if (n<0){
            perror("[Error]Cannot read pcap packet header");
            break;
        }
        //read a packet
        struct pcap_pkthdr *hdr=(struct pcap_pkthdr *)buff;
        buff+=sizeof(struct pcap_pkthdr);
        n=fread(buff,hdr->caplen,1,fd); //caplen:dump下来的包长度, len:原始包长
        if (n<=0) {
            perror("[Error]Cannot read pcap packet");
            break;
        }
        pktNo++;
        printf("\033[1;31;40m>>> Packet %lld: len=%d bytes, cap=%d bytes.\033[0m\n",pktNo,hdr->len,hdr->caplen);
        /* 解析数据帧*/
        ethdump_parseFrame(buff);
    }
    //流表统计
    struct streamHeader *st;
    long long streamNum=0;
    struct in_addr sip,dip;
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        if (st->num>0) {
            while (st != nullptr) {
                sip.s_addr=st->sip.ip32;
                dip.s_addr=st->dip.ip32;
                printf("%lld:hash %x, \033[1;32;40m%s\033[0m:%d",++streamNum,st->hash,inet_ntoa(sip),ntohs(st->sport));
                printf(" -> \033[1;32;40m%s\033[0m:%d,pkt number(%d).\n",inet_ntoa(dip),ntohs(st->dport),st->pktNumber);
                //
                for (int j=0;j<st->pktNumber;j++)
                    printf("%d ",st->pktInfo[j]);
                printf("\n");
                //
                st=st->next;
            }
        }
    }
    //plotting data
    plot_init(1024,1024);
    //
    Uint8 color=1;
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        if (st->num>0) {
            while (st != nullptr) {
                if (st->pktNumber<500) { st=st->next; continue; }
                sip.s_addr=st->sip.ip32;
                dip.s_addr=st->dip.ip32;
                plot_color(color++%7+1);
                //printf("%lld:hash %x, \033[1;32;40m%s\033[0m:%d",++streamNum,st->hash,inet_ntoa(sip),ntohs(st->sport));
                //printf(" -> \033[1;32;40m%s\033[0m:%d,pkt number(%d).\n",inet_ntoa(dip),ntohs(st->dport),st->pktNumber);
                int dy;
                for (int j=0;j<st->pktNumber;j++) {
                    dy = st->pktInfo[j]/10;
                    if (dy>0) {
                        //dy = 32-__builtin_clz(dy);
                        plot_dot(j,dy);
                    }
                    else if (dy<0) {
                        //dy = __builtin_clz(-dy)-32;
                        plot_dot(j,dy);
                    }
                    else
                        plot_dot(j,0);
                }
                st=st->next;
            }
        }
    }
    plot_show();
    //plot_delay(30);
    pause();
    plot_close();

    /*关闭文件，清理内存 */
    fclose(fd);
    free(g_pBuff);
    //
    struct streamHeader *last;
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        st=st->next;
        while (st != nullptr) {
            last=st;
            st=st->next;
            free(last);
        }
    }
    //
    return 0;
}

