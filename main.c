#include "main.h"
#include "plot.h"
#include "dns.h"

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

/* 解析ICMP数据包头 */
static int ethdump_parseIcmpHead(const struct icmphdr *pstIcmpHead,void *ipHEAD,bool ipV6)
{
    if (nullptr == pstIcmpHead) {
        return -1;
    }
    const struct ip *pstIpHead;
    union ipaddr *sip,*dip;

    const struct ipv6hdr *pstIpv6Head;
    const struct in6_addr *sip6,*dip6;

    char strSip[INET6_ADDRSTRLEN],strDip[INET6_ADDRSTRLEN];

    if (ipV6) {
        pstIpv6Head=(struct ipv6hdr *)ipHEAD;
        sip6=&pstIpv6Head->saddr;
        dip6=&pstIpv6Head->daddr;
        inet_ntop(AF_INET6,sip6, strSip, sizeof(strSip));
        inet_ntop(AF_INET6,dip6, strDip, sizeof(strDip));
    } else {
        pstIpHead=(struct ip *)ipHEAD;
        sip=(union ipaddr *)&(pstIpHead->ip_src);
        dip=(union ipaddr *)&(pstIpHead->ip_dst);
        inet_ntop(AF_INET,sip, strSip, sizeof(strSip));
        inet_ntop(AF_INET,dip, strDip, sizeof(strDip));
    }
    printf("ICMP:%s -> %s\n",strSip,strDip);
    printf("Type=[%d]%s, ", pstIcmpHead->type,(pstIcmpHead->type==8?"Echo Request":(pstIcmpHead->type==0?"Echo Reply":"")));
    printf("Code=[%d]\n", pstIcmpHead->code);
    g_pktdropICMP++;
    return 0;
}

/* 解析UDP数据包头 */
static int parseUdpHead(const struct udphdr *pstUdpHead,void *ipHEAD,bool ipV6)
{
    if (nullptr == pstUdpHead) {
        return -1;
    }
    const struct ip *pstIpHead;
    union ipaddr *sip,*dip;

    const struct ipv6hdr *pstIpv6Head;
    const struct in6_addr *sip6,*dip6;

    char strSip[INET6_ADDRSTRLEN],strDip[INET6_ADDRSTRLEN];
    u_int16 iplen;

    if (ipV6) {
        pstIpv6Head=(struct ipv6hdr *)ipHEAD;
        sip6=&pstIpv6Head->saddr;
        dip6=&pstIpv6Head->daddr;
        inet_ntop(AF_INET6,sip6, strSip, sizeof(strSip));
        inet_ntop(AF_INET6,dip6, strDip, sizeof(strDip));
        iplen=ntohs(pstIpv6Head->payload_len)+40; //only for UDP over IPv6, no extend IPv6 header
    } else {
        pstIpHead=(struct ip *)ipHEAD;
        sip=(union ipaddr *)&(pstIpHead->ip_src);
        dip=(union ipaddr *)&(pstIpHead->ip_dst);
        inet_ntop(AF_INET,sip, strSip, sizeof(strSip));
        inet_ntop(AF_INET,dip, strDip, sizeof(strDip));
        iplen=ntohs(pstIpHead->ip_len);
    }
    struct pcap_pkthdr *hdr=(struct pcap_pkthdr *)g_pBuff;
    // printf("UDP-Pkt:SPort=[%d] DPort=[%d]\n", ntohs(pstUdpHead->uh_sport), ntohs(pstUdpHead->uh_dport));
    // parsing DNS
    if (g_cfg.collectDNS && ntohs(pstUdpHead->uh_sport)==53) {
        //if (g_pktno==1048)
            printf("pktNo:%lld\n",g_pktno);
        char *ph=(char *)(pstUdpHead+1); //-> DNS
        //printf("Pktno:%lld",g_pktno);
        dns_parse_response(ph,strSip,strDip,&hdr->ts);
    }
    //流表处理
    bool bDownStream=false; //上行流还是下行流
    //计算hash，即流表索引
    u_int16 hash=0;
    if (ipV6) {
        for (int i=0;i<8;i++)
            hash^=sip6->__in6_u.__u6_addr16[i];
        for (int i=0;i<8;i++)
            hash^=dip6->__in6_u.__u6_addr16[i];
        hash^=pstUdpHead->uh_sport^pstUdpHead->uh_dport;
    } else {
        hash=sip->ip16[0]^sip->ip16[1]^dip->ip16[0]^dip->ip16[1]^pstUdpHead->uh_sport^pstUdpHead->uh_dport;
    }
    struct streamHeader *st=g_streamHdr+hash;
    if (st->num==0) {
        //新hash值，直接建新流
        memset(st,0,sizeof(struct streamHeader));
        st->num=1; //该表项包含多少个流
        st->hash=hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
        if (ntohs(pstUdpHead->uh_dport)<1024 && ntohs(pstUdpHead->uh_sport)>=1024)
            bDownStream=false;
        else if (ntohs(pstUdpHead->uh_sport)<1024 && ntohs(pstUdpHead->uh_dport)>=1024)
            bDownStream=true;
        else if (ntohs(pstUdpHead->uh_dport)<10000 && ntohs(pstUdpHead->uh_sport)>=10000)
            bDownStream=false;
        else if (ntohs(pstUdpHead->uh_sport)<10000 && ntohs(pstUdpHead->uh_dport)>=10000)
            bDownStream=true;
        if (bDownStream) {
            if (ipV6) {
                st->sip6=*dip6;
                st->dip6=*sip6;
            } else {
                st->sip=*dip;
                st->dip=*sip;
            }
            strcpy(st->sipstr,strDip);
            strcpy(st->dipstr,strSip);
            st->sport=pstUdpHead->uh_dport;
            st->dport=pstUdpHead->uh_sport;
        }else {
            if (ipV6) {
                st->sip6=*sip6;
                st->dip6=*dip6;
            } else {
                st->sip=*sip;
                st->dip=*dip;
            }
            strcpy(st->sipstr,strSip);
            strcpy(st->dipstr,strDip);
            st->sport=pstUdpHead->uh_sport;
            st->dport=pstUdpHead->uh_dport;
        }
        st->ipv=(ipV6?6:4);
        st->protocol=IPPROTO_UDP;
        st->next=nullptr; //hash碰撞后的流表项；
        st->ts=hdr->ts;
        st->pktNumber=0;//收到的包数
        st->pktInfoSize=0;//包长序列当前容量，初始为0
        st->pktInfo=nullptr; //保存包长序列，初始大小PKTINFO_SIZE，倍增法扩容
    }else {
        //hash已存在，查找是否已存在旧流
        int num=st->num;
        if (ipV6) {
            while (st!=nullptr) {
                if (ip6e(&st->sip6,sip6) && ip6e(&st->dip6,dip6) && st->sport==pstUdpHead->uh_sport && st->dport==pstUdpHead->uh_dport && st->protocol==IPPROTO_UDP) {
                    bDownStream=false;
                    break;
                }
                if (ip6e(&st->sip6,dip6) && ip6e(&st->dip6,sip6) && st->sport==pstUdpHead->uh_dport && st->dport==pstUdpHead->uh_sport && st->protocol==IPPROTO_UDP) {
                    bDownStream=true;
                    break;
                }
                st=st->next;
            }
        }
        else {
            while (st!=nullptr) {
                if (st->sip.ip32==sip->ip32 && st->dip.ip32==dip->ip32 && st->sport==pstUdpHead->uh_sport && st->dport==pstUdpHead->uh_dport && st->protocol==IPPROTO_UDP) {
                    bDownStream=false;
                    break;
                }
                if (st->sip.ip32==dip->ip32 && st->dip.ip32==sip->ip32 && st->sport==pstUdpHead->uh_dport && st->dport==pstUdpHead->uh_sport && st->protocol==IPPROTO_UDP) {
                    bDownStream=true;
                    break;
                }
                st=st->next;
            }
        }
        if (st==nullptr) {
            //新流,插入到最前面（假设新建的流访问频率高，老流访问频率低）
            st=malloc(sizeof(struct streamHeader));
            if (st==nullptr) {
                perror("malloc new streamHeader");
                return -1;
            }
            memset(st,0,sizeof(struct streamHeader));
            st->next=(g_streamHdr+hash)->next;
            (g_streamHdr+hash)->next=st;
            st->num=num+1; //该表项包含多少个流
            st->hash=hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
            if (ntohs(pstUdpHead->uh_dport)<1024 && ntohs(pstUdpHead->uh_sport)>=1024)
                bDownStream=false;
            else if (ntohs(pstUdpHead->uh_sport)<1024 && ntohs(pstUdpHead->uh_dport)>=1024)
                bDownStream=true;
            else if (ntohs(pstUdpHead->uh_dport)<10000 && ntohs(pstUdpHead->uh_sport)>=10000)
                bDownStream=false;
            else if (ntohs(pstUdpHead->uh_sport)<10000 && ntohs(pstUdpHead->uh_dport)>=10000)
                bDownStream=true;
            if (bDownStream) {
                if (ipV6) {
                    st->sip6=*dip6;
                    st->dip6=*sip6;
                }else {
                    st->sip=*dip;
                    st->dip=*sip;
                }
                strcpy(st->sipstr,strDip);
                strcpy(st->dipstr,strSip);
                st->sport=pstUdpHead->uh_dport;
                st->dport=pstUdpHead->uh_sport;
            }else {
                if (ipV6) {
                    st->sip6=*sip6;
                    st->dip6=*dip6;
                }else {
                    st->sip=*sip;
                    st->dip=*dip;
                }
                strcpy(st->sipstr,strSip);
                strcpy(st->dipstr,strDip);
                st->sport=pstUdpHead->uh_sport;
                st->dport=pstUdpHead->uh_dport;
            }
            st->ipv=(ipV6?6:4);
            st->protocol=IPPROTO_UDP;
            st->next=nullptr; //hash碰撞后的流表项；
            st->ts=hdr->ts;
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
        st->pktInfo=malloc(sizeof(struct pktinfo_t)*PKTINFO_SIZE);
        if (st->pktInfo==nullptr) {
            perror("malloc new pktInfo");
            return -1;
        }
        memset(st->pktInfo,0,sizeof(struct pktinfo_t)*PKTINFO_SIZE);
        st->pktInfoSize=PKTINFO_SIZE;
    }else if (st->pktNumber==st->pktInfoSize) {
        //包长序列容量已满，扩增容量
        st->pktInfo=realloc(st->pktInfo,sizeof(struct pktinfo_t)*(st->pktInfoSize+PKTINFO_SIZE));
        if (st->pktInfo==nullptr) {
            perror("realloc pktInfo");
            return -1;
        }
        st->pktInfoSize+=PKTINFO_SIZE;
    }
    //流信息更新
    st->te=hdr->ts; //尾包捕获时间
    if (bDownStream) {
        st->down_pktNumber++;
        st->downstreamlen+=hdr->len;
        st->pktInfo[st->pktNumber].pktlen=-hdr->len;
    }
    else {
        st->up_pktNumber++;
        st->upstreamlen+=hdr->len;
        st->pktInfo[st->pktNumber].pktlen=hdr->len;
    }
    st->streamlen+=hdr->len;
    st->pktInfo[st->pktNumber].ts=hdr->ts;
    st->pktInfo[st->pktNumber++].pcappktno=g_pktno;
    return 0;
}

/* 解析TCP数据包头 */
static int parseTcpHead(const struct tcphdr *pstTcpHead,void *ipHEAD,bool ipV6)
{
    if (nullptr == pstTcpHead) {
        return -1;
    }
    const struct ip *pstIpHead;
    union ipaddr *sip,*dip;

    const struct ipv6hdr *pstIpv6Head;
    const struct in6_addr *sip6,*dip6;

    char strSip[INET6_ADDRSTRLEN],strDip[INET6_ADDRSTRLEN];
    u_int16 iplen;

    if (ipV6) {
        pstIpv6Head=(struct ipv6hdr *)ipHEAD;
        sip6=&pstIpv6Head->saddr;
        dip6=&pstIpv6Head->daddr;
        inet_ntop(AF_INET6,sip6, strSip, sizeof(strSip));
        inet_ntop(AF_INET6,dip6, strDip, sizeof(strDip));
        iplen=ntohs(pstIpv6Head->payload_len)+40; //only for TCP over IPv6, no extend IPv6 header
    } else {
        pstIpHead=(struct ip *)ipHEAD;
        sip=(union ipaddr *)&(pstIpHead->ip_src);
        dip=(union ipaddr *)&(pstIpHead->ip_dst);
        inet_ntop(AF_INET,sip, strSip, sizeof(strSip));
        inet_ntop(AF_INET,dip, strDip, sizeof(strDip));
        iplen=ntohs(pstIpHead->ip_len);
    }
    //printf("TCP-Pkt:");
    //printfSPort=[%d] ", ntohs(pstTcpHead->th_sport));
    //printf("DPort=[%d]\n", ntohs(pstTcpHead->th_dport));
    //流表处理
    struct pcap_pkthdr *hdr=(struct pcap_pkthdr *)g_pBuff;
    //parsing TLS head
    u_int32 tcppayloadlen;
    if (ipV6)
        tcppayloadlen=ntohs(pstIpv6Head->payload_len)-pstTcpHead->th_off*4;
    else
        tcppayloadlen=ntohs(pstIpHead->ip_len)-pstIpHead->ip_hl*4-pstTcpHead->th_off*4;
    char *pstTLS=(char *)pstTcpHead+pstTcpHead->th_off*4;
    char *pstEND=(char *)(hdr+1)+hdr->caplen;
    bool foundClientHello=false;
    bool foundSNI=false;
    int tlsVersion=-1;
    int CHlen=0;
    u_int16 CipherSuiteLen=0;
    char CipherSuite[128];
    if (pstTLS[0]==0x16) {// TLS handshake
        tlsVersion=ntohs(*(u_int16 *)(pstTLS+1));
        CHlen=ntohs(*(u_int16 *)(pstTLS+3));
        if (tlsVersion>=0x300 && tlsVersion<=0x304 && CHlen==tcppayloadlen-5 && *(pstTLS+5)==1) {
            foundClientHello=true;
            char *pch=(char *)pstTLS+5;
            pch+=38; // ->Session ID length: 1 byte
            pch+=(u_int8)(*pch)+1; // ->CipherSuite length: 2
            CipherSuiteLen=ntohs(*(u_int16 *)(pch));
            pch+=2;
            for (int i=0;i<min(CipherSuiteLen,128);i++) {
                CipherSuite[i]=pch[i];
            }
            pch+=CipherSuiteLen; //->Compression Methods length: 1 byte
            pch+=(u_int8)(*pch)+1; // ->Extension length: 2bytes
            u_int16 extlen=ntohs(*(u_int16 *)pch); //externsions length
            pch+=2; //->Extensions
            char *pext=pch;
            while (pext<pch+extlen && pext<pstEND) {
                u_int16 type=ntohs(*(u_int16 *)pext);
                u_int16 len=ntohs(*(u_int16 *)(pext+2));
                if (type==0) {
                    // server name - SNI
                    pext+=4; // -> server name list length: 2 bytes
                    pext+=2; // -> server name type: 1 byte
                    if (*pext==0) {
                        // host_name
                        foundSNI=true;
                        pext++; // -> server name length: 2 bytes
                        u_int16 SNIlen=ntohs(*(u_int16 *)pext);
                        pext+=2;// -> SNI
                        if (SNIlen>120) {
                            //truncate
                            strncpy(g_SNI,pext,120);
                            g_SNI[120]=0;
                        }else {
                            strcpy(g_SNI,pext);
                            g_SNI[SNIlen]=0;
                        }
                        break;
                    }
                }
                pext+=len+4;
            }
        }
    }
    //上行流还是下行流
    bool bDownStream=false;
    //计算hash，即流表索引
    u_int16 hash=0;
    if (ipV6) {
        for (int i=0;i<8;i++)
            hash^=sip6->__in6_u.__u6_addr16[i];
        for (int i=0;i<8;i++)
            hash^=dip6->__in6_u.__u6_addr16[i];
        hash^=pstTcpHead->th_sport^pstTcpHead->th_dport;
    } else {
        hash=sip->ip16[0]^sip->ip16[1]^dip->ip16[0]^dip->ip16[1]^pstTcpHead->th_sport^pstTcpHead->th_dport;
    }
    struct streamHeader *st=g_streamHdr+hash;
    if (st->num==0) {
        //新hash值，直接建新流
        memset(st,0,sizeof(struct streamHeader));
        st->num=1; //该表项包含多少个流
        st->hash=hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
        if (pstTcpHead->syn && pstTcpHead->ack)
            bDownStream=true;
        else if (pstTcpHead->syn && !pstTcpHead->ack)
            bDownStream=false;
        else if (ntohs(pstTcpHead->th_dport)<1024 && ntohs(pstTcpHead->th_sport)>=1024)
            bDownStream=false;
        else if (ntohs(pstTcpHead->th_sport)<1024 && ntohs(pstTcpHead->th_dport)>=1024)
            bDownStream=true;
        else if (ntohs(pstTcpHead->th_dport)<10000 && ntohs(pstTcpHead->th_sport)>=10000)
            bDownStream=false;
        else if (ntohs(pstTcpHead->th_sport)<10000 && ntohs(pstTcpHead->th_dport)>=10000)
            bDownStream=true;
        if (bDownStream) {
            if (ipV6) {
                st->sip6=*dip6;
                st->dip6=*sip6;
            } else {
                st->sip=*dip;
                st->dip=*sip;
            }
            strcpy(st->sipstr,strDip);
            strcpy(st->dipstr,strSip);
            st->sport=pstTcpHead->th_dport;
            st->dport=pstTcpHead->th_sport;
        }else {
            if (ipV6) {
                st->sip6=*sip6;
                st->dip6=*dip6;
            } else {
                st->sip=*sip;
                st->dip=*dip;
            }
            strcpy(st->sipstr,strSip);
            strcpy(st->dipstr,strDip);
            st->sport=pstTcpHead->th_sport;
            st->dport=pstTcpHead->th_dport;
        }
        st->ipv=(ipV6?6:4);
        st->protocol=IPPROTO_TCP;
        st->next=nullptr; //hash碰撞后的流表项；
        st->ts=hdr->ts;
        st->pktNumber=0;//收到的包数
        st->pktInfoSize=0;//包长序列当前容量，初始为0
        st->pktInfo=nullptr; //保存包长序列，初始大小PKTINFO_SIZE，倍增法扩容
    }else {
        //hash已存在，查找是否已存在旧流
        int num=st->num;
        if (ipV6) {
            while (st!=nullptr) {
                if (ip6e(&st->sip6,sip6) && ip6e(&st->dip6,dip6) && st->sport==pstTcpHead->th_sport && st->dport==pstTcpHead->th_dport && st->protocol==IPPROTO_TCP) {
                    bDownStream=false;
                    break;
                }
                if (ip6e(&st->sip6,dip6) && ip6e(&st->dip6,sip6) && st->sport==pstTcpHead->th_dport && st->dport==pstTcpHead->th_sport && st->protocol==IPPROTO_TCP) {
                    bDownStream=true;
                    break;
                }
                st=st->next;
            }
        }
        else {
            while (st!=nullptr) {
                if (st->sip.ip32==sip->ip32 && st->dip.ip32==dip->ip32 && st->sport==pstTcpHead->th_sport && st->dport==pstTcpHead->th_dport && st->protocol==IPPROTO_TCP) {
                    bDownStream=false;
                    break;
                }
                if (st->sip.ip32==dip->ip32 && st->dip.ip32==sip->ip32 && st->sport==pstTcpHead->th_dport && st->dport==pstTcpHead->th_sport && st->protocol==IPPROTO_TCP) {
                    bDownStream=true;
                    break;
                }
                st=st->next;
            }
        }
        if (st==nullptr) {
            //新流,插入到最前面（假设新建的流访问频率高，老流访问频率低）
            st=malloc(sizeof(struct streamHeader));
            if (st==nullptr) {
                perror("malloc new streamHeader");
                return -1;
            }
            memset(st,0,sizeof(struct streamHeader));
            st->next=(g_streamHdr+hash)->next;
            (g_streamHdr+hash)->next=st;
            st->num=num+1; //该表项包含多少个流
            st->hash=hash; //sip(H)^sip(L)^dip(H)^dip(L)^sport^dport
            if (pstTcpHead->syn && pstTcpHead->ack)
                bDownStream=true;
            else if (pstTcpHead->syn && !pstTcpHead->ack)
                bDownStream=false;
            else if (ntohs(pstTcpHead->th_dport)<1024 && ntohs(pstTcpHead->th_sport)>=1024)
                bDownStream=false;
            else if (ntohs(pstTcpHead->th_sport)<1024 && ntohs(pstTcpHead->th_dport)>=1024)
                bDownStream=true;
            else if (ntohs(pstTcpHead->th_dport)<10000 && ntohs(pstTcpHead->th_sport)>=10000)
                bDownStream=false;
            else if (ntohs(pstTcpHead->th_sport)<10000 && ntohs(pstTcpHead->th_dport)>=10000)
                bDownStream=true;
            if (bDownStream) {
                if (ipV6) {
                    st->sip6=*dip6;
                    st->dip6=*sip6;
                } else {
                    st->sip=*dip;
                    st->dip=*sip;
                }
                strcpy(st->sipstr,strDip);
                strcpy(st->dipstr,strSip);
                st->sport=pstTcpHead->th_dport;
                st->dport=pstTcpHead->th_sport;
            }else {
                if (ipV6) {
                    st->sip6=*sip6;
                    st->dip6=*dip6;
                } else {
                    st->sip=*sip;
                    st->dip=*dip;
                }
                strcpy(st->sipstr,strSip);
                strcpy(st->dipstr,strDip);
                st->sport=pstTcpHead->th_sport;
                st->dport=pstTcpHead->th_dport;
            }
            st->ipv=(ipV6?6:4);
            st->protocol=IPPROTO_TCP;
            st->next=nullptr; //hash碰撞后的流表项；
            st->ts=hdr->ts;
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
        st->pktInfo=malloc(sizeof(struct pktinfo_t)*PKTINFO_SIZE);
        if (st->pktInfo==nullptr) {
            perror("malloc new pktInfo");
            return -1;
        }
        memset(st->pktInfo,0,sizeof(struct pktinfo_t)*PKTINFO_SIZE);
        st->pktInfoSize=PKTINFO_SIZE;
    }else if (st->pktNumber==st->pktInfoSize) {
        //包长序列容量已满，扩增容量
        st->pktInfo=realloc(st->pktInfo,sizeof(struct pktinfo_t)*(st->pktInfoSize+PKTINFO_SIZE));
        if (st->pktInfo==nullptr) {
            perror("realloc pktInfo");
            return -1;
        }
        st->pktInfoSize+=PKTINFO_SIZE;
    }
    //流信息更新
    st->te=hdr->ts; //尾包捕获时间
    getTLSV(st->tlsv,tlsVersion);
    if (CipherSuiteLen>0) {
        st->CipherSuiteLen=CipherSuiteLen;
        for (int i=0;i<min(CipherSuiteLen,128);i++) {
            st->CipherSuite[i]=CipherSuite[i];
        }
    }
    if (foundSNI) {
        strcpy(st->SNI,g_SNI);
    }
    if (bDownStream) {
        st->down_pktNumber++;
        st->downstreamlen+=hdr->len;
        st->pktInfo[st->pktNumber].pktlen=-hdr->len;
    }
    else {
        st->up_pktNumber++;
        st->upstreamlen+=hdr->len;
        st->pktInfo[st->pktNumber].pktlen=hdr->len;
    }
    st->streamlen+=hdr->len;
    st->pktInfo[st->pktNumber].ts=hdr->ts;
    st->pktInfo[st->pktNumber].pcappktno=g_pktno;
    st->pktNumber++;
    return 0;
}

/* 解析IPv6数据包头 */
static int ethdump_parseIpv6Head(const struct ipv6hdr *pstIpv6Head)
{
    int iRet=-1;
    if (nullptr == pstIpv6Head) {
        return -1;
    }
    char strSip[INET6_ADDRSTRLEN];
    char strDip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6,&pstIpv6Head->saddr, strSip, sizeof(strSip));
    inet_ntop(AF_INET6,&pstIpv6Head->daddr, strDip, sizeof(strDip));
    //printf("IPv6-Pkt:");
    /*
    uint16_t *sa=(uint16_t *)&(pstIpv6Head->saddr.__in6_u.__u6_addr16);
    uint16_t *da=(uint16_t *)&(pstIpv6Head->daddr.__in6_u.__u6_addr16);
    printf("SAddr=[%x:%x:%x:%x:%x:%x:%x:%x] ", ntohs(sa[0]), ntohs(sa[1]), ntohs(sa[2]),ntohs(sa[3]), ntohs(sa[4]), ntohs(sa[5]), ntohs(sa[6]), ntohs(sa[7]));
    printf("DAddr=[%x:%x:%x:%x:%x:%x:%x:%x]\n",ntohs(da[0]), ntohs(da[1]), ntohs(da[2]),ntohs(da[3]), ntohs(da[4]), ntohs(da[5]), ntohs(da[6]), ntohs(da[7]));
    */
    //printf("(%d)%s:%d -> %s:%d\n",pstIpv6Head->nexthdr,strSip,*pstIpv6Head->flow_lbl,strDip,*pstIpv6Head->flow_lbl);
    switch (pstIpv6Head->nexthdr) {
        case IPPROTO_UDP:
            struct udphdr *pstUdpHdr = (struct udphdr *)(pstIpv6Head+1);
            iRet = parseUdpHead(pstUdpHdr,(void *)pstIpv6Head,true);
            break;
        case IPPROTO_TCP:
            struct tcphdr *pstTcpHdr = (struct tcphdr *)(pstIpv6Head+1);
            iRet = parseTcpHead(pstTcpHdr,(void *)pstIpv6Head,true);
            break;
        case IPPROTO_ICMP: //icmpv4
            struct icmphdr *pstIcmpHdr = (struct icmphdr *)(pstIpv6Head+1);
            iRet = ethdump_parseIcmpHead(pstIcmpHdr,(void *)pstIpv6Head,true);
            break;
        default:
            g_pktdropIPv6++;
            break;
    }
    return iRet;
}

/* 解析IP数据包头 */
static int parseIpHead(const struct ip *pstIpHead)
{
    int iRet=-1;
    struct protoent *pstIpProto = nullptr;
    if (nullptr == pstIpHead) {
        return -1;
    }

    /* 协议类型、源IP地址、目的IP地址 */
    pstIpProto = getprotobynumber(pstIpHead->ip_p);
    /*
    if(nullptr != pstIpProto) {
        printf("IP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, pstIpProto->p_name);
    }
    else {
        printf("IP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, "None");
    }
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&pstIpHead->ip_src, str, sizeof(str));
    printf("SAddr=[%s] ", str);
    inet_ntop(AF_INET,&pstIpHead->ip_dst, str, sizeof(str));
    printf("DAddr=[%s]\n", str);
    */
    switch (pstIpHead->ip_p) {
        case IPPROTO_UDP:
            struct udphdr *pstUdpHdr = (struct udphdr *)(pstIpHead+1);
            iRet = parseUdpHead(pstUdpHdr,(void *)pstIpHead,false);
            break;
        case IPPROTO_TCP:
            struct tcphdr *pstTcpHdr = (struct tcphdr *)(pstIpHead+1);
            iRet = parseTcpHead(pstTcpHdr,(void *)pstIpHead,false);
            break;
        case IPPROTO_ICMP:
            struct icmphdr *pstIcmpHdr = (struct icmphdr *)(pstIpHead+1);
            iRet = ethdump_parseIcmpHead(pstIcmpHdr,(void *)pstIpHead,false);
            break;
        default:
            g_pktdropIPv4++;
            break;
    }
    return iRet;
}

/* 解析Ethernet帧首部 */
static int parseEthHead(const struct ether_header *pstEthHead)
{
    int iRet = -1;
    unsigned short usEthPktType;
    if (nullptr == pstEthHead) {
        return -1;
    }
    /* 协议类型、源MAC、目的MAC */
    //
    usEthPktType = ntohs(pstEthHead->ether_type);
    //printf("Eth-Pkt-Type:0x%04x(%s) ", usEthPktType, ethdump_getProName(usEthPktType));
    //ethdump_showMac(0, pstEthHead->ether_shost);
    //ethdump_showMac(1, pstEthHead->ether_dhost);
    //printf("\n");
    //
    char *pdu=(char *)(pstEthHead+1); // -> VLAN tag
    if (usEthPktType==ETHERTYPE_VLAN) {
        //parsing VLAN tag
        pdu+=2;
        usEthPktType = ntohs(*(u_int16 *)pdu);
        pdu+=2;
    }
    switch (usEthPktType) {
        case ETHERTYPE_IP:
            /* IP数据包类型 */
            struct ip *pstIpHead = nullptr;
            pstIpHead  = (struct ip *)pdu;
            iRet = parseIpHead(pstIpHead);
            break;
        case ETHERTYPE_IPV6:
            /* IPv6数据包类型 */
            struct ipv6hdr *pstIpv6Head = nullptr;
            pstIpv6Head  = (struct ipv6hdr *)pdu;
            iRet = ethdump_parseIpv6Head(pstIpv6Head);
            break;
        default:
            g_pktdrop++;
            break;
    }
    return iRet;
}

/* 数据帧解析函数 */
static int parseFrame(const char *pcFrameData)
{
    int iRet = -1;
    struct ether_header *pstEthHead = nullptr;

    /* Ethnet帧头解析 */
    pstEthHead = (struct ether_header*)pcFrameData;
    if (g_cfg.vxlan) {
        char * pdu=(char *)(pstEthHead+1); //-> outer ip hdr
        pdu=(char *)((struct ip *)pdu+1); //-> outer udp
        pdu=(char *)((struct udphdr *)pdu+1); //->vxlan tag, 8 bytes
        pdu+=8; //->inner ethernet header
        iRet = parseEthHead((struct ether_header*)pdu);
    }else {
        iRet = parseEthHead(pstEthHead);
    }
    return iRet;
}

// before exit;
void freeBuff() {
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        struct streamHeader *st = g_streamHdr + i;
        st=st->next;
        while (st != nullptr) {
            struct streamHeader *last = st;
            st=st->next;
            free(last);
        }
    }
    while (g_dns_list != NULL) {
        g_dns_tail=g_dns_list;
        g_dns_list=g_dns_list->next;
        if (g_dns_tail->dn) free(g_dns_tail->dn);
        if (g_dns_tail->rr) free(g_dns_tail->rr);
        if (g_dns_tail->clt) free(g_dns_tail->clt);
        if (g_dns_tail->ns) free(g_dns_tail->ns);
        free(g_dns_tail);
    }
    g_dns_tail=nullptr;
    g_dns_list=nullptr;
}
//
int my_query(const char *query) {
    const int res=mysql_query(g_mysql,query);
    if (res!=0) {
        error2("Mysql",mysql_error(g_mysql),query);
    }
    return res;
}
int process_args(int argc, char *argv[]) {
    // args parsing
    //g_cfg.vxlan=false;
    if (argc>1) {
        strcpy(g_szDumpFileName,argv[1]); //tcpdump file name ,e.g. "dump.pcap"
    }
    if (argc>2) {
        sprintf(g_cfg.mysqlStreamsTbl,"%s_streams",argv[2]);
        sprintf(g_cfg.mysqlPktInfoTbl,"%s_pktinfo",argv[2]);
        sprintf(g_cfg.mysqlDNSTbl,"%s_dns",argv[2]);
    }
    if (argc>3) {
        if (strcmp(argv[3],"vxlan")==0) {
            g_cfg.vxlan=true;
        } else
            g_cfg.vxlan=false;
    }
    if (argc==1) {
        printf("\nUsage: %s [<pcap file name> [<mysql table name prefix> [vxlan]]]\n",argv[0]);
        printf("       <pcap file name> - default: dump.pcap\n");
        printf("       <mysql table name prefix> - default: ''\n\n");
    }
    return 0;
}
/* Main */
int main(int argc, char *argv[]) {
    int iRet = -1;
    FILE *fd   = nullptr;
    //read config file
    readconfig();
    //初始化流表
    memset(g_streamHdr,0,sizeof(struct streamHeader)*STREAM_TABLE_SIZE);
    //处理命令行参数
    if (process_args(argc,argv)!=0) {
        return -1;
    }
    /* 打开 pcap文件 */
    fd = fopen(g_szDumpFileName,"rb");
    if(!fd) {
        perror("[Error]Cannot open pcap file ");
        return -1;
    }
    //处理pcap文件头
    unsigned long int n = fread(&g_pcapFileHeader, sizeof(g_pcapFileHeader), 1, fd);
    if (n>0) {
        printf("magic: %x, ",g_pcapFileHeader.magic);
        printf("major: %x, ",g_pcapFileHeader.version_major);
        printf("minor: %x, ",g_pcapFileHeader.version_minor);
        printf("thiszone: %x, ",g_pcapFileHeader.thiszone);
        printf("sigfigs: %x\n",g_pcapFileHeader.sigfigs);
        printf("snaplen: %x\n",g_pcapFileHeader.snaplen);
        printf("linktype: %x(%s)\n\n",g_pcapFileHeader.linktype,(g_pcapFileHeader.linktype==1?"Ethernet":""));
    }else{
        perror("[Error]Cannot read pcap file ");
        fclose(fd);
        return 0;
    }
    /* 处理数据包 */
    g_pktno=0;
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
            printf("%lld packets processed.\n",g_pktno);
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
        g_pktno++;
        //printf("\033[1;31;40m>>> Packet %lld: len=%d bytes, cap=%d bytes.\033[0m\n",pktNo,hdr->len,hdr->caplen);
        /* 解析数据帧*/
        parseFrame(buff);
    }
    printf("%llu packets in pcap file, %lld packets dropped, %lld packets could be write to DB.",g_pktno,g_pktdrop,g_pktno-g_pktdrop);
    //流表统计
    //streams_stats();
    //plotting data
    //plot_data();
    /*关闭文件，清理文件处理缓冲区内存 */
    fclose(fd);
    free(g_pBuff);
    // write to mysql
    // connect mysql
    g_mysql=mysql_init(NULL);
    if (g_mysql == NULL) {
        perror("[Error]Cannot init mysql");
        freeBuff();
        return 0;
    }
    if( mysql_real_connect(g_mysql,g_cfg.mysqlIPString,g_cfg.mysqlUserName,g_cfg.mysqlPassword,NULL,g_cfg.mysqlPort,NULL,0)==NULL){
        perror("[Error]Cannot connect to mysql");
        freeBuff();
        mysql_close(g_mysql);
        return 0;
    }
    mysql_set_character_set(g_mysql, "utf8");
    sprintf(g_sql,"create database if not exists %s;",g_cfg.mysqlDB);
    my_query(g_sql);
    mysql_select_db(g_mysql,g_cfg.mysqlDB);
    sprintf(g_sql,"drop table %s;",g_cfg.mysqlStreamsTbl);
    my_query(g_sql);
    //sprintf(g_sql,"create table if not exists %s(pcapname varchar(256),sid int unique key auto_increment,sip varchar(16), sport int, dip varchar(16), dport int, protocol int, pktnumber int,PRIMARY KEY (sip,sport,dip,dport,protocol));",g_cfg.mysqlStreamsTbl);
    sprintf(g_sql,"create table if not exists %s(",g_cfg.mysqlStreamsTbl);
    strcat(g_sql,"pcapname varchar(256),sid int unsigned unique key auto_increment,sip varchar(40), sport int unsigned, dip varchar(40), dport int unsigned, ipv tinyint unsigned, protocol int unsigned, ");
    strcat(g_sql,"ts_sec timestamp, ts_usec int unsigned, te_sec timestamp, te_usec int unsigned, upstreamlen int(8) unsigned, downstreamlen int(8) unsigned, up_pktnumber int unsigned, down_pktnumber int unsigned, sni varchar(128),tlsv varchar(6),");
    strcat(g_sql,"ciphersuitelen smallint unsigned, ciphersuite varchar(360),");
    strcat(g_sql,"PRIMARY KEY (sip,sport,dip,dport,protocol));");
    my_query(g_sql);
    // packet information table
    if (g_cfg.writePktInfo) {
        sprintf(g_sql,"drop table %s;",g_cfg.mysqlPktInfoTbl);
        my_query(g_sql);
        sprintf(g_sql,"create table if not exists %s(sid int unsigned,pid int unsigned, ts_sec timestamp, ts_usec int unsigned, pktlen int, pcappktno int unsigned, PRIMARY KEY(sid,pid));",g_cfg.mysqlPktInfoTbl);
        my_query(g_sql);
    }
    // DNS collection table
    if (g_cfg.collectDNS) {
        sprintf(g_sql,"drop table %s;",g_cfg.mysqlDNSTbl);
        my_query(g_sql);
        sprintf(g_sql,"create table if not exists %s(dn varchar(255), type varchar(8), rr varchar(255), clt varchar(40), ns varchar(40), ts_sec timestamp, ts_usec int unsigned, ttl int unsigned);",g_cfg.mysqlDNSTbl);
        my_query(g_sql);
        while (g_dns_list != NULL) {
            sprintf(g_sql,"insert into %s(dn,type,rr,clt,ns,ts_sec,ts_usec,ttl) values('%s','%s','%s','%s','%s',from_unixtime(%u),%u,%u); ",
                         g_cfg.mysqlDNSTbl,g_dns_list->dn,g_dns_list->type,g_dns_list->rr,g_dns_list->clt,g_dns_list->ns,(g_dns_list->ts.tv_sec==0?1:g_dns_list->ts.tv_sec),g_dns_list->ts.tv_usec,g_dns_list->ttl);
            my_query(g_sql);
            g_dns_list = g_dns_list->next;
        }
    }
    MYSQL_RES *res=nullptr;
    struct streamHeader *st;
    long long streamNum=0;
    unsigned char strT[360];
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        if (st->num>0) {
            while (st != nullptr) {
                printf("%lld:hash %x,(ipv%d:%d) \033[1;32;40m%s\033[0m:%d -> \033[1;32;40m%s\033[0m:%d,pkt number(%d),SNI:%s.\n",++streamNum,st->hash,st->ipv,st->protocol,st->sipstr,ntohs(st->sport),st->dipstr,ntohs(st->dport),st->pktNumber,st->SNI);
                //
                strcpy(strT,"");
                if (st->CipherSuiteLen>0) {
                    char * ps=strT;
                    for (int j=0;j<min(st->CipherSuiteLen,120);) {
                        unsigned char c=st->CipherSuite[j];
                        *ps++=HEX[c>>4];
                        *ps++=HEX[c&0xf];
                        j++;
                        if (j%2==0)
                            *ps++=',';
                    }
                    *--ps='\0';
                }
                sprintf(g_sql,"insert into %s(pcapname,sip,sport,dip,dport,ipv,protocol,ts_sec,ts_usec,te_sec,te_usec,upstreamlen,downstreamlen,up_pktnumber,down_pktnumber,sni,tlsv,ciphersuitelen,ciphersuite) values('%s','%s',%u,'%s',%u,%u,%u,from_unixtime(%u),%u,from_unixtime(%u),%u,%llu,%llu,%u,%u,'%s','%s',%u,'%s');",
                              g_cfg.mysqlStreamsTbl,g_szDumpFileName,st->sipstr,ntohs(st->sport),st->dipstr,ntohs(st->dport),st->ipv,st->protocol,st->ts.tv_sec+(st->ts.tv_sec==0?1:0),st->ts.tv_usec,st->te.tv_sec+(st->te.tv_sec==0?1:0),st->te.tv_usec,
                              st->upstreamlen,st->downstreamlen,st->up_pktNumber,st->down_pktNumber,st->SNI,st->tlsv,st->CipherSuiteLen>>1,strT);
                my_query(g_sql);
                if (g_cfg.writePktInfo) {
                    sprintf(g_sql,"select sid from %s where sip='%s' and sport=%u and dip='%s' and dport=%u and protocol=%u;",g_cfg.mysqlStreamsTbl,st->sipstr,ntohs(st->sport),st->dipstr,ntohs(st->dport),st->protocol);
                    my_query(g_sql);
                    res = mysql_store_result(g_mysql);
                    MYSQL_ROW row_data = mysql_fetch_row(res);
                    if (row_data!=nullptr) {
                        printf("sid: %s",row_data[0]);
                        for (int j=0;j<st->pktNumber;j++) {
                            sprintf(g_sql,"insert into %s(sid,pid,ts_sec,ts_usec,pktlen,pcappktno) values(%s,%u,from_unixtime(%u),%u,%d,%u); ",
                                         g_cfg.mysqlPktInfoTbl,row_data[0],j+1,st->pktInfo[j].ts.tv_sec+(st->pktInfo[j].ts.tv_sec==0?1:0),st->pktInfo[j].ts.tv_usec,st->pktInfo[j].pktlen,st->pktInfo[j].pcappktno);
                            my_query(g_sql);
                            if (j%100==0){
                                printf(".");
                                fflush(stdout);
                            }
                        }
                        printf("\n");
                    }else {
                        error1("SQL",g_sql);
                    }
                }
                st=st->next;
            }
        }
    }
    if (res)
        mysql_free_result(res);
    mysql_close(g_mysql);
    //
    freeBuff();
    long long t=g_pktdrop+g_pktdropIPv4+g_pktdropIPv6+g_pktdropICMP;
    printf("%llu packets in pcap file, %lld packets dropped(%lld ETH,%lld IPv4,%lld IPv6,%lld ICMP), %lld packets could be write to DB.\n",g_pktno,t,g_pktdrop,g_pktdropIPv4,g_pktdropIPv6,g_pktdropICMP,g_pktno-t);
    saveconfig();
    return 0;
}
