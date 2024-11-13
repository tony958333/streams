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

/* 解析ICMP数据包头 */
static int ethdump_parseIcmpHead(const struct icmphdr *pstIcmpHead,void *ipHEAD,bool ipV6)
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
static int ethdump_parseUdpHead(const struct udphdr *pstUdpHead,void *ipHEAD,bool ipV6)
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
        iplen=ntohs(pstIpv6Head->payload_len)+40; //only for TCP over IPv6, no extend IPv6 header
    } else {
        pstIpHead=(struct ip *)ipHEAD;
        sip=(union ipaddr *)&(pstIpHead->ip_src);
        dip=(union ipaddr *)&(pstIpHead->ip_dst);
        inet_ntop(AF_INET,sip, strSip, sizeof(strSip));
        inet_ntop(AF_INET,dip, strDip, sizeof(strDip));
        iplen=ntohs(pstIpHead->ip_len);
    }
    /*
    printf("UDP-Pkt:");
    printf("SPort=[%d] ", ntohs(pstUdpHead->uh_sport));
    printf("DPort=[%d]\n", ntohs(pstUdpHead->uh_dport));
    */
    //流表处理
    struct pcap_pkthdr *hdr=(struct pcap_pkthdr *)g_pBuff;
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
static int ethdump_parseTcpHead(const struct tcphdr *pstTcpHead,void *ipHEAD,bool ipV6)
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
    char *pstEND;
    if (ipV6)
        pstEND=(char *)pstIpv6Head+min(iplen,hdr->caplen-14);
    else
        pstEND=(char *)pstIpHead+min(ntohs(pstIpHead->ip_len),hdr->caplen-14);
    bool foundClientHello=false;
    bool foundSNI=false;
    int tlsVersion=-1;
    int CHlen=0;
    if (pstTLS[0]==0x16) {// TLS handshake
        tlsVersion=ntohs(*(u_int16 *)(pstTLS+1));
        CHlen=ntohs(*(u_int16 *)(pstTLS+3));
        if (tlsVersion>=0x300 && tlsVersion<=0x304 && CHlen==tcppayloadlen-5 && *(pstTLS+5)==1) {
            foundClientHello=true;
            char *pch=(char *)pstTLS+5;
            pch+=38; // Session ID length: 1 byte
            pch+=(u_int8)(*pch)+1; // CipherSuite length: 2 bytes
            pch+=ntohs(*(u_int16 *)(pch))+2; //Compression Methods length: 1 byte
            pch+=(u_int8)(*pch)+1; // Extension length: 2bytes
            u_int16 extlen=ntohs(*(u_int16 *)pch);
            pch+=2; //Extensions
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
                        u_int16 SNIlen=*(u_int16 *)pext;
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
    if (tlsVersion==0x300) strcpy(st->tlsv,"SSL3.0");
    if (tlsVersion==0x301) strcpy(st->tlsv,"TLS1.0");
    if (tlsVersion==0x302) strcpy(st->tlsv,"TLS1.1");
    if (tlsVersion==0x303) strcpy(st->tlsv,"TLS1.2");
    if (tlsVersion==0x304) strcpy(st->tlsv,"TLS1.3");
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
    printf("IPv6-Pkt:");
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
            iRet = ethdump_parseUdpHead(pstUdpHdr,(void *)pstIpv6Head,true);
            break;
        case IPPROTO_TCP:
            struct tcphdr *pstTcpHdr = (struct tcphdr *)(pstIpv6Head+1);
            iRet = ethdump_parseTcpHead(pstTcpHdr,(void *)pstIpv6Head,true);
            break;
        case IPPROTO_ICMP: //icmpv4
            struct icmphdr *pstIcmpHdr = (struct icmphdr *)(pstIpv6Head+1);
            iRet = ethdump_parseIcmpHead(pstIcmpHdr,(void *)pstIpv6Head,true);
            break;
        default:
            break;
    }
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
            iRet = ethdump_parseUdpHead(pstUdpHdr,(void *)pstIpHead,false);
            break;
        case IPPROTO_TCP:
            struct tcphdr *pstTcpHdr = (struct tcphdr *)(pstIpHead+1);
            iRet = ethdump_parseTcpHead(pstTcpHdr,(void *)pstIpHead,false);
            break;
        case IPPROTO_ICMP:
            struct icmphdr *pstIcmpHdr = (struct icmphdr *)(pstIpHead+1);
            iRet = ethdump_parseIcmpHead(pstIcmpHdr,(void *)pstIpHead,false);
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
    //printf("Eth-Pkt-Type:0x%04x(%s) ", usEthPktType, ethdump_getProName(usEthPktType));
    //ethdump_showMac(0, pstEthHead->ether_shost);
    //ethdump_showMac(1, pstEthHead->ether_dhost);
    //printf("\n");
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

int readconfig() {
    g_cfg.mysqlPort=3306;
    strcpy(g_cfg.mysqlIPString,"127.0.0.1");
    inet_pton(AF_INET,g_cfg.mysqlIPString,&g_cfg.mysqlIP);
    strcpy(g_cfg.mysqlUserName,"root");
    strcpy(g_cfg.mysqlPassword,"Cxx12345");
    strcpy(g_cfg.mysqlDB,"streams");
    strcpy(g_cfg.mysqlStreamsTbl,"streams");
    strcpy(g_cfg.mysqlPktInfoTbl,"pktinfo");
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
    /* config.json格式：
     [
        {"mysqlIPString:"127.0.0.1"},
        {"mysqlPort:3306},
        {"mysqlUserName:"root"},
        {"mysqlPassword:"Cxx12345_"},
        {"mysqlDB:"streams"}
     ]
     */
    cJSON *item;
    for (int i = 0; i < cJSON_GetArraySize(cfg); i++) {
        item = cJSON_GetArrayItem(cfg, i);
        // UserName
        if (strcmp(item->child->string, "mysqlIPString") == 0) {
            strcpy(g_cfg.mysqlIPString, item->child->valuestring);
            inet_pton(AF_INET,g_cfg.mysqlIPString,&g_cfg.mysqlIP);
        }else if (strcmp(item->child->string, "mysqlPort") == 0) {
            g_cfg.mysqlPort=item->child->valueint;
        }else if (strcmp(item->child->string, "mysqlUserName") == 0) {
            strcpy(g_cfg.mysqlUserName, item->child->valuestring);
        }else if (strcmp(item->child->string, "mysqlPassword") == 0) {
            strcpy(g_cfg.mysqlPassword, item->child->valuestring);
        }else if (strcmp(item->child->string, "mysqlDB") == 0) {
            strcpy(g_cfg.mysqlDB, item->child->valuestring);
        }else if (strcmp(item->child->string,"mysqlStreamsTbl") == 0) {
            strcpy(g_cfg.mysqlStreamsTbl, item->child->valuestring);
        }else if (strcmp(item->child->string,"mysqlPktInfoTbl") == 0) {
            strcpy(g_cfg.mysqlPktInfoTbl, item->child->valuestring);
        }
        //printf("string:%s,valuestring:%s,valueint:%d\n", item->child->string,item->child->valuestring,item->child->valueint);
    }
    // clear
    cJSON_Delete(cfg);
    return 0;
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
    if (argc>1) {
        strcpy(g_szDumpFileName,argv[1]); //tcpdump file name ,e.g. "dump.pcap"
    }
    if (argc>2) {
        sprintf(g_cfg.mysqlStreamsTbl,"%s_streams",argv[2]);
        sprintf(g_cfg.mysqlPktInfoTbl,"%s_pktinfo",argv[2]);
    }
    if (argc==1) {
        printf("\nUsage: %s [<pcap file name> [<mysql table name prefix>]]\n",argv[0]);
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
        g_pktno++;
        //printf("\033[1;31;40m>>> Packet %lld: len=%d bytes, cap=%d bytes.\033[0m\n",pktNo,hdr->len,hdr->caplen);
        /* 解析数据帧*/
        ethdump_parseFrame(buff);
    }
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
    strcat(g_sql,"pcapname varchar(256),sid int unsigned unique key auto_increment,sip varchar(40), sport int unsigned, dip varchar(40), dport int unsigned, protocol int unsigned, ");
    strcat(g_sql,"ts_sec timestamp, ts_usec int unsigned, te_sec timestamp, te_usec int unsigned, upstreamlen int(8) unsigned, downstreamlen int(8) unsigned, up_pktnumber int unsigned, down_pktnumber int unsigned, sni varchar(128),tlsv varchar(6),");
    strcat(g_sql,"PRIMARY KEY (sip,sport,dip,dport,protocol));");
    my_query(g_sql);
    sprintf(g_sql,"drop table %s;",g_cfg.mysqlPktInfoTbl);
    my_query(g_sql);
    sprintf(g_sql,"create table if not exists %s(sid int unsigned,pid int unsigned, ts_sec timestamp, ts_usec int unsigned, pktlen int, pcappktno int unsigned, PRIMARY KEY(sid,pid));",g_cfg.mysqlPktInfoTbl);
    my_query(g_sql);
    MYSQL_RES *res;
    struct streamHeader *st;
    long long streamNum=0;
    for (int i=0;i<STREAM_TABLE_SIZE;i++) {
        st=g_streamHdr+i;
        if (st->num>0) {
            while (st != nullptr) {
                printf("%lld:hash %x,(%d) \033[1;32;40m%s\033[0m:%d -> \033[1;32;40m%s\033[0m:%d,pkt number(%d),SNI:%s.\n",++streamNum,st->hash,st->protocol,st->sipstr,ntohs(st->sport),st->dipstr,ntohs(st->dport),st->pktNumber,st->SNI);
                //
                sprintf(g_sql,"insert into %s(pcapname,sip,sport,dip,dport,protocol,ts_sec,ts_usec,te_sec,te_usec,upstreamlen,downstreamlen,up_pktnumber,down_pktnumber,sni,tlsv) values('%s','%s',%u,'%s',%u,%u,from_unixtime(%u),%u,from_unixtime(%u),%u,%llu,%llu,%u,%u,'%s','%s');",
                              g_cfg.mysqlStreamsTbl,g_szDumpFileName,st->sipstr,ntohs(st->sport),st->dipstr,ntohs(st->dport),st->protocol,st->ts.tv_sec+(st->ts.tv_sec==0?1:0),st->ts.tv_usec,st->te.tv_sec+(st->te.tv_sec==0?1:0),st->te.tv_usec,st->upstreamlen,st->downstreamlen,st->up_pktNumber,st->down_pktNumber,st->SNI,st->tlsv);
                my_query(g_sql);
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
                st=st->next;
            }
        }
    }
    mysql_free_result(res);
    mysql_close(g_mysql);
    //
    freeBuff();
    return 0;
}
