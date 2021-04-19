#include "myfluxcap_windows.h"
#define MAXLINE 1450
#define SERV_PORT 45253
#ifdef _WIN32
char config_file[] = "windows_gre_config.ini";
#else
char config_file[] = "config.ini";
#endif // _WIN32
#define ARP_FLAG 0
char gredstip[32];
char uuid[100];
#include<string>
#include<thread>
int mtu;
u_int ip_int[24];
u_int gre_ip_int;
union thdr {
    struct tpacket_hdr* h1;
    struct tpacket2_hdr* h2;
    void* raw;
};
typedef struct {
    int                  fd;
#ifndef _WIN32
    struct tpacket_req3  req;
    struct tpacket_req  req1;
#endif // !_WIN32

    int bufsize;
    int offset;
    int frames_per_block;
    char* map;
    struct iovec* rd;
    union thdr* buffer;
    int                  nextPos;
    char NICname[100];//本地网卡名字
    int  NICstatus;//是否开启转发
    uint16_t ip_id; /* for implementing IP fragmentation when */
    int encap_key;  //添加的数字标识
    struct in_addr ip_addr;//本地网卡IPv4
    char ipstring[16];
    char mac[64];//本地mac地址
    int mtu;        /* using gre encapsulation */
    int sequence_number;
    char NICip[46];
    char uuid[100];
} MolochTPacketV3_t;
MolochTPacketV3_t infos[32];
int numThreads;//网卡数量，需要开启的线程数
int total_packets = 0;
int total_bytes = 0;
int sock;
typedef  struct {
    uint16_t flag_version;
    uint16_t protocol;
}greheader;
static greheader greh;
uint8_t arr[2048];
int name = 0;

static struct sockaddr_in remote;


#define CONF_FILE_PATH	"config.ini"

#ifdef WIN32

#else

#define  MAX_PATH 260

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#endif

static inline void
ink_set_thread_name(const char* name)
{
#if defined(HAVE_PTHREAD_SETNAME_NP_1)
    pthread_setname_np(name);
#elif defined(HAVE_PTHREAD_SETNAME_NP_2)
    pthread_setname_np(pthread_self(), name);
#elif defined(HAVE_PTHREAD_SET_NAME_NP_2)
    pthread_set_name_np(pthread_self(), name);
#elif defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_NAME)
    prctl(PR_SET_NAME, name, 0, 0, 0);
#endif
}

//从INI文件读取字符串类型数据
const char* GetIniKeyString(char* title, char* key, char* filename)
{
    FILE* fp;
    char szLine[1024];
    static char tmpstr[1024];
    int rtnval;
    int i = 0;
    int flag = 0;
    char* tmp;

    if ((fp = fopen(filename, "r")) == NULL)
    {
        printf("have   no   such   file \n");
        return "-1";
    }
    while (!feof(fp))
    {
        rtnval = fgetc(fp);
        if (rtnval == EOF)
        {
            break;
        }
        else
        {
            szLine[i++] = rtnval;
        }
        if (rtnval == '\n')
        {
#ifndef WIN32
            i--;
#endif	
            szLine[--i] = '\0';
            i = 0;
            tmp = strchr(szLine, '=');

            if ((tmp != NULL) && (flag == 1))
            {
                if (strstr(szLine, key) != NULL)
                {
                    //注释行
                    if ('#' == szLine[0])
                    {
                    }
                    else if ('/' == szLine[0] && '/' == szLine[1])
                    {

                    }
                    else
                    {
                        //找打key对应变量
                        strcpy(tmpstr, tmp + 1);
                        fclose(fp);
                        return tmpstr;
                    }
                }
            }
            else
            {
                strcpy(tmpstr, "[");
                strcat(tmpstr, title);
                strcat(tmpstr, "]");
                if (strncmp(tmpstr, szLine, strlen(tmpstr)) == 0)
                {
                    //找到title
                    flag = 1;
                }
            }
        }
    }
    fclose(fp);
    return "";
}

//从INI文件读取整类型数据
int GetIniKeyInt(char* title, char* key, char* filename)
{
    return atoi(GetIniKeyString(title, key, filename));
}
uint8_t gbuf[65535];
int txnum[32] = { 0 };
int more[32] = { 0 };
#ifdef _WIN32
int HKRunator(char* programName);
void encapsulate_tx_win( char* tx, int nx, int numThreads) {

    /*
    转发数据统计

    */
    uint16_t encap_ethertype, more_fragments = 1, fo = 0, fn = 0;
    uint32_t ip_src, ip_dst, off;
    char* ethertype, ipproto;
    uint8_t* g;
    struct sockaddr_in sin;
    struct sockaddr* dst;
    size_t nr = 0, fl = 0;
    socklen_t sz;

    assert(nx >= 14);
    struct sockaddr_in remote;
    remote.sin_family = AF_INET;
    remote.sin_port = 0;//htons(IPPROTO_GRE);
    remote.sin_addr.s_addr = inet_addr(gredstip);
    ip_src = 0;
    //ip_dst = cfg.encap.dst.s_addr;
    ip_dst = remote.sin_addr.s_addr;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    //sin.sin_addr = cfg.encap.dst;
    sin.sin_addr = remote.sin_addr;
    dst = (struct sockaddr*)&sin;
    sz = sizeof(sin);

    infos[numThreads].ip_id++;
    memset(gbuf, 0, 65535);
    g = gbuf;
    off = 0;
    ipproto = IPPROTO_GRE;
    memset(g, 0, 2); /* zero first two bytes of GRE header */
    g[0] |= (1 ? (1U << 5) : 0); /* key bit */
    g += 2;
    encap_ethertype = htons(0x3258); /* transparent ethernet bridging */
    memcpy(g, &encap_ethertype, sizeof(uint16_t));
    g += 2;
    if (infos[0].encap_key) {//infos[0].encap_key
        uint32_t key;
        key = htonl(infos[numThreads].encap_key);//infos[numThreads].encap_key
        ++txnum[numThreads];
        memcpy(g, &key, 4);
        g += 4;
    }
    else
    {
        uint32_t key;
        key = htonl(0x12345678);//infos[numThreads].encap_key
        ++txnum[numThreads];
        memcpy(g, &key, 4);
        g += 4;
    }
    assert(nx <= sizeof(gbuf) - (g - gbuf));
    memcpy(g, tx, nx);
    g += nx;
    nx = g - gbuf;
    more_fragments = (nx > mtu) ? 1 : 0;
    assert((off & 0x7) == 0);
    fo = off / 8;
    fl = nx;
    nr = sendto(sock, (const char*)gbuf, fl, 0, (struct sockaddr*)&remote, sz);//最后在这里发送
    return;
}

#else

void encapsulate_tx_linux(char* tx, int nx, int numThreads) {
    uint16_t encap_ethertype, more_fragments = 1, fo = 0, fn = 0;
    uint32_t ip_src, ip_dst, seqno, off;
    char* ethertype, ipproto;
    uint8_t* g;
    struct sockaddr_in sin;
    struct sockaddr* dst;
    size_t nr, fl;
    socklen_t sz;

    uint16_t vxlan_src_port;
    uint16_t vxlan_dst_port;
    uint16_t vxlan_udp_len;
    uint16_t vxlan_udp_cksum;
    uint8_t vxlan_flags;
    uint8_t* vni_big_endian;

    assert(nx >= 14);
    struct sockaddr_in remote;
    remote.sin_family = AF_INET;
    remote.sin_port = 0;//htons(IPPROTO_GRE);
    remote.sin_addr.s_addr = inet_addr(gredstip);
    ip_src = 0;
    //ip_dst = cfg.encap.dst.s_addr;
    ip_dst = remote.sin_addr.s_addr;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    //sin.sin_addr = cfg.encap.dst;
    sin.sin_addr = remote.sin_addr;
    dst = (struct sockaddr*)&sin;
    sz = sizeof(sin);

    infos[numThreads].ip_id++;
    g = gbuf;
    off = 0;


    ipproto = IPPROTO_GRE;

    /* construct 20-byte IP header.
     * NOTE: some zeroed header fields are filled out for us, when we send this
     * packet; particularly, checksum, src IP; ID and total length. see raw(7).
     */
    g[0] = 4 << 4;  /* IP version goes in MSB (upper 4 bits) of the first byte */
    g[0] |= 5;      /* IP header length (5 * 4 = 20 bytes) in lower 4 bits */
    g[1] = 0;       /* DSCP / ECN */
    g[2] = 0;       /* total length (upper byte) (see NOTE) */
    g[3] = 0;       /* total length (lower byte) (see NOTE) */
    g[4] = (infos[numThreads].ip_id & 0xff00) >> 8; /* id (upper byte); for frag reassembly */
    g[5] = (infos[numThreads].ip_id & 0x00ff);      /* id (lower byte); for frag reassembly */
    g[6] = 0;       /* 0 DF MF flags and upper bits of frag offset */
    g[7] = 0;       /* lower bits of frag offset */
    g[8] = 255;     /* TTL */
    g[9] = ipproto; /* IPPROTO_GRE or IPPROTO_UDP (VXLAN) */
    g[10] = 0;      /* IP checksum (high byte) (see NOTE) */
    g[11] = 0;      /* IP checksum (low byte) (see NOTE) */
    memcpy(&g[12], &ip_src, sizeof(ip_src)); /* IP source (see NOTE) */
    memcpy(&g[16], &ip_dst, sizeof(ip_dst)); /* IP destination */

    g += 20;

    //gre 协议

    memset(g, 0, 2); /* zero first two bytes of GRE header */
    g[0] |= (1 ? (1U << 5) : 0); /* key bit */
    g += 2;
    encap_ethertype = htons(0x3258); /* transparent ethernet bridging */
    memcpy(g, &encap_ethertype, sizeof(uint16_t));
    g += 2;
    if (infos[0].encap_key) {
        uint32_t key;
        key = htonl(infos[0].encap_key);
        memcpy(g, &key, 4);
        g += 4;
    }
    else
    {
        uint32_t key;
        key = htonl(0x12345678);
        memcpy(g, &key, 4);
        g += 4;
    }
    assert(nx <= sizeof(gbuf) - (g - gbuf));
    memcpy(g, tx, nx);
    g += nx;
    nx = g - gbuf;


    /*
     * send IP packet, performing fragmentation if greater than mtu发送IP数据包，如果大于mtu，则执行分段
     */

    do {

        //more_fragments = (nx > cfg.mtu) ? 1 : 0;
        more_fragments = (nx > mtu) ? 1 : 0;
        assert((off & 0x7) == 0);
        fo = off / 8;

        gbuf[6] = more_fragments ? (1 << 5) : 0; /* 0 DF [MF] flag */
        gbuf[6] |= (fo & 0x1f00) >> 8; /* upper bits of frag offset */
        gbuf[7] = fo & 0x00ff;        /* lower bits of frag offset */

        /* choose fragment length so it's below MTU and so the payload
         * length after 20 byte header is a multiple of 8 as required */
        if (more_fragments)
            fl = ((mtu - 20) & ~7U) + 20;
        else
            fl = nx;
        nr = sendto(sock, gbuf, fl, 0, (struct sockaddr*)&remote, sz);//最后在这里发送
        if (nr < 0) {
            printf("发送失败\n");
        }

        int i = 0;
        int sum = 0;
        for (; i < 32; i++)
            sum += txnum[i];
        if (nr != fl) {
            fprintf(stderr, "sendto: %s\n", (nr < 0) ?
                strerror(errno) : "incomplete");
            return;
        }
        /* keeping 20-byte IP header, slide next fragment payload */
        if (more_fragments) {
            assert(fl > 20);
            memmove(&gbuf[20], &gbuf[fl], nx - fl);
            off += (fl - 20);
            nx -= (fl - 20);
        }
        if (more_fragments)
        {
            ++more[numThreads];
            int i = 0;
            int moresum = 0;
            for (; i < 32; i++)
                moresum += more[i];
            printf("数据太大分片了:%d\n", moresum);
        }
    } while (more_fragments);

    return;


}
#endif // _WIN32

/*
 * find start and length of column N (one-based)
 * in input buffer buf of length buflen
 *
 * columns must be space-or-tab delimited
 * returns NULL if column not found
 *
 * the final column may end in newline or eob
 *
 * col: column index (1-based)
 * len: OUTPUT parameter (column length)
 * buf: buffer to find columns in
 * buflen: length of buf
 *
 * returns:
 *   pointer to column N, or NULL
 */
#define ws(x) (((x) == ' ') || ((x) == '\t'))
char* get_col(int col, size_t* len, char* buf, size_t buflen) {
    char* b, * start = NULL, * eob;
    int num;

    eob = buf + buflen;

    b = buf;
    num = 0;  /* column number */
    *len = 0; /* column length */

    while (b < eob) {

        if (ws(*b) && (num == col)) break; /* end of sought column */
        if (*b == '\n') break;             /* end of line */

        if (ws(*b)) *len = 0;              /* skip over whitespace */
        if ((!ws(*b)) && (*len == 0)) {    /* record start of column */
            num++;
            start = b;
        }
        if (!ws(*b)) (*len)++;             /* increment column length */
        b++;
    }

    if ((*len) && (num == col)) return start;
    return NULL;
}
/*
 * read_proc
 *
 * read a complete file from the /proc filesystem
 * this is special because its size is not known a priori
 * so a read/realloc loop is needed
 *
 * size into len, returning buffer or NULL on error.
 * caller should free the buffer eventually.
 */
#ifdef _WIN32
#else

char* read_proc(const char* file, size_t* len) {
    char* buf = NULL, * b, * tmp;
    int fd = -1, rc = -1, eof = 0;
    size_t sz, br = 0, l;
    size_t nr;

    /* initial guess at a sufficient buffer size */
    sz = 1000;

    fd = open(file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        goto done;
    }

    while (!eof) {

        tmp = (char*)realloc(buf, sz);
        if (tmp == NULL) {
            fprintf(stderr, "out of memory\n");
            goto done;
        }

        buf = tmp;
        b = buf + br;
        l = sz - br;

        do {
            nr = read(fd, b, l);
            if (nr < 0) {
                fprintf(stderr, "read: %s\n", strerror(errno));
                goto done;
            }

            b += nr;
            l -= nr;
            br += nr;

            /* out of space? double buffer size */
            if (l == 0) {
                sz *= 2;
                break;
            }

            if (nr == 0) eof = 1;

        } while (nr > 0);
    }

    *len = br;
    rc = 0;

done:
    if (fd != -1) close(fd);
    if (rc && buf) { free(buf); buf = NULL; }
    return buf;
}
int get_if_mtu(char* eth);
int find_route(uint32_t dest_ip,
    char* interfacename) {

    int rc = -1, sc;
    char* buf = NULL, * line, * b, * iface, * s_dest, * s_mask;
    unsigned mask, dest, best_mask = 0, nroutes = 0;
    size_t len, sz = 0, to_eob, iface_len;

    buf = read_proc("/proc/net/route", &sz);
    if (buf == NULL) goto done;

    /* find initial newline; discard header row */
    b = buf;
    while ((b < buf + sz) && (*b != '\n')) b++;
    line = b + 1;

    while (line < buf + sz) {

        to_eob = sz - (line - buf);

        s_dest = get_col(2, &len, line, to_eob);
        if (s_dest == NULL) goto done;
        sc = sscanf(s_dest, "%x", &dest);
        if (sc != 1) goto done;

        s_mask = get_col(8, &len, line, to_eob);
        if (s_mask == NULL) goto done;
        sc = sscanf(s_mask, "%x", &mask);
        if (sc != 1) goto done;

        iface = get_col(1, &iface_len, line, to_eob);
        if (iface == NULL) goto done;

        /* advance to next line */
        b = line;
        while ((b < buf + sz) && (*b != '\n')) b++;
        line = b + 1;

        /* does the route apply? */
        if ((dest_ip & mask) != dest) continue;

        /* know a more specific route? */
        if (mask < best_mask) continue;

        /* this is the best route so far */
        best_mask = mask;

        /* copy details of this route */
        if (iface_len + 1 > NAMESIZE) goto done;
        memcpy(interfacename, iface, iface_len);
        interfacename[iface_len] = '\0';
        nroutes++;
    }

    rc = nroutes ? 0 : -2;

done:
    if (buf) free(buf);
    return rc;
}
#endif
//#pragma comment(lib,"Ws2_32.lib")
int NICsendsock() {
    //gre转发套接字创建
    char interfacename[NAMESIZE];
    int ec;
    const char one = 1;
#ifdef _WIN32
    SOCKET sock;
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 1), &wsd);
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)) == SOCKET_ERROR)//创建一个原始套接字
    {
        exit(0);
    }
    mtu = 1500;
#else
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (sock < 0)
    {
        perror("socket");
        return 0;
    }
    ec = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (ec < 0) {
        fprintf(stderr, "setsockopt IP_HDRINCL: %s\n", strerror(errno));
        return -1;
    }

    /* we need the mtu of the egress NIC to implement IP fragmentation,
     * if needed, since raw sockets do not do that for us. to get the
     * interface mtu, we need the egress interface, based on routing */
     //remote.sin_addr.s_addr
    ec = find_route(remote.sin_addr.s_addr, interfacename);
    if (ec < 0) {
        //ip = inet_ntoa((struct sockaddr_in*)remote.sin_addr);
        fprintf(stderr, "can't determine route to %s\n", "aaa");
        goto done;
    }
    mtu = get_if_mtu(interfacename);
#endif
    if (mtu < 0) {
        fprintf(stderr, "mtu lookup failed: %s\n", interfacename);
        goto done;
    }
    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = htons(IPPROTO_GRE);
    local.sin_addr.s_addr = inet_addr("0.0.0.0");
    if (local.sin_addr.s_addr == INADDR_NONE)
    {
        fprintf(stderr, "bad local address\n");
        return 0;
    }
    else
    {
        if (bind(sock, (struct sockaddr*)&local, sizeof(local)) != 0)
        {
            perror("bind");
            return 0;
        }
    }
done:
    return sock;
}
typedef unsigned int uint;
uint ipTint(char* ipstr)
{
    if (ipstr == NULL) return 0;

    char* token;
    uint i = 3, total = 0, cur;

    token = strtok(ipstr, ".");

    while (token != NULL) {
        cur = atoi(token);
        if (cur >= 0 && cur <= 255) {
            total += cur * pow(256, i);
        }
        i--;
        token = strtok(NULL, ".");
    }

    return total;
}
#ifdef _WIN32


//开启一个线程读取一张网卡的流量
BOOL LoadNpcapDlls()
{
    TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
// Prototypes

void sendPackets(LPPACKET lpPacket);

char        AdapterList[Max_Num_Adapter][1024];
void reader_windows_thread(int infov) {
    //define a pointer to an ADAPTER structure
    cout << "infov" << infov << endl;
    LPADAPTER  lpAdapter = 0;

    //define a pointer to a PACKET structure

    LPPACKET   lpPacket;

    int        i = infov;
    DWORD      dwErrorCode;

    //ascii strings
    char		AdapterName[8192]; // string that contains a list of the network adapters
    char* temp, * temp1;


    int			AdapterNum = 0, Open;
    ULONG		AdapterLength;

    char buffer[256000];  // buffer to hold the data coming from the driver

    struct bpf_stat stat;

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

    //
    // Obtain the name of the adapters installed on this machine
    //
    printf("Packet.dll test application. Library version:%s\n", PacketGetVersion());

    printf("Adapters installed:\n");

    char* pre = (char*)"\\Device\\NPF_";
    char pre_name[100] = { 0 };
    strcat(pre_name, pre);
    strcat(pre_name, infos[infov].NICname);
    cout << pre_name << endl;
    lpAdapter = PacketOpenAdapter(pre_name);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        dwErrorCode = GetLastError();
        printf("Unable to open the adapter, Error Code : %lx\n", dwErrorCode);
        return;
    }
    // set the network adapter in promiscuous mode

    if (PacketSetHwFilter(lpAdapter, NDIS_PACKET_TYPE_PROMISCUOUS) == FALSE) {
        printf("Warning: unable to set promiscuous mode!\n");
    }

    // set a 512K buffer in the driver
    if (PacketSetBuff(lpAdapter, 512000) == FALSE) {
        printf("Unable to set the kernel buffer!\n");
        return;
    }

    // set a 1 second read timeout
    if (PacketSetReadTimeout(lpAdapter, 1000) == FALSE) {
        printf("Warning: unable to set the read tiemout!\n");
    }

    //allocate and initialize a packet structure that will be used to
    //receive the packets.
    if ((lpPacket = PacketAllocatePacket()) == NULL) {
        printf("\nError: failed to allocate the LPPACKET structure.");
        return;
    }
    PacketInitPacket(lpPacket, (char*)buffer, 256000);

    while (!_kbhit())
    {
        // while (infos[i].NICstatus) {
        while (1) {
            // capture the packets
            if (PacketReceivePacket(lpAdapter, lpPacket, TRUE) == FALSE) {
                printf("Error: PacketReceivePacket failed");
                return;
            }

            sendPackets(lpPacket);
        }
        printf("%d\n", i);
        std::this_thread::sleep_for(1s);
    }


    //print the capture statistics
    if (PacketGetStats(lpAdapter, &stat) == FALSE) {
        printf("Warning: unable to get stats from the kernel!\n");
    }
    else
        printf("\n\n%d packets received.\n%d Packets lost", stat.bs_recv, stat.bs_drop);

    PacketFreePacket(lpPacket);

    // close the adapter and exit

    PacketCloseAdapter(lpAdapter);
    return;
}
void sendPackets(LPPACKET lpPacket)
{

    ULONG	i, j, ulLines, ulen, ulBytesReceived;
    char* pChar, * pLine, * base, * dchar;
    char* buf;
    u_int off = 0;
    u_int tlen, tlen1;
    struct bpf_hdr* hdr;

    ulBytesReceived = lpPacket->ulBytesReceived;


    buf = (char*)lpPacket->Buffer;

    off = 0;

    while (off < ulBytesReceived) {
        if (_kbhit())return;
        hdr = (struct bpf_hdr*)(buf + off);
        tlen1 = hdr->bh_datalen;
        tlen = hdr->bh_caplen;
        off += hdr->bh_hdrlen;
        if (off == 0)
            break;
        ulLines = (tlen + 15) / 16;
        pChar = (char*)(buf + off);
        dchar = (char*)(buf + off);
        base = pChar;
        off = Packet_WORDALIGN(off + tlen);
        
        /*
        是否转发
        1 对于非gre协议 全都转发
        2 对于gre
        2.1 是gre包，但是起gre协议是0x3258 不转发
        2.2 是gre包，又是分片包，那么先判断源ip（为本地IP），目的IP（greip）,不转发，其他都转发
        */
        if (0x0806 == ntohs(*(u_short*)&dchar[12]) && !ARP_FLAG) {//是否转发arp的数据包,默认不转发
            goto done;
        }
        if (tlen1 < 38) {
            encapsulate_tx_win(dchar, tlen1, 0);
            continue;
        }
        if (dchar[23] != 47)//能转发||(dchar[23] == 47 && 0x3258 != (u_short)&dchar[36])
        {
            encapsulate_tx_win(dchar, tlen1, 0);
            total_bytes += tlen1;
        }
        else if (dchar[23] == 47 && 0x3258 == ntohs(*(u_short*)&dchar[36]))
        {
            //printf("自己的grebao:%d\n", tlen1);
            continue;
        }
        else if (dchar[23] == 47 && (ntohs(*(u_short*)(dchar + 20)) & 0x1ff != 0)) {//是gre包的分片包
            //已经是分片了,且不是片头,且这个gre包不是自己构造的包
            int m = 0;
            for (; ip_int[m] != 0; m++) {//自己构造的包
                if (ip_int[m] == ntohl(*(u_int*)&dchar[26]) && ntohl(*(u_int*)&dchar[30]) == gre_ip_int)
                    //不转发
                {
                    //printf("/自己构造的包,不转发%d\n", m);                 
                    goto done;
                }
            }
            //转发  原生的gre包
            encapsulate_tx_win(dchar, tlen1, 0);
            //printf("原生的gre包,转发%d\n", m);
            
        }
        else {//是gre协议 是自己创建的gre协议,不转发，和linux不同，原因在于创建gre转发套接字时不同，linux需要自己做分片，windows交给系统做分片了。  
        }
    done:
        printf("");
    }
}
#pragma comment(lib,"Iphlpapi.lib")
#include <Iphlpapi.h>
bool GetAdapterState(DWORD index);
bool GetAdapterState(DWORD nIndex)
{
    MIB_IFROW miInfo;   // 存放获取到的 Adapter 参数
    memset(&miInfo, 0, sizeof(MIB_IFROW));
    miInfo.dwIndex = nIndex;   // dwIndex 是需要获取的 Adapter 的索引
    if (GetIfEntry(&miInfo) != NOERROR)
    {
        printf("ErrorCode = %d\n", GetLastError());
        return false;
    }
    if (miInfo.dwOperStatus == IF_OPER_STATUS_NON_OPERATIONAL || miInfo.dwOperStatus == IF_OPER_STATUS_UNREACHABLE
        || miInfo.dwOperStatus == IF_OPER_STATUS_DISCONNECTED || miInfo.dwOperStatus == IF_OPER_STATUS_CONNECTING)
    {
        return false;
    }
    else if (miInfo.dwOperStatus == IF_OPER_STATUS_OPERATIONAL || miInfo.dwOperStatus == IF_OPER_STATUS_CONNECTED)
    {
        return true;
    }
    else
    {
        return false;
    }
}
using namespace std;
#pragma comment(lib,"Iphlpapi.lib")
int getconf_windows() {
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
    // PIP_ADAPTER_INFO 结构体指针存储本机网卡信息
    PIP_ADAPTER_INFO pIPAdapterInfo = new IP_ADAPTER_INFO();
    PIP_ADAPTER_INFO pAdapter = NULL;
    // 得到结构体大小 , 用于 GetAdaptersInfo 参数
    unsigned long ulSize = sizeof(IP_ADAPTER_INFO);
    // 调用 GetAdaptersInfo 函数 , 填充 pIpAdapterInfo 指针变量 , 其中 ulSize 参数既是一个输入量也是一个输出量
    int nRstCode = GetAdaptersInfo(pIPAdapterInfo, &ulSize);
    // 记录网卡数量
    int nNetCardNum = 0;
    // 记录每张网卡上的 IP 地址数量
    int nIPNumPerNetCard = 0;
    if (ERROR_BUFFER_OVERFLOW == nRstCode)
    {
        // 如果函数返回的是 ERROR_BUFFER_OVERFLOW
        // 则说明 GetAdaptersInfo 参数传递的内存空间不够 , 同时其传出 ulSize , 表示需要的空间大小
        // 这也是说明为什么 ulSize 既是一个输入量也是一个输出量
        // 释放原来的内存空间
        delete pIPAdapterInfo;
        // 重新申请内存空间用来存储所有网卡信息
        pIPAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[ulSize];
        // 再次调用 GetAdaptersInfo 函数 , 填充 pIpAdapterInfo 指针变量
        nRstCode = GetAdaptersInfo(pIPAdapterInfo, &ulSize);
    }
    if (ERROR_SUCCESS == nRstCode)
    {
        // 输出网卡信息 , 可能有多网卡 , 因此通过循环去判断
        pAdapter = pIPAdapterInfo;
        while (pAdapter)
        {
            if (GetAdapterState(pAdapter->Index))
            {
                cout << "网卡工作正常" << "\n";
            }
            else
            {
                cout << "网卡工作异常" << endl;
                pAdapter = pAdapter->Next;
                continue;
            }
            cout << "网卡数量 : " << ++nNetCardNum << endl;
            cout << "网卡名称 : " << pAdapter->AdapterName << endl;
            strcpy(infos[nNetCardNum - 1].NICname, (pAdapter->AdapterName));
            printf("name:%s", infos[nNetCardNum - 1].NICname);
            cout << "网卡描述 : " << pAdapter->Description << endl;
            switch (pAdapter->Type)
            {
            case MIB_IF_TYPE_OTHER:
                cout << "网卡类型 : " << "OTHER" << endl;
                break;
            case MIB_IF_TYPE_ETHERNET:
                cout << "网卡类型 : " << "ETHERNET" << endl;
                break;
            case MIB_IF_TYPE_TOKENRING:
                cout << "网卡类型 : " << "TOKENRING" << endl;
                break;
            case MIB_IF_TYPE_FDDI:
                cout << "网卡类型 : " << "FDDI" << endl;
                break;
            case MIB_IF_TYPE_PPP:
                cout << "网卡类型 : " << "PPP" << endl;
                break;
            case MIB_IF_TYPE_LOOPBACK:
                cout << "网卡类型 : " << "LOOPBACK" << endl;
                break;
            case MIB_IF_TYPE_SLIP:
                cout << "网卡类型 : " << "SLIP" << endl;
                break;
            default:
                break;
            }

            cout << "网卡IP地址如下 : " << endl;
            // 可能网卡有多 IP , 因此通过循环去判断
            IP_ADDR_STRING* pIPAddrString = &(pAdapter->IpAddressList);
            nIPNumPerNetCard = 0;
            while (pIPAddrString)
            {
                cout << "该网卡上的IP数量 : " << ++nIPNumPerNetCard << endl;
                cout << "IP 地址 : " << pIPAddrString->IpAddress.String << endl;
                inet_pton(AF_INET, pIPAddrString->IpAddress.String, &infos[nNetCardNum - 1].ip_addr);//adasdas
                strcat(infos[nNetCardNum - 1].ipstring, pIPAddrString->IpAddress.String);
                strcat(infos[nNetCardNum - 1].ipstring, ";");

                u_int intIp = ipTint(infos[nNetCardNum - 1].ipstring);
                int m = 0;
                for (; ip_int[m] == 0 && m < 24; m++) {
                    ip_int[m] = intIp;
                    break;
                }
                cout << "子网地址 : " << pIPAddrString->IpMask.String << endl;
                cout << "网关地址 : " << pAdapter->GatewayList.IpAddress.String << endl;
                pIPAddrString = pIPAddrString->Next;
            }

            pAdapter = pAdapter->Next;
            cout << "--------------------------------------------------------------------" << endl;
        }
    }
    // 释放内存空间
    if (pIPAdapterInfo != NULL)
    {
        delete[] pIPAdapterInfo;
        pIPAdapterInfo = NULL;
    }
    //getchar();
    cout << infos << endl;
    return nNetCardNum;
}

#else
void reader_tpacketv3_thread(int infov) {

    long numThreads = (long)infov;
    struct pollfd pfd;
    int pos = -1;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = infos[numThreads].fd;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;
    greh.flag_version = 0;
    greh.protocol = 0;
    //再来一个大循环，当网卡转发状态为关闭时，就sleep(1)

    while (1)
    {
        // 在下面的循环里表示正在执行，在上面的while(1)
        while (infos[numThreads].NICstatus) {
            if (pos == -1) {
                pos = infos[numThreads].nextPos;//没有赋值时为空  nextpos
                infos[numThreads].nextPos = (infos[numThreads].nextPos + 1) % infos[numThreads].req.tp_block_nr;
            }
            struct tpacket_block_desc* tbd = (struct tpacket_block_desc*)infos[numThreads].rd[pos].iov_base;
            // Wait until the block is owned by moloch
            if ((tbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
                poll(&pfd, 1, -1);
                goto done;
            }
            struct tpacket3_hdr* th;

            th = (struct tpacket3_hdr*)((uint8_t*)tbd + tbd->hdr.bh1.offset_to_first_pkt);
            uint16_t p;

            for (p = 0; p < tbd->hdr.bh1.num_pkts; p++) {
                if (unlikely(th->tp_snaplen != th->tp_len)) {
                    printf("ERROR - Moloch requires full packet captures caplen: %d pktlen: %d\n"
                        "See https://github.com/aol/moloch/wiki/FAQ#Moloch_requires_full_packet_captures_error",
                        th->tp_snaplen, th->tp_len);
                }

                char* pak = (char*)th + th->tp_mac; 
                    int len = th->tp_len;
                if (th->tp_len < 42)
                    goto done;
                /*
        是否转发
        1 对于非gre协议 全都转发
        2 对于gre
        2.1 是gre包，但是起gre协议是0x3258 不转发
        2.2 是gre包，又是分片包，那么先判断源ip（为本地IP），目的IP（greip）,不转发，其他都转发
        */
                if (th->tp_len < 38) {
                    goto done;
                }
                if (pak[23] != 47)//能转发||(dchar[23] == 47 && 0x3258 != (u_short)&dchar[36])
                {
                    encapsulate_tx_linux(pak, th->tp_len, 0);
                    printf("转发的包\n");
                    printf("第一次包大小:%d\n", th->tp_len);
                    printf("total_packets:%d\n", total_packets++);
                    total_bytes += th->tp_len;
                    printf("total_bytes:%d\n", total_bytes);
                }
                else if (pak[23] == 47 && 0x3258 == ntohs(*(u_short*)&pak[36]))
                {
                    printf("自己的grebao\n");
                    goto done;
                }
                else if (pak[23] == 47 && (ntohs(*(u_short*)(pak + 20)) & 0x1ff != 0)) {//是gre包的分片包
                //已经是分片了,且不是片头,且这个gre包不是自己构造的包
                    int m = 0;
                    printf("已经是分片了%02x\n", ntohs(*(u_short*)(pak + 20)));
                    printf("已经是分片了%02x\n", *(pak + 21));
                    printf("已经是分片了%02x\n", *(pak + 22));
                    printf("已经是分片了%02x\n", *(pak + 23));
                    for (; ip_int[m] != 0; m++) {//自己构造的包
                        if (ip_int[m] == ntohl(*(u_int*)&pak[26]) && ntohl(*(u_int*)&pak[30]) == gre_ip_int)
                            //不转发
                        {
                            printf("不转发%d\n", m);
                            printf("ip_int[m]:%ud,ntohl(*(u_int*)&dchar[26]):%ud", ip_int[m], ntohl(*(u_int*)&pak[26]));
                            printf("igre_ip_int:%ud,ntohl(*(u_int*)&dchar[30]):%ud", gre_ip_int, ntohl(*(u_int*)&pak[30]));
                            goto done;
                        }
                    }
                    //转发  原生的gre包
                    printf("转发  原生的gre包\n");
                    encapsulate_tx_linux(pak, th->tp_len, 0);
                    printf("%x\n", ntohl(*(u_int*)&pak[26]));
                    printf("%x\n", ntohl(*(u_int*)&pak[30]));
                }
                else {//是gre协议 但是不是自己创建的gre协议
                    encapsulate_tx_linux(pak, th->tp_len, 0);
                    printf("%x\n", ntohs(*(u_short*)(pak + 20)) & 0x1ff);
                    printf("是gre协议 但是不是自己创建的gre协议,转发%d\n", th->tp_len);

                    printf("total_packets:%d\n", total_packets++);
                    total_bytes += th->tp_len;
                    printf("total_bytes:%d\n", total_bytes);
                }
            done:
                printf("");

                th = (struct tpacket3_hdr*)((uint8_t*)th + th->tp_next_offset);
            }//在一个线程中，把所有的包都加入到batch->packetQ[thread]中, batch->count  记录总包数
            //reader_tpacketv3_stats();

            tbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            pos = -1;
        }
        sleep(1);
    }
    return;
}
void reader_tpacketv2_thread(int infov) {
    long numThreads = (long)infov;
    int nIndex = 0, i = 0;
    int ret = 0;
    int total = 0;
    ink_set_thread_name("reader_tpacketv2_thread");
    while (1)
    {
        printf("reader_tpacketv2_thread");
        //这里在poll前先检查是否已经有报文被捕获了
        struct tpacket2_hdr* pHead = (struct tpacket2_hdr*)(infos[numThreads].map + nIndex * infos[numThreads].req1.tp_frame_size);
        //如果frame的状态已经为TP_STATUS_USER了，说明已经在poll前已经有一个数据包被捕获了，如果poll后不再有数据包被捕获，那么这个报文不会被处理，这就是所谓的竞争情况。
        if (pHead->tp_status == TP_STATUS_USER)
            goto process_packet;
        //poll检测报文捕获
        struct pollfd pfd;
        pfd.fd = infos[numThreads].fd;
        //pfd.events = POLLIN|POLLRDNORM|POLLERR;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ret = poll(&pfd, 1, -1);
        if (ret < 0)
        {
            perror("poll");
            //munmap(buff, infos[numThreads].req1.tp_frame_size);
            break;
        }
    process_packet:

        //尽力的去处理环形缓冲区中的数据frame，直到没有数据frame了
        for (i = 0; i < infos[numThreads].req1.tp_frame_nr; i++)
        {
            printf("%d\n", i);
            struct tpacket2_hdr* pHead = (struct tpacket2_hdr*)(infos[numThreads].map + nIndex * infos[numThreads].req1.tp_frame_size);
            //struct tpacket_hdr* pHead = (struct tpacket_hdr*)&(infos[numThreads].buffer[nIndex]);
            //XXX: 由于frame都在一个环形缓冲区中，因此如果下一个frame中没有数据了，后面的frame也就没有frame了

            if (pHead->tp_status == TP_STATUS_KERNEL)
                break;

            char* pak = (char*)pHead + pHead->tp_mac;

            /*
           是否转发
           1 对于非gre协议 全都转发
           2 对于gre
           2.1 是gre包，但是起gre协议是0x3258 不转发
           2.2 是gre包，又是分片包，那么先判断源ip（为本地IP），目的IP（greip）,不转发，其他都转发
           */
            if (pHead->tp_len < 38) {
                printf("小于38\n");
                goto done;
            }
            if (pak[23] != 47)//能转发||(dchar[23] == 47 && 0x3258 != (u_short)&dchar[36])
            {
                encapsulate_tx_linux(pak, pHead->tp_len, 0);

                //printf("转发的包\n");
                //printf("第一次包大小:%d\n", pHead->tp_len);
                printf("total_packets:%d\n", total_packets++);
                total_bytes += pHead->tp_len;
                printf("total_bytes:%d\n", total_bytes);
            }
            else if (pak[23] == 47 && 0x3258 == ntohs(*(u_short*)&pak[36]))
            {
                //printf("自己的grebao\n");
                goto done;
            }
            else if (pak[23] == 47 && (ntohs(*(u_short*)(pak + 20)) & 0x1ff != 0)) {//是gre包的分片包
            //已经是分片了,且不是片头,且这个gre包不是自己构造的包
                int m = 0;
                //printf("已经是分片了%02x\n", ntohs(*(u_short*)(pak + 20)));
               // printf("已经是分片了%02x\n", *(pak + 21));
                //printf("已经是分片了%02x\n", *(pak + 22));
                //printf("已经是分片了%02x\n", *(pak + 23));
                for (; ip_int[m] != 0; m++) {//自己构造的包
                    if (ip_int[m] == ntohl(*(u_int*)&pak[26]) && ntohl(*(u_int*)&pak[30]) == gre_ip_int)
                        //不转发
                    {
                        //   printf("不转发%d\n", m);
                          // printf("ip_int[m]:%ud,ntohl(*(u_int*)&dchar[26]):%ud", ip_int[m], ntohl(*(u_int*)&pak[26]));
                          // printf("igre_ip_int:%ud,ntohl(*(u_int*)&dchar[30]):%ud", gre_ip_int, ntohl(*(u_int*)&pak[30]));
                        goto done;
                    }
                }
                //转发  原生的gre包
                //printf("转发  原生的gre包\n");
                encapsulate_tx_linux(pak, pHead->tp_len, 0);
                // printf("%x\n", ntohl(*(u_int*)&pak[26]));
                // printf("%x\n", ntohl(*(u_int*)&pak[30]));
                 //printf("total_packets:%d\n", total_packets++);
                 //total_bytes += pHead->tp_len;
                 //printf("total_bytes:%d\n", total_bytes);

            }
            else {//是gre协议 但是不是自己创建的gre协议

                encapsulate_tx_linux(pak, pHead->tp_len, 0);
                //printf("%x\n", ntohs(*(u_short*)(pak + 20)) & 0x1ff);
                //printf("是gre协议 但是不是自己创建的gre协议,转发%d\n", pHead->tp_len);

                //printf("total_packets:%d\n", total_packets++);
                //total_bytes += pHead->tp_len;
                //printf("total_bytes:%d\n", total_bytes);
            }
        done:

            //重新设置frame的状态为TP_STATUS_KERNEL
            pHead->tp_len = 0;
            pHead->tp_status = TP_STATUS_KERNEL;

            //更新环形缓冲区的索引，指向下一个frame
            nIndex++;
            nIndex %= infos[numThreads].req1.tp_frame_nr;
        }

    }
}
/* get the MTU for the interface, or -1 on error */
int get_if_mtu(char* eth) {
    int fd = -1, sc, rc = -1;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        goto done;
    }

    strncpy(ifr.ifr_name, eth, sizeof(ifr.ifr_name));
    sc = ioctl(fd, SIOCGIFMTU, &ifr);
    if (sc < 0) {
        fprintf(stderr, "ioctl: %s\n", strerror(errno));
        goto done;
    }

    rc = ifr.ifr_mtu;

done:
    if (fd != -1) close(fd);
    return rc;
}
static void
compute_ring_block(int frame_size, unsigned* block_size, unsigned* frames_per_block)
{
    /* compute the minumum block size that will handle this frame.
     * The block has to be page size aligned.
     * The max block size allowed by the kernel is arch-dependent and
     * it's not explicitly checked here. */
    *block_size = getpagesize();
    while (*block_size < frame_size)
        *block_size <<= 1;

    *frames_per_block = *block_size / frame_size;
}
#define  PCAP_ERRBUF_SIZE 1024
int NICinit(int numThreads) {
    int i;
    int blocksize = 32768;
    printf("numThreads:%d\n", numThreads);
    for (i = 0; i < numThreads; i++) {
#ifdef HAVE_TPACKET3
        int ifindex = if_nametoindex(infos[i].NICname);//指定网络接口名称字符串作为参数；若该接口存在，则返回相应的索引，否则返回0
        printf("infos[numThreads].NICname%s\n", infos[i].NICname);
        infos[i].fd = socket(AF_PACKET, SOCK_RAW, 0);

        int version = TPACKET_V3;
        if (setsockopt(infos[i].fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
        {
            printf("Error setting TPACKET_V3, might need a newer kernel: %s", strerror(errno));
            return -1;
        }
        memset(&infos[i].req, 0, sizeof(infos[i].req));
        infos[i].req.tp_block_size = blocksize;
        infos[i].req.tp_block_nr = numThreads * 64;//线程数*64
        infos[i].req.tp_frame_size = getpagesize();//16384  4096的整数倍4倍
        infos[i].req.tp_frame_nr = (blocksize * infos[i].req.tp_block_nr) / infos[i].req.tp_frame_size;
        infos[i].req.tp_retire_blk_tov = 60;
        infos[i].req.tp_feature_req_word = 0;
        if (setsockopt(infos[i].fd, SOL_PACKET, PACKET_RX_RING, &infos[i].req, sizeof(infos[i].req)) < 0)
        {
            printf("Error setting PACKET_RX_RING: %s", strerror(errno));
            return -1;
        }
        struct packet_mreq      mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(infos[i].fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            printf("Error setting PROMISC: %s", strerror(errno));
            return -1;
        }
        infos[i].map = (uint8_t*)mmap(NULL, infos[i].req.tp_block_size * infos[i].req.tp_block_nr,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, infos[i].fd, 0);
        if (unlikely(infos[i].map == MAP_FAILED)) {
            printf("ERROR - MMap64 failure in reader_tpacketv3_init, %d: %s", errno, strerror(errno));
            return -1;
        }
        infos[i].rd = (struct iovec*)malloc(infos[i].req.tp_block_nr * sizeof(struct iovec));

        uint16_t j;
        for (j = 0; j < infos[i].req.tp_block_nr; j++) {
            infos[i].rd[j].iov_base = infos[i].map + (j * infos[i].req.tp_block_size);
            infos[i].rd[j].iov_len = infos[i].req.tp_block_size;
        }

        struct sockaddr_ll ll;//sockaddr_ll： 表示设备无关的物理层地址结构
        memset(&ll, 0, sizeof(ll));
        ll.sll_family = PF_PACKET;
        ll.sll_protocol = htons(ETH_P_ALL);
        ll.sll_ifindex = ifindex;

        if (bind(infos[i].fd, (struct sockaddr*)&ll, sizeof(ll)) < 0)
        {
            printf("Error binding %s: %s", "eno1", strerror(errno));
            return -1;
        }
#else
        int rc = -1, ec;
        int ifindex = if_nametoindex(infos[i].NICname);//指定网络接口名称字符串作为参数；若该接口存在，则返回相应的索引，否则返回0
        printf("infos[numThreads].NICname%s\n", infos[i].NICname);
        infos[i].fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        unsigned int val = TPACKET_V2;
        printf("TPACKET_V2:%d\n", TPACKET_V2);
        socklen_t len = sizeof(val);
        if (getsockopt(infos[i].fd, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
            if (errno == ENOPROTOOPT)
                return -11;
            char errbuf[1024];
            snprintf(errbuf, PCAP_ERRBUF_SIZE,
                "can't get TPACKET_V2 header len on socket %d: %d-%s",
                infos[i].fd, errno, strerror(errno));
            return -1;
        }
        //handle->md.tp_hdrlen = val;
        val = TPACKET_V2;
        if (setsockopt(infos[i].fd, SOL_PACKET, PACKET_VERSION, &val,
            sizeof(val)) < 0) {
            char errbuf[1024];
            snprintf(errbuf, PCAP_ERRBUF_SIZE,
                "can't activate TPACKET_V2 on socket %d: %d-%s",
                infos[i].fd, errno, strerror(errno));
            return -1;
        }
        unsigned j, ringsize, frames_per_block;
        struct tpacket_req req;

        /* Note that with large snapshot (say 64K) only a few frames
         * will be available in the ring even with pretty large ring size
         * (and a lot of memory will be unused).
         * The snap len should be carefully chosen to achive best
         * performance */
        int BUFFER_SIZE = 16384;
        int PER_PACKET_SIZE = 4096;
        infos[i].req1.tp_block_size = 16384;
        infos[i].req1.tp_block_nr = BUFFER_SIZE / infos[i].req1.tp_block_size;
        infos[i].req1.tp_frame_size = PER_PACKET_SIZE;
        infos[i].req1.tp_frame_nr = BUFFER_SIZE / infos[i].req1.tp_frame_size;
        infos[i].frames_per_block = infos[i].req1.tp_block_size / infos[i].req1.tp_frame_size;
        /* ask the kernel to create the ring */
    retry:
        if (setsockopt(infos[i].fd, SOL_PACKET, PACKET_RX_RING,
            (void*)&(infos[i].req1), sizeof((infos[i].req1)))) {
            /* try to reduce requested ring size to prevent memory failure */
            if ((errno == ENOMEM) && (infos[i].req1.tp_block_nr > 1)) {
                infos[i].req1.tp_frame_nr >>= 1;
                infos[i].req1.tp_frame_nr = (blocksize * infos[i].req1.tp_block_nr) / infos[i].req1.tp_frame_size;
                goto retry;
            }
            char errbuf[1024] = {};
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "can't create rx ring on "
                "packet socket %d: %d-%s", infos[i].fd, errno,
                strerror(errno));
            return -1;
        }
        struct sockaddr_ll addr;

        /* memory map the rx ring */
        printf("infos[i].fd:%d\n", infos[i].fd);
        ringsize = infos[i].req1.tp_block_nr * infos[i].req1.tp_block_size;
        infos[i].map = (char*)mmap(0, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, infos[i].fd, 0);
        if (infos[i].map == MAP_FAILED) {
            char errbuf[1024] = {};
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "can't mmap rx ring: %d-%s",
                errno, strerror(errno));
            printf("map错误");
            /* clear the allocated ring on error*/
            //destroy_ring(handle);
            return -1;
        }
        /* allocate a ring for each frame header pointer*/
        infos[i].buffer = (union thdr*)malloc(infos[i].req1.tp_frame_nr * sizeof(union thdr*));
        if (!infos[i].buffer) {
            return -1;
        }
        //struct sockaddr_ll addr;
        struct sockaddr_ll sl;
        memset(&sl, 0, sizeof(sl));
        sl.sll_family = AF_PACKET;
        sl.sll_protocol = htons(0x03);
        sl.sll_ifindex = ifindex;
        ec = bind(infos[i].fd, (struct sockaddr*)&sl, sizeof(sl));
        if (ec < 0) {
            fprintf(stderr, "socket: %s\n", strerror(errno));
            break;
        }
        /* fill the header ring with proper frame ptr*/
        int offset = 0;
        int m = 0;
        for (m = 0; m < infos[i].req1.tp_block_nr; ++m) {

            char* base = &infos[i].map[m * infos[i].req1.tp_block_size];
            for (j = 0; j < infos[i].frames_per_block; ++j, ++offset) {
                //RING_GET_FRAME(handle) = base;
                ((union thdr**)(infos[i].buffer))[offset] = (union thdr*)base;
                base += infos[i].req1.tp_frame_size;
            }
        }
        infos[i].bufsize = infos[i].req1.tp_frame_size;
        infos[i].offset = 0;
        return 1;
#endif

    }
}

//获取网卡信息，网卡名字，IP地址，返回值为网卡数量
int getconf_linux() {

    struct sockaddr_in* sin = NULL;
    struct ifaddrs* ifa = NULL, * ifList;
    string name[10];
    if (getifaddrs(&ifList) < 0)
    {
        return -1;
    }
    int i = 0;
    //找到所有网卡，并打印网卡相关信息
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            string ifname(ifa->ifa_name);
            name[i] = ifname;
            if (ifname == "lo")
                continue;
            strcpy(infos[i].NICname, ifa->ifa_name);
            printf("interfaceName: %s\n", infos[i].NICname);
            sin = (struct sockaddr_in*)ifa->ifa_addr;
            printf("ipAddress: %s\n", inet_ntoa(sin->sin_addr));
            infos[i].ip_addr = ((struct sockaddr_in*)&(sin))->sin_addr;
            printf("ipAddress: %s\n", inet_ntoa(infos[i].ip_addr));
            i++;
        }
    }
    return i;
}
#endif

void* NIC_ctl_thread(int infov) {
    //nps下发控制信息
    /*
    1 下发id,返回所有可用的网卡信息，默认开启gre转发，目的IP，在配置文件中获取，或者通过下发控制时携带目的IP
    */
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddr_len;
    int sockfd;
    char buf[MAXLINE];
    char str[INET_ADDRSTRLEN];
    int i, n;


#ifdef _WIN32
    SOCKADDR_IN   SenderAddr;
    int           SenderAddrSize;
    int           Ret;
    WSADATA       wsaData;
    SenderAddrSize = sizeof(SenderAddr);
    ink_set_thread_name("NIC_ctl_thread");
    if ((Ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)//使用2.2版本
    {
        printf("WSAStartup failed with error %d\n", Ret);
        return (void*)-1;
    }
    else
    {
        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)//检查实际初始化的是否就是2.2版本
        {
            printf("Error: not winsock 2.2\n");
            WSACleanup();
            return (void*)-1;
        }
    }
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
    {
        printf("socket failed with error %d\n", WSAGetLastError());
        WSACleanup();
        return (void*)-1;
    }

    memset(&servaddr, 0, sizeof(servaddr));//初始化为空
    servaddr.sin_family = AF_INET;//地址采用IPv4地址
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);//地址从主机字节顺序转换成网络字节顺序
    servaddr.sin_port = htons(SERV_PORT);//端口号从主机字节顺序转换成网络字节顺序
    /*将文件描述符sockfd和服务器地址绑定*/
    //bind(sockfd, (SOCKADDR*) & servaddr, sizeof(servaddr));
    if (bind(sockfd, (SOCKADDR*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR)
    {
        printf("bind failed with error %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return (void*)-1;
    }
#else
    /*打开一个网络通讯端口，分配一个文件描述符sockfd*/
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd <= 0) {
        printf("套接字创建失败\n");
        return (void*)1;
    }

    bzero(&servaddr, sizeof(servaddr));//初始化为空
    servaddr.sin_family = AF_INET;//地址采用IPv4地址
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);//地址从主机字节顺序转换成网络字节顺序
    servaddr.sin_port = htons(SERV_PORT);//端口号从主机字节顺序转换成网络字节顺序
    /*将文件描述符sockfd和服务器地址绑定*/
    if (0 > bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)))
    {
        printf("bind failed with error \n");
        return (void*)-1;
    }
#endif // !_WIN32  
    printf("等待连接...\n");
    while (1) {
        char data[MAXLINE] = { 0 };
        cliaddr_len = sizeof(cliaddr);
        /*接收client端传过来的的字符串，写入buf*/
        n = recvfrom(sockfd, data, MAXLINE, 0, (struct sockaddr*)&cliaddr, &cliaddr_len);
        if (n == -1) {
#ifdef _WIN32
            printf("recvfrom error%d\n", WSAGetLastError());
#endif // _WIN32          
            printf("recvfrom error\n");
            continue;
        }
        cJSON* json = 0, * json_NIC_id = 0, * json_NICstatus = 0, * json_number_of_NIC = 0;
        //解析数据包
        json = cJSON_Parse(data);
        //如果解析失败
        if (!json)//是否是jsonges
        {
            printf("Error Before:%s\n", cJSON_GetErrorPtr());
            continue;
        }
        else
        {
            char* jsonout = 0;
            jsonout = cJSON_Print(json);
            printf(jsonout);
            //收到的数据包格式：printf("收到的数据包  %s", cJSON_Print(json));
//数据格式："{\"sequence_number\":%d,\"uuid\":\"%s\",\"encap_key\":%d,\"NIC_name\":\"%s\",\"NIC_status\":%d}"
            json_number_of_NIC = cJSON_GetObjectItem(json, "number_of_NIC");
            if (json_number_of_NIC != NULL) {//修改某个网卡的转发状态,命令下发                                          
                cJSON* cJSON_islive, * cJSON_uuid;

                cJSON* cJSON_array, * cJSON_encap_key;
                cJSON_encap_key = cJSON_GetObjectItem(json, "encap_key");
                cJSON_array = cJSON_GetObjectItem(json, "array");
                int i = 0;

                if (cJSON_array != NULL) {
                    cJSON* cJSON_array_list = cJSON_array->child;
                    while (cJSON_array_list != NULL) {
                        cJSON* cJSON_NIC_status, * cJSON_NIC_name, * cJSON_NIC_ip, * cJSON_NIC_id;
                        cJSON_NIC_id = cJSON_GetObjectItem(cJSON_array_list, "NIC_id");
                        int NIC_id = 0;
                        if (cJSON_NIC_id->type == cJSON_Number) {
                            NIC_id = cJSON_NIC_id->valueint;
                            printf("cJSON_NIC_id->valueint:%d\n", cJSON_NIC_id->valueint);
                        }

                        cJSON_NIC_status = cJSON_GetObjectItem(cJSON_array_list, "NIC_status");
                        if (cJSON_NIC_status->type == cJSON_Number) {
                            infos[NIC_id].NICstatus = cJSON_NIC_status->valueint;
                        }

                        cJSON_NIC_name = cJSON_GetObjectItem(cJSON_array_list, "NIC_name");
                        if (0 == strcmp(infos[NIC_id].NICname, cJSON_NIC_name->valuestring))
                        {
                            printf("名字没有改变\n");
                        }
                        else {
                            printf("名字改变\n");
                        }

                        cJSON_NIC_ip = cJSON_GetObjectItem(cJSON_array_list, "NIC_ip");
                        if (0 == strcmp(infos[NIC_id].NICip, cJSON_NIC_ip->valuestring))
                        {
                            printf("ip没有改变\n");
                        }
                        else {
                            printf("ip改变\n");
                        }
                        infos[NIC_id].encap_key = cJSON_encap_key->valueint;
                        cJSON_array_list = cJSON_array_list->next;
                    }
                }

                //状态上传
                //到这里，返回json格式的网卡状态信息
                i = 0;
                cJSON* jsonroot = 0;

                //创建根节点对象
                jsonroot = cJSON_CreateObject();
                //向根节点加入数字对象
                infos[i].ip_addr.s_addr;

                //数组
                cJSON* pJsonArry;
                pJsonArry = cJSON_CreateArray();   /*创建数组*/
                for (i; i < numThreads; i++) {
                    cJSON* pJsonsub;
                    pJsonsub = cJSON_CreateObject();
                    cJSON_AddNumberToObject(pJsonsub, "NICstatus", json_NICstatus->valueint);      /* 给对象增加内容 */
                    cJSON_AddNumberToObject(pJsonsub, "encap_key", infos[i].encap_key);
                    cJSON_AddNumberToObject(pJsonsub, "NIC_id", i);
                    cJSON_AddStringToObject(pJsonsub, "NIC_ip", inet_ntoa(infos[i].ip_addr));
                    cJSON_AddStringToObject(pJsonsub, "NICname", infos[i].NICname);
                    cJSON_AddItemToArray(pJsonArry, pJsonsub);
                }
                cJSON_AddItemToObject(jsonroot, "array", pJsonArry);
                cJSON_AddBoolToObject(jsonroot, "result", cJSON_True);
                jsonout = cJSON_Print(jsonroot);

                n = sendto(sockfd, jsonout, strlen(jsonout), 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr));
                if (n == -1) {
                    printf("sendto error\n");
                }
                cJSON_Delete(jsonroot);
                //释放jsonout的空间
                free(jsonout);
            }
            else {//新的连接，获取所有网卡信息,并返回给客户端

                cJSON* json_encap_key = 0, * json_sequence_number;
                json_encap_key = cJSON_GetObjectItem(json, "encap_key");
                //如果类型是 数字
                if (json_encap_key->type == cJSON_Number)
                {
                    printf("encap_key:%d\n", json_encap_key->valueint);

                }
                json_sequence_number = cJSON_GetObjectItem(json, "sequence_number");
                //如果类型是 数字
                if (json_sequence_number->type == cJSON_Number)
                {
                    printf("json_sequence_number:%d\n", json_sequence_number->valueint);
                }
                json_NICstatus = cJSON_GetObjectItem(json, "NIC_status");
                //到这里，返回json格式的网卡状态信息
                int i = 0;
                cJSON* jsonroot = 0;
                char* jsonout = 0;
                //创建根节点对象
                jsonroot = cJSON_CreateObject();
                //向根节点加入数字对象
                infos[i].ip_addr.s_addr;

                //数组
                cJSON* pJsonArry;
                pJsonArry = cJSON_CreateArray();   /*创建数组*/
                for (i; i < numThreads; i++) {
                    cJSON* pJsonsub;
                    pJsonsub = cJSON_CreateObject();
                    cJSON_AddNumberToObject(pJsonsub, "NIC_status", json_NICstatus->valueint);      /* 给对象增加内容 */
                    cJSON_AddNumberToObject(pJsonsub, "NIC_id", i);
                    cJSON_AddStringToObject(pJsonsub, "NIC_ip", inet_ntoa(infos[i].ip_addr));
                    cJSON_AddStringToObject(pJsonsub, "NIC_name", infos[i].NICname);
                    cJSON_AddItemToArray(pJsonArry, pJsonsub);
                    infos[i].encap_key = json_encap_key->valueint;
                    infos[i].NICstatus = json_NICstatus->valueint;
                    infos[i].sequence_number = json_sequence_number->valueint;
                }
                cJSON_AddNumberToObject(jsonroot, "encap_key", json_encap_key->valueint);
                cJSON_AddNumberToObject(jsonroot, "sequence_number", json_sequence_number->valueint);
                cJSON_AddStringToObject(jsonroot, "uuid", infos[0].uuid);
                cJSON_AddItemToObject(jsonroot, "array", pJsonArry);
                cJSON_AddBoolToObject(jsonroot, "result", cJSON_True);
                jsonout = cJSON_Print(jsonroot);
                n = sendto(sockfd, jsonout, strlen(jsonout), 0, (struct sockaddr*)&cliaddr, sizeof(cliaddr));
                if (n == -1) {
                    printf("sendto error\n");
                }
                cJSON_Delete(jsonroot);
                //释放jsonout的空间
                free(jsonout);
            }
        }
        //释放json对象的空间
        cJSON_Delete(json);
        printf("NIC_ctl_thread");
    }
    //close(sockfd);
}
int get_ini() {
    dictionary* ini;
    int n = 0;
    char* str;
    char* buffer;
    if ((buffer = getcwd(NULL, 0)) == NULL)
    {
        perror("getcwd error");
    }
    else
    {
        printf("buffer=%s\n", buffer);
    }
    ini = iniparser_load(config_file);//parser the file
    if (ini == NULL)
    {
        fprintf(stderr, "can not open %s", "config.ini");
        return -1;
    }
    printf("dictionary obj:\n");
    iniparser_dump(ini, stderr);//save ini to stderr
    printf("\n%s:\n", iniparser_getsecname(ini, 0));//get section name
    str = iniparser_getstring(ini, "CAT:gredstip", (char*)"null");
    if (str == NULL) {
        printf("配置文件缺少gredstip\n");
        return -1;
    }
    strcpy(gredstip, str);
    gre_ip_int = ipTint(str);
    str = iniparser_getstring(ini, "CAT:uuid", (char*)"null");
    if (str == NULL) {
        printf("配置文件缺少uuid\n");
        return -1;
    }
    printf("uuid : %s\n", str);
    strcpy(uuid, str);
    strcpy(infos[0].uuid, uuid);
    int key;
    key = iniparser_getint(ini, "CAT:key", 0x12345678);
    infos[0].encap_key = key;
    iniparser_freedict(ini);//free dirctionary obj
    return 0;
}

int main1() {
    //获取网卡信息，网卡名字，ip,mac ，，返回值为网卡数量
   // GMainLoop* mainLoop;
   // mainLoop = g_main_loop_new(NULL, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    numThreads = getconf_windows();//获取windows开启网卡数量
#else
    numThreads = getconf_linux();
#endif
    
    int re ;
    re = get_ini();//获取配置文件
    if (re < 0)
    {
        exit(EXIT_FAILURE);
    }
    //被动接收控制信息
    char name[32];
    snprintf(name, sizeof(name), "NIC_response_thread");
    //g_thread_unref(g_thread_new(name, &NIC_ctl_thread, (gpointer)(long)0));//控制下发线程,网卡状态上传  被动接收控制信息,暂时弃用
    std::thread thn(NIC_ctl_thread, 0);
    //初始化抓包套接字
    ink_set_thread_name("mainthread");
#ifndef _WIN32
    int ret = NICinit(numThreads);
    if (ret < 0) {
        printf("网卡初始化失败\n");
        return -1;
    }
#endif // !_WIN32
    //初始化发包套接字
    sock = NICsendsock();
    if (sock <= 0) {
        printf("转发套接字创建失败\n");
        exit(EXIT_FAILURE);
    }
    //开启线程抓包和转发
    int i = 0;
    for (; i < numThreads; i++) {
#ifdef _WIN32
        std::thread th(reader_windows_thread, i);
        th.detach();
#else  
#ifdef  HAVE_TPACKET3
        std::thread th(reader_tpacketv3_thread, i);
        th.detach();
#else
        std::thread th(reader_tpacketv2_thread, i);
        th.detach();
#endif // DEBUG

#endif   
    }
    thn.join();
    return 0;
}
 
