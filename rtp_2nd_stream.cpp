#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <memory.h>
#include <net/if.h>
#include <sys/time.h>
#include "amba_stream_reader.h"
#include "h264.h"

// #define _DEBUG_ENABLE

#ifdef _DEBUG_ENABLE
#define DBG_MSG printf
#else
#define DBG_MSG
#endif

#define  UDP_MAX_SIZE 1400

#define  MAX_VIDEO_FIFO_CACHE_SIZE_LIVE (512 << 10) // 512KB
#define  NALU_TYPE_IDR  5
#define  NALU_TYPE_NON_IDR 1

typedef struct
{
    int32_t startcodeprefix_len;      //! 4 for parameter sets and first slice in picture, 3 for everything else (suggested)
    uint32_t len;                 //! Length of the NAL unit (Excluding the start code, which does not belong to the NALU)
    uint32_t max_size;            //! Nal Unit Buffer size
    int32_t forbidden_bit;            //! should be always FALSE
    int32_t nal_reference_idc;        //! NALU_PRIORITY_xxxx
    int32_t nal_unit_type;            //! NALU_TYPE_xxxx
    char *buf;                    //! contains the first byte followed by the EBSP
    uint16_t lost_packets;  //! true, if packet loss is detected
} NALU_t;

static int32_t info2=0, info3=0;
static RTP_FIXED_HEADER *rtp_hdr;

static NALU_HEADER     *nalu_hdr;
static FU_INDICATOR    *fu_ind;
static FU_HEADER       *fu_hdr;

//为NALU_t结构体分配内存空间
NALU_t *AllocNALU(int buffersize)
{
    NALU_t *n;

    if ((n = (NALU_t*)calloc (1, sizeof (NALU_t))) == NULL)
    {
        DBG_MSG("AllocNALU: n");
        exit(0);
    }

    n->max_size = buffersize;

    if ((n->buf = (char*)calloc (buffersize, sizeof (char))) == NULL)
    {
        free (n);
        DBG_MSG ("AllocNALU: n->buf");
        exit(0);
    }

    return n;
}

//释放
void FreeNALU(NALU_t *n)
{
    if (n)
    {
        if (n->buf)
        {
            free(n->buf);
            n->buf=NULL;
        }
        free (n);
    }
}

static int FindStartCode2 (const unsigned char *Buf)
{
    if(Buf[0]!=0 || Buf[1]!=0 || Buf[2] !=1) return 0; //判断是否为0x000001,如果是返回1
    else return 1;
}

static int FindStartCode3 (const unsigned char *Buf)
{
    if(Buf[0]!=0 || Buf[1]!=0 || Buf[2] !=0 || Buf[3] !=1) return 0;//判断是否为0x00000001,如果是返回1
    else return 1;
}

int rtpnum = 0;

//输出NALU长度和TYPE
void dump(NALU_t *n)
{
    if (!n)return;
    DBG_MSG("%3d, len: %6d  ",rtpnum++, n->len);
    DBG_MSG("nal_unit_type: %x\n", n->nal_unit_type);
}

uint32_t current_pos = 0;

int read_one_nalu(NALU_t *nalu, const unsigned char* bs_addr, uint32_t bs_size)
{
	uint32_t pos = 0;

	info2 = FindStartCode2 (bs_addr);//判断是否为0x000001
    if(info2 != 1) {
		info3 = FindStartCode3 (bs_addr);//判断是否为0x00000001
        if (info3 != 1) {
        	return -1;
        } else {
			pos = 4;
            nalu->startcodeprefix_len = 4;
        }
    } else {
		pos = 3;
        nalu->startcodeprefix_len = 3;
    }

	nalu->nal_unit_type = bs_addr[nalu->startcodeprefix_len]&0x1f;
	// DBG_MSG("nalu type:%d\n", nalu->nal_unit_type);

#if 0
	if (nalu->nal_unit_type == NALU_TYPE_IDR || nalu->nal_unit_type == NALU_TYPE_NON_IDR) {
		/* IDR slice and non IDR slice, last nalu in this frame, get the remain bitstream */
		nalu->len = bs_size - nalu->startcodeprefix_len;
        memcpy(nalu->buf, &bs_addr[nalu->startcodeprefix_len], nalu->len);
        nalu->forbidden_bit = nalu->buf[0] & 0x80;
        nalu->nal_reference_idc = nalu->buf[0] & 0x60; // 2 bit
		current_pos = 0;
        return 1;
	}
#endif

	/* find next startcode */
	while (pos <= (bs_size - 3)) {
		info2 = FindStartCode2(&(bs_addr[pos]));
		if (info2 != 1) {
			info3 = FindStartCode3(&(bs_addr[pos]));
			if (info3 != 1) {
				pos++;
				continue;
			}
		}

		nalu->len = pos - nalu->startcodeprefix_len;
    	memcpy(nalu->buf, &bs_addr[nalu->startcodeprefix_len], nalu->len); //拷贝一个完整NALU，不拷贝起始前缀0x000001或0x00000001
    	nalu->forbidden_bit = nalu->buf[0] & 0x80;
    	nalu->nal_reference_idc = nalu->buf[0] & 0x60;
    	current_pos += pos;
    	return 0;
	}

	/* didn't find startcode, maybe reach the end */
	nalu->len = bs_size - nalu->startcodeprefix_len;
    memcpy(nalu->buf, &bs_addr[nalu->startcodeprefix_len], nalu->len);
    nalu->forbidden_bit = nalu->buf[0] & 0x80;
    nalu->nal_reference_idc = nalu->buf[0] & 0x60; // 2 bit
	current_pos = 0;
    return 1;
}


struct sockaddr_in serveraddr;
int sockfd;
int sin_size;

int main(int argc, char* argv[])
{
    unsigned int addr;
    NALU_t *n;
    char* nalu_payload;
    char dest_ip_addr[64] = {0};
    char sendbuf[1500];

    uint16_t seq_num = 0;
    int bytes = 0;
    uint32_t timestamp_increse = 0, ts_current = 0;

    timestamp_increse = 3003;

	if (argc == 1) {
		strncpy(dest_ip_addr, DEST_IP, sizeof(dest_ip_addr));
	} else if (argc == 2) {
		strncpy(dest_ip_addr, argv[1], sizeof(dest_ip_addr));
	} else {
		printf("usage: %s [ipaddr]\n", argv[0]);
		exit(1);
	}

	DBG_MSG("dest ip addr:%s\n", dest_ip_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd == -1) {
		perror("socket");
        exit(1);
    }

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(DEST_PORT);
    inet_pton(AF_INET, DEST_IP, &addr);
    serveraddr.sin_addr.s_addr = addr;
    bzero(&(serveraddr.sin_zero), 8);

    n = AllocNALU(8000000);

	if (stream_reader_init() != 0) {
		perror("stream reader init failed\n");
		exit(1);
	}

	if (stream_reader_start() != 0) {
		perror("stream reader start failed\n");
		exit(1);
	}

	frame_info_s frame_info = {0};
	stream_reader_get_frame_block(&frame_info);

	int eof = 0;
	ssize_t send_size = 0;
	unsigned long long prev_pts = 0;

    while(1) {
    	if (eof) {
			stream_reader_get_frame_block(&frame_info);

			prev_pts = frame_info.pts;
			ts_current = ts_current + timestamp_increse;
			DBG_MSG("get new frame, size:%d, pts:%ld\n", frame_info.frame_size, frame_info.pts);
    	}

		// DBG_MSG("frame size:%ld, cur_pos:%ld\n", frame_info.frame_size, current_pos);
        eof = read_one_nalu(n, (const unsigned char*)frame_info.pFrame_addr + current_pos, frame_info.frame_size - current_pos);
		if (eof < 0) {
			perror("read one nalu failed\n");
			exit(1);
		}

		DBG_MSG("nalu type:%d, nalu len:%d\n",n->nal_unit_type, n->len);

		if (n->nal_unit_type < 6 || n->nal_unit_type == 7 || n->nal_unit_type == 8) {
			// do nothing
		} else {
			continue;
		}

        memset(sendbuf, 0, 1500); //清空sendbuf；此时会将上次的时间戳清空，因此需要ts_current来保存上次的时间戳值
        //rtp固定包头，为12字节,该句将sendbuf[0]的地址赋给rtp_hdr，以后对rtp_hdr的写入操作将直接写入sendbuf。
        rtp_hdr =(RTP_FIXED_HEADER*)&sendbuf[0];

        //设置RTP HEADER，
        rtp_hdr->version = 2;   //版本号，此版本固定为2
        rtp_hdr->marker  = 0;   //标志位，由具体协议规定其值。
        rtp_hdr->payload = H264;//负载类型号，
        rtp_hdr->ssrc    = htonl(10);//随机指定为10，并且在本RTP会话中全局唯一

        //当一个NALU小于1400字节的时候，采用一个单RTP包发送
        if(n->len <= UDP_MAX_SIZE) {
            //设置rtp M 位
            rtp_hdr->marker = 1;
            rtp_hdr->seq_no = htons(seq_num++); //序列号，每发送一个RTP包增1

            //设置NALU HEADER,并将这个HEADER填入sendbuf[12]
            nalu_hdr = (NALU_HEADER*)&sendbuf[12]; //将sendbuf[12]的地址赋给nalu_hdr，之后对nalu_hdr的写入就将写入sendbuf中；
            nalu_hdr->F = n->forbidden_bit;
            nalu_hdr->NRI = n->nal_reference_idc >> 5; //有效数据在n->nal_reference_idc的第6，7位，需要右移5位才能将其值赋给nalu_hdr->NRI。
            nalu_hdr->TYPE = n->nal_unit_type;

            nalu_payload = &sendbuf[13];//同理将sendbuf[13]赋给nalu_payload
            memcpy(nalu_payload, n->buf+1, n->len-1);//去掉nalu头的nalu剩余内容写入sendbuf[13]开始的字符串。

            rtp_hdr->timestamp = htonl(ts_current);
            bytes = n->len + 13;  //获得sendbuf的长度,为nalu的长度（包含NALU头但除去起始前缀）加上rtp_header的固定长度12字节
            send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));
            DBG_MSG("1 bytes:%d, send_size:%d\n", bytes, send_size);
        } else {
            int packetNum = n->len/UDP_MAX_SIZE;
            if (n->len%UDP_MAX_SIZE != 0) {
                packetNum++;
            }

            int lastPackSize = n->len - (packetNum-1)*UDP_MAX_SIZE;
            int packetIndex = 1 ;

            rtp_hdr->timestamp = htonl(ts_current);

            //发送第一个的FU，S=1，E=0，R=0

            rtp_hdr->seq_no = htons(seq_num++); //序列号，每发送一个RTP包增1
            //设置rtp M 位；
            rtp_hdr->marker = 0;
            //设置FU INDICATOR,并将这个HEADER填入sendbuf[12]
            fu_ind = (FU_INDICATOR*)&sendbuf[12]; //将sendbuf[12]的地址赋给fu_ind，之后对fu_ind的写入就将写入sendbuf中；
            fu_ind->F = n->forbidden_bit;
            fu_ind->NRI = n->nal_reference_idc>>5;
            fu_ind->TYPE = 28;

            //设置FU HEADER,并将这个HEADER填入sendbuf[13]
            fu_hdr = (FU_HEADER*)&sendbuf[13];
            fu_hdr->S = 1;
            fu_hdr->E = 0;
            fu_hdr->R = 0;
            fu_hdr->TYPE = n->nal_unit_type;

            nalu_payload = &sendbuf[14];//同理将sendbuf[14]赋给nalu_payload
            memcpy(nalu_payload, n->buf+1, UDP_MAX_SIZE);//去掉NALU头
            bytes = (UDP_MAX_SIZE+14);//获得sendbuf的长度,为nalu的长度（除去起始前缀和NALU头）加上rtp_header，fu_ind，fu_hdr的固定长度14字节

            send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));

			DBG_MSG("2 bytes:%d, send_size:%d\n", bytes, send_size);
            //发送中间的FU，S=0，E=0，R=0
            for(packetIndex=2; packetIndex<packetNum; packetIndex++) {
                rtp_hdr->seq_no = htons(seq_num++); //序列号，每发送一个RTP包增1

                //设置rtp M 位；
                rtp_hdr->marker = 0;
                //设置FU INDICATOR,并将这个HEADER填入sendbuf[12]
                fu_ind = (FU_INDICATOR*)&sendbuf[12]; //将sendbuf[12]的地址赋给fu_ind，之后对fu_ind的写入就将写入sendbuf中；
                fu_ind->F = n->forbidden_bit;
                fu_ind->NRI = n->nal_reference_idc>>5;
                fu_ind->TYPE = 28;

                //设置FU HEADER,并将这个HEADER填入sendbuf[13]
                fu_hdr =(FU_HEADER*)&sendbuf[13];
                fu_hdr->S = 0;
                fu_hdr->E = 0;
                fu_hdr->R = 0;
                fu_hdr->TYPE = n->nal_unit_type;

                nalu_payload=&sendbuf[14];//同理将sendbuf[14]的地址赋给nalu_payload
                memcpy(nalu_payload,n->buf+(packetIndex-1)*UDP_MAX_SIZE+1,UDP_MAX_SIZE);//去掉起始前缀的nalu剩余内容写入sendbuf[14]开始的字符串。
                bytes = UDP_MAX_SIZE+14;//获得sendbuf的长度,为nalu的长度（除去原NALU头）加上rtp_header，fu_ind，fu_hdr的固定长度14字节
                send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));
                DBG_MSG("3 bytes:%d, send_size:%d\n", bytes, send_size);

            }

            //发送最后一个的FU，S=0，E=1，R=0

            rtp_hdr->seq_no = htons(seq_num ++);
            //设置rtp M 位；当前传输的是最后一个分片时该位置1
            rtp_hdr->marker = 1;
            //设置FU INDICATOR,并将这个HEADER填入sendbuf[12]
            fu_ind = (FU_INDICATOR*)&sendbuf[12]; //将sendbuf[12]的地址赋给fu_ind，之后对fu_ind的写入就将写入sendbuf中；
            fu_ind->F = n->forbidden_bit;
            fu_ind->NRI = n->nal_reference_idc>>5;
            fu_ind->TYPE = 28;

            //设置FU HEADER,并将这个HEADER填入sendbuf[13]
            fu_hdr = (FU_HEADER*)&sendbuf[13];
            fu_hdr->S = 0;
            fu_hdr->E = 1;
            fu_hdr->R = 0;
            fu_hdr->TYPE = n->nal_unit_type;

            nalu_payload = &sendbuf[14];//同理将sendbuf[14]的地址赋给nalu_payload
            memcpy(nalu_payload, n->buf+(packetIndex-1)*UDP_MAX_SIZE+1, lastPackSize-1);//将nalu最后剩余的-1(去掉了一个字节的NALU头)字节内容写入sendbuf[14]开始的字符串。
            bytes = lastPackSize-1+14;//获得sendbuf的长度,为剩余nalu的长度l-1加上rtp_header，FU_INDICATOR,FU_HEADER三个包头共14字节
            send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));
            DBG_MSG("4 bytes:%d, send_size:%d\n", bytes, send_size);
        }
    }

    FreeNALU(n);
    close(sockfd);
    return 0;
}

