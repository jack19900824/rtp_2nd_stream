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

//ΪNALU_t�ṹ������ڴ�ռ�
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

//�ͷ�
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
    if(Buf[0]!=0 || Buf[1]!=0 || Buf[2] !=1) return 0; //�ж��Ƿ�Ϊ0x000001,����Ƿ���1
    else return 1;
}

static int FindStartCode3 (const unsigned char *Buf)
{
    if(Buf[0]!=0 || Buf[1]!=0 || Buf[2] !=0 || Buf[3] !=1) return 0;//�ж��Ƿ�Ϊ0x00000001,����Ƿ���1
    else return 1;
}

int rtpnum = 0;

//���NALU���Ⱥ�TYPE
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

	info2 = FindStartCode2 (bs_addr);//�ж��Ƿ�Ϊ0x000001
    if(info2 != 1) {
		info3 = FindStartCode3 (bs_addr);//�ж��Ƿ�Ϊ0x00000001
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
    	memcpy(nalu->buf, &bs_addr[nalu->startcodeprefix_len], nalu->len); //����һ������NALU����������ʼǰ׺0x000001��0x00000001
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

        memset(sendbuf, 0, 1500); //���sendbuf����ʱ�Ὣ�ϴε�ʱ�����գ������Ҫts_current�������ϴε�ʱ���ֵ
        //rtp�̶���ͷ��Ϊ12�ֽ�,�þ佫sendbuf[0]�ĵ�ַ����rtp_hdr���Ժ��rtp_hdr��д�������ֱ��д��sendbuf��
        rtp_hdr =(RTP_FIXED_HEADER*)&sendbuf[0];

        //����RTP HEADER��
        rtp_hdr->version = 2;   //�汾�ţ��˰汾�̶�Ϊ2
        rtp_hdr->marker  = 0;   //��־λ���ɾ���Э��涨��ֵ��
        rtp_hdr->payload = H264;//�������ͺţ�
        rtp_hdr->ssrc    = htonl(10);//���ָ��Ϊ10�������ڱ�RTP�Ự��ȫ��Ψһ

        //��һ��NALUС��1400�ֽڵ�ʱ�򣬲���һ����RTP������
        if(n->len <= UDP_MAX_SIZE) {
            //����rtp M λ
            rtp_hdr->marker = 1;
            rtp_hdr->seq_no = htons(seq_num++); //���кţ�ÿ����һ��RTP����1

            //����NALU HEADER,�������HEADER����sendbuf[12]
            nalu_hdr = (NALU_HEADER*)&sendbuf[12]; //��sendbuf[12]�ĵ�ַ����nalu_hdr��֮���nalu_hdr��д��ͽ�д��sendbuf�У�
            nalu_hdr->F = n->forbidden_bit;
            nalu_hdr->NRI = n->nal_reference_idc >> 5; //��Ч������n->nal_reference_idc�ĵ�6��7λ����Ҫ����5λ���ܽ���ֵ����nalu_hdr->NRI��
            nalu_hdr->TYPE = n->nal_unit_type;

            nalu_payload = &sendbuf[13];//ͬ��sendbuf[13]����nalu_payload
            memcpy(nalu_payload, n->buf+1, n->len-1);//ȥ��naluͷ��naluʣ������д��sendbuf[13]��ʼ���ַ�����

            rtp_hdr->timestamp = htonl(ts_current);
            bytes = n->len + 13;  //���sendbuf�ĳ���,Ϊnalu�ĳ��ȣ�����NALUͷ����ȥ��ʼǰ׺������rtp_header�Ĺ̶�����12�ֽ�
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

            //���͵�һ����FU��S=1��E=0��R=0

            rtp_hdr->seq_no = htons(seq_num++); //���кţ�ÿ����һ��RTP����1
            //����rtp M λ��
            rtp_hdr->marker = 0;
            //����FU INDICATOR,�������HEADER����sendbuf[12]
            fu_ind = (FU_INDICATOR*)&sendbuf[12]; //��sendbuf[12]�ĵ�ַ����fu_ind��֮���fu_ind��д��ͽ�д��sendbuf�У�
            fu_ind->F = n->forbidden_bit;
            fu_ind->NRI = n->nal_reference_idc>>5;
            fu_ind->TYPE = 28;

            //����FU HEADER,�������HEADER����sendbuf[13]
            fu_hdr = (FU_HEADER*)&sendbuf[13];
            fu_hdr->S = 1;
            fu_hdr->E = 0;
            fu_hdr->R = 0;
            fu_hdr->TYPE = n->nal_unit_type;

            nalu_payload = &sendbuf[14];//ͬ��sendbuf[14]����nalu_payload
            memcpy(nalu_payload, n->buf+1, UDP_MAX_SIZE);//ȥ��NALUͷ
            bytes = (UDP_MAX_SIZE+14);//���sendbuf�ĳ���,Ϊnalu�ĳ��ȣ���ȥ��ʼǰ׺��NALUͷ������rtp_header��fu_ind��fu_hdr�Ĺ̶�����14�ֽ�

            send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));

			DBG_MSG("2 bytes:%d, send_size:%d\n", bytes, send_size);
            //�����м��FU��S=0��E=0��R=0
            for(packetIndex=2; packetIndex<packetNum; packetIndex++) {
                rtp_hdr->seq_no = htons(seq_num++); //���кţ�ÿ����һ��RTP����1

                //����rtp M λ��
                rtp_hdr->marker = 0;
                //����FU INDICATOR,�������HEADER����sendbuf[12]
                fu_ind = (FU_INDICATOR*)&sendbuf[12]; //��sendbuf[12]�ĵ�ַ����fu_ind��֮���fu_ind��д��ͽ�д��sendbuf�У�
                fu_ind->F = n->forbidden_bit;
                fu_ind->NRI = n->nal_reference_idc>>5;
                fu_ind->TYPE = 28;

                //����FU HEADER,�������HEADER����sendbuf[13]
                fu_hdr =(FU_HEADER*)&sendbuf[13];
                fu_hdr->S = 0;
                fu_hdr->E = 0;
                fu_hdr->R = 0;
                fu_hdr->TYPE = n->nal_unit_type;

                nalu_payload=&sendbuf[14];//ͬ��sendbuf[14]�ĵ�ַ����nalu_payload
                memcpy(nalu_payload,n->buf+(packetIndex-1)*UDP_MAX_SIZE+1,UDP_MAX_SIZE);//ȥ����ʼǰ׺��naluʣ������д��sendbuf[14]��ʼ���ַ�����
                bytes = UDP_MAX_SIZE+14;//���sendbuf�ĳ���,Ϊnalu�ĳ��ȣ���ȥԭNALUͷ������rtp_header��fu_ind��fu_hdr�Ĺ̶�����14�ֽ�
                send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));
                DBG_MSG("3 bytes:%d, send_size:%d\n", bytes, send_size);

            }

            //�������һ����FU��S=0��E=1��R=0

            rtp_hdr->seq_no = htons(seq_num ++);
            //����rtp M λ����ǰ����������һ����Ƭʱ��λ��1
            rtp_hdr->marker = 1;
            //����FU INDICATOR,�������HEADER����sendbuf[12]
            fu_ind = (FU_INDICATOR*)&sendbuf[12]; //��sendbuf[12]�ĵ�ַ����fu_ind��֮���fu_ind��д��ͽ�д��sendbuf�У�
            fu_ind->F = n->forbidden_bit;
            fu_ind->NRI = n->nal_reference_idc>>5;
            fu_ind->TYPE = 28;

            //����FU HEADER,�������HEADER����sendbuf[13]
            fu_hdr = (FU_HEADER*)&sendbuf[13];
            fu_hdr->S = 0;
            fu_hdr->E = 1;
            fu_hdr->R = 0;
            fu_hdr->TYPE = n->nal_unit_type;

            nalu_payload = &sendbuf[14];//ͬ��sendbuf[14]�ĵ�ַ����nalu_payload
            memcpy(nalu_payload, n->buf+(packetIndex-1)*UDP_MAX_SIZE+1, lastPackSize-1);//��nalu���ʣ���-1(ȥ����һ���ֽڵ�NALUͷ)�ֽ�����д��sendbuf[14]��ʼ���ַ�����
            bytes = lastPackSize-1+14;//���sendbuf�ĳ���,Ϊʣ��nalu�ĳ���l-1����rtp_header��FU_INDICATOR,FU_HEADER������ͷ��14�ֽ�
            send_size = sendto(sockfd, sendbuf, bytes, 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr));
            DBG_MSG("4 bytes:%d, send_size:%d\n", bytes, send_size);
        }
    }

    FreeNALU(n);
    close(sockfd);
    return 0;
}

