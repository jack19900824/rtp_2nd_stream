#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "pthread.h"
#include "AmbaFrameInfo.h"
#include "AmbaNetFifo.h"
#include "amba_stream_reader.h"

#define NG (-1)
#define OK (0)

#define CACHE_FRAME_NUM  (20480) // 20k frames

// #define _DBG_ENABLE
#ifdef _DBG_ENABLE
#define dbg_msg    printf
#else
#define dbg_msg
#endif

typedef struct _rb_s_ {
    uint32_t wp;
    uint32_t rp;
    uint32_t size;
    frame_info_s* head;
} rb_s;

static frame_info_s* queue_buf_ptr = NULL;
static rb_s rb = {0};
static int event_hdl = -1;
static AMBA_NETFIFO_HDLR_s* pfifo_hdl = NULL;
static pthread_t g_tid_netfifo;
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qready = PTHREAD_COND_INITIALIZER;

#define RB_FULL()  (((rb.wp + 1) % rb.size) == rb.rp)
#define RB_EMPTY()  (rb.rp == rb.wp)

static inline void  _rb_init(const frame_info_s* buffer_ptr, uint32_t rb_size)
{
    pthread_mutex_lock(&qlock);
    rb.wp = 0;
    rb.rp = 0;
    rb.size = rb_size;
    rb.head = (frame_info_s*)buffer_ptr;
    pthread_mutex_unlock(&qlock);
}

static inline void  _rb_in(frame_info_s* frame_info)
{
    dbg_msg("in wp:%d, rp:%d, size:%d\n", rb.wp, rb.rp, rb.size);
    pthread_mutex_lock(&qlock);
    if (RB_FULL()) {
        dbg_msg("rb full, drop this frame\n");
    } else {
        memcpy(&rb.head[rb.wp], frame_info, sizeof(frame_info_s));
        rb.wp++;
        rb.wp = (rb.wp % rb.size);
    }
    pthread_mutex_unlock(&qlock);
    pthread_cond_signal(&qready);
}

static inline void  _rb_out(frame_info_s* frame_info)
{
    dbg_msg("%s wp:%d, rp:%d, size:%d\n", __func__, rb.wp, rb.rp, rb.size);
    pthread_mutex_lock(&qlock);
    if (RB_EMPTY()) {
        dbg_msg("rb empty\n");
        memset(frame_info, 0, sizeof(frame_info_s));
    } else {
        memcpy(frame_info, &rb.head[rb.rp], sizeof(frame_info_s));
        rb.rp++;
        rb.rp = (rb.rp % rb.size);
    }
    pthread_mutex_unlock(&qlock);
}

static inline void  _rb_out_block(frame_info_s* frame_info)
{
    dbg_msg("%s wp:%d, rp:%d, size:%d\n", __func__, rb.wp, rb.rp, rb.size);
    if (RB_EMPTY()) {
        pthread_cond_wait(&qready, &qlock);
    }

    memcpy(frame_info, &rb.head[rb.rp], sizeof(frame_info_s));
    rb.rp++;
    rb.rp = (rb.rp % rb.size);

    pthread_mutex_unlock(&qlock);
}


static int stream_reader_frame_ready_cb(void *hdlr, unsigned int event, void* info, void* user_data)
{
    int ret = -1;
    frame_info_s frame_info = {0};
    AMBA_NETFIFO_PEEKENTRY_ARG_s    entry = {0};
    AMBA_NETFIFO_BITS_DESC_s        desc = {0};
    AMBA_NETFIFO_REMOVEENTRY_ARG_s r_entry = {0};

    dbg_msg("event:%d\n", event);

    switch (event) {
    case AMBA_NETFIFO_EVENT_DATA_READY:
        entry.fifo = pfifo_hdl;
        entry.distanceToLastEntry = 0;
        ret = AmbaNetFifo_PeekEntry(&entry, &desc);
        if(ret != 0){
            printf("AmpFifo_PeekEntry failed:%d\n", ret);
            return NG;
        }

        frame_info.pts = desc.Pts;
        frame_info.frame_size = desc.Size;
        frame_info.pFrame_addr = desc.StartAddr;
        frame_info.frame_type = desc.Type;
        frame_info.seq_num = desc.SeqNum;
        _rb_in(&frame_info);

        r_entry.EntriesToBeRemoved = 1;
        r_entry.fifo = pfifo_hdl;
        AmbaNetFifo_RemoveEnrty(&r_entry);
        break;
    case AMBA_NETFIFO_EVENT_DATA_EOS:
        frame_info.frame_size = AMBA_NETFIFO_MARK_EOS;
        _rb_in(&frame_info);
        break;

    }

    return OK;
}

static int stream_reader_ctrl_event_cb(unsigned int cmd, unsigned int param1, unsigned int param2, void *user_data)
{
    dbg_msg("cmd:%d\n", cmd);
    return OK;
}

int stream_reader_get_frame(frame_info_s* frame_info)
{
    if (frame_info == NULL) {
        printf("%s frame_info is NULL", __func__);
        return NG;
    }

    _rb_out(frame_info);
    return OK;
}

int stream_reader_get_frame_block(frame_info_s* frame_info)
{
    if (frame_info == NULL) {
        printf("%s frame_info is NULL", __func__);
        return NG;
    }

    _rb_out_block(frame_info);
    return OK;
}

int stream_reader_start(void)
{
    AMBA_NETFIFO_CFG_s cfg = {0};

    AMBA_NETFIFO_MEDIA_STREAMITEM_LIST_s stream_list = {0};
    int ret = AmbaNetFifo_GetMediaStreamIDList(&stream_list);
    if( ret < 0 ) {
        printf("Fail to do AmbaNetFifo_GetMediaStreamIDList()\n");
        return NG;
    }

    int streamIndex = 0;
    for (streamIndex = 0; streamIndex < stream_list.Amount; streamIndex++) {
        if (stream_list.StreamItemList[streamIndex].Active == 0) {
            dbg_msg("%s: Checking %s .. inactive\n", __FUNCTION__, stream_list.StreamItemList[streamIndex].Name);
            continue;
        } else {
            break;  // use the first active stream index
        }
    }

    AMBA_NETFIFO_MOVIE_INFO_CFG_s movie_info;
    memset(&movie_info, 0, sizeof(AMBA_NETFIFO_MOVIE_INFO_CFG_s));
    ret = AmbaNetFifo_GetMediaInfo(streamIndex, &movie_info);
    if (ret < 0) {
        printf("AmbaNetFifo_GetMediaInfo failed\n");
        return NG;
    }

    dbg_msg("nTrack:%d\n", movie_info.nTrack);
    if (movie_info.nTrack == 0) {
        printf("no track active\n");
        return NG;
    }

    int track_idx;
    AMBA_NETFIFO_MEDIA_TRACK_CFG_s *pAct_track_info = NULL;
    for(track_idx = 0; track_idx < movie_info.nTrack; track_idx++) {
        if( movie_info.Track[track_idx].nTrackType != AMBA_NETFIFO_MEDIA_TRACK_TYPE_VIDEO ||
            movie_info.Track[track_idx].hCodec == NULL ) {
            continue;
        }

        pAct_track_info = &movie_info.Track[track_idx];
        break;
    }

    if (pAct_track_info == NULL) {
        printf("pAct_track_info NULL\n");
        return NG;
    }

    AmbaNetFifo_GetDefaultCFG(&cfg);
    cfg.hCodec     = pAct_track_info->hCodec;
    cfg.cbEvent    = (unsigned int)event_hdl;
    cfg.NumEntries = 256;
    cfg.IsVirtual  = 1;
    pfifo_hdl = (AMBA_NETFIFO_HDLR_s*)AmbaNetFifo_Create(&cfg);
    if (pfifo_hdl == NULL) {
        printf("create net fifo failed\n");
        return NG;
    }

    return AmbaNetFifo_ReportStatus(AMBA_NETFIFO_STATUS_START);
}

int stream_reader_stop(void)
{
    return OK;
}

int stream_reader_init(void)
{
    queue_buf_ptr = (frame_info_s*)malloc(sizeof(frame_info_s) * CACHE_FRAME_NUM);
    if (queue_buf_ptr == NULL) {
        perror("malloc buffer failed\n");
        return NG;
    }

	if(pthread_mutex_init(&qlock, NULL)!=0){
		perror("fail to create qlock!\n");
		return NG;
	}

	if (pthread_cond_init(&qready, NULL) != 0) {
        perror("fail to create qlock!\n");
		return NG;
	}

    _rb_init(queue_buf_ptr, CACHE_FRAME_NUM);

    if (AmbaNetFifo_init(&event_hdl) < 0) {
        perror("netfifo init failed\n");
        free(queue_buf_ptr);
        queue_buf_ptr = NULL;
        return NG;
    }

    AmbaNetFifo_Reg_cbFifoEvent(stream_reader_frame_ready_cb, NULL);
    AmbaNetFifo_Reg_cbControlEvent(stream_reader_ctrl_event_cb, NULL);

    memset(&g_tid_netfifo, 0, sizeof(pthread_t));
    if (pthread_create(&g_tid_netfifo, NULL, (void *)&AmbaNetFifo_ExecEventProcess, NULL) != 0 ) {
        printf("create process thread failed\n");
        return NG;
    }

    return OK;
}

