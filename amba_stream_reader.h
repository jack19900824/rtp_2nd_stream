#ifndef __AMBA_STREAM_READER_H__
#define __AMBA_STREAM_READER_H__

#ifdef  __cplusplus
extern "C" {
#endif


typedef struct _frame_info_s_ {
    unsigned long long  pts;
    uint8_t     *pFrame_addr;
    uint32_t    frame_size;
    uint32_t    frame_type;
    uint32_t    seq_num;
} frame_info_s;

int stream_reader_init(void);
int stream_reader_start(void);
int stream_reader_get_frame(frame_info_s* frame_info);
int stream_reader_get_frame_block(frame_info_s* frame_info);
int stream_reader_stop(void);
int stream_reader_delete(void);

#ifdef  __cplusplus
}
#endif

#endif

