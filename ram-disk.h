#include <linux/blkdev.h>

#define DEV_NAME "myblockdevice"
#define KERNEL_SECTOR_SIZE 512

static int myblockdevicesize_set(const char *val, const struct kernel_param *kp);
static int my_block_device_open(struct gendisk *bdev, blk_mode_t mode);
static void my_block_device_release(struct gendisk *gd);
static blk_status_t my_block_device_request
(
    struct blk_mq_hw_ctx *hctx
    , const struct blk_mq_queue_data *bd
);

static struct my_block_dev
{
    spinlock_t lock;

    struct gendisk *gd;
    struct request_queue *queue;
    struct blk_mq_tag_set tag_set;
    char *data;
} dev;


