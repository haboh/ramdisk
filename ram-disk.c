#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/blk-mq.h>
#include <linux/moduleparam.h>

#include "ram-disk.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maxim Khabarov");
MODULE_DESCRIPTION("Block device with storage in ram.");
MODULE_VERSION("0.1");

static int sectors_count = 2048;

static const struct kernel_param_ops param_ops =
{
    .set = myblockdevicesize_set,
    .get = param_get_int,
};

struct block_device_operations my_block_ops = {
    .owner = THIS_MODULE,
    .open = my_block_device_open,
    .release = my_block_device_release
};

static struct blk_mq_ops my_queue_ops = {
    .queue_rq = my_block_device_request,
};

module_param_cb(sectorscount, &param_ops, &sectors_count, 0664);

static int myblockdevicesize_set(const char *val, const struct kernel_param *kp)
{
    size_t new_sectors_count = 0;
    size_t old_size = sectors_count * KERNEL_SECTOR_SIZE;
    int res, ret;

    res = kstrtoul(val, 10, &new_sectors_count);
    if (res != 0)
    {
        ret = -EINVAL;
        goto exit_blockdevsize_set;
    }

    size_t new_size = new_sectors_count * KERNEL_SECTOR_SIZE;

    char *new_data = vmalloc(new_size);
    if (new_data == NULL)
    {
        ret = -ENOMEM;
        goto exit_blockdevsize_set;
    }

    memset(new_data, 0, new_size);

    if (dev.data != NULL)
    {
        size_t min_size = new_size < old_size ? new_size : old_size;
        memcpy(new_data, dev.data, min_size);
        vfree(dev.data);
    }

    dev.data = new_data;
    ret = param_set_int(val, kp);

    pr_info("SUCCESS old: %lu, new: %lu\n", old_size, new_size);

exit_blockdevsize_set:
    return ret;
}


static blk_status_t my_block_device_request
(
    struct blk_mq_hw_ctx *hctx
    , const struct blk_mq_queue_data *bd
)
{
    printk(KERN_INFO "Visited block request\n");
    struct request *rq = bd->rq;
    struct my_block_dev *dev = rq->q->queuedata;

    blk_mq_start_request(rq);

    if (blk_rq_is_passthrough(rq))
    {
        printk(KERN_NOTICE "Skip non-fs request\n");
        blk_mq_end_request(rq, BLK_STS_IOERR);
        goto out;
    }

    struct bio_vec bvec;
    struct req_iterator iter;
    size_t pos = blk_rq_pos(rq) * KERNEL_SECTOR_SIZE;
    size_t dev_size = sectors_count * KERNEL_SECTOR_SIZE;

    rq_for_each_segment(bvec, rq, iter)
    {
        size_t offset = bvec.bv_offset;
        char *buf = kmap_atomic(bvec.bv_page) + offset;
        size_t len = bvec.bv_len;
        if (pos + len > dev_size)
        {
            len = dev_size - pos;
        }
        if (rq_data_dir(rq))
        {
            memcpy(dev->data + pos, buf, len);
        }
        else
        {
            memcpy(buf, dev->data + pos, len);
        }
        kunmap_atomic(buf);

        pos += len;
    }
    blk_mq_end_request(rq, BLK_STS_OK);

out:
    return BLK_STS_OK;
}

static int __init myblockdevice_init(void)
{
    int major = register_blkdev(0, DEV_NAME);
    if (major < 0)
    {
        printk(KERN_ERR "unable to register block device\n");
        return -EBUSY;
    }

    dev.tag_set.ops = &my_queue_ops;
    dev.tag_set.nr_hw_queues = 1;
    dev.tag_set.queue_depth = 128;
    dev.tag_set.numa_node = NUMA_NO_NODE;
    dev.tag_set.cmd_size = 0;
    dev.tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
    dev.tag_set.driver_data = &dev;
    int status = blk_mq_alloc_tag_set(&dev.tag_set);
    if (status)
    {
        printk(KERN_ERR "Failed to allocate tag set");
        return -ENOMEM;
    }

    dev.gd = blk_alloc_disk(NUMA_NO_NODE);
    if (dev.gd == NULL)
    {
        printk(KERN_ERR "failed to allocate disk\n");
        return -ENOMEM;
    }
    dev.queue = dev.gd->queue;

    status = blk_mq_init_allocated_queue(&dev.tag_set, dev.queue);
    if (status < 0)
    {
        blk_mq_free_tag_set(&dev.tag_set);
        printk(KERN_ERR "Failed to initialize queue");
        return -ENOMEM;
    }
    blk_queue_logical_block_size(dev.queue, KERNEL_SECTOR_SIZE);
    dev.queue->queuedata = &dev;

    dev.gd->major = major;
    dev.gd->first_minor = 0;
    dev.gd->minors = 1;
    dev.gd->fops = &my_block_ops;
    dev.gd->private_data = &dev;
    snprintf(dev.gd->disk_name, 32, DEV_NAME);
    set_capacity(dev.gd, sectors_count);

    dev.data = vmalloc(sectors_count * KERNEL_SECTOR_SIZE);
    if (dev.data == NULL)
    {
        printk(KERN_ERR "Unable to allocate enough memory for device");
        return -ENOMEM;
    }

    status = add_disk(dev.gd);
    printk(KERN_INFO "successfully added block device, status = %d\n", status);
    return 0;
}

static void __exit myblockdevice_end(void)
{
    int major = dev.gd->major;
    if (dev.gd)
    {
        del_gendisk(dev.gd);
    }
    blk_mq_destroy_queue(dev.queue);
    blk_mq_free_tag_set(&dev.tag_set);
    vfree(dev.data);
    unregister_blkdev(major, DEV_NAME);
    pr_info("myblockdevice: unload\n");
}

static int my_block_device_open(struct gendisk *bdev, blk_mode_t mode)
{
    return 0;
}

static void my_block_device_release(struct gendisk *gd)
{
    return;
}

module_init(myblockdevice_init);
module_exit(myblockdevice_end);