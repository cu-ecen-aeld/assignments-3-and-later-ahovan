/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Oleksii Khovan (aka Alexey Hovan)");
MODULE_LICENSE("Dual BSD/GPL");

static struct aesd_dev aesd_device;
static struct aesd_circular_buffer circular_buffer;
static size_t commands_count = 0;
static struct aesd_buffer_entry * command = NULL;
static struct aesd_buffer_entry * commands[AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED];

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    struct aesd_dev * const dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    if (mutex_lock_interruptible(&aesd_device.lock) != 0) {
        return -ERESTARTSYS;
    }

    // TBD: think of kmalloc under mutex. Is it a good idea?...
    size_t * byte_rtn = kmalloc(sizeof(size_t), GFP_KERNEL);
    if (byte_rtn == NULL) {
        printk(KERN_ERR "Failed to allocate memory for byte_rtn");
        return retval;
    }

    struct aesd_buffer_entry * command = aesd_circular_buffer_find_entry_offset_for_fpos(
        &circular_buffer, *f_pos, byte_rtn);

    if (command == NULL) {
        goto cleanup;
    }
    command->size = strlen(command->buffptr);
    count = count > command->size ? command->size : count;

    if (copy_to_user(buf, command->buffptr, count) != 0) {
        printk(KERN_ERR "Failed to copy to userspace");
        retval = -EFAULT;
        goto cleanup;
    }

    *f_pos += count;
    retval = count;

cleanup:
    mutex_unlock(&aesd_device.lock);

    if (byte_rtn != NULL) {
        kfree(byte_rtn);
    }

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    static int command_offset = 0;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if (command_offset == 0) {
        command = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
        if (command == NULL) {
            printk(KERN_ERR "Failed to allocate memory for circular buffer entry");
            return retval;
        }

        command->buffptr = kmalloc(count, GFP_KERNEL);
        if (!command->buffptr) {
            printk(KERN_ERR "Failed to allocate memory for buffer");
            kfree(command);
            command = NULL;
            return retval;
        }

        commands[commands_count++] = command;
        if (commands_count == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
            commands_count = 0;
        }
    }

    if (mutex_lock_interruptible(&aesd_device.lock)) {
		return -ERESTARTSYS;
    }

    // Discard buffptr's constness explicitly
    char * command_buffer = (char *) command->buffptr;
    if (copy_from_user(command_buffer + command_offset, buf, count) != 0) {
        printk(KERN_ERR "Failed to copy from userspace");
        retval = -EFAULT;
        goto cleanup;
    }
    command_offset += count;

    if (*(command->buffptr + command_offset - 1) == '\n') {
        *(command_buffer + command_offset) = '\0';
        command->size = command_offset;
        command_offset = 0;
        aesd_circular_buffer_add_entry(&circular_buffer, command);
        f_pos += command->size; // ??? tentative
    }

    retval = count;

cleanup:
    mutex_unlock(&aesd_device.lock);

    return retval;
}

loff_t aesd_llseek(struct file * filp, loff_t off, int whence)
{
    struct aesd_dev * const dev = filp->private_data;

    if (mutex_lock_interruptible(&dev->lock)) {
        printk(KERN_WARNING "Interrupted waiting on mutex lock");
        return -EINTR;
    }    

    loff_t size = 0;    
    for (ssize_t i = 0; i < commands_count/*AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED */; ++i) {
        size += commands[i]->size;
    }

    mutex_unlock(&dev->lock);
	return fixed_size_llseek(filp, off, whence, size);
}

static long aesd_adjust_file_offset(struct file * filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    struct aesd_dev * dev = filp->private_data;
    unsigned int written_len = 0;
    if (mutex_lock_interruptible(&dev->lock)) {
        printk(KERN_WARNING "aesd_adjust_file_offset: Interrupted waiting on mutex lock");
        return -ERESTARTSYS;
    }

    if (write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED/*10*/) {
        mutex_unlock(&dev->lock);
        printk(KERN_WARNING "aesd_adjust_file_offset: write_cmd >= 10");
        return -EINVAL;
    }

    if (commands[write_cmd]->size == 0 || commands[write_cmd]->size < write_cmd_offset) {
        mutex_unlock(&dev->lock);
        printk(KERN_WARNING "aesd_adjust_file_offset: wrong write_cmd->size");
        return -EINVAL;
    }

    if (write_cmd < circular_buffer.out_offs) {
        write_cmd += AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    for (ssize_t i = write_cmd; i > circular_buffer.out_offs; --i) {
        const int cmd_len = commands[i % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED]->size;
        written_len += cmd_len;
    }

    filp->f_pos = written_len + write_cmd_offset;
    mutex_unlock(&dev->lock);
    return 0;
}

long int aesd_ioctl(struct file * filp, unsigned int cmd, unsigned long arg)
{
    if (cmd != AESDCHAR_IOCSEEKTO) {
        return -EINVAL;
    }

    struct aesd_seekto seekto;
    if (copy_from_user(&seekto, (const void __user *) arg, sizeof(seekto)) != 0) {
        return -EFAULT;
    } else {
        return aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
    }
}

struct file_operations aesd_fops = {
    .owner   = THIS_MODULE,
    .read    = aesd_read,
    .write   = aesd_write,
    .open    = aesd_open,
    .release = aesd_release,
    .llseek  = aesd_llseek,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }

    //NB: it is not libc's memset, but wrapper around kernel intrinsic __memset()
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&circular_buffer);
    mutex_init(&aesd_device.lock);

    commands_count = 0;
    // Initialize all array members in order to properly clean them up
    // in case there were less than AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED
    // commands during session.
    for (size_t i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; ++i) {
        commands[i] = NULL;
    }

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    for (size_t i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; ++i) {
        if (commands[i] != NULL) {
            if (commands[i]->buffptr != NULL) {
                kfree(commands[i]->buffptr);
            }
            kfree(commands[i]);
        }
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
