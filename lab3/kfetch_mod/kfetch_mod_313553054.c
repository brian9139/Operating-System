#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h>
#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/timekeeping.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

/* Module Information */
#define DEVICE_NAME "kfetch"
#define CLASS_NAME  "kfetch_class"

/* KFETCH Information Mask Definitions */
#define KFETCH_NUM_INFO 6

#define KFETCH_RELEASE    (1 << 0)
#define KFETCH_NUM_CPUS   (1 << 1)
#define KFETCH_CPU_MODEL  (1 << 2)
#define KFETCH_MEM        (1 << 3)
#define KFETCH_UPTIME     (1 << 4)
#define KFETCH_NUM_PROCS  (1 << 5)

#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

/* Logo Definition */
#define LOGO "\
      .-.        \n\
     (.. |       \n\
     <>  |       \n\
    / --- \\      \n\
   ( |   | )     \n\
 |\\\\_)__(_//|   \n\
<__)------(__>  \n\n"
#define LOGO "\
      .-.        \n\
     (.. |       \n\
     <>  |       \n\
    / --- \\      \n\
   ( |   | )     \n\
  |\\\\_)__(_//|   \n\
 <__)------(__>  \n\n"


/* Device Variables */
static dev_t dev_num;
static struct cdev kfetch_cdev;
static struct class *kfetch_class = NULL;
static struct device *kfetch_device = NULL;

/* Buffer to Store Information */
#define KFETCH_BUF_SIZE 1024
static char *kfetch_buf;
static size_t kfetch_buf_size = 0;

/* Current Mask (Default: Full Info) */
static int current_mask = KFETCH_FULL_INFO;

/* Mutex for Synchronization */
static DEFINE_MUTEX(kfetch_mutex);

/* Function Prototypes */
static int     kfetch_open(struct inode *, struct file *);
static int     kfetch_release(struct inode *, struct file *);
static ssize_t kfetch_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t kfetch_write(struct file *, const char __user *, size_t, loff_t *);

/* File Operations Structure */
static struct file_operations fops =
{
    .owner   = THIS_MODULE,
    .open    = kfetch_open,
    .release = kfetch_release,
    .read    = kfetch_read,
    .write   = kfetch_write,
};

/* Helper Function to Get System Information */
static void build_kfetch_info(char *buffer, size_t *len)
{
    struct sysinfo si;
    struct timespec64 uptime;
    struct task_struct *task;
    int procs = 0;
    int ret;
    int padding = 5;  // Adjust padding to position the info correctly
    int dash_line_length = 40; // Length for the dashed line separator

    /* Initialize buffer */
    *len = 0;

    /* Add Logo (first part of the lines) */
    
    // ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "                 %*sHostname: %s\n", padding, "", utsname()->nodename);
    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "                      %s\n", utsname()->nodename);

    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;
    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "      .-.        ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;
 
    /* Add dashed separator line after the hostname */
    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "%*s%.*s\n", padding, "", dash_line_length, "--------------------");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;

    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "     (.. |       ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;
    
    /* Fetch Kernel Release */
    if (current_mask & KFETCH_RELEASE) {
        ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "%*sKernel: %s\n", padding, "", utsname()->release);
        if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
            return;
        *len += ret;
    }

    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "     <>  |       ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;
    
    /* Fetch CPU Model Name */
    if (current_mask & KFETCH_CPU_MODEL) {
        const char *cpu_model = "Unknown";
        #if defined(CONFIG_X86)
            cpu_model = boot_cpu_data.x86_model_id;
        #elif defined(CONFIG_ARM64)
            cpu_model = "ARM64 CPU Model";  // Placeholder for ARM64
        #endif
        ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "%*sCPU:    %s\n", padding, "", cpu_model);
        if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
            return;
        *len += ret;
    }

    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "    / --- \\      ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;
    
    /* Fetch Number of CPUs */
    if (current_mask & KFETCH_NUM_CPUS) {
        int online_cpus = num_online_cpus();
        int total_cpus = num_possible_cpus();
        ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "%*sCPUs:   %d / %d\n", padding, "", online_cpus, total_cpus);
        if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
            return;
        *len += ret;
    }

    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "   ( |   | )     ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;
    
    /* Fetch Memory Information */
    if (current_mask & KFETCH_MEM) {
        si_meminfo(&si);
        unsigned long total_mem_mb = si.totalram * si.mem_unit / (1024 * 1024);
        unsigned long free_mem_mb = si.freeram * si.mem_unit / (1024 * 1024);
        ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "%*sMem:    %lu / %lu MB\n", padding, "", free_mem_mb, total_mem_mb);
        if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
            return;
        *len += ret;
    }

    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, " |\\\\_)__(_//|   ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;

    /* Fetch Number of Processes */
    if (current_mask & KFETCH_NUM_PROCS) {
        rcu_read_lock();
        for_each_process(task)
            procs++;
        rcu_read_unlock();
        ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, " %*sProcs:  %d\n", padding, "", procs);
        if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
            return;
        *len += ret;
    }

    ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, "<__)------(__>  ");
    if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
        return;
    *len += ret;

    /* Fetch Uptime */
    if (current_mask & KFETCH_UPTIME) {
        ktime_get_boottime_ts64(&uptime);
        unsigned long uptime_minutes = uptime.tv_sec / 60;
        ret = snprintf(buffer + *len, KFETCH_BUF_SIZE - *len, " %*sUptime: %lu minutes\n", padding, "", uptime_minutes);
        if (ret < 0 || ret >= KFETCH_BUF_SIZE - *len)
            return;
        *len += ret;
    }
}

/* Open Operation */
static int kfetch_open(struct inode *inode, struct file *file)
{
    pr_info("kfetch: Device opened\n");
    return 0;
}

/* Release Operation */
static int kfetch_release(struct inode *inode, struct file *file)
{
    pr_info("kfetch: Device closed\n");
    return 0;
}

/* Read Operation */
static ssize_t kfetch_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    ssize_t bytes_read = 0;

    mutex_lock(&kfetch_mutex);

    /* Build the information */
    build_kfetch_info(kfetch_buf, &kfetch_buf_size);

    pr_info("kfetch_read: buffer_size=%zu, offset=%lld, requested_length=%zu\n", kfetch_buf_size, *offset, length);

    /* Check if offset is beyond the buffer */
    if (*offset >= kfetch_buf_size) {
        mutex_unlock(&kfetch_mutex);
        pr_info("kfetch_read: EOF reached (offset >= buffer_size)\n");
        return 0;  // EOF
    }

    /* Adjust length if it exceeds buffer size */
    if (*offset + length > kfetch_buf_size)
        length = kfetch_buf_size - *offset;

    pr_info("kfetch_read: Copying %zu bytes to user-space\n", length);

    /* Copy to user */
    if (copy_to_user(buffer, kfetch_buf + *offset, kfetch_buf_size)) {
        pr_alert("kfetch: Failed to copy data to user\n");
        mutex_unlock(&kfetch_mutex);
        return -EFAULT;
    }

    /* Update offset and bytes read */
    *offset += length;
    bytes_read = length;

    pr_info("kfetch_read: bytes_read=%zd, new offset=%lld\n", bytes_read, *offset);

    mutex_unlock(&kfetch_mutex);
    return kfetch_buf_size;
}
/* Write Operation */
static ssize_t kfetch_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    int mask_info;
    int ret;

    /* Ensure only an integer is written */
    if (length != sizeof(int)) {
        pr_alert("kfetch: Invalid write length\n");
        return -EINVAL;
    }

    /* Copy mask from user */
    ret = copy_from_user(&mask_info, buffer, sizeof(int));
    if (ret) {
        pr_alert("kfetch: Failed to copy data from user\n");
        return -EFAULT;
    }

    /* Validate mask */
    if (mask_info < 0 || mask_info > KFETCH_FULL_INFO) {
        pr_alert("kfetch: Invalid mask value\n");
        return -EINVAL;
    }

    /* Update the current mask */
    mutex_lock(&kfetch_mutex);
    current_mask = mask_info;
    mutex_unlock(&kfetch_mutex);

    pr_info("kfetch: Information mask set to 0x%X\n", current_mask);
    return sizeof(int);
}

/* Module Initialization */
static int __init kfetch_init(void)
{
    int ret;

    /* Allocate Major and Minor Numbers Dynamically */
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_alert("kfetch: Failed to allocate major number\n");
        return ret;
    }
    pr_info("kfetch: Registered with major number %d\n", MAJOR(dev_num));

    /* Initialize cdev Structure and Add to Kernel */
    cdev_init(&kfetch_cdev, &fops);
    kfetch_cdev.owner = THIS_MODULE;

    ret = cdev_add(&kfetch_cdev, dev_num, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev_num, 1);
        pr_alert("kfetch: Failed to add cdev\n");
        return ret;
    }

    /* Create Device Class */
    kfetch_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(kfetch_class)) {
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev_num, 1);
        pr_alert("kfetch: Failed to create device class\n");
        return PTR_ERR(kfetch_class);
    }

    /* Create Device File in /dev */
    kfetch_device = device_create(kfetch_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(kfetch_device)) {
        class_destroy(kfetch_class);
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev_num, 1);
        pr_alert("kfetch: Failed to create device\n");
        return PTR_ERR(kfetch_device);
    }

    /* Allocate Buffer */
    kfetch_buf = kmalloc(KFETCH_BUF_SIZE, GFP_KERNEL);
    if (!kfetch_buf) {
        device_destroy(kfetch_class, dev_num);
        class_destroy(kfetch_class);
        cdev_del(&kfetch_cdev);
        unregister_chrdev_region(dev_num, 1);
        pr_alert("kfetch: Failed to allocate buffer\n");
        return -ENOMEM;
    }

    /* Initialize Mutex */
    mutex_init(&kfetch_mutex);

    pr_info("kfetch: Module loaded successfully\n");
    return 0;
}

/* Module Exit */
static void __exit kfetch_exit(void)
{
    /* Free Buffer */
    if (kfetch_buf)
        kfree(kfetch_buf);

    /* Destroy Device */
    device_destroy(kfetch_class, dev_num);

    /* Destroy Class */
    class_destroy(kfetch_class);

    /* Delete cdev */
    cdev_del(&kfetch_cdev);

    /* Unregister Major and Minor Numbers */
    unregister_chrdev_region(dev_num, 1);

    /* Destroy Mutex */
    mutex_destroy(&kfetch_mutex);

    pr_info("kfetch: Module unloaded successfully\n");
}

/* Register Module Entry and Exit Points */
module_init(kfetch_init);
module_exit(kfetch_exit);

/* Module Metadata */
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Module to Fetch System Information");
MODULE_VERSION("1.0");


