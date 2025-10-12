// SPDX-License-Identifier: GPL-2.0
// ts is straigh ai right now, 

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/cred.h>
#include <linux/kmod.h>
#include <linux/reboot.h>
#include <crypto/hash.h>           // HMAC (shash)
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/random.h>
#include <linux/timekeeping.h>
#include <linux/version.h>
#include "awdog.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define awdog_class_create(name) class_create(name)
#else
#define awdog_class_create(name) class_create(THIS_MODULE, name)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static inline int timer_shutdown_sync(struct timer_list *timer)
{
    return del_timer_sync(timer);
}
#endif

#define DRV_NAME "awdog"

struct awdog_ctx {
    struct mutex lock;            /* serialize register/hb/unreg */
    bool registered;
    u32  pid;
    kuid_t uid;
    u64  exe_fp;
    u8   key[AWDOG_KEY_LEN];
    u32  hb_period_ms;
    u32  hb_timeout_ms;
    u64  session_id;
    u32  proto_ver;
    u64  last_nonce;
    unsigned long deadline;

    struct timer_list timer;

    /* crypto */
    struct crypto_shash *tfm;     /* "hmac(sha256)" */
    struct shash_desc *desc;

    /* chardev */
    dev_t devt;
    struct cdev cdev;
    struct class *class;
    struct device *device;
} g;

static int awdog_reset_deadline_locked(void)
{
    g.deadline = jiffies + msecs_to_jiffies(g.hb_timeout_ms);
    mod_timer(&g.timer, g.deadline);
    return 0;
}

static int awdog_run_saver(const char *why)
{
    char *argv[] = { "/opt/artisan/ice", (char *)why, NULL }; // incase of emergencies not the plight on society 
    static char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    pr_emerg(DRV_NAME ": invoking saver: %s\n", why);
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static void awdog_timeout(struct timer_list *t)
{
    mutex_lock(&g.lock);
    if (!g.registered) {
        mutex_unlock(&g.lock);
        return;
    }
    if (time_is_before_jiffies(g.deadline)) {
        pr_emerg(DRV_NAME ": missed heartbeat; taking emergency action\n");
        /* Try saver, then immediate reboot */
        mutex_unlock(&g.lock);
        awdog_run_saver("timeout");
        pr_emerg(DRV_NAME ": emergency_restart\n");
        emergency_restart();
        return;
    }
    mutex_unlock(&g.lock);
    /* Shouldn't happen: deadline is maintained on hb; but keep timer alive */
    mod_timer(&g.timer, jiffies + msecs_to_jiffies(1000));
}

/* Minimal binary identity validation hook:
   In a production build, resolve pid->task and check task->mm->exe_file inode/mtime. */
static bool awdog_sanity_pid_exe(u32 pid, u64 exe_fp)
{
    return (pid == g.pid) && (exe_fp == g.exe_fp);
}

/* HMAC-SHA256(input = hb fields except mac, key = Kc) */
static int awdog_hmac_verify(const struct awdog_hb *hb)
{
    int ret;
    u8 digest[AWDOG_MAC_LEN];

    SHASH_DESC_ON_STACK(desc, g.tfm);
    desc->tfm = g.tfm;

    ret = crypto_shash_setkey(g.tfm, g.key, AWDOG_KEY_LEN);
    if (ret) return ret;

    ret = crypto_shash_init(desc);
    if (ret) return ret;

    ret = crypto_shash_update(desc, (const u8 *)&hb->monotonic_nonce, sizeof(hb->monotonic_nonce));
    if (ret) return ret;
    ret = crypto_shash_update(desc, (const u8 *)&hb->pid, sizeof(hb->pid));
    if (ret) return ret;
    ret = crypto_shash_update(desc, (const u8 *)&hb->exe_fingerprint, sizeof(hb->exe_fingerprint));
    if (ret) return ret;
    ret = crypto_shash_update(desc, (const u8 *)&hb->ts_ns, sizeof(hb->ts_ns));
    if (ret) return ret;

    ret = crypto_shash_final(desc, digest);
    if (ret) return ret;

    if (memcmp(digest, hb->mac, AWDOG_MAC_LEN) != 0)
        return -EBADMSG;

    return 0;
}

/* ------------ file ops ------------ */

static int awdog_open(struct inode *inode, struct file *filp)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    try_module_get(THIS_MODULE);
    return 0;
}

static int awdog_release(struct inode *inode, struct file *filp)
{
    module_put(THIS_MODULE);
    return 0;
}

static long awdog_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    switch (cmd) {
    case AWDOG_IOCTL_REGISTER: {
        struct awdog_register r;
        if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
            return -EFAULT;
        if (r.key_len != AWDOG_KEY_LEN || r.hb_timeout_ms < r.hb_period_ms)
            return -EINVAL;

        mutex_lock(&g.lock);
        memcpy(g.key, r.key, AWDOG_KEY_LEN);
        g.pid          = r.pid;
        g.uid          = current_uid();
        g.exe_fp       = r.exe_fingerprint;
        g.hb_period_ms = r.hb_period_ms;
        g.hb_timeout_ms= r.hb_timeout_ms;
        g.session_id   = r.session_id;
        g.proto_ver    = r.proto_ver;
        g.last_nonce   = 0;
        g.registered   = true;
        awdog_reset_deadline_locked();
        mutex_unlock(&g.lock);

        pr_info(DRV_NAME ": registered pid=%u exe_fp=%llx session=%llx\n",
                r.pid, r.exe_fingerprint, r.session_id);
        return 0;
    }
    case AWDOG_IOCTL_UNREG: {
        mutex_lock(&g.lock);
        memset(g.key, 0, AWDOG_KEY_LEN);
        g.registered = false;
        g.last_nonce = 0;
        timer_shutdown_sync(&g.timer);
        mutex_unlock(&g.lock);
        pr_info(DRV_NAME ": unregistered\n");
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static ssize_t awdog_write(struct file *f, const char __user *buf, size_t len, loff_t *ppos)
{
    struct awdog_hb hb;
    int ret = 0;

    if (len != sizeof(hb)) return -EINVAL;
    if (copy_from_user(&hb, buf, sizeof(hb))) return -EFAULT;

    mutex_lock(&g.lock);
    if (!g.registered) { ret = -EPIPE; goto out; }

    if (!awdog_sanity_pid_exe(hb.pid, hb.exe_fingerprint))
    { ret = -EPERM; goto out; }

    if (hb.monotonic_nonce <= g.last_nonce)
    { ret = -EINVAL; goto out; }

    ret = awdog_hmac_verify(&hb);
    if (ret) goto out;

    g.last_nonce = hb.monotonic_nonce;
    awdog_reset_deadline_locked();
    ret = sizeof(hb);
out:
    mutex_unlock(&g.lock);
    if (ret < 0) {
        pr_warn(DRV_NAME ": bad heartbeat (%d), triggering saver+reboot\n", ret);
        awdog_run_saver("verify-failed");
        emergency_restart();
    }
    return ret;
}

static const struct file_operations awdog_fops = {
    .owner          = THIS_MODULE,
    .open           = awdog_open,
    .release        = awdog_release,
    .unlocked_ioctl = awdog_ioctl,
    .write          = awdog_write,
};

static int __init awdog_init(void)
{
    int ret;
    mutex_init(&g.lock);

    g.tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(g.tfm)) {
        pr_err(DRV_NAME ": crypto_alloc_shash failed\n");
        return PTR_ERR(g.tfm);
    }

    timer_setup(&g.timer, awdog_timeout, 0);

    ret = alloc_chrdev_region(&g.devt, 0, 1, DRV_NAME);
    if (ret) goto out_crypto;

    cdev_init(&g.cdev, &awdog_fops);
    ret = cdev_add(&g.cdev, g.devt, 1);
    if (ret) goto out_chrdev;

    g.class = awdog_class_create(DRV_NAME);
    if (IS_ERR(g.class)) { ret = PTR_ERR(g.class); goto out_cdev; }

    g.device = device_create(g.class, NULL, g.devt, NULL, AWDOG_DEV_NAME);
    if (IS_ERR(g.device)) { ret = PTR_ERR(g.device); goto out_class; }

    pr_info(DRV_NAME ": loaded, /dev/%s ready\n", AWDOG_DEV_NAME);
    return 0;

out_class:
    class_destroy(g.class);
out_cdev:
    cdev_del(&g.cdev);
out_chrdev:
    unregister_chrdev_region(g.devt, 1);
out_crypto:
    crypto_free_shash(g.tfm);
    return ret;
}

static void __exit awdog_exit(void)
{
    timer_shutdown_sync(&g.timer);
    device_destroy(g.class, g.devt);
    class_destroy(g.class);
    cdev_del(&g.cdev);
    unregister_chrdev_region(g.devt, 1);
    if (g.tfm) crypto_free_shash(g.tfm);
    memset(&g, 0, sizeof(g));
    pr_info(DRV_NAME ": unloaded\n");
}

module_init(awdog_init);
module_exit(awdog_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Darrion Whitfield");
MODULE_DESCRIPTION("Artisan Watchdog (HMAC heartbeat, saver+reboot)");
