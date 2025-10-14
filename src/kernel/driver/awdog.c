// SPDX-License-Identifier: GPL-2.0
#include "awdog.h"
#include <crypto/hash.h> // HMAC (shash)
#include <linux/cdev.h>
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kmod.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define awdog_class_create(name) class_create(name)
#else
#define awdog_class_create(name) class_create(THIS_MODULE, name)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static inline int timer_shutdown_sync(struct timer_list *timer) {
  return del_timer_sync(timer);
}
#endif

#define DRV_NAME "awdog"
#define AWDOG_REASON_LEN 64

struct awdog_ctx {
  struct mutex lock;    /* serialize register/hb/unreg */
  spinlock_t work_lock; /* protects queued work reasons */
  bool registered;
  u32 pid;
  u64 exe_fp;
  bool exe_fp_locked;
  u8 key[AWDOG_KEY_LEN];
  u32 hb_period_ms;
  u32 hb_timeout_ms;
  u64 session_id;
  u32 proto_ver;
  u64 last_nonce;
  u64 last_hb_mono_ns;
  unsigned long deadline;

  struct timer_list timer;

  /* async actions */
  struct work_struct reboot_work;
  struct work_struct sos_work;
  char reboot_reason[AWDOG_REASON_LEN];
  char sos_reason[AWDOG_REASON_LEN];

  /* crypto */
  struct crypto_shash *tfm; /* "hmac(sha256)" */
  struct shash_desc *desc;

  /* chardev */
  dev_t devt;
  struct cdev cdev;
  struct class *class;
  struct device *device;
} g;

static int awdog_reset_deadline_locked(void) {
  g.deadline = jiffies + msecs_to_jiffies(g.hb_timeout_ms);
  mod_timer(&g.timer, g.deadline);
  return 0;
}

static int __maybe_unused awdog_run_ko_test(const char *why) {
  char *argv[] = {"/bin/echo", (char *)why, NULL};
  static char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
  pr_emerg(DRV_NAME ": invoking ko-test: %s\n", why);
  return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static int awdog_run_soscall(const char *reason) {
    const char *why = reason ? reason : "unknown";
    static char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    char *argv[] = { "/sbin/awdog-saver", (char *)why, NULL };

    pr_emerg("awdog: tamper tripped: %s\n", why);


    int rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    // if (rc) {  ahpn is missing some modules or headers to use this, skipping for now
    //     /* Fallback when userspace is toast: do what we can in-kernel. */
    //     pr_emerg("awdog: usermode helper failed (%d), using emergency fallback\n", rc);

    //     /* 1) Try to push data */
    //     emergency_sync();          /* if available in your kernel */
    //     /* 2) Try to remount RO all filesystems */
    //     emergency_remount();       /* likewise; some trees call it emergency_remount_ro() */
    // }

    return rc;
}

static void awdog_run_reboot(const char *reason) {
  pr_emerg(DRV_NAME ": reboot requested (%s)\n", reason);
  emergency_restart();
}

static void awdog_reboot_workfn(struct work_struct *work) {
  struct awdog_ctx *ctx = container_of(work, struct awdog_ctx, reboot_work);
  unsigned long flags;
  char reason[sizeof(ctx->reboot_reason)];

  spin_lock_irqsave(&ctx->work_lock, flags);
  if (strscpy(reason, ctx->reboot_reason, sizeof(reason)) < 0)
    reason[AWDOG_REASON_LEN - 1] = '\0';
  spin_unlock_irqrestore(&ctx->work_lock, flags);
  if (!reason[0])
    strscpy(reason, "unknown", sizeof(reason));

  awdog_run_reboot(reason);
  // awdog_run_ko_test(reason);
}

static void awdog_soscall_workfn(struct work_struct *work) {
  struct awdog_ctx *ctx = container_of(work, struct awdog_ctx, sos_work);
  unsigned long flags;
  char reason[sizeof(ctx->sos_reason)];

  spin_lock_irqsave(&ctx->work_lock, flags);
  if (strscpy(reason, ctx->sos_reason, sizeof(reason)) < 0)
    reason[AWDOG_REASON_LEN - 1] = '\0';
  spin_unlock_irqrestore(&ctx->work_lock, flags);
  if (!reason[0])
    strscpy(reason, "unknown", sizeof(reason));

  if (awdog_run_soscall(reason))
    pr_err(DRV_NAME ": saver helper failed (%s)\n", reason);
}

static void awdog_queue_reboot(const char *reason) {
  unsigned long flags;
  const char *why = reason ? reason : "unknown";

  spin_lock_irqsave(&g.work_lock, flags);
  if (strscpy(g.reboot_reason, why, sizeof(g.reboot_reason)) < 0)
    g.reboot_reason[AWDOG_REASON_LEN - 1] = '\0';
  spin_unlock_irqrestore(&g.work_lock, flags);
  schedule_work(&g.reboot_work);
}

static void awdog_queue_soscall(const char *reason) {
  unsigned long flags;
  const char *why = reason ? reason : "unknown";

  spin_lock_irqsave(&g.work_lock, flags);
  if (strscpy(g.sos_reason, why, sizeof(g.sos_reason)) < 0)
    g.sos_reason[AWDOG_REASON_LEN - 1] = '\0';
  spin_unlock_irqrestore(&g.work_lock, flags);
  schedule_work(&g.sos_work);
}

static void awdog_timeout(struct timer_list *t) {
  unsigned long deadline = READ_ONCE(g.deadline);

  if (!READ_ONCE(g.registered))
    return;

  if (time_is_before_jiffies(deadline)) {
    awdog_queue_soscall("timeout");
    awdog_queue_reboot("timeout");
    return;
  }

  mod_timer(&g.timer, jiffies + msecs_to_jiffies(1000));
}

static bool awdog_sanity_pid_exe(u32 pid, u64 exe_fp) {
  if (!g.registered)
    return false;

  if (pid != g.pid) {
    pr_warn(DRV_NAME ": heartbeat pid mismatch (expected=%u got=%u)\n",
            g.pid, pid);
    return false;
  }

  if (!g.exe_fp_locked) {
    g.exe_fp = exe_fp;
    g.exe_fp_locked = true;
    pr_info(DRV_NAME ": locking fingerprint to %llx\n", exe_fp);
    return true;
  }

  if (exe_fp != g.exe_fp) {
    pr_warn(DRV_NAME ": heartbeat fingerprint mismatch pid=%u expected=%llx got=%llx\n",
            pid, g.exe_fp, exe_fp);
    return false;
  }

  return true;
}

/* HMAC-SHA256(input = hb fields except mac, key = Kc) */
static int awdog_hmac_verify(const struct awdog_hb *hb) {
  int ret;
  u8 digest[AWDOG_MAC_LEN];

  SHASH_DESC_ON_STACK(desc, g.tfm);
  desc->tfm = g.tfm;

  ret = crypto_shash_setkey(g.tfm, g.key, AWDOG_KEY_LEN);
  if (ret)
    return ret;

  ret = crypto_shash_init(desc);
  if (ret)
    return ret;

  ret = crypto_shash_update(desc, (const u8 *)&hb->monotonic_nonce,
                            sizeof(hb->monotonic_nonce));
  if (ret)
    return ret;
  ret = crypto_shash_update(desc, (const u8 *)&hb->pid, sizeof(hb->pid));
  if (ret)
    return ret;
  ret = crypto_shash_update(desc, (const u8 *)&hb->exe_fingerprint,
                            sizeof(hb->exe_fingerprint));
  if (ret)
    return ret;
  ret = crypto_shash_update(desc, (const u8 *)&hb->ts_ns, sizeof(hb->ts_ns));
  if (ret)
    return ret;

  ret = crypto_shash_final(desc, digest);
  if (ret)
    return ret;

  if (memcmp(digest, hb->mac, AWDOG_MAC_LEN) != 0)
    return -EBADMSG;

  return 0;
}

/* ------------ file ops ------------ */

static int awdog_open(struct inode *inode, struct file *filp) {
  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;
  try_module_get(THIS_MODULE);
  return 0;
}

static int awdog_release(struct inode *inode, struct file *filp) {
  module_put(THIS_MODULE);
  return 0;
}

static long awdog_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;

  // debugging
  pr_info("awdog: ioctl cmd=0x%x magic=0x%x type=0x%x nr=0x%x\n", cmd,
          _IOC_TYPE(cmd), _IOC_TYPE(cmd), _IOC_NR(cmd));

  switch (cmd) {
  case AWDOG_IOCTL_REGISTER: {
    struct awdog_register r;
    if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
      return -EFAULT;
    if (r.key_len != AWDOG_KEY_LEN || r.hb_timeout_ms < r.hb_period_ms)
      return -EINVAL;

    mutex_lock(&g.lock);

    if (g.exe_fp_locked && r.exe_fingerprint != g.exe_fp) {
      mutex_unlock(&g.lock);
      pr_warn(DRV_NAME ": rejected re-register pid=%u fingerprint %llx (expected %llx)\n",
              r.pid, r.exe_fingerprint, g.exe_fp);
      return -EPERM;
    }

    if (!g.exe_fp_locked) {
      g.exe_fp = r.exe_fingerprint;
      g.exe_fp_locked = true;
      pr_info(DRV_NAME ": canonical fingerprint set to %llx\n", g.exe_fp);
    }

    memcpy(g.key, r.key, AWDOG_KEY_LEN);
    g.pid = r.pid;
    g.hb_period_ms = r.hb_period_ms;
    g.hb_timeout_ms = r.hb_timeout_ms;
    g.session_id = r.session_id;
    g.proto_ver = r.proto_ver;
    g.last_nonce = 0;
    g.last_hb_mono_ns = 0;
    g.registered = true;
    memset(g.reboot_reason, 0, sizeof(g.reboot_reason));
    memset(g.sos_reason, 0, sizeof(g.sos_reason));
    awdog_reset_deadline_locked();
    mutex_unlock(&g.lock);

    pr_info(DRV_NAME ": registered pid=%u exe_fp=%llx session=%llx\n", r.pid,
            r.exe_fingerprint, r.session_id);
    return 0;
  }
  case AWDOG_IOCTL_UNREG: {
    mutex_lock(&g.lock);
    memset(g.key, 0, AWDOG_KEY_LEN);
    g.registered = false;
    g.pid = 0;
    g.last_nonce = 0;
    g.last_hb_mono_ns = 0;
    memset(g.reboot_reason, 0, sizeof(g.reboot_reason));
    memset(g.sos_reason, 0, sizeof(g.sos_reason));
    timer_shutdown_sync(&g.timer);
    mutex_unlock(&g.lock);
    cancel_work_sync(&g.sos_work);
    cancel_work_sync(&g.reboot_work);
    pr_info(DRV_NAME ": unregistered\n");
    return 0;
  }
  default:
    return -ENOTTY;
  }
}

static ssize_t awdog_write(struct file *f, const char __user *buf, size_t len,
                           loff_t *ppos) {
  struct awdog_hb hb;
  int ret = 0;

  if (len != sizeof(hb))
    return -EINVAL;
  if (copy_from_user(&hb, buf, sizeof(hb)))
    return -EFAULT;

  mutex_lock(&g.lock);
  if (!g.registered) {
    ret = -EPIPE;
    goto out;
  }

  if (!awdog_sanity_pid_exe(hb.pid, hb.exe_fingerprint)) {
    ret = -EPERM;
    goto out;
  }

  if (hb.monotonic_nonce <= g.last_nonce) {
    ret = -EINVAL;
    goto out;
  }

  ret = awdog_hmac_verify(&hb);
  if (ret)
    goto out;

  {
    u64 now_mono_ns = ktime_get_ns();
    u64 gap_ms = 0;

    if (g.last_hb_mono_ns)
      gap_ms = div_u64(now_mono_ns - g.last_hb_mono_ns, NSEC_PER_MSEC);

    g.last_hb_mono_ns = now_mono_ns;

    {
      u64 now_real_ns = ktime_get_real_ns();
      s64 latency_ns = (s64)now_real_ns - (s64)hb.ts_ns;
      s64 latency_ms = div_s64(latency_ns, NSEC_PER_MSEC);

      pr_debug(
          DRV_NAME
          ": heartbeat nonce=%llu pid=%u gap_ms=%llums latency_ms=%lldms\n",
          hb.monotonic_nonce, hb.pid, (unsigned long long)gap_ms,
          (long long)latency_ms);
    }
  }

  g.last_nonce = hb.monotonic_nonce;
  awdog_reset_deadline_locked();
  ret = sizeof(hb);
out:
  mutex_unlock(&g.lock);
  if (ret < 0) {
    pr_warn(DRV_NAME ": bad heartbeat (%d), triggering saver+reboot\n", ret);
    if (awdog_run_soscall("verify-failed"))
      pr_err(DRV_NAME ": saver helper failed (verify-failed)\n");
    awdog_run_reboot("verify-failed");
    // awdog_run_ko_test("verify-failed");
  }
  return ret;
}

static const struct file_operations awdog_fops = {
    .owner = THIS_MODULE,
    .open = awdog_open,
    .release = awdog_release,
    .unlocked_ioctl = awdog_ioctl,
    .write = awdog_write,
};

static int __init awdog_init(void) {
  int ret;

  mutex_init(&g.lock);
  spin_lock_init(&g.work_lock);
  INIT_WORK(&g.reboot_work, awdog_reboot_workfn);
  INIT_WORK(&g.sos_work, awdog_soscall_workfn);

  g.tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
  if (IS_ERR(g.tfm)) {
    pr_err(DRV_NAME ": crypto_alloc_shash failed\n");
    return PTR_ERR(g.tfm);
  }

  timer_setup(&g.timer, awdog_timeout, 0);

  ret = alloc_chrdev_region(&g.devt, 0, 1, DRV_NAME);
  if (ret)
    goto out_crypto;

  cdev_init(&g.cdev, &awdog_fops);
  ret = cdev_add(&g.cdev, g.devt, 1);
  if (ret)
    goto out_chrdev;

  g.class = awdog_class_create(DRV_NAME);
  if (IS_ERR(g.class)) {
    ret = PTR_ERR(g.class);
    goto out_cdev;
  }

  g.device = device_create(g.class, NULL, g.devt, NULL, AWDOG_DEV_NAME);
  if (IS_ERR(g.device)) {
    ret = PTR_ERR(g.device);
    goto out_class;
  }

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

static void __exit awdog_exit(void) {
  timer_shutdown_sync(&g.timer);
  cancel_work_sync(&g.sos_work);
  cancel_work_sync(&g.reboot_work);
  device_destroy(g.class, g.devt);
  class_destroy(g.class);
  cdev_del(&g.cdev);
  unregister_chrdev_region(g.devt, 1);
  if (g.tfm)
    crypto_free_shash(g.tfm);
  memset(&g, 0, sizeof(g));
  pr_info(DRV_NAME ": unloaded\n");
}

module_init(awdog_init);
module_exit(awdog_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Darrion Whitfield <dwhitfield@artisanhosting.net>");
MODULE_DESCRIPTION("Artisan Watchdog (HMAC heartbeat, saver+reboot)");
