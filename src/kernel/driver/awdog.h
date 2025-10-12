#ifndef _UAPI_AWDOG_H
#define _UAPI_AWDOG_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define AWDOG_DEV_NAME      "awdog"
#define AWDOG_IOC_MAGIC     0xA7

/* Configuration */
#define AWDOG_KEY_LEN       32          /* Kc size in bytes */
#define AWDOG_MAC_LEN       32          /* HMAC-SHA256 output (full 32 bytes) */

/* Ioctls */
struct awdog_register {
    __u32 pid;                /* manager PID (for sanity check) */
    __u64 exe_fingerprint;    /* your chosen fingerprint (inode, or hash id) */
    __u32 key_len;            /* must be 32 */
    __u8  key[AWDOG_KEY_LEN]; /* Kc (HKDF derived) */
    __u32 hb_period_ms;       /* expected heartbeat period */
    __u32 hb_timeout_ms;      /* timeout (e.g., 3x period) */
    __u64 session_id;         /* arbitrary session id (rotate when re-registering) */
    __u32 proto_ver;          /* start at 1 */
};

#define AWDOG_IOCTL_REGISTER  _IOW(AWDOG_IOC_MAGIC, 0x01, struct awdog_register)
#define AWDOG_IOCTL_UNREG     _IO(AWDOG_IOC_MAGIC,  0x02)

/* Heartbeat blob written via write(2); must be exactly sizeof(struct awdog_hb) */
struct awdog_hb {
    __u64 monotonic_nonce;    /* strictly increasing */
    __u32 pid;                /* same pid as registered (sanity) */
    __u64 exe_fingerprint;    /* same as registered (or kernel rechecks) */
    __u64 ts_ns;              /* sender timestamp */
    __u8  mac[AWDOG_MAC_LEN]; /* HMAC-SHA256 over the first 8+4+8+8 bytes */
} __attribute__((packed));

#endif
