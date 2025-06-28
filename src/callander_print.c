#define _GNU_SOURCE
#define _XOPEN_SOURCE
#include "callander_print.h"

#include <sys/mount.h>
#ifdef __linux__
#include <asm/ioctls.h>
#include <drm/drm.h>
#include <linux/auto_dev-ioctl.h>
#include <linux/auto_fs.h>
#include <linux/blkpg.h>
#include <linux/blktrace_api.h>
#include <linux/blkzoned.h>
#include <linux/bpf.h>
#include <linux/btrfs.h>
#include <linux/cdrom.h>
#include <linux/cec.h>
#include <linux/cxl_mem.h>
#include <linux/dm-ioctl.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/dvb/dmx.h>
#include <linux/f2fs.h>
#include <linux/falloc.h>
#include <linux/fb.h>
#include <linux/fd.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/fsl_hypervisor.h>
#include <linux/fsmap.h>
#include <linux/fsverity.h>
#include <linux/fuse.h>
#include <linux/gpio.h>
#include <linux/gsmmux.h>
#include <linux/hdreg.h>
#include <linux/hiddev.h>
#include <linux/hidraw.h>
#include <linux/hpet.h>
#include <linux/i2c.h>
#include <linux/icmpv6.h>
#include <linux/if_alg.h>
#include <linux/if_tun.h>
#include <linux/iio/buffer.h>
#include <linux/iio/events.h>
#include <linux/input.h>
#include <linux/kd.h>
#include <linux/keyctl.h>
#include <linux/loop.h>
#include <linux/lp.h>
#include <linux/major.h>
#include <linux/memfd.h>
#include <linux/module.h>
#include <linux/mtio.h>
#include <linux/netlink.h>
#include <linux/nilfs2_api.h>
#include <linux/nsfs.h>
#include <linux/perf_event.h>
#include <linux/pr.h>
#include <linux/raid/md_u.h>
#include <linux/random.h>
#include <linux/rtc.h>
#include <linux/seccomp.h>
#include <linux/sed-opal.h>
#include <linux/serial.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/spi/spidev.h>
#include <linux/tiocl.h>
#include <linux/tipc.h>
#include <linux/tls.h>
#include <linux/types.h>
#include <linux/usb/cdc-wdm.h>
#include <linux/usb/functionfs.h>
#include <linux/usb/g_printer.h>
#include <linux/usb/g_uvc.h>
#include <linux/usb/gadgetfs.h>
#include <linux/usb/raw_gadget.h>
#include <linux/usb/tmc.h>
#include <linux/usbdevice_fs.h>
#include <linux/userfaultfd.h>
#include <linux/vt.h>
#include <linux/watchdog.h>
#include <linux/wireless.h>
#include <mtd/mtd-abi.h>
#include <scsi/sg.h>
#include <sys/rseq.h>
typedef __u32 compat_ulong_t;
#ifdef __x86_64__
#include <asm/mce.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/sgx.h>
#endif
#include <linux/kfd_ioctl.h>
#include <linux/mmtimer.h>
#include <linux/pktcdvd.h>
#include <linux/uinput.h>
// #include <linux/socket.h>
#include <linux/in6.h>
#include <netinet/udp.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#endif
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#endif
#include <sys/random.h>
#include <sys/sem.h>
#include <sys/shm.h>
#ifdef __linux__
#include <sys/signalfd.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/swap.h>
#endif
#include <sys/time.h>
#ifdef __linux__
#include <sys/timerfd.h>
#endif
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <time.h>

static inline char *strdup_fixed(const char *str, size_t size)
{
	char *buf = malloc(size);
	memcpy(buf, str, size);
	return buf;
}

#define SYSCALL_ARG_IS_RELATED(relation, related_arg) ((relation) | (SYSCALL_ARG_RELATED_ARGUMENT_BASE * (related_arg)))
#define SYSCALL_ARG_IS_SIZE_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_SIZE, related_arg_index)
#define SYSCALL_ARG_IS_COUNT_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_COUNT, related_arg_index)
#define SYSCALL_ARG_IS_MODEFLAGS_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_MODEFLAGS, related_arg_index)
#define SYSCALL_ARG_IS_SOCKET_OPTION_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_SOCKET_OPTION, related_arg_index)
#define SYSCALL_ARG_IS_PRCTL_ARG_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_PRCTL_ARG, related_arg_index)
#define SYSCALL_ARG_IS_FCNTL_ARG_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_FCNTL_ARG, related_arg_index)
#define SYSCALL_ARG_IS_PTRACE_ARG_OF(related_arg_index) SYSCALL_ARG_IS_RELATED(SYSCALL_ARG_IS_PTRACE_ARG, related_arg_index)
#define SYSCALL_ARG_IS_PRESERVED(underlying) (SYSCALL_ARG_IS_PRESERVED | (underlying))

#define SYSCALL_DEF_(_0, _1, _2, _3, _4, _5, _6, N, ...) N
#define SYSCALL_DEF(name, attributes, ...) {#name, {SYSCALL_DEF_(0, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0) | ((attributes) & ~SYSCALL_ARGC_MASK), {__VA_ARGS__}}},
#define SYSCALL_DEF_EMPTY {NULL, 6, {}},
struct syscall_decl const syscall_list[] = {
#include "syscall_defs.h"
};
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY

const char *name_for_syscall(uintptr_t nr)
{
	if (nr < sizeof(syscall_list) / sizeof(syscall_list[0])) {
		const char *name = syscall_list[nr].name;
		if (name != NULL) {
			return name;
		}
	}
	char buf[100];
	int count = fs_utoa(nr, buf);
	char *result = malloc(count + 1);
	fs_memcpy(result, buf, count + 1);
	return result;
}

struct syscall_info info_for_syscall(uintptr_t nr)
{
	if (nr < sizeof(syscall_list) / sizeof(syscall_list[0])) {
		return syscall_list[nr].info;
	}
	return (struct syscall_info){
		.attributes = 6,
		.arguments = {0},
	};
}

__attribute__((nonnull(1))) char *copy_register_state_description(const struct loader_context *context, struct register_state reg)
{
	if (register_is_exactly_known(&reg)) {
		if (reg.value == ~(uintptr_t)0) {
			return strdup("-1");
		}
		if (reg.value == 0xffffffff) {
			return strdup("-1 as u32");
		}
		if (reg.value == 0x7fffffff) {
			return strdup("INT_MAX");
		}
		if (reg.value == 0x7fffffffffffffff) {
			return strdup("LONG_MAX");
		}
		if ((uintptr_t)reg.value < 4096) {
			char *buf = malloc(5);
			fs_utoa(reg.value, buf);
			return buf;
		}
		return copy_address_description(context, (const void *)reg.value);
	}
	if (register_is_partially_known(&reg)) {
		if (reg.value == 1 && reg.max == ~(uintptr_t)0) {
			return strdup("non-NULL");
		}
		if (reg.value == 0) {
			if (reg.max == 0x7fffffffffffffff) {
				return strdup("0-LONG_MAX");
			}
			if (reg.max == 0xffffffff) {
				return strdup("any u32");
			}
			if (reg.max == 0x7fffffff) {
				return strdup("0-INT_MAX");
			}
			if (reg.max == 0xffff) {
				return strdup("any u16");
			}
			if (reg.max == 0xff) {
				return strdup("any u8");
			}
		}
		char *min = copy_address_description(context, (const void *)reg.value);
		size_t min_size = fs_strlen(min);
		char *max = copy_address_description(context, (const void *)reg.max);
		size_t max_size = fs_strlen(max);
		char *result = malloc(min_size + max_size + 2);
		fs_memcpy(result, min, min_size);
		result[min_size] = '-';
		fs_memcpy(&result[min_size + 1], max, max_size + 1);
		free(min);
		free(max);
		return result;
	}
	return strdup("any");
}

struct enum_option
{
	uintptr_t value;
	const char *description;
};

#ifdef __linux__

#define DESCRIBE_ENUM(x) {.value = x, .description = #x}

#define DESCRIBE_FLAG(X) [(__builtin_popcount(X) == 1 ? (unsigned)(8 * sizeof(unsigned long long) - __builtin_clzll((X)) - 1) : (unsigned)-1)] = #X

struct enum_option file_descriptors[] = {
	DESCRIBE_ENUM(STDIN_FILENO),
	DESCRIBE_ENUM(STDOUT_FILENO),
	DESCRIBE_ENUM(STDERR_FILENO),
	DESCRIBE_ENUM(AT_FDCWD),
	{.value = (uint32_t)AT_FDCWD, .description = "AT_FDCWD"},
	{.value = -1, .description = "-1"},
	{.value = (uint32_t)-1, .description = "-1 as u32"},
};

struct enum_option prots[] = {
	DESCRIBE_ENUM(PROT_NONE),
};

static const char *prot_flags[64] = {
	DESCRIBE_FLAG(PROT_READ),
	DESCRIBE_FLAG(PROT_WRITE),
	DESCRIBE_FLAG(PROT_EXEC),
#ifdef __aarch64__
	DESCRIBE_FLAG(PROT_MTE),
#endif
};

static struct enum_option maps[] = {
	// DESCRIBE_ENUM(MAP_FILE),
	DESCRIBE_ENUM(MAP_SHARED),
	DESCRIBE_ENUM(MAP_PRIVATE),
	DESCRIBE_ENUM(MAP_SHARED_VALIDATE),
};

static const char *map_flags[64] = {
#ifdef MAP_32BIT
	DESCRIBE_FLAG(MAP_32BIT),
#endif
	DESCRIBE_FLAG(MAP_ANONYMOUS),
	DESCRIBE_FLAG(MAP_DENYWRITE),
	DESCRIBE_FLAG(MAP_EXECUTABLE),
	DESCRIBE_FLAG(MAP_FIXED),
	DESCRIBE_FLAG(MAP_FIXED_NOREPLACE),
	DESCRIBE_FLAG(MAP_GROWSDOWN),
	DESCRIBE_FLAG(MAP_HUGETLB),
	// DESCRIBE_FLAG(MAP_HUGE_2MB),
    // DESCRIBE_FLAG(MAP_HUGE_1GB),
	DESCRIBE_FLAG(MAP_LOCKED),
	DESCRIBE_FLAG(MAP_NORESERVE),
	DESCRIBE_FLAG(MAP_POPULATE),
	DESCRIBE_FLAG(MAP_STACK),
	DESCRIBE_FLAG(MAP_SYNC),
	// DESCRIBE_FLAG(MAP_UNINITIALIZED),
};

static const char *remap_flags[64] = {
	DESCRIBE_FLAG(MREMAP_MAYMOVE),
	DESCRIBE_FLAG(MREMAP_FIXED),
};

#ifdef O_LARGEFILE
#undef O_LARGEFILE
#endif
#define O_LARGEFILE 00100000

#ifdef __O_SYNC
#undef __O_SYNC
#endif
#define __O_SYNC 04000000

#ifdef __O_TMPFILE
#undef __O_TMPFILE
#endif
#define __O_TMPFILE 020000000

#ifdef O_DSYNC
#undef O_DSYNC
#endif
#define O_DSYNC 00010000

#ifdef O_NOFOLLOW
#undef O_NOFOLLOW
#endif
#define O_NOFOLLOW 00400000

static struct enum_option opens[] = {
	DESCRIBE_ENUM(O_RDONLY),
	DESCRIBE_ENUM(O_WRONLY),
	DESCRIBE_ENUM(O_RDWR),
	DESCRIBE_ENUM(O_ACCMODE),
};

static const char *open_flags[64] = {
	DESCRIBE_FLAG(O_APPEND),
	DESCRIBE_FLAG(O_ASYNC),
	DESCRIBE_FLAG(O_CLOEXEC),
	DESCRIBE_FLAG(O_CREAT),
	DESCRIBE_FLAG(O_DIRECT),
	DESCRIBE_FLAG(O_DIRECTORY),
	DESCRIBE_FLAG(O_DSYNC),
	DESCRIBE_FLAG(O_EXCL),
	DESCRIBE_FLAG(O_LARGEFILE),
	DESCRIBE_FLAG(O_NOATIME),
	DESCRIBE_FLAG(O_NOCTTY),
	DESCRIBE_FLAG(O_NOFOLLOW),
	DESCRIBE_FLAG(O_NONBLOCK),
	DESCRIBE_FLAG(O_PATH),
	DESCRIBE_FLAG(__O_SYNC),
	DESCRIBE_FLAG(__O_TMPFILE),
	DESCRIBE_FLAG(O_TRUNC),
};

static struct enum_option access_modes[] = {
	DESCRIBE_ENUM(F_OK),
};

static const char *access_mode_flags[64] = {
	DESCRIBE_FLAG(R_OK),
	DESCRIBE_FLAG(W_OK),
	DESCRIBE_FLAG(X_OK),
};

static struct enum_option shutdown_hows[] = {
	DESCRIBE_ENUM(SHUT_RD),
	DESCRIBE_ENUM(SHUT_WR),
	DESCRIBE_ENUM(SHUT_RDWR),
};

static const char *accessat_flags[64] = {
	DESCRIBE_FLAG(AT_EACCESS),
	DESCRIBE_FLAG(AT_SYMLINK_NOFOLLOW),
	DESCRIBE_FLAG(AT_SYMLINK_FOLLOW),
	DESCRIBE_FLAG(AT_NO_AUTOMOUNT),
	DESCRIBE_FLAG(AT_EMPTY_PATH),
	DESCRIBE_FLAG(AT_STATX_FORCE_SYNC),
	DESCRIBE_FLAG(AT_STATX_DONT_SYNC),
	DESCRIBE_FLAG(AT_RECURSIVE),
	// DESCRIBE_FLAG(AT_HANDLE_FID), // conflicts with AT_EACCESS
};

static const char *removeat_flags[64] = {
	DESCRIBE_FLAG(AT_SYMLINK_NOFOLLOW),
	DESCRIBE_FLAG(AT_REMOVEDIR),
	DESCRIBE_FLAG(AT_SYMLINK_FOLLOW),
	DESCRIBE_FLAG(AT_NO_AUTOMOUNT),
	DESCRIBE_FLAG(AT_EMPTY_PATH),
	DESCRIBE_FLAG(AT_STATX_FORCE_SYNC),
	DESCRIBE_FLAG(AT_STATX_DONT_SYNC),
	DESCRIBE_FLAG(AT_RECURSIVE),
	// DESCRIBE_FLAG(AT_HANDLE_FID), // conflicts with AT_REMOVEDIR
};

static const char *msync_flags[64] = {
	DESCRIBE_FLAG(MS_ASYNC),
	DESCRIBE_FLAG(MS_SYNC),
	DESCRIBE_FLAG(MS_INVALIDATE),
};

// glibc defines these
#define SIGCANCEL __SIGRTMIN
#define SIGSETXID (__SIGRTMIN + 1)

#define SIGTIMER 32
// #define SIGCANCEL 33
#define SIGSYNCCALL 34

static struct enum_option signums[] = {
	DESCRIBE_ENUM(SIGHUP),
	DESCRIBE_ENUM(SIGINT),
	DESCRIBE_ENUM(SIGQUIT),
	DESCRIBE_ENUM(SIGILL),
	DESCRIBE_ENUM(SIGTRAP),
	DESCRIBE_ENUM(SIGABRT),
	DESCRIBE_ENUM(SIGBUS),
	DESCRIBE_ENUM(SIGFPE),
	DESCRIBE_ENUM(SIGKILL),
	DESCRIBE_ENUM(SIGUSR1),
	DESCRIBE_ENUM(SIGSEGV),
	DESCRIBE_ENUM(SIGUSR2),
	DESCRIBE_ENUM(SIGPIPE),
	DESCRIBE_ENUM(SIGALRM),
	DESCRIBE_ENUM(SIGTERM),
	DESCRIBE_ENUM(SIGSTKFLT),
	DESCRIBE_ENUM(SIGCHLD),
	DESCRIBE_ENUM(SIGCONT),
	DESCRIBE_ENUM(SIGSTOP),
	DESCRIBE_ENUM(SIGTSTP),
	DESCRIBE_ENUM(SIGTTIN),
	DESCRIBE_ENUM(SIGTTOU),
	DESCRIBE_ENUM(SIGURG),
	DESCRIBE_ENUM(SIGXCPU),
	DESCRIBE_ENUM(SIGXFSZ),
	DESCRIBE_ENUM(SIGVTALRM),
	DESCRIBE_ENUM(SIGPROF),
	DESCRIBE_ENUM(SIGWINCH),
	DESCRIBE_ENUM(SIGIO),
	DESCRIBE_ENUM(SIGPWR),
	DESCRIBE_ENUM(SIGSYS),
	DESCRIBE_ENUM(SIGCANCEL),
	DESCRIBE_ENUM(SIGSETXID),
	DESCRIBE_ENUM(SIGTIMER),
	DESCRIBE_ENUM(SIGSYNCCALL),
};

#ifndef UFFDIO_WRITEPROTECT
#define _UFFDIO_WRITEPROTECT (0x06)
#define UFFDIO_WRITEPROTECT _IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, void)
#endif
#ifndef UFFDIO_CONTINUE
#define _UFFDIO_CONTINUE (0x07)
#define UFFDIO_CONTINUE _IOWR(UFFDIO, _UFFDIO_CONTINUE, void)
#endif

#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
#define SECCOMP_IOCTL_NOTIF_ADDFD SECCOMP_IOW(3, void)
#endif

#define SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR SECCOMP_IOR(2, __u64)

struct termios2
{
	tcflag_t c_iflag;  /* input mode flags */
	tcflag_t c_oflag;  /* output mode flags */
	tcflag_t c_cflag;  /* control mode flags */
	tcflag_t c_lflag;  /* local mode flags */
	cc_t c_line;   /* line discipline */
	cc_t c_cc[19];  /* control characters */
	speed_t c_ispeed;  /* input speed */
	speed_t c_ospeed;  /* output speed */
};
#define TCGETS2 _IOR('T', 0x2A, struct termios2)
#define TCSETS2 _IOW('T', 0x2B, struct termios2)
#define TCSETSW2 _IOW('T', 0x2C, struct termios2)
#define TCSETSF2 _IOW('T', 0x2D, struct termios2)

#define EVMS_MAJOR 117
#define EVMS_GET_STRIPE_INFO _IOR(EVMS_MAJOR, 0xF0, struct evms_stripe_info)

struct evms_stripe_info
{
	uint32_t size;  /* stripe unit 512-byte blocks */
	uint32_t width;  /* the number of stripe members or RAID data disks */
};

#define RAID_VERSION _IOR(MD_MAJOR, 0x10, mdu_version_t)
#define GET_ARRAY_INFO _IOR(MD_MAJOR, 0x11, mdu_array_info_t)
#define GET_DISK_INFO _IOR(MD_MAJOR, 0x12, mdu_disk_info_t)
#define RAID_AUTORUN _IO(MD_MAJOR, 0x14)
#define GET_BITMAP_FILE _IOR(MD_MAJOR, 0x15, mdu_bitmap_file_t)
#define CLEAR_ARRAY _IO(MD_MAJOR, 0x20)
#define ADD_NEW_DISK _IOW(MD_MAJOR, 0x21, mdu_disk_info_t)
#define HOT_REMOVE_DISK _IO(MD_MAJOR, 0x22)
#define SET_ARRAY_INFO _IOW(MD_MAJOR, 0x23, mdu_array_info_t)
#define SET_DISK_INFO _IO(MD_MAJOR, 0x24)
#define WRITE_RAID_INFO _IO(MD_MAJOR, 0x25)
#define UNPROTECT_ARRAY _IO(MD_MAJOR, 0x26)
#define PROTECT_ARRAY _IO(MD_MAJOR, 0x27)
#define HOT_ADD_DISK _IO(MD_MAJOR, 0x28)
#define SET_DISK_FAULTY _IO(MD_MAJOR, 0x29)
#define HOT_GENERATE_ERROR _IO(MD_MAJOR, 0x2a)
#define SET_BITMAP_FILE _IOW(MD_MAJOR, 0x2b, int)
#define RUN_ARRAY _IOW(MD_MAJOR, 0x30, mdu_param_t)
#define STOP_ARRAY _IO(MD_MAJOR, 0x32)
#define STOP_ARRAY_RO _IO(MD_MAJOR, 0x33)
#define RESTART_ARRAY_RW _IO(MD_MAJOR, 0x34)
#define CLUSTERED_DISK_NACK _IO(MD_MAJOR, 0x35)

#define RAW_SETBIND _IO(0xac, 0)
#define RAW_GETBIND _IO(0xac, 1)

#define SCSI_IOCTL_GET_IDLUN 0x5382
#define SCSI_IOCTL_PROBE_HOST 0x5385
#define SCSI_IOCTL_GET_BUS_NUMBER 0x5386
#define SCSI_IOCTL_GET_PCI 0x5387

#define SG_GET_ACCESS_COUNT 0x2289

#define TW_OP_NOP 0x0
#define TW_OP_INIT_CONNECTION 0x1
#define TW_OP_READ 0x2
#define TW_OP_WRITE 0x3
#define TW_OP_VERIFY 0x4
#define TW_OP_GET_PARAM 0x12
#define TW_OP_SET_PARAM 0x13
#define TW_OP_SECTOR_INFO 0x1a
#define TW_OP_AEN_LISTEN 0x1c
#define TW_OP_FLUSH_CACHE 0x0e
#define TW_CMD_PACKET 0x1d
#define TW_CMD_PACKET_WITH_DATA 0x1f

#ifndef DRM_IOCTL_SYNCOBJ_EVENTFD
#define DRM_IOCTL_SYNCOBJ_EVENTFD DRM_IOWR(0xCF, struct drm_syncobj_eventfd)
struct drm_syncobj_eventfd
{
	__u32 handle;
	__u32 flags;
	__u64 point;
	__s32 fd;
	__u32 pad;
};
#endif

#ifndef DRM_IOCTL_MODE_CLOSEFB
#define DRM_IOCTL_MODE_CLOSEFB DRM_IOWR(0xD0, struct drm_mode_closefb)
struct drm_mode_closefb
{
	__u32 fb_id;
	__u32 pad;
};
#endif

#ifndef BTRFS_IOC_ENCODED_READ
#define BTRFS_IOC_ENCODED_READ _IOR(BTRFS_IOCTL_MAGIC, 64, struct btrfs_ioctl_encoded_io_args)
struct btrfs_ioctl_encoded_io_args
{
	const struct iovec *iov;
	unsigned long iovcnt;
	__s64 offset;
	__u64 flags;
	__u64 len;
	__u64 unencoded_len;
	__u64 unencoded_offset;
	__u32 compression;
	__u32 encryption;
	__u8 reserved[64];
};
#endif

#ifndef BTRFS_IOC_ENCODED_WRITE
#define BTRFS_IOC_ENCODED_WRITE _IOW(BTRFS_IOCTL_MAGIC, 64, struct btrfs_ioctl_encoded_io_args)
#endif

#ifndef DMA_BUF_IOCTL_EXPORT_SYNC_FILE
#define DMA_BUF_IOCTL_EXPORT_SYNC_FILE _IOWR(DMA_BUF_BASE, 2, struct dma_buf_export_sync_file)
struct dma_buf_export_sync_file
{
	__u32 flags;
	__s32 fd;
};
#endif

#ifndef DMA_BUF_IOCTL_IMPORT_SYNC_FILE
#define DMA_BUF_IOCTL_IMPORT_SYNC_FILE _IOW(DMA_BUF_BASE, 3, struct dma_buf_import_sync_file)
struct dma_buf_import_sync_file
{
	__u32 flags;
	__s32 fd;
};
#endif

#ifndef EPOLL_IOC_TYPE
struct epoll_params
{
	__u32 busy_poll_usecs;
	__u16 busy_poll_budget;
	__u8 prefer_busy_poll;

	/* pad the struct to a multiple of 64bits */
	__u8 __pad;
};

#define EPOLL_IOC_TYPE 0x8A

#define EPIOCSPARAMS _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)
#define EPIOCGPARAMS _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)
#endif

struct ext2_new_group_input
{
	__u32 group;  /* Group number for this data */
	__u32 block_bitmap; /* Absolute block number of block bitmap */
	__u32 inode_bitmap; /* Absolute block number of inode bitmap */
	__u32 inode_table; /* Absolute block number of inode table start */
	__u32 blocks_count; /* Total number of blocks in this group */
	__u16 reserved_blocks; /* Number of reserved blocks in this group */
	__u16 unused;  /* Number of reserved GDT blocks in group */
};

struct ext4_new_group_input
{
	__u32 group;  /* Group number for this data */
	__u64 block_bitmap; /* Absolute block number of block bitmap */
	__u64 inode_bitmap; /* Absolute block number of inode bitmap */
	__u64 inode_table; /* Absolute block number of inode table start */
	__u32 blocks_count; /* Total number of blocks in this group */
	__u16 reserved_blocks; /* Number of reserved blocks in this group */
	__u16 unused;
};

struct move_extent
{
	__s32 reserved; /* original file descriptor */
	__u32 donor_fd; /* donor file descriptor */
	__u64 orig_start; /* logical start offset in block for orig */
	__u64 donor_start; /* logical start offset in block for donor */
	__u64 len; /* block length to be moved */
	__u64 moved_len; /* moved block length */
};

struct ext4_encryption_policy
{
	char version;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[8];
} __attribute__((__packed__));

#define EXT2_IOC_GETFLAGS _IOR('f', 1, long)
#define EXT2_IOC_SETFLAGS _IOW('f', 2, long)
#define EXT2_IOC_GETVERSION _IOR('v', 1, long)
#define EXT2_IOC_SETVERSION _IOW('v', 2, long)
#define EXT2_IOC_GETVERSION_NEW _IOR('f', 3, long)
#define EXT2_IOC_SETVERSION_NEW _IOW('f', 4, long)
#define EXT2_IOC_GROUP_EXTEND _IOW('f', 7, unsigned long)
#define EXT2_IOC_GROUP_ADD _IOW('f', 8, struct ext2_new_group_input)

#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#define EXT4_IOC_MOVE_EXT _IOWR('f', 15, struct move_extent)
#define EXT4_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct ext4_encryption_policy)
#define EXT4_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct ext4_encryption_policy)

#define EXT4_IOC_GETVERSION _IOR('f', 3, long)
#define EXT4_IOC_SETVERSION _IOW('f', 4, long)
#define EXT4_IOC_GETVERSION_OLD FS_IOC_GETVERSION
#define EXT4_IOC_SETVERSION_OLD FS_IOC_SETVERSION
#define EXT4_IOC_GETRSVSZ _IOR('f', 5, long)
#define EXT4_IOC_SETRSVSZ _IOW('f', 6, long)
#define EXT4_IOC_GROUP_EXTEND _IOW('f', 7, unsigned long)
#define EXT4_IOC_GROUP_ADD _IOW('f', 8, struct ext4_new_group_input)
#define EXT4_IOC_MIGRATE _IO('f', 9)
#define EXT4_IOC_ALLOC_DA_BLKS _IO('f', 12)
#define EXT4_IOC_MOVE_EXT _IOWR('f', 15, struct move_extent)
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#define EXT4_IOC_SWAP_BOOT _IO('f', 17)
#define EXT4_IOC_PRECACHE_EXTENTS _IO('f', 18)
#define EXT4_IOC_CLEAR_ES_CACHE _IO('f', 40)
#define EXT4_IOC_GETSTATE _IOW('f', 41, __u32)
#define EXT4_IOC_GET_ES_CACHE _IOWR('f', 42, struct fiemap)
#define EXT4_IOC_CHECKPOINT _IOW('f', 43, __u32)
#define EXT4_IOC_GETFSUUID _IOR('f', 44, struct fsuuid)
#define EXT4_IOC_SETFSUUID _IOW('f', 44, struct fsuuid)
#define EXT4_IOC_SHUTDOWN _IOR('X', 125, __u32)

struct fsuuid
{
	__u32 fsu_len;
	__u32 fsu_flags;
	__u8 fsu_uuid[];
};

typedef struct dasd_information_t
{
	unsigned int devno;  /* S/390 devno */
	unsigned int real_devno; /* for aliases */
	unsigned int schid;  /* S/390 subchannel identifier */
	unsigned int cu_type : 16; /* from SenseID */
	unsigned int cu_model : 8; /* from SenseID */
	unsigned int dev_type : 16; /* from SenseID */
	unsigned int dev_model : 8; /* from SenseID */
	unsigned int open_count;
	unsigned int req_queue_len;
	unsigned int chanq_len;  /* length of chanq */
	char type[4];   /* from discipline.name, 'none' for unknown */
	unsigned int status;  /* current device level */
	unsigned int label_block; /* where to find the VOLSER */
	unsigned int FBA_layout; /* fixed block size (like AIXVOL) */
	unsigned int characteristics_size;
	unsigned int confdata_size;
	char characteristics[64]; /* from read_device_characteristics */
	char configuration_data[256]; /* from read_configuration_data */
} dasd_information_t;

#define DASD_IOCTL_LETTER 'D'
#define BIODASDINFO _IOR(DASD_IOCTL_LETTER, 1, dasd_information_t)

#define HCIUARTSETPROTO _IOW('U', 200, int)
#define HCIUARTGETPROTO _IOR('U', 201, int)
#define HCIUARTGETDEVICE _IOR('U', 202, int)
#define HCIUARTSETFLAGS _IOW('U', 203, int)
#define HCIUARTGETFLAGS _IOR('U', 204, int)

#define HCIDEVUP _IOW('H', 201, int)
#define HCIDEVDOWN _IOW('H', 202, int)
#define HCIDEVRESET _IOW('H', 203, int)
#define HCIDEVRESTAT _IOW('H', 204, int)

#define HCIGETDEVLIST _IOR('H', 210, int)
#define HCIGETDEVINFO _IOR('H', 211, int)
#define HCIGETCONNLIST _IOR('H', 212, int)
#define HCIGETCONNINFO _IOR('H', 213, int)
#define HCIGETAUTHINFO _IOR('H', 215, int)

#define HCISETRAW _IOW('H', 220, int)
#define HCISETSCAN _IOW('H', 221, int)
#define HCISETAUTH _IOW('H', 222, int)
#define HCISETENCRYPT _IOW('H', 223, int)
#define HCISETPTYPE _IOW('H', 224, int)
#define HCISETLINKPOL _IOW('H', 225, int)
#define HCISETLINKMODE _IOW('H', 226, int)
#define HCISETACLMTU _IOW('H', 227, int)
#define HCISETSCOMTU _IOW('H', 228, int)

#define HCIBLOCKADDR _IOW('H', 230, int)
#define HCIUNBLOCKADDR _IOW('H', 231, int)

#define HCIINQUIRY _IOR('H', 240, int)

#define RDMA_IOCTL_MAGIC 0x1b
#define RDMA_VERBS_IOCTL _IOWR(RDMA_IOCTL_MAGIC, 1, struct ib_uverbs_ioctl_hdr)
struct ib_uverbs_attr
{
	__u16 attr_id;  /* command specific type attribute */
	__u16 len;  /* only for pointers and IDRs array */
	__u16 flags;  /* combination of UVERBS_ATTR_F_XXXX */
	union {
		struct
		{
			__u8 elem_id;
			__u8 reserved;
		} enum_data;
		__u16 reserved;
	} attr_data;
	union {
		/*
		 * ptr to command, inline data, idr/fd or
		 * ptr to __u32 array of IDRs
		 */
		__aligned_u64 data;
		/* Used by FD_IN and FD_OUT */
		__s64 data_s64;
	};
};

struct ib_uverbs_ioctl_hdr
{
	__u16 length;
	__u16 object_id;
	__u16 method_id;
	__u16 num_attrs;
	__aligned_u64 reserved1;
	__u32 driver_id;
	__u32 reserved2;
	struct ib_uverbs_attr attrs[];
};

#define FUNCTIONFS_DMABUF_ATTACH _IOW('g', 131, int)
#define FUNCTIONFS_DMABUF_DETACH _IOW('g', 132, int)
#define FUNCTIONFS_DMABUF_TRANSFER _IOW('g', 133, struct usb_ffs_dmabuf_transfer_req)
#ifndef USB_FFS_DMABUF_TRANSFER_MASK
struct usb_ffs_dmabuf_transfer_req
{
	int fd;
	__u32 flags;
	__u64 length;
} __attribute__((packed));
#endif

#ifndef FS_IOC_GETFSUUID
struct fsuuid2
{
	__u8 len;
	__u8 uuid[16];
};
#define FS_IOC_GETFSUUID _IOR(0x15, 0, struct fsuuid2)
#endif

#ifndef FS_IOC_GETFSSYSFSPATH
struct fs_sysfs_path
{
	__u8 len;
	__u8 name[128];
};
#define FS_IOC_GETFSSYSFSPATH _IOR(0x15, 1, struct fs_sysfs_path)
#endif

#ifndef FUSE_DEV_IOC_BACKING_OPEN
#define FUSE_DEV_IOC_BACKING_OPEN _IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_backing_map)
struct fuse_backing_map
{
	int32_t fd;
	uint32_t flags;
	uint64_t padding;
};
#endif

#ifndef FUSE_DEV_IOC_BACKING_CLOSE
#define FUSE_DEV_IOC_BACKING_CLOSE _IOW(FUSE_DEV_IOC_MAGIC, 2, uint32_t)
#endif

#ifndef INOTIFY_IOC_SETNEXTWD
#define INOTIFY_IOC_SETNEXTWD _IOW('I', 0, __s32)
#endif

#ifndef CDROM_TIMED_MEDIA_CHANGE
#define CDROM_TIMED_MEDIA_CHANGE 0x5396  /* get the timestamp of the last media change */
#endif

#define PACKET_SETUP_DEV _IOW('X', 1, unsigned int)
#define PACKET_TEARDOWN_DEV _IOW('X', 2, unsigned int)

#ifndef GSMIOC_GETCONF_EXT
#define GSMIOC_GETCONF_EXT _IOR('G', 5, struct gsm_config_ext)
struct gsm_config_ext
{
	__u32 keep_alive;
	__u32 wait_config;
	__u32 flags;
	__u32 reserved[5];
};
#endif

#ifndef GSMIOC_SETCONF_EXT
#define GSMIOC_SETCONF_EXT _IOW('G', 6, struct gsm_config_ext)
#endif

#ifndef GSMIOC_GETCONF_DLCI
#define GSMIOC_GETCONF_DLCI _IOWR('G', 7, struct gsm_dlci_config)
struct gsm_dlci_config
{
	__u32 channel;
	__u32 adaption;
	__u32 mtu;
	__u32 priority;
	__u32 i;
	__u32 k;
	__u32 flags;
	__u32 reserved[7];
};
#endif

#ifndef GSMIOC_SETCONF_DLCI
#define GSMIOC_SETCONF_DLCI _IOW('G', 8, struct gsm_dlci_config)
#endif

#define SIOCGETTUNNEL (SIOCDEVPRIVATE + 0)
#define SIOCADDTUNNEL (SIOCDEVPRIVATE + 1)
#define SIOCDELTUNNEL (SIOCDEVPRIVATE + 2)
#define SIOCCHGTUNNEL (SIOCDEVPRIVATE + 3)
#define SIOCGETPRL (SIOCDEVPRIVATE + 4)
#define SIOCADDPRL (SIOCDEVPRIVATE + 5)
#define SIOCDELPRL (SIOCDEVPRIVATE + 6)
#define SIOCCHGPRL (SIOCDEVPRIVATE + 7)
#define SIOCGET6RD (SIOCDEVPRIVATE + 8)
#define SIOCADD6RD (SIOCDEVPRIVATE + 9)
#define SIOCDEL6RD (SIOCDEVPRIVATE + 10)
#define SIOCCHG6RD (SIOCDEVPRIVATE + 11)

typedef enum zfs_ioc
{
	/*
 * Core features - 88/128 numbers reserved.
 */
#ifdef __FreeBSD__
	ZFS_IOC_FIRST = 0,
#else
	ZFS_IOC_FIRST = ('Z' << 8),
#endif
	ZFS_IOC = ZFS_IOC_FIRST,
	ZFS_IOC_POOL_CREATE = ZFS_IOC_FIRST, /* 0x5a00 */
	ZFS_IOC_POOL_DESTROY,   /* 0x5a01 */
	ZFS_IOC_POOL_IMPORT,   /* 0x5a02 */
	ZFS_IOC_POOL_EXPORT,   /* 0x5a03 */
	ZFS_IOC_POOL_CONFIGS,   /* 0x5a04 */
	ZFS_IOC_POOL_STATS,   /* 0x5a05 */
	ZFS_IOC_POOL_TRYIMPORT,   /* 0x5a06 */
	ZFS_IOC_POOL_SCAN,   /* 0x5a07 */
	ZFS_IOC_POOL_FREEZE,   /* 0x5a08 */
	ZFS_IOC_POOL_UPGRADE,   /* 0x5a09 */
	ZFS_IOC_POOL_GET_HISTORY,  /* 0x5a0a */
	ZFS_IOC_VDEV_ADD,   /* 0x5a0b */
	ZFS_IOC_VDEV_REMOVE,   /* 0x5a0c */
	ZFS_IOC_VDEV_SET_STATE,   /* 0x5a0d */
	ZFS_IOC_VDEV_ATTACH,   /* 0x5a0e */
	ZFS_IOC_VDEV_DETACH,   /* 0x5a0f */
	ZFS_IOC_VDEV_SETPATH,   /* 0x5a10 */
	ZFS_IOC_VDEV_SETFRU,   /* 0x5a11 */
	ZFS_IOC_OBJSET_STATS,   /* 0x5a12 */
	ZFS_IOC_OBJSET_ZPLPROPS,  /* 0x5a13 */
	ZFS_IOC_DATASET_LIST_NEXT,  /* 0x5a14 */
	ZFS_IOC_SNAPSHOT_LIST_NEXT,  /* 0x5a15 */
	ZFS_IOC_SET_PROP,   /* 0x5a16 */
	ZFS_IOC_CREATE,    /* 0x5a17 */
	ZFS_IOC_DESTROY,   /* 0x5a18 */
	ZFS_IOC_ROLLBACK,   /* 0x5a19 */
	ZFS_IOC_RENAME,    /* 0x5a1a */
	ZFS_IOC_RECV,    /* 0x5a1b */
	ZFS_IOC_SEND,    /* 0x5a1c */
	ZFS_IOC_INJECT_FAULT,   /* 0x5a1d */
	ZFS_IOC_CLEAR_FAULT,   /* 0x5a1e */
	ZFS_IOC_INJECT_LIST_NEXT,  /* 0x5a1f */
	ZFS_IOC_ERROR_LOG,   /* 0x5a20 */
	ZFS_IOC_CLEAR,    /* 0x5a21 */
	ZFS_IOC_PROMOTE,   /* 0x5a22 */
	ZFS_IOC_SNAPSHOT,   /* 0x5a23 */
	ZFS_IOC_DSOBJ_TO_DSNAME,  /* 0x5a24 */
	ZFS_IOC_OBJ_TO_PATH,   /* 0x5a25 */
	ZFS_IOC_POOL_SET_PROPS,   /* 0x5a26 */
	ZFS_IOC_POOL_GET_PROPS,   /* 0x5a27 */
	ZFS_IOC_SET_FSACL,   /* 0x5a28 */
	ZFS_IOC_GET_FSACL,   /* 0x5a29 */
	ZFS_IOC_SHARE,    /* 0x5a2a */
	ZFS_IOC_INHERIT_PROP,   /* 0x5a2b */
	ZFS_IOC_SMB_ACL,   /* 0x5a2c */
	ZFS_IOC_USERSPACE_ONE,   /* 0x5a2d */
	ZFS_IOC_USERSPACE_MANY,   /* 0x5a2e */
	ZFS_IOC_USERSPACE_UPGRADE,  /* 0x5a2f */
	ZFS_IOC_HOLD,    /* 0x5a30 */
	ZFS_IOC_RELEASE,   /* 0x5a31 */
	ZFS_IOC_GET_HOLDS,   /* 0x5a32 */
	ZFS_IOC_OBJSET_RECVD_PROPS,  /* 0x5a33 */
	ZFS_IOC_VDEV_SPLIT,   /* 0x5a34 */
	ZFS_IOC_NEXT_OBJ,   /* 0x5a35 */
	ZFS_IOC_DIFF,    /* 0x5a36 */
	ZFS_IOC_TMP_SNAPSHOT,   /* 0x5a37 */
	ZFS_IOC_OBJ_TO_STATS,   /* 0x5a38 */
	ZFS_IOC_SPACE_WRITTEN,   /* 0x5a39 */
	ZFS_IOC_SPACE_SNAPS,   /* 0x5a3a */
	ZFS_IOC_DESTROY_SNAPS,   /* 0x5a3b */
	ZFS_IOC_POOL_REGUID,   /* 0x5a3c */
	ZFS_IOC_POOL_REOPEN,   /* 0x5a3d */
	ZFS_IOC_SEND_PROGRESS,   /* 0x5a3e */
	ZFS_IOC_LOG_HISTORY,   /* 0x5a3f */
	ZFS_IOC_SEND_NEW,   /* 0x5a40 */
	ZFS_IOC_SEND_SPACE,   /* 0x5a41 */
	ZFS_IOC_CLONE,    /* 0x5a42 */
	ZFS_IOC_BOOKMARK,   /* 0x5a43 */
	ZFS_IOC_GET_BOOKMARKS,   /* 0x5a44 */
	ZFS_IOC_DESTROY_BOOKMARKS,  /* 0x5a45 */
	ZFS_IOC_RECV_NEW,   /* 0x5a46 */
	ZFS_IOC_POOL_SYNC,   /* 0x5a47 */
	ZFS_IOC_CHANNEL_PROGRAM,  /* 0x5a48 */
	ZFS_IOC_LOAD_KEY,   /* 0x5a49 */
	ZFS_IOC_UNLOAD_KEY,   /* 0x5a4a */
	ZFS_IOC_CHANGE_KEY,   /* 0x5a4b */
	ZFS_IOC_REMAP,    /* 0x5a4c */
	ZFS_IOC_POOL_CHECKPOINT,  /* 0x5a4d */
	ZFS_IOC_POOL_DISCARD_CHECKPOINT, /* 0x5a4e */
	ZFS_IOC_POOL_INITIALIZE,  /* 0x5a4f */
	ZFS_IOC_POOL_TRIM,   /* 0x5a50 */
	ZFS_IOC_REDACT,    /* 0x5a51 */
	ZFS_IOC_GET_BOOKMARK_PROPS,  /* 0x5a52 */
	ZFS_IOC_WAIT,    /* 0x5a53 */
	ZFS_IOC_WAIT_FS,   /* 0x5a54 */
	ZFS_IOC_VDEV_GET_PROPS,   /* 0x5a55 */
	ZFS_IOC_VDEV_SET_PROPS,   /* 0x5a56 */
	ZFS_IOC_POOL_SCRUB,   /* 0x5a57 */

	/*
	 * Per-platform (Optional) - 8/128 numbers reserved.
	 */
	ZFS_IOC_PLATFORM = ZFS_IOC_FIRST + 0x80,
	ZFS_IOC_EVENTS_NEXT,   /* 0x81 (Linux) */
	ZFS_IOC_EVENTS_CLEAR,   /* 0x82 (Linux) */
	ZFS_IOC_EVENTS_SEEK,   /* 0x83 (Linux) */
	ZFS_IOC_NEXTBOOT,   /* 0x84 (FreeBSD) */
	ZFS_IOC_JAIL,    /* 0x85 (FreeBSD) */
	ZFS_IOC_USERNS_ATTACH = ZFS_IOC_JAIL, /* 0x85 (Linux) */
	ZFS_IOC_UNJAIL,    /* 0x86 (FreeBSD) */
	ZFS_IOC_USERNS_DETACH = ZFS_IOC_UNJAIL, /* 0x86 (Linux) */
	ZFS_IOC_SET_BOOTENV,   /* 0x87 */
	ZFS_IOC_GET_BOOTENV,   /* 0x88 */
	ZFS_IOC_LAST
} zfs_ioc_t;

#define BLKZNAME _IOR(0x12, 125, char[ZFS_MAX_DATASET_NAME_LEN])

#define ZFS_IOC_GETDOSFLAGS _IOR(0x83, 1, uint64_t)
#define ZFS_IOC_SETDOSFLAGS _IOW(0x83, 2, uint64_t)

#define SECCOMP_IOCTL_NOTIF_SET_FLAGS SECCOMP_IOW(4, __u64)

#define MON_IOC_MAGIC 0x92

#define MON_IOCQ_URB_LEN _IO(MON_IOC_MAGIC, 1)
/* #2 used to be MON_IOCX_URB, removed before it got into Linus tree */
#define MON_IOCG_STATS _IOR(MON_IOC_MAGIC, 3, struct mon_bin_stats)
#define MON_IOCT_RING_SIZE _IO(MON_IOC_MAGIC, 4)
#define MON_IOCQ_RING_SIZE _IO(MON_IOC_MAGIC, 5)
#define MON_IOCX_GET _IOW(MON_IOC_MAGIC, 6, struct mon_bin_get)
#define MON_IOCX_MFETCH _IOWR(MON_IOC_MAGIC, 7, struct mon_bin_mfetch)
#define MON_IOCH_MFLUSH _IO(MON_IOC_MAGIC, 8)
/* #9 was MON_IOCT_SETAPI */
#define MON_IOCX_GETX _IOW(MON_IOC_MAGIC, 10, struct mon_bin_get)

struct mon_bin_isodesc
{
	int iso_status;
	unsigned int iso_off;
	unsigned int iso_len;
	__u32 _pad;
};

/* per file statistic */
struct mon_bin_stats
{
	__u32 queued;
	__u32 dropped;
};

struct mon_bin_get
{
	struct mon_bin_hdr *hdr; /* Can be 48 bytes or 64. */
	void *data;
	size_t alloc;  /* Length of data (can be zero) */
};

struct mon_bin_mfetch
{
	__u32 *offvec; /* Vector of events fetched */
	__u32 nfetch;  /* Number of events to fetch (out: fetched) */
	__u32 nflush;  /* Number of events to flush */
};

struct space_resv
{
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;  /* len == 0 means until end of file */
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4]; /* reserved area */
};

#define FS_IOC_RESVSP _IOW('X', 40, struct space_resv)
#define FS_IOC_UNRESVSP _IOW('X', 41, struct space_resv)
#define FS_IOC_RESVSP64 _IOW('X', 42, struct space_resv)
#define FS_IOC_UNRESVSP64 _IOW('X', 43, struct space_resv)
#define FS_IOC_ZERO_RANGE _IOW('X', 57, struct space_resv)

typedef uint16_t domid_t;

#ifdef __x86_64__
typedef unsigned long xen_pfn_t;
#else
typedef uint64_t xen_pfn_t;
#endif

struct privcmd_hypercall
{
	__u64 op;
	__u64 arg[5];
};

struct privcmd_mmap_entry
{
	__u64 va;
	/*
	 * This should be a GFN. It's not possible to change the name because
	 * it's exposed to the user-space.
	 */
	__u64 mfn;
	__u64 npages;
};

struct privcmd_mmap
{
	int num;
	domid_t dom; /* target domain */
	struct privcmd_mmap_entry *entry;
};

struct privcmd_mmapbatch
{
	int num;     /* number of pages to populate */
	domid_t dom; /* target domain */
	__u64 addr;  /* virtual address */
	xen_pfn_t *arr; /* array of mfns - or'd with
	              PRIVCMD_MMAPBATCH_*_ERROR on err */
};

#define PRIVCMD_MMAPBATCH_MFN_ERROR 0xf0000000U
#define PRIVCMD_MMAPBATCH_PAGED_ERROR 0x80000000U

struct privcmd_mmapbatch_v2
{
	unsigned int num; /* number of pages to populate */
	domid_t dom;      /* target domain */
	__u64 addr;       /* virtual address */
	const xen_pfn_t *arr; /* array of mfns */
	int *err;  /* array of error codes */
};

struct privcmd_dm_op_buf
{
	void *uptr;
	size_t size;
};

struct privcmd_dm_op
{
	domid_t dom;
	__u16 num;
	const struct privcmd_dm_op_buf *ubufs;
};

struct privcmd_mmap_resource
{
	domid_t dom;
	__u32 type;
	__u32 id;
	__u32 idx;
	__u64 num;
	__u64 addr;
};

/* For privcmd_irqfd::flags */
#define PRIVCMD_IRQFD_FLAG_DEASSIGN (1 << 0)

struct privcmd_irqfd
{
	__u64 dm_op;
	__u32 size; /* Size of structure pointed by dm_op */
	__u32 fd;
	__u32 flags;
	domid_t dom;
	__u8 pad[2];
};

/* For privcmd_ioeventfd::flags */
#define PRIVCMD_IOEVENTFD_FLAG_DEASSIGN (1 << 0)

struct privcmd_ioeventfd
{
	__u64 ioreq;
	__u64 ports;
	__u64 addr;
	__u32 addr_len;
	__u32 event_fd;
	__u32 vcpus;
	__u32 vq;
	__u32 flags;
	domid_t dom;
	__u8 pad[2];
};

/*
 * @cmd: IOCTL_PRIVCMD_HYPERCALL
 * @arg: &privcmd_hypercall_t
 * Return: Value returned from execution of the specified hypercall.
 *
 * @cmd: IOCTL_PRIVCMD_MMAPBATCH_V2
 * @arg: &struct privcmd_mmapbatch_v2
 * Return: 0 on success (i.e., arg->err contains valid error codes for
 * each frame).  On an error other than a failed frame remap, -1 is
 * returned and errno is set to EINVAL, EFAULT etc.  As an exception,
 * if the operation was otherwise successful but any frame failed with
 * -ENOENT, then -1 is returned and errno is set to ENOENT.
 */
#define IOCTL_PRIVCMD_HYPERCALL _IOC(_IOC_NONE, 'P', 0, sizeof(struct privcmd_hypercall))
#define IOCTL_PRIVCMD_MMAP _IOC(_IOC_NONE, 'P', 2, sizeof(struct privcmd_mmap))
#define IOCTL_PRIVCMD_MMAPBATCH _IOC(_IOC_NONE, 'P', 3, sizeof(struct privcmd_mmapbatch))
#define IOCTL_PRIVCMD_MMAPBATCH_V2 _IOC(_IOC_NONE, 'P', 4, sizeof(struct privcmd_mmapbatch_v2))
#define IOCTL_PRIVCMD_DM_OP _IOC(_IOC_NONE, 'P', 5, sizeof(struct privcmd_dm_op))
#define IOCTL_PRIVCMD_RESTRICT _IOC(_IOC_NONE, 'P', 6, sizeof(domid_t))
#define IOCTL_PRIVCMD_MMAP_RESOURCE _IOC(_IOC_NONE, 'P', 7, sizeof(struct privcmd_mmap_resource))
#define IOCTL_PRIVCMD_IRQFD _IOW('P', 8, struct privcmd_irqfd)
#define IOCTL_PRIVCMD_IOEVENTFD _IOW('P', 9, struct privcmd_ioeventfd)

typedef uint32_t prid_t;
typedef __s64 xfs_off_t;

typedef struct xfs_bstime
{
	__kernel_long_t tv_sec;  /* seconds		*/
	__s32 tv_nsec; /* and nanoseconds	*/
} xfs_bstime_t;

typedef struct xfs_flock64
{
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;  /* len == 0 means until end of file */
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4]; /* reserve area			    */
} xfs_flock64_t;

struct dioattr
{
	__u32 d_mem;  /* data buffer memory alignment */
	__u32 d_miniosz; /* min xfer size		*/
	__u32 d_maxiosz; /* max xfer size		*/
};

struct getbmap
{
	__s64 bmv_offset; /* file offset of segment in blocks */
	__s64 bmv_block; /* starting block (64-bit daddr_t)  */
	__s64 bmv_length; /* length of segment, blocks	    */
	__s32 bmv_count; /* # of entries in array incl. 1st  */
	__s32 bmv_entries; /* # of entries filled in (output)  */
};

struct xfs_fs_eofblocks
{
	__u32 eof_version;
	__u32 eof_flags;
	uid_t eof_uid;
	gid_t eof_gid;
	prid_t eof_prid;
	__u32 pad32;
	__u64 eof_min_file_size;
	__u64 pad64[12];
};

struct xfs_scrub_metadata
{
	__u32 sm_type;  /* What to check? */
	__u32 sm_flags;  /* flags; see below. */
	__u64 sm_ino;  /* inode number. */
	__u32 sm_gen;  /* inode generation. */
	__u32 sm_agno;  /* ag number. */
	__u64 sm_reserved[5]; /* pad to 64 bytes */
};

struct xfs_ag_geometry
{
	uint32_t ag_number; /* i/o: AG number */
	uint32_t ag_length; /* o: length in blocks */
	uint32_t ag_freeblks; /* o: free space */
	uint32_t ag_icount; /* o: inodes allocated */
	uint32_t ag_ifree; /* o: inodes free */
	uint32_t ag_sick; /* o: sick things in ag */
	uint32_t ag_checked; /* o: checked metadata in ag */
	uint32_t ag_flags; /* i/o: flags for this ag */
	uint64_t ag_reserved[12];/* o: zero */
};

struct xfs_fsop_geom_v1
{
	__u32 blocksize; /* filesystem (data) block size */
	__u32 rtextsize; /* realtime extent size		*/
	__u32 agblocks; /* fsblocks in an AG		*/
	__u32 agcount; /* number of allocation groups	*/
	__u32 logblocks; /* fsblocks in the log		*/
	__u32 sectsize; /* (data) sector size, bytes	*/
	__u32 inodesize; /* inode size in bytes		*/
	__u32 imaxpct; /* max allowed inode space(%)	*/
	__u64 datablocks; /* fsblocks in data subvolume	*/
	__u64 rtblocks; /* fsblocks in realtime subvol	*/
	__u64 rtextents; /* rt extents in realtime subvol*/
	__u64 logstart; /* starting fsblock of the log	*/
	unsigned char uuid[16]; /* unique id of the filesystem	*/
	__u32 sunit;  /* stripe unit, fsblocks	*/
	__u32 swidth;  /* stripe width, fsblocks	*/
	__s32 version; /* structure version		*/
	__u32 flags;  /* superblock version flags	*/
	__u32 logsectsize; /* log sector size, bytes	*/
	__u32 rtsectsize; /* realtime sector size, bytes	*/
	__u32 dirblocksize; /* directory block size, bytes	*/
};

struct xfs_fsop_geom_v4
{
	__u32 blocksize; /* filesystem (data) block size */
	__u32 rtextsize; /* realtime extent size		*/
	__u32 agblocks; /* fsblocks in an AG		*/
	__u32 agcount; /* number of allocation groups	*/
	__u32 logblocks; /* fsblocks in the log		*/
	__u32 sectsize; /* (data) sector size, bytes	*/
	__u32 inodesize; /* inode size in bytes		*/
	__u32 imaxpct; /* max allowed inode space(%)	*/
	__u64 datablocks; /* fsblocks in data subvolume	*/
	__u64 rtblocks; /* fsblocks in realtime subvol	*/
	__u64 rtextents; /* rt extents in realtime subvol*/
	__u64 logstart; /* starting fsblock of the log	*/
	unsigned char uuid[16]; /* unique id of the filesystem	*/
	__u32 sunit;  /* stripe unit, fsblocks	*/
	__u32 swidth;  /* stripe width, fsblocks	*/
	__s32 version; /* structure version		*/
	__u32 flags;  /* superblock version flags	*/
	__u32 logsectsize; /* log sector size, bytes	*/
	__u32 rtsectsize; /* realtime sector size, bytes	*/
	__u32 dirblocksize; /* directory block size, bytes	*/
	__u32 logsunit; /* log stripe unit, bytes	*/
};

struct xfs_fsop_geom
{
	__u32 blocksize; /* filesystem (data) block size */
	__u32 rtextsize; /* realtime extent size		*/
	__u32 agblocks; /* fsblocks in an AG		*/
	__u32 agcount; /* number of allocation groups	*/
	__u32 logblocks; /* fsblocks in the log		*/
	__u32 sectsize; /* (data) sector size, bytes	*/
	__u32 inodesize; /* inode size in bytes		*/
	__u32 imaxpct; /* max allowed inode space(%)	*/
	__u64 datablocks; /* fsblocks in data subvolume	*/
	__u64 rtblocks; /* fsblocks in realtime subvol	*/
	__u64 rtextents; /* rt extents in realtime subvol*/
	__u64 logstart; /* starting fsblock of the log	*/
	unsigned char uuid[16]; /* unique id of the filesystem	*/
	__u32 sunit;  /* stripe unit, fsblocks	*/
	__u32 swidth;  /* stripe width, fsblocks	*/
	__s32 version; /* structure version		*/
	__u32 flags;  /* superblock version flags	*/
	__u32 logsectsize; /* log sector size, bytes	*/
	__u32 rtsectsize; /* realtime sector size, bytes	*/
	__u32 dirblocksize; /* directory block size, bytes	*/
	__u32 logsunit; /* log stripe unit, bytes	*/
	uint32_t sick;  /* o: unhealthy fs & rt metadata */
	uint32_t checked; /* o: checked fs & rt metadata	*/
	__u64 reserved[17]; /* reserved space		*/
};

struct xfs_fsop_bulkreq
{
	__u64 *lastip; /* last inode # pointer		*/
	__s32 icount;  /* count of entries in buffer	*/
	void *ubuffer;/* user buffer for inode desc.	*/
	__s32 *ocount; /* output count pointer		*/
};

typedef struct xfs_fsop_handlereq
{
	__u32 fd;  /* fd for FD_TO_HANDLE		*/
	void *path; /* user pathname		*/
	__u32 oflags;  /* open flags			*/
	void *ihandle;/* user supplied handle		*/
	__u32 ihandlen; /* user supplied length		*/
	void *ohandle;/* user buffer for handle	*/
	__u32 *ohandlen;/* user buffer length		*/
} xfs_fsop_handlereq_t;

struct xfs_bstat
{
	__u64 bs_ino;  /* inode number			*/
	__u16 bs_mode; /* type and mode		*/
	__u16 bs_nlink; /* number of links		*/
	__u32 bs_uid;  /* user id			*/
	__u32 bs_gid;  /* group id			*/
	__u32 bs_rdev; /* device value			*/
	__s32 bs_blksize; /* block size			*/
	__s64 bs_size; /* file size			*/
	xfs_bstime_t bs_atime; /* access time			*/
	xfs_bstime_t bs_mtime; /* modify time			*/
	xfs_bstime_t bs_ctime; /* inode change time		*/
	int64_t bs_blocks; /* number of blocks		*/
	__u32 bs_xflags; /* extended flags		*/
	__s32 bs_extsize; /* extent size			*/
	__s32 bs_extents; /* number of extents		*/
	__u32 bs_gen;  /* generation count		*/
	__u16 bs_projid_lo; /* lower part of project id	*/
	__u16 bs_forkoff; /* inode fork offset in bytes	*/
	__u16 bs_projid_hi; /* higher part of project id	*/
	uint16_t bs_sick; /* sick inode metadata		*/
	uint16_t bs_checked; /* checked inode metadata	*/
	unsigned char bs_pad[2]; /* pad space, unused		*/
	__u32 bs_cowextsize; /* cow extent size		*/
	__u32 bs_dmevmask; /* DMIG event mask		*/
	__u16 bs_dmstate; /* DMIG state info		*/
	__u16 bs_aextents; /* attribute number of extents	*/
};

typedef struct xfs_swapext
{
	int64_t sx_version; /* version */
	int64_t sx_fdtarget; /* fd of target file */
	int64_t sx_fdtmp; /* fd of tmp file */
	xfs_off_t sx_offset; /* offset into file */
	xfs_off_t sx_length; /* leng from offset */
	char sx_pad[16]; /* pad space, unused */
	struct xfs_bstat sx_stat; /* stat of target b4 copy */
} xfs_swapext_t;

typedef struct xfs_growfs_data
{
	__u64 newblocks; /* new data subvol size, fsblocks */
	__u32 imaxpct; /* new inode space percentage limit */
} xfs_growfs_data_t;

typedef struct xfs_growfs_log
{
	__u32 newblocks; /* new log size, fsblocks */
	__u32 isint;  /* 1 if new log is internal */
} xfs_growfs_log_t;

typedef struct xfs_growfs_rt
{
	__u64 newblocks; /* new realtime size, fsblocks */
	__u32 extsize; /* new realtime extent size, fsblocks */
} xfs_growfs_rt_t;

typedef struct xfs_fsop_counts
{
	__u64 freedata; /* free data section blocks */
	__u64 freertx; /* free rt extents */
	__u64 freeino; /* free inodes */
	__u64 allocino; /* total allocated inodes */
} xfs_fsop_counts_t;

typedef struct xfs_fsop_resblks
{
	__u64 resblks;
	__u64 resblks_avail;
} xfs_fsop_resblks_t;

typedef struct xfs_error_injection
{
	__s32 fd;
	__s32 errtag;
} xfs_error_injection_t;

typedef struct xfs_attrlist_cursor
{
	__u32 opaque[4];
} xfs_attrlist_cursor_t;

typedef struct xfs_fsop_attrlist_handlereq
{
	struct xfs_fsop_handlereq hreq; /* handle interface structure */
	struct xfs_attrlist_cursor pos; /* opaque cookie, list offset */
	__u32 flags; /* which namespace to use */
	__u32 buflen; /* length of buffer supplied */
	void *buffer; /* returned names */
} xfs_fsop_attrlist_handlereq_t;

typedef struct xfs_fsop_attrmulti_handlereq
{
	struct xfs_fsop_handlereq hreq; /* handle interface structure */
	__u32 opcount;/* count of following multiop */
	struct xfs_attr_multiop *ops; /* attr_multi data */
} xfs_fsop_attrmulti_handlereq_t;

struct xfs_bulk_ireq
{
	uint64_t ino;  /* I/O: start with this inode	*/
	uint32_t flags;  /* I/O: operation flags		*/
	uint32_t icount;  /* I: count of entries in buffer */
	uint32_t ocount;  /* O: count of entries filled out */
	uint32_t agno;  /* I: see comment for IREQ_AGNO	*/
	uint64_t reserved[5]; /* must be zero			*/
};

struct xfs_bulkstat
{
	uint64_t bs_ino;  /* inode number			*/
	uint64_t bs_size; /* file size			*/

	uint64_t bs_blocks; /* number of blocks		*/
	uint64_t bs_xflags; /* extended flags		*/

	int64_t bs_atime; /* access time, seconds		*/
	int64_t bs_mtime; /* modify time, seconds		*/

	int64_t bs_ctime; /* inode change time, seconds	*/
	int64_t bs_btime; /* creation time, seconds	*/

	uint32_t bs_gen;  /* generation count		*/
	uint32_t bs_uid;  /* user id			*/
	uint32_t bs_gid;  /* group id			*/
	uint32_t bs_projectid; /* project id			*/

	uint32_t bs_atime_nsec; /* access time, nanoseconds	*/
	uint32_t bs_mtime_nsec; /* modify time, nanoseconds	*/
	uint32_t bs_ctime_nsec; /* inode change time, nanoseconds */
	uint32_t bs_btime_nsec; /* creation time, nanoseconds	*/

	uint32_t bs_blksize; /* block size			*/
	uint32_t bs_rdev; /* device value			*/
	uint32_t bs_cowextsize_blks; /* cow extent size hint, blocks */
	uint32_t bs_extsize_blks; /* extent size hint, blocks	*/

	uint32_t bs_nlink; /* number of links		*/
	uint32_t bs_extents; /* 32-bit data fork extent counter */
	uint32_t bs_aextents; /* attribute number of extents	*/
	uint16_t bs_version; /* structure version		*/
	uint16_t bs_forkoff; /* inode fork offset in bytes	*/

	uint16_t bs_sick; /* sick inode metadata		*/
	uint16_t bs_checked; /* checked inode metadata	*/
	uint16_t bs_mode; /* type and mode		*/
	uint16_t bs_pad2; /* zeroed			*/
	uint64_t bs_extents64; /* 64-bit data fork extent counter */

	uint64_t bs_pad[6]; /* zeroed			*/
};

struct xfs_bulkstat_req
{
	struct xfs_bulk_ireq hdr;
	struct xfs_bulkstat bulkstat[];
};

struct xfs_inumbers
{
	uint64_t xi_startino; /* starting inode number	*/
	uint64_t xi_allocmask; /* mask of allocated inodes	*/
	uint8_t xi_alloccount; /* # bits set in allocmask	*/
	uint8_t xi_version; /* version			*/
	uint8_t xi_padding[6]; /* zero				*/
};

struct xfs_inumbers_req
{
	struct xfs_bulk_ireq hdr;
	struct xfs_inumbers inumbers[];
};

#define XFS_IOC_ALLOCSP _IOW('X', 10, struct xfs_flock64)
#define XFS_IOC_FREESP _IOW('X', 11, struct xfs_flock64)
#define XFS_IOC_ALLOCSP64 _IOW('X', 36, struct xfs_flock64)
#define XFS_IOC_FREESP64 _IOW('X', 37, struct xfs_flock64)

#define XFS_IOC_DIOINFO _IOR('X', 30, struct dioattr)
#define XFS_IOC_FSGETXATTR FS_IOC_FSGETXATTR
#define XFS_IOC_FSSETXATTR FS_IOC_FSSETXATTR
/*	XFS_IOC_ALLOCSP64 ----- deprecated 36	 */
/*	XFS_IOC_FREESP64 ------ deprecated 37	 */
#define XFS_IOC_GETBMAP _IOWR('X', 38, struct getbmap)
/*      XFS_IOC_FSSETDM ------- deprecated 39    */
#define XFS_IOC_RESVSP _IOW('X', 40, struct xfs_flock64)
#define XFS_IOC_UNRESVSP _IOW('X', 41, struct xfs_flock64)
#define XFS_IOC_RESVSP64 _IOW('X', 42, struct xfs_flock64)
#define XFS_IOC_UNRESVSP64 _IOW('X', 43, struct xfs_flock64)
#define XFS_IOC_GETBMAPA _IOWR('X', 44, struct getbmap)
#define XFS_IOC_FSGETXATTRA _IOR('X', 45, struct fsxattr)
/*	XFS_IOC_SETBIOSIZE ---- deprecated 46	   */
/*	XFS_IOC_GETBIOSIZE ---- deprecated 47	   */
#define XFS_IOC_GETBMAPX _IOWR('X', 56, struct getbmap)
#define XFS_IOC_ZERO_RANGE _IOW('X', 57, struct xfs_flock64)
#define XFS_IOC_FREE_EOFBLOCKS _IOR('X', 58, struct xfs_fs_eofblocks)
/*	XFS_IOC_GETFSMAP ------ hoisted 59         */
#define XFS_IOC_SCRUB_METADATA _IOWR('X', 60, struct xfs_scrub_metadata)
#define XFS_IOC_AG_GEOMETRY _IOWR('X', 61, struct xfs_ag_geometry)

#define XFS_IOC_FSGEOMETRY_V1 _IOR('X', 100, struct xfs_fsop_geom_v1)
#define XFS_IOC_FSBULKSTAT _IOWR('X', 101, struct xfs_fsop_bulkreq)
#define XFS_IOC_FSBULKSTAT_SINGLE _IOWR('X', 102, struct xfs_fsop_bulkreq)
#define XFS_IOC_FSINUMBERS _IOWR('X', 103, struct xfs_fsop_bulkreq)
#define XFS_IOC_PATH_TO_FSHANDLE _IOWR('X', 104, struct xfs_fsop_handlereq)
#define XFS_IOC_PATH_TO_HANDLE _IOWR('X', 105, struct xfs_fsop_handlereq)
#define XFS_IOC_FD_TO_HANDLE _IOWR('X', 106, struct xfs_fsop_handlereq)
#define XFS_IOC_OPEN_BY_HANDLE _IOWR('X', 107, struct xfs_fsop_handlereq)
#define XFS_IOC_READLINK_BY_HANDLE _IOWR('X', 108, struct xfs_fsop_handlereq)
#define XFS_IOC_SWAPEXT _IOWR('X', 109, struct xfs_swapext)
#define XFS_IOC_FSGROWFSDATA _IOW('X', 110, struct xfs_growfs_data)
#define XFS_IOC_FSGROWFSLOG _IOW('X', 111, struct xfs_growfs_log)
#define XFS_IOC_FSGROWFSRT _IOW('X', 112, struct xfs_growfs_rt)
#define XFS_IOC_FSCOUNTS _IOR('X', 113, struct xfs_fsop_counts)
#define XFS_IOC_SET_RESBLKS _IOWR('X', 114, struct xfs_fsop_resblks)
#define XFS_IOC_GET_RESBLKS _IOR('X', 115, struct xfs_fsop_resblks)
#define XFS_IOC_ERROR_INJECTION _IOW('X', 116, struct xfs_error_injection)
#define XFS_IOC_ERROR_CLEARALL _IOW('X', 117, struct xfs_error_injection)
/*	XFS_IOC_ATTRCTL_BY_HANDLE -- deprecated 118	 */

#define XFS_IOC_FREEZE _IOWR('X', 119, int) /* aka FIFREEZE */
#define XFS_IOC_THAW _IOWR('X', 120, int) /* aka FITHAW */

/*      XFS_IOC_FSSETDM_BY_HANDLE -- deprecated 121      */
#define XFS_IOC_ATTRLIST_BY_HANDLE _IOW('X', 122, struct xfs_fsop_attrlist_handlereq)
#define XFS_IOC_ATTRMULTI_BY_HANDLE _IOW('X', 123, struct xfs_fsop_attrmulti_handlereq)
#define XFS_IOC_FSGEOMETRY_V4 _IOR('X', 124, struct xfs_fsop_geom_v4)
#define XFS_IOC_GOINGDOWN _IOR('X', 125, uint32_t)
#define XFS_IOC_FSGEOMETRY _IOR('X', 126, struct xfs_fsop_geom)
#define XFS_IOC_BULKSTAT _IOR('X', 127, struct xfs_bulkstat_req)
#define XFS_IOC_INUMBERS _IOR('X', 128, struct xfs_inumbers_req)

#define BLKGETLASTSECT _IO(0x12, 108) /* get last sector of block device */
#define BLKSETLASTSECT _IO(0x12, 109) /* set last sector of block device */

#define MEMSETOOBSEL _IOW('M', 9, struct nand_oobinfo)
#define MEMREAD _IOWR('M', 26, struct mtd_read_req)

#define F2FS_IOC_ABORT_ATOMIC_WRITE _IO(F2FS_IOCTL_MAGIC, 5)
#define F2FS_IOC_START_ATOMIC_REPLACE _IO(F2FS_IOCTL_MAGIC, 25)

#define I2C_RETRIES 0x0701
#define I2C_TIMEOUT 0x0702

#define I2C_SLAVE 0x0703
#define I2C_SLAVE_FORCE 0x0706
#define I2C_TENBIT 0x0704
#define I2C_FUNCS 0x0705
#define I2C_RDWR 0x0707
#define I2C_PEC 0x0708
#define I2C_SMBUS 0x0720

#define SOL_SCTP 132
#define SOL_UDPLITE 136
#define SOL_IPX 256
#define SOL_AX25 257
#define SOL_ATALK 258
#define SOL_NETROM 259
// #define	SOL_X25		262
#define SOL_ROSE 260
#define SOL_MPTCP 284
#define SOL_MCTP 285
#define SOL_SMC 286
#define SOL_VSOCK 287

#define FS_IOC_ENABLE_VERITY_OLD _IO('f', 133)

struct kdbus_notify_id_change
{
	__u64 id;
	__u64 flags;
} __attribute__((__aligned__(8)));

struct kdbus_notify_name_change
{
	struct kdbus_notify_id_change old_id;
	struct kdbus_notify_id_change new_id;
	char name[0];
} __attribute__((__aligned__(8)));

struct kdbus_creds
{
	__u32 uid;
	__u32 euid;
	__u32 suid;
	__u32 fsuid;
	__u32 gid;
	__u32 egid;
	__u32 sgid;
	__u32 fsgid;
} __attribute__((__aligned__(8)));

struct kdbus_pids
{
	__u64 pid;
	__u64 tid;
	__u64 ppid;
} __attribute__((__aligned__(8)));

struct kdbus_caps
{
	__u32 last_cap;
	__u32 caps[0];
} __attribute__((__aligned__(8)));

struct kdbus_audit
{
	__u32 sessionid;
	__u32 loginuid;
} __attribute__((__aligned__(8)));

struct kdbus_timestamp
{
	__u64 seqnum;
	__u64 monotonic_ns;
	__u64 realtime_ns;
} __attribute__((__aligned__(8)));

struct kdbus_vec
{
	__u64 size;
	union {
		__u64 address;
		__u64 offset;
	};
} __attribute__((__aligned__(8)));

struct kdbus_bloom_parameter
{
	__u64 size;
	__u64 n_hash;
} __attribute__((__aligned__(8)));

struct kdbus_bloom_filter
{
	__u64 generation;
	__u64 data[0];
} __attribute__((__aligned__(8)));

struct kdbus_memfd
{
	__u64 start;
	__u64 size;
	int fd;
	__u32 __pad;
} __attribute__((__aligned__(8)));

struct kdbus_name
{
	__u64 flags;
	char name[0];
} __attribute__((__aligned__(8)));

struct kdbus_policy_access
{
	__u64 type; /* USER, GROUP, WORLD */
	__u64 access; /* OWN, TALK, SEE */
	__u64 id; /* uid, gid, 0 */
} __attribute__((__aligned__(8)));

struct kdbus_item
{
	__u64 size;
	__u64 type;
	union {
		__u8 data[0];
		__u32 data32[0];
		__u64 data64[0];
		char str[0];

		__u64 id;
		struct kdbus_vec vec;
		struct kdbus_creds creds;
		struct kdbus_pids pids;
		struct kdbus_audit audit;
		struct kdbus_caps caps;
		struct kdbus_timestamp timestamp;
		struct kdbus_name name;
		struct kdbus_bloom_parameter bloom_parameter;
		struct kdbus_bloom_filter bloom_filter;
		struct kdbus_memfd memfd;
		int fds[0];
		struct kdbus_notify_name_change name_change;
		struct kdbus_notify_id_change id_change;
		struct kdbus_policy_access policy_access;
	};
} __attribute__((__aligned__(8)));

struct kdbus_msg
{
	__u64 size;
	__u64 flags;
	__s64 priority;
	__u64 dst_id;
	__u64 src_id;
	__u64 payload_type;
	__u64 cookie;
	union {
		__u64 timeout_ns;
		__u64 cookie_reply;
	};
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

struct kdbus_msg_info
{
	__u64 offset;
	__u64 msg_size;
	__u64 return_flags;
} __attribute__((__aligned__(8)));

struct kdbus_cmd_send
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__u64 msg_address;
	struct kdbus_msg_info reply;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

struct kdbus_cmd_recv
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__s64 priority;
	__u64 dropped_msgs;
	struct kdbus_msg_info msg;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

struct kdbus_cmd_free
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__u64 offset;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

/**
 * struct kdbus_cmd_hello - struct to say hello to kdbus
 * @size:		The total size of the structure
 * @flags:		Connection flags (KDBUS_HELLO_*), userspace → kernel
 * @return_flags:	Command return flags, kernel → userspace
 * @attach_flags_send:	Mask of metadata to attach to each message sent
 *			off by this connection (KDBUS_ATTACH_*)
 * @attach_flags_recv:	Mask of metadata to attach to each message receieved
 *			by the new connection (KDBUS_ATTACH_*)
 * @bus_flags:		The flags field copied verbatim from the original
 *			KDBUS_CMD_BUS_MAKE ioctl. It's intended to be useful
 *			to do negotiation of features of the payload that is
 *			transferred (kernel → userspace)
 * @id:			The ID of this connection (kernel → userspace)
 * @pool_size:		Size of the connection's buffer where the received
 *			messages are placed
 * @offset:		Pool offset where additional items of type
 *			kdbus_item_list are stored. They contain information
 *			about the bus and the newly created connection.
 * @items_size:		Copy of item_list.size stored in @offset.
 * @id128:		Unique 128-bit ID of the bus (kernel → userspace)
 * @items:		A list of items
 *
 * This struct is used with the KDBUS_CMD_HELLO ioctl.
 */
struct kdbus_cmd_hello
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__u64 attach_flags_send;
	__u64 attach_flags_recv;
	__u64 bus_flags;
	__u64 id;
	__u64 pool_size;
	__u64 offset;
	__u64 items_size;
	__u8 id128[16];
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

/**
 * struct kdbus_info - connection information
 * @size:		total size of the struct
 * @id:			64bit object ID
 * @flags:		object creation flags
 * @items:		list of items
 *
 * Note that the user is responsible for freeing the allocated memory with
 * the KDBUS_CMD_FREE ioctl.
 */
struct kdbus_info
{
	__u64 size;
	__u64 id;
	__u64 flags;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

/**
 * enum kdbus_list_flags - what to include into the returned list
 * @KDBUS_LIST_UNIQUE:		active connections
 * @KDBUS_LIST_ACTIVATORS:	activator connections
 * @KDBUS_LIST_NAMES:		known well-known names
 * @KDBUS_LIST_QUEUED:		queued-up names
 */
enum kdbus_list_flags
{
	KDBUS_LIST_UNIQUE = 1ULL << 0,
	KDBUS_LIST_NAMES = 1ULL << 1,
	KDBUS_LIST_ACTIVATORS = 1ULL << 2,
	KDBUS_LIST_QUEUED = 1ULL << 3,
};

/**
 * struct kdbus_cmd_list - list connections
 * @size:		overall size of this object
 * @flags:		flags for the query (KDBUS_LIST_*), userspace → kernel
 * @return_flags:	command return flags, kernel → userspace
 * @offset:		Offset in the caller's pool buffer where an array of
 *			kdbus_info objects is stored.
 *			The user must use KDBUS_CMD_FREE to free the
 *			allocated memory.
 * @list_size:		size of returned list in bytes
 * @items:		Items for the command. Reserved for future use.
 *
 * This structure is used with the KDBUS_CMD_LIST ioctl.
 */
struct kdbus_cmd_list
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__u64 offset;
	__u64 list_size;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

/**
 * struct kdbus_cmd_info - struct used for KDBUS_CMD_CONN_INFO ioctl
 * @size:		The total size of the struct
 * @flags:		KDBUS_ATTACH_* flags, userspace → kernel
 * @return_flags:	Command return flags, kernel → userspace
 * @id:			The 64-bit ID of the connection. If set to zero, passing
 *			@name is required. kdbus will look up the name to
 *			determine the ID in this case.
 * @offset:		Returned offset in the caller's pool buffer where the
 *			kdbus_info struct result is stored. The user must
 *			use KDBUS_CMD_FREE to free the allocated memory.
 * @info_size:		Output buffer to report size of data at @offset.
 * @items:		The optional item list, containing the
 *			well-known name to look up as a KDBUS_ITEM_NAME.
 *			Only needed in case @id is zero.
 *
 * On success, the KDBUS_CMD_CONN_INFO ioctl will return 0 and @offset will
 * tell the user the offset in the connection pool buffer at which to find the
 * result in a struct kdbus_info.
 */
struct kdbus_cmd_info
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__u64 id;
	__u64 offset;
	__u64 info_size;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

/**
 * enum kdbus_cmd_match_flags - flags to control the KDBUS_CMD_MATCH_ADD ioctl
 * @KDBUS_MATCH_REPLACE:	If entries with the supplied cookie already
 *				exists, remove them before installing the new
 *				matches.
 */
enum kdbus_cmd_match_flags
{
	KDBUS_MATCH_REPLACE = 1ULL << 0,
};

/**
 * struct kdbus_cmd_match - struct to add or remove matches
 * @size:		The total size of the struct
 * @flags:		Flags for match command (KDBUS_MATCH_*),
 *			userspace → kernel
 * @return_flags:	Command return flags, kernel → userspace
 * @cookie:		Userspace supplied cookie. When removing, the cookie
 *			identifies the match to remove
 * @items:		A list of items for additional information
 *
 * This structure is used with the KDBUS_CMD_MATCH_ADD and
 * KDBUS_CMD_MATCH_REMOVE ioctl.
 */
struct kdbus_cmd_match
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	__u64 cookie;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

/**
 * enum kdbus_make_flags - Flags for KDBUS_CMD_{BUS,ENDPOINT}_MAKE
 * @KDBUS_MAKE_ACCESS_GROUP:	Make the bus or endpoint node group-accessible
 * @KDBUS_MAKE_ACCESS_WORLD:	Make the bus or endpoint node world-accessible
 */
enum kdbus_make_flags
{
	KDBUS_MAKE_ACCESS_GROUP = 1ULL << 0,
	KDBUS_MAKE_ACCESS_WORLD = 1ULL << 1,
};

/**
 * enum kdbus_name_flags - flags for KDBUS_CMD_NAME_ACQUIRE
 * @KDBUS_NAME_REPLACE_EXISTING:	Try to replace name of other connections
 * @KDBUS_NAME_ALLOW_REPLACEMENT:	Allow the replacement of the name
 * @KDBUS_NAME_QUEUE:			Name should be queued if busy
 * @KDBUS_NAME_IN_QUEUE:		Name is queued
 * @KDBUS_NAME_ACTIVATOR:		Name is owned by a activator connection
 */
enum kdbus_name_flags
{
	KDBUS_NAME_REPLACE_EXISTING = 1ULL << 0,
	KDBUS_NAME_ALLOW_REPLACEMENT = 1ULL << 1,
	KDBUS_NAME_QUEUE = 1ULL << 2,
	KDBUS_NAME_IN_QUEUE = 1ULL << 3,
	KDBUS_NAME_ACTIVATOR = 1ULL << 4,
};

/**
 * struct kdbus_cmd - generic ioctl payload
 * @size:		Overall size of this structure
 * @flags:		Flags for this ioctl, userspace → kernel
 * @return_flags:	Ioctl return flags, kernel → userspace
 * @items:		Additional items to modify the behavior
 *
 * This is a generic ioctl payload object. It's used by all ioctls that only
 * take flags and items as input.
 */
struct kdbus_cmd
{
	__u64 size;
	__u64 flags;
	__u64 return_flags;
	struct kdbus_item items[0];
} __attribute__((__aligned__(8)));

#define KDBUS_IOCTL_MAGIC 0x95
enum kdbus_ioctl_type
{
	/* bus owner (00-0f) */
	KDBUS_CMD_BUS_MAKE = _IOW(KDBUS_IOCTL_MAGIC, 0x00, struct kdbus_cmd),

	/* endpoint owner (10-1f) */
	KDBUS_CMD_ENDPOINT_MAKE = _IOW(KDBUS_IOCTL_MAGIC, 0x10, struct kdbus_cmd),
	KDBUS_CMD_ENDPOINT_UPDATE = _IOW(KDBUS_IOCTL_MAGIC, 0x11, struct kdbus_cmd),

	/* connection owner (80-ff) */
	KDBUS_CMD_HELLO = _IOWR(KDBUS_IOCTL_MAGIC, 0x80, struct kdbus_cmd_hello),
	KDBUS_CMD_UPDATE = _IOW(KDBUS_IOCTL_MAGIC, 0x81, struct kdbus_cmd),
	KDBUS_CMD_BYEBYE = _IOW(KDBUS_IOCTL_MAGIC, 0x82, struct kdbus_cmd),
	KDBUS_CMD_FREE = _IOW(KDBUS_IOCTL_MAGIC, 0x83, struct kdbus_cmd_free),
	KDBUS_CMD_CONN_INFO = _IOR(KDBUS_IOCTL_MAGIC, 0x84, struct kdbus_cmd_info),
	KDBUS_CMD_BUS_CREATOR_INFO = _IOR(KDBUS_IOCTL_MAGIC, 0x85, struct kdbus_cmd_info),
	KDBUS_CMD_LIST = _IOR(KDBUS_IOCTL_MAGIC, 0x86, struct kdbus_cmd_list),

	KDBUS_CMD_SEND = _IOW(KDBUS_IOCTL_MAGIC, 0x90, struct kdbus_cmd_send),
	KDBUS_CMD_RECV = _IOR(KDBUS_IOCTL_MAGIC, 0x91, struct kdbus_cmd_recv),

	KDBUS_CMD_NAME_ACQUIRE = _IOW(KDBUS_IOCTL_MAGIC, 0xa0, struct kdbus_cmd),
	KDBUS_CMD_NAME_RELEASE = _IOW(KDBUS_IOCTL_MAGIC, 0xa1, struct kdbus_cmd),

	KDBUS_CMD_MATCH_ADD = _IOW(KDBUS_IOCTL_MAGIC, 0xb0, struct kdbus_cmd_match),
	KDBUS_CMD_MATCH_REMOVE = _IOW(KDBUS_IOCTL_MAGIC, 0xb1, struct kdbus_cmd_match),
};

#define HSMP_MAX_MSG_LEN 8
struct hsmp_message
{
	__u32 msg_id;   /* Message ID */
	__u16 num_args;  /* Number of input argument words in message */
	__u16 response_sz;  /* Number of expected output/response words */
	__u32 args[HSMP_MAX_MSG_LEN]; /* argument/response buffer */
	__u16 sock_ind;  /* socket number */
};
#define HSMP_BASE_IOCTL_NR 0xF8
#define HSMP_IOCTL_CMD _IOWR(HSMP_BASE_IOCTL_NR, 0, struct hsmp_message)

// workaround for old dma-buf header: https://lore.kernel.org/lkml/YoNx8a8+gvOWwfc9@kroah.com/T/
#define u32 __u32
#define u64 __u64

static struct enum_option ioctls[] = {
	// ioctl_tty
	DESCRIBE_ENUM(TCGETS),
	DESCRIBE_ENUM(TCSETS),
	DESCRIBE_ENUM(TCSETSW),
	DESCRIBE_ENUM(TCSETSF),
	DESCRIBE_ENUM(TCGETA),
	DESCRIBE_ENUM(TCSETA),
	DESCRIBE_ENUM(TCSETAW),
	DESCRIBE_ENUM(TCSETAF),
	DESCRIBE_ENUM(TCSBRK),
	DESCRIBE_ENUM(TCXONC),
	DESCRIBE_ENUM(TCFLSH),
	DESCRIBE_ENUM(TIOCEXCL),
	DESCRIBE_ENUM(TIOCNXCL),
	DESCRIBE_ENUM(TIOCSCTTY),
	DESCRIBE_ENUM(TIOCGPGRP),
	DESCRIBE_ENUM(TIOCSPGRP),
	DESCRIBE_ENUM(TIOCOUTQ),
	DESCRIBE_ENUM(TIOCSTI),
	DESCRIBE_ENUM(TIOCGWINSZ),
	DESCRIBE_ENUM(TIOCSWINSZ),
	DESCRIBE_ENUM(TIOCMGET),
	DESCRIBE_ENUM(TIOCMBIS),
	DESCRIBE_ENUM(TIOCMBIC),
	DESCRIBE_ENUM(TIOCMSET),
	DESCRIBE_ENUM(TIOCGSOFTCAR),
	DESCRIBE_ENUM(TIOCSSOFTCAR),
	DESCRIBE_ENUM(FIONREAD),
	DESCRIBE_ENUM(TIOCLINUX),
	DESCRIBE_ENUM(TIOCCONS),
	DESCRIBE_ENUM(TIOCGSERIAL),
	DESCRIBE_ENUM(TIOCSSERIAL),
	DESCRIBE_ENUM(TIOCPKT),
	DESCRIBE_ENUM(FIONBIO),
	DESCRIBE_ENUM(TIOCNOTTY),
	DESCRIBE_ENUM(TIOCSETD),
	DESCRIBE_ENUM(TIOCGETD),
	DESCRIBE_ENUM(TCSBRKP),
	DESCRIBE_ENUM(TIOCSBRK),
	DESCRIBE_ENUM(TIOCCBRK),
	DESCRIBE_ENUM(TIOCGSID),
	DESCRIBE_ENUM(TCGETS2),
	DESCRIBE_ENUM(TCSETS2),
	DESCRIBE_ENUM(TCSETSW2),
	DESCRIBE_ENUM(TCSETSF2),
	DESCRIBE_ENUM(TIOCGRS485),
	DESCRIBE_ENUM(TIOCSRS485),
	DESCRIBE_ENUM(TIOCGPTN),
	DESCRIBE_ENUM(TIOCSPTLCK),
	DESCRIBE_ENUM(TIOCGDEV),
	DESCRIBE_ENUM(TCGETX),
	DESCRIBE_ENUM(TCSETX),
	DESCRIBE_ENUM(TCSETXF),
	DESCRIBE_ENUM(TCSETXW),
	DESCRIBE_ENUM(TIOCSIG),
	DESCRIBE_ENUM(TIOCVHANGUP),
	DESCRIBE_ENUM(TIOCGPKT),
	DESCRIBE_ENUM(TIOCGPTLCK),
	DESCRIBE_ENUM(TIOCGEXCL),
	DESCRIBE_ENUM(TIOCGPTPEER),
	DESCRIBE_ENUM(TIOCGISO7816),
	DESCRIBE_ENUM(TIOCSISO7816),
	DESCRIBE_ENUM(FIONCLEX),
	DESCRIBE_ENUM(FIOCLEX),
	DESCRIBE_ENUM(FIOASYNC),
	DESCRIBE_ENUM(TIOCSERCONFIG),
	DESCRIBE_ENUM(TIOCSERGWILD),
	DESCRIBE_ENUM(TIOCSERSWILD),
	DESCRIBE_ENUM(TIOCGLCKTRMIOS),
	DESCRIBE_ENUM(TIOCSLCKTRMIOS),
	DESCRIBE_ENUM(TIOCSERGSTRUCT),
	DESCRIBE_ENUM(TIOCSERGETLSR),
	DESCRIBE_ENUM(TIOCSERGETMULTI),
	DESCRIBE_ENUM(TIOCSERSETMULTI),
	DESCRIBE_ENUM(TIOCMIWAIT),
	DESCRIBE_ENUM(TIOCGICOUNT),
	// DESCRIBE_ENUM(TIOCGHAYESESP),
	// DESCRIBE_ENUM(TIOCSHAYESESP),
	DESCRIBE_ENUM(FIOQSIZE),
	DESCRIBE_ENUM(FIOGETOWN),
	DESCRIBE_ENUM(FIOSETOWN),
	DESCRIBE_ENUM(SIOCATMARK),
	DESCRIBE_ENUM(SIOCSPGRP),
	DESCRIBE_ENUM(SIOCGPGRP),
	DESCRIBE_ENUM(SIOCADDRT),
	DESCRIBE_ENUM(SIOCDELRT),
	DESCRIBE_ENUM(SIOCRTMSG),
	DESCRIBE_ENUM(SIOCGIFNAME),
	DESCRIBE_ENUM(SIOCSIFLINK),
	DESCRIBE_ENUM(SIOCGIFCONF),
	DESCRIBE_ENUM(SIOCGIFFLAGS),
	DESCRIBE_ENUM(SIOCSIFFLAGS),
	DESCRIBE_ENUM(SIOCGIFADDR),
	DESCRIBE_ENUM(SIOCSIFADDR),
	DESCRIBE_ENUM(SIOCGIFDSTADDR),
	DESCRIBE_ENUM(SIOCSIFDSTADDR),
	DESCRIBE_ENUM(SIOCGIFBRDADDR),
	DESCRIBE_ENUM(SIOCSIFBRDADDR),
	DESCRIBE_ENUM(SIOCGIFNETMASK),
	DESCRIBE_ENUM(SIOCSIFNETMASK),
	DESCRIBE_ENUM(SIOCGIFMETRIC),
	DESCRIBE_ENUM(SIOCSIFMETRIC),
	DESCRIBE_ENUM(SIOCGIFMEM),
	DESCRIBE_ENUM(SIOCSIFMEM),
	DESCRIBE_ENUM(SIOCGIFMTU),
	DESCRIBE_ENUM(SIOCSIFMTU),
	DESCRIBE_ENUM(SIOCSIFNAME),
	DESCRIBE_ENUM(SIOCSIFHWADDR),
	DESCRIBE_ENUM(SIOCGIFENCAP),
	DESCRIBE_ENUM(SIOCSIFENCAP),
	DESCRIBE_ENUM(SIOCGIFHWADDR),
	DESCRIBE_ENUM(SIOCGIFSLAVE),
	DESCRIBE_ENUM(SIOCSIFSLAVE),
	DESCRIBE_ENUM(SIOCADDMULTI),
	DESCRIBE_ENUM(SIOCDELMULTI),
	DESCRIBE_ENUM(SIOCGIFINDEX),
	DESCRIBE_ENUM(SIOCSIFPFLAGS),
	DESCRIBE_ENUM(SIOCGIFPFLAGS),
	DESCRIBE_ENUM(SIOCDIFADDR),
	DESCRIBE_ENUM(SIOCSIFHWBROADCAST),
	DESCRIBE_ENUM(SIOCGIFCOUNT),
	DESCRIBE_ENUM(SIOCGIFBR),
	DESCRIBE_ENUM(SIOCSIFBR),
	DESCRIBE_ENUM(SIOCGIFTXQLEN),
	DESCRIBE_ENUM(SIOCSIFTXQLEN),
	DESCRIBE_ENUM(SIOCDARP),
	DESCRIBE_ENUM(SIOCGARP),
	DESCRIBE_ENUM(SIOCSARP),
	DESCRIBE_ENUM(SIOCDRARP),
	DESCRIBE_ENUM(SIOCGRARP),
	DESCRIBE_ENUM(SIOCSRARP),
	DESCRIBE_ENUM(SIOCGIFMAP),
	DESCRIBE_ENUM(SIOCSIFMAP),
	DESCRIBE_ENUM(SIOCADDDLCI),
	DESCRIBE_ENUM(SIOCDELDLCI),
	DESCRIBE_ENUM(SIOCDEVPRIVATE),
	DESCRIBE_ENUM(SIOCPROTOPRIVATE),
	// ioctl_userfaultfd
	DESCRIBE_ENUM(UFFDIO_API),
	DESCRIBE_ENUM(UFFDIO_REGISTER),
	DESCRIBE_ENUM(UFFDIO_UNREGISTER),
	DESCRIBE_ENUM(UFFDIO_WAKE),
	DESCRIBE_ENUM(UFFDIO_COPY),
	DESCRIBE_ENUM(UFFDIO_ZEROPAGE),
	DESCRIBE_ENUM(UFFDIO_WRITEPROTECT),
	DESCRIBE_ENUM(UFFDIO_CONTINUE),
	// ioctl_console
	DESCRIBE_ENUM(KDGETLED),
	DESCRIBE_ENUM(KDSETLED),
	DESCRIBE_ENUM(KDGKBLED),
	DESCRIBE_ENUM(KDSKBLED),
	DESCRIBE_ENUM(KDGKBTYPE),
	DESCRIBE_ENUM(KDADDIO),
	DESCRIBE_ENUM(KDDELIO),
	DESCRIBE_ENUM(KDENABIO),
	DESCRIBE_ENUM(KDDISABIO),
	DESCRIBE_ENUM(KDSETMODE),
	DESCRIBE_ENUM(KDGETMODE),
	DESCRIBE_ENUM(KDMKTONE),
	DESCRIBE_ENUM(KIOCSOUND),
	DESCRIBE_ENUM(GIO_CMAP),
	DESCRIBE_ENUM(PIO_CMAP),
	DESCRIBE_ENUM(GIO_FONT),
	DESCRIBE_ENUM(GIO_FONTX),
	DESCRIBE_ENUM(PIO_FONT),
	DESCRIBE_ENUM(PIO_FONTX),
	DESCRIBE_ENUM(PIO_FONTRESET),
	DESCRIBE_ENUM(GIO_SCRNMAP),
	DESCRIBE_ENUM(GIO_UNISCRNMAP),
	DESCRIBE_ENUM(PIO_SCRNMAP),
	DESCRIBE_ENUM(PIO_UNISCRNMAP),
	DESCRIBE_ENUM(GIO_UNIMAP),
	DESCRIBE_ENUM(PIO_UNIMAP),
	DESCRIBE_ENUM(PIO_UNIMAPCLR),
	DESCRIBE_ENUM(KDGKBMODE),
	DESCRIBE_ENUM(KDSKBMODE),
	DESCRIBE_ENUM(KDGKBMETA),
	DESCRIBE_ENUM(KDSKBMETA),
	DESCRIBE_ENUM(KDGKBENT),
	DESCRIBE_ENUM(KDSKBENT),
	DESCRIBE_ENUM(KDGKBSENT),
	DESCRIBE_ENUM(KDSKBSENT),
	DESCRIBE_ENUM(KDGKBDIACR),
	DESCRIBE_ENUM(KDSKBDIACR),
	DESCRIBE_ENUM(KDGETKEYCODE),
	DESCRIBE_ENUM(KDSETKEYCODE),
	DESCRIBE_ENUM(KDSIGACCEPT),
	DESCRIBE_ENUM(VT_OPENQRY),
	DESCRIBE_ENUM(VT_GETMODE),
	DESCRIBE_ENUM(VT_SETMODE),
	DESCRIBE_ENUM(VT_GETSTATE),
	DESCRIBE_ENUM(VT_RELDISP),
	DESCRIBE_ENUM(VT_ACTIVATE),
	DESCRIBE_ENUM(VT_WAITACTIVE),
	DESCRIBE_ENUM(VT_DISALLOCATE),
	DESCRIBE_ENUM(VT_RESIZE),
	DESCRIBE_ENUM(VT_RESIZEX),
	DESCRIBE_ENUM(KDMAPDISP),
	DESCRIBE_ENUM(KDUNMAPDISP),
	DESCRIBE_ENUM(KDGKBDIACRUC),
	DESCRIBE_ENUM(KDSKBDIACRUC),
	DESCRIBE_ENUM(KDKBDREP),
	DESCRIBE_ENUM(KDFONTOP),
	// ioctl_ficlone
	DESCRIBE_ENUM(FICLONERANGE),
	DESCRIBE_ENUM(FICLONE),
	// ioctl_fideduperange
	DESCRIBE_ENUM(FIDEDUPERANGE),
	// ioctl_fslabel
	DESCRIBE_ENUM(FS_IOC_GETFSLABEL),
	DESCRIBE_ENUM(FS_IOC_SETFSLABEL),
	// ioctl_getfsmap
	DESCRIBE_ENUM(FS_IOC_GETFSMAP),
	// ioctl_iflags
	DESCRIBE_ENUM(FS_IOC_GETFLAGS),
	DESCRIBE_ENUM(FS_IOC_SETFLAGS),
	// seccomp_unotify
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_RECV),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_SEND),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ID_VALID),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ADDFD),
#ifdef __x86_64__
	// mtrr
	DESCRIBE_ENUM(MTRRIOC_ADD_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_SET_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_DEL_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_GET_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_KILL_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_ADD_PAGE_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_SET_PAGE_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_DEL_PAGE_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_GET_PAGE_ENTRY),
	DESCRIBE_ENUM(MTRRIOC_KILL_PAGE_ENTRY),
	// amd_hsmp
	DESCRIBE_ENUM(HSMP_IOCTL_CMD),
	// mce
	DESCRIBE_ENUM(MCE_GET_RECORD_LEN),
	DESCRIBE_ENUM(MCE_GET_LOG_LEN),
	DESCRIBE_ENUM(MCE_GETCLEAR_FLAGS),
	// msr
	DESCRIBE_ENUM(X86_IOC_RDMSR_REGS),
	DESCRIBE_ENUM(X86_IOC_WRMSR_REGS),
	// sgx
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_CREATE),
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_ADD_PAGES),
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_INIT),
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_PROVISION),
	DESCRIBE_ENUM(SGX_IOC_VEPC_REMOVE_ALL),
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS),
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_MODIFY_TYPES),
	DESCRIBE_ENUM(SGX_IOC_ENCLAVE_REMOVE_PAGES),
#endif
	// drm
	DESCRIBE_ENUM(DRM_IOCTL_VERSION),
	DESCRIBE_ENUM(DRM_IOCTL_GET_UNIQUE),
	DESCRIBE_ENUM(DRM_IOCTL_GET_MAGIC),
	DESCRIBE_ENUM(DRM_IOCTL_IRQ_BUSID),
	DESCRIBE_ENUM(DRM_IOCTL_GET_MAP),
	DESCRIBE_ENUM(DRM_IOCTL_GET_CLIENT),
	DESCRIBE_ENUM(DRM_IOCTL_GET_STATS),
	DESCRIBE_ENUM(DRM_IOCTL_SET_VERSION),
	DESCRIBE_ENUM(DRM_IOCTL_MODESET_CTL),
	DESCRIBE_ENUM(DRM_IOCTL_GEM_CLOSE),
	DESCRIBE_ENUM(DRM_IOCTL_GEM_FLINK),
	DESCRIBE_ENUM(DRM_IOCTL_GEM_OPEN),
	DESCRIBE_ENUM(DRM_IOCTL_GET_CAP),
	DESCRIBE_ENUM(DRM_IOCTL_SET_CLIENT_CAP),
	DESCRIBE_ENUM(DRM_IOCTL_SET_UNIQUE),
	DESCRIBE_ENUM(DRM_IOCTL_AUTH_MAGIC),
	DESCRIBE_ENUM(DRM_IOCTL_BLOCK),
	DESCRIBE_ENUM(DRM_IOCTL_UNBLOCK),
	DESCRIBE_ENUM(DRM_IOCTL_CONTROL),
	DESCRIBE_ENUM(DRM_IOCTL_ADD_MAP),
	DESCRIBE_ENUM(DRM_IOCTL_ADD_BUFS),
	DESCRIBE_ENUM(DRM_IOCTL_MARK_BUFS),
	DESCRIBE_ENUM(DRM_IOCTL_INFO_BUFS),
	DESCRIBE_ENUM(DRM_IOCTL_MAP_BUFS),
	DESCRIBE_ENUM(DRM_IOCTL_FREE_BUFS),
	DESCRIBE_ENUM(DRM_IOCTL_RM_MAP),
	DESCRIBE_ENUM(DRM_IOCTL_SET_SAREA_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_GET_SAREA_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_SET_MASTER),
	DESCRIBE_ENUM(DRM_IOCTL_DROP_MASTER),
	DESCRIBE_ENUM(DRM_IOCTL_ADD_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_RM_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_MOD_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_GET_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_SWITCH_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_NEW_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_RES_CTX),
	DESCRIBE_ENUM(DRM_IOCTL_ADD_DRAW),
	DESCRIBE_ENUM(DRM_IOCTL_RM_DRAW),
	DESCRIBE_ENUM(DRM_IOCTL_DMA),
	DESCRIBE_ENUM(DRM_IOCTL_LOCK),
	DESCRIBE_ENUM(DRM_IOCTL_UNLOCK),
	DESCRIBE_ENUM(DRM_IOCTL_FINISH),
	DESCRIBE_ENUM(DRM_IOCTL_PRIME_HANDLE_TO_FD),
	DESCRIBE_ENUM(DRM_IOCTL_PRIME_FD_TO_HANDLE),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_ACQUIRE),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_RELEASE),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_ENABLE),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_INFO),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_ALLOC),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_FREE),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_BIND),
	DESCRIBE_ENUM(DRM_IOCTL_AGP_UNBIND),
	DESCRIBE_ENUM(DRM_IOCTL_SG_ALLOC),
	DESCRIBE_ENUM(DRM_IOCTL_SG_FREE),
	DESCRIBE_ENUM(DRM_IOCTL_WAIT_VBLANK),
	DESCRIBE_ENUM(DRM_IOCTL_CRTC_GET_SEQUENCE),
	DESCRIBE_ENUM(DRM_IOCTL_CRTC_QUEUE_SEQUENCE),
	DESCRIBE_ENUM(DRM_IOCTL_UPDATE_DRAW),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETRESOURCES),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETCRTC),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_SETCRTC),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_CURSOR),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETGAMMA),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_SETGAMMA),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETENCODER),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETCONNECTOR),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_ATTACHMODE),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_DETACHMODE),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETPROPERTY),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_SETPROPERTY),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETPROPBLOB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETFB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_ADDFB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_RMFB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_PAGE_FLIP),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_DIRTYFB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_CREATE_DUMB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_MAP_DUMB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_DESTROY_DUMB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETPLANERESOURCES),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETPLANE),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_SETPLANE),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_ADDFB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_OBJ_GETPROPERTIES),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_OBJ_SETPROPERTY),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_CURSOR),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_ATOMIC),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_CREATEPROPBLOB),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_DESTROYPROPBLOB),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_CREATE),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_DESTROY),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_WAIT),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_RESET),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_SIGNAL),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_CREATE_LEASE),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_LIST_LESSEES),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GET_LEASE),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_REVOKE_LEASE),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_QUERY),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_TRANSFER),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_GETFB),
	DESCRIBE_ENUM(DRM_IOCTL_SYNCOBJ_EVENTFD),
	DESCRIBE_ENUM(DRM_IOCTL_MODE_CLOSEFB),
	// pktcdvd
	DESCRIBE_ENUM(PACKET_CTRL_CMD),
	// uinput
	DESCRIBE_ENUM(UI_DEV_CREATE),
	DESCRIBE_ENUM(UI_DEV_DESTROY),
	DESCRIBE_ENUM(UI_DEV_SETUP),
	DESCRIBE_ENUM(UI_SET_EVBIT),
	DESCRIBE_ENUM(UI_SET_KEYBIT),
	DESCRIBE_ENUM(UI_SET_RELBIT),
	DESCRIBE_ENUM(UI_SET_ABSBIT),
	DESCRIBE_ENUM(UI_SET_MSCBIT),
	DESCRIBE_ENUM(UI_SET_LEDBIT),
	DESCRIBE_ENUM(UI_SET_SNDBIT),
	DESCRIBE_ENUM(UI_SET_FFBIT),
	DESCRIBE_ENUM(UI_SET_PHYS),
	DESCRIBE_ENUM(UI_SET_SWBIT),
	DESCRIBE_ENUM(UI_SET_PROPBIT),
	DESCRIBE_ENUM(UI_BEGIN_FF_UPLOAD),
	DESCRIBE_ENUM(UI_END_FF_UPLOAD),
	DESCRIBE_ENUM(UI_BEGIN_FF_ERASE),
	DESCRIBE_ENUM(UI_END_FF_ERASE),
	DESCRIBE_ENUM(UI_GET_VERSION),
	// mmtimer
	DESCRIBE_ENUM(MMTIMER_GETOFFSET),
	DESCRIBE_ENUM(MMTIMER_GETRES),
	DESCRIBE_ENUM(MMTIMER_GETFREQ),
	DESCRIBE_ENUM(MMTIMER_GETBITS),
	DESCRIBE_ENUM(MMTIMER_MMAPAVAIL),
	DESCRIBE_ENUM(MMTIMER_GETCOUNTER),
	// kfd_ioctl
	DESCRIBE_ENUM(AMDKFD_IOC_GET_VERSION),
	DESCRIBE_ENUM(AMDKFD_IOC_CREATE_QUEUE),
	DESCRIBE_ENUM(AMDKFD_IOC_DESTROY_QUEUE),
	DESCRIBE_ENUM(AMDKFD_IOC_SET_MEMORY_POLICY),
	DESCRIBE_ENUM(AMDKFD_IOC_GET_CLOCK_COUNTERS),
	DESCRIBE_ENUM(AMDKFD_IOC_GET_PROCESS_APERTURES),
	DESCRIBE_ENUM(AMDKFD_IOC_UPDATE_QUEUE),
	DESCRIBE_ENUM(AMDKFD_IOC_CREATE_EVENT),
	DESCRIBE_ENUM(AMDKFD_IOC_DESTROY_EVENT),
	DESCRIBE_ENUM(AMDKFD_IOC_SET_EVENT),
	DESCRIBE_ENUM(AMDKFD_IOC_RESET_EVENT),
	DESCRIBE_ENUM(AMDKFD_IOC_WAIT_EVENTS),
	// DESCRIBE_ENUM(AMDKFD_IOC_DBG_REGISTER_DEPRECATED),
	// DESCRIBE_ENUM(AMDKFD_IOC_DBG_UNREGISTER_DEPRECATED),
	// DESCRIBE_ENUM(AMDKFD_IOC_DBG_ADDRESS_WATCH_DEPRECATED),
	// DESCRIBE_ENUM(AMDKFD_IOC_DBG_WAVE_CONTROL_DEPRECATED),
	DESCRIBE_ENUM(AMDKFD_IOC_SET_SCRATCH_BACKING_VA),
	DESCRIBE_ENUM(AMDKFD_IOC_GET_TILE_CONFIG),
	DESCRIBE_ENUM(AMDKFD_IOC_SET_TRAP_HANDLER),
	DESCRIBE_ENUM(AMDKFD_IOC_GET_PROCESS_APERTURES_NEW),
	DESCRIBE_ENUM(AMDKFD_IOC_ACQUIRE_VM),
	DESCRIBE_ENUM(AMDKFD_IOC_ALLOC_MEMORY_OF_GPU),
	DESCRIBE_ENUM(AMDKFD_IOC_FREE_MEMORY_OF_GPU),
	DESCRIBE_ENUM(AMDKFD_IOC_MAP_MEMORY_TO_GPU),
	DESCRIBE_ENUM(AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU),
	DESCRIBE_ENUM(AMDKFD_IOC_SET_CU_MASK),
	DESCRIBE_ENUM(AMDKFD_IOC_GET_QUEUE_WAVE_STATE),
	DESCRIBE_ENUM(AMDKFD_IOC_GET_DMABUF_INFO),
	DESCRIBE_ENUM(AMDKFD_IOC_IMPORT_DMABUF),
	DESCRIBE_ENUM(AMDKFD_IOC_ALLOC_QUEUE_GWS),
	DESCRIBE_ENUM(AMDKFD_IOC_SMI_EVENTS),
	DESCRIBE_ENUM(AMDKFD_IOC_SVM),
	DESCRIBE_ENUM(AMDKFD_IOC_SET_XNACK_MODE),
	// DESCRIBE_ENUM(AMDKFD_IOC_CRIU_OP),
	// DESCRIBE_ENUM(AMDKFD_IOC_AVAILABLE_MEMORY),
	// DESCRIBE_ENUM(AMDKFD_IOC_EXPORT_DMABUF),
	// DESCRIBE_ENUM(AMDKFD_IOC_RUNTIME_ENABLE),
	// DESCRIBE_ENUM(AMDKFD_IOC_DBG_TRAP),
	// 3w-xxxx
	DESCRIBE_ENUM(TW_OP_NOP),
	DESCRIBE_ENUM(TW_OP_INIT_CONNECTION),
	DESCRIBE_ENUM(TW_OP_READ),
	DESCRIBE_ENUM(TW_OP_WRITE),
	DESCRIBE_ENUM(TW_OP_VERIFY),
	DESCRIBE_ENUM(TW_OP_GET_PARAM),
	DESCRIBE_ENUM(TW_OP_SET_PARAM),
	DESCRIBE_ENUM(TW_OP_SECTOR_INFO),
	DESCRIBE_ENUM(TW_OP_AEN_LISTEN),
	DESCRIBE_ENUM(TW_OP_FLUSH_CACHE),
	DESCRIBE_ENUM(TW_CMD_PACKET),
	DESCRIBE_ENUM(TW_CMD_PACKET_WITH_DATA),
	// autofs
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_VERSION),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_PROTOVER),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_PROTOSUBVER),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_OPENMOUNT),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_CLOSEMOUNT),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_READY),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_FAIL),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_SETPIPEFD),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_CATATONIC),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_TIMEOUT),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_REQUESTER),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_EXPIRE),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_ASKUMOUNT),
	DESCRIBE_ENUM(AUTOFS_DEV_IOCTL_ISMOUNTPOINT),
	DESCRIBE_ENUM(AUTOFS_IOC_READY),
	DESCRIBE_ENUM(AUTOFS_IOC_FAIL),
	DESCRIBE_ENUM(AUTOFS_IOC_CATATONIC),
	DESCRIBE_ENUM(AUTOFS_IOC_PROTOVER),
	DESCRIBE_ENUM(AUTOFS_IOC_SETTIMEOUT32),
	DESCRIBE_ENUM(AUTOFS_IOC_SETTIMEOUT),
	DESCRIBE_ENUM(AUTOFS_IOC_EXPIRE),
	// blkpg
	DESCRIBE_ENUM(BLKPG),
	// blkzoned
	DESCRIBE_ENUM(BLKREPORTZONE),
	DESCRIBE_ENUM(BLKRESETZONE),
	DESCRIBE_ENUM(BLKGETZONESZ),
	DESCRIBE_ENUM(BLKGETNRZONES),
	DESCRIBE_ENUM(BLKOPENZONE),
	DESCRIBE_ENUM(BLKCLOSEZONE),
	DESCRIBE_ENUM(BLKFINISHZONE),
	// bluetooth
	DESCRIBE_ENUM(HCIUARTSETPROTO),
	DESCRIBE_ENUM(HCIUARTGETPROTO),
	DESCRIBE_ENUM(HCIUARTGETDEVICE),
	DESCRIBE_ENUM(HCIUARTSETFLAGS),
	DESCRIBE_ENUM(HCIUARTGETFLAGS),
	// bluetooth/hci_sock
	DESCRIBE_ENUM(HCIDEVUP),
	DESCRIBE_ENUM(HCIDEVDOWN),
	DESCRIBE_ENUM(HCIDEVRESET),
	DESCRIBE_ENUM(HCIDEVRESTAT),
	DESCRIBE_ENUM(HCIGETDEVLIST),
	DESCRIBE_ENUM(HCIGETDEVINFO),
	DESCRIBE_ENUM(HCIGETCONNLIST),
	DESCRIBE_ENUM(HCIGETCONNINFO),
	DESCRIBE_ENUM(HCIGETAUTHINFO),
	DESCRIBE_ENUM(HCISETRAW),
	DESCRIBE_ENUM(HCISETSCAN),
	DESCRIBE_ENUM(HCISETAUTH),
	DESCRIBE_ENUM(HCISETENCRYPT),
	DESCRIBE_ENUM(HCISETPTYPE),
	DESCRIBE_ENUM(HCISETLINKPOL),
	DESCRIBE_ENUM(HCISETLINKMODE),
	DESCRIBE_ENUM(HCISETACLMTU),
	DESCRIBE_ENUM(HCISETSCOMTU),
	DESCRIBE_ENUM(HCIBLOCKADDR),
	DESCRIBE_ENUM(HCIUNBLOCKADDR),
	DESCRIBE_ENUM(HCIINQUIRY),
	// btrfs
	DESCRIBE_ENUM(BTRFS_IOC_SNAP_CREATE),
	DESCRIBE_ENUM(BTRFS_IOC_DEFRAG),
	DESCRIBE_ENUM(BTRFS_IOC_RESIZE),
	DESCRIBE_ENUM(BTRFS_IOC_SCAN_DEV),
	DESCRIBE_ENUM(BTRFS_IOC_FORGET_DEV),
	DESCRIBE_ENUM(BTRFS_IOC_TRANS_START),
	DESCRIBE_ENUM(BTRFS_IOC_TRANS_END),
	DESCRIBE_ENUM(BTRFS_IOC_SYNC),
	DESCRIBE_ENUM(BTRFS_IOC_CLONE),
	DESCRIBE_ENUM(BTRFS_IOC_ADD_DEV),
	DESCRIBE_ENUM(BTRFS_IOC_RM_DEV),
	DESCRIBE_ENUM(BTRFS_IOC_BALANCE),
	DESCRIBE_ENUM(BTRFS_IOC_CLONE_RANGE),
	DESCRIBE_ENUM(BTRFS_IOC_SUBVOL_CREATE),
	DESCRIBE_ENUM(BTRFS_IOC_SNAP_DESTROY),
	DESCRIBE_ENUM(BTRFS_IOC_DEFRAG_RANGE),
	DESCRIBE_ENUM(BTRFS_IOC_TREE_SEARCH),
	DESCRIBE_ENUM(BTRFS_IOC_TREE_SEARCH_V2),
	DESCRIBE_ENUM(BTRFS_IOC_INO_LOOKUP),
	DESCRIBE_ENUM(BTRFS_IOC_DEFAULT_SUBVOL),
	DESCRIBE_ENUM(BTRFS_IOC_SPACE_INFO),
	DESCRIBE_ENUM(BTRFS_IOC_START_SYNC),
	DESCRIBE_ENUM(BTRFS_IOC_WAIT_SYNC),
	DESCRIBE_ENUM(BTRFS_IOC_SNAP_CREATE_V2),
	DESCRIBE_ENUM(BTRFS_IOC_SUBVOL_CREATE_V2),
	DESCRIBE_ENUM(BTRFS_IOC_SUBVOL_GETFLAGS),
	DESCRIBE_ENUM(BTRFS_IOC_SUBVOL_SETFLAGS),
	DESCRIBE_ENUM(BTRFS_IOC_SCRUB),
	DESCRIBE_ENUM(BTRFS_IOC_SCRUB_CANCEL),
	DESCRIBE_ENUM(BTRFS_IOC_SCRUB_PROGRESS),
	DESCRIBE_ENUM(BTRFS_IOC_DEV_INFO),
	DESCRIBE_ENUM(BTRFS_IOC_FS_INFO),
	DESCRIBE_ENUM(BTRFS_IOC_BALANCE_V2),
	DESCRIBE_ENUM(BTRFS_IOC_BALANCE_CTL),
	DESCRIBE_ENUM(BTRFS_IOC_BALANCE_PROGRESS),
	DESCRIBE_ENUM(BTRFS_IOC_INO_PATHS),
	DESCRIBE_ENUM(BTRFS_IOC_LOGICAL_INO),
	DESCRIBE_ENUM(BTRFS_IOC_SET_RECEIVED_SUBVOL),
	DESCRIBE_ENUM(BTRFS_IOC_SEND),
	DESCRIBE_ENUM(BTRFS_IOC_DEVICES_READY),
	DESCRIBE_ENUM(BTRFS_IOC_QUOTA_CTL),
	DESCRIBE_ENUM(BTRFS_IOC_QGROUP_ASSIGN),
	DESCRIBE_ENUM(BTRFS_IOC_QGROUP_CREATE),
	DESCRIBE_ENUM(BTRFS_IOC_QGROUP_LIMIT),
	DESCRIBE_ENUM(BTRFS_IOC_QUOTA_RESCAN),
	DESCRIBE_ENUM(BTRFS_IOC_QUOTA_RESCAN_STATUS),
	DESCRIBE_ENUM(BTRFS_IOC_QUOTA_RESCAN_WAIT),
	DESCRIBE_ENUM(BTRFS_IOC_GET_FSLABEL),
	DESCRIBE_ENUM(BTRFS_IOC_SET_FSLABEL),
	DESCRIBE_ENUM(BTRFS_IOC_GET_DEV_STATS),
	DESCRIBE_ENUM(BTRFS_IOC_DEV_REPLACE),
	DESCRIBE_ENUM(BTRFS_IOC_FILE_EXTENT_SAME),
	DESCRIBE_ENUM(BTRFS_IOC_GET_FEATURES),
	DESCRIBE_ENUM(BTRFS_IOC_SET_FEATURES),
	DESCRIBE_ENUM(BTRFS_IOC_GET_SUPPORTED_FEATURES),
	DESCRIBE_ENUM(BTRFS_IOC_RM_DEV_V2),
	DESCRIBE_ENUM(BTRFS_IOC_LOGICAL_INO_V2),
	DESCRIBE_ENUM(BTRFS_IOC_GET_SUBVOL_INFO),
	DESCRIBE_ENUM(BTRFS_IOC_GET_SUBVOL_ROOTREF),
	DESCRIBE_ENUM(BTRFS_IOC_INO_LOOKUP_USER),
	DESCRIBE_ENUM(BTRFS_IOC_SNAP_DESTROY_V2),
	DESCRIBE_ENUM(BTRFS_IOC_ENCODED_READ),
	DESCRIBE_ENUM(BTRFS_IOC_ENCODED_WRITE),
	// cdrom
	DESCRIBE_ENUM(CDROM_GET_MCN),
	DESCRIBE_ENUM(CDROM_GET_UPC),
	DESCRIBE_ENUM(CDROM_SET_OPTIONS),
	DESCRIBE_ENUM(CDROM_CLEAR_OPTIONS),
	DESCRIBE_ENUM(CDROM_SELECT_SPEED),
	DESCRIBE_ENUM(CDROM_SELECT_DISC),
	DESCRIBE_ENUM(CDROM_MEDIA_CHANGED),
	DESCRIBE_ENUM(CDROM_DRIVE_STATUS),
	DESCRIBE_ENUM(CDROM_DISC_STATUS),
	DESCRIBE_ENUM(CDROM_CHANGER_NSLOTS),
	DESCRIBE_ENUM(CDROM_LOCKDOOR),
	DESCRIBE_ENUM(CDROM_DEBUG),
	DESCRIBE_ENUM(CDROM_GET_CAPABILITY),
	DESCRIBE_ENUM(CDROM_SEND_PACKET),
	DESCRIBE_ENUM(CDROM_NEXT_WRITABLE),
	DESCRIBE_ENUM(CDROM_LAST_WRITTEN),
	DESCRIBE_ENUM(CDROM_TIMED_MEDIA_CHANGE),
	DESCRIBE_ENUM(CDROMPAUSE),
	DESCRIBE_ENUM(CDROMRESUME),
	DESCRIBE_ENUM(CDROMPLAYMSF),
	DESCRIBE_ENUM(CDROMPLAYTRKIND),
	DESCRIBE_ENUM(CDROMREADTOCHDR),
	DESCRIBE_ENUM(CDROMREADTOCENTRY),
	DESCRIBE_ENUM(CDROMSTOP),
	DESCRIBE_ENUM(CDROMSTART),
	DESCRIBE_ENUM(CDROMEJECT),
	DESCRIBE_ENUM(CDROMVOLCTRL),
	DESCRIBE_ENUM(CDROMSUBCHNL),
	DESCRIBE_ENUM(CDROMREADMODE2),
	DESCRIBE_ENUM(CDROMREADMODE1),
	DESCRIBE_ENUM(CDROMREADAUDIO),
	DESCRIBE_ENUM(CDROMEJECT_SW),
	DESCRIBE_ENUM(CDROMMULTISESSION),
	DESCRIBE_ENUM(CDROM_GET_MCN),
	DESCRIBE_ENUM(CDROM_GET_UPC),
	DESCRIBE_ENUM(CDROMRESET),
	DESCRIBE_ENUM(CDROMVOLREAD),
	DESCRIBE_ENUM(CDROMREADRAW),
	DESCRIBE_ENUM(CDROMREADCOOKED),
	DESCRIBE_ENUM(CDROMSEEK),
	DESCRIBE_ENUM(CDROMPLAYBLK),
	DESCRIBE_ENUM(CDROMREADALL),
	DESCRIBE_ENUM(CDROMGETSPINDOWN),
	DESCRIBE_ENUM(CDROMSETSPINDOWN),
	DESCRIBE_ENUM(CDROMCLOSETRAY),
	DESCRIBE_ENUM(CDROMAUDIOBUFSIZ),
	DESCRIBE_ENUM(DVD_READ_STRUCT),
	DESCRIBE_ENUM(DVD_WRITE_STRUCT),
	DESCRIBE_ENUM(DVD_AUTH),
	DESCRIBE_ENUM(CDROM_SEND_PACKET),
	DESCRIBE_ENUM(CDROM_NEXT_WRITABLE),
	DESCRIBE_ENUM(CDROM_LAST_WRITTEN),
	DESCRIBE_ENUM(CDROM_TIMED_MEDIA_CHANGE),
	// cdrom packet
	DESCRIBE_ENUM(PACKET_SETUP_DEV),
	DESCRIBE_ENUM(PACKET_TEARDOWN_DEV),
	// cxl_mem
	DESCRIBE_ENUM(CXL_MEM_QUERY_COMMANDS),
	DESCRIBE_ENUM(CXL_MEM_SEND_COMMAND),
	// cec
	DESCRIBE_ENUM(CEC_ADAP_G_CAPS),
	DESCRIBE_ENUM(CEC_ADAP_G_PHYS_ADDR),
	DESCRIBE_ENUM(CEC_ADAP_S_PHYS_ADDR),
	DESCRIBE_ENUM(CEC_ADAP_G_LOG_ADDRS),
	DESCRIBE_ENUM(CEC_ADAP_S_LOG_ADDRS),
	DESCRIBE_ENUM(CEC_TRANSMIT),
	DESCRIBE_ENUM(CEC_RECEIVE),
	DESCRIBE_ENUM(CEC_DQEVENT),
	DESCRIBE_ENUM(CEC_G_MODE),
	DESCRIBE_ENUM(CEC_S_MODE),
	DESCRIBE_ENUM(CEC_ADAP_G_CONNECTOR_INFO),
	// dasd
	DESCRIBE_ENUM(BIODASDINFO),
	// dm-ioctl
	DESCRIBE_ENUM(DM_VERSION),
	DESCRIBE_ENUM(DM_REMOVE_ALL),
	DESCRIBE_ENUM(DM_LIST_DEVICES),
	DESCRIBE_ENUM(DM_DEV_CREATE),
	DESCRIBE_ENUM(DM_DEV_REMOVE),
	DESCRIBE_ENUM(DM_DEV_RENAME),
	DESCRIBE_ENUM(DM_DEV_SUSPEND),
	DESCRIBE_ENUM(DM_DEV_STATUS),
	DESCRIBE_ENUM(DM_DEV_WAIT),
	DESCRIBE_ENUM(DM_DEV_ARM_POLL),
	DESCRIBE_ENUM(DM_TABLE_LOAD),
	DESCRIBE_ENUM(DM_TABLE_CLEAR),
	DESCRIBE_ENUM(DM_TABLE_DEPS),
	DESCRIBE_ENUM(DM_TABLE_STATUS),
	DESCRIBE_ENUM(DM_LIST_VERSIONS),
	DESCRIBE_ENUM(DM_GET_TARGET_VERSION),
	DESCRIBE_ENUM(DM_TARGET_MSG),
	DESCRIBE_ENUM(DM_DEV_SET_GEOMETRY),
	// dma-buf
	DESCRIBE_ENUM(DMA_BUF_IOCTL_SYNC),
	DESCRIBE_ENUM(DMA_BUF_SET_NAME),
	DESCRIBE_ENUM(DMA_BUF_SET_NAME_A),
	DESCRIBE_ENUM(DMA_BUF_SET_NAME_B),
	DESCRIBE_ENUM(DMA_BUF_IOCTL_EXPORT_SYNC_FILE),
	DESCRIBE_ENUM(DMA_BUF_IOCTL_IMPORT_SYNC_FILE),
	// dma-heap
	DESCRIBE_ENUM(DMA_HEAP_IOCTL_ALLOC),
	// dmx
	DESCRIBE_ENUM(DMX_START),
	DESCRIBE_ENUM(DMX_STOP),
	DESCRIBE_ENUM(DMX_SET_FILTER),
	DESCRIBE_ENUM(DMX_SET_PES_FILTER),
	DESCRIBE_ENUM(DMX_SET_BUFFER_SIZE),
	DESCRIBE_ENUM(DMX_GET_PES_PIDS),
	DESCRIBE_ENUM(DMX_GET_STC),
	DESCRIBE_ENUM(DMX_ADD_PID),
	DESCRIBE_ENUM(DMX_REMOVE_PID),
	// eventpoll
	DESCRIBE_ENUM(EPIOCSPARAMS),
	DESCRIBE_ENUM(EPIOCGPARAMS),
	// evms
	DESCRIBE_ENUM(EVMS_GET_STRIPE_INFO),
	// falloc
	DESCRIBE_ENUM(FS_IOC_RESVSP),
	DESCRIBE_ENUM(FS_IOC_UNRESVSP),
	DESCRIBE_ENUM(FS_IOC_RESVSP64),
	DESCRIBE_ENUM(FS_IOC_UNRESVSP64),
	DESCRIBE_ENUM(FS_IOC_ZERO_RANGE),
	// fb
	DESCRIBE_ENUM(FBIOGET_VSCREENINFO),
	DESCRIBE_ENUM(FBIOPUT_VSCREENINFO),
	DESCRIBE_ENUM(FBIOGET_FSCREENINFO),
	DESCRIBE_ENUM(FBIOGETCMAP),
	DESCRIBE_ENUM(FBIOPUTCMAP),
	DESCRIBE_ENUM(FBIOPAN_DISPLAY),
	DESCRIBE_ENUM(FBIO_CURSOR),
	DESCRIBE_ENUM(FBIOGET_CON2FBMAP),
	DESCRIBE_ENUM(FBIOPUT_CON2FBMAP),
	DESCRIBE_ENUM(FBIOBLANK),
	DESCRIBE_ENUM(FBIOGET_VBLANK),
	DESCRIBE_ENUM(FBIO_ALLOC),
	DESCRIBE_ENUM(FBIO_FREE),
	DESCRIBE_ENUM(FBIOGET_GLYPH),
	DESCRIBE_ENUM(FBIOGET_HWCINFO),
	DESCRIBE_ENUM(FBIOPUT_MODEINFO),
	DESCRIBE_ENUM(FBIOGET_DISPINFO),
	DESCRIBE_ENUM(FBIO_WAITFORVSYNC),
	// fd
	DESCRIBE_ENUM(FDCLRPRM),
	DESCRIBE_ENUM(FDSETPRM),
	DESCRIBE_ENUM(FDDEFPRM),
	DESCRIBE_ENUM(FDGETPRM),
	DESCRIBE_ENUM(FDMSGON),
	DESCRIBE_ENUM(FDMSGOFF),
	DESCRIBE_ENUM(FDFMTBEG),
	DESCRIBE_ENUM(FDFMTTRK),
	DESCRIBE_ENUM(FDFMTEND),
	DESCRIBE_ENUM(FDSETEMSGTRESH),
	DESCRIBE_ENUM(FDFLUSH),
	DESCRIBE_ENUM(FDSETMAXERRS),
	DESCRIBE_ENUM(FDGETMAXERRS),
	DESCRIBE_ENUM(FDGETDRVTYP),
	DESCRIBE_ENUM(FDSETDRVPRM),
	DESCRIBE_ENUM(FDGETDRVPRM),
	DESCRIBE_ENUM(FDGETDRVSTAT),
	DESCRIBE_ENUM(FDPOLLDRVSTAT),
	DESCRIBE_ENUM(FDRESET),
	DESCRIBE_ENUM(FDGETFDCSTAT),
	DESCRIBE_ENUM(FDWERRORCLR),
	DESCRIBE_ENUM(FDWERRORGET),
	DESCRIBE_ENUM(FDRAWCMD),
	DESCRIBE_ENUM(FDTWADDLE),
	DESCRIBE_ENUM(FDEJECT),
	// fs
	DESCRIBE_ENUM(BLKROSET),
	DESCRIBE_ENUM(BLKROGET),
	DESCRIBE_ENUM(BLKRRPART),
	DESCRIBE_ENUM(BLKGETSIZE),
	DESCRIBE_ENUM(BLKFLSBUF),
	DESCRIBE_ENUM(BLKRASET),
	DESCRIBE_ENUM(BLKRAGET),
	DESCRIBE_ENUM(BLKFRASET),
	DESCRIBE_ENUM(BLKFRAGET),
	DESCRIBE_ENUM(BLKSECTSET),
	DESCRIBE_ENUM(BLKSECTGET),
	DESCRIBE_ENUM(BLKSSZGET),
	DESCRIBE_ENUM(BLKBSZGET),
	DESCRIBE_ENUM(BLKBSZSET),
	DESCRIBE_ENUM(BLKGETSIZE64),
	DESCRIBE_ENUM(BLKTRACESETUP),
	DESCRIBE_ENUM(BLKTRACESTART),
	DESCRIBE_ENUM(BLKTRACESTOP),
	DESCRIBE_ENUM(BLKTRACETEARDOWN),
	DESCRIBE_ENUM(BLKDISCARD),
	DESCRIBE_ENUM(BLKIOMIN),
	DESCRIBE_ENUM(BLKPBSZGET),
	DESCRIBE_ENUM(BLKALIGNOFF),
	DESCRIBE_ENUM(BLKDISCARDZEROES),
	DESCRIBE_ENUM(BLKSECDISCARD),
	DESCRIBE_ENUM(BLKROTATIONAL),
	DESCRIBE_ENUM(BLKZEROOUT),
	DESCRIBE_ENUM(BLKGETDISKSEQ),
	DESCRIBE_ENUM(BMAP_IOCTL),
	DESCRIBE_ENUM(FIBMAP),
	DESCRIBE_ENUM(FIGETBSZ),
	DESCRIBE_ENUM(FIFREEZE),
	DESCRIBE_ENUM(FITHAW),
	DESCRIBE_ENUM(FITRIM),
	DESCRIBE_ENUM(FICLONE),
	DESCRIBE_ENUM(FICLONERANGE),
	DESCRIBE_ENUM(FIDEDUPERANGE),
	DESCRIBE_ENUM(FSLABEL_MAX),
	DESCRIBE_ENUM(FS_IOC_GETFLAGS),
	DESCRIBE_ENUM(FS_IOC_SETFLAGS),
	DESCRIBE_ENUM(FS_IOC_GETVERSION),
	DESCRIBE_ENUM(FS_IOC_SETVERSION),
	DESCRIBE_ENUM(FS_IOC_FIEMAP),
	DESCRIBE_ENUM(FS_IOC32_GETFLAGS),
	DESCRIBE_ENUM(FS_IOC32_SETFLAGS),
	DESCRIBE_ENUM(FS_IOC32_GETVERSION),
	DESCRIBE_ENUM(FS_IOC32_SETVERSION),
	DESCRIBE_ENUM(FS_IOC_FSGETXATTR),
	DESCRIBE_ENUM(FS_IOC_FSSETXATTR),
	DESCRIBE_ENUM(FS_IOC_GETFSLABEL),
	DESCRIBE_ENUM(FS_IOC_SETFSLABEL),
	DESCRIBE_ENUM(FS_IOC_GETFSUUID),
	DESCRIBE_ENUM(FS_IOC_GETFSSYSFSPATH),
	DESCRIBE_ENUM(BLKIOOPT),
	DESCRIBE_ENUM(BLKGETLASTSECT), // unused
	DESCRIBE_ENUM(BLKSETLASTSECT), // unused
	// fscrypt
	DESCRIBE_ENUM(FS_IOC_SET_ENCRYPTION_POLICY),
	DESCRIBE_ENUM(FS_IOC_GET_ENCRYPTION_PWSALT),
	DESCRIBE_ENUM(FS_IOC_GET_ENCRYPTION_POLICY),
	DESCRIBE_ENUM(FS_IOC_GET_ENCRYPTION_POLICY_EX),
	DESCRIBE_ENUM(FS_IOC_ADD_ENCRYPTION_KEY),
	DESCRIBE_ENUM(FS_IOC_REMOVE_ENCRYPTION_KEY),
	DESCRIBE_ENUM(FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS),
	DESCRIBE_ENUM(FS_IOC_GET_ENCRYPTION_KEY_STATUS),
	DESCRIBE_ENUM(FS_IOC_GET_ENCRYPTION_NONCE),
	// fsl_hypervisor
	DESCRIBE_ENUM(FSL_HV_IOCTL_PARTITION_RESTART),
	DESCRIBE_ENUM(FSL_HV_IOCTL_PARTITION_GET_STATUS),
	DESCRIBE_ENUM(FSL_HV_IOCTL_PARTITION_START),
	DESCRIBE_ENUM(FSL_HV_IOCTL_PARTITION_STOP),
	DESCRIBE_ENUM(FSL_HV_IOCTL_MEMCPY),
	DESCRIBE_ENUM(FSL_HV_IOCTL_DOORBELL),
	DESCRIBE_ENUM(FSL_HV_IOCTL_GETPROP),
	DESCRIBE_ENUM(FSL_HV_IOCTL_SETPROP),
	// fsmap
	DESCRIBE_ENUM(FS_IOC_GETFSMAP),
	// fsverity
	DESCRIBE_ENUM(FS_IOC_ENABLE_VERITY),
	DESCRIBE_ENUM(FS_IOC_MEASURE_VERITY),
	DESCRIBE_ENUM(FS_IOC_READ_VERITY_METADATA),
	DESCRIBE_ENUM(FS_IOC_ENABLE_VERITY_OLD),
	// fuse
	DESCRIBE_ENUM(FUSE_DEV_IOC_CLONE),
	DESCRIBE_ENUM(FUSE_DEV_IOC_BACKING_OPEN),
	DESCRIBE_ENUM(FUSE_DEV_IOC_BACKING_CLOSE),
	// gpio
	DESCRIBE_ENUM(GPIO_GET_CHIPINFO_IOCTL),
	DESCRIBE_ENUM(GPIO_GET_LINEINFO_UNWATCH_IOCTL),
	DESCRIBE_ENUM(GPIO_V2_GET_LINEINFO_IOCTL),
	DESCRIBE_ENUM(GPIO_V2_GET_LINEINFO_WATCH_IOCTL),
	DESCRIBE_ENUM(GPIO_V2_GET_LINE_IOCTL),
	DESCRIBE_ENUM(GPIO_V2_LINE_SET_CONFIG_IOCTL),
	DESCRIBE_ENUM(GPIO_V2_LINE_GET_VALUES_IOCTL),
	DESCRIBE_ENUM(GPIO_V2_LINE_SET_VALUES_IOCTL),
	DESCRIBE_ENUM(GPIO_GET_LINEINFO_IOCTL),
	DESCRIBE_ENUM(GPIO_GET_LINEHANDLE_IOCTL),
	DESCRIBE_ENUM(GPIO_GET_LINEEVENT_IOCTL),
	DESCRIBE_ENUM(GPIOHANDLE_GET_LINE_VALUES_IOCTL),
	DESCRIBE_ENUM(GPIOHANDLE_SET_LINE_VALUES_IOCTL),
	DESCRIBE_ENUM(GPIOHANDLE_SET_CONFIG_IOCTL),
	DESCRIBE_ENUM(GPIO_GET_LINEINFO_WATCH_IOCTL),
	// gsmmux
	DESCRIBE_ENUM(GSMIOC_GETCONF),
	DESCRIBE_ENUM(GSMIOC_SETCONF),
	DESCRIBE_ENUM(GSMIOC_ENABLE_NET),
	DESCRIBE_ENUM(GSMIOC_DISABLE_NET),
	DESCRIBE_ENUM(GSMIOC_GETFIRST),
	DESCRIBE_ENUM(GSMIOC_GETCONF_EXT),
	DESCRIBE_ENUM(GSMIOC_SETCONF_EXT),
	DESCRIBE_ENUM(GSMIOC_GETCONF_DLCI),
	DESCRIBE_ENUM(GSMIOC_SETCONF_DLCI),
	// hdio
	DESCRIBE_ENUM(HDIO_GETGEO),
	DESCRIBE_ENUM(HDIO_GET_UNMASKINTR),
	DESCRIBE_ENUM(HDIO_GET_MULTCOUNT),
	DESCRIBE_ENUM(HDIO_GET_QDMA),
	DESCRIBE_ENUM(HDIO_SET_XFER),
	DESCRIBE_ENUM(HDIO_OBSOLETE_IDENTITY),
	DESCRIBE_ENUM(HDIO_GET_KEEPSETTINGS),
	DESCRIBE_ENUM(HDIO_GET_32BIT),
	DESCRIBE_ENUM(HDIO_GET_NOWERR),
	DESCRIBE_ENUM(HDIO_GET_DMA),
	DESCRIBE_ENUM(HDIO_GET_NICE),
	DESCRIBE_ENUM(HDIO_GET_IDENTITY),
	DESCRIBE_ENUM(HDIO_GET_WCACHE),
	DESCRIBE_ENUM(HDIO_GET_ACOUSTIC),
	DESCRIBE_ENUM(HDIO_GET_ADDRESS),
	DESCRIBE_ENUM(HDIO_GET_BUSSTATE),
	DESCRIBE_ENUM(HDIO_TRISTATE_HWIF),
	DESCRIBE_ENUM(HDIO_DRIVE_RESET),
	DESCRIBE_ENUM(HDIO_DRIVE_TASKFILE),
	DESCRIBE_ENUM(HDIO_DRIVE_TASK),
	DESCRIBE_ENUM(HDIO_DRIVE_CMD),
	DESCRIBE_ENUM(HDIO_DRIVE_CMD_AEB),
	DESCRIBE_ENUM(HDIO_SET_MULTCOUNT),
	DESCRIBE_ENUM(HDIO_SET_UNMASKINTR),
	DESCRIBE_ENUM(HDIO_SET_KEEPSETTINGS),
	DESCRIBE_ENUM(HDIO_SET_32BIT),
	DESCRIBE_ENUM(HDIO_SET_NOWERR),
	DESCRIBE_ENUM(HDIO_SET_DMA),
	DESCRIBE_ENUM(HDIO_SET_PIO_MODE),
	DESCRIBE_ENUM(HDIO_SCAN_HWIF),
	DESCRIBE_ENUM(HDIO_UNREGISTER_HWIF),
	DESCRIBE_ENUM(HDIO_SET_NICE),
	DESCRIBE_ENUM(HDIO_SET_WCACHE),
	DESCRIBE_ENUM(HDIO_SET_ACOUSTIC),
	DESCRIBE_ENUM(HDIO_SET_BUSSTATE),
	DESCRIBE_ENUM(HDIO_SET_QDMA),
	DESCRIBE_ENUM(HDIO_SET_ADDRESS),
	// hiddev
	DESCRIBE_ENUM(HIDIOCGVERSION),
	DESCRIBE_ENUM(HIDIOCGDEVINFO),
	DESCRIBE_ENUM(HIDIOCGSTRING),
	// DESCRIBE_ENUM(HIDIOCGNAME), // variable size
	DESCRIBE_ENUM(HIDIOCGREPORT),
	DESCRIBE_ENUM(HIDIOCSREPORT),
	DESCRIBE_ENUM(HIDIOCGREPORTINFO),
	DESCRIBE_ENUM(HIDIOCGFIELDINFO),
	DESCRIBE_ENUM(HIDIOCGUSAGE),
	DESCRIBE_ENUM(HIDIOCSUSAGE),
	DESCRIBE_ENUM(HIDIOCGUCODE),
	DESCRIBE_ENUM(HIDIOCGFLAG),
	DESCRIBE_ENUM(HIDIOCSFLAG),
	DESCRIBE_ENUM(HIDIOCGCOLLECTIONINDEX),
	DESCRIBE_ENUM(HIDIOCGCOLLECTIONINFO),
	// DESCRIBE_ENUM(HIDIOCGPHYS), // variable size
	DESCRIBE_ENUM(HIDIOCGUSAGES),
	DESCRIBE_ENUM(HIDIOCSUSAGES),
	// hidraw
	DESCRIBE_ENUM(HIDIOCGRDESCSIZE),
	DESCRIBE_ENUM(HIDIOCGRDESC),
	DESCRIBE_ENUM(HIDIOCGRAWINFO),
	// DESCRIBE_ENUM(HIDIOCGRAWNAME), // variable size
	// DESCRIBE_ENUM(HIDIOCGRAWPHYS), // variable size
	// DESCRIBE_ENUM(HIDIOCSFEATURE), // variable size
	// DESCRIBE_ENUM(HIDIOCGFEATURE), // variable size
	// DESCRIBE_ENUM(HIDIOCGRAWUNIQ), // variable size
	// DESCRIBE_ENUM(HIDIOCSINPUT), // variable size
	// DESCRIBE_ENUM(HIDIOCGINPUT), // variable size
	// DESCRIBE_ENUM(HIDIOCSOUTPUT), // variable size
	// DESCRIBE_ENUM(HIDIOCGOUTPUT), // variable size
	// hpet
	DESCRIBE_ENUM(HPET_IE_ON),
	DESCRIBE_ENUM(HPET_IE_OFF),
	DESCRIBE_ENUM(HPET_INFO),
	DESCRIBE_ENUM(HPET_EPI),
	DESCRIBE_ENUM(HPET_DPI),
	DESCRIBE_ENUM(HPET_IRQFREQ),
	// i2c
	DESCRIBE_ENUM(I2C_RETRIES),
	DESCRIBE_ENUM(I2C_TIMEOUT),
	DESCRIBE_ENUM(I2C_SLAVE),
	DESCRIBE_ENUM(I2C_SLAVE_FORCE),
	DESCRIBE_ENUM(I2C_TENBIT),
	DESCRIBE_ENUM(I2C_FUNCS),
	DESCRIBE_ENUM(I2C_RDWR),
	DESCRIBE_ENUM(I2C_PEC),
	DESCRIBE_ENUM(I2C_SMBUS),
	// if_pppox
	// DESCRIBE_ENUM(PPPOEIOCSFWD),
	// DESCRIBE_ENUM(PPPOEIOCDFWD),
	// if_tun
	DESCRIBE_ENUM(TUNSETNOCSUM),
	DESCRIBE_ENUM(TUNSETDEBUG),
	DESCRIBE_ENUM(TUNSETIFF),
	DESCRIBE_ENUM(TUNSETPERSIST),
	DESCRIBE_ENUM(TUNSETOWNER),
	DESCRIBE_ENUM(TUNSETLINK),
	DESCRIBE_ENUM(TUNSETGROUP),
	DESCRIBE_ENUM(TUNGETFEATURES),
	DESCRIBE_ENUM(TUNSETOFFLOAD),
	DESCRIBE_ENUM(TUNSETTXFILTER),
	DESCRIBE_ENUM(TUNGETIFF),
	DESCRIBE_ENUM(TUNGETSNDBUF),
	DESCRIBE_ENUM(TUNSETSNDBUF),
	DESCRIBE_ENUM(TUNATTACHFILTER),
	DESCRIBE_ENUM(TUNDETACHFILTER),
	DESCRIBE_ENUM(TUNGETVNETHDRSZ),
	DESCRIBE_ENUM(TUNSETVNETHDRSZ),
	DESCRIBE_ENUM(TUNSETQUEUE),
	DESCRIBE_ENUM(TUNSETIFINDEX),
	DESCRIBE_ENUM(TUNGETFILTER),
	DESCRIBE_ENUM(TUNSETVNETLE),
	DESCRIBE_ENUM(TUNGETVNETLE),
	DESCRIBE_ENUM(TUNSETVNETBE),
	DESCRIBE_ENUM(TUNGETVNETBE),
	DESCRIBE_ENUM(TUNSETSTEERINGEBPF),
	DESCRIBE_ENUM(TUNSETFILTEREBPF),
	DESCRIBE_ENUM(TUNSETCARRIER),
	DESCRIBE_ENUM(TUNGETDEVNETNS),
	// if_tunnel
	DESCRIBE_ENUM(SIOCGETTUNNEL),
	DESCRIBE_ENUM(SIOCADDTUNNEL),
	DESCRIBE_ENUM(SIOCDELTUNNEL),
	DESCRIBE_ENUM(SIOCCHGTUNNEL),
	DESCRIBE_ENUM(SIOCGETPRL),
	DESCRIBE_ENUM(SIOCADDPRL),
	DESCRIBE_ENUM(SIOCDELPRL),
	DESCRIBE_ENUM(SIOCCHGPRL),
	DESCRIBE_ENUM(SIOCGET6RD),
	DESCRIBE_ENUM(SIOCADD6RD),
	DESCRIBE_ENUM(SIOCDEL6RD),
	DESCRIBE_ENUM(SIOCCHG6RD),
	// iio/buffer
	DESCRIBE_ENUM(IIO_BUFFER_GET_FD_IOCTL),
	// iio/events
	DESCRIBE_ENUM(IIO_GET_EVENT_FD_IOCTL),
	// inotify
	DESCRIBE_ENUM(INOTIFY_IOC_SETNEXTWD),
	// input
	DESCRIBE_ENUM(EVIOCGVERSION),
	DESCRIBE_ENUM(EVIOCGID),
	DESCRIBE_ENUM(EVIOCGREP),
	DESCRIBE_ENUM(EVIOCSREP),
	DESCRIBE_ENUM(EVIOCGKEYCODE),
	DESCRIBE_ENUM(EVIOCGKEYCODE_V2),
	DESCRIBE_ENUM(EVIOCSKEYCODE),
	DESCRIBE_ENUM(EVIOCSKEYCODE_V2),
	// DESCRIBE_ENUM(EVIOCGNAME), // variable size
	// DESCRIBE_ENUM(EVIOCGPHYS), // variable size
	// DESCRIBE_ENUM(EVIOCGUNIQ), // variable size
	// DESCRIBE_ENUM(EVIOCGPROP), // variable size
	// DESCRIBE_ENUM(EVIOCGMTSLOTS), // variable size
	// DESCRIBE_ENUM(EVIOCGKEY), // variable size
	// DESCRIBE_ENUM(EVIOCGLED), // variable size
	// DESCRIBE_ENUM(EVIOCGSND), // variable size
	// DESCRIBE_ENUM(EVIOCGSW), // variable size
	// DESCRIBE_ENUM(EVIOCGBIT), // variable size
	// DESCRIBE_ENUM(EVIOCGABS), // variable size
	DESCRIBE_ENUM(EVIOCGABS(ABS_X)),
	DESCRIBE_ENUM(EVIOCGABS(ABS_Y)),
	DESCRIBE_ENUM(EVIOCGABS(ABS_Z)),
	// DESCRIBE_ENUM(EVIOCSABS), // variable size
	DESCRIBE_ENUM(EVIOCSFF),
	DESCRIBE_ENUM(EVIOCRMFF),
	DESCRIBE_ENUM(EVIOCGEFFECTS),
	DESCRIBE_ENUM(EVIOCGRAB),
	DESCRIBE_ENUM(EVIOCREVOKE),
	DESCRIBE_ENUM(EVIOCGMASK),
	DESCRIBE_ENUM(EVIOCSMASK),
	DESCRIBE_ENUM(EVIOCSCLOCKID),
	// ext2
	DESCRIBE_ENUM(EXT2_IOC_GETFLAGS),
	DESCRIBE_ENUM(EXT2_IOC_SETFLAGS),
	DESCRIBE_ENUM(EXT2_IOC_GETVERSION),
	DESCRIBE_ENUM(EXT2_IOC_SETVERSION),
	DESCRIBE_ENUM(EXT2_IOC_GETVERSION_NEW),
	DESCRIBE_ENUM(EXT2_IOC_SETVERSION_NEW),
	DESCRIBE_ENUM(EXT2_IOC_GROUP_EXTEND),
	DESCRIBE_ENUM(EXT2_IOC_GROUP_ADD),
	// ext4
	DESCRIBE_ENUM(EXT4_IOC_GROUP_ADD),
	DESCRIBE_ENUM(EXT4_IOC_RESIZE_FS),
	DESCRIBE_ENUM(EXT4_IOC_MOVE_EXT),
	DESCRIBE_ENUM(EXT4_IOC_SET_ENCRYPTION_POLICY),
	DESCRIBE_ENUM(EXT4_IOC_GET_ENCRYPTION_POLICY),
	DESCRIBE_ENUM(EXT4_IOC_GETVERSION),
	DESCRIBE_ENUM(EXT4_IOC_SETVERSION),
	DESCRIBE_ENUM(EXT4_IOC_GETVERSION_OLD),
	DESCRIBE_ENUM(EXT4_IOC_SETVERSION_OLD),
	DESCRIBE_ENUM(EXT4_IOC_GETRSVSZ),
	DESCRIBE_ENUM(EXT4_IOC_SETRSVSZ),
	DESCRIBE_ENUM(EXT4_IOC_GROUP_EXTEND),
	DESCRIBE_ENUM(EXT4_IOC_GROUP_ADD),
	DESCRIBE_ENUM(EXT4_IOC_MIGRATE),
	DESCRIBE_ENUM(EXT4_IOC_ALLOC_DA_BLKS),
	DESCRIBE_ENUM(EXT4_IOC_MOVE_EXT),
	DESCRIBE_ENUM(EXT4_IOC_RESIZE_FS),
	DESCRIBE_ENUM(EXT4_IOC_SWAP_BOOT),
	DESCRIBE_ENUM(EXT4_IOC_PRECACHE_EXTENTS),
	DESCRIBE_ENUM(EXT4_IOC_CLEAR_ES_CACHE),
	DESCRIBE_ENUM(EXT4_IOC_GETSTATE),
	DESCRIBE_ENUM(EXT4_IOC_GET_ES_CACHE),
	DESCRIBE_ENUM(EXT4_IOC_CHECKPOINT),
	DESCRIBE_ENUM(EXT4_IOC_GETFSUUID),
	DESCRIBE_ENUM(EXT4_IOC_SETFSUUID),
	DESCRIBE_ENUM(EXT4_IOC_SHUTDOWN),
	// f2fs
	DESCRIBE_ENUM(F2FS_IOC_START_ATOMIC_WRITE),
	DESCRIBE_ENUM(F2FS_IOC_COMMIT_ATOMIC_WRITE),
	DESCRIBE_ENUM(F2FS_IOC_START_VOLATILE_WRITE),
	DESCRIBE_ENUM(F2FS_IOC_RELEASE_VOLATILE_WRITE),
	DESCRIBE_ENUM(F2FS_IOC_ABORT_ATOMIC_WRITE),
	DESCRIBE_ENUM(F2FS_IOC_GARBAGE_COLLECT),
	DESCRIBE_ENUM(F2FS_IOC_WRITE_CHECKPOINT),
	DESCRIBE_ENUM(F2FS_IOC_DEFRAGMENT),
	DESCRIBE_ENUM(F2FS_IOC_MOVE_RANGE),
	DESCRIBE_ENUM(F2FS_IOC_FLUSH_DEVICE),
	DESCRIBE_ENUM(F2FS_IOC_GARBAGE_COLLECT_RANGE),
	DESCRIBE_ENUM(F2FS_IOC_GET_FEATURES),
	DESCRIBE_ENUM(F2FS_IOC_SET_PIN_FILE),
	DESCRIBE_ENUM(F2FS_IOC_GET_PIN_FILE),
	DESCRIBE_ENUM(F2FS_IOC_PRECACHE_EXTENTS),
	DESCRIBE_ENUM(F2FS_IOC_RESIZE_FS),
	DESCRIBE_ENUM(F2FS_IOC_GET_COMPRESS_BLOCKS),
	DESCRIBE_ENUM(F2FS_IOC_RELEASE_COMPRESS_BLOCKS),
	DESCRIBE_ENUM(F2FS_IOC_RESERVE_COMPRESS_BLOCKS),
	DESCRIBE_ENUM(F2FS_IOC_SEC_TRIM_FILE),
	DESCRIBE_ENUM(F2FS_IOC_GET_COMPRESS_OPTION),
	DESCRIBE_ENUM(F2FS_IOC_SET_COMPRESS_OPTION),
	DESCRIBE_ENUM(F2FS_IOC_DECOMPRESS_FILE),
	DESCRIBE_ENUM(F2FS_IOC_COMPRESS_FILE),
	DESCRIBE_ENUM(F2FS_IOC_START_ATOMIC_REPLACE),
	DESCRIBE_ENUM(F2FS_IOC_SHUTDOWN),
	// kdbus
	DESCRIBE_ENUM(KDBUS_CMD_BUS_MAKE),
	DESCRIBE_ENUM(KDBUS_CMD_ENDPOINT_MAKE),
	DESCRIBE_ENUM(KDBUS_CMD_ENDPOINT_UPDATE),
	DESCRIBE_ENUM(KDBUS_CMD_HELLO),
	DESCRIBE_ENUM(KDBUS_CMD_UPDATE),
	DESCRIBE_ENUM(KDBUS_CMD_BYEBYE),
	DESCRIBE_ENUM(KDBUS_CMD_FREE),
	DESCRIBE_ENUM(KDBUS_CMD_CONN_INFO),
	DESCRIBE_ENUM(KDBUS_CMD_BUS_CREATOR_INFO),
	DESCRIBE_ENUM(KDBUS_CMD_LIST),
	DESCRIBE_ENUM(KDBUS_CMD_SEND),
	DESCRIBE_ENUM(KDBUS_CMD_RECV),
	DESCRIBE_ENUM(KDBUS_CMD_NAME_ACQUIRE),
	DESCRIBE_ENUM(KDBUS_CMD_NAME_RELEASE),
	DESCRIBE_ENUM(KDBUS_CMD_MATCH_ADD),
	DESCRIBE_ENUM(KDBUS_CMD_MATCH_REMOVE),
	// loop
	DESCRIBE_ENUM(LOOP_SET_FD),
	DESCRIBE_ENUM(LOOP_CLR_FD),
	DESCRIBE_ENUM(LOOP_SET_STATUS),
	DESCRIBE_ENUM(LOOP_GET_STATUS),
	DESCRIBE_ENUM(LOOP_SET_STATUS64),
	DESCRIBE_ENUM(LOOP_GET_STATUS64),
	DESCRIBE_ENUM(LOOP_CHANGE_FD),
	DESCRIBE_ENUM(LOOP_SET_CAPACITY),
	DESCRIBE_ENUM(LOOP_SET_DIRECT_IO),
	DESCRIBE_ENUM(LOOP_SET_BLOCK_SIZE),
	DESCRIBE_ENUM(LOOP_CONFIGURE),
	DESCRIBE_ENUM(LOOP_CTL_ADD),
	DESCRIBE_ENUM(LOOP_CTL_REMOVE),
	DESCRIBE_ENUM(LOOP_CTL_GET_FREE),
	// lp
	DESCRIBE_ENUM(LPCHAR),
	DESCRIBE_ENUM(LPTIME),
	DESCRIBE_ENUM(LPABORT),
	DESCRIBE_ENUM(LPSETIRQ),
	DESCRIBE_ENUM(LPGETIRQ),
	DESCRIBE_ENUM(LPWAIT),
	DESCRIBE_ENUM(LPCAREFUL),
	DESCRIBE_ENUM(LPABORTOPEN),
	DESCRIBE_ENUM(LPGETSTATUS),
	DESCRIBE_ENUM(LPRESET),
	DESCRIBE_ENUM(LPGETFLAGS),
	DESCRIBE_ENUM(LPSETTIMEOUT),
	// mtd
	DESCRIBE_ENUM(MEMSETOOBSEL),
	DESCRIBE_ENUM(MEMGETINFO),
	DESCRIBE_ENUM(MEMERASE),
	DESCRIBE_ENUM(MEMWRITEOOB),
	DESCRIBE_ENUM(MEMREADOOB),
	DESCRIBE_ENUM(MEMLOCK),
	DESCRIBE_ENUM(MEMUNLOCK),
	DESCRIBE_ENUM(MEMGETREGIONCOUNT),
	DESCRIBE_ENUM(MEMGETREGIONINFO),
	DESCRIBE_ENUM(MEMGETOOBSEL),
	DESCRIBE_ENUM(MEMGETBADBLOCK),
	DESCRIBE_ENUM(MEMSETBADBLOCK),
	DESCRIBE_ENUM(OTPSELECT),
	DESCRIBE_ENUM(OTPGETREGIONCOUNT),
	DESCRIBE_ENUM(OTPGETREGIONINFO),
	DESCRIBE_ENUM(OTPLOCK),
	DESCRIBE_ENUM(ECCGETLAYOUT),
	DESCRIBE_ENUM(ECCGETSTATS),
	DESCRIBE_ENUM(MTDFILEMODE),
	DESCRIBE_ENUM(MEMERASE64),
	DESCRIBE_ENUM(MEMWRITEOOB64),
	DESCRIBE_ENUM(MEMREADOOB64),
	DESCRIBE_ENUM(MEMISLOCKED),
	DESCRIBE_ENUM(MEMWRITE),
	DESCRIBE_ENUM(OTPERASE),
	DESCRIBE_ENUM(MEMREAD),
	// usb/mon
	DESCRIBE_ENUM(MON_IOCQ_URB_LEN),
	DESCRIBE_ENUM(MON_IOCG_STATS),
	DESCRIBE_ENUM(MON_IOCT_RING_SIZE),
	DESCRIBE_ENUM(MON_IOCQ_RING_SIZE),
	DESCRIBE_ENUM(MON_IOCX_GET),
	DESCRIBE_ENUM(MON_IOCX_MFETCH),
	DESCRIBE_ENUM(MON_IOCH_MFLUSH),
	DESCRIBE_ENUM(MON_IOCX_GETX),
	// mtio
	DESCRIBE_ENUM(MTIOCTOP),
	DESCRIBE_ENUM(MTIOCGET),
	DESCRIBE_ENUM(MTIOCPOS),
	// nilfs2_api
	DESCRIBE_ENUM(NILFS_IOCTL_CHANGE_CPMODE),
	DESCRIBE_ENUM(NILFS_IOCTL_DELETE_CHECKPOINT),
	DESCRIBE_ENUM(NILFS_IOCTL_GET_CPINFO),
	DESCRIBE_ENUM(NILFS_IOCTL_GET_CPSTAT),
	DESCRIBE_ENUM(NILFS_IOCTL_GET_SUINFO),
	DESCRIBE_ENUM(NILFS_IOCTL_GET_SUSTAT),
	DESCRIBE_ENUM(NILFS_IOCTL_GET_VINFO),
	DESCRIBE_ENUM(NILFS_IOCTL_GET_BDESCS),
	DESCRIBE_ENUM(NILFS_IOCTL_CLEAN_SEGMENTS),
	DESCRIBE_ENUM(NILFS_IOCTL_SYNC),
	DESCRIBE_ENUM(NILFS_IOCTL_RESIZE),
	DESCRIBE_ENUM(NILFS_IOCTL_SET_ALLOC_RANGE),
	DESCRIBE_ENUM(NILFS_IOCTL_SET_SUINFO),
	// nsfs
	DESCRIBE_ENUM(NS_GET_USERNS),
	DESCRIBE_ENUM(NS_GET_PARENT),
	DESCRIBE_ENUM(NS_GET_NSTYPE),
	DESCRIBE_ENUM(NS_GET_OWNER_UID),
	// perf_event
	DESCRIBE_ENUM(PERF_EVENT_IOC_ENABLE),
	DESCRIBE_ENUM(PERF_EVENT_IOC_DISABLE),
	DESCRIBE_ENUM(PERF_EVENT_IOC_REFRESH),
	DESCRIBE_ENUM(PERF_EVENT_IOC_RESET),
	DESCRIBE_ENUM(PERF_EVENT_IOC_PERIOD),
	DESCRIBE_ENUM(PERF_EVENT_IOC_SET_OUTPUT),
	DESCRIBE_ENUM(PERF_EVENT_IOC_SET_FILTER),
	DESCRIBE_ENUM(PERF_EVENT_IOC_ID),
	DESCRIBE_ENUM(PERF_EVENT_IOC_SET_BPF),
	DESCRIBE_ENUM(PERF_EVENT_IOC_PAUSE_OUTPUT),
	DESCRIBE_ENUM(PERF_EVENT_IOC_QUERY_BPF),
	DESCRIBE_ENUM(PERF_EVENT_IOC_MODIFY_ATTRIBUTES),
	// pr
	DESCRIBE_ENUM(IOC_PR_REGISTER),
	DESCRIBE_ENUM(IOC_PR_RESERVE),
	DESCRIBE_ENUM(IOC_PR_RELEASE),
	DESCRIBE_ENUM(IOC_PR_PREEMPT),
	DESCRIBE_ENUM(IOC_PR_PREEMPT_ABORT),
	DESCRIBE_ENUM(IOC_PR_CLEAR),
	// raid
	DESCRIBE_ENUM(RAID_VERSION),
	DESCRIBE_ENUM(GET_ARRAY_INFO),
	DESCRIBE_ENUM(GET_DISK_INFO),
	DESCRIBE_ENUM(RAID_AUTORUN),
	DESCRIBE_ENUM(GET_BITMAP_FILE),
	DESCRIBE_ENUM(CLEAR_ARRAY),
	DESCRIBE_ENUM(ADD_NEW_DISK),
	DESCRIBE_ENUM(HOT_REMOVE_DISK),
	DESCRIBE_ENUM(SET_ARRAY_INFO),
	DESCRIBE_ENUM(SET_DISK_INFO),
	DESCRIBE_ENUM(WRITE_RAID_INFO),
	DESCRIBE_ENUM(UNPROTECT_ARRAY),
	DESCRIBE_ENUM(PROTECT_ARRAY),
	DESCRIBE_ENUM(HOT_ADD_DISK),
	DESCRIBE_ENUM(SET_DISK_FAULTY),
	DESCRIBE_ENUM(HOT_GENERATE_ERROR),
	DESCRIBE_ENUM(SET_BITMAP_FILE),
	DESCRIBE_ENUM(RUN_ARRAY),
	DESCRIBE_ENUM(STOP_ARRAY),
	DESCRIBE_ENUM(STOP_ARRAY_RO),
	DESCRIBE_ENUM(RESTART_ARRAY_RW),
	DESCRIBE_ENUM(CLUSTERED_DISK_NACK),
	// random
	DESCRIBE_ENUM(RNDGETENTCNT),
	DESCRIBE_ENUM(RNDADDTOENTCNT),
	DESCRIBE_ENUM(RNDGETPOOL),
	DESCRIBE_ENUM(RNDADDENTROPY),
	DESCRIBE_ENUM(RNDZAPENTCNT),
	DESCRIBE_ENUM(RNDCLEARPOOL),
	DESCRIBE_ENUM(RNDRESEEDCRNG),
	// raw
	DESCRIBE_ENUM(RAW_SETBIND),
	DESCRIBE_ENUM(RAW_GETBIND),
	// rdma
	DESCRIBE_ENUM(RDMA_VERBS_IOCTL),
	// rtc
	DESCRIBE_ENUM(RTC_AIE_ON),
	DESCRIBE_ENUM(RTC_AIE_OFF),
	DESCRIBE_ENUM(RTC_UIE_ON),
	DESCRIBE_ENUM(RTC_UIE_OFF),
	DESCRIBE_ENUM(RTC_PIE_ON),
	DESCRIBE_ENUM(RTC_PIE_OFF),
	DESCRIBE_ENUM(RTC_WIE_ON),
	DESCRIBE_ENUM(RTC_WIE_OFF),
	DESCRIBE_ENUM(RTC_ALM_SET),
	DESCRIBE_ENUM(RTC_ALM_READ),
	DESCRIBE_ENUM(RTC_RD_TIME),
	DESCRIBE_ENUM(RTC_SET_TIME),
	DESCRIBE_ENUM(RTC_IRQP_READ),
	DESCRIBE_ENUM(RTC_IRQP_SET),
	DESCRIBE_ENUM(RTC_EPOCH_READ),
	DESCRIBE_ENUM(RTC_EPOCH_SET),
	DESCRIBE_ENUM(RTC_WKALM_SET),
	DESCRIBE_ENUM(RTC_WKALM_RD),
	DESCRIBE_ENUM(RTC_PLL_GET),
	DESCRIBE_ENUM(RTC_PLL_SET),
	DESCRIBE_ENUM(RTC_PARAM_GET),
	DESCRIBE_ENUM(RTC_PARAM_SET),
	DESCRIBE_ENUM(RTC_VL_READ),
	DESCRIBE_ENUM(RTC_VL_CLR),
	// seccomp
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_RECV),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_SEND),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ID_VALID),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ADDFD),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_SET_FLAGS),
	DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR),
	// scsi
	DESCRIBE_ENUM(SCSI_IOCTL_GET_IDLUN),
	DESCRIBE_ENUM(SCSI_IOCTL_PROBE_HOST),
	DESCRIBE_ENUM(SCSI_IOCTL_GET_BUS_NUMBER),
	DESCRIBE_ENUM(SCSI_IOCTL_GET_PCI),
	DESCRIBE_ENUM(SG_EMULATED_HOST),
	DESCRIBE_ENUM(SG_SET_TRANSFORM),
	DESCRIBE_ENUM(SG_GET_TRANSFORM),
	DESCRIBE_ENUM(SG_SET_RESERVED_SIZE),
	DESCRIBE_ENUM(SG_GET_RESERVED_SIZE),
	DESCRIBE_ENUM(SG_GET_SCSI_ID),
	DESCRIBE_ENUM(SG_SET_FORCE_LOW_DMA),
	DESCRIBE_ENUM(SG_GET_LOW_DMA),
	DESCRIBE_ENUM(SG_SET_FORCE_PACK_ID),
	DESCRIBE_ENUM(SG_GET_PACK_ID),
	DESCRIBE_ENUM(SG_GET_NUM_WAITING),
	DESCRIBE_ENUM(SG_GET_SG_TABLESIZE),
	DESCRIBE_ENUM(SG_GET_VERSION_NUM),
	DESCRIBE_ENUM(SG_SCSI_RESET),
	DESCRIBE_ENUM(SG_IO),
	DESCRIBE_ENUM(SG_GET_REQUEST_TABLE),
	DESCRIBE_ENUM(SG_SET_KEEP_ORPHAN),
	DESCRIBE_ENUM(SG_GET_KEEP_ORPHAN),
	DESCRIBE_ENUM(SG_GET_ACCESS_COUNT),
	DESCRIBE_ENUM(SG_SET_TIMEOUT),
	DESCRIBE_ENUM(SG_GET_TIMEOUT),
	DESCRIBE_ENUM(SG_GET_COMMAND_Q),
	DESCRIBE_ENUM(SG_SET_COMMAND_Q),
	DESCRIBE_ENUM(SG_SET_DEBUG),
	DESCRIBE_ENUM(SG_NEXT_CMD_LEN),
	// sed-opal
	DESCRIBE_ENUM(IOC_OPAL_SAVE),
	DESCRIBE_ENUM(IOC_OPAL_LOCK_UNLOCK),
	DESCRIBE_ENUM(IOC_OPAL_TAKE_OWNERSHIP),
	DESCRIBE_ENUM(IOC_OPAL_ACTIVATE_LSP),
	DESCRIBE_ENUM(IOC_OPAL_SET_PW),
	DESCRIBE_ENUM(IOC_OPAL_ACTIVATE_USR),
	DESCRIBE_ENUM(IOC_OPAL_REVERT_TPR),
	DESCRIBE_ENUM(IOC_OPAL_LR_SETUP),
	DESCRIBE_ENUM(IOC_OPAL_ADD_USR_TO_LR),
	DESCRIBE_ENUM(IOC_OPAL_ENABLE_DISABLE_MBR),
	DESCRIBE_ENUM(IOC_OPAL_ERASE_LR),
	DESCRIBE_ENUM(IOC_OPAL_SECURE_ERASE_LR),
	DESCRIBE_ENUM(IOC_OPAL_PSID_REVERT_TPR),
	DESCRIBE_ENUM(IOC_OPAL_MBR_DONE),
	DESCRIBE_ENUM(IOC_OPAL_WRITE_SHADOW_MBR),
	DESCRIBE_ENUM(IOC_OPAL_GENERIC_TABLE_RW),
	DESCRIBE_ENUM(IOC_OPAL_GET_STATUS),
	DESCRIBE_ENUM(IOC_OPAL_GET_LR_STATUS),
	DESCRIBE_ENUM(IOC_OPAL_GET_GEOMETRY),
	DESCRIBE_ENUM(IOC_OPAL_DISCOVERY),
	DESCRIBE_ENUM(IOC_OPAL_REVERT_LSP),
	// sockios
	DESCRIBE_ENUM(SIOCADDRT),
	DESCRIBE_ENUM(SIOCDELRT),
	DESCRIBE_ENUM(SIOCRTMSG),
	DESCRIBE_ENUM(SIOCGIFNAME),
	DESCRIBE_ENUM(SIOCSIFLINK),
	DESCRIBE_ENUM(SIOCGIFCONF),
	DESCRIBE_ENUM(SIOCGIFFLAGS),
	DESCRIBE_ENUM(SIOCSIFFLAGS),
	DESCRIBE_ENUM(SIOCGIFADDR),
	DESCRIBE_ENUM(SIOCSIFADDR),
	DESCRIBE_ENUM(SIOCGIFDSTADDR),
	DESCRIBE_ENUM(SIOCSIFDSTADDR),
	DESCRIBE_ENUM(SIOCGIFBRDADDR),
	DESCRIBE_ENUM(SIOCSIFBRDADDR),
	DESCRIBE_ENUM(SIOCGIFNETMASK),
	DESCRIBE_ENUM(SIOCSIFNETMASK),
	DESCRIBE_ENUM(SIOCGIFMETRIC),
	DESCRIBE_ENUM(SIOCSIFMETRIC),
	DESCRIBE_ENUM(SIOCGIFMEM),
	DESCRIBE_ENUM(SIOCSIFMEM),
	DESCRIBE_ENUM(SIOCGIFMTU),
	DESCRIBE_ENUM(SIOCSIFMTU),
	DESCRIBE_ENUM(SIOCSIFNAME),
	DESCRIBE_ENUM(SIOCSIFHWADDR),
	DESCRIBE_ENUM(SIOCGIFENCAP),
	DESCRIBE_ENUM(SIOCSIFENCAP),
	DESCRIBE_ENUM(SIOCGIFHWADDR),
	DESCRIBE_ENUM(SIOCGIFSLAVE),
	DESCRIBE_ENUM(SIOCSIFSLAVE),
	DESCRIBE_ENUM(SIOCADDMULTI),
	DESCRIBE_ENUM(SIOCDELMULTI),
	DESCRIBE_ENUM(SIOCGIFINDEX),
	DESCRIBE_ENUM(SIOGIFINDEX),
	DESCRIBE_ENUM(SIOCSIFPFLAGS),
	DESCRIBE_ENUM(SIOCGIFPFLAGS),
	DESCRIBE_ENUM(SIOCDIFADDR),
	DESCRIBE_ENUM(SIOCSIFHWBROADCAST),
	DESCRIBE_ENUM(SIOCGIFCOUNT),
	DESCRIBE_ENUM(SIOCGIFBR),
	DESCRIBE_ENUM(SIOCSIFBR),
	DESCRIBE_ENUM(SIOCGIFTXQLEN),
	DESCRIBE_ENUM(SIOCSIFTXQLEN),
	DESCRIBE_ENUM(SIOCETHTOOL),
	DESCRIBE_ENUM(SIOCGMIIPHY),
	DESCRIBE_ENUM(SIOCGMIIREG),
	DESCRIBE_ENUM(SIOCSMIIREG),
	DESCRIBE_ENUM(SIOCWANDEV),
	DESCRIBE_ENUM(SIOCOUTQNSD),
	DESCRIBE_ENUM(SIOCGSKNS),
	DESCRIBE_ENUM(SIOCDARP),
	DESCRIBE_ENUM(SIOCGARP),
	DESCRIBE_ENUM(SIOCSARP),
	DESCRIBE_ENUM(SIOCDRARP),
	DESCRIBE_ENUM(SIOCGRARP),
	DESCRIBE_ENUM(SIOCSRARP),
	DESCRIBE_ENUM(SIOCGIFMAP),
	DESCRIBE_ENUM(SIOCSIFMAP),
	DESCRIBE_ENUM(SIOCADDDLCI),
	DESCRIBE_ENUM(SIOCDELDLCI),
	DESCRIBE_ENUM(SIOCGIFVLAN),
	DESCRIBE_ENUM(SIOCSIFVLAN),
	DESCRIBE_ENUM(SIOCBONDENSLAVE),
	DESCRIBE_ENUM(SIOCBONDRELEASE),
	DESCRIBE_ENUM(SIOCBONDSETHWADDR),
	DESCRIBE_ENUM(SIOCBONDSLAVEINFOQUERY),
	DESCRIBE_ENUM(SIOCBONDINFOQUERY),
	DESCRIBE_ENUM(SIOCBONDCHANGEACTIVE),
	DESCRIBE_ENUM(SIOCBRADDBR),
	DESCRIBE_ENUM(SIOCBRDELBR),
	DESCRIBE_ENUM(SIOCBRADDIF),
	DESCRIBE_ENUM(SIOCBRDELIF),
	DESCRIBE_ENUM(SIOCSHWTSTAMP),
	DESCRIBE_ENUM(SIOCGHWTSTAMP),
	DESCRIBE_ENUM(SIOCDEVPRIVATE),
	DESCRIBE_ENUM(SIOCPROTOPRIVATE),
	DESCRIBE_ENUM(SIOCGSTAMP),
	DESCRIBE_ENUM(SIOCGSTAMPNS),
	// spi
	DESCRIBE_ENUM(SPI_IOC_MESSAGE(0)),
	DESCRIBE_ENUM(SPI_IOC_MESSAGE(1)),
	DESCRIBE_ENUM(SPI_IOC_MESSAGE(2)),
	DESCRIBE_ENUM(SPI_IOC_RD_MODE),
	DESCRIBE_ENUM(SPI_IOC_WR_MODE),
	DESCRIBE_ENUM(SPI_IOC_RD_LSB_FIRST),
	DESCRIBE_ENUM(SPI_IOC_WR_LSB_FIRST),
	DESCRIBE_ENUM(SPI_IOC_RD_BITS_PER_WORD),
	DESCRIBE_ENUM(SPI_IOC_WR_BITS_PER_WORD),
	DESCRIBE_ENUM(SPI_IOC_RD_MAX_SPEED_HZ),
	DESCRIBE_ENUM(SPI_IOC_WR_MAX_SPEED_HZ),
	DESCRIBE_ENUM(SPI_IOC_RD_MODE32),
	DESCRIBE_ENUM(SPI_IOC_WR_MODE32),
	// tipc
	DESCRIBE_ENUM(SIOCGETLINKNAME),
	DESCRIBE_ENUM(SIOCGETNODEID),
	// watchdog
	DESCRIBE_ENUM(WDIOC_GETSUPPORT),
	DESCRIBE_ENUM(WDIOC_GETSTATUS),
	DESCRIBE_ENUM(WDIOC_GETBOOTSTATUS),
	DESCRIBE_ENUM(WDIOC_GETTEMP),
	DESCRIBE_ENUM(WDIOC_SETOPTIONS),
	DESCRIBE_ENUM(WDIOC_KEEPALIVE),
	DESCRIBE_ENUM(WDIOC_SETTIMEOUT),
	DESCRIBE_ENUM(WDIOC_GETTIMEOUT),
	DESCRIBE_ENUM(WDIOC_SETPRETIMEOUT),
	DESCRIBE_ENUM(WDIOC_GETPRETIMEOUT),
	DESCRIBE_ENUM(WDIOC_GETTIMELEFT),
	// usb/cdc-wdm
	DESCRIBE_ENUM(IOCTL_WDM_MAX_COMMAND),
	// usb/functionfs
	DESCRIBE_ENUM(FUNCTIONFS_FIFO_STATUS),
	DESCRIBE_ENUM(FUNCTIONFS_FIFO_FLUSH),
	DESCRIBE_ENUM(FUNCTIONFS_CLEAR_HALT),
	DESCRIBE_ENUM(FUNCTIONFS_INTERFACE_REVMAP),
	DESCRIBE_ENUM(FUNCTIONFS_ENDPOINT_REVMAP),
	DESCRIBE_ENUM(FUNCTIONFS_ENDPOINT_DESC),
	DESCRIBE_ENUM(FUNCTIONFS_DMABUF_ATTACH),
	DESCRIBE_ENUM(FUNCTIONFS_DMABUF_DETACH),
	DESCRIBE_ENUM(FUNCTIONFS_DMABUF_TRANSFER),
	// usb/g_printer
	DESCRIBE_ENUM(GADGET_GET_PRINTER_STATUS),
	DESCRIBE_ENUM(GADGET_SET_PRINTER_STATUS),
	// usb/g_uvc
	DESCRIBE_ENUM(UVCIOC_SEND_RESPONSE),
	// usb/gadgetfs
	DESCRIBE_ENUM(GADGETFS_FIFO_STATUS),
	DESCRIBE_ENUM(GADGETFS_FIFO_FLUSH),
	DESCRIBE_ENUM(GADGETFS_CLEAR_HALT),
	// usb/raw_gadget
	DESCRIBE_ENUM(USB_RAW_IOCTL_INIT),
	DESCRIBE_ENUM(USB_RAW_IOCTL_RUN),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EVENT_FETCH),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP0_WRITE),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP0_READ),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_ENABLE),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_DISABLE),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_WRITE),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_READ),
	DESCRIBE_ENUM(USB_RAW_IOCTL_CONFIGURE),
	DESCRIBE_ENUM(USB_RAW_IOCTL_VBUS_DRAW),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EPS_INFO),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP0_STALL),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_SET_HALT),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_CLEAR_HALT),
	DESCRIBE_ENUM(USB_RAW_IOCTL_EP_SET_WEDGE),
	// usb/tmc
	DESCRIBE_ENUM(USBTMC_IOCTL_INDICATOR_PULSE),
	DESCRIBE_ENUM(USBTMC_IOCTL_CLEAR),
	DESCRIBE_ENUM(USBTMC_IOCTL_ABORT_BULK_OUT),
	DESCRIBE_ENUM(USBTMC_IOCTL_ABORT_BULK_IN),
	DESCRIBE_ENUM(USBTMC_IOCTL_CLEAR_OUT_HALT),
	DESCRIBE_ENUM(USBTMC_IOCTL_CLEAR_IN_HALT),
	DESCRIBE_ENUM(USBTMC_IOCTL_CTRL_REQUEST),
	DESCRIBE_ENUM(USBTMC_IOCTL_GET_TIMEOUT),
	DESCRIBE_ENUM(USBTMC_IOCTL_SET_TIMEOUT),
	DESCRIBE_ENUM(USBTMC_IOCTL_EOM_ENABLE),
	DESCRIBE_ENUM(USBTMC_IOCTL_CONFIG_TERMCHAR),
	DESCRIBE_ENUM(USBTMC_IOCTL_WRITE),
	DESCRIBE_ENUM(USBTMC_IOCTL_READ),
	DESCRIBE_ENUM(USBTMC_IOCTL_WRITE_RESULT),
	DESCRIBE_ENUM(USBTMC_IOCTL_API_VERSION),
	DESCRIBE_ENUM(USBTMC488_IOCTL_GET_CAPS),
	DESCRIBE_ENUM(USBTMC488_IOCTL_READ_STB),
	DESCRIBE_ENUM(USBTMC488_IOCTL_REN_CONTROL),
	DESCRIBE_ENUM(USBTMC488_IOCTL_GOTO_LOCAL),
	DESCRIBE_ENUM(USBTMC488_IOCTL_LOCAL_LOCKOUT),
	DESCRIBE_ENUM(USBTMC488_IOCTL_TRIGGER),
	DESCRIBE_ENUM(USBTMC488_IOCTL_WAIT_SRQ),
	DESCRIBE_ENUM(USBTMC_IOCTL_MSG_IN_ATTR),
	DESCRIBE_ENUM(USBTMC_IOCTL_AUTO_ABORT),
	DESCRIBE_ENUM(USBTMC_IOCTL_GET_STB),
	DESCRIBE_ENUM(USBTMC_IOCTL_GET_SRQ_STB),
	DESCRIBE_ENUM(USBTMC_IOCTL_CANCEL_IO),
	DESCRIBE_ENUM(USBTMC_IOCTL_CLEANUP_IO),
	// usbdevice_fs
	DESCRIBE_ENUM(USBDEVFS_CONTROL),
	DESCRIBE_ENUM(USBDEVFS_BULK),
	DESCRIBE_ENUM(USBDEVFS_RESETEP),
	DESCRIBE_ENUM(USBDEVFS_SETINTERFACE),
	DESCRIBE_ENUM(USBDEVFS_SETCONFIGURATION),
	DESCRIBE_ENUM(USBDEVFS_GETDRIVER),
	DESCRIBE_ENUM(USBDEVFS_SUBMITURB),
	DESCRIBE_ENUM(USBDEVFS_DISCARDURB),
	DESCRIBE_ENUM(USBDEVFS_REAPURB),
	DESCRIBE_ENUM(USBDEVFS_REAPURB32),
	DESCRIBE_ENUM(USBDEVFS_REAPURBNDELAY),
	DESCRIBE_ENUM(USBDEVFS_DISCSIGNAL),
	DESCRIBE_ENUM(USBDEVFS_CLAIMINTERFACE),
	DESCRIBE_ENUM(USBDEVFS_RELEASEINTERFACE),
	DESCRIBE_ENUM(USBDEVFS_CONNECTINFO),
	DESCRIBE_ENUM(USBDEVFS_IOCTL),
	DESCRIBE_ENUM(USBDEVFS_HUB_PORTINFO),
	DESCRIBE_ENUM(USBDEVFS_RESET),
	DESCRIBE_ENUM(USBDEVFS_CLEAR_HALT),
	DESCRIBE_ENUM(USBDEVFS_DISCONNECT),
	DESCRIBE_ENUM(USBDEVFS_CONNECT),
	DESCRIBE_ENUM(USBDEVFS_CLAIM_PORT),
	DESCRIBE_ENUM(USBDEVFS_RELEASE_PORT),
	DESCRIBE_ENUM(USBDEVFS_GET_CAPABILITIES),
	DESCRIBE_ENUM(USBDEVFS_DISCONNECT_CLAIM),
	DESCRIBE_ENUM(USBDEVFS_ALLOC_STREAMS),
	DESCRIBE_ENUM(USBDEVFS_FREE_STREAMS),
	DESCRIBE_ENUM(USBDEVFS_DROP_PRIVILEGES),
	DESCRIBE_ENUM(USBDEVFS_GET_SPEED),
	// DESCRIBE_ENUM(USBDEVFS_CONNINFO_EX), // variable size
	DESCRIBE_ENUM(USBDEVFS_FORBID_SUSPEND),
	DESCRIBE_ENUM(USBDEVFS_ALLOW_SUSPEND),
	DESCRIBE_ENUM(USBDEVFS_WAIT_FOR_RESUME),
	// wireless
	DESCRIBE_ENUM(SIOCSIWCOMMIT),
	DESCRIBE_ENUM(SIOCGIWNAME),
	DESCRIBE_ENUM(SIOCSIWNWID),
	DESCRIBE_ENUM(SIOCGIWNWID),
	DESCRIBE_ENUM(SIOCSIWFREQ),
	DESCRIBE_ENUM(SIOCGIWFREQ),
	DESCRIBE_ENUM(SIOCSIWMODE),
	DESCRIBE_ENUM(SIOCGIWMODE),
	DESCRIBE_ENUM(SIOCSIWSENS),
	DESCRIBE_ENUM(SIOCGIWSENS),
	DESCRIBE_ENUM(SIOCSIWRANGE),
	DESCRIBE_ENUM(SIOCGIWRANGE),
	DESCRIBE_ENUM(SIOCSIWPRIV),
	DESCRIBE_ENUM(SIOCGIWPRIV),
	DESCRIBE_ENUM(SIOCSIWSTATS),
	DESCRIBE_ENUM(SIOCGIWSTATS),
	DESCRIBE_ENUM(SIOCSIWSPY),
	DESCRIBE_ENUM(SIOCGIWSPY),
	DESCRIBE_ENUM(SIOCSIWTHRSPY),
	DESCRIBE_ENUM(SIOCGIWTHRSPY),
	DESCRIBE_ENUM(SIOCSIWAP),
	DESCRIBE_ENUM(SIOCGIWAP),
	DESCRIBE_ENUM(SIOCGIWAPLIST),
	DESCRIBE_ENUM(SIOCSIWSCAN),
	DESCRIBE_ENUM(SIOCGIWSCAN),
	DESCRIBE_ENUM(SIOCSIWESSID),
	DESCRIBE_ENUM(SIOCGIWESSID),
	DESCRIBE_ENUM(SIOCSIWNICKN),
	DESCRIBE_ENUM(SIOCGIWNICKN),
	DESCRIBE_ENUM(SIOCSIWRATE),
	DESCRIBE_ENUM(SIOCGIWRATE),
	DESCRIBE_ENUM(SIOCSIWRTS),
	DESCRIBE_ENUM(SIOCGIWRTS),
	DESCRIBE_ENUM(SIOCSIWFRAG),
	DESCRIBE_ENUM(SIOCGIWFRAG),
	DESCRIBE_ENUM(SIOCSIWTXPOW),
	DESCRIBE_ENUM(SIOCGIWTXPOW),
	DESCRIBE_ENUM(SIOCSIWRETRY),
	DESCRIBE_ENUM(SIOCGIWRETRY),
	DESCRIBE_ENUM(SIOCSIWENCODE),
	DESCRIBE_ENUM(SIOCGIWENCODE),
	DESCRIBE_ENUM(SIOCSIWPOWER),
	DESCRIBE_ENUM(SIOCGIWPOWER),
	DESCRIBE_ENUM(SIOCSIWGENIE),
	DESCRIBE_ENUM(SIOCGIWGENIE),
	DESCRIBE_ENUM(SIOCSIWMLME),
	DESCRIBE_ENUM(SIOCSIWAUTH),
	DESCRIBE_ENUM(SIOCGIWAUTH),
	DESCRIBE_ENUM(SIOCSIWENCODEEXT),
	DESCRIBE_ENUM(SIOCGIWENCODEEXT),
	DESCRIBE_ENUM(SIOCSIWPMKSA),
	DESCRIBE_ENUM(SIOCIWFIRSTPRIV),
	DESCRIBE_ENUM(SIOCIWLASTPRIV),
	// xen
	DESCRIBE_ENUM(IOCTL_PRIVCMD_HYPERCALL),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_MMAP),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_MMAPBATCH),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_MMAPBATCH_V2),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_DM_OP),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_RESTRICT),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_MMAP_RESOURCE),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_IRQFD),
	DESCRIBE_ENUM(IOCTL_PRIVCMD_IOEVENTFD),
	// xfs
	DESCRIBE_ENUM(XFS_IOC_ALLOCSP),
	DESCRIBE_ENUM(XFS_IOC_FREESP),
	DESCRIBE_ENUM(XFS_IOC_ALLOCSP64),
	DESCRIBE_ENUM(XFS_IOC_FREESP64),
	DESCRIBE_ENUM(XFS_IOC_DIOINFO),
	DESCRIBE_ENUM(XFS_IOC_GETBMAP),
	DESCRIBE_ENUM(XFS_IOC_RESVSP),
	DESCRIBE_ENUM(XFS_IOC_UNRESVSP),
	DESCRIBE_ENUM(XFS_IOC_RESVSP64),
	DESCRIBE_ENUM(XFS_IOC_UNRESVSP64),
	DESCRIBE_ENUM(XFS_IOC_GETBMAPA),
	DESCRIBE_ENUM(XFS_IOC_FSGETXATTRA),
	DESCRIBE_ENUM(XFS_IOC_GETBMAPX),
	// DESCRIBE_ENUM(XFS_IOC_ZERO_RANGE),
	DESCRIBE_ENUM(XFS_IOC_FREE_EOFBLOCKS),
	DESCRIBE_ENUM(XFS_IOC_SCRUB_METADATA),
	DESCRIBE_ENUM(XFS_IOC_AG_GEOMETRY),
	DESCRIBE_ENUM(XFS_IOC_FSGEOMETRY_V1),
	DESCRIBE_ENUM(XFS_IOC_FSBULKSTAT),
	DESCRIBE_ENUM(XFS_IOC_FSBULKSTAT_SINGLE),
	DESCRIBE_ENUM(XFS_IOC_FSINUMBERS),
	DESCRIBE_ENUM(XFS_IOC_PATH_TO_FSHANDLE),
	DESCRIBE_ENUM(XFS_IOC_PATH_TO_HANDLE),
	DESCRIBE_ENUM(XFS_IOC_FD_TO_HANDLE),
	DESCRIBE_ENUM(XFS_IOC_OPEN_BY_HANDLE),
	DESCRIBE_ENUM(XFS_IOC_READLINK_BY_HANDLE),
	DESCRIBE_ENUM(XFS_IOC_SWAPEXT),
	DESCRIBE_ENUM(XFS_IOC_FSGROWFSDATA),
	DESCRIBE_ENUM(XFS_IOC_FSGROWFSLOG),
	DESCRIBE_ENUM(XFS_IOC_FSGROWFSRT),
	DESCRIBE_ENUM(XFS_IOC_FSCOUNTS),
	DESCRIBE_ENUM(XFS_IOC_SET_RESBLKS),
	DESCRIBE_ENUM(XFS_IOC_GET_RESBLKS),
	DESCRIBE_ENUM(XFS_IOC_ERROR_INJECTION),
	DESCRIBE_ENUM(XFS_IOC_ERROR_CLEARALL),
	DESCRIBE_ENUM(XFS_IOC_FREEZE),
	DESCRIBE_ENUM(XFS_IOC_THAW),
	DESCRIBE_ENUM(XFS_IOC_ATTRLIST_BY_HANDLE),
	DESCRIBE_ENUM(XFS_IOC_ATTRMULTI_BY_HANDLE),
	DESCRIBE_ENUM(XFS_IOC_FSGEOMETRY_V4),
	DESCRIBE_ENUM(XFS_IOC_GOINGDOWN),
	DESCRIBE_ENUM(XFS_IOC_FSGEOMETRY),
	DESCRIBE_ENUM(XFS_IOC_BULKSTAT),
	DESCRIBE_ENUM(XFS_IOC_INUMBERS),
	// zfs
	DESCRIBE_ENUM(ZFS_IOC_POOL_CREATE),
	DESCRIBE_ENUM(ZFS_IOC_POOL_DESTROY),
	DESCRIBE_ENUM(ZFS_IOC_POOL_IMPORT),
	DESCRIBE_ENUM(ZFS_IOC_POOL_EXPORT),
	DESCRIBE_ENUM(ZFS_IOC_POOL_CONFIGS),
	DESCRIBE_ENUM(ZFS_IOC_POOL_STATS),
	DESCRIBE_ENUM(ZFS_IOC_POOL_TRYIMPORT),
	DESCRIBE_ENUM(ZFS_IOC_POOL_SCAN),
	DESCRIBE_ENUM(ZFS_IOC_POOL_FREEZE),
	DESCRIBE_ENUM(ZFS_IOC_POOL_UPGRADE),
	DESCRIBE_ENUM(ZFS_IOC_POOL_GET_HISTORY),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_ADD),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_REMOVE),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_SET_STATE),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_ATTACH),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_DETACH),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_SETPATH),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_SETFRU),
	DESCRIBE_ENUM(ZFS_IOC_OBJSET_STATS),
	DESCRIBE_ENUM(ZFS_IOC_OBJSET_ZPLPROPS),
	DESCRIBE_ENUM(ZFS_IOC_DATASET_LIST_NEXT),
	DESCRIBE_ENUM(ZFS_IOC_SNAPSHOT_LIST_NEXT),
	DESCRIBE_ENUM(ZFS_IOC_SET_PROP),
	DESCRIBE_ENUM(ZFS_IOC_CREATE),
	DESCRIBE_ENUM(ZFS_IOC_DESTROY),
	DESCRIBE_ENUM(ZFS_IOC_ROLLBACK),
	DESCRIBE_ENUM(ZFS_IOC_RENAME),
	DESCRIBE_ENUM(ZFS_IOC_RECV),
	DESCRIBE_ENUM(ZFS_IOC_SEND),
	DESCRIBE_ENUM(ZFS_IOC_INJECT_FAULT),
	DESCRIBE_ENUM(ZFS_IOC_CLEAR_FAULT),
	DESCRIBE_ENUM(ZFS_IOC_INJECT_LIST_NEXT),
	DESCRIBE_ENUM(ZFS_IOC_ERROR_LOG),
	DESCRIBE_ENUM(ZFS_IOC_CLEAR),
	DESCRIBE_ENUM(ZFS_IOC_PROMOTE),
	DESCRIBE_ENUM(ZFS_IOC_SNAPSHOT),
	DESCRIBE_ENUM(ZFS_IOC_DSOBJ_TO_DSNAME),
	DESCRIBE_ENUM(ZFS_IOC_OBJ_TO_PATH),
	DESCRIBE_ENUM(ZFS_IOC_POOL_SET_PROPS),
	DESCRIBE_ENUM(ZFS_IOC_POOL_GET_PROPS),
	DESCRIBE_ENUM(ZFS_IOC_SET_FSACL),
	DESCRIBE_ENUM(ZFS_IOC_GET_FSACL),
	DESCRIBE_ENUM(ZFS_IOC_SHARE),
	DESCRIBE_ENUM(ZFS_IOC_INHERIT_PROP),
	DESCRIBE_ENUM(ZFS_IOC_SMB_ACL),
	DESCRIBE_ENUM(ZFS_IOC_USERSPACE_ONE),
	DESCRIBE_ENUM(ZFS_IOC_USERSPACE_MANY),
	DESCRIBE_ENUM(ZFS_IOC_USERSPACE_UPGRADE),
	DESCRIBE_ENUM(ZFS_IOC_HOLD),
	DESCRIBE_ENUM(ZFS_IOC_RELEASE),
	DESCRIBE_ENUM(ZFS_IOC_GET_HOLDS),
	DESCRIBE_ENUM(ZFS_IOC_OBJSET_RECVD_PROPS),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_SPLIT),
	DESCRIBE_ENUM(ZFS_IOC_NEXT_OBJ),
	DESCRIBE_ENUM(ZFS_IOC_DIFF),
	DESCRIBE_ENUM(ZFS_IOC_TMP_SNAPSHOT),
	DESCRIBE_ENUM(ZFS_IOC_OBJ_TO_STATS),
	DESCRIBE_ENUM(ZFS_IOC_SPACE_WRITTEN),
	DESCRIBE_ENUM(ZFS_IOC_SPACE_SNAPS),
	DESCRIBE_ENUM(ZFS_IOC_DESTROY_SNAPS),
	DESCRIBE_ENUM(ZFS_IOC_POOL_REGUID),
	DESCRIBE_ENUM(ZFS_IOC_POOL_REOPEN),
	DESCRIBE_ENUM(ZFS_IOC_SEND_PROGRESS),
	DESCRIBE_ENUM(ZFS_IOC_LOG_HISTORY),
	DESCRIBE_ENUM(ZFS_IOC_SEND_NEW),
	DESCRIBE_ENUM(ZFS_IOC_SEND_SPACE),
	DESCRIBE_ENUM(ZFS_IOC_CLONE),
	DESCRIBE_ENUM(ZFS_IOC_BOOKMARK),
	DESCRIBE_ENUM(ZFS_IOC_GET_BOOKMARKS),
	DESCRIBE_ENUM(ZFS_IOC_DESTROY_BOOKMARKS),
	DESCRIBE_ENUM(ZFS_IOC_RECV_NEW),
	DESCRIBE_ENUM(ZFS_IOC_POOL_SYNC),
	DESCRIBE_ENUM(ZFS_IOC_CHANNEL_PROGRAM),
	DESCRIBE_ENUM(ZFS_IOC_LOAD_KEY),
	DESCRIBE_ENUM(ZFS_IOC_UNLOAD_KEY),
	DESCRIBE_ENUM(ZFS_IOC_CHANGE_KEY),
	DESCRIBE_ENUM(ZFS_IOC_REMAP),
	DESCRIBE_ENUM(ZFS_IOC_POOL_CHECKPOINT),
	DESCRIBE_ENUM(ZFS_IOC_POOL_DISCARD_CHECKPOINT),
	DESCRIBE_ENUM(ZFS_IOC_POOL_INITIALIZE),
	DESCRIBE_ENUM(ZFS_IOC_POOL_TRIM),
	DESCRIBE_ENUM(ZFS_IOC_REDACT),
	DESCRIBE_ENUM(ZFS_IOC_GET_BOOKMARK_PROPS),
	DESCRIBE_ENUM(ZFS_IOC_WAIT),
	DESCRIBE_ENUM(ZFS_IOC_WAIT_FS),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_GET_PROPS),
	DESCRIBE_ENUM(ZFS_IOC_VDEV_SET_PROPS),
	DESCRIBE_ENUM(ZFS_IOC_POOL_SCRUB),
	DESCRIBE_ENUM(ZFS_IOC_PLATFORM),
	DESCRIBE_ENUM(ZFS_IOC_EVENTS_NEXT),
	DESCRIBE_ENUM(ZFS_IOC_EVENTS_CLEAR),
	DESCRIBE_ENUM(ZFS_IOC_EVENTS_SEEK),
	DESCRIBE_ENUM(ZFS_IOC_NEXTBOOT),
	DESCRIBE_ENUM(ZFS_IOC_JAIL),
	DESCRIBE_ENUM(ZFS_IOC_USERNS_ATTACH),
	DESCRIBE_ENUM(ZFS_IOC_UNJAIL),
	DESCRIBE_ENUM(ZFS_IOC_USERNS_DETACH),
	DESCRIBE_ENUM(ZFS_IOC_SET_BOOTENV),
	DESCRIBE_ENUM(ZFS_IOC_GET_BOOTENV),
};

static struct enum_option sighows[] = {
	DESCRIBE_ENUM(SIG_BLOCK),
	DESCRIBE_ENUM(SIG_UNBLOCK),
	DESCRIBE_ENUM(SIG_SETMASK),
};

static struct enum_option madvises[] = {
	DESCRIBE_ENUM(MADV_NORMAL),
	DESCRIBE_ENUM(MADV_RANDOM),
	DESCRIBE_ENUM(MADV_SEQUENTIAL),
	DESCRIBE_ENUM(MADV_WILLNEED),
	DESCRIBE_ENUM(MADV_DONTNEED),
	DESCRIBE_ENUM(MADV_REMOVE),
	DESCRIBE_ENUM(MADV_DONTFORK),
	DESCRIBE_ENUM(MADV_DOFORK),
	DESCRIBE_ENUM(MADV_HWPOISON),
	DESCRIBE_ENUM(MADV_MERGEABLE),
	DESCRIBE_ENUM(MADV_UNMERGEABLE),
	// DESCRIBE_ENUM(MADV_SOFT_OFFLINE),
	DESCRIBE_ENUM(MADV_HUGEPAGE),
	DESCRIBE_ENUM(MADV_NOHUGEPAGE),
	DESCRIBE_ENUM(MADV_DONTDUMP),
	DESCRIBE_ENUM(MADV_DODUMP),
	DESCRIBE_ENUM(MADV_FREE),
	DESCRIBE_ENUM(MADV_WIPEONFORK),
	DESCRIBE_ENUM(MADV_KEEPONFORK),
};

static struct enum_option fcntls[] = {
	DESCRIBE_ENUM(F_DUPFD),
	DESCRIBE_ENUM(F_DUPFD_CLOEXEC),
	DESCRIBE_ENUM(F_GETFD),
	DESCRIBE_ENUM(F_SETFD),
	DESCRIBE_ENUM(F_GETFL),
	DESCRIBE_ENUM(F_SETFL),
	DESCRIBE_ENUM(F_SETLK),
	DESCRIBE_ENUM(F_SETLKW),
	DESCRIBE_ENUM(F_GETLK),
	DESCRIBE_ENUM(F_OFD_SETLK),
	DESCRIBE_ENUM(F_OFD_SETLKW),
	DESCRIBE_ENUM(F_OFD_GETLK),
	DESCRIBE_ENUM(F_GETOWN),
	DESCRIBE_ENUM(F_SETOWN),
	DESCRIBE_ENUM(F_GETOWN_EX),
	DESCRIBE_ENUM(F_SETOWN_EX),
	DESCRIBE_ENUM(F_GETSIG),
	DESCRIBE_ENUM(F_SETSIG),
	DESCRIBE_ENUM(F_SETLEASE),
	DESCRIBE_ENUM(F_GETLEASE),
	DESCRIBE_ENUM(F_NOTIFY),
	DESCRIBE_ENUM(F_SETPIPE_SZ),
	DESCRIBE_ENUM(F_GETPIPE_SZ),
	DESCRIBE_ENUM(F_ADD_SEALS),
	DESCRIBE_ENUM(F_GET_SEALS),
	DESCRIBE_ENUM(F_GET_RW_HINT),
	DESCRIBE_ENUM(F_SET_RW_HINT),
	DESCRIBE_ENUM(F_GET_FILE_RW_HINT),
	DESCRIBE_ENUM(F_SET_FILE_RW_HINT),
};

static const char *fd_flags[64] = {
	DESCRIBE_FLAG(FD_CLOEXEC),
};

static struct enum_option lease_args[] = {
	DESCRIBE_ENUM(F_RDLCK),
	DESCRIBE_ENUM(F_WRLCK),
	DESCRIBE_ENUM(F_UNLCK),
};

static const char *seal_flags[64] = {
	DESCRIBE_FLAG(F_SEAL_SEAL),
	DESCRIBE_FLAG(F_SEAL_SHRINK),
	DESCRIBE_FLAG(F_SEAL_GROW),
	DESCRIBE_FLAG(F_SEAL_WRITE),
	DESCRIBE_FLAG(F_SEAL_FUTURE_WRITE),
};

static struct enum_option rlimits[] = {
	DESCRIBE_ENUM(RLIMIT_AS),
	DESCRIBE_ENUM(RLIMIT_CORE),
	DESCRIBE_ENUM(RLIMIT_CPU),
	DESCRIBE_ENUM(RLIMIT_DATA),
	DESCRIBE_ENUM(RLIMIT_FSIZE),
	DESCRIBE_ENUM(RLIMIT_LOCKS),
	DESCRIBE_ENUM(RLIMIT_MEMLOCK),
	DESCRIBE_ENUM(RLIMIT_MSGQUEUE),
	DESCRIBE_ENUM(RLIMIT_NICE),
	DESCRIBE_ENUM(RLIMIT_NOFILE),
	DESCRIBE_ENUM(RLIMIT_NPROC),
	DESCRIBE_ENUM(RLIMIT_RSS),
	DESCRIBE_ENUM(RLIMIT_RTPRIO),
	DESCRIBE_ENUM(RLIMIT_RTTIME),
	DESCRIBE_ENUM(RLIMIT_SIGPENDING),
	DESCRIBE_ENUM(RLIMIT_STACK),
};

static struct enum_option socket_domains[] = {
	DESCRIBE_ENUM(AF_UNIX),
	DESCRIBE_ENUM(AF_LOCAL),
	DESCRIBE_ENUM(AF_INET),
	DESCRIBE_ENUM(AF_AX25),
	DESCRIBE_ENUM(AF_IPX),
	DESCRIBE_ENUM(AF_APPLETALK),
	DESCRIBE_ENUM(AF_X25),
	DESCRIBE_ENUM(AF_INET6),
	DESCRIBE_ENUM(AF_DECnet),
	DESCRIBE_ENUM(AF_KEY),
	DESCRIBE_ENUM(AF_NETLINK),
	DESCRIBE_ENUM(AF_PACKET),
	DESCRIBE_ENUM(AF_RDS),
	DESCRIBE_ENUM(AF_PPPOX),
	DESCRIBE_ENUM(AF_LLC),
	DESCRIBE_ENUM(AF_IB),
	DESCRIBE_ENUM(AF_MPLS),
	DESCRIBE_ENUM(AF_CAN),
	DESCRIBE_ENUM(AF_TIPC),
	DESCRIBE_ENUM(AF_BLUETOOTH),
	DESCRIBE_ENUM(AF_ALG),
	DESCRIBE_ENUM(AF_VSOCK),
	DESCRIBE_ENUM(AF_KCM),
	DESCRIBE_ENUM(AF_XDP),
};

static struct enum_option socket_types[] = {
	DESCRIBE_ENUM(SOCK_STREAM),
	DESCRIBE_ENUM(SOCK_DGRAM),
	DESCRIBE_ENUM(SOCK_SEQPACKET),
	DESCRIBE_ENUM(SOCK_RAW),
	DESCRIBE_ENUM(SOCK_RDM),
	DESCRIBE_ENUM(SOCK_PACKET),
};

static const char *socket_flags[64] = {
	DESCRIBE_FLAG(SOCK_NONBLOCK),
	DESCRIBE_FLAG(SOCK_CLOEXEC),
};

static struct enum_option clock_ids[] = {
	DESCRIBE_ENUM(CLOCK_REALTIME),
	DESCRIBE_ENUM(CLOCK_REALTIME_COARSE),
	DESCRIBE_ENUM(CLOCK_MONOTONIC),
	DESCRIBE_ENUM(CLOCK_MONOTONIC_COARSE),
	DESCRIBE_ENUM(CLOCK_MONOTONIC_RAW),
	DESCRIBE_ENUM(CLOCK_BOOTTIME),
	DESCRIBE_ENUM(CLOCK_PROCESS_CPUTIME_ID),
	DESCRIBE_ENUM(CLOCK_THREAD_CPUTIME_ID),
	{.value = 0xfffffffffffffffa, .description = "MAKE_PROCESS_CPUCLOCK(0, CPUCLOCK_SCHED)"},
};

static struct enum_option socket_levels[] = {
	DESCRIBE_ENUM(SOL_SOCKET),
	DESCRIBE_ENUM(SOL_IP),
	DESCRIBE_ENUM(SOL_TCP),
	DESCRIBE_ENUM(SOL_UDP),
	DESCRIBE_ENUM(SOL_IPV6),
	DESCRIBE_ENUM(SOL_ICMPV6),
	DESCRIBE_ENUM(SOL_SCTP),
	DESCRIBE_ENUM(SOL_UDPLITE),
	DESCRIBE_ENUM(SOL_RAW),
	DESCRIBE_ENUM(SOL_IPX),
	DESCRIBE_ENUM(SOL_AX25),
	DESCRIBE_ENUM(SOL_ATALK),
	DESCRIBE_ENUM(SOL_NETROM),
	DESCRIBE_ENUM(SOL_ROSE),
	DESCRIBE_ENUM(SOL_DECNET),
	DESCRIBE_ENUM(SOL_X25),
	DESCRIBE_ENUM(SOL_PACKET),
	DESCRIBE_ENUM(SOL_ATM),
	DESCRIBE_ENUM(SOL_AAL),
	DESCRIBE_ENUM(SOL_IRDA),
	DESCRIBE_ENUM(SOL_NETBEUI),
	DESCRIBE_ENUM(SOL_LLC),
	DESCRIBE_ENUM(SOL_DCCP),
	DESCRIBE_ENUM(SOL_NETLINK),
	DESCRIBE_ENUM(SOL_TIPC),
	DESCRIBE_ENUM(SOL_RXRPC),
	DESCRIBE_ENUM(SOL_PPPOL2TP),
	DESCRIBE_ENUM(SOL_BLUETOOTH),
	DESCRIBE_ENUM(SOL_PNPIPE),
	DESCRIBE_ENUM(SOL_RDS),
	DESCRIBE_ENUM(SOL_IUCV),
	DESCRIBE_ENUM(SOL_CAIF),
	DESCRIBE_ENUM(SOL_ALG),
	DESCRIBE_ENUM(SOL_NFC),
	DESCRIBE_ENUM(SOL_KCM),
	DESCRIBE_ENUM(SOL_TLS),
	DESCRIBE_ENUM(SOL_XDP),
	DESCRIBE_ENUM(SOL_MPTCP),
	DESCRIBE_ENUM(SOL_MCTP),
	DESCRIBE_ENUM(SOL_SMC),
	DESCRIBE_ENUM(SOL_VSOCK),
};

#define SO_RESERVE_MEM 73
#define SO_TXREHASH 74
#define SO_RCVMARK 75
#define SO_PASSPIDFD 76
#define SO_PEERPIDFD 77

#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif

#ifndef IP_PROTOCOL
#define IP_PROTOCOL 52
#endif

#define IP6T_BASE_CTL 64
#define IP6T_SO_GET_INFO (IP6T_BASE_CTL)
#define IP6T_SO_GET_ENTRIES (IP6T_BASE_CTL + 1)
#define IP6T_SO_GET_REVISION_MATCH (IP6T_BASE_CTL + 4)
#define IP6T_SO_GET_REVISION_TARGET (IP6T_BASE_CTL + 5)
#define IP6T_SO_ORIGINAL_DST 80

#define TLS_TX_ZEROCOPY_RO 3
#define TLS_RX_EXPECT_NO_PAD 4

#define ALG_SET_KEY_BY_KEY_SERIAL 7

#define IPT_BASE_CTL 64

#define IPT_SO_SET_REPLACE (IPT_BASE_CTL)
#define IPT_SO_SET_ADD_COUNTERS (IPT_BASE_CTL + 1)

#define IPT_SO_GET_INFO (IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES (IPT_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH (IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET (IPT_BASE_CTL + 3)

#define IP6T_BASE_CTL 64

#define IP6T_SO_SET_REPLACE (IP6T_BASE_CTL)
#define IP6T_SO_SET_ADD_COUNTERS (IP6T_BASE_CTL + 1)

#define IP6T_SO_GET_INFO (IP6T_BASE_CTL)
#define IP6T_SO_GET_ENTRIES (IP6T_BASE_CTL + 1)
#define IP6T_SO_GET_REVISION_MATCH (IP6T_BASE_CTL + 4)
#define IP6T_SO_GET_REVISION_TARGET (IP6T_BASE_CTL + 5)

#define IP6T_SO_ORIGINAL_DST 80

static struct enum_option socket_options[] = {
	DESCRIBE_ENUM(SO_DEBUG),
	DESCRIBE_ENUM(SO_REUSEADDR),
	DESCRIBE_ENUM(SO_TYPE),
	DESCRIBE_ENUM(SO_ERROR),
	DESCRIBE_ENUM(SO_DONTROUTE),
	DESCRIBE_ENUM(SO_BROADCAST),
	DESCRIBE_ENUM(SO_SNDBUF),
	DESCRIBE_ENUM(SO_RCVBUF),
	DESCRIBE_ENUM(SO_SNDBUFFORCE),
	DESCRIBE_ENUM(SO_RCVBUFFORCE),
	DESCRIBE_ENUM(SO_KEEPALIVE),
	DESCRIBE_ENUM(SO_OOBINLINE),
	DESCRIBE_ENUM(SO_NO_CHECK),
	DESCRIBE_ENUM(SO_PRIORITY),
	DESCRIBE_ENUM(SO_LINGER),
	DESCRIBE_ENUM(SO_BSDCOMPAT),
	DESCRIBE_ENUM(SO_REUSEPORT),
	DESCRIBE_ENUM(SO_PASSCRED),
	DESCRIBE_ENUM(SO_PEERCRED),
	DESCRIBE_ENUM(SO_RCVLOWAT),
	DESCRIBE_ENUM(SO_SNDLOWAT),
	DESCRIBE_ENUM(SO_RCVTIMEO_OLD),
	DESCRIBE_ENUM(SO_SNDTIMEO_OLD),
	DESCRIBE_ENUM(SO_SECURITY_AUTHENTICATION),
	DESCRIBE_ENUM(SO_SECURITY_ENCRYPTION_TRANSPORT),
	DESCRIBE_ENUM(SO_SECURITY_ENCRYPTION_NETWORK),
	DESCRIBE_ENUM(SO_BINDTODEVICE),
	DESCRIBE_ENUM(SO_ATTACH_FILTER),
	DESCRIBE_ENUM(SO_DETACH_FILTER),
	DESCRIBE_ENUM(SO_PEERNAME),
	DESCRIBE_ENUM(SO_TIMESTAMP_OLD),
	DESCRIBE_ENUM(SO_ACCEPTCONN),
	DESCRIBE_ENUM(SO_PEERSEC),
	DESCRIBE_ENUM(SO_PASSSEC),
	DESCRIBE_ENUM(SO_TIMESTAMPNS_OLD),
	DESCRIBE_ENUM(SO_MARK),
	DESCRIBE_ENUM(SO_TIMESTAMPING_OLD),
	DESCRIBE_ENUM(SO_PROTOCOL),
	DESCRIBE_ENUM(SO_DOMAIN),
	DESCRIBE_ENUM(SO_RXQ_OVFL),
	DESCRIBE_ENUM(SO_WIFI_STATUS),
	DESCRIBE_ENUM(SO_PEEK_OFF),
	DESCRIBE_ENUM(SO_NOFCS),
	DESCRIBE_ENUM(SO_LOCK_FILTER),
	DESCRIBE_ENUM(SO_SELECT_ERR_QUEUE),
	DESCRIBE_ENUM(SO_BUSY_POLL),
	DESCRIBE_ENUM(SO_MAX_PACING_RATE),
	DESCRIBE_ENUM(SO_BPF_EXTENSIONS),
	DESCRIBE_ENUM(SO_INCOMING_CPU),
	DESCRIBE_ENUM(SO_ATTACH_BPF),
	DESCRIBE_ENUM(SO_ATTACH_REUSEPORT_CBPF),
	DESCRIBE_ENUM(SO_ATTACH_REUSEPORT_EBPF),
	DESCRIBE_ENUM(SO_CNX_ADVICE),
	DESCRIBE_ENUM(SCM_TIMESTAMPING_OPT_STATS),
	DESCRIBE_ENUM(SO_MEMINFO),
	DESCRIBE_ENUM(SO_INCOMING_NAPI_ID),
	DESCRIBE_ENUM(SO_COOKIE),
	DESCRIBE_ENUM(SCM_TIMESTAMPING_PKTINFO),
	DESCRIBE_ENUM(SO_PEERGROUPS),
	DESCRIBE_ENUM(SO_ZEROCOPY),
	DESCRIBE_ENUM(SO_TXTIME),
	DESCRIBE_ENUM(SO_BINDTOIFINDEX),
	DESCRIBE_ENUM(SO_TIMESTAMP_NEW),
	DESCRIBE_ENUM(SO_TIMESTAMPNS_NEW),
	DESCRIBE_ENUM(SO_TIMESTAMPING_NEW),
	DESCRIBE_ENUM(SO_RCVTIMEO_NEW),
	DESCRIBE_ENUM(SO_SNDTIMEO_NEW),
	DESCRIBE_ENUM(SO_DETACH_REUSEPORT_BPF),
	DESCRIBE_ENUM(SO_PREFER_BUSY_POLL),
	DESCRIBE_ENUM(SO_BUSY_POLL_BUDGET),
	DESCRIBE_ENUM(SO_NETNS_COOKIE),
	DESCRIBE_ENUM(SO_BUF_LOCK),
	DESCRIBE_ENUM(SO_RESERVE_MEM),
	DESCRIBE_ENUM(SO_TXREHASH),
	DESCRIBE_ENUM(SO_RCVMARK),
	DESCRIBE_ENUM(SO_PASSPIDFD),
	DESCRIBE_ENUM(SO_PEERPIDFD),

	DESCRIBE_ENUM(IP_RECVERR),
	DESCRIBE_ENUM(IP_TOS),
	DESCRIBE_ENUM(IP_TTL),
	DESCRIBE_ENUM(IP_HDRINCL),
	DESCRIBE_ENUM(IP_OPTIONS),
	DESCRIBE_ENUM(IP_ROUTER_ALERT),
	DESCRIBE_ENUM(IP_RECVOPTS),
	DESCRIBE_ENUM(IP_RETOPTS),
	DESCRIBE_ENUM(IP_PKTINFO),
	DESCRIBE_ENUM(IP_PKTOPTIONS),
	DESCRIBE_ENUM(IP_MTU_DISCOVER),
	DESCRIBE_ENUM(IP_RECVERR),
	DESCRIBE_ENUM(IP_RECVTTL),
	DESCRIBE_ENUM(IP_RECVTOS),
	DESCRIBE_ENUM(IP_MTU),
	DESCRIBE_ENUM(IP_FREEBIND),
	DESCRIBE_ENUM(IP_IPSEC_POLICY),
	DESCRIBE_ENUM(IP_XFRM_POLICY),
	DESCRIBE_ENUM(IP_PASSSEC),
	DESCRIBE_ENUM(IP_TRANSPARENT),
	DESCRIBE_ENUM(IP_ORIGDSTADDR),
	DESCRIBE_ENUM(IP_MINTTL),
	DESCRIBE_ENUM(IP_NODEFRAG),
	DESCRIBE_ENUM(IP_CHECKSUM),
	DESCRIBE_ENUM(IP_BIND_ADDRESS_NO_PORT),
	DESCRIBE_ENUM(IP_RECVFRAGSIZE),
	DESCRIBE_ENUM(IP_RECVERR_RFC4884),
	DESCRIBE_ENUM(IP_MULTICAST_IF),
	DESCRIBE_ENUM(IP_MULTICAST_TTL),
	DESCRIBE_ENUM(IP_MULTICAST_LOOP),
	DESCRIBE_ENUM(IP_ADD_MEMBERSHIP),
	DESCRIBE_ENUM(IP_DROP_MEMBERSHIP),
	DESCRIBE_ENUM(IP_UNBLOCK_SOURCE),
	DESCRIBE_ENUM(IP_BLOCK_SOURCE),
	DESCRIBE_ENUM(IP_ADD_SOURCE_MEMBERSHIP),
	DESCRIBE_ENUM(IP_DROP_SOURCE_MEMBERSHIP),
	DESCRIBE_ENUM(IP_MSFILTER),
	DESCRIBE_ENUM(MCAST_JOIN_GROUP),
	DESCRIBE_ENUM(MCAST_BLOCK_SOURCE),
	DESCRIBE_ENUM(MCAST_UNBLOCK_SOURCE),
	DESCRIBE_ENUM(MCAST_LEAVE_GROUP),
	DESCRIBE_ENUM(MCAST_JOIN_SOURCE_GROUP),
	DESCRIBE_ENUM(MCAST_LEAVE_SOURCE_GROUP),
	DESCRIBE_ENUM(MCAST_MSFILTER),
	DESCRIBE_ENUM(IP_MULTICAST_ALL),
	DESCRIBE_ENUM(IP_UNICAST_IF),
	DESCRIBE_ENUM(IP_LOCAL_PORT_RANGE),
	DESCRIBE_ENUM(IP_PROTOCOL),

	DESCRIBE_ENUM(IPV6_ADDRFORM),
	DESCRIBE_ENUM(IPV6_2292PKTINFO),
	DESCRIBE_ENUM(IPV6_2292HOPOPTS),
	DESCRIBE_ENUM(IPV6_2292DSTOPTS),
	DESCRIBE_ENUM(IPV6_2292RTHDR),
	DESCRIBE_ENUM(IPV6_2292PKTOPTIONS),
	DESCRIBE_ENUM(IPV6_CHECKSUM),
	DESCRIBE_ENUM(IPV6_2292HOPLIMIT),
	DESCRIBE_ENUM(IPV6_NEXTHOP),
	DESCRIBE_ENUM(IPV6_AUTHHDR),
	DESCRIBE_ENUM(IPV6_FLOWINFO),
	DESCRIBE_ENUM(IPV6_UNICAST_HOPS),
	DESCRIBE_ENUM(IPV6_MULTICAST_IF),
	DESCRIBE_ENUM(IPV6_MULTICAST_HOPS),
	DESCRIBE_ENUM(IPV6_MULTICAST_LOOP),
	DESCRIBE_ENUM(IPV6_ADD_MEMBERSHIP),
	DESCRIBE_ENUM(IPV6_DROP_MEMBERSHIP),
	DESCRIBE_ENUM(IPV6_ROUTER_ALERT),
	DESCRIBE_ENUM(IPV6_MTU_DISCOVER),
	DESCRIBE_ENUM(IPV6_MTU),
	DESCRIBE_ENUM(IPV6_RECVERR),
	DESCRIBE_ENUM(IPV6_V6ONLY),
	DESCRIBE_ENUM(IPV6_JOIN_ANYCAST),
	DESCRIBE_ENUM(IPV6_LEAVE_ANYCAST),
	DESCRIBE_ENUM(IPV6_MULTICAST_ALL),
	DESCRIBE_ENUM(IPV6_ROUTER_ALERT_ISOLATE),
	DESCRIBE_ENUM(IPV6_RECVERR_RFC4884),
	DESCRIBE_ENUM(IPV6_FLOWLABEL_MGR),
	DESCRIBE_ENUM(IPV6_FLOWINFO_SEND),
	DESCRIBE_ENUM(IPV6_IPSEC_POLICY),
	DESCRIBE_ENUM(IPV6_XFRM_POLICY),
	DESCRIBE_ENUM(IPV6_HDRINCL),
	DESCRIBE_ENUM(IPV6_RECVPKTINFO),
	DESCRIBE_ENUM(IPV6_PKTINFO),
	DESCRIBE_ENUM(IPV6_RECVHOPLIMIT),
	DESCRIBE_ENUM(IPV6_HOPLIMIT),
	DESCRIBE_ENUM(IPV6_RECVHOPOPTS),
	DESCRIBE_ENUM(IPV6_HOPOPTS),
	DESCRIBE_ENUM(IPV6_RTHDRDSTOPTS),
	DESCRIBE_ENUM(IPV6_RECVRTHDR),
	DESCRIBE_ENUM(IPV6_RTHDR),
	DESCRIBE_ENUM(IPV6_RECVDSTOPTS),
	DESCRIBE_ENUM(IPV6_DSTOPTS),
	DESCRIBE_ENUM(IPV6_RECVPATHMTU),
	DESCRIBE_ENUM(IPV6_PATHMTU),
	DESCRIBE_ENUM(IPV6_DONTFRAG),
	DESCRIBE_ENUM(IPV6_RECVTCLASS),
	DESCRIBE_ENUM(IPV6_TCLASS),
	DESCRIBE_ENUM(IP6T_SO_GET_REVISION_MATCH),
	DESCRIBE_ENUM(IP6T_SO_GET_REVISION_TARGET),
	DESCRIBE_ENUM(IP6T_SO_ORIGINAL_DST),
	DESCRIBE_ENUM(IPV6_AUTOFLOWLABEL),
	DESCRIBE_ENUM(IPV6_ADDR_PREFERENCES),
	DESCRIBE_ENUM(IPV6_MINHOPCOUNT),
	DESCRIBE_ENUM(IPV6_ORIGDSTADDR),
	DESCRIBE_ENUM(IPV6_TRANSPARENT),
	DESCRIBE_ENUM(IPV6_UNICAST_IF),
	DESCRIBE_ENUM(IPV6_RECVFRAGSIZE),
	DESCRIBE_ENUM(IPV6_FREEBIND),

	DESCRIBE_ENUM(TCP_NODELAY),
	DESCRIBE_ENUM(TCP_MAXSEG),
	DESCRIBE_ENUM(TCP_CORK),
	DESCRIBE_ENUM(TCP_KEEPIDLE),
	DESCRIBE_ENUM(TCP_KEEPINTVL),
	DESCRIBE_ENUM(TCP_KEEPCNT),
	DESCRIBE_ENUM(TCP_SYNCNT),
	DESCRIBE_ENUM(TCP_LINGER2),
	DESCRIBE_ENUM(TCP_DEFER_ACCEPT),
	DESCRIBE_ENUM(TCP_WINDOW_CLAMP),
	DESCRIBE_ENUM(TCP_INFO),
	DESCRIBE_ENUM(TCP_QUICKACK),
	DESCRIBE_ENUM(TCP_CONGESTION),
	DESCRIBE_ENUM(TCP_MD5SIG),
	DESCRIBE_ENUM(TCP_THIN_LINEAR_TIMEOUTS),
	DESCRIBE_ENUM(TCP_THIN_DUPACK),
	DESCRIBE_ENUM(TCP_USER_TIMEOUT),
	DESCRIBE_ENUM(TCP_REPAIR),
	DESCRIBE_ENUM(TCP_REPAIR_QUEUE),
	DESCRIBE_ENUM(TCP_QUEUE_SEQ),
	DESCRIBE_ENUM(TCP_REPAIR_OPTIONS),
	DESCRIBE_ENUM(TCP_FASTOPEN),
	DESCRIBE_ENUM(TCP_TIMESTAMP),
	DESCRIBE_ENUM(TCP_NOTSENT_LOWAT),
	DESCRIBE_ENUM(TCP_CC_INFO),
	DESCRIBE_ENUM(TCP_SAVE_SYN),
	DESCRIBE_ENUM(TCP_SAVED_SYN),
	DESCRIBE_ENUM(TCP_REPAIR_WINDOW),
	DESCRIBE_ENUM(TCP_FASTOPEN_CONNECT),
	DESCRIBE_ENUM(TCP_ULP),
	DESCRIBE_ENUM(TCP_MD5SIG_EXT),
	DESCRIBE_ENUM(TCP_FASTOPEN_KEY),
	DESCRIBE_ENUM(TCP_FASTOPEN_NO_COOKIE),
	DESCRIBE_ENUM(TCP_ZEROCOPY_RECEIVE),
	DESCRIBE_ENUM(TCP_INQ),
	DESCRIBE_ENUM(TCP_TX_DELAY),
};

static struct enum_option socket_options_ip[] = {
	DESCRIBE_ENUM(IP_RECVERR),
	DESCRIBE_ENUM(IP_TOS),
	DESCRIBE_ENUM(IP_TTL),
	DESCRIBE_ENUM(IP_HDRINCL),
	DESCRIBE_ENUM(IP_OPTIONS),
	DESCRIBE_ENUM(IP_ROUTER_ALERT),
	DESCRIBE_ENUM(IP_RECVOPTS),
	DESCRIBE_ENUM(IP_RETOPTS),
	DESCRIBE_ENUM(IP_PKTINFO),
	DESCRIBE_ENUM(IP_PKTOPTIONS),
	DESCRIBE_ENUM(IP_MTU_DISCOVER),
	DESCRIBE_ENUM(IP_RECVERR),
	DESCRIBE_ENUM(IP_RECVTTL),
	DESCRIBE_ENUM(IP_RECVTOS),
	DESCRIBE_ENUM(IP_MTU),
	DESCRIBE_ENUM(IP_FREEBIND),
	DESCRIBE_ENUM(IP_IPSEC_POLICY),
	DESCRIBE_ENUM(IP_XFRM_POLICY),
	DESCRIBE_ENUM(IP_PASSSEC),
	DESCRIBE_ENUM(IP_TRANSPARENT),
	DESCRIBE_ENUM(IP_ORIGDSTADDR),
	DESCRIBE_ENUM(IP_MINTTL),
	DESCRIBE_ENUM(IP_NODEFRAG),
	DESCRIBE_ENUM(IP_CHECKSUM),
	DESCRIBE_ENUM(IP_BIND_ADDRESS_NO_PORT),
	DESCRIBE_ENUM(IP_RECVFRAGSIZE),
	DESCRIBE_ENUM(IP_RECVERR_RFC4884),
	DESCRIBE_ENUM(IP_MULTICAST_IF),
	DESCRIBE_ENUM(IP_MULTICAST_TTL),
	DESCRIBE_ENUM(IP_MULTICAST_LOOP),
	DESCRIBE_ENUM(IP_ADD_MEMBERSHIP),
	DESCRIBE_ENUM(IP_DROP_MEMBERSHIP),
	DESCRIBE_ENUM(IP_UNBLOCK_SOURCE),
	DESCRIBE_ENUM(IP_BLOCK_SOURCE),
	DESCRIBE_ENUM(IP_ADD_SOURCE_MEMBERSHIP),
	DESCRIBE_ENUM(IP_DROP_SOURCE_MEMBERSHIP),
	DESCRIBE_ENUM(IP_MSFILTER),
	DESCRIBE_ENUM(MCAST_JOIN_GROUP),
	DESCRIBE_ENUM(MCAST_BLOCK_SOURCE),
	DESCRIBE_ENUM(MCAST_UNBLOCK_SOURCE),
	DESCRIBE_ENUM(MCAST_LEAVE_GROUP),
	DESCRIBE_ENUM(MCAST_JOIN_SOURCE_GROUP),
	DESCRIBE_ENUM(MCAST_LEAVE_SOURCE_GROUP),
	DESCRIBE_ENUM(MCAST_MSFILTER),
	DESCRIBE_ENUM(IP_MULTICAST_ALL),
	DESCRIBE_ENUM(IP_UNICAST_IF),
	DESCRIBE_ENUM(IP_LOCAL_PORT_RANGE),
	DESCRIBE_ENUM(IP_PROTOCOL),
	DESCRIBE_ENUM(IPT_SO_SET_REPLACE),
	DESCRIBE_ENUM(IPT_SO_SET_ADD_COUNTERS),
	DESCRIBE_ENUM(IPT_SO_GET_INFO),
	DESCRIBE_ENUM(IPT_SO_GET_ENTRIES),
	DESCRIBE_ENUM(IPT_SO_GET_REVISION_MATCH),
	DESCRIBE_ENUM(IPT_SO_GET_REVISION_TARGET),
};

static struct enum_option socket_options_ipv6[] = {
	DESCRIBE_ENUM(IPV6_ADDRFORM),
	DESCRIBE_ENUM(IPV6_2292PKTINFO),
	DESCRIBE_ENUM(IPV6_2292HOPOPTS),
	DESCRIBE_ENUM(IPV6_2292DSTOPTS),
	DESCRIBE_ENUM(IPV6_2292RTHDR),
	DESCRIBE_ENUM(IPV6_2292PKTOPTIONS),
	DESCRIBE_ENUM(IPV6_CHECKSUM),
	DESCRIBE_ENUM(IPV6_2292HOPLIMIT),
	DESCRIBE_ENUM(IPV6_NEXTHOP),
	DESCRIBE_ENUM(IPV6_AUTHHDR),
	DESCRIBE_ENUM(IPV6_FLOWINFO),
	DESCRIBE_ENUM(IPV6_UNICAST_HOPS),
	DESCRIBE_ENUM(IPV6_MULTICAST_IF),
	DESCRIBE_ENUM(IPV6_MULTICAST_HOPS),
	DESCRIBE_ENUM(IPV6_MULTICAST_LOOP),
	DESCRIBE_ENUM(IPV6_ADD_MEMBERSHIP),
	DESCRIBE_ENUM(IPV6_DROP_MEMBERSHIP),
	DESCRIBE_ENUM(IPV6_ROUTER_ALERT),
	DESCRIBE_ENUM(IPV6_MTU_DISCOVER),
	DESCRIBE_ENUM(IPV6_MTU),
	DESCRIBE_ENUM(IPV6_RECVERR),
	DESCRIBE_ENUM(IPV6_V6ONLY),
	DESCRIBE_ENUM(IPV6_JOIN_ANYCAST),
	DESCRIBE_ENUM(IPV6_LEAVE_ANYCAST),
	DESCRIBE_ENUM(IPV6_MULTICAST_ALL),
	DESCRIBE_ENUM(IPV6_ROUTER_ALERT_ISOLATE),
	DESCRIBE_ENUM(IPV6_RECVERR_RFC4884),
	DESCRIBE_ENUM(IPV6_FLOWLABEL_MGR),
	DESCRIBE_ENUM(IPV6_FLOWINFO_SEND),
	DESCRIBE_ENUM(IPV6_IPSEC_POLICY),
	DESCRIBE_ENUM(IPV6_XFRM_POLICY),
	DESCRIBE_ENUM(IPV6_HDRINCL),
	DESCRIBE_ENUM(MCAST_JOIN_GROUP),
	DESCRIBE_ENUM(MCAST_BLOCK_SOURCE),
	DESCRIBE_ENUM(MCAST_UNBLOCK_SOURCE),
	DESCRIBE_ENUM(MCAST_LEAVE_GROUP),
	DESCRIBE_ENUM(MCAST_JOIN_SOURCE_GROUP),
	DESCRIBE_ENUM(MCAST_LEAVE_SOURCE_GROUP),
	DESCRIBE_ENUM(MCAST_MSFILTER),
	DESCRIBE_ENUM(IPV6_RECVPKTINFO),
	DESCRIBE_ENUM(IPV6_PKTINFO),
	DESCRIBE_ENUM(IPV6_RECVHOPLIMIT),
	DESCRIBE_ENUM(IPV6_HOPLIMIT),
	DESCRIBE_ENUM(IPV6_RECVHOPOPTS),
	DESCRIBE_ENUM(IPV6_HOPOPTS),
	DESCRIBE_ENUM(IPV6_RTHDRDSTOPTS),
	DESCRIBE_ENUM(IPV6_RECVRTHDR),
	DESCRIBE_ENUM(IPV6_RTHDR),
	DESCRIBE_ENUM(IPV6_RECVDSTOPTS),
	DESCRIBE_ENUM(IPV6_DSTOPTS),
	DESCRIBE_ENUM(IPV6_RECVPATHMTU),
	DESCRIBE_ENUM(IPV6_PATHMTU),
	DESCRIBE_ENUM(IPV6_DONTFRAG),
	DESCRIBE_ENUM(IPV6_RECVTCLASS),
	DESCRIBE_ENUM(IPV6_TCLASS),
	DESCRIBE_ENUM(IP6T_SO_GET_REVISION_MATCH),
	DESCRIBE_ENUM(IP6T_SO_GET_REVISION_TARGET),
	DESCRIBE_ENUM(IP6T_SO_ORIGINAL_DST),
	DESCRIBE_ENUM(IPV6_AUTOFLOWLABEL),
	DESCRIBE_ENUM(IPV6_ADDR_PREFERENCES),
	DESCRIBE_ENUM(IPV6_MINHOPCOUNT),
	DESCRIBE_ENUM(IPV6_ORIGDSTADDR),
	DESCRIBE_ENUM(IPV6_TRANSPARENT),
	DESCRIBE_ENUM(IPV6_UNICAST_IF),
	DESCRIBE_ENUM(IPV6_RECVFRAGSIZE),
	DESCRIBE_ENUM(IPV6_FREEBIND),
	DESCRIBE_ENUM(IP6T_SO_SET_REPLACE),
	DESCRIBE_ENUM(IP6T_SO_SET_ADD_COUNTERS),
	DESCRIBE_ENUM(IP6T_SO_GET_INFO),
	DESCRIBE_ENUM(IP6T_SO_GET_ENTRIES),
	DESCRIBE_ENUM(IP6T_SO_GET_REVISION_MATCH),
	DESCRIBE_ENUM(IP6T_SO_GET_REVISION_TARGET),
	DESCRIBE_ENUM(IP6T_SO_ORIGINAL_DST),
};

static struct enum_option socket_options_tcp[] = {
	DESCRIBE_ENUM(TCP_NODELAY),
	DESCRIBE_ENUM(TCP_MAXSEG),
	DESCRIBE_ENUM(TCP_CORK),
	DESCRIBE_ENUM(TCP_KEEPIDLE),
	DESCRIBE_ENUM(TCP_KEEPINTVL),
	DESCRIBE_ENUM(TCP_KEEPCNT),
	DESCRIBE_ENUM(TCP_SYNCNT),
	DESCRIBE_ENUM(TCP_LINGER2),
	DESCRIBE_ENUM(TCP_DEFER_ACCEPT),
	DESCRIBE_ENUM(TCP_WINDOW_CLAMP),
	DESCRIBE_ENUM(TCP_INFO),
	DESCRIBE_ENUM(TCP_QUICKACK),
	DESCRIBE_ENUM(TCP_CONGESTION),
	DESCRIBE_ENUM(TCP_MD5SIG),
	DESCRIBE_ENUM(TCP_THIN_LINEAR_TIMEOUTS),
	DESCRIBE_ENUM(TCP_THIN_DUPACK),
	DESCRIBE_ENUM(TCP_USER_TIMEOUT),
	DESCRIBE_ENUM(TCP_REPAIR),
	DESCRIBE_ENUM(TCP_REPAIR_QUEUE),
	DESCRIBE_ENUM(TCP_QUEUE_SEQ),
	DESCRIBE_ENUM(TCP_REPAIR_OPTIONS),
	DESCRIBE_ENUM(TCP_FASTOPEN),
	DESCRIBE_ENUM(TCP_TIMESTAMP),
	DESCRIBE_ENUM(TCP_NOTSENT_LOWAT),
	DESCRIBE_ENUM(TCP_CC_INFO),
	DESCRIBE_ENUM(TCP_SAVE_SYN),
	DESCRIBE_ENUM(TCP_SAVED_SYN),
	DESCRIBE_ENUM(TCP_REPAIR_WINDOW),
	DESCRIBE_ENUM(TCP_FASTOPEN_CONNECT),
	DESCRIBE_ENUM(TCP_ULP),
	DESCRIBE_ENUM(TCP_MD5SIG_EXT),
	DESCRIBE_ENUM(TCP_FASTOPEN_KEY),
	DESCRIBE_ENUM(TCP_FASTOPEN_NO_COOKIE),
	DESCRIBE_ENUM(TCP_ZEROCOPY_RECEIVE),
	DESCRIBE_ENUM(TCP_INQ),
	DESCRIBE_ENUM(TCP_TX_DELAY),
};

static struct enum_option socket_options_tls[] = {
	DESCRIBE_ENUM(TLS_TX),
	DESCRIBE_ENUM(TLS_RX),
	DESCRIBE_ENUM(TLS_TX_ZEROCOPY_RO),
	DESCRIBE_ENUM(TLS_RX_EXPECT_NO_PAD),
};

static struct enum_option socket_options_alg[] = {
	DESCRIBE_ENUM(ALG_SET_KEY),
	DESCRIBE_ENUM(ALG_SET_IV),
	DESCRIBE_ENUM(ALG_SET_OP),
	DESCRIBE_ENUM(ALG_SET_AEAD_ASSOCLEN),
	DESCRIBE_ENUM(ALG_SET_AEAD_AUTHSIZE),
	DESCRIBE_ENUM(ALG_SET_DRBG_ENTROPY),
	DESCRIBE_ENUM(ALG_SET_KEY_BY_KEY_SERIAL),
};

static struct enum_option socket_options_netlink[] = {
	DESCRIBE_ENUM(NETLINK_ADD_MEMBERSHIP),
	DESCRIBE_ENUM(NETLINK_DROP_MEMBERSHIP),
	DESCRIBE_ENUM(NETLINK_PKTINFO),
	DESCRIBE_ENUM(NETLINK_BROADCAST_ERROR),
	DESCRIBE_ENUM(NETLINK_NO_ENOBUFS),
	DESCRIBE_ENUM(NETLINK_RX_RING),
	DESCRIBE_ENUM(NETLINK_TX_RING),
	DESCRIBE_ENUM(NETLINK_LISTEN_ALL_NSID),
	DESCRIBE_ENUM(NETLINK_LIST_MEMBERSHIPS),
	DESCRIBE_ENUM(NETLINK_CAP_ACK),
	DESCRIBE_ENUM(NETLINK_EXT_ACK),
	DESCRIBE_ENUM(NETLINK_GET_STRICT_CHK),
};

static struct enum_option socket_options_icmpv6[] = {
	DESCRIBE_ENUM(ICMPV6_FILTER),
};

#define MSG_PROBE 0x10
#define MSG_CMSG_COMPAT 0x80000000

static const char *msg_flags[64] = {
	DESCRIBE_FLAG(MSG_OOB),
	DESCRIBE_FLAG(MSG_PEEK),
	DESCRIBE_FLAG(MSG_DONTROUTE),
	DESCRIBE_FLAG(MSG_CTRUNC),
	DESCRIBE_FLAG(MSG_PROBE),
	DESCRIBE_FLAG(MSG_TRUNC),
	DESCRIBE_FLAG(MSG_DONTWAIT),
	DESCRIBE_FLAG(MSG_EOR),
	DESCRIBE_FLAG(MSG_WAITALL),
	DESCRIBE_FLAG(MSG_FIN),
	DESCRIBE_FLAG(MSG_SYN),
	DESCRIBE_FLAG(MSG_CONFIRM),
	DESCRIBE_FLAG(MSG_RST),
	DESCRIBE_FLAG(MSG_ERRQUEUE),
	DESCRIBE_FLAG(MSG_NOSIGNAL),
	DESCRIBE_FLAG(MSG_MORE),
	DESCRIBE_FLAG(MSG_WAITFORONE),
	// DESCRIBE_FLAG(MSG_SENDPAGE_NOPOLICY),
	DESCRIBE_FLAG(MSG_BATCH),
	// DESCRIBE_FLAG(MSG_NO_SHARED_FRAGS),
    // DESCRIBE_FLAG(MSG_SENDPAGE_DECRYPTED),
	DESCRIBE_FLAG(MSG_ZEROCOPY),
	// DESCRIBE_FLAG(MSG_SPLICE_PAGES),
	DESCRIBE_FLAG(MSG_FASTOPEN),
	DESCRIBE_FLAG(MSG_CMSG_CLOEXEC),
	DESCRIBE_FLAG(MSG_CMSG_COMPAT),
};

static struct enum_option futex_operations[] = {
	DESCRIBE_ENUM(FUTEX_WAIT),
	DESCRIBE_ENUM(FUTEX_WAKE),
	DESCRIBE_ENUM(FUTEX_REQUEUE),
	DESCRIBE_ENUM(FUTEX_CMP_REQUEUE),
	DESCRIBE_ENUM(FUTEX_WAKE_OP),
	DESCRIBE_ENUM(FUTEX_WAIT_BITSET),
	DESCRIBE_ENUM(FUTEX_WAKE_BITSET),
	DESCRIBE_ENUM(FUTEX_LOCK_PI),
	DESCRIBE_ENUM(FUTEX_TRYLOCK_PI),
	DESCRIBE_ENUM(FUTEX_UNLOCK_PI),
	DESCRIBE_ENUM(FUTEX_CMP_REQUEUE_PI),
	DESCRIBE_ENUM(FUTEX_WAIT_REQUEUE_PI),
};

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static struct enum_option wait_idtypes[] = {
	DESCRIBE_ENUM(P_PID),
	DESCRIBE_ENUM(P_PIDFD),
	DESCRIBE_ENUM(P_PGID),
	DESCRIBE_ENUM(P_ALL),
};

static struct enum_option seccomp_operations[] = {
	DESCRIBE_ENUM(SECCOMP_SET_MODE_STRICT),
	DESCRIBE_ENUM(SECCOMP_SET_MODE_FILTER),
	DESCRIBE_ENUM(SECCOMP_GET_ACTION_AVAIL),
};

// hack to support old version of ubuntu in GitHub Actions
enum
{
	BPF_TOKEN_CREATE_ = BPF_PROG_BIND_MAP + 1,
};
#define BPF_TOKEN_CREATE BPF_TOKEN_CREATE_

static struct enum_option bpf_commands[] = {
	DESCRIBE_ENUM(BPF_MAP_CREATE),
	DESCRIBE_ENUM(BPF_MAP_LOOKUP_ELEM),
	DESCRIBE_ENUM(BPF_MAP_UPDATE_ELEM),
	DESCRIBE_ENUM(BPF_MAP_DELETE_ELEM),
	DESCRIBE_ENUM(BPF_MAP_GET_NEXT_KEY),
	DESCRIBE_ENUM(BPF_PROG_LOAD),
	DESCRIBE_ENUM(BPF_OBJ_PIN),
	DESCRIBE_ENUM(BPF_OBJ_GET),
	DESCRIBE_ENUM(BPF_PROG_ATTACH),
	DESCRIBE_ENUM(BPF_PROG_DETACH),
	DESCRIBE_ENUM(BPF_PROG_TEST_RUN),
	DESCRIBE_ENUM(BPF_PROG_GET_NEXT_ID),
	DESCRIBE_ENUM(BPF_MAP_GET_NEXT_ID),
	DESCRIBE_ENUM(BPF_PROG_GET_FD_BY_ID),
	DESCRIBE_ENUM(BPF_MAP_GET_FD_BY_ID),
	DESCRIBE_ENUM(BPF_OBJ_GET_INFO_BY_FD),
	DESCRIBE_ENUM(BPF_PROG_QUERY),
	DESCRIBE_ENUM(BPF_RAW_TRACEPOINT_OPEN),
	DESCRIBE_ENUM(BPF_BTF_LOAD),
	DESCRIBE_ENUM(BPF_BTF_GET_FD_BY_ID),
	DESCRIBE_ENUM(BPF_TASK_FD_QUERY),
	DESCRIBE_ENUM(BPF_MAP_LOOKUP_AND_DELETE_ELEM),
	DESCRIBE_ENUM(BPF_MAP_FREEZE),
	DESCRIBE_ENUM(BPF_BTF_GET_NEXT_ID),
	DESCRIBE_ENUM(BPF_MAP_LOOKUP_BATCH),
	DESCRIBE_ENUM(BPF_MAP_LOOKUP_AND_DELETE_BATCH),
	DESCRIBE_ENUM(BPF_MAP_UPDATE_BATCH),
	DESCRIBE_ENUM(BPF_MAP_DELETE_BATCH),
	DESCRIBE_ENUM(BPF_LINK_CREATE),
	DESCRIBE_ENUM(BPF_LINK_UPDATE),
	DESCRIBE_ENUM(BPF_LINK_GET_FD_BY_ID),
	DESCRIBE_ENUM(BPF_LINK_GET_NEXT_ID),
	DESCRIBE_ENUM(BPF_ENABLE_STATS),
	DESCRIBE_ENUM(BPF_ITER_CREATE),
	DESCRIBE_ENUM(BPF_LINK_DETACH),
	DESCRIBE_ENUM(BPF_PROG_BIND_MAP),
	DESCRIBE_ENUM(BPF_TOKEN_CREATE),
};

static struct enum_option membarrier_commands[] = {
	DESCRIBE_ENUM(MEMBARRIER_CMD_QUERY),
	DESCRIBE_ENUM(MEMBARRIER_CMD_GLOBAL),
	DESCRIBE_ENUM(MEMBARRIER_CMD_GLOBAL_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_PRIVATE_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE),
	DESCRIBE_ENUM(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE),
};

static const char *futex_flags[64] = {
	DESCRIBE_FLAG(FUTEX_PRIVATE_FLAG),
	DESCRIBE_FLAG(FUTEX_CLOCK_REALTIME),
};

static const char *signalfd_flags[64] = {
	DESCRIBE_FLAG(SFD_NONBLOCK),
	DESCRIBE_FLAG(SFD_CLOEXEC),
};

static const char *timerfd_flags[64] = {
	DESCRIBE_FLAG(TFD_NONBLOCK),
	DESCRIBE_FLAG(TFD_CLOEXEC),
};

static struct enum_option prctls[] = {
	DESCRIBE_ENUM(PR_CAP_AMBIENT),
	DESCRIBE_ENUM(PR_CAPBSET_READ),
	DESCRIBE_ENUM(PR_CAPBSET_DROP),
	DESCRIBE_ENUM(PR_SET_CHILD_SUBREAPER),
	DESCRIBE_ENUM(PR_GET_CHILD_SUBREAPER),
	DESCRIBE_ENUM(PR_SET_DUMPABLE),
	DESCRIBE_ENUM(PR_GET_DUMPABLE),
	// DESCRIBE_ENUM(PR_SET_IO_FLUSHER),
    // DESCRIBE_ENUM(PR_GET_IO_FLUSHER),
	DESCRIBE_ENUM(PR_SET_KEEPCAPS),
	DESCRIBE_ENUM(PR_GET_KEEPCAPS),
	DESCRIBE_ENUM(PR_MCE_KILL),
	DESCRIBE_ENUM(PR_MCE_KILL_GET),
	DESCRIBE_ENUM(PR_SET_MM),
	// DESCRIBE_ENUM(PR_SET_VMA),
	DESCRIBE_ENUM(PR_SET_NAME),
	DESCRIBE_ENUM(PR_GET_NAME),
	DESCRIBE_ENUM(PR_SET_NO_NEW_PRIVS),
	DESCRIBE_ENUM(PR_GET_NO_NEW_PRIVS),
	DESCRIBE_ENUM(PR_SET_PDEATHSIG),
	DESCRIBE_ENUM(PR_GET_PDEATHSIG),
	DESCRIBE_ENUM(PR_SET_PTRACER),
	DESCRIBE_ENUM(PR_SET_SECCOMP),
	DESCRIBE_ENUM(PR_GET_SECCOMP),
	DESCRIBE_ENUM(PR_SET_SECUREBITS),
	DESCRIBE_ENUM(PR_GET_SECUREBITS),
	DESCRIBE_ENUM(PR_GET_SPECULATION_CTRL),
	DESCRIBE_ENUM(PR_SET_SPECULATION_CTRL),
	// DESCRIBE_ENUM(PR_SET_SYSCALL_USER_DISPATCH),
	DESCRIBE_ENUM(PR_TASK_PERF_EVENTS_DISABLE),
	DESCRIBE_ENUM(PR_TASK_PERF_EVENTS_ENABLE),
	DESCRIBE_ENUM(PR_SET_THP_DISABLE),
	DESCRIBE_ENUM(PR_GET_THP_DISABLE),
	DESCRIBE_ENUM(PR_GET_TID_ADDRESS),
	DESCRIBE_ENUM(PR_SET_TIMERSLACK),
	DESCRIBE_ENUM(PR_GET_TIMERSLACK),
	DESCRIBE_ENUM(PR_SET_TIMING),
	DESCRIBE_ENUM(PR_GET_TIMING),
	DESCRIBE_ENUM(PR_SET_TSC),
	DESCRIBE_ENUM(PR_GET_TSC),
#ifdef __aarch64__
	DESCRIBE_ENUM(PR_SET_TAGGED_ADDR_CTRL),
	DESCRIBE_ENUM(PR_GET_TAGGED_ADDR_CTRL),
	DESCRIBE_ENUM(PR_PAC_RESET_KEYS),
	DESCRIBE_ENUM(PR_SVE_SET_VL),
	DESCRIBE_ENUM(PR_SVE_GET_VL),
#endif
	DESCRIBE_ENUM(PR_SET_VMA),
};

static struct enum_option set_mm_ops[] = {
	DESCRIBE_ENUM(PR_SET_MM_START_CODE),
	DESCRIBE_ENUM(PR_SET_MM_END_CODE),
	DESCRIBE_ENUM(PR_SET_MM_START_DATA),
	DESCRIBE_ENUM(PR_SET_MM_END_DATA),
	DESCRIBE_ENUM(PR_SET_MM_START_STACK),
	DESCRIBE_ENUM(PR_SET_MM_START_BRK),
	DESCRIBE_ENUM(PR_SET_MM_BRK),
	DESCRIBE_ENUM(PR_SET_MM_ARG_START),
	DESCRIBE_ENUM(PR_SET_MM_ARG_END),
	DESCRIBE_ENUM(PR_SET_MM_ENV_START),
	DESCRIBE_ENUM(PR_SET_MM_ENV_END),
	DESCRIBE_ENUM(PR_SET_MM_AUXV),
	DESCRIBE_ENUM(PR_SET_MM_EXE_FILE),
	DESCRIBE_ENUM(PR_SET_MM_MAP),
	DESCRIBE_ENUM(PR_SET_MM_MAP_SIZE),
};

static struct enum_option cap_ambient_ops[] = {
	DESCRIBE_ENUM(PR_CAP_AMBIENT_RAISE),
	DESCRIBE_ENUM(PR_CAP_AMBIENT_LOWER),
	DESCRIBE_ENUM(PR_CAP_AMBIENT_IS_SET),
	DESCRIBE_ENUM(PR_CAP_AMBIENT_CLEAR_ALL),
};

static struct enum_option flock_operations[] = {
	DESCRIBE_ENUM(LOCK_SH),
	DESCRIBE_ENUM(LOCK_EX),
	DESCRIBE_ENUM(LOCK_UN),
	DESCRIBE_ENUM(LOCK_MAND),
};

static const char *flock_flags[64] = {
	DESCRIBE_FLAG(LOCK_NB),
	DESCRIBE_FLAG(LOCK_READ),
	DESCRIBE_FLAG(LOCK_WRITE),
};

static struct enum_option itimer_whiches[] = {
	DESCRIBE_ENUM(ITIMER_REAL),
	DESCRIBE_ENUM(ITIMER_VIRTUAL),
	DESCRIBE_ENUM(ITIMER_PROF),
};

static struct enum_option seek_whences[] = {
	DESCRIBE_ENUM(SEEK_SET),
	DESCRIBE_ENUM(SEEK_CUR),
	DESCRIBE_ENUM(SEEK_END),
	DESCRIBE_ENUM(SEEK_DATA),
	DESCRIBE_ENUM(SEEK_HOLE),
};

static struct enum_option shmctl_commands[] = {
	DESCRIBE_ENUM(IPC_STAT),
	DESCRIBE_ENUM(IPC_SET),
	DESCRIBE_ENUM(IPC_RMID),
	DESCRIBE_ENUM(IPC_INFO),
	DESCRIBE_ENUM(SHM_INFO),
	DESCRIBE_ENUM(SHM_STAT),
	DESCRIBE_ENUM(SHM_STAT_ANY),
	DESCRIBE_ENUM(SHM_LOCK),
	DESCRIBE_ENUM(SHM_UNLOCK),
};

static struct enum_option semctl_commands[] = {
	DESCRIBE_ENUM(IPC_STAT),
	DESCRIBE_ENUM(IPC_SET),
	DESCRIBE_ENUM(IPC_RMID),
	DESCRIBE_ENUM(IPC_INFO),
	DESCRIBE_ENUM(SEM_INFO),
	DESCRIBE_ENUM(SEM_STAT),
	DESCRIBE_ENUM(SEM_STAT_ANY),
	DESCRIBE_ENUM(GETALL),
	DESCRIBE_ENUM(GETNCNT),
	DESCRIBE_ENUM(GETPID),
	DESCRIBE_ENUM(GETVAL),
	DESCRIBE_ENUM(GETZCNT),
	DESCRIBE_ENUM(SETALL),
	DESCRIBE_ENUM(SETVAL),
};

static struct enum_option ptrace_requests[] = {
	DESCRIBE_ENUM(PTRACE_TRACEME),
	DESCRIBE_ENUM(PTRACE_PEEKTEXT),
	DESCRIBE_ENUM(PTRACE_PEEKDATA),
	DESCRIBE_ENUM(PTRACE_PEEKUSER),
	DESCRIBE_ENUM(PTRACE_POKETEXT),
	DESCRIBE_ENUM(PTRACE_POKEDATA),
	DESCRIBE_ENUM(PTRACE_POKEUSER),
#ifdef __x86_64__
	DESCRIBE_ENUM(PTRACE_GETREGS),
	DESCRIBE_ENUM(PTRACE_GETFPREGS),
#endif
	DESCRIBE_ENUM(PTRACE_GETREGSET),
#ifdef __x86_64__
	DESCRIBE_ENUM(PTRACE_SETREGS),
	DESCRIBE_ENUM(PTRACE_SETFPREGS),
#endif
	DESCRIBE_ENUM(PTRACE_SETREGSET),
	DESCRIBE_ENUM(PTRACE_GETSIGINFO),
	DESCRIBE_ENUM(PTRACE_SETSIGINFO),
	DESCRIBE_ENUM(PTRACE_PEEKSIGINFO),
	DESCRIBE_ENUM(PTRACE_GETSIGMASK),
	DESCRIBE_ENUM(PTRACE_SETSIGMASK),
	DESCRIBE_ENUM(PTRACE_SETOPTIONS),
	DESCRIBE_ENUM(PTRACE_GETEVENTMSG),
	DESCRIBE_ENUM(PTRACE_CONT),
	DESCRIBE_ENUM(PTRACE_SYSCALL),
	DESCRIBE_ENUM(PTRACE_SINGLESTEP),
#ifdef __x86_64__
	DESCRIBE_ENUM(PTRACE_SYSEMU),
	DESCRIBE_ENUM(PTRACE_SYSEMU_SINGLESTEP),
#endif
	DESCRIBE_ENUM(PTRACE_LISTEN),
	DESCRIBE_ENUM(PTRACE_KILL),
	DESCRIBE_ENUM(PTRACE_INTERRUPT),
	DESCRIBE_ENUM(PTRACE_ATTACH),
	DESCRIBE_ENUM(PTRACE_SEIZE),
	DESCRIBE_ENUM(PTRACE_SECCOMP_GET_FILTER),
	DESCRIBE_ENUM(PTRACE_DETACH),
#ifdef __x86_64__
	DESCRIBE_ENUM(PTRACE_GET_THREAD_AREA),
	DESCRIBE_ENUM(PTRACE_SET_THREAD_AREA),
#endif
	DESCRIBE_ENUM(PTRACE_GET_SYSCALL_INFO),
#ifdef __aarch64__
	DESCRIBE_ENUM(PTRACE_PEEKMTETAGS),
	DESCRIBE_ENUM(PTRACE_POKEMTETAGS),
#define COMPAT_PTRACE_SET_SYSCALL 23
	DESCRIBE_ENUM(COMPAT_PTRACE_SET_SYSCALL),
#endif
};

static struct enum_option keyctl_ops[] = {
	DESCRIBE_ENUM(KEYCTL_GET_KEYRING_ID),
	DESCRIBE_ENUM(KEYCTL_JOIN_SESSION_KEYRING),
	DESCRIBE_ENUM(KEYCTL_UPDATE),
	DESCRIBE_ENUM(KEYCTL_REVOKE),
	DESCRIBE_ENUM(KEYCTL_CHOWN),
	DESCRIBE_ENUM(KEYCTL_SETPERM),
	DESCRIBE_ENUM(KEYCTL_DESCRIBE),
	DESCRIBE_ENUM(KEYCTL_CLEAR),
	DESCRIBE_ENUM(KEYCTL_LINK),
	DESCRIBE_ENUM(KEYCTL_UNLINK),
	DESCRIBE_ENUM(KEYCTL_SEARCH),
	DESCRIBE_ENUM(KEYCTL_READ),
	DESCRIBE_ENUM(KEYCTL_INSTANTIATE),
	DESCRIBE_ENUM(KEYCTL_INSTANTIATE_IOV),
	DESCRIBE_ENUM(KEYCTL_NEGATE),
	DESCRIBE_ENUM(KEYCTL_REJECT),
	DESCRIBE_ENUM(KEYCTL_SET_REQKEY_KEYRING),
	DESCRIBE_ENUM(KEYCTL_SET_TIMEOUT),
	DESCRIBE_ENUM(KEYCTL_ASSUME_AUTHORITY),
	DESCRIBE_ENUM(KEYCTL_GET_SECURITY),
	DESCRIBE_ENUM(KEYCTL_SESSION_TO_PARENT),
	DESCRIBE_ENUM(KEYCTL_INVALIDATE),
	DESCRIBE_ENUM(KEYCTL_GET_PERSISTENT),
	DESCRIBE_ENUM(KEYCTL_DH_COMPUTE),
	DESCRIBE_ENUM(KEYCTL_RESTRICT_KEYRING),
};

static struct enum_option personas[] = {
	{.description = "PER_SVR4", .value = PER_SVR4 & PER_MASK},
	{.description = "PER_SVR3", .value = PER_SVR3 & PER_MASK},
	{.description = "PER_OSR5", .value = PER_OSR5 & PER_MASK},
	{.description = "PER_WYSEV386", .value = PER_WYSEV386 & PER_MASK},
	{.description = "PER_ISCR4", .value = PER_ISCR4 & PER_MASK},
	{.description = "PER_BSD", .value = PER_BSD & PER_MASK},
	{.description = "PER_XENIX", .value = PER_XENIX & PER_MASK},
	{.description = "PER_LINUX32", .value = PER_LINUX32 & PER_MASK},
	{.description = "PER_IRIX32", .value = PER_IRIX32 & PER_MASK},
	{.description = "PER_IRIXN32", .value = PER_IRIXN32 & PER_MASK},
	{.description = "PER_IRIX64", .value = PER_IRIX64 & PER_MASK},
	{.description = "PER_RISCOS", .value = PER_RISCOS & PER_MASK},
	{.description = "PER_SOLARIS", .value = PER_SOLARIS & PER_MASK},
	{.description = "PER_UW7", .value = PER_UW7 & PER_MASK},
	{.description = "PER_OSF4", .value = PER_OSF4 & PER_MASK},
	{.description = "PER_HPUX", .value = PER_HPUX & PER_MASK},
};

#ifndef SYSLOG_ACTION_CLOSE
#define SYSLOG_ACTION_CLOSE 0
#define SYSLOG_ACTION_OPEN 1
#define SYSLOG_ACTION_READ 2
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_READ_CLEAR 4
#define SYSLOG_ACTION_CLEAR 5
#define SYSLOG_ACTION_CONSOLE_OFF 6
#define SYSLOG_ACTION_CONSOLE_ON 7
#define SYSLOG_ACTION_CONSOLE_LEVEL 8
#define SYSLOG_ACTION_SIZE_UNREAD 9
#define SYSLOG_ACTION_SIZE_BUFFER 10
#endif

static struct enum_option syslog_actions[] = {
	DESCRIBE_ENUM(SYSLOG_ACTION_CLOSE),
	DESCRIBE_ENUM(SYSLOG_ACTION_OPEN),
	DESCRIBE_ENUM(SYSLOG_ACTION_READ),
	DESCRIBE_ENUM(SYSLOG_ACTION_READ_ALL),
	DESCRIBE_ENUM(SYSLOG_ACTION_READ_CLEAR),
	DESCRIBE_ENUM(SYSLOG_ACTION_CLEAR),
	DESCRIBE_ENUM(SYSLOG_ACTION_CONSOLE_OFF),
	DESCRIBE_ENUM(SYSLOG_ACTION_CONSOLE_ON),
	DESCRIBE_ENUM(SYSLOG_ACTION_CONSOLE_LEVEL),
	DESCRIBE_ENUM(SYSLOG_ACTION_SIZE_UNREAD),
	DESCRIBE_ENUM(SYSLOG_ACTION_SIZE_BUFFER),
};

static const char *clone_flags[64] = {
	DESCRIBE_FLAG(CLONE_CHILD_CLEARTID),
	DESCRIBE_FLAG(CLONE_CHILD_SETTID),
	// DESCRIBE_FLAG(CLONE_CLEAR_SIGHAND), // clone3 only
	DESCRIBE_FLAG(CLONE_FILES),
	DESCRIBE_FLAG(CLONE_FS),
	DESCRIBE_FLAG(CLONE_IO),
	DESCRIBE_FLAG(CLONE_NEWCGROUP),
	DESCRIBE_FLAG(CLONE_NEWIPC),
	DESCRIBE_FLAG(CLONE_NEWNET),
	DESCRIBE_FLAG(CLONE_NEWNS),
	DESCRIBE_FLAG(CLONE_NEWPID),
	DESCRIBE_FLAG(CLONE_NEWUSER),
	DESCRIBE_FLAG(CLONE_NEWUTS),
	DESCRIBE_FLAG(CLONE_PARENT),
	DESCRIBE_FLAG(CLONE_PARENT_SETTID),
	DESCRIBE_FLAG(CLONE_PIDFD),
	DESCRIBE_FLAG(CLONE_PTRACE),
	DESCRIBE_FLAG(CLONE_SETTLS),
	DESCRIBE_FLAG(CLONE_SIGHAND),
	DESCRIBE_FLAG(CLONE_SYSVSEM),
	DESCRIBE_FLAG(CLONE_THREAD),
	DESCRIBE_FLAG(CLONE_UNTRACED),
	DESCRIBE_FLAG(CLONE_VFORK),
	DESCRIBE_FLAG(CLONE_VM),
	DESCRIBE_FLAG(CLONE_DETACHED),
};

#define CLONE_NEWTIME 0x00000080

static const char *unshare_flags[64] = {
	DESCRIBE_FLAG(CLONE_CHILD_CLEARTID),
	DESCRIBE_FLAG(CLONE_CHILD_SETTID),
	// DESCRIBE_FLAG(CLONE_CLEAR_SIGHAND), // clone3 only
	DESCRIBE_FLAG(CLONE_FILES),
	DESCRIBE_FLAG(CLONE_FS),
	DESCRIBE_FLAG(CLONE_IO),
	DESCRIBE_FLAG(CLONE_NEWCGROUP),
	DESCRIBE_FLAG(CLONE_NEWIPC),
	DESCRIBE_FLAG(CLONE_NEWNET),
	DESCRIBE_FLAG(CLONE_NEWNS),
	DESCRIBE_FLAG(CLONE_NEWPID),
	DESCRIBE_FLAG(CLONE_NEWUSER),
	DESCRIBE_FLAG(CLONE_NEWUTS),
	DESCRIBE_FLAG(CLONE_NEWTIME),
	DESCRIBE_FLAG(CLONE_PARENT),
	DESCRIBE_FLAG(CLONE_PARENT_SETTID),
	DESCRIBE_FLAG(CLONE_PIDFD),
	DESCRIBE_FLAG(CLONE_PTRACE),
	DESCRIBE_FLAG(CLONE_SETTLS),
	DESCRIBE_FLAG(CLONE_SIGHAND),
	DESCRIBE_FLAG(CLONE_SYSVSEM),
	DESCRIBE_FLAG(CLONE_THREAD),
	DESCRIBE_FLAG(CLONE_UNTRACED),
	DESCRIBE_FLAG(CLONE_VFORK),
	DESCRIBE_FLAG(CLONE_VM),
	DESCRIBE_FLAG(CLONE_DETACHED),
};

// #define SHM_HUGE_64KB	HUGETLB_FLAG_ENCODE_64KB
// #define SHM_HUGE_512KB	HUGETLB_FLAG_ENCODE_512KB
// #define SHM_HUGE_1MB	HUGETLB_FLAG_ENCODE_1MB
// #define SHM_HUGE_2MB	HUGETLB_FLAG_ENCODE_2MB
// #define SHM_HUGE_8MB	HUGETLB_FLAG_ENCODE_8MB
// #define SHM_HUGE_16MB	HUGETLB_FLAG_ENCODE_16MB
// #define SHM_HUGE_32MB	HUGETLB_FLAG_ENCODE_32MB
// #define SHM_HUGE_256MB	HUGETLB_FLAG_ENCODE_256MB
// #define SHM_HUGE_512MB	HUGETLB_FLAG_ENCODE_512MB
// #define SHM_HUGE_1GB	HUGETLB_FLAG_ENCODE_1GB
// #define SHM_HUGE_2GB	HUGETLB_FLAG_ENCODE_2GB
// #define SHM_HUGE_16GB	HUGETLB_FLAG_ENCODE_16GB

static const char *shm_flags[64] = {
	DESCRIBE_FLAG(IPC_CREAT),
	DESCRIBE_FLAG(IPC_EXCL),
	DESCRIBE_FLAG(SHM_HUGETLB),
	// DESCRIBE_FLAG(SHM_HUGE_2MB),
    // DESCRIBE_FLAG(SHM_HUGE_1GB),
	DESCRIBE_FLAG(SHM_R),
	DESCRIBE_FLAG(SHM_W),
	DESCRIBE_FLAG(SHM_NORESERVE),
};

static const char *sem_flags[64] = {
	DESCRIBE_FLAG(IPC_CREAT),
	DESCRIBE_FLAG(IPC_EXCL),
	DESCRIBE_FLAG(SEM_UNDO),
};

static const char *eventfd_flags[64] = {
	DESCRIBE_FLAG(EFD_CLOEXEC),
	DESCRIBE_FLAG(EFD_NONBLOCK),
	DESCRIBE_FLAG(EFD_SEMAPHORE),
};

static const char *epoll_flags[64] = {
	DESCRIBE_FLAG(EPOLL_CLOEXEC),
};

static const char *xattr_flags[64] = {
	DESCRIBE_FLAG(XATTR_CREATE),
	DESCRIBE_FLAG(XATTR_REPLACE),
};

static const char *timer_flags[64] = {
	DESCRIBE_FLAG(TIMER_ABSTIME),
};

static const char *wait_flags[64] = {
	DESCRIBE_FLAG(WNOHANG),
	DESCRIBE_FLAG(WUNTRACED),
	DESCRIBE_FLAG(WCONTINUED),
	DESCRIBE_FLAG(WEXITED),
	DESCRIBE_FLAG(WNOWAIT),
	DESCRIBE_FLAG(__WNOTHREAD),
	DESCRIBE_FLAG(__WALL),
	DESCRIBE_FLAG(__WCLONE),
};

static const char *inotify_event_flags[64] = {
	DESCRIBE_FLAG(IN_ACCESS),
	DESCRIBE_FLAG(IN_ATTRIB),
	DESCRIBE_FLAG(IN_CLOSE_WRITE),
	DESCRIBE_FLAG(IN_CLOSE_NOWRITE),
	DESCRIBE_FLAG(IN_CREATE),
	DESCRIBE_FLAG(IN_DELETE),
	DESCRIBE_FLAG(IN_DELETE_SELF),
	DESCRIBE_FLAG(IN_MODIFY),
	DESCRIBE_FLAG(IN_MOVE_SELF),
	DESCRIBE_FLAG(IN_MOVED_FROM),
	DESCRIBE_FLAG(IN_MOVED_TO),
	DESCRIBE_FLAG(IN_OPEN),
	DESCRIBE_FLAG(IN_DONT_FOLLOW),
	DESCRIBE_FLAG(IN_EXCL_UNLINK),
	DESCRIBE_FLAG(IN_MASK_ADD),
	DESCRIBE_FLAG(IN_ONESHOT),
	DESCRIBE_FLAG(IN_ONLYDIR),
	DESCRIBE_FLAG(IN_MASK_CREATE),
	DESCRIBE_FLAG(IN_IGNORED),
	DESCRIBE_FLAG(IN_ISDIR),
	DESCRIBE_FLAG(IN_Q_OVERFLOW),
	DESCRIBE_FLAG(IN_UNMOUNT),
};

static const char *inotify_init_flags[64] = {
	DESCRIBE_FLAG(IN_NONBLOCK),
	DESCRIBE_FLAG(IN_CLOEXEC),
};

static const char *memfd_flags[64] = {
	DESCRIBE_FLAG(MFD_CLOEXEC), DESCRIBE_FLAG(MFD_ALLOW_SEALING), DESCRIBE_FLAG(MFD_HUGETLB), DESCRIBE_FLAG(MFD_NOEXEC_SEAL), DESCRIBE_FLAG(MFD_EXEC),
	// DESCRIBE_FLAG(MFD_HUGE_2MB),
    // DESCRIBE_FLAG(MFD_HUGE_1GB),
};

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif

static const char *userfaultfd_flags[64] = {
	DESCRIBE_FLAG(O_CLOEXEC),
	DESCRIBE_FLAG(O_NONBLOCK),
	DESCRIBE_FLAG(UFFD_USER_MODE_ONLY),
};

static const char *mlockall_flags[64] = {
	DESCRIBE_FLAG(MCL_CURRENT),
	DESCRIBE_FLAG(MCL_FUTURE),
};

static const char *umount_flags[64] = {
	DESCRIBE_FLAG(MNT_FORCE),
	DESCRIBE_FLAG(MNT_DETACH),
	DESCRIBE_FLAG(MNT_EXPIRE),
	DESCRIBE_FLAG(UMOUNT_NOFOLLOW),
};

static const char *swap_flags[64] = {
	DESCRIBE_FLAG(SWAP_FLAG_DISCARD),
};

static const char *splice_flags[64] = {
	DESCRIBE_FLAG(SPLICE_F_MOVE),
	DESCRIBE_FLAG(SPLICE_F_NONBLOCK),
	DESCRIBE_FLAG(SPLICE_F_MORE),
	DESCRIBE_FLAG(SPLICE_F_GIFT),
};

static const char *sync_file_range_flags[64] = {
	DESCRIBE_FLAG(SYNC_FILE_RANGE_WAIT_BEFORE),
	DESCRIBE_FLAG(SYNC_FILE_RANGE_WRITE),
	DESCRIBE_FLAG(SYNC_FILE_RANGE_WAIT_AFTER),
};

static const char *timerfd_settime_flags[64] = {
	DESCRIBE_FLAG(TFD_TIMER_ABSTIME),
	DESCRIBE_FLAG(TFD_TIMER_CANCEL_ON_SET),
};

static const char *perf_event_open_flags[64] = {
	DESCRIBE_FLAG(PERF_FLAG_FD_CLOEXEC),
	DESCRIBE_FLAG(PERF_FLAG_FD_NO_GROUP),
	DESCRIBE_FLAG(PERF_FLAG_FD_OUTPUT),
	DESCRIBE_FLAG(PERF_FLAG_PID_CGROUP),
};

static const char *module_init_flags[64] = {
	DESCRIBE_FLAG(MODULE_INIT_IGNORE_MODVERSIONS),
	DESCRIBE_FLAG(MODULE_INIT_IGNORE_VERMAGIC),
};

#ifndef GRND_INSECURE
#define GRND_INSECURE 0x4
#endif

static const char *getrandom_flags[64] = {
	DESCRIBE_FLAG(GRND_RANDOM),
	DESCRIBE_FLAG(GRND_NONBLOCK),
	DESCRIBE_FLAG(GRND_INSECURE),
};

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif
#ifndef STATX_DIOALIGN
#define STATX_DIOALIGN 0x00002000U
#endif

static const char *statx_mask[64] = {
	DESCRIBE_FLAG(STATX_TYPE),
	DESCRIBE_FLAG(STATX_MODE),
	DESCRIBE_FLAG(STATX_NLINK),
	DESCRIBE_FLAG(STATX_UID),
	DESCRIBE_FLAG(STATX_GID),
	DESCRIBE_FLAG(STATX_ATIME),
	DESCRIBE_FLAG(STATX_MTIME),
	DESCRIBE_FLAG(STATX_CTIME),
	DESCRIBE_FLAG(STATX_INO),
	DESCRIBE_FLAG(STATX_SIZE),
	DESCRIBE_FLAG(STATX_BLOCKS),
	DESCRIBE_FLAG(STATX_BTIME),
	DESCRIBE_FLAG(STATX_MNT_ID),
	DESCRIBE_FLAG(STATX_DIOALIGN),
};

static const char *persona_flags[64] = {
	DESCRIBE_FLAG(ADDR_COMPAT_LAYOUT),
	DESCRIBE_FLAG(ADDR_NO_RANDOMIZE),
	DESCRIBE_FLAG(ADDR_LIMIT_32BIT),
	DESCRIBE_FLAG(ADDR_LIMIT_3GB),
	DESCRIBE_FLAG(FDPIC_FUNCPTRS),
	DESCRIBE_FLAG(MMAP_PAGE_ZERO),
	DESCRIBE_FLAG(READ_IMPLIES_EXEC),
	DESCRIBE_FLAG(SHORT_INODE),
	DESCRIBE_FLAG(STICKY_TIMEOUTS),
	DESCRIBE_FLAG(UNAME26),
	DESCRIBE_FLAG(WHOLE_SECONDS),
};

static const char *ptrace_option_flags[64] = {
	DESCRIBE_FLAG(PTRACE_O_EXITKILL),
	DESCRIBE_FLAG(PTRACE_O_TRACECLONE),
	DESCRIBE_FLAG(PTRACE_O_TRACEEXEC),
	DESCRIBE_FLAG(PTRACE_O_TRACEEXIT),
	DESCRIBE_FLAG(PTRACE_O_TRACEFORK),
	DESCRIBE_FLAG(PTRACE_O_TRACESYSGOOD),
	DESCRIBE_FLAG(PTRACE_O_TRACEVFORK),
	DESCRIBE_FLAG(PTRACE_O_TRACEVFORKDONE),
	DESCRIBE_FLAG(PTRACE_O_TRACESECCOMP),
	DESCRIBE_FLAG(PTRACE_O_SUSPEND_SECCOMP),
};

#endif

__attribute__((nonnull(1))) static char *copy_register_state_description_simple(const struct loader_context *context, struct register_state reg)
{
	if (register_is_exactly_known(&reg)) {
		return copy_address_details(context, (const void *)reg.value, false);
	}
	char *min = copy_address_details(context, (const void *)reg.value, false);
	size_t min_size = fs_strlen(min);
	char *max = copy_address_details(context, (const void *)reg.max, false);
	size_t max_size = fs_strlen(max);
	char *result = malloc(min_size + max_size + 2);
	fs_memcpy(result, min, min_size);
	result[min_size] = '-';
	fs_memcpy(&result[min_size + 1], max, max_size + 1);
	free(min);
	free(max);
	return result;
}

enum
{
	DESCRIBE_PRINT_ZERO_ENUMS = 0x1,
	DESCRIBE_AS_FILE_MODE = 0x2,
	DESCRIBE_AS_IOCTL = 0x4,
	DESCRIBE_IGNORE_UNKNOWN_FLAGS = 0x8,
};

typedef uint8_t description_format_options;

static inline size_t format_octal(uintptr_t value, char buffer[])
{
	buffer[0] = '0';
	if (value == 0) {
		buffer[1] = '\0';
		return 1;
	}
	size_t i = 1;
	while (value != 0) {
		buffer[i++] = "0123456789abcdef"[(unsigned char)value & 0x7];
		value = value >> 3;
	}
	buffer[i] = '\0';
	fs_reverse(&buffer[1], i - 1);
	return i + 1;
}

#ifdef __linux__

static void fill_ioctl_description(uintptr_t value, char buf[])
{
	uintptr_t nr = (value >> _IOC_NRSHIFT) & _IOC_TYPEMASK;
	uintptr_t type = (value >> _IOC_TYPESHIFT) & _IOC_TYPEMASK;
	uintptr_t size = (value >> _IOC_SIZESHIFT) & _IOC_SIZEMASK;
	uintptr_t dir = (value >> _IOC_DIRSHIFT) & _IOC_DIRMASK;
	int i = 0;
	buf[i++] = '_';
	buf[i++] = 'I';
	buf[i++] = 'O';
	if (dir & _IOC_WRITE) {
		buf[i++] = 'W';
	}
	if (dir & _IOC_READ) {
		buf[i++] = 'R';
	}
	buf[i++] = '(';
	if ((type >= 'A' && type <= 'Z') || (type >= 'a' && type <= 'z') || type == '!' || type == '$') {
		buf[i++] = '\'';
		buf[i++] = type;
		buf[i++] = '\'';
	} else {
		i += fs_utoah(type, &buf[i]);
	}
	buf[i++] = ',';
	i += fs_itoa((intptr_t)nr, &buf[i]);
	if (dir != 0 || size != 0) {
		buf[i++] = ',';
		i += fs_itoa((intptr_t)size, &buf[i]);
	}
	buf[i++] = ')';
	uintptr_t remaining = value & ~_IOC(dir, type, nr, size);
	if (remaining != 0) {
		buf[i++] = '|';
		i += fs_utoah(remaining, &buf[i]);
	}
	buf[i++] = '\0';
}

#endif

static char *copy_enum_flags_value_description(const struct loader_context *context, uintptr_t value, const struct enum_option *options, size_t sizeof_options, const char *flags[64], description_format_options description_options)
{
	char num_buf[128];
	if (flags == NULL) {
		uintptr_t compared_value = (description_options & DESCRIBE_AS_IOCTL) ? (value & 0xffffffff) : value;
		for (size_t i = 0; i < sizeof_options / sizeof(*options); i++) {
			if (compared_value == options[i].value) {
				return strdup(options[i].description);
			}
		}
		if (description_options & DESCRIBE_AS_FILE_MODE) {
			format_octal(value, num_buf);
			return strdup(num_buf);
		}
#ifdef __linux__
		if (description_options & DESCRIBE_AS_IOCTL) {
			fill_ioctl_description(value, num_buf);
			return strdup(num_buf);
		}
#endif
		return copy_address_details(context, (const void *)value, false);
	}
	// calculate length
	size_t length = 0;
	uintptr_t remaining = 0;
	{
		for_each_bit (value, bit, i) {
			if (flags[i] != NULL) {
				length += fs_strlen(flags[i]) + 1;
			} else {
				remaining |= bit;
			}
		}
	}
	const char *suffix = NULL;
	size_t suffix_len = 0;
	if (length == 0 || remaining != 0 || (description_options & DESCRIBE_PRINT_ZERO_ENUMS)) {
		for (size_t i = 0; i < sizeof_options / sizeof(*options); i++) {
			if (remaining == options[i].value) {
				suffix = options[i].description;
				suffix_len = fs_strlen(suffix);
				length += suffix_len + 1;
				break;
			}
		}
		if (description_options & DESCRIBE_IGNORE_UNKNOWN_FLAGS) {
			remaining = 0;
		}
		if (suffix == NULL && (length == 0 || remaining != 0)) {
			suffix = num_buf;
			suffix_len = (description_options & DESCRIBE_AS_FILE_MODE) ? format_octal(remaining, num_buf) : (remaining < 4096 ? fs_utoa(remaining, num_buf) : fs_utoah(remaining, num_buf));
			length += suffix_len + 1;
		}
	}
	// allocate buffer
	char *result = malloc(length);
	// fill buffer
	char *next = result;
	if (suffix_len != 0) {
		fs_memcpy(next, suffix, suffix_len);
		next[suffix_len] = '|';
		next += suffix_len + 1;
	}
	{
		for_each_bit (value, bit, i) {
			if (flags[i] != NULL) {
				next = fs_strcpy(next, flags[i]);
				*next++ = '|';
			}
		}
	}
	next--;
	*next = '\0';
	return result;
}

static char *copy_enum_flags_description(const struct loader_context *context, struct register_state state, const struct enum_option *options, size_t sizeof_options, const char *flags[64], description_format_options description_options)
{
	if (register_is_exactly_known(&state)) {
		return copy_enum_flags_value_description(context, state.value, options, sizeof_options, flags, description_options);
	}
	if (state.value == 0) {
		if (state.max == ~(uintptr_t)0) {
			return strdup("any");
		}
		if (state.max == 0xffffffff) {
			return strdup("any u32");
		}
		if (state.max == 0xffff) {
			return strdup("any u16");
		}
		if (state.max == 0xff) {
			return strdup("any u8");
		}
	}
	char *low = copy_enum_flags_value_description(context, state.value, options, sizeof_options, flags, description_options);
	size_t low_size = strlen(low);
	char *high = copy_enum_flags_value_description(context, state.max, options, sizeof_options, flags, description_options);
	size_t high_size = strlen(high);
	char *buf = realloc(low, low_size + 1 + high_size + 1);
	// memcpy(buf, low, low_size);
	buf[low_size] = '-';
	memcpy(&buf[low_size + 1], high, high_size + 1);
	free(high);
	return buf;
}

static char *copy_escaped(const char *input)
{
	size_t size = 3;
	for (const char *buf = input; *buf != '\0'; buf++) {
		switch (*buf) {
			case '\a':
			case '\b':
			case '\f':
			case '\n':
			case '\r':
			case '\t':
			case '\v':
			case '\\':
			case '"':
				size += 2;
				break;
			case ' ' ... '!':
			case '#' ... '[':
			case ']' ... '~':
				size++;
				break;
			default:
				size += 4;
				break;
		}
	}
	char *buf = malloc(size);
	int i = 0;
	buf[i++] = '"';
	for (; *input != '\0'; input++) {
		switch (*input) {
			case '\a':
				buf[i++] = '\\';
				buf[i++] = 'a';
				break;
			case '\b':
				buf[i++] = '\\';
				buf[i++] = 'b';
				break;
			case '\f':
				buf[i++] = '\\';
				buf[i++] = 'f';
				break;
			case '\n':
				buf[i++] = '\\';
				buf[i++] = 'n';
				break;
			case '\r':
				buf[i++] = '\\';
				buf[i++] = 'r';
				break;
			case '\t':
				buf[i++] = '\\';
				buf[i++] = 't';
				break;
			case '\v':
				buf[i++] = '\\';
				buf[i++] = 'v';
				break;
			case '\\':
				buf[i++] = '\\';
				buf[i++] = '\\';
				break;
			case '"':
				buf[i++] = '\\';
				buf[i++] = '"';
				break;
			case ' ' ... '!':
			case '#' ... '[':
			case ']' ... '~':
				buf[i++] = *input;
				break;
			default:
				buf[i++] = '\\';
				buf[i++] = 'x';
				buf[i++] = "0123456789abcdef"[(unsigned char)*input >> 4];
				buf[i++] = "0123456789abcdef"[(unsigned char)*input & 0xf];
				break;
		}
	}
	buf[i++] = '"';
	buf[i++] = '\0';
	return buf;
}

static char *copy_argument_description(const struct loader_context *context, struct register_state state, uint8_t argument_type, struct register_state related_state, uint8_t related_argument_type)
{
	switch (argument_type) {
#ifdef __linux__
		case SYSCALL_ARG_IS_SIZE:
			if (state.value == state.max) {
				switch (related_argument_type) {
					case SYSCALL_ARG_IS_SIGSET:
					case SYSCALL_ARG_IS_SIGNUM:
						if (state.value == 8) {
							return strdup("sizeof(kernel_sigset_t)");
						}
						break;
					case SYSCALL_ARG_IS_ROBUST_LIST:
						if (state.value == 24) {
							return strdup("sizeof(struct robust_list_head)");
						}
						break;
					case SYSCALL_ARG_IS_CLONE_ARGS:
						if (state.value == 88) {
							return strdup("sizeof(struct clone_args)");
						}
						break;
					case SYSCALL_ARG_IS_BPF_ATTR:
						if (state.value == 144) {
							return strdup("sizeof(union bpf_attr)");
						}
						break;
				}
			}
			return copy_register_state_description(context, state);
		case SYSCALL_ARG_IS_FD:
			return copy_enum_flags_description(context, state, file_descriptors, sizeof(file_descriptors), NULL, false);
		case SYSCALL_ARG_IS_PROT:
			return copy_enum_flags_description(context, state, prots, sizeof(prots), prot_flags, false);
		case SYSCALL_ARG_IS_MAP_FLAGS:
			return copy_enum_flags_description(context, state, maps, sizeof(maps), map_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_REMAP_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, remap_flags, false);
		case SYSCALL_ARG_IS_OPEN_FLAGS:
			return copy_enum_flags_description(context, state, opens, sizeof(opens), open_flags, DESCRIBE_PRINT_ZERO_ENUMS | DESCRIBE_IGNORE_UNKNOWN_FLAGS);
		case SYSCALL_ARG_IS_SIGNUM:
			return copy_enum_flags_description(context, state, signums, sizeof(signums), NULL, false);
		case SYSCALL_ARG_IS_IOCTL:
			return copy_enum_flags_description(context, state, ioctls, sizeof(ioctls), NULL, DESCRIBE_AS_IOCTL);
		case SYSCALL_ARG_IS_SIGHOW:
			return copy_enum_flags_description(context, state, sighows, sizeof(sighows), NULL, false);
		case SYSCALL_ARG_IS_MADVISE:
			return copy_enum_flags_description(context, state, madvises, sizeof(madvises), NULL, false);
		case SYSCALL_ARG_IS_FCNTL:
			return copy_enum_flags_description(context, state, fcntls, sizeof(fcntls), NULL, false);
		case SYSCALL_ARG_IS_RLIMIT:
			return copy_enum_flags_description(context, state, rlimits, sizeof(rlimits), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_DOMAIN:
			return copy_enum_flags_description(context, state, socket_domains, sizeof(socket_domains), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_TYPE:
			return copy_enum_flags_description(context, state, socket_types, sizeof(socket_types), socket_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_CLOCK_ID:
			return copy_enum_flags_description(context, state, clock_ids, sizeof(clock_ids), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_LEVEL:
			return copy_enum_flags_description(context, state, socket_levels, sizeof(socket_levels), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_OPTION:
			if (related_argument_type == SYSCALL_ARG_IS_SOCKET_LEVEL && related_state.value == related_state.max) {
				switch (related_state.value) {
					case SOL_IP:
						return copy_enum_flags_description(context, state, socket_options_ip, sizeof(socket_options_ip), NULL, false);
					case SOL_IPV6:
						return copy_enum_flags_description(context, state, socket_options_ipv6, sizeof(socket_options_ipv6), NULL, false);
					case SOL_TCP:
						return copy_enum_flags_description(context, state, socket_options_tcp, sizeof(socket_options_tcp), NULL, false);
					case SOL_TLS:
						return copy_enum_flags_description(context, state, socket_options_tls, sizeof(socket_options_tls), NULL, false);
					case SOL_ALG:
						return copy_enum_flags_description(context, state, socket_options_alg, sizeof(socket_options_alg), NULL, false);
					case SOL_NETLINK:
						return copy_enum_flags_description(context, state, socket_options_netlink, sizeof(socket_options_netlink), NULL, false);
					case SOL_ICMPV6:
						return copy_enum_flags_description(context, state, socket_options_icmpv6, sizeof(socket_options_icmpv6), NULL, false);
					case SOL_RAW:
						return copy_enum_flags_description(context, state, socket_options_ip, sizeof(socket_options_ip), NULL, false);
				}
			}
			return copy_enum_flags_description(context, state, socket_options, sizeof(socket_options), NULL, false);
		case SYSCALL_ARG_IS_ACCESS_MODE:
			return copy_enum_flags_description(context, state, access_modes, sizeof(access_modes), access_mode_flags, false);
		case SYSCALL_ARG_IS_ACCESSAT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, accessat_flags, false);
		case SYSCALL_ARG_IS_REMOVEAT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, removeat_flags, false);
		case SYSCALL_ARG_IS_MSYNC_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, msync_flags, false);
		case SYSCALL_ARG_IS_OFLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, open_flags, false);
		case SYSCALL_ARG_IS_MSG_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, msg_flags, false);
		case SYSCALL_ARG_IS_SHUTDOWN_HOW:
			return copy_enum_flags_description(context, state, shutdown_hows, sizeof(shutdown_hows), NULL, false);
		case SYSCALL_ARG_IS_FUTEX_OP:
			return copy_enum_flags_description(context, state, futex_operations, sizeof(futex_operations), futex_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_SIGNALFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, signalfd_flags, false);
		case SYSCALL_ARG_IS_TIMERFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, timerfd_flags, false);
		case SYSCALL_ARG_IS_SOCKET_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, socket_flags, false);
		case SYSCALL_ARG_IS_PRCTL:
			return copy_enum_flags_description(context, state, prctls, sizeof(prctls), NULL, false);
		case SYSCALL_ARG_IS_CLONEFLAGS:
			return copy_enum_flags_description(context, state, signums, sizeof(signums), clone_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_UNSHARE_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, unshare_flags, false);
		case SYSCALL_ARG_IS_SHM_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, shm_flags, DESCRIBE_AS_FILE_MODE);
		case SYSCALL_ARG_IS_EVENTFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, eventfd_flags, false);
		case SYSCALL_ARG_IS_EPOLL_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, epoll_flags, false);
		case SYSCALL_ARG_IS_XATTR_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, xattr_flags, false);
		case SYSCALL_ARG_IS_TIMER_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, timer_flags, false);
		case SYSCALL_ARG_IS_WAIT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, wait_flags, false);
		case SYSCALL_ARG_IS_WAITIDTYPE:
			return copy_enum_flags_description(context, state, wait_idtypes, sizeof(wait_idtypes), NULL, false);
		case SYSCALL_ARG_IS_INOTIFY_EVENT_MASK:
			return copy_enum_flags_description(context, state, NULL, 0, inotify_event_flags, DESCRIBE_IGNORE_UNKNOWN_FLAGS);
		case SYSCALL_ARG_IS_INOTIFY_INIT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, inotify_init_flags, false);
		case SYSCALL_ARG_IS_SECCOMP_OPERATION:
			return copy_enum_flags_description(context, state, seccomp_operations, sizeof(seccomp_operations), NULL, false);
		case SYSCALL_ARG_IS_MEMFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, memfd_flags, false);
		case SYSCALL_ARG_IS_BPF_COMMAND:
			return copy_enum_flags_description(context, state, bpf_commands, sizeof(bpf_commands), NULL, false);
		case SYSCALL_ARG_IS_USERFAULTFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, userfaultfd_flags, false);
		case SYSCALL_ARG_IS_MLOCKALL_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, mlockall_flags, false);
		case SYSCALL_ARG_IS_UMOUNT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, umount_flags, false);
		case SYSCALL_ARG_IS_SWAP_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, swap_flags, false);
		case SYSCALL_ARG_IS_SPLICE_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, splice_flags, false);
		case SYSCALL_ARG_IS_SYNC_FILE_RANGE_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, sync_file_range_flags, false);
		case SYSCALL_ARG_IS_TIMERFD_SETTIME_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, timerfd_settime_flags, false);
		case SYSCALL_ARG_IS_PERF_EVENT_OPEN_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, perf_event_open_flags, false);
		case SYSCALL_ARG_IS_MODULE_INIT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, module_init_flags, false);
		case SYSCALL_ARG_IS_GETRANDOM_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, getrandom_flags, false);
		case SYSCALL_ARG_IS_MEMBARRIER_COMMAND:
			return copy_enum_flags_description(context, state, membarrier_commands, sizeof(membarrier_commands), NULL, false);
		case SYSCALL_ARG_IS_STATX_MASK:
			return copy_enum_flags_description(context, state, NULL, 0, statx_mask, false);
		case SYSCALL_ARG_IS_FLOCK_OPERATION:
			return copy_enum_flags_description(context, state, flock_operations, sizeof(flock_operations), flock_flags, false);
		case SYSCALL_ARG_IS_ITIMER_WHICH:
			return copy_enum_flags_description(context, state, itimer_whiches, sizeof(itimer_whiches), NULL, false);
		case SYSCALL_ARG_IS_SEEK_WHENCE:
			return copy_enum_flags_description(context, state, seek_whences, sizeof(seek_whences), NULL, false);
		case SYSCALL_ARG_IS_SHMCTL_COMMAND:
			return copy_enum_flags_description(context, state, shmctl_commands, sizeof(shmctl_commands), NULL, false);
		case SYSCALL_ARG_IS_SEMCTL_COMMAND:
			return copy_enum_flags_description(context, state, semctl_commands, sizeof(semctl_commands), NULL, false);
		case SYSCALL_ARG_IS_PTRACE_REQUEST:
			return copy_enum_flags_description(context, state, ptrace_requests, sizeof(ptrace_requests), NULL, false);
		case SYSCALL_ARG_IS_SEM_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, sem_flags, DESCRIBE_AS_FILE_MODE);
		case SYSCALL_ARG_IS_PID:
			if (context->pid != 0 && register_is_exactly_known(&state) && state.value == (uintptr_t)context->pid) {
				return strdup("getpid()");
			} else {
				return copy_register_state_description(context, state);
			}
		case SYSCALL_ARG_IS_FCNTL_ARG:
			if (related_state.value == related_state.max) {
				switch (related_state.value) {
					case F_SETFD:
						return copy_enum_flags_description(context, state, NULL, 0, fd_flags, false);
					case F_SETFL:
						return copy_enum_flags_description(context, state, NULL, 0, open_flags, DESCRIBE_IGNORE_UNKNOWN_FLAGS);
					case F_SETSIG:
						return copy_enum_flags_description(context, state, signums, sizeof(signums), NULL, false);
					case F_SETLEASE:
						return copy_enum_flags_description(context, state, lease_args, sizeof(lease_args), NULL, false);
					case F_ADD_SEALS:
						return copy_enum_flags_description(context, state, NULL, 0, seal_flags, false);
				}
			}
			return copy_register_state_description(context, state);
		case SYSCALL_ARG_IS_PRCTL_ARG:
			if (related_state.value == related_state.max) {
				switch (related_state.value) {
					case PR_SET_NAME:
						if (state.value == state.max) {
							struct loaded_binary *binary = binary_for_address(context, (const void *)state.value);
							if (binary != NULL) {
								return copy_escaped((const char *)state.value);
							}
						}
						break;
					case PR_SET_PDEATHSIG:
						return copy_enum_flags_description(context, state, signums, sizeof(signums), NULL, false);
					case PR_SET_SECCOMP:
						return copy_enum_flags_description(context, state, seccomp_operations, sizeof(seccomp_operations), NULL, false);
					case PR_SET_MM:
						return copy_enum_flags_description(context, state, set_mm_ops, sizeof(set_mm_ops), NULL, false);
					case PR_CAP_AMBIENT:
						return copy_enum_flags_description(context, state, cap_ambient_ops, sizeof(cap_ambient_ops), NULL, false);
				}
			}
			return copy_register_state_description(context, state);
		case SYSCALL_ARG_IS_KEYCTL_OP:
			return copy_enum_flags_description(context, state, keyctl_ops, sizeof(keyctl_ops), NULL, false);
		case SYSCALL_ARG_IS_RSEQ_SIG:
			if (state.value == state.max && state.value == RSEQ_SIG) {
				return strdup("RSEQ_SIG");
			}
			return copy_register_state_description(context, state);
		case SYSCALL_ARG_IS_PERSONALITY:
			return copy_enum_flags_description(context, state, personas, sizeof(personas), persona_flags, false);
		case SYSCALL_ARG_IS_PTRACE_ARG:
			if (related_state.value == related_state.max) {
				switch (related_state.value) {
					case PTRACE_SETOPTIONS:
						return copy_enum_flags_description(context, state, NULL, 0, ptrace_option_flags, false);
				}
			}
			return copy_register_state_description(context, state);
		case SYSCALL_ARG_IS_SYSLOG_ACTION:
			return copy_enum_flags_description(context, state, syslog_actions, sizeof(syslog_actions), NULL, false);
#endif
		case SYSCALL_ARG_IS_MODE:
		case SYSCALL_ARG_IS_MODEFLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, NULL, DESCRIBE_AS_FILE_MODE);
		case SYSCALL_ARG_IS_SOCKET_PROTOCOL:
			return copy_register_state_description(context, state);
		case SYSCALL_ARG_IS_STRING:
			if (state.value == state.max) {
				struct loaded_binary *binary = binary_for_address(context, (const void *)state.value);
				if (binary != NULL) {
					return copy_escaped((const char *)state.value);
				}
			}
			return copy_register_state_description(context, state);
		default:
			return copy_register_state_description(context, state);
	}
}

__attribute__((unused)) __attribute__((nonnull(1, 2, 4))) char *copy_call_description(const struct loader_context *context, const char *name, const struct registers *registers, const int *register_indexes, struct syscall_info info,
                                                                                      bool include_symbol)
{
	int argc = info.attributes & SYSCALL_ARGC_MASK;
	size_t name_len = fs_strlen(name);
	size_t len = name_len + 3; // name + '(' + ... + ')' + '\0'
	char *args[9];
	size_t arg_len[9];
	for (int i = 0; i < argc; i++) {
		if (i != 0) {
			len += 2; // ", "
		}
		int reg = register_indexes[i];
		if (include_symbol) {
			uint8_t argument_type = info.arguments[i] & SYSCALL_ARG_TYPE_MASK;
			int related_arg = info.arguments[i] / SYSCALL_ARG_RELATED_ARGUMENT_BASE;
			int related_reg = register_indexes[related_arg];
			uint8_t related_arg_type = info.arguments[related_arg] & SYSCALL_ARG_TYPE_MASK;
			args[i] = copy_argument_description(context, registers->registers[reg], argument_type, registers->registers[related_reg], related_arg_type);
		} else {
			args[i] = copy_register_state_description_simple(context, registers->registers[reg]);
		}
		arg_len[i] = fs_strlen(args[i]);
		len += arg_len[i];
	}
	char *result = malloc(len);
	fs_memcpy(result, name, name_len);
	size_t pos = name_len;
	result[pos++] = '(';
	for (int i = 0; i < argc; i++) {
		if (i != 0) {
			result[pos++] = ',';
			result[pos++] = ' ';
		}
		fs_memcpy(&result[pos], args[i], arg_len[i]);
		free(args[i]);
		pos += arg_len[i];
	}
	result[pos++] = ')';
	result[pos++] = '\0';
	return result;
}

char *copy_raw_syscall_description(intptr_t syscall, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6)
{
	const char *name = name_for_syscall(syscall);
	size_t name_len = fs_strlen(name);
	size_t len = name_len + 3; // '(' ... ')' '\0'
	int argc = info_for_syscall(syscall).attributes & SYSCALL_ARGC_MASK;
	uintptr_t args[] = {arg1, arg2, arg3, arg4, arg5, arg6};
	for (int i = 0; i < argc; i++) {
		if (i != 0) {
			len += 2; // ", "
		}
		char buf[10];
		len += args[i] < PAGE_SIZE ? fs_utoa(args[i], buf) : fs_utoah(args[i], buf);
	}
	char *buf = malloc(len);
	char *cur = buf;
	fs_memcpy(cur, name, name_len);
	cur += name_len;
	*cur++ = '(';
	for (int i = 0; i < argc; i++) {
		if (i != 0) {
			*cur++ = ',';
			*cur++ = ' ';
		}
		cur += args[i] < PAGE_SIZE ? fs_utoa(args[i], cur) : fs_utoah(args[i], cur);
	}
	*cur++ = ')';
	*cur++ = '\0';
	return buf;
}

const char *name_for_register(int register_index)
{
	switch (register_index) {
#if defined(__x86_64__)
		case REGISTER_RAX:
			return "ax";
		case REGISTER_RCX:
			return "cx";
		case REGISTER_RDX:
			return "dx";
		case REGISTER_RBX:
			return "bx";
		case REGISTER_SP:
			return "sp";
		case REGISTER_RBP:
			return "bp";
		case REGISTER_RSI:
			return "si";
		case REGISTER_RDI:
			return "di";
		case REGISTER_R8:
			return "r8";
		case REGISTER_R9:
			return "r9";
		case REGISTER_R10:
			return "r10";
		case REGISTER_R11:
			return "r11";
		case REGISTER_R12:
			return "r12";
		case REGISTER_R13:
			return "r13";
		case REGISTER_R14:
			return "r14";
		case REGISTER_R15:
			return "r15";
#else
#if defined(__aarch64__)
		case REGISTER_X0:
			return "r0";
		case REGISTER_X1:
			return "r1";
		case REGISTER_X2:
			return "r2";
		case REGISTER_X3:
			return "r3";
		case REGISTER_X4:
			return "r4";
		case REGISTER_X5:
			return "r5";
		case REGISTER_X6:
			return "r6";
		case REGISTER_X7:
			return "r7";
		case REGISTER_X8:
			return "r8";
		case REGISTER_X9:
			return "r9";
		case REGISTER_X10:
			return "r10";
		case REGISTER_X11:
			return "r11";
		case REGISTER_X12:
			return "r12";
		case REGISTER_X13:
			return "r13";
		case REGISTER_X14:
			return "r14";
		case REGISTER_X15:
			return "r15";
		case REGISTER_X16:
			return "r16";
		case REGISTER_X17:
			return "r17";
		case REGISTER_X18:
			return "r18";
		case REGISTER_X19:
			return "r19";
		case REGISTER_X20:
			return "r20";
		case REGISTER_X21:
			return "r21";
		case REGISTER_X22:
			return "r22";
		case REGISTER_X23:
			return "r23";
		case REGISTER_X24:
			return "r24";
		case REGISTER_X25:
			return "r25";
		case REGISTER_X26:
			return "r26";
		case REGISTER_X27:
			return "r27";
		case REGISTER_X28:
			return "r28";
		case REGISTER_SP:
			return "sp";
#else
#error "Unknown architecture"
#endif
#endif
		case REGISTER_MEM:
			return "mem";
#define PER_STACK_REGISTER_IMPL(offset) \
	case REGISTER_STACK_##offset:       \
		return "stack+" #offset;
			GENERATE_PER_STACK_REGISTER()
#undef PER_STACK_REGISTER_IMPL
		default:
			return "invalid";
	}
}

char *copy_registers_description(const struct loader_context *loader, const struct registers *registers, register_mask mask)
{
	const char *names[REGISTER_COUNT];
	size_t name_lengths[REGISTER_COUNT];
	char *descriptions[REGISTER_COUNT];
	size_t description_lengths[REGISTER_COUNT];
	size_t used = 0;
	size_t characters = 1;
	for_each_bit (mask, bit, r) {
		// name
		const char *name = name_for_register(r);
		names[used] = name;
		size_t name_length = fs_strlen(name);
		name_lengths[used] = name_length;
		// description
		char *description = copy_register_state_description(loader, registers->registers[r]);
		descriptions[used] = description;
		size_t description_len = fs_strlen(description);
		description_lengths[used] = description_len;
		used++;
		characters += name_length + 2 + description_len;
	}
	char *buf = malloc(characters);
	size_t i = 0;
	for (size_t r = 0; r < used; r++) {
		buf[i++] = ' ';
		memcpy(&buf[i], names[r], name_lengths[r]);
		i += name_lengths[r];
		buf[i++] = '=';
		memcpy(&buf[i], descriptions[r], description_lengths[r]);
		i += description_lengths[r];
		free(descriptions[r]);
	}
	buf[i] = '\0';
	return buf;
}
