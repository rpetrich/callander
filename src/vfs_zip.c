#define _GNU_SOURCE
#include "vfs_zip.h"
#include "freestanding.h"
#include "axon_shared.h"
#include "linux.h"
#include "vfs.h"
#include "attempt.h"
#include "proxy.h"

#include "libzip/lib/zip.h"
#include "libzip/lib/zipint.h"
#include <zlib.h>

#include <dirent.h>

void *shared_malloc(size_t size);
void shared_free(void *ptr);

struct vfs_zip_state *get_zip_state(void);

void vfs_zip_install(void *addr)
{
	// read the path
	struct vfs_zip_state *state = get_zip_state();
	intptr_t result = fs_fd_getpath(PROXY_FD, state->mountpoint);
	if (result < 0) {
		DIE("failed to read path of zip: ", as_errno(result));
	}
	state->mountpoint_len = fs_strlen(state->mountpoint);
	// check the file size
	struct fs_stat stat;
	result = fs_fstat(PROXY_FD, &stat);
	if (result < 0) {
		DIE("failed to read size of zip: ", as_errno(result));
	}
	state->size = stat.st_size;

	// map the zip file into memory
	void *address = fs_mmap(addr, stat.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, PROXY_FD, 0);
	if (fs_is_map_failed(address)) {
		DIE("failed to map zip: ", as_errno((intptr_t)address));
	}
	state->address = address;

	zip_error_t error;
	zip_error_init(&error);

	// create an in-memory source
	zip_source_t *src;
	if ((src = zip_source_buffer_create(state->address, stat.st_size, 1, &error)) == NULL) {
		DIE("can't create source: ", error.zip_err);
		zip_error_fini(&error);
		return;
	}

	// open zip from our mapped in-memory source
	if ((state->za = zip_open_from_source(src, 0, &error)) == NULL) {
		DIE("can't open zip from source: ", error.zip_err);
		zip_source_free(src);
		zip_error_fini(&error);
		return;
	}

	// parse each entry upfront
	zip_stat_t zip_stat;
	zip_stat_init(&zip_stat);
	size_t file_count = zip_get_num_entries(state->za, ZIP_FL_UNCHANGED);
	state->entry_offsets = shared_malloc(file_count * sizeof(size_t));
	if (state->entry_offsets == NULL) {
		DIE("cannot allocate offset array");
	}
	for (size_t i = 0; i < file_count; i++) {
		if (_zip_read_local_ef(state->za, i) < 0) {
			size_t name_size;
			const char *name = _zip_get_name_raw(state->za, i, 0, &name_size, NULL);
			DIE("can't read local extra fields for ", ((struct iovec){ (void *)name, name_size }), ": ", error.zip_err);
			zip_source_free(src);
			zip_error_fini(&error);
		}
		zip_stat_index(state->za, i, 0, &zip_stat);
		state->entry_offsets[i] = _zip_file_get_offset(state->za, i, &error);
	}
	zip_error_fini(&error);
}

void vfs_zip_configure(void)
{
	struct vfs_zip_state *state = get_zip_state();
	void *address = fs_mmap(state->address, state->size, PROT_READ, MAP_FILE | MAP_PRIVATE, PROXY_FD, 0);
	if (fs_is_map_failed(address)) {
		DIE("failed to map zip: ", as_errno((intptr_t)address));
	}
	if (address != state->address) {
		DIE("could not map zip file to dedicated address");
	}
}

__attribute__((warn_unused_result)) int fixup_exe_open(int dfd, const char *filename, int flags)
{
	// TODO: fixup /proc/self/exe for target opens
	(void)dfd;
	(void)filename;
	(void)flags;
	return -EACCES;
}

__attribute__((warn_unused_result)) bool lookup_real_path(int fd, const char *path, path_info *out_path)
{
	struct vfs_zip_state *state = get_zip_state();
	return lookup_potential_mount_path(state->mountpoint, state->mountpoint_len, fd, path, out_path);
}

static struct zip_state *state_for_fd(int fd)
{
	struct fd_global_state *state = get_fd_global_state();
	return &state->files[fd].state.zip;
}

static const char *normalize_path(const char *path, char buf[PATH_MAX], size_t *out_len)
{
	size_t seg_start = 0;
	bool only_dots = true;
	size_t i = 0;
	for (;; i++) {
		switch (path[i]) {
			case '\0':
				if (only_dots && i < seg_start + 3) {
					goto requires_normalization;
				}
				*out_len = i;
				return path;
			case '/':
				if (only_dots && i < seg_start + 3) {
					goto requires_normalization;
				}
				seg_start = i+1;
				only_dots = true;
				break;
			case '.':
				break;
			default:
				only_dots = false;
				break;
		}
	}
requires_normalization:
	fs_memcpy(buf, path, seg_start);
	size_t o = i;
	for (;; i++) {
		switch (path[i]) {
			case '\0':
			case '/':
				if (only_dots && i != seg_start && i < seg_start + 3) {
					if (i == seg_start + 2) {
						for (o -= i - seg_start + 2; buf[o] != '/' && o != 0; o--) {
						}
					} else {
						o -= i - seg_start + 1;
					}
				} else {
				}
				if (path[i] == '\0') {
					if (buf[o-1] == '/') {
						o--;
					}
					*out_len = o;
					buf[o++] = '\0';
					return &buf[0];
				}
				buf[o++] = '/';
				seg_start = i+1;
				only_dots = true;
				break;
			case '.':
				buf[o++] = '.';
				break;
			default:
				only_dots = false;
				buf[o++] = path[i];
				break;
		}
	}
}

static zip_int64_t zip_index_for_resolved_path(struct vfs_resolved_path resolved, int flags, bool *is_dir)
{
	if ((flags & AT_EMPTY_PATH) && (resolved.info.path == NULL || *resolved.info.path == '\0')) {
		if (resolved.info.handle == AT_FDCWD) {
			return -EINVAL;
		}
		struct zip_state *state = state_for_fd(resolved.info.handle);
		*is_dir = state->is_dir;
		return state->index;
	}
	struct vfs_zip_state *zip = get_zip_state();
	char buf[PATH_MAX];
	zip_error_t error;
	const char *filename;
	if (resolved.info.handle != AT_FDCWD && resolved.info.path != NULL && resolved.info.path[0] != '/') {		
		struct zip_state *state = state_for_fd(resolved.info.handle);
		size_t dir_name_size;
		zip_error_init(&error);
		const char *dir_name = _zip_get_name_raw(zip->za, state->index, 0, &dir_name_size, NULL);
		zip_error_fini(&error);
		if (dir_name == NULL) {
			return -EIO;
		}
		memcpy(buf, dir_name, dir_name_size);
		memcpy(&buf[dir_name_size], resolved.info.path, fs_strlen(resolved.info.path) + 1);
		filename = buf;
	} else {
		if ((resolved.info.handle != AT_FDCWD) || (resolved.info.path == NULL) || (resolved.info.path[0] != '/')) {
			return -EINVAL;
		}
		filename = &resolved.info.path[1];
	}
	if (filename[0] == '\0') {
		return -ENOENT;
	}
	size_t link_count = 0;
	zip_error_init(&error);
normalize:
	size_t filename_len;
	filename = normalize_path(filename, buf, &filename_len);
	zip_int64_t index = _zip_name_locate(zip->za, filename, filename_len, ZIP_FL_ENC_UTF_8, &error);
	if (index < 0) {
		zip_error_fini(&error);
		return -ENOENT;
	}
	// check for symlink
	zip_uint8_t opsys = 0;
	zip_uint32_t attributes = 0;
	if (zip_file_get_external_attributes(zip->za, index, ZIP_FL_UNCHANGED, &opsys, &attributes) == 0) {
		switch (opsys) {
		case ZIP_OPSYS_UNIX:
			if (S_ISLNK(attributes >> 16) && (flags & AT_SYMLINK_NOFOLLOW) == 0) {
				// a symlink
				if (++link_count == 3) {
					zip_error_fini(&error);
					return -ELOOP;
				}
				const char *slash = fs_strrchr(filename, '/');
				if (slash == NULL) {
					zip_error_fini(&error);
					return -ENOENT;
				}
				size_t suffix_pos = slash - filename + 1;
				if (filename != &buf[0]) {
					fs_memcpy(buf, filename, suffix_pos);
					filename = buf;
				}
				size_t offset = zip->entry_offsets[index];
				if (offset == 0) {
					zip_error_fini(&error);
					return -EINVAL;
				}
				size_t name_size = zip->za->entry[index].orig.uncomp_size;
				fs_memcpy(&buf[suffix_pos], zip->address + offset, name_size);
				buf[suffix_pos + name_size] = '\0';
				goto normalize;
			}
			if (S_ISDIR(attributes >> 16)) {
				// a directory
				*is_dir = true;
				zip_error_fini(&error);
				return index;
			}
			break;
		case ZIP_OPSYS_DOS:
			if (attributes & 0x10) {
				// a directory
				*is_dir = true;
				zip_error_fini(&error);
				return index;
			}
			break;
		}
	}
	// a regular file
	*is_dir = false;
	zip_error_fini(&error);
	return index;
}	

static void *zlib_alloc(void *, unsigned int items, unsigned int size)
{
	return shared_malloc(items * size);
}

static void zlib_free(void *, void *ptr)
{
	shared_free(ptr);
}

static inline void attempt_lock_and_push_shared_mutex(struct thread_storage *thread, struct attempt_cleanup_state *state, struct shared_mutex *mutex)
{
	shared_mutex_lock(mutex);
	state->body = (attempt_cleanup_body)(void *)&shared_mutex_unlock;
	state->data = mutex;
	attempt_push_cleanup(thread, state);
}

static inline void attempt_unlock_and_pop_shared_mutex(struct attempt_cleanup_state *state, struct shared_mutex *mutex)
{
	attempt_pop_and_skip_cleanup(state);
	shared_mutex_unlock(mutex);
}

static intptr_t materialize_file_contents(struct zip_state *state, void **data)
{
	if (UNLIKELY(state->is_dir)) {
		return -EISDIR;
	}
	if (!state->is_compressed) {
		*data = get_zip_state()->address + state->offset;
		return 0;
	}
	void *materialized = atomic_load(&state->materialized);
	if (materialized != NULL) {
		*data = materialized;
		return 0;
	}
	materialized = shared_malloc((state->size + (PAGE_SIZE - 1)) & -PAGE_SIZE);
	if (materialized == NULL) {
		return -ESPIPE;
	}
	struct vfs_zip_state *zip = get_zip_state();
	struct z_stream_s stream = { 0 };
	stream.zalloc = zlib_alloc;
	stream.zfree = zlib_free;
	stream.avail_in = zip->za->entry[state->index].orig.comp_size;
	stream.next_in = zip->address + state->offset;
	stream.avail_out = state->size;
	stream.next_out = materialized;
	inflateInit2(&stream, -MAX_WBITS);
	shared_mutex_lock(&state->stream_lock);
	if (state->materialized != NULL) {
		*data = state->materialized;
		shared_mutex_unlock(&state->stream_lock);
		shared_free(materialized);
		return 0;
	}
	do {
		int ret = inflate(&stream, Z_SYNC_FLUSH);
		if (ret == Z_STREAM_END) {
			break;
		}
		if (ret == Z_BUF_ERROR) {
			shared_mutex_unlock(&state->stream_lock);
			inflateEnd(&stream);
			return -EIO;
		}
	} while(stream.avail_out != 0);
	atomic_store(&state->materialized, materialized);
	shared_mutex_unlock(&state->stream_lock);
	inflateEnd(&stream);
	inflateEnd(&state->stream);
	*data = materialized;
	return 0;
}

static intptr_t zip_path_mkdirat(struct thread_storage *, struct vfs_resolved_path, mode_t)
{
	return -EROFS;
}

static intptr_t zip_path_mknodat(struct thread_storage *, struct vfs_resolved_path, mode_t, dev_t)
{
	return -EROFS;
}

static intptr_t zip_path_openat(struct thread_storage *, struct vfs_resolved_path resolved, int flags, mode_t, struct vfs_resolved_file *out_file)
{
	bool is_dir;
	zip_int64_t index = zip_index_for_resolved_path(resolved, flags, &is_dir);
	if (index < 0) {
		return index;
	}
	struct vfs_zip_state *zip = get_zip_state();
	size_t offset = zip->entry_offsets[index];
	if (offset == 0) {
		return -EINVAL;
	}
	struct z_stream_s stream;
	const zip_dirent_t *dirent = &zip->za->entry[index].orig;
	bool is_compressed;
	switch (dirent->comp_method) {
	case ZIP_CM_STORE:
		is_compressed = false;
		break;
	case ZIP_CM_DEFLATE:
		stream.zalloc = zlib_alloc;
		stream.zfree = zlib_free;
		stream.opaque = NULL;
		stream.avail_in = dirent->comp_size;
		stream.next_in = zip->address + offset;
		stream.avail_out = 0;
		stream.next_out = NULL;
		inflateInit2(&stream, -MAX_WBITS);
		is_compressed = true;
		break;
	default:
		return -EIO;
	}
	return vfs_allocate_file(&zip_path_ops.dirfd_ops, (union vfs_file_state){
		.zip = {
			.index = index,
			.offset = offset,
			.size = dirent->uncomp_size,
			.dent_offset = index - 1,
			.is_dir = is_dir,
			.is_compressed = is_compressed,
			.stream = stream,
		},
	}, out_file);
}

static intptr_t zip_path_unlinkat(struct thread_storage *, struct vfs_resolved_path, int)
{
	return -EROFS;
}

static intptr_t zip_path_renameat2(struct thread_storage *, struct vfs_resolved_path, struct vfs_resolved_path, int)
{
	return -EROFS;
}

static intptr_t zip_path_linkat(struct thread_storage *, struct vfs_resolved_path, struct vfs_resolved_path, int)
{
	return -EROFS;
}

static intptr_t zip_path_symlinkat(struct thread_storage *, struct vfs_resolved_path, const char *)
{
	return -EROFS;
}

static intptr_t zip_path_truncate(struct thread_storage *, struct vfs_resolved_path, off_t)
{
	return -EROFS;
}

static intptr_t zip_path_fchmodat(struct thread_storage *, struct vfs_resolved_path, mode_t, int)
{
	return -EROFS;
}

static intptr_t zip_path_fchownat(struct thread_storage *, struct vfs_resolved_path, uid_t, gid_t, int)
{
	return -EROFS;
}

static intptr_t zip_path_utimensat(struct thread_storage *, struct vfs_resolved_path, const struct timespec[2], int)
{
	return -EROFS;
}

static uint64_t read_sized_uint(const uint8_t *data, size_t size)
{
	uint64_t result = 0;
	for (ssize_t i = 0; i < (ssize_t)size; i++) {
		result |= (uint64_t)data[i] << (i*8);
	}
	return result;
}

static intptr_t zip_path_statx(struct thread_storage *, struct vfs_resolved_path resolved, int flags, unsigned int mask, struct linux_statx *restrict statxbuf)
{
	bool is_dir;
	zip_int64_t index = zip_index_for_resolved_path(resolved, flags, &is_dir);
	if (index < 0) {
		return index;
	}
	struct vfs_zip_state *zip = get_zip_state();
	zip_stat_t zip_stat;
	zip_stat_init(&zip_stat);
	if (zip_stat_index(zip->za, index, 0, &zip_stat) < 0) {
		return -EINVAL;
	}
	uint32_t valid = 0;
	statxbuf->stx_blksize = 512;
	statxbuf->stx_attributes = 0;
	if (mask & STATX_NLINK) {
		valid |= STATX_NLINK;
		statxbuf->stx_nlink = 1;
	}
	statxbuf->stx_nlink = 1;
	statxbuf->stx_uid = 0;
	statxbuf->stx_gid = 0;
	if (mask & (STATX_UID|STATX_GID)) {
		// read Info-ZIP New Unix Extra Field
		zip_uint16_t len;
		const zip_uint8_t *data = zip_file_extra_field_get_by_id(zip->za, index, 0x7875, 0, &len, ZIP_FL_LOCAL | ZIP_FL_CENTRAL);
		if (data && data[0] == 1) {
			statxbuf->stx_uid = read_sized_uint(&data[2], data[1]);
			statxbuf->stx_gid = read_sized_uint(&data[2 + data[1] + 1], data[1 + data[1]]);
			valid |= STATX_UID | STATX_GID;
		}
	}
	if (mask & (STATX_MODE|STATX_TYPE)) {
		valid |= STATX_MODE|STATX_TYPE;
		zip_uint8_t opsys = 0;
		zip_uint32_t attributes = 0;
		zip_file_get_external_attributes(zip->za, index, ZIP_FL_UNCHANGED, &opsys, &attributes);
		statxbuf->stx_mode = opsys == ZIP_OPSYS_UNIX ? (attributes >> 16) : (is_dir ? S_IFDIR | 0755 : S_IFREG | 0644);
	} else {
		statxbuf->stx_mode = is_dir ? S_IFDIR | 0755 : S_IFREG | 0644;
	}
	if (mask & (STATX_INO)) {
		valid |= STATX_INO;
	}
	statxbuf->stx_ino = index;
	if (mask & STATX_SIZE && zip_stat.valid & ZIP_STAT_SIZE) {
		valid |= STATX_SIZE;
	}
	statxbuf->stx_size = (zip_stat.valid & ZIP_STAT_SIZE) ? zip_stat.size : 0;
	// always provide blocks even when not requested, since ls requires this
	valid |= STATX_BLOCKS;
	statxbuf->stx_blocks = (zip_stat.valid & ZIP_STAT_SIZE) ? ((zip_stat.size + 511) / 512) : 0;
	statxbuf->stx_attributes_mask = 0;
	if (mask & STATX_ATIME) {
		valid |= STATX_ATIME;
	}
	statxbuf->stx_mtime.tv_sec = (zip_stat.valid & ZIP_STAT_MTIME) ? zip_stat.mtime : 1000000000;
	statxbuf->stx_atime.tv_nsec = 0;
	if (mask & STATX_MTIME) {
		valid |= STATX_MTIME;
	}
	statxbuf->stx_mtime.tv_sec = (zip_stat.valid & ZIP_STAT_MTIME) ? zip_stat.mtime : 1000000000;
	statxbuf->stx_mtime.tv_nsec = 0;
	if (mask & STATX_CTIME) {
		valid |= STATX_CTIME;
	}
	statxbuf->stx_ctime.tv_sec = (zip_stat.valid & ZIP_STAT_MTIME) ? zip_stat.mtime : 1000000000;
	statxbuf->stx_ctime.tv_nsec = 0;
	statxbuf->stx_mask = valid;
	return 0;
}

static intptr_t zip_path_faccessat(struct thread_storage *, struct vfs_resolved_path resolved, int mode, int flags)
{
	bool is_dir;
	zip_int64_t index = zip_index_for_resolved_path(resolved, flags, &is_dir);
	if (index < 0) {
		return index;
	}
	if (mode & 0111) {
		return -EACCES;
	}
	return 0;
}

static intptr_t zip_path_readlinkat(struct thread_storage *, struct vfs_resolved_path resolved, char *buf, size_t bufsz)
{
	bool is_dir;
	zip_int64_t index = zip_index_for_resolved_path(resolved, AT_SYMLINK_NOFOLLOW, &is_dir);
	if (index < 0) {
		return index;
	}
	struct vfs_zip_state *zip = get_zip_state();
	size_t offset = zip->entry_offsets[index];
	if (offset == 0) {
		return -EINVAL;
	}
	const zip_dirent_t *dirent = &zip->za->entry[index].orig;
	if (dirent->uncomp_size > bufsz) {
		return -ENAMETOOLONG;
	}
	fs_memcpy(buf, zip->address + offset, dirent->uncomp_size);
	return dirent->uncomp_size;
}

static intptr_t zip_path_getxattr(struct thread_storage *, struct vfs_resolved_path, const char *, void *, size_t, int)
{
	return -ENOTSUP;
}

static intptr_t zip_path_setxattr(struct thread_storage *, struct vfs_resolved_path, const char *, const void *, size_t, int)
{
	return -ENOTSUP;
}

static intptr_t zip_path_removexattr(struct thread_storage *, struct vfs_resolved_path, const char *, int)
{
	return -EROFS;
}

static intptr_t zip_path_listxattr(struct thread_storage *, struct vfs_resolved_path, void *, size_t, int)
{
	return -ENOTSUP;
}

static intptr_t zip_file_socket(struct thread_storage *, int, int, int, struct vfs_resolved_file *)
{
	return -EINVAL;
}

static intptr_t zip_file_close(struct vfs_resolved_file, union vfs_file_state *state)
{
	if (state->zip.is_compressed) {
		if (state->zip.materialized != NULL) {
			shared_free(state->zip.materialized);
		} else {
			inflateEnd(&state->zip.stream);
		}
	}
	state->zip = (struct zip_state){0};
	return 0;
}

static intptr_t zip_file_read(struct thread_storage *thread, struct vfs_resolved_file file, char *buf, size_t bufsz)
{
	struct zip_state *state = state_for_fd(file.handle);
	if (state->is_dir) {
		return -EISDIR;
	}
	void *data;
	if (state->is_compressed) {
		data = atomic_load(&state->materialized);
		if (data == NULL) {
			struct attempt_cleanup_state cleanup;
			attempt_lock_and_push_shared_mutex(thread, &cleanup, &state->stream_lock);
			data = state->materialized;
			if (data == NULL) {
				state->stream.avail_out = bufsz;
				state->stream.next_out = (void *)buf;
				int ret = inflate(&state->stream, Z_SYNC_FLUSH);
				switch (ret) {
					case Z_OK:
					case Z_STREAM_END: {
						size_t count = bufsz - state->stream.avail_out;
						state->cursor += count;
						attempt_unlock_and_pop_shared_mutex(&cleanup, &state->stream_lock);
						return count;
					}
					case Z_BUF_ERROR:
					default:
						attempt_unlock_and_pop_shared_mutex(&cleanup, &state->stream_lock);
						return -EIO;
				}
			} else {
				attempt_unlock_and_pop_shared_mutex(&cleanup, &state->stream_lock);
			}
		}
	} else {
		struct vfs_zip_state *zip = get_zip_state();
		data = zip->address + state->offset;
	}
	size_t cursor = atomic_fetch_add_explicit(&state->cursor, bufsz, memory_order_relaxed);
	size_t new_cursor = cursor + bufsz;
	size_t size = state->size;
	if (UNLIKELY(new_cursor > size)) {
		bufsz = size - cursor;
		atomic_compare_exchange_strong_explicit(&state->cursor, &new_cursor, size, memory_order_relaxed, memory_order_relaxed);
	}
	fs_memcpy(buf, data + cursor, bufsz);
	return bufsz;
}

static intptr_t zip_file_write(struct thread_storage *, struct vfs_resolved_file, const char *, size_t)
{
	return -EBADF;
}

static intptr_t zip_file_recvfrom(struct thread_storage *, struct vfs_resolved_file, char *, size_t, int, struct sockaddr *, socklen_t *)
{
	return -EBADF;
}

static intptr_t zip_file_sendto(struct thread_storage *, struct vfs_resolved_file, const char *, size_t, int, const struct sockaddr *, socklen_t)
{
	return -EBADF;
}

static intptr_t zip_file_lseek(struct thread_storage *, struct vfs_resolved_file file, off_t offset, int whence)
{
	struct zip_state *state = state_for_fd(file.handle);
	void *data;
	intptr_t result = materialize_file_contents(state, &data);
	if (result < 0) {
		return result;
	}
	switch (whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR: {
		size_t cur = atomic_load(&state->cursor);
		offset += UNLIKELY(cur > state->size) ? state->size : cur;
		break;
	}
	case SEEK_END:
		offset += state->size;
		break;
	default:
		return -EINVAL;
	}
	if (offset < 0 || offset > (off_t)state->size) {
		return -EINVAL;
	}
	atomic_store(&state->cursor, offset);
	return offset;
}

static intptr_t zip_file_readahead(struct thread_storage *, struct vfs_resolved_file, off_t, size_t)
{
	return -EINVAL;
}

static intptr_t zip_file_pread(struct thread_storage *, struct vfs_resolved_file file, void *buf, size_t count, off_t offset)
{
	struct zip_state *state = state_for_fd(file.handle);
	if (UNLIKELY(offset < 0 || offset > (off_t)state->size)) {
		return -EINVAL;
	}
	void *data;
	intptr_t result = materialize_file_contents(state, &data);
	if (result < 0) {
		return result;
	}
	if (offset + count > state->size) {
		count = state->size - offset;
	}
	fs_memcpy(buf, data + offset, count);
	return count;
}

static intptr_t zip_file_pwrite(struct thread_storage *, struct vfs_resolved_file, const void *, size_t, off_t)
{
	return -EROFS;
}

static intptr_t zip_file_flock(struct thread_storage *, struct vfs_resolved_file, int)
{
	return -ENOLCK;
}

static intptr_t zip_file_fsync(struct thread_storage *, struct vfs_resolved_file)
{
	return -EROFS;
}

static intptr_t zip_file_fdatasync(struct thread_storage *, struct vfs_resolved_file)
{
	return -EROFS;
}

static intptr_t zip_file_syncfs(struct thread_storage *, struct vfs_resolved_file)
{
	return -EROFS;
}

static intptr_t zip_file_ftruncate(struct thread_storage *, struct vfs_resolved_file, off_t)
{
	return -EROFS;
}

static intptr_t zip_file_fallocate(struct thread_storage *, struct vfs_resolved_file, int, off_t, off_t)
{
	return -EROFS;
}

static intptr_t zip_file_recvmsg(struct thread_storage *, struct vfs_resolved_file, struct msghdr *, int)
{
	return -ENOTSOCK;
}

static intptr_t zip_file_sendmsg(struct thread_storage *, struct vfs_resolved_file, const struct msghdr *, int)
{
	return -ENOTSOCK;
}

static intptr_t zip_file_fcntl_basic(struct thread_storage *, struct vfs_resolved_file, int cmd, intptr_t)
{
	switch (cmd) {
	case F_GETFL:
		return O_RDONLY;
	case F_SETFL:
		return -EPERM;
	}
	return -ENOSYS;
}

static intptr_t zip_file_fcntl_lock(struct thread_storage *, struct vfs_resolved_file, int cmd, struct flock *)
{
	switch (cmd) {
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_OFD_GETLK:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
		return -ENOLCK;
	}
	return -ENOSYS;
}

static intptr_t zip_file_fchmod(struct thread_storage *, struct vfs_resolved_file, mode_t)
{
	return -EROFS;
}

static intptr_t zip_file_fchown(struct thread_storage *, struct vfs_resolved_file, uid_t, gid_t)
{
	return -EROFS;
}

static intptr_t zip_file_readlink_fd(struct thread_storage *, struct vfs_resolved_file file, char *buf, size_t size)
{
	struct zip_state *state = state_for_fd(file.handle);
	size_t name_size;
	struct vfs_zip_state *zip = get_zip_state();
	const char *name = _zip_get_name_raw(zip->za, state->index, 0, &name_size, NULL);
	if (name_size != 0 && name[name_size-1] == '/') {
		// strip trailing slash, if any
		name_size--;
	}
	if (name_size > size) {
		return -ENAMETOOLONG;
	}
	memcpy(buf, name, name_size);
	return name_size;
}

static intptr_t zip_file_getdents64(struct thread_storage *, struct vfs_resolved_file file, char *buf, size_t size)
{
	struct vfs_zip_state *zip = get_zip_state();
	struct zip_state *state = state_for_fd(file.handle);
	zip_int64_t index = state->index;
	size_t dir_name_size;
	const char *dir_name = _zip_get_name_raw(zip->za, index, 0, &dir_name_size, NULL);
	if (dir_name == NULL) {
		return -EIO;
	}
	if (dir_name_size < 1 || dir_name[dir_name_size-1] != '/') {
		return -ENOTDIR;
	}
	size_t bpos = 0;
	for (zip_int64_t num_entries = zip_get_num_entries(zip->za, 0); state->dent_offset < num_entries; ++state->dent_offset) {
		const char *filename;
		char type;
		size_t filename_len;
		if (state->dent_offset > index) {
			size_t name_size;
			const char *name = _zip_get_name_raw(zip->za, state->dent_offset, 0, &name_size, NULL);
			if (name == NULL) {
				break;
			}
			if ((name_size < dir_name_size) || (fs_memcmp(dir_name, name, dir_name_size) != 0)) {
				break;
			}
			filename = &name[dir_name_size];
			filename_len = name_size - dir_name_size;
			const char *slash = fs_memchr(filename, '/', filename_len);
			if (slash == NULL) {
				// regular file
				type = DT_REG;
			} else {
				if (&slash[1] != &filename[filename_len]) {
					// file in subfolder
					continue;
				}
				// directory
				type = DT_DIR;
				filename_len = slash - filename;
			}
		} else if (state->dent_offset == index) {
			// parent directory
			filename = "..";
			filename_len = 2;
			type = DT_DIR;
		} else {
			// self directory
			filename = ".";
			filename_len = 1;
			type = DT_DIR;
		}
		struct fs_dirent *dirent = (void *)&buf[bpos];
		size_t rec_len = (offsetof(struct fs_dirent, d_name) + filename_len + 1 + 7) & ~7;
		size_t new_bpos = bpos + rec_len;
		if (new_bpos > size) {
			// would exceed buffer
			if (bpos == 0) {
				return -EINVAL;
			}
			return bpos;
		}
		// have space in buffer, fill it
		dirent->d_ino = state->dent_offset;
		dirent->d_off = state->dent_offset;
		dirent->d_reclen = rec_len;
		dirent->d_type = type;
		fs_memcpy(&dirent->d_name[0], filename, filename_len);
		dirent->d_name[filename_len] = '\0';
		// buf[bpos + rec_len - 1] = type;
		bpos = new_bpos;
	}
	return bpos;
}

static intptr_t zip_file_fgetxattr(struct thread_storage *, struct vfs_resolved_file, const char *, void *, size_t)
{
	return -ENOTSUP;
}

static intptr_t zip_file_fsetxattr(struct thread_storage *, struct vfs_resolved_file, const char *, const void *, size_t, int)
{
	return -ENOTSUP;
}

static intptr_t zip_file_fremovexattr(struct thread_storage *, struct vfs_resolved_file, const char *)
{
	return -ENOTSUP;
}

static intptr_t zip_file_flistxattr(struct thread_storage *, struct vfs_resolved_file, void *, size_t)
{
	return -ENOTSUP;
}


off_t shared_get_pointer_file_offset(void *ptr);


static intptr_t zip_file_mmap(struct thread_storage *, struct vfs_resolved_file file, void *addr, size_t length, int prot, int flags, size_t offset)
{
	struct zip_state *state = state_for_fd(file.handle);
	void *data;
	int result = materialize_file_contents(state, &data);
	if (result < 0) {
		return -ESPIPE;
	}
	if ((uintptr_t)data & -PAGE_SIZE) {
		return -EACCES;
	}
	if ((ssize_t)offset < 0) {
		return -EINVAL;
	}
	struct vfs_zip_state *zip = get_zip_state();
	if (data > zip->address && data < zip->address + zip->size) {
		// don't permit writing through to the underlying zip file, always MAP_PRIVATE
		if ((flags & MAP_TYPE) != MAP_PRIVATE) {
			return -EACCES;
		}
		// map from the underlying zip file
		return (intptr_t)fs_mmap(addr, length, prot, flags, PROXY_FD, (data - zip->address) + offset);
	}
	// map out of the shared heap
	// assume the caller won't close the file descriptor before unmapping a region out of it
	return (intptr_t)fs_mmap(addr, length, prot, flags, SHARED_PAGE_FD, shared_get_pointer_file_offset(data) + offset);
}

const struct vfs_path_ops zip_path_ops = {
	.dirfd_ops =
		{
			.socket = zip_file_socket,
			.close = zip_file_close,
			.read = zip_file_read,
			.write = zip_file_write,
			.recvfrom = zip_file_recvfrom,
			.sendto = zip_file_sendto,
			.lseek = zip_file_lseek,
			.readahead = zip_file_readahead,
			.pread = zip_file_pread,
			.pwrite = zip_file_pwrite,
			.flock = zip_file_flock,
			.fsync = zip_file_fsync,
			.fdatasync = zip_file_fdatasync,
			.syncfs = zip_file_syncfs,
			.ftruncate = zip_file_ftruncate,
			.fallocate = zip_file_fallocate,
			.recvmsg = zip_file_recvmsg,
			.sendmsg = zip_file_sendmsg,
			.fcntl_basic = zip_file_fcntl_basic,
			.fcntl_lock = zip_file_fcntl_lock,
			.fchmod = zip_file_fchmod,
			.fchown = zip_file_fchown,
			.fstat = fstat_from_statx,
			.readlink_fd = zip_file_readlink_fd,
			.getdents64 = zip_file_getdents64,
			.fgetxattr = zip_file_fgetxattr,
			.fsetxattr = zip_file_fsetxattr,
			.fremovexattr = zip_file_fremovexattr,
			.flistxattr = zip_file_flistxattr,
			.mmap = zip_file_mmap,
		},
	.mkdirat = zip_path_mkdirat,
	.mknodat = zip_path_mknodat,
	.openat = zip_path_openat,
	.unlinkat = zip_path_unlinkat,
	.renameat2 = zip_path_renameat2,
	.linkat = zip_path_linkat,
	.symlinkat = zip_path_symlinkat,
	.truncate = zip_path_truncate,
	.fchmodat = zip_path_fchmodat,
	.fchownat = zip_path_fchownat,
	.utimensat = zip_path_utimensat,
	.newfstatat = newfstatat_from_statx,
	.statx = zip_path_statx,
	.faccessat = zip_path_faccessat,
	.readlinkat = zip_path_readlinkat,
	.getxattr = zip_path_getxattr,
	.setxattr = zip_path_setxattr,
	.removexattr = zip_path_removexattr,
	.listxattr = zip_path_listxattr,
};
