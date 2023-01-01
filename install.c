#include "install.h"

#include <linux/limits.h>

#include "freestanding.h"
#include "axon.h"

static void install_at_lib_path(const char *path)
{
	// Find ELF interpreters and rename them so that axon can highjack
	// loads of dynamically linked binaries
	int dirfd = fs_open(path, O_RDONLY | O_DIRECTORY, 0);
	if (dirfd < 0) {
		return;
	}
	for (;;) {
		char buf[8192];
		int count = fs_getdents(dirfd, (struct fs_dirent *)&buf[0], sizeof(buf));
		if (count <= 0) {
			break;
		}
		for (int offset = 0; offset < count; ) {
			const struct fs_dirent *ent = (const struct fs_dirent *)&buf[offset];
			const char *name = ent->d_name;
			if (fs_strncmp(name, "ld-", 3) == 0) {
				size_t len = fs_strlen(name);
				if (len > 5 && fs_strncmp(&name[len-5], ".so.", 4) == 0) {
					char new_path[PATH_MAX];
					fs_memcpy(new_path, name, len);
					fs_memcpy(&new_path[len], ".axon", sizeof(".axon"));
					int result = fs_renameat(dirfd, name, dirfd, new_path);
					if (result < 0) {
						ERROR("error renaming existing interpreter", fs_strerror(result));
					}
					result = fs_symlinkat("/bin/axon", dirfd, name);
					if (result < 0) {
						ERROR("error symlinking as interpreter", fs_strerror(result));
					}
				}
			}
			offset += ent->d_reclen;
		}
    }
	fs_close(dirfd);
}

void install(void)
{
	install_at_lib_path("/lib");
	install_at_lib_path("/lib64");
}
