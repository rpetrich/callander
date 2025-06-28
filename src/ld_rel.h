static inline const char *apply_origin(const char *self_path, const char *path, char buf[PATH_MAX])
{
	if (fs_strncmp(path, "$ORIGIN/", sizeof("$ORIGIN/") - 1) != 0) {
		return path;
	}
	const char *suffix = &path[sizeof("$ORIGIN/") - 1];
	size_t self_len = fs_strlen(self_path);
	while (fs_strncmp(suffix, "../", 3) == 0) {
		suffix += 3;
		while (self_path[--self_len] != '/' && self_len > 0) {
		}
		if (self_len == 0) {
			break;
		}
	}
	fs_memcpy(buf, self_path, self_len + 1);
	fs_memcpy(&buf[self_len + 1], suffix, fs_strlen(suffix) + 1);
	return buf;
}
