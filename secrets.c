/*
 * Copyright 2015 Andreas Oberritter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _BSD_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "secrets.h"

#define MIN(a, b)	((a) < (b) ? (a) : (b))

static inline unsigned int align(unsigned int n, unsigned int p)
{
	p -= 1;
	return (n + p) & ~p;
}

static bool secret_read(int fd, unsigned char *buf, size_t n)
{
	struct stat st;
	ssize_t ret;

	if (fstat(fd, &st) != 0) {
		perror("fstat");
		return false;
	}

	if ((size_t)st.st_size != n)
		return false;

	ret = read(fd, buf, n);
	if (ret < 0) {
		perror("read");
		return false;
	}

	return (size_t)ret == n;
}

static const char *secret_path(void)
{
	static const char default_prefix[] = "secrets";
	const char *env;
	struct stat st;

	env = getenv("SECRETS");
	if (env && stat(env, &st) == 0 && S_ISDIR(st.st_mode))
		return env;

	return default_prefix;
}

static ssize_t secret_write(const unsigned char *buf, size_t n)
{
	char filename[FILENAME_MAX];
	unsigned char sha[0x20];
	unsigned int len;
	int fd;

	len = be32toh(*(const unsigned int *)&buf[4]);
	if (len > MIN(n - 0x30, 0x20000))
		return -1;

	SHA256(&buf[0x30], len, sha);
	if (memcmp(sha, &buf[0x10], 0x20))
		return -1;

	snprintf(filename, sizeof(filename), "%s/%.4s.bin", secret_path(), buf);
	printf("writing '%s'\n", filename);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror(filename);
		return align(len + 0x30, 16);
	}

	if (write(fd, &buf[0x30], len) < 0)
		perror("write");

	close(fd);
	return align(len + 0x30, 16);
}

static size_t secrets_write(const unsigned char *m, size_t n)
{
	ssize_t len;
	size_t i;

	for (i = 0; i < n; i += len) {
		len = secret_write(&m[i], n - i);
		if (len < 0)
			break;
	}

	return i;
}

void secrets_search(const unsigned char *m, size_t n, size_t step)
{
	size_t len, offset;

	for (offset = 0; offset < n; offset += len ? len : step)
		len = secrets_write(&m[offset], n - offset);
}

bool secret_find(const char *name, unsigned char *buf, size_t n)
{
	char filename[FILENAME_MAX];
	bool ret;
	int fd;

	snprintf(filename, sizeof(filename), "%s/%s.bin", secret_path(), name);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			perror(filename);
		return false;
	}

	ret = secret_read(fd, buf, n);
	close(fd);
	return ret;
}
