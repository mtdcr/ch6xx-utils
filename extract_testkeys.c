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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/aes.h>
#include "secrets.h"

static void process_file(const AES_KEY *key, const char *filename)
{
	unsigned char *m;
	struct stat st;
	unsigned char *buf;
	unsigned int i, j;
	int fd;

	printf("reading '%s'\n", filename);
	fd = open(filename, O_RDONLY);
	assert(fd >= 0);
	assert(fstat(fd, &st) == 0);

	m = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	assert(m != MAP_FAILED);

	buf = malloc(st.st_size);
	assert(buf != NULL);

	for (i = 0; i < 16; i++) {
		for (j = 0; j < ((st.st_size - i) & ~15); j += 16)
			AES_decrypt(&m[i + j], &buf[j], key);
		secrets_search(buf, (st.st_size - i) & ~15, 16);
	}

	free(buf);
	munmap(m, st.st_size);
	close(fd);
}

int main(int argc, char *argv[])
{
	unsigned char buf[16];
	AES_KEY dkey;
	int i;

	for (i = 0; i < 16; i++)
		buf[i] = i;

	AES_set_decrypt_key(buf, 128, &dkey);

	for (i = 1; i < argc; i++)
		process_file(&dkey, argv[i]);

	return 0;
}
