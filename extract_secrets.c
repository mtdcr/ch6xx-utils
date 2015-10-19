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
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "secrets.h"

int main(int argc, char *argv[])
{
	unsigned char *m;
	struct stat st;
	int fd;

	assert(argc == 2);
	fd = open(argv[1], O_RDONLY);
	assert(fd >= 0);
	assert(fstat(fd, &st) == 0);

	m = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	assert(m != MAP_FAILED);

	secrets_search(m, st.st_size, 4);

	munmap(m, st.st_size);
	close(fd);
	return 0;
}
