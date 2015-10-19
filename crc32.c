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
 *
 * Based on "Improved Branch-free" CRC32 implementation by Stephan Brumme
 *   http://create.stephan-brumme.com/crc32/#fastest-bitwise-crc32
 */

#include <stdbool.h>
#include "crc32.h"

unsigned int crc32(enum crc32_mode m, enum crc32_poly p, unsigned int val,
                   const unsigned char *buf, size_t count)
{
	const unsigned char *end = buf + count;
	unsigned long i;

	while (buf < end) {
		if (m == CRC32_BE) {
			val ^= *buf++ << 24;
			for (i = 0; i < 8; i++)
				val = (val << 1) ^ (-(bool)(val & (1 << 31)) & p);
		} else {
			val ^= *buf++;
			for (i = 0; i < 8; i++)
				val = (val >> 1) ^ (-(val & 1) & p);
		}
	}

	return val;
}
