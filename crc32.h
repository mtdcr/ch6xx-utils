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

#ifndef _crc32_h_
#define _crc32_h_

#include <stddef.h>

enum crc32_mode {
	CRC32_BE,
	CRC32_LE,
};

enum crc32_poly {
	CRC32_POLY_BE = 0x04c11db7,
	CRC32C_POLY_LE = 0x82F63B78,
	CRC32_POLY_LE = 0xedb88320,
};

unsigned int crc32(enum crc32_mode m, enum crc32_poly p, unsigned int val,
                   const unsigned char *buf, size_t count);

#endif /* _crc32_h_ */
