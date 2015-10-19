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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "crc32.h"
#include "secrets.h"

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))
#define ELF_MAGIC		"\177ELF"
#define GZ_MAGIC		"\x1f\x8b"
#define JFFS2_MAGIC_BITMASK	0x1985
#define MIN(x, y)		((x) < (y) ? (x) : (y))
#define ZLIB_MAGIC		"\x78\x9c"

#define err(fmt, ...) \
	fprintf(stderr, "%s:%u: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

struct mem_ctx {
	const struct mem_ctx *parent;
	const unsigned char *base;
	size_t size;
};

static bool no_cxt2_sanity;

static ptrdiff_t compute_offset(const struct mem_ctx *ctx, const void *ptr)
{
	if (ctx->parent)
		return compute_offset(ctx->parent, ptr);

	return ptr - (const void *)ctx->base;
}

static void hexdump(const char *str, const unsigned char *buf, size_t n)
{
	size_t i;

	printf("%s:", str);

	for (i = 0; i < n; i++)
		printf(" %02x", buf[i]);

	printf("\n");
}

static unsigned short le16tohp(const void *ptr)
{
	return le16toh(*(const unsigned short *)ptr);
}

static unsigned int le32tohp(const void *ptr)
{
	return le32toh(*(const unsigned int *)ptr);
}

static void trim_strcpy(char *dst, const unsigned char *src, size_t n)
{
	bool trim = true;

	if (n == 0)
		return;

	n--;
	dst[n] = '\0';

	while (n > 0) {
		n--;
		if (trim && src[n] == ' ') {
			dst[n] = '\0';
		} else if (src[n] == '/') {
			dst[n] = '-';
		} else {
			dst[n] = src[n];
			trim = false;
		}
	}
}

static void save_buffer(const unsigned char *buf, size_t size, const char *prefix)
{
	char filename[FILENAME_MAX];
	const char *suffix = "bin";
	FILE *f;

	if (size < 4) {
		err("Invalid size!");
		return;
	}

	if (!memcmp(buf, ELF_MAGIC, 4))
		suffix = "elf";
	else if (le16tohp(buf) == JFFS2_MAGIC_BITMASK)
		suffix = "jffs2";
	else if (!memcmp(buf, "LZ77", 4))
		suffix = "lz77";
	else if (!memcmp(buf, GZ_MAGIC, 2))
		suffix = "tgz";
	else if (!memcmp(buf, ZLIB_MAGIC, 2))
		suffix = "zlib";

	snprintf(filename, FILENAME_MAX, "%s.%s", prefix, suffix);
	f = fopen(filename, "w");
	if (f) {
		fwrite(buf, size, 1, f);
		fclose(f);
	}
}

static int process_cxt2(const struct mem_ctx *ctx, const char *prefix)
{
	unsigned int tag, len;
	const unsigned char *val;
	size_t i = 4;
	char subprefix[42];
	unsigned int addr = 0, crc = 0;

	while (ctx->size >= i + 8) {
		tag = le32tohp(&ctx->base[i]);
		i += 4;
		len = le32tohp(&ctx->base[i]);
		i += 4;

		if (ctx->size < i + len)
			return -1;

		val = &ctx->base[i];
		i += len;

		//printf("T: %#x L: %#x ", tag, len);
		//hexdump("V", val, MIN(64, len));

		switch (tag) {
		case 0:		// end of TLV
			return 1;
		case 1:		// uncompressed size?
			break;
		case 2:		// crc
			if (len == 4)
				crc = le32tohp(val);
			break;
		case 3:		// load address / entry point
			if (len == 4)
				addr = le32tohp(val);
			break;
		case 7:		// type?
			break;
		case 8:		// description
			break;
		case 16:	// payload
			snprintf(subprefix, sizeof(subprefix), "%s_%08X", prefix, addr);
			if (!no_cxt2_sanity && (crc32(CRC32_LE, CRC32_POLY_LE, ~0, val, len) ^ 0xffffffff) != crc) {
				err("CRC32 mismatch at '%s' [offset=%#tx]", subprefix, compute_offset(ctx, val));
				return -1;
			}
			save_buffer(val, len, subprefix);
			break;
		}
	}

	if (!no_cxt2_sanity && le32tohp(&ctx->base[i]) != 0) {
		err("Missing TLV end marker! (%#X)", le32tohp(&ctx->base[i]));
		return -1;
	}

	return 1;
}

static int process_mh_data(const struct mem_ctx *ctx, const unsigned char *buf, size_t size, const char *prefix)
{
	if (size < 4) {
		err("Invalid size!");
		return -1;
	}

	if (!memcmp(buf, "CXT2", 4)) {
		struct mem_ctx cxt2_ctx = {
			.base = buf,
			.size = size,
			.parent = ctx,
		};
		return process_cxt2(&cxt2_ctx, prefix);
	}

	save_buffer(buf, size, prefix);
	return 1;
}

static int process_mh_subpacket(const struct mem_ctx *ctx, size_t offset, const char *prefix)
{
	unsigned char md[MD5_DIGEST_LENGTH];
	const unsigned char *mh_header;
	unsigned int mh_offs, mh_len, mh_flash;
	unsigned int i;
	char subprefix[33];

	if (ctx->size < offset + 0x20) {
		err("Invalid size!");
		return -1;
	}

	mh_header = &ctx->base[offset];
	if (le32tohp(&mh_header[0]) == 0)
		return 0;
	mh_offs = le32tohp(&mh_header[0x4]);
	mh_len = le32tohp(&mh_header[0x8]);
	mh_flash = le32tohp(&mh_header[0xc]);

	printf("    mh[%zu]: %c%c%c%c: offs=%08x, len=%8d, flash=%08x md5sum=", offset / 0x40,
		mh_header[0],
		mh_header[1],
		mh_header[2],
		mh_header[3],
		mh_offs,
		mh_len,
		mh_flash);

	for (i = 0; i < 0x10; i++)
		printf("%02X", mh_header[i + 0x10]);
	printf("\n");

	if (!(mh_offs && mh_len))
		return 1;

	MD5(&ctx->base[mh_offs], mh_len, md);
	if (memcmp(md, &mh_header[0x10], MD5_DIGEST_LENGTH)) {
		err("MD5 mismatch at mh '%.4s'", ctx->base);
		return -1;
	}

	snprintf(subprefix, sizeof(subprefix), "%s_%08X_%.4s", prefix, mh_flash, mh_header);
	return process_mh_data(ctx, &ctx->base[mh_offs], mh_len, subprefix);
}

static int process_mh_packet(const struct mem_ctx *ctx, const char *prefix)
{
	const unsigned char *mem = ctx->base;
	size_t offset;
	int ret;

	printf("  MH packet:\n");
	for (offset = 0; le32tohp(&mem[offset]) != 0; offset += 0x40) {
		ret = process_mh_subpacket(ctx, offset, prefix);
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;
	}
	printf("\n");

	return 1;
}

static int process_section(const struct mem_ctx *ctx, size_t offset);

static int process_packet(const struct mem_ctx *ctx, const unsigned char header[0x40], const char *prefix)
{
	const unsigned char *mem = ctx->base;

	if (ctx->size < 0x40) {
		err("Invalid size!");
		return -1;
	}

	if (!memcmp(mem, "uart", 4))
		return process_mh_packet(ctx, prefix);

	if (!memcmp(&header[0], &mem[0], 8) &&
	    !memcmp(&header[20], &mem[20], 10))
		return process_section(ctx, 0);

	save_buffer(ctx->base, ctx->size, prefix);
	return 1;
}

static int process_section(const struct mem_ctx *ctx, size_t offset)
{
	const unsigned char *mem;
	unsigned int sh_offset, sh_size, crc;
	char name[9];
	char version[11];
	char prefix[20];

	if (ctx->size < offset + 0x40) {
		err("Invalid size!");
		return -1;
	}

	mem = &ctx->base[offset];
	sh_offset = le32tohp(&mem[8]);
	sh_size = le32tohp(&mem[12]);

	if (sh_offset == 0 || sh_offset == 0xffffffff)
		return 0;
	if (sh_size == 0 || sh_size == 0xffffffff)
		return 0;
	if (ctx->size < sh_offset + sh_size) {
		err("Invalid size!");
		return -1;
	}

	crc = le32tohp(&mem[16]);

	trim_strcpy(name, &mem[0], sizeof(name));
	trim_strcpy(version, &mem[20], sizeof(version));
	snprintf(prefix, sizeof(prefix), "%s_%s", name, version);

	printf("Section:\n");
	printf("  name: '%s'\n", name);
	printf("  version: '%s'\n", version);
	printf("  offset: %#x (%u)\n", sh_offset, sh_offset);
	printf("  size: %#x (%u)\n", sh_size, sh_size);
	printf("  crc32: %#x\n", crc);
	printf("\n");

	struct mem_ctx pkt;

	pkt.base = &ctx->base[sh_offset];
	pkt.size = sh_size;
	pkt.parent = ctx;

	if (crc32(CRC32_BE, CRC32_POLY_BE, ~0, pkt.base, pkt.size) != crc) {
		err("CRC32 mismatch at section '%.8s'", &mem[0]);
		return -1;
	}

	return process_packet(&pkt, mem, prefix);
}

static int process_sections(const struct mem_ctx *ctx, size_t offset)
{
	int ret;

	for (;;) {
		ret = process_section(ctx, offset);
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;
		offset += 0x40;
	}

	return 1;
}

static void process_mde_fs(const struct mem_ctx *ctx)
{
	save_buffer(ctx->base, ctx->size, "MDE_FS");
}

static int process_file_ch606(const struct mem_ctx *ctx)
{
	const unsigned char *mde_header = ctx->base;
	struct {
		char version[5];
		unsigned char hardware[4];
		unsigned int mde_fs_offset;
		unsigned int mde_fs_size;
		unsigned int mh_offset;
		unsigned int mh_size;
		char format[5];
	} mde;
	unsigned int i;

	no_cxt2_sanity = true;

	memset(&mde, 0, sizeof(mde));

	mde_header = ctx->base;

	hexdump("MDE", mde_header, 0x3c);

	memcpy(mde.format, &mde_header[0x20], 4);
	memcpy(mde.version, &mde_header[0x24], 4);
	memcpy(mde.hardware, &mde_header[0x28], 4);
	mde.mde_fs_offset = le32tohp(&mde_header[0x10]);
	mde.mde_fs_size = le32tohp(&mde_header[0x14]);
	mde.mh_offset = le32tohp(&mde_header[0x2c]);
	mde.mh_size = le32tohp(&mde_header[0x30]);

	printf("MDE Packet information:\n");
	printf("  version:   %s\n",
		mde.version);
	printf("  hardware:  %02x %02x %02x %02x\n",
		mde.hardware[0],
		mde.hardware[1],
		mde.hardware[2],
		mde.hardware[3]);
	printf("  MDE_FS:    %08x, len=%d\n",
		mde.mde_fs_offset,
		mde.mde_fs_size);
	printf("  MH         %08x, len=%d\n",
		mde.mh_offset,
		mde.mh_size);

	if (mde.mde_fs_offset != 0 && mde.mde_fs_size != 0) {
		printf("  MDE_FS Magic: %.4s\n", &ctx->base[mde.mde_fs_offset]);	// LZ77
		const struct mem_ctx mdefs_ctx = {
			.base = &ctx->base[mde.mde_fs_offset],
			.size = mde.mde_fs_size,
			.parent = ctx,
		};
		process_mde_fs(&mdefs_ctx);
	}

	if (mde.mh_offset != 0 && mde.mh_size != 0) {
		if (!strcmp(mde.format, "pUSB")) {
			const struct mem_ctx mh_ctx = {
				.base = &ctx->base[mde.mh_offset],
				.size = mde.mh_size,
				.parent = ctx,
			};
			process_mh_packet(&mh_ctx, "MH");
		} else if (!strcmp(mde.format, "pTFT")) {
			for (i = 0; i < 5; i++) {
				const char types[][5] = { "uart", "unkn", "linx", "rtfs", "unkn" };
				const unsigned char *mh_header = &ctx->base[mde.mh_offset + i * 8];
				const char *asc_type = types[4];
				unsigned int mh_offs, mh_len;
				char prefix[17];

				if (i < ARRAY_SIZE(types))
					asc_type = types[i];

				mh_offs = le32tohp(&mh_header[0]);
				mh_len = le32tohp(&mh_header[0x4]);
				printf("    mh[%d]: %s: offs=%08x, len=%8d\n", i, asc_type, mh_offs, mh_len);

				if (!(mh_offs && mh_len))
					continue;

				snprintf(prefix, sizeof(prefix), "MH_%08x_%s", mh_offs, asc_type);
				process_mh_data(ctx, &ctx->base[mh_offs], mh_len, prefix);
			}
		}
	}

	return 0;
}

static int process_file_ch610(const struct mem_ctx *ctx)
{
	if (ctx->size < 0x10) {
		err("Invalid size!");
		return -1;
	}

	printf("File header:\n");
	printf("  hardware:  '%.8s'\n", &ctx->base[0]);
	printf("  version:   '%.8s'\n", &ctx->base[8]);
	printf("\n");

	return process_sections(ctx, 0x10);
}

struct fw_gen {
	const unsigned char hwid[8];
	int (*func)(const struct mem_ctx *ctx);
};

static const struct fw_gen fw_types[] = {
	{
		.hwid = "Metz MDE",
		.func = process_file_ch606,
	}, {
		.hwid = "METZ610 ",
		.func = process_file_ch610,
	}, {
		.hwid = "METZ613 ",
		.func = process_file_ch610,
	},
};

static int process_mem(unsigned char *mem, size_t size)
{
	unsigned int offsets[] = { 0, 32 };
	struct mem_ctx ctx;
	unsigned int i, j, k;
	unsigned char mebk[16];
	bool have_mebk;
	AES_KEY key;

	have_mebk = secret_find("mebk", mebk, sizeof(mebk));
	if (have_mebk)
		AES_set_decrypt_key(mebk, 128, &key);

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		if (offsets[i] >= size) {
			err("Cannot read packet file header!");
			return -1;
		}

		if (offsets[i] == 32 && have_mebk) {
			unsigned char sha[32];
			SHA256(&mem[32], size - 32, sha);
			if (memcmp(mem, sha, 32)) {
				err("Invalid SHA256 hash!");
				return -1;
			}
		}

		ctx.base = &mem[offsets[i]];
		ctx.size = size - offsets[i];
		ctx.parent = NULL;
		for (j = 0; j < ARRAY_SIZE(fw_types); j++)
			if (!memcmp(ctx.base, fw_types[j].hwid, 8))
				return fw_types[j].func(&ctx);

		if (offsets[i] == 0 && have_mebk) {
			for (k = 0; k < 32; k += 16)
				AES_decrypt(&mem[k], &mem[k], &key);

			for (j = 0; j < ARRAY_SIZE(fw_types); j++) {
				if (!memcmp(ctx.base, fw_types[j].hwid, 8)) {
					for (k = 32; k < (size & ~15); k += 16)
						AES_decrypt(&mem[k], &mem[k], &key);
					return fw_types[j].func(&ctx);
				}
			}
		}
	}

	err("Invalid header!");
	return -1;
}

static int process_file(int fd)
{
	struct stat st;
	void *mem;
	int ret;

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return -1;
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	ret = process_mem(mem, st.st_size);

	munmap(mem, st.st_size);
	return ret < 0 ? ret : 0;
}

int main(int argc, char *argv[])
{
	int fd;
	int i;
	int ret = 0;

	for (i = 1; i < argc; i++) {
		printf("Input file: '%s'\n\n", argv[i]);
		fd = open(argv[i], O_RDONLY);
		if (fd < 0) {
			perror(argv[i]);
			return 1;
		}

		ret = process_file(fd);
		close(fd);
		if (ret)
			break;
	}

	return !!ret;
}
