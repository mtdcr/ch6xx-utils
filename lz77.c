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
 * Based on code from "The Data Compression Book" by Mark Nelson.
 *  http://marknelson.us/code-use-policy/
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define INDEX_BIT_COUNT		14
#define LENGTH_BIT_COUNT	6
#define BREAK_EVEN		2
#define WINDOW_SIZE		(1 << INDEX_BIT_COUNT)
#define END_OF_STREAM		0
#define MOD_WINDOW(A)		((A) & (WINDOW_SIZE - 1))

typedef struct {
	unsigned char mask;
	unsigned char rack;
	unsigned int rptr;
	unsigned int size;
	int (*input)(void *);
	void *priv;
} BIT_FILE;

struct mdefs_state {
	unsigned int crc;
	unsigned int size;
	int (*output)(int, void *);
};

static unsigned char lz77_status;

static void InitInputBitFile(BIT_FILE *bit_file, size_t size, void *priv)
{
	bit_file->size = size;
	bit_file->rack = 0;
	bit_file->mask = 0x80;
	bit_file->rptr = 0;
	bit_file->input = (int(*)(void *))fgetc;
	bit_file->priv = priv;
}

static long InputBits(BIT_FILE *bit_file, unsigned int bit_count)
{
	unsigned long mask;
	long return_value;
	int c;

	mask = 1 << (bit_count - 1);
	return_value = 0;

	while (mask != 0) {
		if (bit_file->mask == 0x80) {
			if (bit_file->rptr >= bit_file->size) {
				lz77_status++;
				break;
			}

			c = bit_file->input(bit_file->priv);
			bit_file->rptr++;
			if (c == EOF) {
				lz77_status++;
				break;
			}
			bit_file->rack = c;
		}

		if (bit_file->rack & bit_file->mask)
			return_value |= mask;

		mask >>= 1;
		bit_file->mask >>= 1;
		if (bit_file->mask == 0)
			bit_file->mask = 0x80;
	}

	if (lz77_status) {
		return_value = -1;
		bit_file->rack = 0xff;
	}

	return return_value;
}

static bool ExpandFile(BIT_FILE *input, struct mdefs_state *output)
{
	unsigned char window[WINDOW_SIZE];
	int i;
	int current_position;
	int c;
	int match_length;
	int match_position;

	memset(window, 0, sizeof(window));

	lz77_status = 0;
	current_position = 1;

	do {
		if (InputBits(input, 1)) {
			c = InputBits(input, 8);
			output->output(c, output);
			window[current_position] = c;
			current_position = MOD_WINDOW(current_position + 1);
		} else {
			match_position = InputBits(input, INDEX_BIT_COUNT);
			if (match_position == END_OF_STREAM)
				return true;

			match_length = InputBits(input, LENGTH_BIT_COUNT);
			match_length += BREAK_EVEN;

			for (i = 0; i <= match_length; i++) {
				c = window[MOD_WINDOW(match_position + i)];

				output->output(c, output);
				window[current_position] = c;
				current_position = MOD_WINDOW(current_position + 1);
			}
		}
	} while (lz77_status == 0);

	return false;
}

static int mdefs_putc(int c, void *priv)
{
	struct mdefs_state *ms = priv;

	if (ms->size >= 12) {
		putchar(c);
		ms->crc += c << (((ms->size ^ 3) & 3) << 3);
	}

	ms->size++;
	return c;
}

static void mdefs_state_init(struct mdefs_state *ctx)
{
	ctx->crc = 0;
	ctx->size = 0;
	ctx->output = mdefs_putc;
}

static bool decompress_image(FILE *in, size_t size)
{
	BIT_FILE input;
	struct mdefs_state output;

	InitInputBitFile(&input, size, in);
	mdefs_state_init(&output);

	if (ExpandFile(&input, &output)) {
		fprintf(stderr, "ok. crc=%#x\n", output.crc);
		return true;
	}

	return false;
}

int main(int argc, char *argv[])
{
	unsigned char header[4];
	long size;
	FILE *f;

	assert(argc == 2);

	f = fopen(argv[1], "rb");
	if (f == NULL) {
		perror(argv[1]);
		return 1;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	assert(fread(header, 4, 1, f) == 1);
	assert(!memcmp(header, "LZ77", 4));

	if (!decompress_image(f, size - 4))
		fprintf(stderr, "decompression failed\n");

	fclose(f);
	return 0;
}
