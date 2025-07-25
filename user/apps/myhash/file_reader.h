#ifndef FILE_READER_H
#define FILE_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "hash_algo.h"

int read_and_process_file(HashJob *job, const char *filename, size_t block_size);

#endif