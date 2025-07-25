#include "file_reader.h"

// 按block_size大小逐次读取文件，然后交给算法处理
int read_and_process_file(HashJob *job, const char *filename, size_t block_size){
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error: Failed to open file '%s': %s\n", filename, strerror(errno));
        return -1;
    }

    unsigned char *buffer = (unsigned char *)malloc(block_size);
    if (!buffer) {
        fprintf(stderr, "Error: Memory allocation failed: %s\n", strerror(errno));
        fclose(fp);
        return -1;
    }

    // fseek(fp, 0, SEEK_END);
    // size_t file_size = ftell(fp);
    // fseek(fp, 0, SEEK_SET);

    size_t bytes_read;
    // total_read = 0;
    // printf("Processing %s : 000.00%%", job->row_number, filename);
    while ((bytes_read = fread(buffer, 1, block_size, fp)) > 0)
    {
        job->algo->update(job->ctx, buffer, bytes_read);
        // printf("Processing %s : %6.2f%%", job->row_number, filename, (double)total_read / file_size * 100);
    }

    // 检查是否因为错误而结束
    if (ferror(fp)) {
        printf("Error: Failed to read file '%s': %s\n", filename, strerror(errno));
        free(buffer);
        fclose(fp);
        return -1;
    }

    free(buffer);
    fclose(fp);
    return 0;
}

