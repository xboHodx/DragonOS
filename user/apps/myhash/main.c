#include <stdio.h>
#include <string.h>
#include "file_reader.h"
#include "hash_algo.h"
#include "MD5.h"
#include "SHA256.h"

void print_hash(const char* hash_algo_name, const uint8_t* hash, size_t digest_size){
    printf("%s:", hash_algo_name);
    for (size_t i = 0; i < digest_size; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

void cal_hash(HashAlgoType algo_type, const char* files[], size_t filenum){
    HashJob job;
    switch (algo_type)
    {
    case HASH_ALGO_MD5:
        job.algo = &MD5_ALGO;
        break;
    case HASH_ALGO_SHA256:
        job.algo = &SHA256_ALGO;
        break;
    default:
        printf("Unsupported hash algorithm type: %d\n", algo_type);
        return;
    }

    job.ctx = malloc(job.algo->ctx_size);
    if (!job.ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return;
    }
    
    job.algo->init(job.ctx);

    for (size_t i = 0; i < filenum; i++){
        if(read_and_process_file(&job, files[i], 4096) < 0){
            // 错误信息已经在read_and_process_file中打印
            free(job.ctx);
            return;
        }
    }

    // 使用算法定义的摘要大小来分配结果缓冲区
    uint8_t* result = malloc(job.algo->digest_size);
    if (!result) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(job.ctx);
        return;
    }
    
    job.algo->final(job.ctx, result);

    // 使用算法结构中的名称和摘要大小打印结果
    print_hash(job.algo->name, result, job.algo->digest_size);

    free(result);
    free(job.ctx);
}

void print_help(){
    printf("Usage: myhash <command> [<args>]\n");
    printf("These are commands used in various situations:\n");
    printf("calculate the hash value of the file\n");
    printf("    -c <algoname> <filename1> <filename2> ...\n");
    printf("view help\n");
    printf("    -h\n");
}

int main(int argc, char const *argv[])
{
    if(argc < 2) {
        print_help();
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0){
        print_help();
        return 1;
    }
    if (strcmp(argv[1], "-c") == 0){
        if(argc < 4) {
            printf("Usage: myhash -c <algoname> <filename1> <filename2> ...\n");
            return 1;
        }

        if(strcmp(argv[2], "md5") == 0){
            cal_hash(HASH_ALGO_MD5, argv + 3, argc - 3);
            return 0;
        }
        else if(strcmp(argv[2], "sha256") == 0){
            cal_hash(HASH_ALGO_SHA256, argv + 3, argc - 3);
            return 0;
        }

        printf("Error: There isn't a hash algorithm named %s.\n", argv[2]);
        printf("    use: md5 / sha256\n");
        return 1;
    }

    return 0;
}