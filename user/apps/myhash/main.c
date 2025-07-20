#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "file_reader.h"
#include "hash_algo.h"
#include "MD5.h"
#include "SHA256.h"

pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

void print_hash(const char* hash_algo_name, const uint8_t* hash, size_t digest_size, const char* files[], size_t filenum)
{
    pthread_mutex_lock(&print_lock);
    
    for (size_t i = 0; i < filenum; i++)
    {
        printf("%s ", files[i]);
    }
    printf("%s:", hash_algo_name);
    for (size_t i = 0; i < digest_size; i++)
        printf("%02x", hash[i]);
    printf("\n");

    pthread_mutex_unlock(&print_lock);
}

void cal_hash(HashAlgoType algo_type, const char* files[], size_t filenum)
{
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
        if(read_and_process_file(&job, files[i], sysconf(_SC_PAGESIZE)) < 0){
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
    print_hash(job.algo->name, result, job.algo->digest_size, files, filenum);

    free(result);
    free(job.ctx);
}

typedef struct{
    HashAlgoType algo_type;
    const char** files;
    size_t filenum;
} ThreadData;

void* thread_cal(void* args)
{
    cal_hash(((ThreadData*)args)->algo_type, ((ThreadData*)args)->files, ((ThreadData*)args)->filenum);
    return NULL;
}

void cal_separately(HashAlgoType algo_type, const char* files[], size_t filenum)
{
    pthread_t threads[filenum];
    ThreadData *thread_args = malloc(filenum * sizeof(ThreadData));
    
    if (!thread_args) {
        fprintf(stderr, "Error: Memory allocation failed for thread arguments\n");
        return;
    }
    
    // 创建线程计算每个文件的哈希值
    for (size_t i = 0; i < filenum; i++)
    {
        thread_args[i].algo_type = algo_type;
        thread_args[i].files = files + i;
        thread_args[i].filenum = 1;
        
        if (pthread_create(&threads[i], NULL, thread_cal, &thread_args[i]) != 0) {
            fprintf(stderr, "Error: Failed to create thread %zu\n", i);
            // 清理已创建的线程
            for (size_t j = 0; j < i; j++) {
                pthread_cancel(threads[j]);
                pthread_join(threads[j], NULL);
            }
            free(thread_args);
            return;
        }
    }
    
    // 等待所有线程完成
    for (size_t i = 0; i < filenum; i++)
    {
        pthread_join(threads[i], NULL);
    }
    
    free(thread_args);
}

void print_help(){
    printf("Usage: myhash <command> [<args>]\n");
    printf("These are commands used in various situations:\n");
    printf("calculate the hash value of the files\n");
    printf("    -c <algoname> <filename1> <filename2> ...\n");
    printf("calculate the hash value of each file separately\n");
    printf("    -s <algoname> <filename1> <filename2> ...\n");
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
    if (strcmp(argv[1], "-s") == 0){
        // 该功能在dragonos中会触发 一直输出
        // [ WARN ] (src/syscall/mod.rs:840)        SYS_RT_SIGTIMEDWAIT has not yet been implemented
        if(argc < 4) {
            printf("Usage: myhash -s <algoname> <filename1> <filename2> ...\n");
            return 1;
        }

        if(strcmp(argv[2], "md5") == 0){
            cal_separately(HASH_ALGO_MD5, argv + 3, argc - 3);
            return 0;
        }
        else if(strcmp(argv[2], "sha256") == 0){
            cal_separately(HASH_ALGO_SHA256, argv + 3, argc - 3);
            return 0;
        }

        printf("Error: There isn't a hash algorithm named %s.\n", argv[2]);
        printf("    use: md5 / sha256\n");
        return 1;
    }

    printf("Error: Unknown command '%s'.\n", argv[1]);
    print_help();
    return 0;
}