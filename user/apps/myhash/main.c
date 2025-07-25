#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "file_reader.h"
#include "hash_algo.h"
#include "MD5.h"
#include "SHA256.h"

#define CMD_DELIMITER ","
pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

void print_hash(const char *hash_algo_name, const uint8_t *hash, size_t digest_size, const char *files[], size_t filenum)
{
    pthread_mutex_lock(&print_lock);
    printf("\r\033[2K");
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

void cal_hash(HashJob *job)
{
    job->ctx = malloc(job->algo->ctx_size);
    if (!job->ctx)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return;
    }

    // 初始化算法上下文
    job->algo->init(job->ctx);

    for (size_t i = 0; i < job->filenum; i++)
    {
        if (read_and_process_file(job, job->files[i], sysconf(_SC_PAGESIZE)) < 0)
        {
            // 错误信息已经在read_and_process_file中打印
            free(job->ctx);
            return;
        }
    }

    // 使用算法定义的摘要大小来分配结果缓冲区
    uint8_t *result = malloc(job->algo->digest_size);
    if (!result)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(job->ctx);
        return;
    }

    // 完成哈希计算
    job->algo->final(job->ctx, result);

    // 使用算法结构中的名称和摘要大小打印结果
    print_hash(job->algo->name, result, job->algo->digest_size, job->files, job->filenum);

    free(result);
    free(job->ctx);
}

void *thread_cal(void *job)
{
    cal_hash((HashJob *)job);
    return NULL;
}

void cal_separately(const HashAlgo *algo, int argc, char const *argv[])
{
    int job_cnt = 0;
    for (size_t i = 0; i < argc; i++){
        if(strcmp(argv[i], CMD_DELIMITER) != 0){
            if(i == 0 || strcmp(argv[i - 1], CMD_DELIMITER) == 0){
                ++job_cnt;
            }
        }
    }

    if (job_cnt == 0){
        fprintf(stderr, "Error: Input cannot all be |\n");
        return;
    }

    pthread_t threads[job_cnt];
    HashJob *jobs = malloc(job_cnt * sizeof(HashJob));

    if (!jobs){
        fprintf(stderr, "Error: Memory allocation failed for thread arguments\n");
        return;
    }

    int job_cnt2 = 0;
    for (size_t i = 0; i < argc; i++) {
        if(strcmp(argv[i], CMD_DELIMITER) != 0){
            if (i == 0 || strcmp(argv[i - 1], CMD_DELIMITER) == 0) {
                job_cnt2++;
                jobs[job_cnt2 - 1].files = argv + i;
                jobs[job_cnt2 - 1].filenum = 1;
            }
            else {
                jobs[job_cnt2 - 1].filenum++;
            }
        }
    }

    // 清屏并隐藏光标
    // printf("\033[2J\033[?25l");

    // 创建线程计算每个任务的哈希值
    for (size_t i = 0; i < job_cnt; i++)
    {
        jobs[i].algo = algo;
        jobs[i].row_number = i + 1; // 行号从1开始

        if (pthread_create(&threads[i], NULL, thread_cal, &jobs[i]) != 0)
        {
            fprintf(stderr, "Error: Failed to create thread %zu\n", i);
            // 清理已创建的线程
            for (size_t j = 0; j < i; j++)
            {
                pthread_cancel(threads[j]);
                pthread_join(threads[j], NULL);
            }
            free(jobs);
            return;
        }
    }

    // 等待所有线程完成
    for (size_t i = 0; i < job_cnt; i++)
    {
        pthread_join(threads[i], NULL);
    }

    free(jobs);

    // 恢复光标位置并显示光标
    // printf("\033[%d;1H\033[?25h\n", job_cnt + 1); 
}

HashAlgo const * find_algo(const char* type){
    if (strcmp(type, "md5") == 0){
        return &MD5_ALGO;
    }
    else if (strcmp(type, "sha256") == 0){
        return &SHA256_ALGO;
    }
    else {
        printf("Error: Unsupported hash algorithm '%s'.\n", type);
        printf("Supported algorithms: md5, sha256\n");
        return NULL;
    }
}

void print_help()
{
    printf("Usage: myhash <command> [<args>]\n");
    printf("These are commands used in various situations:\n");
    printf("calculate the merged hash values separately\n");
    printf("    -c <algoname> <filename1> <filename2> ... %s <filename3> ...\n", CMD_DELIMITER);
    printf("view help\n");
    printf("    -h\n");
}

int main(int argc, char const *argv[])
{
    if (argc < 2)
    {
        print_help();
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0)
    {
        print_help();
        return 1;
    }
    if (strcmp(argv[1], "-c") == 0)
    {
        // 该功能在dragonos中会触发 一直输出 已知由多线程引起
        // [ WARN ] (src/syscall/mod.rs:840)        SYS_RT_SIGTIMEDWAIT has not yet been implemented
        if (argc < 4)
        {
            printf("Usage: myhash -c <algoname> <filename1> <filename2> ... %s <filename3> ...\n", CMD_DELIMITER);
            return 1;
        }

        HashAlgo const *algo = find_algo(argv[2]);
        if (!algo) 
            return 1;

        cal_separately(algo, argc - 3, argv + 3);
        return 0;
    }

    printf("Error: Unknown command '%s'.\n", argv[1]);
    print_help();
    return 0;
}