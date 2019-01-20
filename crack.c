/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the written permission of the copyright holder.
 */
#define _GNU_SOURCE

#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define ZERO 0
#define MAX_LEN 160
#define CHARSET 62
#define NUMSET  10
#define ALPHSET 26
#define SALT_LEN 2
#define BREAK 100
#define TOTALNUMTHREADS 24
#define NUMOFSETS 6
#define NUMTHREADS 6

typedef struct thread_data {
    int id;
    int pwlen;
    int pflag;
    char* charSet;
    char* cryptPasswd;
    char* passwd;
    //char* testString;
    //char* hash;
    char salt[3];
    //struct crypt_data *cdata;
} Thread_data;

void* stringcopy(char* dest, const char* src);
char* stringcopyN(char* dest, char* src, size_t n);
int stringcompare(char* string1, char* string2);
void* threadedCrack(void* arg);

int flag[NUMTHREADS] = {0};
pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;
/*
static pthread_mutex_t myMutex[NUMTHREADS] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};
*/

static const char *charSet[6] = {
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",    
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz",    
};

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd) {
    char* salt = strndup(cryptPasswd, SALT_LEN);
    
    // brute force
    for (int a = 0; a < CHARSET; a++) {
        for (int b = 0; b < CHARSET; b++) {
            for (int c = 0; c < CHARSET; c++) {
                if (pwlen == 4) {
                    for (int d = 0; d < CHARSET; d++) {
                        char testString[4];
                        testString[0] = charSet[0][a]; testString[1] = charSet[0][b];
                        testString[2] = charSet[0][c]; testString[3] = charSet[0][d]; testString[4] = '\0';
                        char* hash = crypt(testString, salt);
                        if(strcmp(cryptPasswd, hash) == ZERO) {
                            stringcopy(passwd, testString);
                            a = b = c = d = BREAK;
                        }
                    }
                } else if (pwlen == 3) {
                    char testString[3];
                    testString[0] = charSet[0][a]; testString[1] = charSet[0][b];
                    testString[2] = charSet[0][c]; testString[3] = '\0';
                    char* hash = crypt(testString, salt);
                    if(strcmp(cryptPasswd, hash) == ZERO) {
                        stringcopy(passwd, testString);
                        a = b = c = BREAK;
                    }
                } else {
                    printf("Password lengths of 3 and 4 supported only.\n");
                    a = b = c = BREAK;
                }
            }
        }
    }
    free(salt);
}

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds) {
    FILE *in = fopen(fname, "r");
    int j = 0;
    char* username = malloc(MAX_LEN);
    char* cryptPasswd = malloc(MAX_LEN);
    char* ignoredChars = malloc(MAX_LEN);

    while(fscanf(in, "%[^:]%*c", username) != EOF) {
        fscanf(in, "%[^:]%*c", cryptPasswd);
        fscanf(in, "%[^\n]%*c", ignoredChars);
        crackSingle(username, cryptPasswd, pwlen, passwds[j++]);
    }

    free(ignoredChars);
    free(cryptPasswd);
    free(username);
    fclose(in);    
} 

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackSpeedy(char *fname, int pwlen, char **passwds) {
    pthread_t thread[NUMTHREADS];
    FILE *in = fopen(fname, "r");
    int j = -1;
    char* username = malloc(MAX_LEN);
    char* cryptPasswd = malloc(MAX_LEN);
    char* ignoredChars = malloc(MAX_LEN);
    char salt[3] = {0};
    Thread_data data[NUMTHREADS];

    while(fscanf(in, "%[^:]%*c", username) != EOF) {
        fscanf(in, "%[^:]%*c", cryptPasswd);
        fscanf(in, "%[^\n]%*c", ignoredChars);
        j++;
        strncpy(salt, cryptPasswd, SALT_LEN);
        data[j].id = j;
        data[j].pwlen = pwlen;
        data[j].pflag = -1;
        data[j].passwd = malloc(pwlen + 1);
        data[j].cryptPasswd = malloc(strlen(cryptPasswd));
        data[j].charSet = malloc(63);
        memset(data[j].passwd, 0, pwlen + 1);
        memset(data[j].cryptPasswd, 0, strlen(cryptPasswd));
        strcpy(data[j].charSet, charSet[j]);
        stringcopy(data[j].cryptPasswd, cryptPasswd);
        memset(data[j].salt, 0, 3);
        strcpy(data[j].salt, salt);

        pthread_create(&thread[j], NULL, threadedCrack, &data[j]);
    }

    for(int k = 0; k <= j; ++k) {        
        pthread_join(thread[k], NULL);
    }

    for(int i = 0; i <= j; ++i) {
        strcpy(passwds[i], data[i].passwd);
        free(data[i].cryptPasswd);
        free(data[i].passwd);
        free(data[i].charSet);
    }

    free(ignoredChars);
    free(cryptPasswd);
    free(username);
    fclose(in);
} 

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD withoiut using more than MAXCPU
 * percent of any processor.
 */
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu) {
    crackSingle(username, cryptPasswd, pwlen, passwd);
}

/* 
 * Adapted from the strcpy(3) man pages this function will copy a string in safer way
 */
char* stringcopyN(char* dest, char* src, size_t n) {
    size_t i;

    for (i = 0; i < n && src[i] != '\0'; i++)
        dest[i] = src[i];
    for ( ; i < n; i++)
        dest[i] = '\0';

    return dest;
}

/* 
 * Adapted from the strcpy(3) man pages this function will copy a string
 */
void* stringcopy(char* dest, const char* src) {
    size_t i;
    for (i = 0; src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
    return dest;
}

/* 
 * Inspired by CMPS122 Tuesday Section
 */
void* threadedCrack(void* args) {
    Thread_data *data = args;
    struct crypt_data cdata;
	cdata.initialized = 0;
    for (int a = 0; a < (int) strlen(data->charSet); a++) {
        for (int b = 0; b < (int) strlen(data->charSet); b++) {
            for (int c = 0; c < (int) strlen(data->charSet); c++) {
                if (data->pwlen == 4) {
                    for (int d = 0; d < (int) strlen(data->charSet); d++) {
                        char testString[4];
                        testString[0] = data->charSet[a]; testString[1] = data->charSet[b];
                        testString[2] = data->charSet[c]; testString[3] = data->charSet[d]; testString[4] = '\0';
                        char* hash = malloc(strlen(data->cryptPasswd));
                        hash = crypt_r(testString, data->salt, &cdata);
                        if(strcmp(data->cryptPasswd, hash) == ZERO) {
                            stringcopy(data->passwd, testString);
                            a = b = c = BREAK;
                        }
                    }                    
                } else if (data->pwlen == 3) {
                    char testString[3];
                    testString[0] = data->charSet[a]; testString[1] = data->charSet[b];
                    testString[2] = data->charSet[c]; testString[3] = '\0';
                    char* hash = malloc(strlen(data->cryptPasswd));
                    hash = crypt_r(testString, data->salt, &cdata);
                    if(strcmp(data->cryptPasswd, hash) == ZERO) {
                        stringcopy(data->passwd, testString);
                        a = b = c = BREAK;
                    }
                } else {
                    printf("Password lengths of 3 and 4 supported only.\n");
                    a = b = c = BREAK;
                    break;
                }
            }
        }
    }
    

    pthread_exit(NULL);
}
