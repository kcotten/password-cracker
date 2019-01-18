/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the written permission of the copyright holder.
 */

#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define ZERO 0
#define MAX_LEN 160
#define FULLSET 62
#define NUMSET  10
#define ALPHSET 26
#define SALT_LEN 2
#define BREAK 100

void * stringcopy(char *dest, const char *src);
char * stringcopyN(char *dest, char *src, size_t n);
int stringcompare(char* string1, char* string2);

static const char fullCharSet[]  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char numCharSet[]   = "0123456789";
static const char lowerCharSet[] = "abcdefghijklmnopqrstuvwxyz";
static const char upperCharSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd) {    
    char* salt = strndup(cryptPasswd, SALT_LEN);
    
    // brute force
    for (int a = 0; a < FULLSET; a++) {
        for (int b = 0; b < FULLSET; b++) {
            for (int c = 0; c < FULLSET; c++) {
                if (pwlen == 4) {
                    for (int d = 0; d < FULLSET; d++) {
                        char testString[4];
                        testString[0] = fullCharSet[a]; testString[1] = fullCharSet[b];
                        testString[2] = fullCharSet[c]; testString[3] = fullCharSet[d]; testString[4] = '\0';
                        char* hash = crypt(testString, salt);
                        if(strcmp(cryptPasswd, hash) == ZERO) {
                            stringcopy(passwd, testString);
                            a = b = c = d = BREAK;
                        }
                    }
                } else if (pwlen == 3) {
                    char testString[3];
                    testString[0] = fullCharSet[a]; testString[1] = fullCharSet[b];
                    testString[2] = fullCharSet[c]; testString[3] = '\0';
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
    crackMultiple(fname, pwlen, passwds);
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
char * stringcopyN(char *dest, char *src, size_t n) {
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
void *stringcopy(char *dest, const char *src) {
    size_t i;
    for (i = 0; src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
    return dest;
}

/* 
 * Adapted from built in function strcmp(3)
 */
/*
int stringcompare(char* string1, char* string2) {
    while(*string1 == *string2++) {
        if(*string1 == 0) {
            return 0;
        }
    }
    return (*string1 - *--string2);
}
 */