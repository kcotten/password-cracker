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

#define _XOPEN_SOURCE
#define ZERO 0
#define MAX_LEN 160

typedef unsigned long size_t;

void * stringcopy(char *dest, const char *src);
char * stringcopyN(char *dest, char *src, size_t n);
int stringcompare(char* string1, char* string2);

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd) {    
    const char charSet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const int sizeOfCharSet = 62;
    char* salt = strndup(cryptPasswd, 2);
    // brute force guess, first attempt
    for (int a = 0; a < sizeOfCharSet; a++) {
        for (int b = 0; b < sizeOfCharSet; b++) {
            for (int c = 0; c < sizeOfCharSet; c++) {
                char testString[3];
                testString[0] = charSet[a];testString[1] = charSet[b];testString[2] = charSet[c];testString[3] = '\0';
                char* hash = crypt(testString, salt);
                if(strcmp(cryptPasswd, hash) == ZERO) {
                    //printf("%s \n", hash);
                    //printf("%s \n", cryptPasswd);
                    stringcopy(passwd, testString);
                    //printf("%s \n", passwd);
                    a = b = c = 100;
                }
            }
        }
    }
 

    /* char* testString = "god";
    char* hash = crypt(testString, salt);
    if(strcmp(cryptPasswd, hash) == 0) {
        printf("%s \n", "The hash is equal to the encryptd password, setting passwd.");
        stringcopy(passwd, testString);
        printf("%s \n", passwd);        
    } */

}

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds) {
    FILE *in = fopen(fname, "r");
    int peek, lineCount = 0;
    char* username = malloc(MAX_LEN);
    char* cryptPasswd = malloc(MAX_LEN);
    char* ignored = malloc(MAX_LEN);

    while(!feof(in)) {
        peek = fgetc(in);
        if(peek == '\n') {
            lineCount++;
        }
    }
    fclose(in);
    in = fopen(fname, "r");

    for(int i = 0; i < lineCount; i++) {
        fscanf(in, "%[^:]%*c", username);
        fscanf(in, "%[^:]%*c", cryptPasswd);
        fscanf(in, "%[^\n]%*c", ignored);
        //printf("%s%s%s \n", username, " : ", cryptPasswd);
        crackSingle(username, cryptPasswd, pwlen, passwds[i]);
    }

    free(ignored);
    free(cryptPasswd);
    free(username);
    fclose(in);
} 

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackSpeedy(char *fname, int pwlen, char **passwds) {

} 

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD withoiut using more than MAXCPU
 * percent of any processor.
 */
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu) {

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