// for future attacks, if the dict files are still sorted, use MergeSort to increase efficiency

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hashText = md5(plaintext, strlen(plaintext));         // hash word
    char *nl = strchr(hashText, '\n');                          // trim newline
    if (nl)
    {
        *nl = '\0';
    }

    // Open the hash file
    FILE *srcFile = fopen(hashFilename, "r");                   // open source file
    if (!srcFile)                                               // confirm it was opened
    {
        printf("Can't open %s for reading\n", hashFilename);
        exit(1);
    }

    // Loop through the hash file, one line at a time.
    int matchFlag = 0;
    char line[HASH_LEN];                    
    while (fgets(line, HASH_LEN, srcFile) != NULL)              // while not at end of file
    {                                                           
        char *nl = strchr(line, '\n');                          // trim newline
        if (nl)
        {
            *nl = '\0';
        }        

        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(line, hashText) == 0) 
        {
            matchFlag = 1;
        }
    } 

    // If there is a match, you'll return the hash.
    // If not, return NULL.
    if (matchFlag == 1)
    {
        fclose(srcFile);                                        // close source file
        return hashText;                                        // match was found, return hash
    }
    else
    {
        fclose(srcFile);                                        // close source file
        return NULL;                                            // no match was found
    }

    // Before returning, do any needed cleanup:
    //   Close files? YES, done
    //   Free memory? NO
}

int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.
    // char *found = tryWord("hello", "hashes00.txt");
    // printf("%s %s\n", found, "hello");


    // Open the dictionary file for reading.
    FILE *dictFile = fopen(argv[2], "r");                           // open source file
    if (!dictFile)                                                  // confirm it was opened
    {
        printf("Can't open %s for reading\n", argv[2]);
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    int pwFound = 0;
    char currentWord[PASS_LEN];                    
    while (fgets(currentWord, PASS_LEN, dictFile) != NULL)           // while not at end of file
    {                                                           
        char *nl = strchr(currentWord, '\n');                        // trim newline
        if (nl)
        {
            *nl = '\0';
        }        

        // If we got a match, display the hash and the word. For example:
        //   5d41402abc4b2a76b9719d911017c592 hello
        char *wordToCheck = tryWord(currentWord, argv[1]);               
        if (wordToCheck != NULL)
        {
            printf("%s  %s\n", wordToCheck, currentWord);
            ++pwFound;
        }
    }

    
    // Close the dictionary file.
    fclose(dictFile);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", pwFound);
    
    // Free up any malloc'd memory? No malloc instructions used, free not needed
}

