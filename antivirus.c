#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

/// functia de calculare hash
int calculateFileHash(const char* filePath, unsigned char* hash) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        printf("Eroare la citirea fisierului: %s\n", filePath);
        return 0;
    }

    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    unsigned char buffer[BUFSIZ];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, BUFSIZ, file)) != 0) {
        MD5_Update(&md5Context, buffer, bytesRead);
    }

    MD5_Final(hash, &md5Context);

    fclose(file);
    return 1;
}

int isHashMalicious(const char* hash) {
    /// hash - uri random, printre ele este si cel al fisierul test1_mal pentru a dovedi corectitudinea script-ului
    const char* maliciousHashes[] = {
        "4c08a19e95b9cb5ac162a73b430f1a52",
        "d41d8cd98f00b204e9800998ecf8427e",
        "c897a4ee3a17d5d9a70ab8b61df12e24",
    };

    size_t numMaliciousHashes = sizeof(maliciousHashes) / sizeof(maliciousHashes[0]);

    for (size_t i = 0; i < numMaliciousHashes; ++i) {
        if (strcmp(hash, maliciousHashes[i]) == 0) {
            return 1; /// Hash ul a fost gasit
        }
    }

    return 0; /// hash-ul nu a fost gasit in baza de date definita
}

int hasMaliciousWords(const char* string) {
    const char* maliciousWords[] = {
        "malware",
        "virus",
        "exploit",
        "attack",
        "connect"
    };

    size_t numMaliciousWords = sizeof(maliciousWords) / sizeof(maliciousWords[0]);

    for (size_t i = 0; i < numMaliciousWords; ++i) {
        if (strstr(string, maliciousWords[i]) != NULL) {
            return 1; /// string ul contine unul dintre cuvintele definite ca fiind malitioase
        }
    }

    return 0; /// String-ul nu reprezinta unul din cuvintele date ca fiind malitioase
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Folosire: %s <file_path>\n", argv[0]);
        return 1;
    }

    const char* filePath = argv[1];
    unsigned char hash[MD5_DIGEST_LENGTH];

    if (!calculateFileHash(filePath, hash)) {
        printf("Fail la calcularea hash-ului.\n");
        return 1;
    }

    char hashString[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(&hashString[i * 2], "%02x", (unsigned int)hash[i]);
    }

    printf("MD5 Hash: %s\n", hashString);

    /// construim comanda pentru strings
    char command[256];
    snprintf(command, sizeof(command), "strings %s", filePath);

    /// Deschidem un pipe special pentru comanda "strings" din linux
    FILE* stringsPipe = popen(command, "r");
    if (!stringsPipe) {
        printf("Fail la comanda strings.\n");
        return 1;
    }

    /// citim linie cu linie din output-ul comenzii strings
    char line[256];
    int ok = 0;
    while (fgets(line, sizeof(line), stringsPipe)) {
        line[strcspn(line, "\n")] = '\0';
        //printf("String: %s\n", line);

        if (hasMaliciousWords(line)) {
            printf("Atentie! Cuvant suspicios gasit! Cuvant: %s\n", line);
            ok = 1;
        }
    }

    /// oprim pipe-ul aferent lui strings
    pclose(stringsPipe);

    if (isHashMalicious(hashString)) {
        printf("Fisierul este recunoscut ca fiind malicios pe baza has-ului sau!\n");
        ok = 1;
    } else
        if (ok == 0)
            {
            printf("Fisier nemalitios! \n");
            }
    return 0;
}
