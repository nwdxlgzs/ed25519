#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "src/ed25519.h"
#include "src/sha512.h"
#include "src/ge.h"
#include "src/sc.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

static char* hex_encode(const unsigned char* input, size_t input_len) {
    const char hex_chars[] = "0123456789ABCDEF";
    char* output = (char*)malloc(input_len * 2 + 1);
    if (output == NULL) {
        fprintf(stderr, "[Error]: HEX编码时内存分配失败。\n");
        return NULL;
    }
    for (size_t i = 0; i < input_len; ++i) {
        output[i * 2] = hex_chars[(input[i] >> 4) & 0xF];
        output[i * 2 + 1] = hex_chars[input[i] & 0xF];
    }
    output[input_len * 2] = '\0';
    return output;
}
static unsigned char* hex_decode(const char* input, size_t* output_len) {
    if (input == NULL) {
        fprintf(stderr, "[Error]: HEX解码时输入字符串为空。\n");
        return NULL;
    }
    size_t input_len = strlen(input);
    if (input_len % 2 != 0) {
        fprintf(stderr, "[Error]: HEX字符串长度非法，应是偶数长度。\n");
        return NULL;
    }
    unsigned char* output = (unsigned char*)malloc(input_len / 2);
    if (output == NULL) {
        fprintf(stderr, "[Error]: HEX解码时内存分配失败。\n");
        return NULL;
    }
    for (size_t i = 0; i < input_len / 2; ++i) {
        char high = input[i * 2];
        char low = input[i * 2 + 1];
        if (isxdigit(high) && isxdigit(low)) {
            high = tolower(high);
            low = tolower(low);
            output[i] = ((high >= 'a') ? (high - 'a' + 10) : (high - '0')) << 4;
            output[i] |= (low >= 'a') ? (low - 'a' + 10) : (low - '0');
        } else {
            fprintf(stderr, "[Error]: 遇到了非HEX字符。\n");
            free(output);
            return NULL;
        }
    }
    *output_len = input_len / 2;
    return output;
}
static unsigned char* readFile(const char* path, size_t* buffsz) {
    if (buffsz)*buffsz = 0;
    FILE* file = fopen(path, "rb");
    fseek(file, 0L, SEEK_END);
    size_t length = ftell(file);
    fseek(file, 0L, SEEK_SET);
    unsigned char* buffer = (unsigned char*)malloc(length + 1);
    if (buffer == NULL) {
        fprintf(stderr, "[Error]: 文件读取失败。\n");
        return NULL;
    }
    fread(buffer, 1, length, file);
    buffer[length] = 0;
    fclose(file);
    if (buffsz)*buffsz = length;
    return buffer;
}

static void writeFile(const char* path, const unsigned char* buffer, size_t length) {
    FILE* file = fopen(path, "wb");
    fwrite(buffer, 1, length, file);
    fclose(file);
}

int main(const int argc, const char* argv[], const char* env[]) {
    unsigned char SHA512_Hash[64];
    unsigned char seed[32];
    unsigned char signature[64];
    unsigned char public_key[32];
    unsigned char private_key[64];
    unsigned char shared_secret[32];
    if (argc < 2) {
    show_usage:;
        printf("Usage:\n");
        printf("SHA512: %s -sha512 -file/-string <file>/<string> [-o <file>]\n", argv[0]);
        printf("ED25519: %s [-ed25519] -seed [-o <file>]\n", argv[0]);
        printf("ED25519: %s [-ed25519] -keypair -i <file> [-publ-o <file> -priv-o <file>]\n", argv[0]);
        printf("ED25519: %s [-ed25519] -sign -i -file/-string <file>/<string> -publ-i <file> -priv-i <file> [-o <file>]\n", argv[0]);
        printf("ED25519: %s [-ed25519] -verify -i -file/-string <file>/<string> -publ-i <file> -sign-i <file>\n", argv[0]);
        printf("ED25519: %s [-ed25519] -add-scalar -publ-i <file>/NULL -priv-i <file>/NULL -scalar-i <file> [-publ-o <file> -priv-o <file>]\n", argv[0]);
        printf("ED25519: %s [-ed25519] -key-exchange -publ-i <file> -priv-i <file> [-o <file>]\n", argv[0]);
        return 0;
    }
    if (strcmp(argv[1], "-sha512") == 0) {
        if (argc == 4) {
            if (strcmp(argv[2], "-file") == 0) {
                size_t length = 0;
                unsigned char* buffer = readFile(argv[3], &length);
                if (buffer == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                sha512(buffer, length, SHA512_Hash);
                free(buffer);
                char* hex = hex_encode(SHA512_Hash, 64);
                printf("%s\n", hex);
                free(hex);
                return 0;
            } else if (strcmp(argv[2], "-string") == 0) {
                sha512((unsigned char*)argv[3], strlen(argv[3]), SHA512_Hash);
                char* hex = hex_encode(SHA512_Hash, 64);
                printf("%s\n", hex);
                free(hex);
                return 0;
            } else goto show_usage;
        } else if (argc == 6 && strcmp(argv[4], "-o") == 0) {
            if (strcmp(argv[2], "-file") == 0) {
                size_t length = 0;
                unsigned char* buffer = readFile(argv[3], &length);
                if (buffer == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                sha512(buffer, length, SHA512_Hash);
                free(buffer);
                writeFile(argv[5], SHA512_Hash, sizeof(SHA512_Hash));
                return 0;
            } else if (strcmp(argv[2], "-string") == 0) {
                sha512((unsigned char*)argv[3], strlen(argv[3]), SHA512_Hash);
                writeFile(argv[5], SHA512_Hash, sizeof(SHA512_Hash));
                return 0;
            } else goto show_usage;
        } else goto show_usage;
    } else {
        int Argc = argc;
        if (strcmp(argv[1], "-ed25519") == 0) {
            argv--;
            Argc--;
        }
        if (Argc <= 1) goto show_usage;
        if (strcmp(argv[1], "-seed") == 0) {
            if (ed25519_create_seed(seed) != 0) {
                fprintf(stderr, "[Error]: 种子生成失败。\n");
                return 1;
            }
            if (Argc > 3 && strcmp(argv[2], "-o") == 0) {
                writeFile(argv[3], seed, sizeof(seed));
                return 0;
            } else {
                char* hex = hex_encode(seed, sizeof(seed));
                printf("%s\n", hex);
                free(hex);
                return 0;
            }
        } else if (strcmp(argv[1], "-keypair") == 0) {
            if (Argc == 4 && strcmp(argv[2], "-i") == 0) {
                size_t length = 0;
                unsigned char* buffer = readFile(argv[3], &length);
                if (buffer == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                ed25519_create_keypair(public_key, private_key, buffer);
                free(buffer);
                char* hex = hex_encode(public_key, sizeof(public_key));
                printf("Public Key: %s\n", hex);
                free(hex);
                hex = hex_encode(private_key, sizeof(private_key));
                printf("Private Key: %s\n", hex);
                free(hex);
                return 0;
            } else if (Argc == 8 && strcmp(argv[2], "-i") == 0 && strcmp(argv[4], "-publ-o") == 0 && strcmp(argv[6], "-priv-o") == 0) {
                size_t length = 0;
                unsigned char* buffer = readFile(argv[3], &length);
                if (buffer == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                ed25519_create_keypair(public_key, private_key, buffer);
                free(buffer);
                writeFile(argv[5], public_key, sizeof(public_key));
                writeFile(argv[7], private_key, sizeof(private_key));
                return 0;
            } else goto show_usage;
        } else if (strcmp(argv[1], "-sign") == 0) {
            if (Argc == 9 && strcmp(argv[2], "-i") == 0 && strcmp(argv[5], "-publ-i") == 0 && strcmp(argv[7], "-priv-i") == 0) {
                size_t msglength = 0;
                unsigned char* msg = NULL;
                if (strcmp(argv[3], "-file") == 0) {
                    msg = readFile(argv[4], &msglength);
                    if (msg == NULL) {
                        fprintf(stderr, "[Error]: 文件读取失败。\n");
                        return 1;
                    }
                } else if (strcmp(argv[3], "-string") == 0) {
                    msg = (unsigned char*)strdup(argv[4]);
                    msglength = strlen((const char*)msg);
                } else goto show_usage;
                size_t publlength = 0;
                unsigned char* publ = readFile(argv[6], &publlength);
                if (publ == NULL) {
                    free(msg);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                size_t privlength = 0;
                unsigned char* priv = readFile(argv[8], &privlength);
                if (priv == NULL) {
                    free(msg);
                    free(publ);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                ed25519_sign(signature, msg, msglength, publ, priv);
                free(msg);
                free(publ);
                free(priv);
                char* hex = hex_encode(signature, sizeof(signature));
                printf("%s\n", hex);
                free(hex);
                return 0;
            } else if (Argc == 11 && strcmp(argv[2], "-i") == 0 && strcmp(argv[5], "-publ-i") == 0 && strcmp(argv[7], "-priv-i") == 0 && strcmp(argv[9], "-o") == 0) {
                size_t msglength = 0;
                unsigned char* msg = NULL;
                if (strcmp(argv[3], "-file") == 0) {
                    msg = readFile(argv[4], &msglength);
                    if (msg == NULL) {
                        fprintf(stderr, "[Error]: 文件读取失败。\n");
                        return 1;
                    }
                } else if (strcmp(argv[3], "-string") == 0) {
                    msg = (unsigned char*)strdup(argv[4]);
                    msglength = strlen((const char*)msg);
                } else goto show_usage;
                size_t publlength = 0;
                unsigned char* publ = readFile(argv[6], &publlength);
                if (publ == NULL) {
                    free(msg);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                size_t privlength = 0;
                unsigned char* priv = readFile(argv[8], &privlength);
                if (priv == NULL) {
                    free(msg);
                    free(publ);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                ed25519_sign(signature, msg, msglength, publ, priv);
                free(msg);
                free(publ);
                free(priv);
                writeFile(argv[10], signature, sizeof(signature));
                return 0;
            } else goto show_usage;
        } else if (strcmp(argv[1], "-verify") == 0 && Argc == 9 && strcmp(argv[2], "-i") == 0 && strcmp(argv[5], "-publ-i") == 0 && strcmp(argv[7], "-sign-i") == 0) {
            size_t msglength = 0;
            unsigned char* msg = NULL;
            if (strcmp(argv[3], "-file") == 0) {
                msg = readFile(argv[4], &msglength);
                if (msg == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
            } else if (strcmp(argv[3], "-string") == 0) {
                msg = (unsigned char*)strdup(argv[4]);
                msglength = strlen((const char*)msg);
            } else goto show_usage;
            size_t publlength = 0;
            unsigned char* publ = readFile(argv[6], &publlength);
            if (publ == NULL) {
                free(msg);
                fprintf(stderr, "[Error]: 文件读取失败。\n");
                return 1;
            }
            size_t signlength = 0;
            unsigned char* sign = readFile(argv[8], &signlength);
            if (sign == NULL) {
                free(msg);
                free(publ);
                fprintf(stderr, "[Error]: 文件读取失败。\n");
                return 1;
            }
            if (ed25519_verify(sign, msg, msglength, publ)) {
                printf("TRUE\n");
            } else {
                printf("FALSE\n");
            }
            free(msg);
            free(publ);
            free(sign);
            return 0;
        } else if (strcmp(argv[1], "-add-scalar") == 0) {
            if (Argc == 8 && strcmp(argv[2], "-publ-i") == 0 && strcmp(argv[4], "-priv-i") == 0 && strcmp(argv[6], "-scalar-i") == 0) {
                size_t publlength = 0;
                unsigned char* publ = NULL;
                if (strcmp(argv[3], "NULL") != 0) {
                    publ = readFile(argv[3], &publlength);
                    if (publ == NULL) {
                        fprintf(stderr, "[Error]: 文件读取失败。\n");
                        return 1;
                    }
                }
                size_t privlength = 0;
                unsigned char* priv = NULL;
                if (strcmp(argv[5], "NULL") != 0) {
                    priv = readFile(argv[5], &privlength);
                    if (priv == NULL) {
                        if (publ) free(publ);
                        fprintf(stderr, "[Error]: 文件读取失败。\n");
                        return 1;
                    }
                }
                size_t scalarelength = 0;
                unsigned char* scalar = readFile(argv[7], &scalarelength);
                if (scalar == NULL) {
                    if (publ) free(publ);
                    if (priv) free(priv);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                } else {
                    memcpy(seed, scalar, 32);
                    free(scalar);
                    seed[31] &= 127;
                }
                ed25519_add_scalar(publ, priv, seed);
                if (publ) {
                    char* hex = hex_encode(publ, publlength);
                    printf("Public Key: %s\n", hex);
                    free(hex);
                    free(publ);
                }
                if (priv) {
                    char* hex = hex_encode(priv, privlength);
                    printf("Private Key: %s\n", hex);
                    free(hex);
                    free(priv);
                }
                return 0;
            } else if (Argc == 12 && strcmp(argv[2], "-publ-i") == 0 && strcmp(argv[4], "-priv-i") == 0 && strcmp(argv[6], "-scalar-i") == 0 && strcmp(argv[8], "-publ-o") == 0 && strcmp(argv[10], "-priv-o") == 0) {
                size_t publlength = 0;
                unsigned char* publ = NULL;
                if (strcmp(argv[3], "NULL") != 0) {
                    publ = readFile(argv[3], &publlength);
                    if (publ == NULL) {
                        fprintf(stderr, "[Error]: 文件读取失败。\n");
                        return 1;
                    }
                }
                size_t privlength = 0;
                unsigned char* priv = NULL;
                if (strcmp(argv[5], "NULL") != 0) {
                    priv = readFile(argv[5], &privlength);
                    if (priv == NULL) {
                        if (publ) free(publ);
                        fprintf(stderr, "[Error]: 文件读取失败。\n");
                        return 1;
                    }
                }
                size_t scalarelength = 0;
                unsigned char* scalar = readFile(argv[7], &scalarelength);
                if (scalar == NULL) {
                    if (publ) free(publ);
                    if (priv) free(priv);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                } else if (scalarelength != 32) {
                    if (publ) free(publ);
                    if (priv) free(priv);
                    free(scalar);
                } else {
                    memcpy(seed, scalar, 32);
                    free(scalar);
                    seed[31] &= 127;
                }
                ed25519_add_scalar(publ, priv, seed);
                if (publ) {
                    writeFile(argv[9], publ, publlength);
                    free(publ);
                }
                if (priv) {
                    writeFile(argv[11], priv, privlength);
                    free(priv);
                }
                return 0;
            } else goto show_usage;
        } else if (strcmp(argv[1], "-key-exchange") == 0) {
            if (Argc == 6 && strcmp(argv[2], "-publ-i") == 0 && strcmp(argv[4], "-priv-i") == 0) {
                size_t publlength = 0;
                unsigned char* publ = readFile(argv[3], &publlength);
                if (publ == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                size_t privlength = 0;
                unsigned char* priv = readFile(argv[5], &privlength);
                if (priv == NULL) {
                    free(publ);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                ed25519_key_exchange(shared_secret, publ, priv);
                char* hex = hex_encode(shared_secret, 32);
                printf("Shared Secret: %s\n", hex);
                free(hex);
                free(publ);
                free(priv);
            } else if (Argc == 8 && strcmp(argv[2], "-publ-i") == 0 && strcmp(argv[4], "-priv-i") == 0 && strcmp(argv[6], "-o") == 0) {
                size_t publlength = 0;
                unsigned char* publ = readFile(argv[3], &publlength);
                if (publ == NULL) {
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                size_t privlength = 0;
                unsigned char* priv = readFile(argv[5], &privlength);
                if (priv == NULL) {
                    free(publ);
                    fprintf(stderr, "[Error]: 文件读取失败。\n");
                    return 1;
                }
                ed25519_key_exchange(shared_secret, publ, priv);
                writeFile(argv[7], shared_secret, 32);
            } else goto show_usage;
        }else goto show_usage;
    }
}
