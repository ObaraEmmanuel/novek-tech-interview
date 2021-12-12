#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 5050
#define SA struct sockaddr

// 1kb chunk for zlib
#define CHUNK 0x400
#define ENABLE_ZLIB_GZIP 32
#define MESSAGE_SIZE 161
#define HEX_STRING_SIZE 180

static uint8_t *hex_decode(const char *hex_string);

static uint8_t hex_char_to_int(char hex_char);

static uint8_t *gzip_decompress(uint8_t *bytes, size_t size);

static char *get_plaintext(const char *hex_str);

static void zerr(int ret);


int main() {
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed!\n");
        exit(EXIT_FAILURE);
    } else
        printf("Socket successfully created...\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("20.108.244.219");
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(sockfd, (SA *) &servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed!\n");
        exit(EXIT_FAILURE);
    }

    printf("reading from the server...\n");
    size_t bytes_read = 0;
    char buff[CHUNK];
    while (bytes_read < MESSAGE_SIZE) {
        bytes_read += recv(sockfd, buff + bytes_read, MESSAGE_SIZE - bytes_read, 0);
    }
    printf("%s", buff);
    bzero(buff, CHUNK);
    ssize_t hex_size = recv(sockfd, buff, HEX_STRING_SIZE, 0);
    if (hex_size < 0) {
        printf("Could not fetch hex string");
        exit(EXIT_FAILURE);
    }
    printf("%s\n", buff);

    // decode and decompress hex_string
    printf("Decoding hex string...\n");
    char *decoded = get_plaintext(buff);

    bzero(buff, CHUNK);
    // extra data to be read after the hex string
    recv(sockfd, buff, 10, 0);
    printf("%s", buff);
    printf("%s\n", decoded);

    send(sockfd, decoded, strlen(decoded) + 1, 0);

    // and now the secret key
    bzero(buff, CHUNK);
    recv(sockfd, buff, CHUNK, 0);
    printf("%s", buff);

    close(sockfd);
    free(decoded);
    return 0;
}

char *get_plaintext(const char *hex_str) {
    size_t size = strlen(hex_str) / 2;
    // hex decode string
    uint8_t *bytes = hex_decode(hex_str);
    // gzip decompress string
    uint8_t *decompressed = gzip_decompress(bytes, size);
    // newline hack allows the server to read the decoded string to the end and return a response
    // gzip_decompress will hopefully have allocated surplus memory we can use for the newline
    // this is otherwise not the best thing to do
    decompressed[strlen((char *) decompressed)] = '\n';
    free(bytes);
    return (char *) decompressed;
}

void zerr(int ret) {
    // for debugging gzip decompress errors
    fputs("zpipe: ", stderr);
    switch (ret) {
        case Z_ERRNO:
            if (ferror(stdin))
                fputs("error reading stdin\n", stderr);
            if (ferror(stdout))
                fputs("error writing stdout\n", stderr);
            break;
        case Z_STREAM_ERROR:
            fputs("invalid compression level\n", stderr);
            break;
        case Z_DATA_ERROR:
            fputs("invalid or incomplete deflate data\n", stderr);
            break;
        case Z_MEM_ERROR:
            fputs("out of memory\n", stderr);
            break;
        case Z_VERSION_ERROR:
            fputs("zlib version mismatch!\n", stderr);
        default:
            fputs("zlib unknown error\n", stderr);
    }
}


uint8_t hex_char_to_int(const char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    } else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    } else {
        return 0;
    }
}

uint8_t *hex_decode(const char *hex_string) {
    size_t len = strlen(hex_string);
    uint8_t *bytes = malloc(len / 2);

    for (size_t i = 0; i < len; i += 2) {
        // read first high nibble
        uint8_t val = hex_char_to_int(hex_string[i]) << 4;
        // read lower nibble
        val |= hex_char_to_int(hex_string[i + 1]);
        bytes[i / 2] = val;
    }
    return bytes;
}

static uint8_t *gzip_decompress(uint8_t *bytes, size_t size) {
    uint8_t out[CHUNK];
    uint8_t *decompressed = malloc(CHUNK);
    size_t decompressed_size = 0, out_buff_size = CHUNK;
    z_stream stream = {0};
    stream.zalloc = Z_NULL;
    stream.opaque = Z_NULL;
    stream.zfree = Z_NULL;
    stream.next_in = bytes;
    stream.avail_in = size;

    int ret = inflateInit2(&stream, MAX_WBITS | ENABLE_ZLIB_GZIP);
    if (ret != Z_OK) {
        zerr(ret);
        exit(EXIT_FAILURE);
    }

    int status;
    do {
        size_t have;
        stream.next_out = out;
        stream.avail_out = CHUNK;
        status = inflate(&stream, Z_NO_FLUSH);

        switch (status) {
            case Z_OK:
                printf("okay");
                break;
            case Z_STREAM_END:
                break;
            case Z_BUF_ERROR:
                printf("buffer error");
                break;
            default:
                inflateEnd(&stream);
                zerr(status);
                exit(EXIT_FAILURE);
        }
        have = CHUNK - stream.avail_out;
        // extra work for handling larger decompression output just in case
        if (decompressed_size + have > out_buff_size) {
            // double output buffer
            out_buff_size *= 2;
            decompressed = realloc(decompressed, out_buff_size);
        }
        memcpy(decompressed + decompressed_size, out, have);
        decompressed_size += have;

    } while (stream.avail_out == 0);
    decompressed[decompressed_size] = '\0';
    inflateEnd(&stream);
    return decompressed;
}
