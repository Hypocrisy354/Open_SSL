#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

int get_stop = 0; //结束标志

#define MAXSIZE 1024
#define CA_CERT_FILE "ca.crt"
#define CLIENT_CERT_FILE "client.crt"
#define CLIENT_KEY_FILE "client.key"

void print_usage(char *order)
{
    printf("usages: %s\n", order);
    printf("-I(IP):server IP\n");
    printf("-p(port):server port\n");
    printf("-h(help):help information\n");
    exit(0);
}
/*证书信息*/
void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("数字证书信息：\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书：%s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者：%s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("无证书信息！\n");
    }
}

int main(int argc, char **argv)
{
    int opt = -1;
    int on = 1;
    int sockfd = -1;
    int len;
    int rv;
    int port = 0;
    char send_buffer[MAXSIZE];
    char rec_buffer[MAXSIZE];
    char *ip = NULL;

    SSL_CTX *ctx;
    SSL *ssl;

    struct sockaddr_in serv_addr;
    struct option opts[] =
        {
            {"IP", required_argument, NULL, 'i'},
            {"port", required_argument, NULL, 'p'},
            {"help", no_argument, NULL, 'h'},
            {0, 0, 0, 0}};
    while ((opt = getopt_long(argc, argv, "i:p:d:h", opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'i':
            ip = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            break;
        default:
            break;
        }
    }
    if ((!ip) || (!port))
    {
        print_usage(argv[0]);
        return 0;
    }

    SSL_library_init();           //初始化SSL库
    OpenSSL_add_all_algorithms(); //加载所有算法
    SSL_load_error_strings();     //加载错误信息
    ERR_load_BIO_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx == NULL)
    {
        printf("SSL_ctx_new faile!\n");
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    // 证书验证
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // 加载CA的证书
    printf("SSL_CTX_load_verify_locations start!\n");
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    {
        printf("SSL_CTX_load_verify_locations error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 加载自己的证书
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 加载自己的密钥
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    //验证私钥和证书是否相符
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("SSL_CTX_check_private_key error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    //socket初始化
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Fail to create a server socket [%d]: %s\n", sockfd, strerror(errno));
        return -1;
    }
    printf("creat a server socket[%d] successufully!\n", sockfd);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_aton(ip, &serv_addr.sin_addr);
    int num = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (num < 0)
    {
        printf("connect failure[%s:%d] : %s\n", ip, port, strerror(errno));
        return -2;
    }
    printf("connect server[%s:%d] sucessful!\n", ip, port);

    //创建SSL套字节
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (NULL == ssl)
    {
        printf("SSL_new error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    else
    {
        SSL_connect(ssl);
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    while (!get_stop)
    {
        printf("输入信息:\n");
        bzero(send_buffer, MAXSIZE + 1);
        fgets(send_buffer, MAXSIZE, stdin);

        len = SSL_write(ssl, send_buffer, strlen(send_buffer));
        if (len < 0)
        {
            printf("消息'%s'发送失败！错误信息是'%s'\n", send_buffer, strerror(errno));
            goto finish;
        }
        else
        {
            printf("消息%s发送成功，共发送了%d个字节！\n", send_buffer, len - 1);
        }

        memset(rec_buffer, 0, sizeof(rec_buffer));
        rv = SSL_read(ssl, rec_buffer, sizeof(rec_buffer));
        if (rv < 0)
        {
            printf("read data from server failure:%s\n", strerror(errno));
            goto finish;
        }
        else
        {
            printf("read %zd bytes data from server is:%s\n", strlen(rec_buffer) - 1, rec_buffer);
        }
    }
finish:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}