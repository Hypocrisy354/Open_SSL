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

#define MAXSIZE 1024
#define CA_CERT_FILE "ca.crt"
#define SERVER_CERT_FILE "server.crt"
#define SERVER_KEY_FILE "server.key"

void print_usage(char *order)
{
    printf("usages: %s\n", order);
    printf("-p(port):server port\n");
    printf("-h(help):help information\n");
    exit(0);
}

int main(int argc, char **argv)
{
    int opt;
    int port = 0;
    int len;
    int rv;
    int sockfd;
    int on;
    int listenfd;
    int clifd;
    char send_buffer[MAXSIZE];
    char rec_buffer[MAXSIZE];

    SSL_CTX *ctx;
    SSL *ssl;

    struct sockaddr_in serv_addr;
    struct option opts[] =
        {

            {"port", 1, NULL, 'p'},
            {"h", 0, NULL, 'h'},
            {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "p:h", opts, NULL)) != -1)
    {
        switch (opt)
        {
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

    if (!port)
    {
        print_usage(argv[0]);
    }

    /*错误队列*/
    ERR_load_BIO_strings();

    /*SSL初始化*/
    SSL_library_init();
    printf("SSL_library_init ok!\n");

    OpenSSL_add_all_algorithms(); //加载算法
    SSL_load_error_strings();     //加载错误信息
    ERR_load_BIO_strings();

    /*建立会话环境*/
    printf("建立链接....\n");

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        printf("建立会话失败!\n");
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    // 是否要求校验对方证书 此处不验证客户端身份所以为： SSL_VERIFY_NONE
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // 加载CA的证书
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    {
        printf("SSL_CTX_load_verify_locations error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 加载自己的证书
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file error!\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    /* 加载自己的私钥，确认收到与发送的信息是否一致，是否是正确的服务器链接  */
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file error!\n");
        ERR_print_errors_fp(stderr);
        return -3;
    }
    /*检查用户私钥是否正确*/
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("SSL_CTX_check_private_key error!\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    //socket初始化
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("serve socket failed: %s\n", strerror(errno));
    }
    printf("sever socket creat successful!\n ");
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt)) < 0) //设置>端口属性，服务器重启是可再次使用该端口
    {
        printf("set port reuse error:%s\n", strerror(errno));
        return -1;
    }
    //绑定端口和ip
    if (bind(sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("bind ip port error:%s\n", strerror(errno));
        return -1;
    }
    //监听socket，等待客户端连接触发并指定服务器可排队连接的最大数
    listenfd = listen(sockfd, 10);
    if (listenfd < 0)
    {
        printf("listen server socket error:%s\n", strerror(errno));
        return -1;
    }
    clifd = accept(sockfd, (struct sockaddr *)NULL, NULL);
    if (clifd < 0)
    {
        printf("accept new client failure:%s\n", strerror(errno));
        return -1;
    }
    printf("Accept new client[%d] successfully!\n", clifd);

    /*申请SSL套接字*/
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clifd);

    if (SSL_accept(ssl) == -1)
    {
        printf("SSL_accept failure:%s!\n", strerror(errno));
        close(clifd);
        return -2;
    }

    while (1)
    {
        memset(rec_buffer, 0, sizeof(rec_buffer));
        len = SSL_read(ssl, rec_buffer, MAXSIZE);
        if (len > 0)
        {
            printf("接收消息成功:%s，共%d个字节的数据\n", rec_buffer, len - 1);
        }
        else
        {
            printf("消息接收失败！错误信息是'%s'\n", strerror(errno));
        }
        memset(send_buffer, 0, sizeof(send_buffer));
        printf("Input reply message:\n");
        fgets(send_buffer, MAXSIZE, stdin);

        rv = SSL_write(ssl, send_buffer, MAXSIZE);
        if (rv > 0)
        {
            printf("send %ld bytes data to client:%s\n", strlen(send_buffer) - 1, send_buffer);
        }
        else
        {
            printf("send data to client failure:%s\n", strerror(errno));
            break;
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clifd);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
