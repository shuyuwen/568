#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#define HOST "localhost"
#define PORT 8765
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define CN_SERVER "Bob's Server"
#define KEY_FILE "alice.pem"
#define PASSWORD "password"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

int check_cert(SSL *ssl);
int send_request(SSL *ssl, char * request);

int main(int argc, char **argv)
{
    int sock, port=PORT;
    char *host=HOST;
    struct sockaddr_in addr;
    struct hostent *host_entry;
    char *secret = "What's the question?";

    /*Parse command line arguments*/
    switch(argc){
        case 1:
            break;
        case 3:
            host = argv[1];
            port=atoi(argv[2]);
            if (port<1||port>65535){
                fprintf(stderr,"invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s server port\n", argv[0]);
            exit(0);
    }

    /* Set up context object (an SSL_CTX)*/
    SSL_CTX *ctx ;
    ctx = initialize_ctx(KEY_FILE, PASSWORD);


    /* set CTX communication options to SSLv3 or TLSv1*/
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    /* set cipher list to SHA1 */
    SSL_CTX_set_cipher_list(ctx, "SHA1");

    /* Create a TCP socket:
     1. prepare socket address
     2. open a socket
     3. coonect to the socket */

     /* 1. prepare socket address */
    host_entry=gethostbyname(host) ;
    if (!host_entry) {
        perror("Couldn't resolve host\n");
        exit(0) ;
    }

    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*) host_entry->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

      /* 2. open socket */
    if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0)
        perror("Couldn't create socket");
      /* 3. connect to the socket */
    if(connect(sock,(struct sockaddr *)&addr,sizeof(addr))<0)
        perror("Couldn't connect socket");

    /* Use this TCP socket to create a SSL socket */
    SSL *ssl=SSL_new(ctx);
    BIO *sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);

    /* connect to the SSL socket */
    printf("SSL handshake\n");
    if(SSL_connect(ssl)<=0) {
        //printf("SSL connect error");
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stdout);
        goto finish;
    }

    printf("Checking Server's certificate\n");
    /* Check server's certificate */
    if (!check_cert(ssl))
        goto finish;

    /* send request */
    send_request(ssl, secret);

    finish:
    SSL_CTX_free(ctx) ;
    close(sock);
    return 1;
}

int check_cert(SSL *ssl) {

    X509 *peer;
    char peer_CN[256];
    char peer_email[256];
    char cert_issuer[256];

    peer = SSL_get_peer_certificate(ssl);

    /* check if the certificate is valid */
    if ((NULL == peer)||(SSL_get_verify_result(ssl) != X509_V_OK)) {
       printf(FMT_NO_VERIFY);
       return 0;
    }

    /* check server's common name */
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName,peer_CN,256) ;

    if (strcasecmp(peer_CN, CN_SERVER)) {
         printf(FMT_CN_MISMATCH);
         return 0 ;
    }

    /* check Email address of the server certification subject */
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress,peer_email,256) ;

     if (strcasecmp(peer_email, EMAIL)) {
        printf(FMT_EMAIL_MISMATCH);
        return 0;
    }

    /* print information when both CN and email are correct */
    X509_NAME *issuer_name = X509_get_issuer_name(peer);
    X509_NAME_get_text_by_NID (issuer_name,
                                NID_commonName,
                                cert_issuer,
                                256);

    printf(FMT_SERVER_INFO, peer_CN, peer_email, cert_issuer);
    return 1;
}

int send_request(SSL *ssl, char * request) {

    char buf[BUFSIZZ];
    int request_len = strlen(request);
    int len;

    /* write to ssl connection */
    printf("SSL_WRITE %s\n", request);
    int r = SSL_write(ssl,request,request_len);
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
            if(request_len!=r)
                printf("Incomplete write!");
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            printf(FMT_INCORRECT_CLOSE);
            goto done;
        default:
            printf("SSL write problem");
    }

    /* read from ssl connection */
    while(1){
        r=SSL_read(ssl,buf,BUFSIZZ);
        switch(SSL_get_error(ssl,r)){
            case SSL_ERROR_NONE:
                len=r;
                break;
            case SSL_ERROR_ZERO_RETURN:
                goto shutdown;
            case SSL_ERROR_SYSCALL:
                printf(FMT_INCORRECT_CLOSE);
                goto done;
            default:
                printf("SSL read problem");
        }
        buf[len]='\0';
        printf(FMT_OUTPUT, request, buf);
    }

    shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
        case 1:
            break; /* Success */
        case 0:
        case -1:
        default:
            printf("Shutdown failed");
    }

    done:
    SSL_free(ssl);
    return(0);
  }
