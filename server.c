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

#define PORT 8765
#define KEY_FILE "bob.pem"

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

int receive_request( SSL *ssl, int s);
void print_client_info (SSL *ssl);

int main(int argc, char **argv)
{
    int s, sock, port=PORT;
    struct sockaddr_in sin;
    int val=1, r ;
    pid_t pid;

    /*Parse command line arguments*/

    switch(argc){
        case 1:
            break;
        case 2:
            port=atoi(argv[1]);
            if (port<1||port>65535){
                fprintf(stderr,"invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s port\n", argv[0]);
            exit(0);
    }
    
    /* create server's SSL context */    
    SSL_CTX *ctx = initialize_ctx(KEY_FILE, "password");
    
    /* set option to support cipher suites available for SSLv2, SSLv3, TLSv1*/
    SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
    //SSL_CTX_set_cipher_list(ctx, "SHA256");


    /*set verification mode for all to certificate based*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    
    /* create TCP socket */
    if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
        perror("socket");
        close(sock);
        exit(0);
    }
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr=INADDR_ANY;
    sin.sin_family=AF_INET;
    sin.sin_port=htons(port);

    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));

    /* bind the socket */
    if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
        perror("bind");
        close(sock);
        exit (0);
    }

    /* listen on the socket */
    if(listen(sock,5)<0){
        perror("listen");
        close(sock);
        exit (0);
    }

    while(1){
        if((s=accept(sock, NULL, 0))<0){
            perror("accept");
            close(sock);
            close(s);
            exit (0);
        }

        /*fork a child to handle the connection*/
        if((pid=fork())){
            close(s);
        }
        /* child code */
        else {
            
            /* set up SSL socket */
            BIO *sbio = BIO_new_socket(s, BIO_NOCLOSE);
            SSL *ssl = SSL_new(ctx);
            SSL_set_bio(ssl, sbio, sbio);

            printf("new connection..handshake..SSL_accept\n");
            /* ssl handshake on server side */
            if((r=SSL_accept(ssl)<=0)) {
                /* he TLS/SSL handshake was not successful */
                printf(FMT_ACCEPT_ERR);
                ERR_print_errors_fp(stdout);
                close(s);
                exit (0);            
            }

            /* print ClientCN and email when client has a valid certificate */
            print_client_info(ssl);                        
            
            /* receive and respond the request from client */
            receive_request(ssl, s);

            return 0;
        }
    }
    
    SSL_CTX_free(ctx) ;
    close(sock);
    return 1;
}

void print_client_info (SSL *ssl) {
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    peer = SSL_get_peer_certificate(ssl);
    if ((NULL == peer)||(SSL_get_verify_result(ssl) != X509_V_OK)) {
       printf(FMT_ACCEPT_ERR);
       ERR_print_errors_fp(stdout);
       return;
    }

    
    X509_NAME_get_text_by_NID (X509_get_subject_name(peer), 
                                NID_commonName, 
                                peer_CN, 
                                256);
   
    X509_NAME_get_text_by_NID (X509_get_subject_name(peer), 
                                NID_pkcs9_emailAddress, 
                                peer_email, 
                                256);
    
    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
    
}

int receive_request( SSL *ssl, int s) {
    
    char buf[BUFSIZZ];
    int r ;//, len;
    char *answer = "42";

    //read from ssl connection
    r=SSL_read(ssl,buf,BUFSIZZ);
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          //len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          printf(FMT_INCOMPLETE_CLOSE);
          goto done;
        default:
          printf("SSL read problem");
    }
    
    //write to ssl connection
    printf(FMT_OUTPUT, buf, answer);
    r = SSL_write(ssl,answer,strlen(answer));
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
            if(strlen(answer)!=r)
                printf("Incomplete write!");
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            printf(FMT_INCOMPLETE_CLOSE);
            goto done;
        default:
            printf("SSL write problem");
    }
    
    shutdown:
    r=SSL_shutdown(ssl);
    if(!r){
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify*/
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }
      
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
    close(s);
    return 0;
}

