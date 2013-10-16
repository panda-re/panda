#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int opt=1;

    char buffer[256];
    char buffer2[256];
    bzero(buffer,256);
    bzero(buffer2,256);

    if (argc < 2) {
       fprintf(stderr,"usage %s port [hostname]\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[1]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    // Defaults to localhost
    if (argc == 2) {
        server = gethostbyname("localhost");
    } else {
        server = gethostbyname(argv[2]);
    }
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(const char *)&opt,sizeof(int));
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    // File manipulation
    printf("Please enter the file location: ");
    fgets(buffer2,255,stdin);
    strtok(buffer2, "\n");
    FILE *fp;
    fp = fopen(buffer2,"r");
    if ( fp == 0 ) {
        printf( "ERROR could not open file\n" );
        close(sockfd);
        exit(0);
    }

    int x;
    int i = 0;
    // Reads from file
    while  ( ( x = fgetc(fp) ) != EOF && i < 255) {
        buffer[i] = x;
        i++;
    }
    buffer[i] = '\0';
    fclose(fp);

    // Writes to socket
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0)
         error("ERROR writing to socket");

    // Reads from socket
    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0)
         error("ERROR reading from socket");
    printf("%s\n",buffer);
    close(sockfd);
    return 0;
}
