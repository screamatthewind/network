/*
    C ECHO client example using sockets
*/
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include <unistd.h>
#include<arpa/inet.h> //inet_addr
 
int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char message[1000] , server_reply[2000];
     
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
//    server.sin_addr.s_addr = inet_addr("173.225.90.3");
    server.sin_addr.s_addr = inet_addr("10.153.0.10");
    server.sin_family = AF_INET;
    server.sin_port = htons( 1214 );
 
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
     
    puts("Connected\n");
     
    //keep communicating with server
    while(1)
    {
        printf("Enter message : ");
		scanf("%s" , message);
	    
//	    strcpy(message, "GET /omni/stb/?debug&debug_key=cda9fefe14f1735668b33242678a6ac4&mac=00:1A:79:3E:F0:A3");
         
        //Send some data
        if( send(sock , message , strlen(message) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }
         
	    //Receive a reply from the server
		ssize_t len;
        if((len = recv(sock , server_reply , 2000 , 0)) < 0)
        {
            puts("recv failed");
            break;
        }
         
	    server_reply[len] = 0;
	    
        puts("Server reply :");
        puts(server_reply);
    }
     
    close(sock);
    return 0;
}