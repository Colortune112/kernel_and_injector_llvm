#pragma once

#include <ntddk.h>
#include <wsk.h>

typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef int       socklen_t;
typedef intptr_t  ssize_t;

unsigned int htonl( unsigned int hostlong );
unsigned short htons( unsigned short hostshort );
unsigned int ntohl( unsigned int netlong );
unsigned short ntohs( unsigned short netshort );

int getaddrinfo( const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res );
void freeaddrinfo( struct addrinfo* res );

extern int socket_connection( int domain, int type, int protocol );
int socket_listen( int domain, int type, int protocol );
int socket_datagram( int domain, int type, int protocol );
int connect( int sockfd, const struct sockaddr* addr, socklen_t addrlen );
int listen( int sockfd, int backlog );
int bind( int sockfd, const struct sockaddr* addr, socklen_t addrlen );
int accept( int sockfd, struct sockaddr* addr, socklen_t* addrlen );
int send( int sockfd, const void* buf, size_t len, int flags );
int sendto( int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen );
int recv( int sockfd, void* buf, size_t len, int flags );
int recvfrom( int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen );
int closesocket( int sockfd );

#define socket  socket_connection
