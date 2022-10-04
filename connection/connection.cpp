#include "ksocket.h"
#include "berkeley.h"

#include "connection.h"

c_connection g_connection;

bool c_connection::initialize( )
{
	 if ( !NT_SUCCESS( KsInitialize( ) ) )
		  return false;

	 SOCKADDR_IN server_info;
	 __stosb( reinterpret_cast< PUCHAR >( &server_info ), 0, sizeof( SOCKADDR_IN ) );

	 server_info.sin_family = AF_INET;
	 server_info.sin_port = htons( 1337 );
	 server_info.sin_addr.S_un.S_addr = 0x100007F;

	 m_socket = socket_connection( AF_INET, SOCK_STREAM, IPPROTO_TCP );
	 if ( m_socket <= 0 )
		  return false;

	 if ( connect( m_socket, reinterpret_cast< const SOCKADDR* >( &server_info ), sizeof( SOCKADDR_IN ) ) != 0 )
	 {
		  closesocket( m_socket );
		  return false;
	 }

	 return true;
}

void c_connection::shutdown( )
{
	 if ( m_socket > 0 )
		  closesocket( m_socket );

	 KsDestroy( );
}
