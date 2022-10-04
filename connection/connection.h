#pragma once

#include <intrin.h>
#include <immintrin.h>

#include "../utils/address.h"

enum class start_answer_t : uint64_t
{
	 SUCCESS = 1 << 0,
	 HWID_MISMATCH = 1 << 1,
	 INVALID_KEY = 1 << 2,
	 BANNED = 1 << 3,
	 UNKNOWN_ERROR = 1 << 4,
	 EXPIRED_KEY = 1 << 5
};

struct start_packet_t
{
	 unsigned long long m_magic;
	 unsigned char m_from_driver;
	 char m_key[ 255 ];
	 unsigned long long m_hwid_hash;
};

struct import_t
{
	 char m_module_name[ 128 ];
	 uint64_t m_function_hash;
	 uint64_t m_ordinal;
};

extern int recv( int sockfd, void* buf, size_t len, int flags );
extern int send( int sockfd, const void* buf, size_t len, int flags );

__forceinline void crypt( void* buf, void** crypted, size_t size )
{
	 if ( !*crypted )
		  return;

	 for ( int i = 0; i < size / 4; ++i )
		  *( ( uint64_t* )( *crypted ) + i ) = ~_byteswap_uint64( _rotl64( *( ( uint32_t* )buf + i ), 7 ) );
}

inline void decrypt( void* buf, void** decrypted, size_t size )
{
	 if ( !*decrypted )
		  return;

	 for ( int i = 0; i < size / 8; ++i )
		  *( ( uint32_t* )( *decrypted ) + i ) = ( uint32_t )( _rotr64( _byteswap_uint64( ~*( ( uint64_t* )( buf )+i ) ), 7 ) );
}

class c_connection
{
private:
	 int m_socket;

public:
	 bool initialize( );
	 void shutdown( );

	 inline bool send( void* buf, size_t size )
	 {
		  auto addr = utils::alloc< void* >( size * 2 );
		  void* tmp = ( void* )addr.m_ptr;
		  crypt( buf, &tmp, size );
		  bool ret = ::send( m_socket, reinterpret_cast< const char* >( tmp ), size * 2, 0 ) > 0;
		  utils::free( addr );
		  return ret;
	 }

	 inline bool recv( void* buf, size_t size )
	 {
		  auto addr = utils::alloc< void* >( size * 2 );
		  void* tmp = ( void* )addr.m_ptr;
		  bool ret = ::recv( m_socket, reinterpret_cast< char* >( tmp ), size * 2, 0 ) > 0;
		  decrypt( tmp, &buf, size * 2 );
		  utils::free( addr );
		  return ret;
	 }
};

extern c_connection g_connection;