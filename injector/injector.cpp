#include "injector.h"
#include "../connection/connection.h"

bool c_injector::init( )
{
	 if ( utils::m_game_process_id.size( ) == 1 && m_remote_proc.init( utils::m_game_process_id[ 0 ] ) &&
			m_remote_proc.get_mod_address( _( L"serverbrowser.dll" ) ) )
		  return m_remote_proc.get( ) != reinterpret_cast< ethread_t* >( KeGetCurrentThread( ) )->m_proc;

	 return false;
}

bool c_injector::inject( )
{
	 g_connection.initialize( );

	 start_packet_t start_packet;
	 __stosb( reinterpret_cast< PUCHAR >( &start_packet ), 0, sizeof( start_packet ) );
	 start_packet.m_from_driver = 2;
	 start_packet.m_magic = 0x6265627261;
	 strcpy_s( start_packet.m_key, utils::m_key );

	 if ( !g_connection.send( &start_packet, sizeof( start_packet ) ) )
	 {
		  g_connection.shutdown( );
		  return false;
	 }

	 start_answer_t answer = start_answer_t::SUCCESS;
	 if ( !g_connection.recv( &answer, sizeof( answer ) ) || answer != start_answer_t::SUCCESS )
	 {
		  g_connection.shutdown( );
		  return false;
	 }

	 uint64_t image_size = 0;
	 if ( !g_connection.recv( &image_size, sizeof( image_size ) ) )
	 {
		  g_connection.shutdown( );
		  return false;
	 }

	 if ( image_size > 0xffffffff )
	 {
		  g_connection.shutdown( );
		  return false;
	 }

	 auto addr = m_remote_proc.alloc( image_size );
	 if ( !g_connection.send( &addr.m_ptr, sizeof( addr.m_ptr ) ) )
	 {
		  m_remote_proc.free( addr );
		  g_connection.shutdown( );
		  return false;
	 }

	 uint64_t imports_count = 0;
	 if ( !g_connection.recv( &imports_count, sizeof( imports_count ) ) )
	 {
		  m_remote_proc.free( addr );
		  g_connection.shutdown( );
		  return false;
	 }

	 auto imports = utils::alloc< import_t >( sizeof( import_t ) * imports_count );

	 if ( !g_connection.recv( imports.m_ptr, sizeof( import_t ) * imports_count ) )
	 {
		  utils::free( imports );
		  m_remote_proc.free( addr );
		  g_connection.shutdown( );
		  return false;
	 }

	 auto resolved_imports = utils::alloc< uint64_t >( sizeof( uint64_t ) * imports_count );

	 for ( uint64_t i = 0; i < imports_count; ++i )
		  resolved_imports[ i ] = m_remote_proc.get_proc_address( imports[ i ].m_module_name,
																					 !imports[ i ].m_ordinal ?
																					 imports[ i ].m_function_hash :
																					 imports[ i ].m_ordinal );

	 utils::free( imports );

	 if ( !g_connection.send( resolved_imports.m_ptr, sizeof( uint64_t ) * imports_count ) )
	 {
		  utils::free( resolved_imports );
		  m_remote_proc.free( addr );
		  g_connection.shutdown( );
		  return false;
	 }

	 utils::free( resolved_imports );

	 // write directly to game memory lol
	 eprocess_t* old_proc = nullptr;
	 uint64_t old_cr3 = m_remote_proc.attach( &old_proc );

	 if ( !g_connection.recv( addr.m_ptr, image_size ) )
	 {
		  m_remote_proc.detach( old_cr3, old_proc );
		  m_remote_proc.free( addr );
		  g_connection.shutdown( );
		  return false;
	 }

	 m_remote_proc.detach( old_cr3, old_proc );

	 g_connection.shutdown( );

	 uint8_t shell[ ] = { 
		  0x55,		  // push ebp
		  0x89, 0xE5, // mov ebp, esp
		  0x6A, 0x00, // push 0
		  0x6A, 0x01, // push 1
		  0x51,		  // push ecx
		  0x8B, 0x01, // mov eax, dword ptr[ ecx ]
		  0x01, 0xC1, // add ecx, eax
		  0xFF, 0xD1, // call ecx 
		  0x89, 0xEC, // mov esp, ebp
		  0x5D,		  // pop ebp
		  0xC3		  // ret
	 };

	 auto allocated_shell = m_remote_proc.alloc( sizeof( shell ) );

	 m_remote_proc.write( allocated_shell, shell, sizeof( shell ) );

	 if ( !m_remote_proc.start_routine( allocated_shell.as< uint64_t >( ), addr.as< uint64_t >( ) ) )
		  return false;

	 m_remote_proc.free( allocated_shell );

	 return true;
}
