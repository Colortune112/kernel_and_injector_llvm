#include "ssdt.h"

ssdt::ssdt_t* ssdt::m_service_desc_table = 0;

bool ssdt::hook( int index, void* function, void** original, bool shadow )
{
	 UNREFERENCED_PARAMETER( shadow );

	 if ( index < 0 )
		  return false;

	 if ( !m_service_desc_table )
		  m_service_desc_table = utils::find_pattern< ssdt_t >( utils::m_krnl, _( "4C 8D 1D ? ? ? ? 4D 8B CB" ) ).rel( 3 ).m_ptr;

	 uint8_t shell[ ] = { 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0 };
	 *reinterpret_cast< void** >( &shell[ 2 ] ) = function;

	 static uint64_t start = reinterpret_cast< uint64_t >( m_service_desc_table->m_service_table ) + static_cast< uint64_t >( m_service_desc_table->m_service_table[ 0 ] >> 4 );
	 static size_t size = utils::m_krnl.m_size - ( start - utils::m_krnl.m_base );

	 void* cave_address = nullptr;

	 for ( uint64_t scan_address = start, i = 0; scan_address < start + size; ++scan_address )
	 {
		  if ( *reinterpret_cast< uint8_t* >( scan_address ) == 0xCC )
				++i;
		  else
				i = 0;

		  if ( i == sizeof( shell ) )
		  {
				cave_address = reinterpret_cast< void* >( scan_address - i + 1 );
				break;
		  }
	 }

	 if ( !NT_SUCCESS( utils::write_to_readonly_memory( cave_address, shell, sizeof( shell ) ) ) )
	 {
		  drv_log( "[-] Failed to write shell during hooking %d index\n", index );
		  return false;
	 }

	 uint32_t old_val = m_service_desc_table->m_service_table[ index ];
	 uint32_t new_val = static_cast< uint32_t >( ( reinterpret_cast< uint64_t >( cave_address ) - reinterpret_cast< uint64_t >( m_service_desc_table->m_service_table ) ) << 4 ) | old_val & 0xF;

	 if ( !NT_SUCCESS( utils::write_to_readonly_memory( &m_service_desc_table->m_service_table[ index ], &new_val, sizeof( uint32_t ) ) ) )
		  return false;

	 if ( original )
		  *original = reinterpret_cast< void* >( static_cast< uint64_t >( old_val >> 4 ) + reinterpret_cast< uint64_t >( m_service_desc_table->m_service_table ) );

	 return true;
}