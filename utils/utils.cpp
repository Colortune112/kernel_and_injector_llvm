#include "utils.h"

#include "../ssdt/ssdt.h"
#include "../ntdll/ntdll.h"

utils::module_t utils::m_krnl;
uint32_t utils::m_krnl_process_id;
char utils::m_key[ 32 ];

UNICODE_STRING utils::init_unicode_string( wchar_t* str )
{
	 UNICODE_STRING uni_str;
	 uni_str.Buffer = str;
	 size_t length = strlen( str );

	 size_t end_length = length * 2;
	 if ( end_length == 0xFFFE )
		  end_length = 0xFFFC;

	 uni_str.Length = static_cast< USHORT >( end_length );
	 uni_str.MaximumLength = static_cast< USHORT >( end_length ) + 2;

	 return uni_str;
}

void pattern_to_bytes( utils::c_vector< int32_t, 'pat' >& bytes, const char* pattern )
{
	 char* start = const_cast< char* >( pattern );
	 char* end = start + utils::strlen( pattern );

	 for ( char* current = start; current < end; ++current )
	 {
		  if ( *current == '?' )
		  {
				++current;
				if ( *current == '?' )
					 ++current;
				bytes.push( -1 );
		  }
		  else
		  {
				bytes.push( utils::strtoul( current, &current, 16 ) );
		  }
	 }
}

uint64_t utils::find_pattern_stub( module_t mod, const char* pattern )
{
	 c_vector< int32_t, 'pat' > bytes = c_vector< int32_t, 'pat' >( );
	 pattern_to_bytes( bytes, pattern );
	 uint32_t bytes_size = bytes.size( );

	 IMAGE_NT_HEADERS* nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( mod.m_base + reinterpret_cast< IMAGE_DOS_HEADER* >( mod.m_base )->e_lfanew );

	 IMAGE_SECTION_HEADER* current_section = IMAGE_FIRST_SECTION( nt_headers );
	 for ( uint32_t c = 0; c != nt_headers->FileHeader.NumberOfSections; ++c, ++current_section )
	 {
		  if ( current_section->SizeOfRawData && current_section->SizeOfRawData > bytes_size
				 && ( current_section->Characteristics & IMAGE_SCN_CNT_CODE || current_section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
		  {
				uint8_t* scan_bytes = reinterpret_cast< uint8_t* >( mod.m_base + current_section->VirtualAddress );

				for ( uint32_t i = 0; i < current_section->SizeOfRawData - bytes_size; ++i )
				{
					 bool found = true;

					 for ( uint32_t j = 0; j < bytes_size; ++j )
					 {
						  if ( scan_bytes[ i + j ] != bytes[ j ] && bytes[ j ] != -1 )
						  {
								found = false;
								break;
						  }
					 }

					 if ( found )
					 {
						  bytes.shutdown( );
						  return ( uint64_t )( &scan_bytes[ i ] );
					 }
				}
		  }
	 }

	 bytes.shutdown( );

	 return 0;
}

uint32_t utils::strtoul( const char* nptr, char** endptr, int base )
{
	 const char* s = nptr;
	 unsigned long acc;
	 int c;
	 unsigned long cutoff;
	 int neg = 0, any, cutlim;

#define is_space( x ) ( x == ( int32_t )( ' ' ) )
#define is_alpha( x ) ( ( ( int32_t )( x ) >= ( int32_t )( 'A' ) && ( int32_t )( x ) <= ( int32_t )( 'Z' ) ) || ( ( int32_t )( x ) >= ( int32_t )( 'a' ) && ( int32_t )( x ) <= ( int32_t )( 'z' ) ) )
#define is_digit( x ) ( ( int32_t )( x ) >= ( int32_t )( '0' ) && ( int32_t )( x ) <= ( int32_t )( '9' ) )
#define is_upper( x ) ( ( int )( x ) >= ( int )( 'A' ) && ( int )( x ) <= ( int )( 'Z' ) )

	 do
	 {
		  c = *s++;
	 } while ( is_space( c ) );
	 if ( c == '-' )
	 {
		  neg = 1;
		  c = *s++;
	 }
	 else if ( c == '+' )
		  c = *s++;
	 if ( ( !base || base == 16 ) &&
			c == '0' && ( *s == 'x' || *s == 'X' ) )
	 {
		  c = s[ 1 ];
		  s += 2;
		  base = 16;
	 }
	 if ( !base )
		  base = c == '0' ? 8 : 10;
	 cutoff = ( unsigned long )0xffffffffUL / ( unsigned long )base;
	 cutlim = ( unsigned long )0xffffffffUL % ( unsigned long )base;
	 for ( acc = 0, any = 0;; c = *s++ )
	 {
		  if ( is_digit( c ) )
				c -= '0';
		  else if ( is_alpha( c ) )
				c -= is_upper( c ) ? 'A' - 10 : 'a' - 10;
		  else
				break;
		  if ( c >= base )
				break;
		  if ( any < 0 || acc > cutoff || acc == cutoff && c > cutlim )
				any = -1;
		  else
		  {
				any = 1;
				acc *= base;
				acc += c;
		  }
	 }
	 if ( any < 0 )
	 {
		  acc = 0xffffffffUL;
	 }

	 if ( endptr != 0 )
		  *endptr = ( char* )( any ? s - 1 : nptr );
	 return ( acc );
}

NTSTATUS utils::write_to_readonly_memory( void* dst, void* src, uint64_t size )
{
	 KIRQL irql = KeRaiseIrqlToDpcLevel( );

	 MDL* mem_desc_list = IoAllocateMdl( dst, static_cast< uint32_t >( size ), 0, 0, nullptr );
	 if ( !mem_desc_list )
	 {
		  KeLowerIrql( irql );
		  return STATUS_MEMORY_NOT_ALLOCATED;
	 }

	 MmBuildMdlForNonPagedPool( mem_desc_list );

#pragma prefast( push )
#pragma prefast( disable:__WARNING_MODIFYING_MDL, "tak nado" )

	 short orig_flags = mem_desc_list->MdlFlags;

	 mem_desc_list->MdlFlags |= MDL_PAGES_LOCKED;
	 mem_desc_list->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

	 void* mapped = MmMapLockedPagesSpecifyCache( mem_desc_list, KernelMode, MmCached, nullptr, FALSE, HighPagePriority );
	 if ( !mapped )
	 {
		  mem_desc_list->MdlFlags = orig_flags;
		  IoFreeMdl( mem_desc_list );
		  KeLowerIrql( irql );
		  return STATUS_NONE_MAPPED;
	 }

	 if ( size == 4 )
		  _InterlockedExchange( reinterpret_cast< LONG* >( mapped ), *reinterpret_cast< LONG* >( src ) );
	 else if ( size == 8 )
		  _InterlockedExchange64( reinterpret_cast< LONG64* >( mapped ), *reinterpret_cast< LONG64* >( src ) );
	 else
		  __movsb( reinterpret_cast< PUCHAR >( mapped ), reinterpret_cast< const UCHAR* >( src ), size );

	 MmUnmapLockedPages( mapped, mem_desc_list );
	 mem_desc_list->MdlFlags = orig_flags;

#pragma prefast( pop )

	 IoFreeMdl( mem_desc_list );
	 KeLowerIrql( irql );

	 patch_t patch;
	 patch.m_rva = reinterpret_cast< uint64_t >( dst ) - utils::m_krnl.m_base;
	 patch.m_patch_size = size;
	 __movsb( reinterpret_cast< PUCHAR >( patch.m_patches ), reinterpret_cast< PUCHAR >( src ), size );

	 m_kernel_patches.push( patch );

	 return STATUS_SUCCESS;
}

void utils::sleep( uint64_t ms )
{
	 static NTSTATUS( *nt_delay_execution )( BOOLEAN, LARGE_INTEGER* ) = ssdt::get_ssdt_function< decltype( nt_delay_execution ) >( g_ntdll.get_ssdt_index( HASH( "ZwDelayExecution" ) ) );

	 LARGE_INTEGER interval;
	 interval.QuadPart = -10000 * static_cast< int64_t >( ms );
	 system_call( nt_delay_execution, false, &interval );
}

bool utils::module_t::initialize( const char* mod_name )
{
	 ULONG mod_info_size = 0;
	 if ( !NT_SUCCESS( utils::system_call( NtQuerySystemInformation, SystemModuleInformation, nullptr, mod_info_size, &mod_info_size ) ) && mod_info_size == 0 )
	 {
		  drv_log( "[-] failed to query information\n" );
		  return false;
	 }

	 sys_module_info_t* sys_mod_info = reinterpret_cast< sys_module_info_t* >( ExAllocatePoolWithTag( NonPagedPool, mod_info_size, 'ssmi' ) );;
	 if ( !sys_mod_info )
	 {
		  drv_log( "[-] failed to allocate memory\n" );
		  return false;
	 }

	 __stosb( reinterpret_cast< PUCHAR >( sys_mod_info ), 0, mod_info_size );

	 if ( !NT_SUCCESS( utils::system_call( NtQuerySystemInformation, SystemModuleInformation, sys_mod_info, mod_info_size, &mod_info_size ) ) )
	 {
		  ExFreePoolWithTag( sys_mod_info, 'ssmi' );
		  drv_log( "[-] failed to query information2\n" );
		  return false;
	 }

	 for ( uint32_t i = 0; i < sys_mod_info->m_count; ++i )
	 {
		  sys_module_entry_t entry = sys_mod_info->m_module[ i ];
		  if ( utils::strstr( ( const char* )entry.m_full_path_name, mod_name ) )
		  {
				m_base = entry.m_image_base;
				m_size = entry.m_image_size;
				break;
		  }
	 }

	 ExFreePoolWithTag( sys_mod_info, 'ssmi' );
	 return m_base > 0 && m_size > 0;
}
