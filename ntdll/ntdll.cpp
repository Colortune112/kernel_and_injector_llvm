#include "ntdll.h"

c_ntdll g_ntdll;

NTSTATUS c_ntdll::initialize( )
{
	 if ( KeGetCurrentIrql( ) != PASSIVE_LEVEL )
		  return STATUS_UNSUCCESSFUL;

	 UNICODE_STRING ntdll_path = utils::init_unicode_string( _( L"\\SystemRoot\\system32\\ntdll.dll" ) );
	 OBJECT_ATTRIBUTES obj_attributes;
	 InitializeObjectAttributes( &obj_attributes, &ntdll_path,
										  OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
										  nullptr, nullptr );

	 IO_STATUS_BLOCK status_block;
	 HANDLE file;
	 if ( !NT_SUCCESS( utils::system_call( NtCreateFile, &file, GENERIC_READ, &obj_attributes, &status_block, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0 ) ) )
		  return STATUS_FILE_INVALID;

	 FILE_STANDARD_INFORMATION file_info;
	 if ( !NT_SUCCESS( utils::system_call( NtQueryInformationFile, file, &status_block, &file_info, sizeof( file_info ), FileStandardInformation ) ) )
	 {
		  utils::system_call( NtClose, file );
		  return STATUS_FILE_CHECKED_OUT;
	 }

	 void* file_data = ExAllocatePoolWithTag( NonPagedPool, file_info.EndOfFile.LowPart, 'rdnt' );
	 if ( !file_data )
	 {
		  utils::system_call( NtClose, file );
		  return STATUS_MEMORY_NOT_ALLOCATED;
	 }

	 LARGE_INTEGER byte_offset;
	 byte_offset.LowPart = 0;
	 byte_offset.HighPart = 0;

	 NTSTATUS status = utils::system_call( NtReadFile, file, nullptr, nullptr, nullptr, &status_block, file_data, file_info.EndOfFile.LowPart, &byte_offset, nullptr );
	 if ( !NT_SUCCESS( status ) )
	 {
		  ExFreePoolWithTag( file_data, 'rdnt' );
		  utils::system_call( NtClose, file );
		  return status;
	 }

	 IMAGE_NT_HEADERS* nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< IMAGE_DOS_HEADER* >( file_data )->e_lfanew + ( uint64_t )file_data );

	 uint64_t mapped_file = reinterpret_cast< uint64_t >( ExAllocatePoolWithTag( NonPagedPool, nt_headers->OptionalHeader.SizeOfImage, 'mdnt' ) );
	 if ( !mapped_file )
	 {
		  ExFreePoolWithTag( file_data, 'rdnt' );
		  utils::system_call( NtClose, file );
		  return STATUS_MEMORY_NOT_ALLOCATED;
	 }

	 __movsb( reinterpret_cast< PUCHAR >( mapped_file ), reinterpret_cast< PUCHAR >( file_data ), nt_headers->OptionalHeader.SizeOfHeaders );
	 IMAGE_SECTION_HEADER* cur_section = IMAGE_FIRST_SECTION( nt_headers );
	 for ( uint32_t i = 0; i != nt_headers->FileHeader.NumberOfSections; ++i, ++cur_section )
		  __movsb( reinterpret_cast< PUCHAR >( mapped_file + cur_section->VirtualAddress ), reinterpret_cast< PUCHAR >( ( uint64_t )file_data + cur_section->PointerToRawData ),
					  cur_section->SizeOfRawData );

	 nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< IMAGE_DOS_HEADER* >( mapped_file )->e_lfanew + mapped_file );
	 IMAGE_EXPORT_DIRECTORY* exports = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( mapped_file + nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

	 uint32_t* functions_table = reinterpret_cast< uint32_t* >( mapped_file + exports->AddressOfFunctions );
	 uint32_t* names_table = reinterpret_cast< uint32_t* >( mapped_file + exports->AddressOfNames );
	 uint16_t* ordinal_table = reinterpret_cast< uint16_t* >( mapped_file + exports->AddressOfNameOrdinals );

	 for ( uint32_t i = 0; i < exports->NumberOfNames; ++i )
	 {
		  char* name = reinterpret_cast< char* >( mapped_file + names_table[ i ] );
		  if ( *reinterpret_cast< uint16_t* >( name ) == 'wZ' )
				++m_count;
	 }

	 m_indexes = reinterpret_cast< idx* >( ExAllocatePoolWithTag( NonPagedPool, sizeof( idx ) * m_count, 'idxs' ) );
	 __stosb( reinterpret_cast< PUCHAR >( m_indexes ), 0, sizeof( idx ) * m_count );

	 int count = 0;
	 for ( uint32_t i = 0; i < exports->NumberOfNames; ++i )
	 {
		  if ( count >= m_count )
				break;

		  char* name = reinterpret_cast< char* >( mapped_file + names_table[ i ] );
		  uint64_t address = mapped_file + functions_table[ ordinal_table[ i ] ];
		  if ( *reinterpret_cast< uint16_t* >( name ) == 'wZ' )
		  {
				m_indexes[ count ].m_index = *reinterpret_cast< int* >( address + 4 );
				m_indexes[ count ].m_hash = HASH_RT( name );
				++count;
		  }
	 }

	 ExFreePoolWithTag( reinterpret_cast< PVOID >( mapped_file ), 'mdnt' );
	 ExFreePoolWithTag( file_data, 'rdnt' );
	 utils::system_call( NtClose, file );
	 return STATUS_SUCCESS;
}

void c_ntdll::shutdown( )
{
	 ExFreePoolWithTag( m_indexes, 'idxs' );
}

int c_ntdll::get_ssdt_index( uint64_t export_hash )
{
	 for ( int i = 0; i < m_count; ++i )
		  if ( m_indexes[ i ].m_hash == export_hash )
				return m_indexes[ i ].m_index;

	 return -1;
}
