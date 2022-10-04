#include "utils/utils.h"
#include "ntdll/ntdll.h"

#include "hooks/hooks.h"

#include "connection/connection.h"

uint8_t* raw_from_rva( uint64_t rva, IMAGE_NT_HEADERS* nt, void* image )
{
	 auto get_section_header = [ rva, nt ]( ) -> IMAGE_SECTION_HEADER*
	 {
		  IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION( nt );
		  for ( int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++ )
		  {
				uint64_t size = section->Misc.VirtualSize;
				if ( !size )
					 size = section->SizeOfRawData;

				if ( ( rva >= section->VirtualAddress ) && ( rva < ( section->VirtualAddress + size ) ) )
					 return section;
		  }

		  return nullptr;
	 };

	 IMAGE_SECTION_HEADER* section = get_section_header( );
	 if ( !section )
		  return 0;

	 return reinterpret_cast< uint8_t* >( image ) + rva - ( uint64_t )( section->VirtualAddress - section->PointerToRawData );
}

bool apply_patches( )
{
	 UNICODE_STRING file_name = utils::init_unicode_string( ( L"\\SystemRoot\\System32\\ntoskrnl.exe" ) );
	 HANDLE file = nullptr;
	 OBJECT_ATTRIBUTES obj_attr;
	 IO_STATUS_BLOCK io_status_block;
	 __stosb( reinterpret_cast< PUCHAR >( &io_status_block ), 0, sizeof( io_status_block ) );
	 InitializeObjectAttributes( &obj_attr, &file_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );
	 if ( !NT_SUCCESS( utils::system_call( NtOpenFile, &file, FILE_GENERIC_READ, &obj_attr, &io_status_block, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT ) ) )
	 {
		  if ( file )
				utils::system_call( NtClose, file );

		  return false;
	 }

	 FILE_STANDARD_INFORMATION file_info;
	 __stosb( reinterpret_cast< PUCHAR >( &file_info ), 0, sizeof( file_info ) );
	 if ( !NT_SUCCESS( utils::system_call( NtQueryInformationFile, file, &io_status_block, &file_info, sizeof( file_info ), FileStandardInformation ) ) )
	 {
		  utils::system_call( NtClose, file );
		  return false;
	 }

	 void* binary = ExAllocatePoolWithTag( PagedPool, file_info.EndOfFile.LowPart, 'kpbf' );

	 if ( !binary )
	 {
		  utils::system_call( NtClose, file );
		  return false;
	 }

	 LARGE_INTEGER byte_offset;
	 byte_offset.QuadPart = 0;
	 if ( !NT_SUCCESS( utils::system_call( NtReadFile, file, nullptr, nullptr, nullptr, &io_status_block, binary, file_info.EndOfFile.LowPart, &byte_offset, nullptr ) ) )
	 {
		  ExFreePoolWithTag( binary, 'kpbf' );
		  utils::system_call( NtClose, file );
		  return false;
	 }

	 IMAGE_NT_HEADERS* nt = ( IMAGE_NT_HEADERS* )( ( uint64_t )( binary )+reinterpret_cast< IMAGE_DOS_HEADER* >( binary )->e_lfanew );

	 for ( uint32_t i = 0; i < utils::m_kernel_patches.size( ); ++i )
		  __movsb( raw_from_rva( utils::m_kernel_patches[ i ].m_rva, nt, binary ), utils::m_kernel_patches[ i ].m_patches, utils::m_kernel_patches[ i ].m_patch_size );

	 utils::m_kernel_patches.shutdown( );
	 utils::system_call( NtClose, file );

	 wchar_t fake_filename[ 255 ];
	 RtlStringCbPrintfExW( fake_filename, 255 * 2, nullptr, nullptr, STRSAFE_FILL_ON_FAILURE, L"\\SystemRoot\\System32\\%llX",
								  ( ( reinterpret_cast< uint64_t >( apply_patches ) ^ HASH( __TIMESTAMP__ ) ) >> 8 ) ^ HASH( __TIME__ ) );

	 UNICODE_STRING fake_path = utils::init_unicode_string( fake_filename );
	 HANDLE fake_file = nullptr;
	 OBJECT_ATTRIBUTES fake_obj_attr;
	 IO_STATUS_BLOCK fake_io_status_block;
	 __stosb( reinterpret_cast< PUCHAR >( &fake_io_status_block ), 0, sizeof( fake_io_status_block ) );
	 InitializeObjectAttributes( &fake_obj_attr, &fake_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

	 if ( !NT_SUCCESS( utils::system_call( NtCreateFile, &fake_file, GENERIC_WRITE, &fake_obj_attr, &fake_io_status_block, nullptr, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
			FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0 ) ) )
	 {
		  if ( fake_file )
				utils::system_call( NtClose, fake_file );

		  ExFreePoolWithTag( binary, 'kpbf' );
		  return false;
	 }

	 byte_offset.QuadPart = 0;
	 if ( !NT_SUCCESS( utils::system_call( NtWriteFile, fake_file, nullptr, nullptr, nullptr, &fake_io_status_block, binary, file_info.EndOfFile.LowPart, &byte_offset, nullptr ) ) )
	 {
		  utils::system_call( NtClose, fake_file );
		  ExFreePoolWithTag( binary, 'kpbf' );
		  return false;
	 }

	 utils::system_call( NtClose, fake_file );

	 fake_file = nullptr;
	 __stosb( reinterpret_cast< PUCHAR >( &fake_io_status_block ), 0, sizeof( fake_io_status_block ) );
	 if ( !NT_SUCCESS( utils::system_call( NtOpenFile, &fake_file, FILE_GENERIC_READ, &fake_obj_attr, &fake_io_status_block, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT ) ) )
	 {
		  if ( fake_file )
				utils::system_call( NtClose, fake_file );

		  ExFreePoolWithTag( binary, 'kpbf' );
		  return false;
	 }

	 utils::m_fake_ntoskrnl = fake_file;

	 ExFreePoolWithTag( binary, 'kpbf' );

	 return true;
}

NTSTATUS DriverEntry( _DRIVER_OBJECT* drv_object, _UNICODE_STRING* reg_path )
{
#ifdef _DEBUG
	 UNREFERENCED_PARAMETER( drv_object );
	 UNREFERENCED_PARAMETER( reg_path );
	 strcpy( utils::m_key, "qwertyuiop" );
#else
	 drv_log( "%d\n", ( uint32_t )( ( uint64_t )drv_object ) );
	 utils::m_loader_process_id.push( ( uint32_t )( ( uint64_t )drv_object ), true );
	 __movsb( reinterpret_cast< PUCHAR >( utils::m_key ), reinterpret_cast< PUCHAR >( reg_path ), 32 );

	 if ( !g_connection.initialize( ) )
	 {
		  drv_log( "[-] failed to connect to server\n" );
		  return STATUS_FAILED_DRIVER_ENTRY;
	 }

	 start_packet_t start_packet;
	 __stosb( reinterpret_cast< PUCHAR >( &start_packet ), 0, sizeof( start_packet ) );

	 start_packet.m_magic = 0x6265627261;
	 start_packet.m_from_driver = 1;
	 strcpy_s( start_packet.m_key, utils::m_key );

	 if ( !g_connection.send( &start_packet, sizeof( start_packet ) ) )
	 {
		  g_connection.shutdown( );
		  return STATUS_FAILED_DRIVER_ENTRY;
	 }

	 uint64_t answer = 0;
	 if ( !g_connection.recv( &answer, sizeof( answer ) ) )
	 {
		  g_connection.shutdown( );
		  return STATUS_FAILED_DRIVER_ENTRY;
	 }

	 g_connection.shutdown( );

	 if ( answer & ( uint64_t )start_answer_t::BANNED || !( answer & ( uint64_t )start_answer_t::SUCCESS ) )
	 {
		  system_crash( );
	 }

#endif

#pragma warning( push )
#pragma warning( disable : 4244 4311 4302 )
	 utils::m_krnl_process_id = reinterpret_cast< uint32_t >( PsGetCurrentProcessId( ) );

	 if ( !utils::m_krnl.initialize( _( "ntoskrnl.exe" ) ) )
	 {
		  drv_log( "[-] failed to find ntoskrnl.exe\n" );
		  return STATUS_FAILED_DRIVER_ENTRY;
	 }

	 NTSTATUS ntdll_status = g_ntdll.initialize( );
	 if ( !NT_SUCCESS( ntdll_status ) )
	 {
		  drv_log( "[-] failed to initialize ntdll stub with status 0x%lX\n", ntdll_status );
		  return STATUS_FAILED_DRIVER_ENTRY;
	 }

	 if ( !hooks::setup( ) )
	 {
		  drv_log( "[-] failed to setup ssdt hooks\n" );
		  return STATUS_FAILED_DRIVER_ENTRY;
	 }

	 if ( !apply_patches( ) )
	 {
		  drv_log( "[-] Failed to apply patches to kernel file\n" );
		  return STATUS_FAILED_DRIVER_ENTRY; // if compiled as debug - systeme pizda
	 }

	 drv_log( "[+] p2c_loader: initialized\n" );

#pragma warning( pop )
	 return STATUS_SUCCESS;
}