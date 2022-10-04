#include "hooks.h"

#include "../ntdll/ntdll.h"
#include "../ssdt/ssdt.h"
#include "../utils/remote_proc.h"
#include "../injector/injector.h"

#pragma warning( disable : 4244 4311 4302 )

bool hooks::setup( )
{
	 return ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwDebugActiveProcess" ) ), hk_nt_debug_active_process, reinterpret_cast< void** >( &o_nt_debug_active_process ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwOpenProcess" ) ), hk_nt_open_process, reinterpret_cast< void** >( &o_nt_open_process ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwQueryInformationProcess" ) ), hk_nt_query_information_process, reinterpret_cast< void** >( &o_nt_query_information_process ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwLoadDriver" ) ), hk_nt_load_driver, reinterpret_cast< void** >( &o_nt_load_driver ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwOpenThread" ) ), hk_nt_open_thread, reinterpret_cast< void** >( &o_nt_open_thread ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwQueryVirtualMemory" ) ), hk_nt_query_virtual_memory, reinterpret_cast< void** >( &o_nt_query_virtual_memory ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwCreateUserProcess" ) ), hk_nt_create_user_process, reinterpret_cast< void** >( &o_nt_create_user_process ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwReadFile" ) ), hk_nt_read_file, reinterpret_cast< void** >( &o_nt_read_file ) ) &&
		  ssdt::hook( g_ntdll.get_ssdt_index( HASH( "ZwSuspendThread" ) ), hk_nt_suspend_thread, reinterpret_cast< void** >( &o_nt_suspend_thread ) );
}

int is_allowed_process( )
{
	 eprocess_t* eproc = reinterpret_cast< eprocess_t* >( IoGetCurrentProcess( ) );

	 static wchar_t game_launcher_path[ 255 ];
	 static bool once = false;
	 if ( !utils::m_allowed_process_id.size( ) )
		  once = false;

	 if ( !once && utils::m_allowed_process_id.size( ) == 1 )
	 {
		  once = true;
		  __stosb( reinterpret_cast< PUCHAR >( game_launcher_path ), 0, 255 * 2 );

		  c_remote_proc proc;
		  if ( proc.init( utils::m_allowed_process_id[ 0 ] ) )
		  {
				if ( proc.is_wow64( ) )
				{
					 peb32_t peb;
					 proc.read( &peb, proc.get( )->m_wow64_process->m_peb, sizeof( peb ) );

					 if ( !peb.m_user_process_params )
					 {
						  once = false;
					 }
					 else
					 {
						  rtl_user_process_params32_t params;
						  proc.read( &params, peb.m_user_process_params, sizeof( params ) );
						  proc.read( game_launcher_path, params.m_dir.m_dos_path.m_buffer, params.m_dir.m_dos_path.m_length * 2 );
					 }
				}
				else
				{
					 peb_t peb;
					 proc.read( &peb, proc.get( )->m_peb, sizeof( peb ) );

					 if ( !peb.m_user_process_params )
					 {
						  once = false;
					 }
					 else
					 {
						  rtl_user_process_params_t params;
						  proc.read( &params, peb.m_user_process_params, sizeof( params ) );
						  proc.read( game_launcher_path, params.m_dir.m_dos_path.m_buffer, params.m_dir.m_dos_path.m_length * 2 );
					 }
				}
		  }
	 }

	 wchar_t* image_path_name = nullptr;
	 if ( eproc->m_wow64_process )
	 {
		  if ( eproc->m_wow64_process->m_peb && eproc->m_wow64_process->m_peb->m_user_process_params )
				image_path_name = ( wchar_t* )reinterpret_cast< rtl_user_process_params32_t* >( eproc->m_wow64_process->m_peb->m_user_process_params )->m_image_path_name.m_buffer;
	 }
	 else
	 {
		  if ( eproc->m_peb && eproc->m_peb->m_user_process_params )
				image_path_name = eproc->m_peb->m_user_process_params->m_image_path_name.m_buffer;
	 }

	 if ( image_path_name )
	 {
		  wchar_t scan_name[ 255 ];
		  RtlStringCbPrintfExW( scan_name, 255 * 2, nullptr, nullptr, STRSAFE_NULL_ON_FAILURE,
										_( L"%wssteamservice.exe" ), game_launcher_path );
		  if ( !_wcsicmp( scan_name, image_path_name ) )
				return true;
		  __stosw( scan_name, 0, 255 );
		  RtlStringCbPrintfExW( scan_name, 255 * 2, nullptr, nullptr, STRSAFE_NULL_ON_FAILURE,
										_( L"%wsGameOverlayUI.exe" ), game_launcher_path );
		  if ( !_wcsicmp( scan_name, image_path_name ) )
				return true;
	 }

	 if ( ExGetPreviousMode( ) || eproc->m_process_id != utils::m_krnl_process_id )
	 {
		  if ( utils::m_allowed_process_id.find( eproc->m_process_id ) )
				return true;

		  if ( eproc->m_flags3 & 0x1000 ) // system_process
				return true;

		  if ( !_stricmp( eproc->m_image_file_name, _( "MsMpEng.exe" ) ) )
				return true;

		  peb_t* proc_env_block = eproc->m_peb;

		  if ( image_path_name && ( !_wcsicmp( image_path_name, _( L"C:\\Windows\\system32\\csrss.exe" ) ) ||
				 !_wcsicmp( image_path_name, _( L"C:\\Windows\\system32\\lsass.exe" ) ) ) )
				return 1;

		  if ( image_path_name && ( !_wcsicmp( image_path_name, _( L"C:\\Windows\\explorer.exe" ) ) ||
				 !_wcsicmp( image_path_name, _( L"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" ) ) ||
				 !_wcsicmp( image_path_name, _( L"C:\\Windows\\System32\\svchost.exe" ) ) ||
				 !_wcsicmp( image_path_name, _( L"C:\\Windows\\system32\\AUDIODG.EXE" ) ) ||
				 !_wcsicmp( image_path_name, _( L"C:\\Windows\\system32\\ctfmon.exe" ) ) ) )
				return 2;

		  if ( eproc->m_wow64_process )
		  {
				peb32_t* proc_env_block32 = eproc->m_wow64_process->m_peb;

				if ( proc_env_block32->m_flags & 2 || proc_env_block32->m_flags & 0x40 ) // protected_process || protected_proccess_light
					 return true;
		  }

		  if ( proc_env_block )
		  {
				if ( proc_env_block->m_flags & 2 || proc_env_block->m_flags & 0x40 ) // protected_process || protected_proccess_light
					 return true;
		  }
	 }

	 return true;
}

void validate_pids( )
{
	 for ( uint32_t i = 0; i < utils::m_allowed_process_id.size( ); ++i )
	 {
		  eprocess_t* proc = nullptr;
		  if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( utils::m_allowed_process_id[ i ] ), reinterpret_cast< PEPROCESS* >( &proc ) ) ) || !proc ||
				 proc->m_exit_status != STATUS_PENDING )
				utils::m_allowed_process_id.erase( i );
	 }

	 for ( uint32_t i = 0; i < utils::m_game_process_id.size( ); ++i )
	 {
		  eprocess_t* proc = nullptr;
		  if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( utils::m_game_process_id[ i ] ), reinterpret_cast< PEPROCESS* >( &proc ) ) ) || !proc ||
				 proc->m_exit_status != STATUS_PENDING )
				utils::m_game_process_id.erase( i );
	 }

	 for ( uint32_t i = 0; i < utils::m_loader_process_id.size( ); ++i )
	 {
		  eprocess_t* proc = nullptr;
		  if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( utils::m_loader_process_id[ i ] ), reinterpret_cast< PEPROCESS* >( &proc ) ) ) || !proc )
				utils::m_loader_process_id.erase( i );
	 }
}

NTSTATUS hooks::hk_nt_debug_active_process( HANDLE proc_handle, HANDLE debug_object_handle )
{
	 KIRQL old_irql = KeGetCurrentIrql( );
	 if ( old_irql != PASSIVE_LEVEL )
		  KeLowerIrql( PASSIVE_LEVEL );

	 validate_pids( );

	 eprocess_t* proc = nullptr;
	 NTSTATUS status = ObReferenceObjectByHandle( proc_handle, 0x400, *PsProcessType, ExGetPreviousMode( ), reinterpret_cast< PVOID* >( &proc ), nullptr );

	 if ( old_irql != PASSIVE_LEVEL )
		  KfRaiseIrql( old_irql );

	 if ( NT_SUCCESS( status ) && ( utils::m_game_process_id.find( proc->m_process_id ) || utils::m_loader_process_id.find( proc->m_process_id ) ) )
	 {
		  if ( proc )
				ObfDereferenceObject( proc );

		  return STATUS_ACCESS_DENIED;
	 }

	 if ( proc )
		  ObfDereferenceObject( proc );

	 return o_nt_debug_active_process( proc_handle, debug_object_handle );
}

NTSTATUS hooks::hk_nt_open_process( HANDLE* proc_handle, ACCESS_MASK access_mask, OBJECT_ATTRIBUTES* obj_attr, CLIENT_ID* client_id )
{
	 if ( proc_handle == reinterpret_cast< HANDLE >( -1 ) )
		  return o_nt_open_process( proc_handle, access_mask, obj_attr, client_id );

	 {
		  eprocess_t* proc = reinterpret_cast< eprocess_t* >( IoGetCurrentProcess( ) );
		  if ( !_stricmp( proc->m_image_file_name, _( "MsMpEng.exe" ) ) )
				access_mask &= ~( 0x0002 | 0x0200 | 0x0800 | 0x0001 | 0x0020 );
	 }

	 validate_pids( );	 

	 if ( ( utils::m_loader_process_id.find( ( uint32_t )client_id->UniqueProcess ) || utils::m_game_process_id.find( ( uint32_t )client_id->UniqueProcess ) ) &&
			( !utils::m_loader_process_id.find( ( uint32_t )PsGetCurrentProcessId( ) ) && !utils::m_game_process_id.find( ( uint32_t )PsGetCurrentProcessId( ) ) ) )
	 {
		  int is_allowed = is_allowed_process( );

		  if ( !is_allowed )
				return STATUS_ACCESS_DENIED;
		  else if ( is_allowed == 2 )
				access_mask &= ~( 0x0080 | 0x0002 | 0x0040 | 0x0200 | 0x0100 | 0x0800 | 0x0001 | 0x0008 | 0x0010 | 0x0020 );
	 }

	 NTSTATUS ret = o_nt_open_process( proc_handle, access_mask, obj_attr, client_id );

	 static char once = FALSE;
	 if ( utils::m_game_process_id.size( ) == 1 )
	 {
		  if ( _InterlockedCompareExchange8( &once, TRUE, FALSE ) == FALSE )
		  {
				if ( g_injector.init( ) )
					 g_injector.inject( );
				else
					 _InterlockedExchange8( &once, FALSE );
		  }
	 }
	 else
		  _InterlockedExchange8( &once, FALSE );

	 return ret;
}

NTSTATUS hooks::hk_nt_query_information_process( HANDLE proc_handle, PROCESSINFOCLASS process_information_class, PVOID process_information, ULONG process_information_length,
																 PULONG return_length )
{
	 KIRQL old_irql = KeGetCurrentIrql( );
	 if ( old_irql != PASSIVE_LEVEL )
		  KeLowerIrql( PASSIVE_LEVEL );

	 validate_pids( );

	 eprocess_t* proc = nullptr;
	 NTSTATUS status = ObReferenceObjectByHandle( proc_handle, 0x400, *PsProcessType, ExGetPreviousMode( ), reinterpret_cast< PVOID* >( &proc ), nullptr );

	 if ( old_irql != PASSIVE_LEVEL )
		  KfRaiseIrql( old_irql );

	 if ( NT_SUCCESS( status ) && proc->m_process_id != reinterpret_cast< uint64_t >( PsGetCurrentProcessId( ) ) &&
			( utils::m_game_process_id.find( proc->m_process_id ) || utils::m_loader_process_id.find( proc->m_process_id ) ) && !is_allowed_process( ) )
	 {
		  if ( proc )
				ObfDereferenceObject( proc );

		  return STATUS_ACCESS_DENIED;
	 }

	 if ( proc )
		  ObfDereferenceObject( proc );

	 return o_nt_query_information_process( proc_handle, process_information_class, process_information, process_information_length, return_length );
}

NTSTATUS hooks::hk_nt_load_driver( UNICODE_STRING* drv_service_name )
{
	 HANDLE reg_key;
	 UNICODE_STRING val_name = utils::init_unicode_string( _( L"ImagePath" ) );
	 OBJECT_ATTRIBUTES obj_attr;
	 InitializeObjectAttributes( &obj_attr, drv_service_name, OBJ_KERNEL_HANDLE, nullptr, nullptr );

	 static NTSTATUS( NTAPI * nt_open_key )( HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES* ) = ssdt::get_ssdt_function< decltype( nt_open_key ) >( g_ntdll.get_ssdt_index( HASH( "ZwOpenKey" ) ) );
	 static NTSTATUS( NTAPI * nt_query_value_key )( HANDLE, UNICODE_STRING*, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG ) = ssdt::get_ssdt_function< decltype( nt_query_value_key ) >( g_ntdll.get_ssdt_index( HASH( "ZwQueryValueKey" ) ) );

	 if ( !NT_SUCCESS( utils::system_call( nt_open_key, &reg_key, KEY_QUERY_VALUE, &obj_attr ) ) )
		  return o_nt_load_driver( drv_service_name );

	 ULONG length = 0;
	 NTSTATUS status = utils::system_call( nt_query_value_key, reg_key, &val_name, KeyValueFullInformation, 0, 0, &length );
	 if ( !NT_SUCCESS( status ) && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
	 {
		  utils::system_call( NtClose, reg_key );
		  return o_nt_load_driver( drv_service_name );
	 }

	 KEY_VALUE_FULL_INFORMATION* key_info = reinterpret_cast< KEY_VALUE_FULL_INFORMATION* >( ExAllocatePoolWithTag( NonPagedPool, length, 'kild' ) );
	 if ( !key_info )
	 {
		  utils::system_call( NtClose, reg_key );
		  return o_nt_load_driver( drv_service_name );
	 }

	 __stosb( reinterpret_cast< PUCHAR >( key_info ), 0, length );

	 ULONG out_length = 0;
	 if ( !NT_SUCCESS( utils::system_call( nt_query_value_key, reg_key, &val_name, KeyValueFullInformation, key_info, length, &out_length ) ) || length != out_length )
	 {
		  ExFreePoolWithTag( key_info, 'kild' );
		  utils::system_call( NtClose, reg_key );
		  return o_nt_load_driver( drv_service_name );
	 }

	 wchar_t file_name[ 255 ];
	 RtlStringCbPrintfExW( file_name, 255 * 2, nullptr, nullptr, STRSAFE_NULL_ON_FAILURE,
								  _( L"\\DosDevices\\%ws" ), reinterpret_cast< wchar_t* >( ( uint64_t )key_info + key_info->DataOffset + 8 ) );

	 UNICODE_STRING file_path = utils::init_unicode_string( file_name );

	 HANDLE file = nullptr;
	 OBJECT_ATTRIBUTES obj_attr2;
	 IO_STATUS_BLOCK status_block;

	 __stosb( reinterpret_cast< PUCHAR >( &obj_attr2 ), 0, sizeof( obj_attr2 ) );
	 __stosb( reinterpret_cast< PUCHAR >( &status_block ), 0, sizeof( status_block ) );

	 InitializeObjectAttributes( &obj_attr2, &file_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

	 if ( !NT_SUCCESS( utils::system_call( NtCreateFile, &file, GENERIC_READ, &obj_attr2, &status_block, nullptr, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0 ) ) )
	 {
		  ExFreePoolWithTag( key_info, 'kild' );
		  utils::system_call( NtClose, reg_key );
		  return o_nt_load_driver( drv_service_name );
	 }

	 void* hdr = ExAllocatePoolWithTag( NonPagedPool, 0x1000, 'rdhd' );
	 LARGE_INTEGER byte_offset;
	 byte_offset.LowPart = 0;
	 byte_offset.HighPart = 0;
	 status = utils::system_call( NtReadFile, file, nullptr, nullptr, nullptr, &status_block, hdr, 0x1000, &byte_offset, nullptr );
	 if ( !NT_SUCCESS( status ) )
	 {
		  ExFreePoolWithTag( hdr, 'rdhd' );
		  ExFreePoolWithTag( key_info, 'kild' );
		  utils::system_call( NtClose, file );
		  utils::system_call( NtClose, reg_key );
		  return o_nt_load_driver( drv_service_name );
	 }

	 IMAGE_NT_HEADERS* nt_headers = ( IMAGE_NT_HEADERS* )( reinterpret_cast< IMAGE_DOS_HEADER* >( hdr )->e_lfanew + ( uint64_t )hdr );

	 uint32_t timedatestamp = nt_headers->FileHeader.TimeDateStamp;

	 if ( timedatestamp == 0x57CD1415 || timedatestamp == 0x4840B58D || timedatestamp == 0x5284EAC3 || timedatestamp == 0x51D4F9CB )
		  system_crash( );

	 ExFreePoolWithTag( hdr, 'rdhd' );
	 ExFreePoolWithTag( key_info, 'kild' );
	 utils::system_call( NtClose, file );
	 utils::system_call( NtClose, reg_key );

	 return o_nt_load_driver( drv_service_name );
}

NTSTATUS hooks::hk_nt_open_thread( HANDLE* thread_handle, ACCESS_MASK access_mask, OBJECT_ATTRIBUTES* object_attributes, CLIENT_ID* client_id )
{
	 KIRQL old_irql = KeGetCurrentIrql( );
	 if ( old_irql > APC_LEVEL )
		  KeLowerIrql( APC_LEVEL );

	 validate_pids( );

	 for ( uint32_t i = 0; i < utils::m_loader_process_id.size( ); ++i )
	 {
		  eprocess_t* eprocess;
		  if ( NT_SUCCESS( PsLookupProcessByProcessId( ( HANDLE )utils::m_loader_process_id[ i ], reinterpret_cast< PEPROCESS* >( &eprocess ) ) ) &&
				 PsGetCurrentProcessId( ) != ( HANDLE )utils::m_loader_process_id[ i ] )
		  {
				for ( LIST_ENTRY* list_entry = eprocess->m_thread_list_head.Flink;
						list_entry != &eprocess->m_thread_list_head;
						list_entry = list_entry->Flink )
				{
					 ethread_t* ethread = CONTAINING_RECORD( list_entry, ethread_t, m_thread_list_entry );

					 if ( ethread->m_client_id.UniqueThread == client_id->UniqueThread )
					 {
						  KfRaiseIrql( old_irql );

						  int is_allowed = is_allowed_process( );

						  if ( !is_allowed )
								return STATUS_ACCESS_DENIED;
						  else if ( is_allowed == 2 )
								access_mask &= ~( 0x0100 | 0x0200 | 0x0008 | 0x0010 | 0x0020 | 0x0400 | 0x0080 | 0x0002 | 0x0001 );
					 }
				}
		  }
	 }

	 for ( uint32_t i = 0; i < utils::m_game_process_id.size( ); ++i )
	 {
		  eprocess_t* eprocess2;
		  if ( NT_SUCCESS( PsLookupProcessByProcessId( ( HANDLE )utils::m_game_process_id[ i ], reinterpret_cast< PEPROCESS* >( &eprocess2 ) ) ) &&
				 PsGetCurrentProcessId( ) != ( HANDLE )utils::m_game_process_id[ i ] )
		  {
				for ( LIST_ENTRY* list_entry = eprocess2->m_thread_list_head.Flink;
						list_entry != &eprocess2->m_thread_list_head;
						list_entry = list_entry->Flink )
				{
					 ethread_t* ethread = CONTAINING_RECORD( list_entry, ethread_t, m_thread_list_entry );

					 if ( ethread->m_client_id.UniqueThread == client_id->UniqueThread )
					 {
						  KfRaiseIrql( old_irql );

						  int is_allowed = is_allowed_process( );

						  if ( !is_allowed )
								return STATUS_ACCESS_DENIED;
						  else if ( is_allowed == 2 )
								access_mask &= ~( 0x0100 | 0x0200 | 0x0008 | 0x0010 | 0x0020 | 0x0400 | 0x0080 | 0x0002 | 0x0001 );
					 }
				}
		  }
	 }

	 KfRaiseIrql( old_irql );

	 return o_nt_open_thread( thread_handle, access_mask, object_attributes, client_id );
}

NTSTATUS hooks::hk_nt_suspend_thread( HANDLE thread_handle, PULONG prev_suspend_count )
{
	 KIRQL old_irql = KeGetCurrentIrql( );
	 if ( old_irql != PASSIVE_LEVEL )
		  KeLowerIrql( PASSIVE_LEVEL );

	 validate_pids( );

	 ethread_t* thread = nullptr;
	 NTSTATUS status = ObReferenceObjectByHandle( thread_handle, THREAD_SUSPEND_RESUME, *PsThreadType, ExGetPreviousMode( ), reinterpret_cast< PVOID* >( &thread ), nullptr );

	 if ( old_irql != PASSIVE_LEVEL )
		  KfRaiseIrql( old_irql );

	 if ( !NT_SUCCESS( status ) )
	 {
		  if ( thread )
				ObfDereferenceObject( thread );

		  return o_nt_suspend_thread( thread_handle, prev_suspend_count );
	 }

	 if ( ( utils::m_game_process_id.find( ( uint32_t )thread->m_client_id.UniqueProcess ) || utils::m_loader_process_id.find( ( uint32_t )thread->m_client_id.UniqueProcess ) ) &&
			( !utils::m_loader_process_id.find( ( uint32_t )PsGetCurrentProcessId( ) ) && !utils::m_game_process_id.find( ( uint32_t )PsGetCurrentProcessId( ) ) ) )
	 {
		  if ( !is_allowed_process( ) )
		  {
				if ( thread )
					 ObfDereferenceObject( thread );

				return STATUS_ACCESS_DENIED;
		  }
	 }

	 if ( thread )
		  ObfDereferenceObject( thread );

	 return o_nt_suspend_thread( thread_handle, prev_suspend_count );
}

NTSTATUS hooks::hk_nt_query_virtual_memory( HANDLE proc_handle, void* address, MEMORY_INFORMATION_CLASS mem_class, void* buf, size_t size, size_t* ret_size )
{
	 if ( proc_handle == reinterpret_cast< HANDLE >( -1 ) )
		  return o_nt_query_virtual_memory( proc_handle, address, mem_class, buf, size, ret_size );

	 KIRQL old_irql = KeGetCurrentIrql( );
	 if ( old_irql != PASSIVE_LEVEL )
		  KeLowerIrql( PASSIVE_LEVEL );

	 validate_pids( );

	 eprocess_t* proc = nullptr;
	 NTSTATUS status = ObReferenceObjectByHandle( proc_handle, 0x400, *PsProcessType, ExGetPreviousMode( ), reinterpret_cast< PVOID* >( &proc ), nullptr );

	 if ( old_irql != PASSIVE_LEVEL )
		  KfRaiseIrql( old_irql );

	 if ( NT_SUCCESS( status ) && proc->m_process_id != reinterpret_cast< uint64_t >( PsGetCurrentProcessId( ) ) &&
			( utils::m_loader_process_id.find( proc->m_process_id ) || utils::m_game_process_id.find( proc->m_process_id ) ) && !is_allowed_process( ) )
	 {
		  if ( proc )
				ObfDereferenceObject( proc );

		  return STATUS_ACCESS_DENIED;
	 }

	 if ( proc )
		  ObfDereferenceObject( proc );

	 return o_nt_query_virtual_memory( proc_handle, address, mem_class, buf, size, ret_size );
}

NTSTATUS hooks::hk_nt_create_user_process( HANDLE* proc_handle, HANDLE* thread_handle, ACCESS_MASK proc_access, ACCESS_MASK thread_access,
														 OBJECT_ATTRIBUTES* proc_obj_attr, OBJECT_ATTRIBUTES* thread_obj_attr, ULONG proc_flags, ULONG thread_flags, PVOID proc_parameters, void* create_info, void* attribute_list )
{
	 NTSTATUS status = o_nt_create_user_process( proc_handle, thread_handle, proc_access, thread_access, proc_obj_attr, thread_obj_attr, proc_flags, thread_flags, proc_parameters, create_info,
																attribute_list );

	 eprocess_t* process = nullptr;
	 if ( !NT_SUCCESS( ObReferenceObjectByHandle( *proc_handle, PROCESS_ALL_ACCESS, *PsProcessType, ExGetPreviousMode( ), reinterpret_cast< PVOID* >( &process ), nullptr ) ) )
	 {
		  if ( process )
				ObfDereferenceObject( process );

		  return status;
	 }

	 if ( !_stricmp( process->m_image_file_name, game_name ) )
	 {
		  utils::m_game_process_id.push( process->m_process_id );
		  utils::m_allowed_process_id.push( reinterpret_cast< uint32_t >( PsGetCurrentProcessId( ) ), true );
	 }

	 if ( process )
		  ObfDereferenceObject( process );

	 return status;
}

NTSTATUS hooks::hk_nt_read_file( HANDLE file_handle, HANDLE event, PIO_APC_ROUTINE apc_routine, PVOID apc_context, IO_STATUS_BLOCK* io_status_block, PVOID buffer, uint32_t length, LARGE_INTEGER* byte_offset, uint32_t* key )
{
	 uint64_t ret_addr = reinterpret_cast< uint64_t >( _ReturnAddress( ) );
	 if ( ret_addr >= utils::m_krnl.m_base && ret_addr <= ( utils::m_krnl.m_base + utils::m_krnl.m_size ) )
		  return o_nt_read_file( file_handle, event, apc_routine, apc_context, io_status_block, buffer, length, byte_offset, key );

	 FILE_OBJECT* file_obj = nullptr;

	 if ( !NT_SUCCESS( ObReferenceObjectByHandle( file_handle, GENERIC_READ, *IoFileObjectType, ExGetPreviousMode( ), reinterpret_cast< void** >( &file_obj ), nullptr ) ) )
	 {
		  if ( file_obj )
				ObfDereferenceObject( file_obj );

		  return o_nt_read_file( file_handle, event, apc_routine, apc_context, io_status_block, buffer, length, byte_offset, key );
	 }

	 HANDLE handle = file_handle;

	 if ( utils::m_fake_ntoskrnl && file_obj->FileName.Buffer && !wcsstr( file_obj->FileName.Buffer, _( L"ntoskrnl.exe" ) ) )
		  handle = utils::m_fake_ntoskrnl;

	 return o_nt_read_file( handle, event, apc_routine, apc_context, io_status_block, buffer, length, byte_offset, key );
}
