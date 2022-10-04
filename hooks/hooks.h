#pragma once

#include "../utils/utils.h"

namespace hooks
{
	 bool setup( );// todo: hook ntallocatevirtualmemory

	 NTSTATUS NTAPI hk_nt_debug_active_process( HANDLE proc_handle, HANDLE debug_object_handle );
	 NTSTATUS NTAPI hk_nt_open_process( HANDLE* proc_handle, ACCESS_MASK access_mask, OBJECT_ATTRIBUTES* obj_attr, CLIENT_ID* client_id );
	 NTSTATUS NTAPI hk_nt_query_information_process( HANDLE proc_handle, PROCESSINFOCLASS process_information_class, PVOID process_information, ULONG process_information_length,
																	 PULONG return_length );
	 NTSTATUS NTAPI hk_nt_load_driver( UNICODE_STRING* drv_service_name );
	 NTSTATUS NTAPI hk_nt_open_thread( HANDLE* thread_handle, ACCESS_MASK access_mask, OBJECT_ATTRIBUTES* object_attributes, CLIENT_ID* client_id );
	 NTSTATUS NTAPI hk_nt_suspend_thread( HANDLE thread_handle, PULONG prev_suspend_count );
	 NTSTATUS NTAPI hk_nt_query_virtual_memory( HANDLE proc_handle, void* address, MEMORY_INFORMATION_CLASS mem_class, void* buf, size_t size, size_t* ret_size );
	 NTSTATUS NTAPI hk_nt_create_user_process( HANDLE* proc_handle, HANDLE* thread_handle, ACCESS_MASK proc_access, ACCESS_MASK thread_access,
															 OBJECT_ATTRIBUTES* proc_obj_attr, OBJECT_ATTRIBUTES* thread_obj_attr, ULONG proc_flags, ULONG thread_flags, PVOID proc_parameters, void* create_info, void* attribute_list );
	 NTSTATUS NTAPI hk_nt_read_file( HANDLE file_handle, HANDLE event, PIO_APC_ROUTINE apc_routine, PVOID apc_context, IO_STATUS_BLOCK* io_status_block, PVOID buffer, uint32_t length,
												LARGE_INTEGER* byte_offset, uint32_t* key );

	 inline decltype( &hk_nt_debug_active_process ) o_nt_debug_active_process;
	 inline decltype( &hk_nt_open_process ) o_nt_open_process;
	 inline decltype( &hk_nt_query_information_process ) o_nt_query_information_process;
	 inline decltype( &hk_nt_load_driver ) o_nt_load_driver;
	 inline decltype( &hk_nt_open_thread ) o_nt_open_thread;
	 inline decltype( &hk_nt_suspend_thread ) o_nt_suspend_thread;
	 inline decltype( &hk_nt_query_virtual_memory ) o_nt_query_virtual_memory;
	 inline decltype( &hk_nt_create_user_process ) o_nt_create_user_process;
	 inline decltype( &hk_nt_read_file ) o_nt_read_file;
}