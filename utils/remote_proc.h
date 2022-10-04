#pragma once

#include "utils.h"

class c_remote_proc
{
	 eprocess_t* m_proc;
	 HANDLE m_proc_handle;
	 bool m_wow64;

	 uint64_t get_mod_address86( const wchar_t* mod_name, bool load_if_not_found = false );
	 uint64_t get_mod_address64( const wchar_t* mod_name, bool load_if_not_found = false );

	 bool start_routine86( uint32_t address, uint32_t arg );
	 bool start_routine64( uint64_t address, uint64_t arg );

	 bool is_thread_alertable86( ethread_t* thread, NTSTATUS( * ps_suspend_thread )( ethread_t*, void* ), NTSTATUS( * ps_resume_thread )( ethread_t*, void* ), NTSTATUS( *psp_get_context_thread_internal )( ethread_t*, CONTEXT*, bool, bool, uint32_t ) );
	 bool is_thread_alertable64( ethread_t* thread );

	 uint64_t get_proc_address86( const char* mod_name, uint64_t func_hash );
	 uint64_t get_proc_address64( const char* mod_name, uint64_t func_hash );
public:
	 bool init( uint64_t proc_id );

	 bool open_handle( );
	 void close_handle( );

	 uint64_t get_mod_address( const wchar_t* mod_name, bool load_if_not_found = false );
	 uint64_t get_proc_address( const char* mod_name, uint64_t func_hash );

	 bool start_routine( uint64_t address, uint64_t arg );

	 address_t< uint64_t >	alloc( size_t size );
	 void							free( address_t< uint64_t > address );

	 bool check( );

	 uint64_t	attach( eprocess_t** old_proc );
	 void		detach( uint64_t old_cr3, eprocess_t* old_proc );

	 mm_pte_t get_pte( uint64_t virtual_address );
	 void write_pte( uint64_t virtual_address, mm_pte_t new_pte );

	 bool is_wow64( );
	 eprocess_t* get( );

	 template< typename _ty >
	 NTSTATUS read( void* buf, address_t< _ty > address, size_t size )
	 {
		  if ( address.as< uint64_t >( ) + size < address.as< uint64_t >( ) || address.as< uint64_t >( ) + size > 0x7FFFFFFF0000 ||
				 !address.as< uint64_t >( ) )
		  {
				return STATUS_ACCESS_VIOLATION;
		  }

		  mm_pte_t pte = get_pte( address.as< uint64_t >( ) );
		  if ( !pte.m_long )
		  {
				return STATUS_PTE_CHANGED;
		  }

		  if ( __readcr3( ) == m_proc->m_directory_table_base )
		  {
				utils::memcpy( ( void* )buf, address.as< void* >( ), size );
				return STATUS_SUCCESS;
		  }		  

		  uint64_t physical_address = ( pte.m_page_frame_number << 12 ) | ( address.as< uint64_t >( ) & 0xFFF );
		  return utils::read_physical( physical_address, buf, size );
	 }

	 template< typename _ty >
	 NTSTATUS write( address_t< _ty > address, const void* buf, size_t size )
	 {
		  if ( address.as< uint64_t >( ) + size < address.as< uint64_t >( ) || address.as< uint64_t >( ) + size > 0x7FFFFFFF0000 ||
				 !address.as< uint64_t >( ) )
				return STATUS_ACCESS_VIOLATION;

		  mm_pte_t pte = get_pte( address.as< uint64_t >( ) );
		  if ( !pte.m_long )
				return STATUS_PTE_CHANGED;

		  if ( __readcr3( ) == m_proc->m_directory_table_base )
		  {
				utils::memcpy( address.as< void* >( ), buf, size );
				return STATUS_SUCCESS;
		  }

		  uint64_t physical_address = ( pte.m_page_frame_number << 12 ) | ( address.as< uint64_t >( ) & 0xFFF );
		  return utils::write_physical( physical_address, buf, size );
	 }

	 template< typename _ty >
	 NTSTATUS read( void* buf, _ty address, size_t size )
	 {
		  return read( buf, address_t< _ty >( ( _ty* )address ), size );
	 }

	 template< typename _ty >
	 NTSTATUS write( _ty address, const void* buf, size_t size )
	 {
		  return write( address_t< _ty >( ( _ty* )address ), buf, size );
	 }
};