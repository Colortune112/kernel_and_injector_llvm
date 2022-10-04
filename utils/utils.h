#pragma once

#include <VirtualizerSDK.h>
#include <VirtualizerSDK_CustomVMs.h>

#include <ntifs.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <wdm.h>
#include <intrin.h>
#include <ntddk.h>

#include "xorstr.h"

#include "address.h"

#ifndef _MSC_VER
extern "C" void __movsb( unsigned char*, unsigned char const*, size_t );
extern "C" void __stosb( unsigned char*, unsigned char, size_t );
#endif

#include "xorstr.h"

#ifdef _DEBUG
#define drv_log( s, ... ) DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, s, __VA_ARGS__ )
#else
#define drv_log( s, ... ) DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, s, __VA_ARGS__ )
#endif

extern "C" void system_crash( );
extern "C" void _sti( ); // _enable
extern "C" void _cli( ); // _disable

#define game_name ( "csgo.exe" )

namespace utils
{
	 struct module_t
	 {
		  uint64_t m_base;
		  uint32_t m_size;

		  bool initialize( const char* mod_name );
	 };

	 struct patch_t
	 {
		  uint64_t m_rva;
		  uint8_t m_patches[ 0x10 ];
		  size_t m_patch_size;

		  bool operator==( patch_t& o )
		  {
				return this->m_rva == o.m_rva;
		  }
	 };

	 template< typename _ty, uint32_t tag >
	 class c_vector
	 {
	 private:
		  uint32_t m_size;
		  _ty* m_data;

	 public:
		  void shutdown( )
		  {
				ExFreePoolWithTag( m_data, tag );
		  }

		  void erase( uint32_t pos )
		  {
				--m_size;

				if ( !m_size )
				{
					 if ( m_data )
						  ExFreePoolWithTag( m_data, tag );

					 m_data = nullptr;
					 return;
				}

				void* temp = ExAllocatePoolWithTag( PagedPool, sizeof( _ty ) * m_size, tag );

				if ( pos )
					 __movsb( reinterpret_cast< PUCHAR >( temp ), reinterpret_cast< PUCHAR >( m_data ), sizeof( _ty ) * pos );
				else if ( !m_size )
				{
					 ExFreePoolWithTag( temp, tag );
					 ExFreePoolWithTag( m_data, tag );
				}

				__movsb( reinterpret_cast< PUCHAR >( ( uint64_t )temp + ( pos * 8 ) ), reinterpret_cast< PUCHAR >( ( uint64_t )m_data + ( ( pos + 1 ) * 8 ) ), sizeof( _ty ) * ( m_size - pos ) );
				ExFreePoolWithTag( m_data, tag );
				m_data = reinterpret_cast< _ty* >( temp );
		  }

		  void push( _ty value, bool ignore_same = false )
		  {
				if ( !m_size )
				{
					 m_data = reinterpret_cast< _ty* >( ExAllocatePoolWithTag( PagedPool, sizeof( _ty ), tag ) );
					 m_data[ m_size++ ] = value;

					 return;
				}
				else if ( ignore_same )
				{
					 for ( uint32_t i = 0; i < m_size; ++i )
						  if ( m_data[ i ] == value )
								return;
				}

				++m_size;
				void* temp = ExAllocatePoolWithTag( PagedPool, sizeof( _ty ) * m_size, tag );
				__movsb( reinterpret_cast< PUCHAR >( temp ), reinterpret_cast< PUCHAR >( m_data ), sizeof( _ty ) * ( m_size - 1 ) );
				ExFreePoolWithTag( m_data, tag );
				m_data = reinterpret_cast< _ty* >( temp );
				m_data[ m_size - 1 ] = value;
		  }

		  _ty pop( )
		  {
				--m_size;

				if ( !m_size )
				{
					 _ty val = m_data[ 0 ];
					 ExFreePoolWithTag( m_data, tag );
					 m_data = 0;
					 return val;
				}

				void* temp = ExAllocatePoolWithTag( PagedPool, sizeof( _ty ) * m_size, tag );
				__movsb( reinterpret_cast< PUCHAR >( temp ), reinterpret_cast< PUCHAR >( m_data ), sizeof( _ty ) * m_size );
				_ty val = m_data[ m_size ];
				ExFreePoolWithTag( m_data, tag );
				m_data = reinterpret_cast< _ty* >( temp );
				return val;
		  }

		  _ty* data( )
		  {
				return m_data;
		  }

		  uint32_t size( ) const
		  {
				return m_size;
		  }

		  _ty& operator[ ]( uint32_t index )
		  {
				return m_data[ index ];
		  }

		  bool find( _ty val )
		  {
				for ( uint32_t i = 0; i < m_size; ++i )
					 if ( m_data[ i ] == val )
						  return true;
				return false;
		  }
	 };

	 UNICODE_STRING init_unicode_string( wchar_t* str );
	 uint64_t find_pattern_stub( module_t mod, const char* pattern );
	 uint32_t strtoul( const char* nptr, char** endptr, int base );
	 NTSTATUS write_to_readonly_memory( void* dst, void* src, uint64_t size );

	 template< typename _ty >
	 _ty* strstr( _ty* str1, _ty* str2 )
	 {
		  if ( !*str2 )
				return str1;

		  for ( size_t i = 0; i < strlen( str1 ); i++ )
		  {
				if ( *( str1 + i ) == *str2 )
				{
					 _ty* ptr = strstr( str1 + i + 1, str2 + 1 );
					 return ( ptr ) ? ptr - 1 : nullptr;
				}
		  }

		  return nullptr;
	 }

	 template< typename _ty >
	 size_t strlen( const _ty* str )
	 {
		  size_t length = 0;
		  while ( str[ length ] )
				++length;
		  return length;
	 }

	 template< typename _ty = uint64_t >
	 address_t< _ty > find_pattern( module_t module, const char* pattern )
	 {
		  return address_t< _ty >( ( _ty* )( find_pattern_stub( module, pattern ) ) );
	 }

#ifdef _MSC_VER
	 __forceinline
#else
	 __attribute__( ( always_inline ) )
#endif
		  void memset( void* address, uint8_t val, size_t size )
	 {
		  __stosb( reinterpret_cast< uint8_t* >( address ), val, size );
	 }

#ifdef _MSC_VER
	 __forceinline
#else
	 __attribute__( ( always_inline ) )
#endif
		  void memcpy( void* dst, const void* src, size_t size )
	 {
		  __movsb( reinterpret_cast< uint8_t* >( dst ), reinterpret_cast< const uint8_t* >( src ), size );
	 }

	 void sleep( uint64_t ms );

	 extern module_t m_krnl;
	 inline c_vector< uint32_t, 'ldpi' > m_loader_process_id{ };
	 inline c_vector< uint32_t, 'gmpi' > m_game_process_id{ };
	 inline c_vector< uint32_t, 'appi' > m_allowed_process_id{ };
	 inline HANDLE m_fake_ntoskrnl;
	 inline c_vector< patch_t, 'kpvr' > m_kernel_patches{ };
	 extern uint32_t m_krnl_process_id;
	 extern char m_key[ 32 ];
}

#include "hash.h"

#pragma warning( push )
#pragma warning( disable : 4201 )

typedef enum _SYSTEM_INFORMATION_CLASS
{
	 SystemBasicInformation = 0,
	 SystemPerformanceInformation = 2,
	 SystemTimeOfDayInformation = 3,
	 SystemProcessInformation = 5,
	 SystemProcessorPerformanceInformation = 8,
	 SystemModuleInformation = 11,
	 SystemInterruptInformation = 23,
	 SystemExceptionInformation = 33,
	 SystemRegistryQuotaInformation = 37,
	 SystemLookasideInformation = 45,
	 SystemCodeIntegrityInformation = 103,
	 SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

struct list_entry32_t
{
	 uint32_t m_flink;
	 uint32_t m_blink;
};

struct list_entry64_t
{
	 uint64_t m_flink;
	 uint64_t m_blink;
};

struct unicode_string32_t
{
	 uint16_t m_length;
	 uint16_t m_max_length;
	 uint32_t m_buffer;
};

// x64
struct unicode_string_t
{
	 uint16_t m_length;
	 uint16_t m_max_length;
	 wchar_t* m_buffer;
};

struct sys_module_entry_t
{
	 HANDLE		m_section;
	 uintptr_t	m_mapped_base;
	 uintptr_t	m_image_base;
	 uint32_t		m_image_size;
	 uint32_t		m_flags;
	 uint16_t		m_load_order_index;
	 uint16_t		m_init_order_index;
	 uint16_t		m_load_count;
	 uint16_t		m_offset_to_file_name;
	 uint8_t		m_full_path_name[ 256u ];
};

struct sys_module_info_t
{
	 uint32_t					m_count;
	 sys_module_entry_t	m_module[ 1u ];
};

struct sys_process_info_t
{
	 uint32_t				m_next_entry_offset;
	 uint32_t				m_threads_count;
	 uint8_t				pad0[ 48u ];
	 unicode_string_t	m_image_name;
	 KPRIORITY			m_base_priority;
	 HANDLE				m_unique_process_id;
	 uintptr_t			pad1;
	 uint32_t				m_handle_count;
	 uint32_t				m_session_id;
	 uintptr_t			pad2;
	 size_t				m_peak_virtual_size;
	 size_t				m_virtual_size;
	 uint32_t				pad3;
	 size_t				m_peak_working_set_size;
	 size_t				m_working_set_size;
	 uintptr_t			pad4;
	 size_t				m_quota_paged_pool_usage;
	 uintptr_t			pad5;
	 size_t				m_quota_non_paged_pool_usage;
	 size_t				m_pagefile_usage;
	 size_t				m_peak_pagefile_usage;
	 size_t				m_private_page_count;
	 LARGE_INTEGER		pad6[ 6u ];
};

struct rtl_avl_tree_t
{
	 PRTL_BALANCED_NODE	m_root;
	 void* m_node_hint;
	 uint64_t					m_number_generic_table_elements;
};

struct cur_dir32_t
{
	 unicode_string32_t	m_dos_path;
	 uint32_t					m_handle;
};

// 64
struct cur_dir_t
{
	 unicode_string_t	m_dos_path;
	 uint32_t				m_handle;
};

struct rtl_user_process_params32_t
{
	 uint64_t					pad0;
	 uint32_t					m_flags;
	 uint32_t					m_debug_flags;
	 char						pad1[ 20u ];
	 cur_dir32_t				m_dir;
	 unicode_string32_t	m_dll_path;
	 unicode_string32_t	m_image_path_name;
	 unicode_string32_t	m_cmd_line;
};

// 64
struct rtl_user_process_params_t
{
	 void* pad0;
	 uint32_t				m_flags;
	 uint32_t				m_debug_flags;
	 char					pad1[ 40u ];
	 cur_dir_t			m_dir;
	 unicode_string_t	m_dll_path;
	 unicode_string_t	m_image_path_name;
	 unicode_string_t	m_cmd_line;
};

struct peb_ldr_data32_t
{
	 uint32_t			m_length;
	 uint8_t			m_initialized;
	 uint32_t			m_ss_handle;
	 list_entry32_t	m_in_load_order_module_list;
	 list_entry32_t	m_in_memory_order_module_list;
	 list_entry32_t	m_in_initialization_order_module_list;
	 uint32_t			m_entry_in_progress;
	 uint8_t			m_shutdown_in_progress;
	 uint32_t			m_shutdown_thread_id;
};

// 64
struct peb_ldr_data_t
{
	 uint32_t		m_length;
	 uint8_t		m_initialized;
	 uint64_t		m_ss_handle;
	 _LIST_ENTRY	m_in_load_order_module_list;
	 _LIST_ENTRY	m_in_memory_order_module_list;
	 _LIST_ENTRY	m_in_initialization_order_module_list;
	 uint64_t		m_entry_in_progress;
	 uint8_t		m_shutdown_in_progress;
	 uint64_t		m_shutdown_thread_id;
};

struct ldr_data_table_entry32_t
{
	 list_entry32_t			m_in_load_order_links;
	 list_entry32_t			m_in_memory_order_links;
	 list_entry32_t			m_in_initialization_order_links;
	 uint32_t					m_base_address;
	 uint32_t					m_entry_point;
	 uint32_t					m_size_of_image;
	 unicode_string32_t	m_full_dll_name;
	 unicode_string32_t	m_base_dll_name;
	 uint32_t					m_flags;
	 uint16_t					m_obsolete_load_count;
	 uint16_t					m_tls_index;
	 list_entry32_t			m_hash_links;
	 uint32_t					m_time_date_stamp;
};

struct ldr_data_table_entry_t
{
	 LIST_ENTRY		m_in_load_order_links;
	 LIST_ENTRY		m_in_memoryo_rder_links;
	 LIST_ENTRY		m_in_initialization_order_links;
	 uint64_t			m_base_address;
	 uint64_t			m_entry_point;
	 uint64_t			m_size_of_image;
	 UNICODE_STRING	m_full_dll_name;
	 UNICODE_STRING	m_base_dll_name;
	 uint32_t			m_flags;
	 uint16_t			m_load_count;
	 uint16_t			m_tls_index;
	 LIST_ENTRY		m_hash_table_entry;
	 uint64_t			m_time_date_stamp;
};

struct peb_t
{
	 char								pad0[ 3 ];					  // 0x0
	 uint8_t							m_flags;						  // 0x3
	 char								pad1[ 18u ];				  // 0x4
	 peb_ldr_data_t* m_ldr;										  // 0x18
	 rtl_user_process_params_t* m_user_process_params;
};

static_assert( offsetof( peb_t, m_ldr ) == 0x18, "wrong" );

struct peb32_t
{
	 char		pad0[ 3u ];						 // 0x0
	 uint8_t	m_flags;							 // 0x3
	 char		pad1[ 8u ];						 // 0x4
	 uint32_t	m_ldr;						 // 0xC
	 uint32_t	m_user_process_params;
};

enum struct e_sys_dll_type : int
{
	 ps_native_system_dll,
	 ps_wow_x86_system_dll,
	 ps_wow_arm32_system_dll,
	 ps_wow_amd64_system_dll,
	 ps_wow_chpex86_system_dll,
	 ps_vsm_enclave_runtime_dll,
	 ps_system_dll_total_types
};

struct wow64_process_t
{
	 peb32_t* m_peb;
	 uint16_t			m_machine;
	 e_sys_dll_type	m_ntdll_type;
};

struct eprocess_t
{
	 char pad[ 0x28 ];
	 uint64_t m_directory_table_base; // 0x28
	 char pad_0[ 0x3a8 ];// 0x30
	 void* m_instrumentation_callback; // 0x3d8
	 char pad_1[ 0x60 ];// 0x3e0
	 uint64_t m_process_id; // 0x440
	 char pad_2[ 0x108 ];// 0x448
	 peb_t* m_peb; // 0x550
	 char pad_3[ 0x28 ];// 0x558
	 wow64_process_t* m_wow64_process; // 0x580
	 char pad_4[ 0x20 ];// 0x588
	 char m_image_file_name[ 15 ]; // 0x5a8
	 char pad_5[ 0x29 ];// 0x5b7
	 _LIST_ENTRY m_thread_list_head; // 0x5e0
	 char pad_6[ 0x1e4 ];// 0x5f0
	 uint32_t m_exit_status; // 0x7d4
	 rtl_avl_tree_t m_vad_root; // 0x7d8
	 //void* m_vad_hint; // 0x7e0
	 //uint64_t m_vad_count; // 0x7e8
	 char pad_7[ 0x8c ];// 0x7f0
	 uint32_t m_flags3; // 0x87c
};

struct ethread_t
{
	 char				pad0[ 184u ];
	 eprocess_t* m_proc; // 0xb8
	 char pad_0[ 0x30 ];// 0xc0
	 void* m_teb; // 0xf0
	 char pad_1[ 0x8c ];// 0xf8
	 uint8_t m_state; // 0x184
	 char pad_2[ 0x2 ];// 0x185
	 uint8_t m_wait_mode; // 0x187
	 char pad_3[ 0xaa ];// 0x188
	 uint8_t			m_prev_mode; // 0x232
	 char pad_4[ 0x50 ];// 0x233
	 uint8_t m_wait_reason; // 0x283
	 char pad_5[ 0x1f4 ];// 0x284
	 _CLIENT_ID		m_client_id; // 0x478
	 char				pad3[ 96u ];// 0x488
	 _LIST_ENTRY		m_thread_list_entry; // 0x4e8
	 char				pad4[ 24u ]; // 0x4f8
	 uint32_t			m_cross_thread_flags; // 0x510
	 char				pad5[ 52u ]; // 0x514
	 uint32_t			m_exit_status; // 0x548
};

struct process_instrument_callback_info_t
{
	 uint32_t		m_version;
	 uint32_t		m_reserved;
	 uintptr_t	m_callback;
};

struct mm_address_list_t
{
	 uint64_t	pad0;
	 void* m_end_va;
};

struct rtl_bitmap_ex_t
{
	 uint64_t	m_size_of_bitmap;
	 void* m_buffer;
};

struct ex_push_lock_t
{
	 union
	 {
		  uint64_t m_locked : 1;
		  uint64_t m_waiting : 1;
		  uint64_t m_waking : 1;
		  uint64_t m_multiple_shared : 1;
		  uint64_t m_shared : 60;
		  uint64_t m_value;
		  void* m_ptr;
	 };
};

struct mm_pte_t
{
	 union
	 {
		  uint64_t m_long;

		  struct
		  {
				uint64_t m_valid : 1;
				uint64_t m_dirty1 : 1;
				uint64_t m_owner : 1;
				uint64_t m_write_through : 1;
				uint64_t m_cache_disable : 1;
				uint64_t m_accessed : 1;
				uint64_t m_dirty : 1;
				uint64_t m_large_page : 1;
				uint64_t m_global : 1;
				uint64_t m_copy_on_write : 1;
				uint64_t m_unused : 1;
				uint64_t m_write : 1;
				uint64_t m_page_frame_number : 36;
				uint64_t m_reserved_for_hardware : 4;
				uint64_t m_reserved_for_software : 4;
				uint64_t m_wsle_age : 4;
				uint64_t m_wsle_protection : 3;
				uint64_t m_no_execute : 1;
		  };
	 };
};

struct mm_pfn_t
{
	 union
	 {
		  struct
		  {
				_LIST_ENTRY	m_list_entry;
				mm_pte_t		m_original_pte;
		  };

		  _RTL_BALANCED_NODE m_tree_node;

		  struct
		  {
				union
				{
					 _SINGLE_LIST_ENTRY	m_next_slist_pfn;
					 void* m_next;

					 struct
					 {
						  uint64_t	m_flink : 36;
						  uint64_t	m_node_flink_high : 28;
					 };

					 struct
					 {
						  union
						  {
								struct
								{
									 uint64_t	m_tradable : 1;
									 uint64_t	m_non_paged_buddy : 43;
								} m_leaf;

								struct
								{
									 uint64_t m_tradable : 1;
									 uint64_t m_wsle_age : 3;
									 uint64_t m_oldest_wsle_leaf_entries : 10;
									 uint64_t m_oldest_wsle_leaf_age : 3;
									 uint64_t m_non_paged_buddy : 43;
								} m_page_table;
								uint64_t m_entire_active_field;
						  };
					 } m_active;
				};

				mm_pte_t* m_pte_address;
		  };

		  struct
		  {
				uint64_t gap;
				uint64_t m_pte_long;
		  };
	 };

	 struct
	 {
		  union
		  {
				struct
				{
					 uint64_t m_blink : 36;
					 uint64_t m_node_blink_high : 20;
					 uint64_t m_tb_flushstamp : 4;
					 uint64_t m_unused : 2;
					 uint64_t m_page_blink_delete_bit : 1;
					 uint64_t m_page_blink_lock_bit : 1;
				};

				struct
				{
					 uint64_t m_share_count : 62;
					 uint64_t m_page_share_count_delete_bit : 1;
					 uint64_t m_page_share_count_lock_bit : 1;
				};

				uint64_t				m_entire_field;
				volatile int64_t	m_lock;

				struct
				{
					 uint64_t m_lock_not_used : 62;
					 uint64_t m_delete_bit : 1;
					 uint64_t m_lock_bit : 1;
				};
		  };
	 } m_pfn_blink;

	 union
	 {
		  struct
		  {
				uint16_t m_ref_count;

				struct
				{
					 uint8_t m_page_location : 3;
					 uint8_t m_write_in_progress : 1;
					 uint8_t m_modified : 1;
					 uint8_t m_read_in_progress : 1;
					 uint8_t m_cache_attribute : 2;
				};

				struct
				{
					 uint8_t m_priority : 3;
					 uint8_t m_on_protected_standby : 1;
					 uint8_t m_in_page_error : 1;
					 uint8_t m_system_charged_page : 1;
					 uint8_t m_removal_requested : 1;
					 uint8_t m_parity_error : 1;
				};
		  };

		  struct
		  {
				uint16_t m_ref_count;
		  };

		  struct
		  {
				uint32_t m_entire_field2;
		  };
	 };

	 uint16_t m_node_blink_low;

	 union
	 {
		  struct
		  {
				uint8_t m_unused : 4;
				uint8_t m_unused2 : 4;
				uint8_t m_view_count;
		  };

		  struct
		  {
				uint8_t gap0;
				uint8_t m_node_flink_low;
		  };

		  struct
		  {
				uint8_t gap2;
				uint8_t m_modified_list_bucket_index : 4;
		  };

		  struct
		  {
				uint8_t gap1;
				uint8_t m_anchor_large_page_size : 2;
		  };
	 };

	 union
	 {
		  struct
		  {
				uint64_t m_pte_frame : 36;
				uint64_t m_resident_page : 1;
				uint64_t m_unused1 : 1;
				uint64_t m_unused3 : 1;
				uint64_t m_partition : 10;
				uint64_t m_file_only : 1;
				uint64_t m_pfn_exists : 1;
				uint64_t m_spare : 9;
				uint64_t m_page_identity : 3;
				uint64_t m_proto_type_pte : 1;
		  };

		  uint64_t m_entire_field3;
	 };
};

struct mi_control_area_wait_block_t
{
	 mi_control_area_wait_block_t* m_next;
	 uint32_t								m_wait_reason;
	 uint32_t								m_wait_response;
	 KGATE									m_gate;
};

struct mm_extend_info_t
{
	 uint64_t m_commited_size;
	 uint32_t m_ref_count;
};

struct mm_control_area_t;

struct mm_segment_t
{
	 mm_control_area_t* m_control_area;
	 uint32_t					m_total_numbers_of_ptes;

	 struct
	 {
		  union
		  {
				uint16_t m_total_number_of_ptes : 10;
				uint16_t m_session_driver_protos : 1;
				uint16_t m_large_pages : 1;
				uint16_t m_debug_symbols_loaded : 1;
				uint16_t m_write_combined : 1;
				uint16_t m_no_cache : 1;

				uint16_t m_short0;
		  };

		  union
		  {
				uint8_t m_spare : 1;
				uint8_t m_default_protection_mask : 5;
				uint8_t m_binary32 : 1;
				uint8_t m_contains_debug : 1;

				uint8_t m_char1;
		  };

		  union
		  {
				uint8_t m_force_collision : 1;
				uint8_t m_image_signing_type : 3;
				uint8_t m_image_signing_level : 4;
				uint8_t m_char2;
		  };
	 };

	 uint64_t m_number_of_commited_pages;
	 uint64_t m_size_of_segment;

	 union
	 {
		  mm_extend_info_t* m_extend_info;
		  void* m_based_address;
	 };

	 ex_push_lock_t	m_segment_lock;
	 uint64_t			u1;
	 uint64_t			u2;
	 mm_pte_t* m_prototype_pte;
};

struct mm_control_area_t
{
	 mm_segment_t* m_segment;

	 union
	 {
		  LIST_ENTRY	m_list_head;
		  void* m_awe_ctx;
	 };

	 uint64_t m_number_of_section_references;
	 uint64_t m_number_of_pfn_references;
	 uint64_t m_number_of_mapped_views;
	 uint64_t m_number_of_user_references;

	 union
	 {
		  uint32_t m_long_flags;
		  struct
		  {
				uint32_t m_being_deleted : 1;
				uint32_t m_being_created : 1;
				uint32_t m_being_purged : 1;
				uint32_t m_no_modified_writing : 1;
				uint32_t m_fail_all_io : 1;
				uint32_t m_image : 1;
				uint32_t m_based : 1;
				uint32_t m_file : 1;
				uint32_t m_attempting_delete : 1;
				uint32_t m_prefetch_created : 1;
				uint32_t m_physical_memory : 1;
				uint32_t m_image_control_area_on_removable_media : 1;
				uint32_t m_reserve : 1;
				uint32_t m_commit : 1;
				uint32_t m_no_change : 1;
				uint32_t m_was_purged : 1;
				uint32_t m_user_reference : 1;
				uint32_t m_global_memory : 1;
				uint32_t m_delete_on_close : 1;
				uint32_t m_file_pointer_null : 1;
				uint32_t m_preferred_node : 6;
				uint32_t m_global_only_per_session : 1;
				uint32_t m_user_writable : 1;
				uint32_t m_system_va_allocated : 1;
				uint32_t m_preferred_fs_compression_boundary : 1;
				uint32_t m_using_file_extents : 1;
				uint32_t m_page_size_64k : 1;
		  };
	 };

	 uint32_t								m_long_flags2;
	 uint64_t								m_file_ptr;
	 uint32_t								m_control_area_lock;
	 uint32_t								m_modified_write_count;
	 mi_control_area_wait_block_t* m_wait_list;
	 uint64_t								u2[ 2 ];
	 uint64_t								m_file_object_lock;
	 uint64_t								m_locked_pages;
	 uint64_t								u3;
};

struct mm_inpage_support_t;

struct mm_inpage_support_flow_thru_t
{
	 uint64_t						m_page;
	 mm_inpage_support_t* m_initial_page_support;
	 void* m_paging_file;
	 uint64_t						m_page_file_offset;
	 RTL_BALANCED_NODE			m_node;
};

struct mm_inpage_support_t
{
	 union
	 {
		  LIST_ENTRY	m_list_entry;
		  SLIST_ENTRY	m_slist_entry;
	 };

	 LIST_ENTRY			m_list_head;
	 KEVENT				m_event;
	 KEVENT				m_collided_event;
	 IO_STATUS_BLOCK	m_io_status;
	 LARGE_INTEGER		m_read_offset;

	 union
	 {
		  KAPC_STATE m_apc_state;

		  struct
		  {
				mm_pfn_t* m_swap_pfn;

				struct
				{
					 union
					 {
						  uint32_t m_entire_flags;

						  struct
						  {
								uint32_t m_store_fault : 1;
								uint32_t m_low_processor_failure : 1;
								uint32_t m_spare : 14;
								uint32_t m_remaining_page_support : 16;
						  };
					 };
				} m_store_flags;
		  } m_hadr_fault_state;
	 };

	 ethread_t* m_thread;
	 mm_pfn_t* m_locked_proto_pfn;
	 mm_pte_t			m_pte_contents;
	 volatile int	m_wait_count;
	 volatile int	m_inject_retry;
	 uint32_t			m_byte_count;

	 union
	 {
		  uint32_t m_image_pte_offset;
		  uint32_t m_toss_page;
	 };

	 union
	 {
		  struct
		  {
				uint32_t m_get_extents : 1;
				uint32_t m_prefetch_system_vm_type : 2;
				uint32_t m_va_prefetch_read_block : 1;
				uint32_t m_collided_flow_through : 1;
				uint32_t m_force_collisions : 1;
				uint32_t m_in_page_expanded : 1;
				uint32_t m_issued_at_low_priority : 1;
				uint32_t m_fault_from_store : 1;
				uint32_t m_page_priority : 3;
				uint32_t m_clustered_page_priority : 3;
				uint32_t m_make_cluster_valid : 1;
				uint32_t m_perform_relocations : 1;
				uint32_t m_zero_last_page : 1;
				uint32_t m_user_fault : 1;
				uint32_t m_stand_by_protection_needed : 1;
				uint32_t m_pte_changed : 1;
				uint32_t m_page_file_fault : 1;
				uint32_t m_page_file_page_hash_active : 1;
				uint32_t m_coalesced_Io : 1;
				uint32_t m_mm_lock_not_needed : 1;
				uint32_t m_spare0 : 1;
				uint32_t m_spare1 : 6;
		  };
		  uint32_t m_long_flags;
	 };

	 union
	 {
		  FILE_OBJECT* m_file_pointer;
		  void* m_paging_file;
	 };

	 union
	 {
		  mm_control_area_t* m_control_area;
		  void* m_subsection;
	 };

	 void* m_autoboost;
	 void* m_faulting_address;
	 mm_pte_t* m_pointer_pte;
	 mm_pte_t* m_base_pte;
	 mm_pfn_t* m_pfn;
	 MDL* m_prefetch_mdl;
	 volatile __int64	m_probe_count;
	 _MDL					m_mdl;

	 union
	 {
		  uint64_t								m_page[ 16u ];
		  mm_inpage_support_flow_thru_t	m_flow_through;
	 };
};

struct epartition_t
{
	 void* m_mm_partition;
	 void* m_cc_partition;
	 void* m_ex_partition;
	 uint64_t				m_hard_reference_count;
	 uint64_t				m_open_handle_count;
	 LIST_ENTRY			m_active_partition_links;
	 epartition_t* m_parent_partition;
	 WORK_QUEUE_ITEM	m_teardown_work_item;
	 ex_push_lock_t		m_teardown_lock;
	 eprocess_t* m_system_process;
	 void* m_system_process_handle;
	 uint32_t				m_partition_flags;
};

struct mi_largepage_vad_info_t
{
	 uint8_t			m_large_image_bias;
	 uint8_t			m_spare[ 3u ];
	 uint64_t			m_actual_image_view_size;
	 epartition_t* m_ref_partition;
};

struct mm_vad_short_t;

struct mi_physical_view_t
{
	 RTL_BALANCED_NODE		m_physical_node;
	 mm_vad_short_t* m_vad;
	 void* m_awe_info;

	 union
	 {
		  struct
		  {
				uint64_t m_view_page_size : 2;
		  };

		  mm_control_area_t* m_control_area;
	 };
};

struct mi_sub64k_free_ranges_t
{
	 rtl_bitmap_ex_t	m_bitmap;
	 LIST_ENTRY			m_list_entry;
	 mm_vad_short_t* m_vad;
	 uint32_t				m_set_bits;
	 uint32_t				m_full_set_bits;
	 uint32_t				m_sub_list_index : 2;
	 uint32_t				m_hint : 30;
};

struct mi_vad_event_block_t
{
	 mi_vad_event_block_t* m_next;

	 union
	 {
		  KGATE							m_gate;
		  mm_address_list_t			m_secure_info;
		  rtl_bitmap_ex_t			m_bitmap;
		  mm_inpage_support_t* m_in_page_support;
		  mi_largepage_vad_info_t	m_large_page;
		  mi_physical_view_t		m_awe_view;
		  ethread_t* m_thread;
		  mi_sub64k_free_ranges_t	m_peb_teb;
		  mm_vad_short_t* m_placeholder_vad;
	 };

	 uint32_t m_wait_reason;
};

struct mm_vad_short_t
{
	 union
	 {
		  mm_vad_short_t* m_next_vad;
		  void* m_extra_create_info;
		  RTL_BALANCED_NODE	m_vad_node;
	 };

	 uint32_t	m_starting_vpn;
	 uint32_t	m_ending_vpn;
	 uint8_t	m_starting_vpn_high;
	 uint8_t	m_ending_vpn_high;
	 uint8_t	m_commit_charge_high;
	 uint8_t	m_spare_nt64_vad;
	 uint32_t	m_ref_count;

	 ex_push_lock_t m_push_lock;

	 union
	 {
		  uint32_t m_long_flags;

		  struct
		  {
				uint32_t m_lock : 1;
				uint32_t m_lock_contended : 1;
				uint32_t m_delete_in_progress : 1;
				uint32_t m_no_change : 1;
				uint32_t m_vad_type : 3;
				uint32_t m_protection : 5;
				uint32_t m_preferred_node : 6;
				uint32_t m_page_size : 2;
				uint32_t m_private_memory : 1;
		  };
	 };

	 union
	 {
		  uint32_t m_long_flags1;

		  struct
		  {
				uint32_t m_commit_charge : 31;
				uint32_t m_mem_commit : 1;
		  };
	 };

	 mi_vad_event_block_t* m_event_list;
};

struct mm_vad_t
{
	 mm_vad_short_t m_core;

	 union
	 {
		  uint32_t m_long_flags;

		  struct
		  {
				uint32_t m_file_offset : 24;
				uint32_t m_large : 1;
				uint32_t m_trim_behind : 1;
				uint32_t m_inherit : 1;
				uint32_t m_no_validation_needed : 1;
				uint32_t m_private_demand_zero : 1;
				uint32_t m_spare : 3;
		  } m_flags;
	 } u;

	 void* m_sub_section;
	 mm_pte_t* m_first_prototype_pte;
	 mm_pte_t* m_last_prototype_pte;
	 LIST_ENTRY		m_view_links;
	 eprocess_t* m_vads_process;
	 uint64_t			u4;
	 FILE_OBJECT* m_file_object;
};

typedef struct _FLOATING_SAVE_AREA
{
	 ULONG   ControlWord;
	 ULONG   StatusWord;
	 ULONG   TagWord;
	 ULONG   ErrorOffset;
	 ULONG   ErrorSelector;
	 ULONG   DataOffset;
	 ULONG   DataSelector;
	 UCHAR   RegisterArea[ 80 ];
	 ULONG   Spare0;
} FLOATING_SAVE_AREA, * PFLOATING_SAVE_AREA;

typedef struct DECLSPEC_NOINITALL _CONTEXT86
{
	 ULONG ContextFlags;

	 //
	 // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
	 // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
	 // included in CONTEXT_FULL.
	 //

	 ULONG   Dr0;
	 ULONG   Dr1;
	 ULONG   Dr2;
	 ULONG   Dr3;
	 ULONG   Dr6;
	 ULONG   Dr7;

	 //
	 // This section is specified/returned if the
	 // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
	 //

	 FLOATING_SAVE_AREA FloatSave;

	 //
	 // This section is specified/returned if the
	 // ContextFlags word contians the flag CONTEXT_SEGMENTS.
	 //

	 ULONG   SegGs;
	 ULONG   SegFs;
	 ULONG   SegEs;
	 ULONG   SegDs;

	 //
	 // This section is specified/returned if the
	 // ContextFlags word contians the flag CONTEXT_INTEGER.
	 //

	 ULONG   Edi;
	 ULONG   Esi;
	 ULONG   Ebx;
	 ULONG   Edx;
	 ULONG   Ecx;
	 ULONG   Eax;

	 //
	 // This section is specified/returned if the
	 // ContextFlags word contians the flag CONTEXT_CONTROL.
	 //

	 ULONG   Ebp;
	 ULONG   Eip;
	 ULONG   SegCs;              // MUST BE SANITIZED
	 ULONG   EFlags;             // MUST BE SANITIZED
	 ULONG   Esp;
	 ULONG   SegSs;

	 UCHAR   ExtendedRegisters[ 512 ];

} CONTEXT86, * PCONTEXT86;

#pragma warning( pop )

extern "C" NTSTATUS NTAPI NtQuerySystemInformation( SYSTEM_INFORMATION_CLASS system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length );
extern "C" NTSTATUS NTAPI NtQueryInformationProcess( HANDLE proc_handle, PROCESSINFOCLASS process_information_class, PVOID process_information, ULONG process_information_length, PULONG return_length );
extern "C" NTSTATUS NTAPI NtOpenThread( HANDLE * thread_handle, ACCESS_MASK access_mask, OBJECT_ATTRIBUTES * object_attributes, CLIENT_ID * client_id );
extern "C" NTSTATUS NTAPI NtSetInformationProcess( HANDLE proc_handle, uint32_t proc_info_class, void* buffer, uint32_t size );
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory( eprocess_t * source_process, void* source_address, eprocess_t * target_process, void* target_address, size_t buffer_size, KPROCESSOR_MODE previous_mode, size_t * return_size );
extern "C" NTSTATUS NTAPI PsSuspendProcess( eprocess_t * proc );
extern "C" void     NTAPI RtlAvlRemoveNode( rtl_avl_tree_t * table, PRTL_BALANCED_NODE node );

namespace utils
{
	 template< typename _ty, typename ...args >
#ifdef _MSC_VER
	 __forceinline
#else
	 __attribute__( ( always_inline ) )
#endif
		  NTSTATUS system_call( _ty* fn, args... arguments )
	 {
		  ethread_t* thread = reinterpret_cast< ethread_t* >( KeGetCurrentThread( ) );
		  uint8_t old_prev_mode = thread->m_prev_mode;
		  thread->m_prev_mode = 0;
		  NTSTATUS status = reinterpret_cast< NTSTATUS( * )( args... ) >( fn )( arguments... );
		  thread->m_prev_mode = old_prev_mode;
		  return status;
	 }

	 template< typename _ty, typename _addr_ty >
	 NTSTATUS read_physical( _addr_ty address, _ty* buf, size_t size )
	 {
		  MM_COPY_ADDRESS addr;
		  addr.PhysicalAddress.QuadPart = ( uint64_t )address;
		  size_t out_size = 0;
		  return MmCopyMemory( buf, addr, size, MM_COPY_MEMORY_PHYSICAL, &out_size );
	 }

	 template< typename _addr_ty >
	 NTSTATUS write_physical( _addr_ty address, const void* buf, size_t size )
	 {
		  KIRQL irql = KeRaiseIrqlToDpcLevel( );

		  uint64_t pages = size / PAGE_SIZE + 1;

		  for ( uint64_t i = 0; i < pages; ++i )
		  {
				PHYSICAL_ADDRESS phys_addr;
				phys_addr.QuadPart = ( uint64_t )address + ( i * PAGE_SIZE );

				void* mapped = MmMapIoSpace( phys_addr, min( PAGE_SIZE, size ), MmNonCached );

				if ( !mapped )
				{
					 KeLowerIrql( irql );
					 return STATUS_UNSUCCESSFUL;
				}

				__movsb( reinterpret_cast< PUCHAR >( mapped ), ( const PUCHAR )buf, min( PAGE_SIZE, size ) );

				MmUnmapIoSpace( mapped, min( PAGE_SIZE, size ) );

				size -= PAGE_SIZE;
		  }

		  KeLowerIrql( irql );
		  return STATUS_SUCCESS;
	 }

	 struct memory_region_t
	 {
		  uint64_t m_base;
		  uint32_t m_size;
		  eprocess_t* m_proc;
	 };

	 inline c_vector< memory_region_t, 'mrgn' > m_allocated_memory{ };
}