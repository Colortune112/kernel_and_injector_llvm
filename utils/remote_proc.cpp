#include "remote_proc.h"

uint64_t c_remote_proc::get_mod_address86( const wchar_t* mod_name, bool load_if_not_found )
{
	 if ( !m_proc->m_wow64_process->m_peb )
		  return 0;

	 eprocess_t* old_proc = nullptr;
	 uint64_t old_cr3 = attach( &old_proc );

	 if ( !m_proc->m_wow64_process->m_peb->m_ldr )
	 {
		  detach( old_cr3, old_proc );
		  return 0;
	 }

	 uint64_t base = 0;

	 for ( list_entry32_t* list_entry = ( list_entry32_t* )reinterpret_cast< peb_ldr_data32_t* >( m_proc->m_wow64_process->m_peb->m_ldr )->m_in_load_order_module_list.m_flink;
			 list_entry != &reinterpret_cast< peb_ldr_data32_t* >( m_proc->m_wow64_process->m_peb->m_ldr )->m_in_load_order_module_list;
			 list_entry = reinterpret_cast< list_entry32_t* >( list_entry->m_flink ) )
	 {
		  ldr_data_table_entry32_t* entry = CONTAINING_RECORD( list_entry, ldr_data_table_entry32_t, m_in_load_order_links );

		  if ( !_wcsicmp( reinterpret_cast< wchar_t* >( entry->m_base_dll_name.m_buffer ), mod_name ) )
		  {
				base = entry->m_base_address;
				break;
		  }
	 }

	 detach( old_cr3, old_proc );

	 /*peb_ldr_data32_t ldr;
	 __stosb( reinterpret_cast< PUCHAR >( &ldr ), 0, sizeof( ldr ) );
	 read( &ldr, peb.m_ldr, sizeof( ldr ) );

	 list_entry32_t list_entry = ldr.m_in_initialization_order_module_list;
	 uint32_t address = list_entry.m_blink;
	 read( &list_entry, address, sizeof( list_entry ) );
	 address = list_entry.m_flink;
	 list_entry = ldr.m_in_initialization_order_module_list;

	 uint64_t base = 0;

	 do
	 {
		  ldr_data_table_entry32_t entry;
		  __stosb( reinterpret_cast< PUCHAR >( &entry ), 0, sizeof( entry ) );
		  read( &entry, CONTAINING_RECORD( address, ldr_data_table_entry32_t, m_in_initialization_order_links ), sizeof( entry ) );

		  if ( entry.m_base_dll_name.m_buffer && entry.m_base_dll_name.m_length && entry.m_base_dll_name.m_length <= 255 )
		  {
				wchar_t buf[ 255 ];
				read( buf, entry.m_base_dll_name.m_buffer, static_cast< uint64_t >( entry.m_base_dll_name.m_length ) * 2 + 1 );

				if ( !_wcsicmp( buf, mod_name ) )
					 base = entry.m_base_address;

				if ( base )
					 break;
		  }

		  address = list_entry.m_flink;
		  read( &list_entry, address, sizeof( list_entry ) );
	 } while ( list_entry.m_flink != ldr.m_in_initialization_order_module_list.m_flink );*/

	 if ( !base && load_if_not_found && _wcsicmp( mod_name, _( L"kernelbase.dll" ) ) )
	 {
		  static uint64_t load_library = get_proc_address86( _( "kernelbase.dll" ), HASH( "LoadLibraryW" ) );

		  struct
		  {
				uint32_t m_load_library;
				uint32_t m_file_name;
		  } arg;

		  uint8_t shell[ ] = {
			  0x8D, 0x41, 0x04,	  // lea eax, [ ecx + 0x4 ]
			  0x8B, 0x00,			  // mov eax, [ eax ]
			  0x50,					  // push eax
			  0xFF, 0x11,			  // call dword ptr[ ecx ]
			  0xC3					  // ret
		  };

		  auto allocated = alloc( sizeof( shell ) + sizeof( arg ) + ( wcslen( mod_name ) * 2 ) + 1 );

		  arg.m_load_library = static_cast< uint32_t >( load_library );
		  arg.m_file_name = static_cast< uint32_t >( allocated.as< uint64_t >( ) + sizeof( shell ) + sizeof( arg ) );

		  write( allocated, shell, sizeof( shell ) );
		  write( allocated + sizeof( shell ), &arg, sizeof( arg ) );
		  write( allocated + sizeof( shell ) + sizeof( arg ), mod_name, wcslen( mod_name ) * 2 + 1 );

		  if ( !start_routine( allocated.as< uint64_t >( ), allocated.as< uint64_t >( ) + sizeof( shell ) ) )
		  {
				free( allocated );
				__debugbreak( );
				return 0;
		  }

		  free( allocated );

		  return get_mod_address86( mod_name, false );
	 }

	 return base;
}

uint64_t c_remote_proc::get_mod_address64( const wchar_t* mod_name, bool load_if_not_found )
{
	 UNREFERENCED_PARAMETER( load_if_not_found );

	 if ( !m_proc->m_peb )
		  return 0;

	 peb_t peb;
	 __stosb( reinterpret_cast< PUCHAR >( &peb ), 0, sizeof( peb ) );
	 read( &peb, m_proc->m_peb, sizeof( peb ) );

	 if ( !peb.m_ldr )
		  return 0;

	 peb_ldr_data_t ldr;
	 __stosb( reinterpret_cast< PUCHAR >( &ldr ), 0, sizeof( ldr ) );
	 read( &ldr, peb.m_ldr, sizeof( ldr ) );

	 LIST_ENTRY list_entry = ldr.m_in_initialization_order_module_list;
	 uint64_t address = reinterpret_cast< uint64_t >( list_entry.Blink );
	 read( &list_entry, address, sizeof( list_entry ) );
	 address = reinterpret_cast< uint64_t >( list_entry.Flink );
	 list_entry = ldr.m_in_initialization_order_module_list;

	 uint64_t base = 0;

	 do
	 {
		  ldr_data_table_entry_t entry;
		  __stosb( reinterpret_cast< PUCHAR >( &entry ), 0, sizeof( entry ) );
		  read( &entry, CONTAINING_RECORD( address, ldr_data_table_entry_t, m_in_initialization_order_links ), sizeof( entry ) );

		  if ( entry.m_base_dll_name.Buffer && entry.m_base_dll_name.Length )
		  {
				wchar_t buf[ 255 ];
				read( buf, entry.m_base_dll_name.Buffer, static_cast< uint64_t >( entry.m_base_dll_name.Length ) * 2 + 1 );

				if ( !_wcsicmp( buf, mod_name ) )
					 base = entry.m_base_address;

				if ( base )
					 break;
		  }

		  address = reinterpret_cast< uint64_t >( list_entry.Flink );
		  read( &list_entry, address, sizeof( list_entry ) );
	 } while ( list_entry.Flink != ldr.m_in_initialization_order_module_list.Flink );

	 return base;
}

bool c_remote_proc::start_routine86( uint32_t address, uint32_t arg )
{
	 static NTSTATUS( *ps_suspend_thread )( ethread_t*, void* ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B F8 BA 50 73 53 75" ) ).rel( 1 ).as< decltype( ps_suspend_thread ) >( );

	 static NTSTATUS( *psp_get_context_thread_internal )( ethread_t*, CONTEXT*, bool, bool, uint32_t ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B F8 48 8B CB E8 ? ? ? ? 48 8B 5C 24 40" )
	 ).rel( 1 ).as< decltype( psp_get_context_thread_internal ) >( );

	 static NTSTATUS( *psp_set_context_thread_internal )( ethread_t*, CONTEXT*, bool, bool, uint32_t ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B F8 EB 05 BF 08 00 00 C0" )
	 ).rel( 1 ).as< decltype( psp_set_context_thread_internal ) >( );

	 static NTSTATUS( *ps_resume_thread )( ethread_t*, void* ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? BA 50 73 53 75" ) ).rel( 1 ).as< decltype( ps_resume_thread ) >( );

	 //static NTSTATUS( *psp_wow64_get_context_thread )( ethread_t*, CONTEXT86*, uint32_t, uint8_t ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B D8 85 C0 78 6E B8" ) ).rel( 1 ).as< decltype( psp_wow64_get_context_thread ) >( );

	 //static NTSTATUS( *psp_wow64_set_context_thread )( ethread_t*, CONTEXT86*, uint32_t, uint8_t ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B D8 49 8D 8E" ) ).rel( 1 ).as< decltype( psp_wow64_set_context_thread ) >( );

	 ethread_t* thread = nullptr;
	 ethread_t* cur_thread = reinterpret_cast< ethread_t* >( KeGetCurrentThread( ) );
	 auto read_entry = utils::alloc< ethread_t >( sizeof( ethread_t ) );

	 do
	 {
		  for ( LIST_ENTRY* list_entry = m_proc->m_thread_list_head.Flink;
				  list_entry != &m_proc->m_thread_list_head;
				  list_entry = list_entry->Flink )
		  {
				ethread_t* entry = CONTAINING_RECORD( list_entry, ethread_t, m_thread_list_entry );

				if ( !entry || entry == cur_thread )
					 continue;

				uint16_t same_teb_flags = 0;
				if ( !NT_SUCCESS( read( &same_teb_flags, ( uint64_t )entry->m_teb + 0xFCA, sizeof( uint16_t ) ) ) )
					 continue;

				utils::memcpy( read_entry.m_ptr, entry, sizeof( ethread_t ) );

				if ( is_thread_alertable86( entry, ps_suspend_thread, ps_resume_thread, psp_get_context_thread_internal ) || read_entry->m_state != 2 || 
					  same_teb_flags & 0x2000 || read_entry->m_wait_reason == KWAIT_REASON::WrQueue )
					 continue;
			
				thread = entry;
				break;
		  }
	 } while ( !thread );

	 utils::free( read_entry );

	 if ( !thread )
		  return false;

	 uint8_t shell[ ] = {
		  0x50,												// push							 $+0
		  0x51,												// push							 $+1
		  0x52,												// push							 $+2
		  0x53,												//	push							 $+3
		  0x55,												// push							 $+4
		  0x56,												// push							 $+5
		  0x57,												// push							 $+6
		  0x9C,												// push							 $+7
		  0x81, 0xEC, 0x00, 0x01, 0x00, 0x00,		// sub esp, 0x100				 $+8
		  0xB8, 0x78, 0x56, 0x34, 0x12,				// mov eax, address			 $+14
		  0xB9, 0x78, 0x56, 0x34, 0x12,				// mov ecx, arg				 $+19
		  0xFF, 0xD0,										// call eax						 $+24
		  0xA3, 0x00, 0x00, 0x00, 0x00,				// mov [ ret_val ], eax		 $+26
		  0x81, 0xC4, 0x00, 0x01, 0x00, 0x00,		// add esp, 0x100				 $+31
		  0x9D,												// pop							 $+37
		  0x5F,												// pop							 $+38
		  0x5E,												// pop							 $+39
		  0x5D,												// pop							 $+40
		  0x5B,												// pop							 $+41
		  0x5A,												// pop							 $+42
		  0x59,												// pop							 $+43
		  0x58,												// pop							 $+44
		  0x68, 0x78, 0x56, 0x34, 0x12,				// push orig_eip				 $+45
		  0xC3,												// ret							 $+50
		  0xFF, 0xFF, 0xFF, 0xFF						// ret_val						 $+51
	 };

	 auto ctx = alloc( sizeof( CONTEXT ) ).to< CONTEXT >( );
	 address_t< uint64_t > allocated_shell = alloc( sizeof( shell ) );

	 eprocess_t* old_proc = nullptr;
	 uint64_t old_cr3 = attach( &old_proc );

	 utils::memset( ctx.m_ptr, 0, sizeof( CONTEXT ) );
	 ctx->ContextFlags = CONTEXT_FULL;

	 if ( !NT_SUCCESS( psp_get_context_thread_internal( thread, ctx.m_ptr, 1, 1, 1 ) ) )
	 {
		  ps_resume_thread( thread, nullptr );
		  return false;
	 }

	 *reinterpret_cast< uint32_t* >( &shell[ 15 ] ) = address;
	 *reinterpret_cast< uint32_t* >( &shell[ 20 ] ) = arg;
	 *reinterpret_cast< uint32_t* >( &shell[ 27 ] ) = static_cast< uint32_t >( allocated_shell.as< uint64_t >( ) + 51 );
	 *reinterpret_cast< uint32_t* >( &shell[ 46 ] ) = static_cast< uint32_t >( ctx->Rip );

	 ctx->Rip = static_cast< uint32_t >( allocated_shell.as< uint64_t >( ) );

	 write( allocated_shell, shell, sizeof( shell ) );

	 if ( !NT_SUCCESS( psp_set_context_thread_internal( thread, ctx.m_ptr, 1, 1, 1 ) ) )
	 {
		  free( allocated_shell );
		  ps_resume_thread( thread, nullptr );
		  return false;
	 }

	 detach( old_cr3, old_proc );

	 free( ctx.to< uint64_t >( ) );

	 if ( !NT_SUCCESS( ps_resume_thread( thread, nullptr ) ) )
	 {
		  free( allocated_shell );
		  return false;
	 }

	 uint32_t done_flag = 0xFFFFFFFF;
	 while ( done_flag == 0xFFFFFFFF &&
				NT_SUCCESS( read( &done_flag, allocated_shell.as< uint64_t >( ) + 51, sizeof( uint32_t ) ) ) );
	 
	 utils::sleep( 1000 );

	 free( allocated_shell );

	 return true;
}

bool c_remote_proc::start_routine64( uint64_t address, uint64_t arg )
{
	 ethread_t* thread = nullptr;

	 for ( LIST_ENTRY* list_entry = m_proc->m_thread_list_head.Flink;
			 list_entry != &m_proc->m_thread_list_head;
			 list_entry = list_entry->Flink )
	 {
		  ethread_t* entry = CONTAINING_RECORD( list_entry, ethread_t, m_thread_list_entry );
		  if ( entry->m_exit_status != STATUS_PENDING || entry->m_cross_thread_flags & 1 )
				continue;

		  thread = entry;
	 }

	 if ( !thread )
		  return false;

	 uint8_t shell[ ] = {
			 0x50,                                                           // push rax                 $+0
			 0x51,                                                           // push rcx                 $+1
			 0x53,                                                           // push rbx                 $+2
			 0x55,                                                           // push rbp                 $+3
			 0x57,                                                           // push rdi                 $+4
			 0x56,                                                           // push rsi                 $+5
			 0x54,                                                           // push rsp                 $+6
			 0x41, 0x52,                                                     // push r10                 $+7
			 0x41, 0x53,                                                     // push r11                 $+9
			 0x41, 0x54,                                                     // push r12                 $+B
			 0x41, 0x55,                                                     // push r13                 $+D
			 0x41, 0x56,                                                     // push r14                 $+F
			 0x41, 0x57,                                                     // push r15                 $+11
			 0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00,                       // sub rsp, 0x1000          $+13
			 0x48, 0xB8, 0xFF, 0xFF, 0x34, 0x12, 0xFF, 0xFF, 0x34, 0x12,     // mov rax, routine         $+1A
			 0x48, 0xB9, 0xFF, 0xFF, 0x34, 0x12, 0xFF, 0xFF, 0x34, 0x12,     // mov rcx, arg             $+24
			 0xFF, 0xD0,                                                     // call rax                 $+2E
			 0x48, 0xB8, 0xFF, 0xFF, 0x34, 0x12, 0xFF, 0xFF, 0x34, 0x12,     // mov rax, &done_flag      $+30
			 0xC6, 0x00, 0x01,                                               // mov byte ptr[ rax ], 1   $+3A
			 0x48, 0x81, 0xC4, 0x00, 0x10, 0x00, 0x00,                       // add rsp, 0x1000          $+3D
			 0x41, 0x5F,                                                     // pop r15                  $+44
			 0x41, 0x5E,                                                     // pop r14                  $+46
			 0x41, 0x5D,                                                     // pop r13                  $+48
			 0x41, 0x5C,                                                     // pop r12                  $+4A
			 0x41, 0x5B,                                                     // pop r11                  $+4C
			 0x41, 0x5A,                                                     // pop r10                  $+4E
			 0x5C,                                                           // pop rsp                  $+50
			 0x5E,                                                           // pop rsi                  $+51
			 0x5F,                                                           // pop rdi                  $+52
			 0x5D,                                                           // pop rbp                  $+53
			 0x5B,                                                           // pop rbx                  $+54
			 0x59,                                                           // pop rcx                  $+55
			 0x58,                                                           // pop rax                  $+56
			 0x48, 0x83, 0xEC, 0x10,                                         // sub rsp, 0x10            $+57
			 0x48, 0x89, 0x04, 0x24,                                         // mov qword ptr[ rsp ], rax $+5B
			 0x48, 0xB8, 0x34, 0x12, 0xFF, 0xFF, 0x34, 0x12, 0xFF, 0xFF,     // mov rax, orig_rip        $+5F
			 0x48, 0x89, 0x44, 0x24, 0x08,                                   // mov qword ptr[ rsp + 8 ], rax    $+69
			 0x48, 0x8B, 0x04, 0x24,                                         // mov rax, qword ptr[ rsp ] $+6E
			 0x48, 0x83, 0xC4, 0x08,                                         // add rsp, 8               $+72
			 0xC3,                                                           // ret                      $+76
			 0x00,                                                           // done_flag                $+77
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                  // orig_rip                 $+78
	 };

	 static NTSTATUS( *ps_suspend_thread )( ethread_t*, void* ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B F8 BA 50 73 53 75" ) ).rel( 1 ).as< decltype( ps_suspend_thread ) >( );

	 static NTSTATUS( *psp_get_context_thread_internal )( ethread_t*, CONTEXT*, bool, bool, uint32_t ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B F8 48 8B CB E8 ? ? ? ? 48 8B 5C 24 40" )
	 ).rel( 1 ).as< decltype( psp_get_context_thread_internal ) >( );

	 static NTSTATUS( *psp_set_context_thread_internal )( ethread_t*, CONTEXT*, bool, bool, uint32_t ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? 8B F8 EB 05 BF 08 00 00 C0" )
	 ).rel( 1 ).as< decltype( psp_set_context_thread_internal ) >( );

	 static NTSTATUS( *ps_resume_thread )( ethread_t*, void* ) = utils::find_pattern( utils::m_krnl, _( "E8 ? ? ? ? BA 50 73 53 75" ) ).rel( 1 ).as< decltype( ps_resume_thread ) >( );

	 auto allocated_shell = alloc( sizeof( shell ) );

	 if ( !ps_suspend_thread( thread, nullptr ) )
	 {
		  free( allocated_shell );
		  return false;
	 }

	 CONTEXT ctx;
	 ctx.ContextFlags = CONTEXT_FULL;

	 if ( !psp_get_context_thread_internal( thread, &ctx, 0, 0, 1 ) )
	 {
		  free( allocated_shell );
		  ps_resume_thread( thread, nullptr );
		  return false;
	 }

	 uint64_t old_rip = ctx.Rip;

	 *reinterpret_cast< uint64_t* >( shell + 0x1C ) = address;
	 *reinterpret_cast< uint64_t* >( shell + 0x26 ) = arg;
	 *reinterpret_cast< uint64_t* >( shell + 0x32 ) = allocated_shell.as< uint64_t >( ) + 0x77;
	 *reinterpret_cast< uint64_t* >( shell + 0x78 ) = old_rip;

	 write( allocated_shell, shell, sizeof( shell ) );

	 ctx.Rip = allocated_shell.as< uint64_t >( );

	 if ( !psp_set_context_thread_internal( thread, &ctx, 0, 0, 1 ) )
	 {
		  // fatal error
	 }

	 if ( !ps_resume_thread( thread, nullptr ) )
	 {
		  free( allocated_shell );
		  return false;
	 }

	 uint8_t done_flag = 0;
	 while ( !done_flag )
		  read( &done_flag, allocated_shell.as< uint64_t >( ) + 0x77, sizeof( uint8_t ) );

	 free( allocated_shell );

	 return true;
}

bool c_remote_proc::is_thread_alertable86( ethread_t* thread, NTSTATUS( *ps_suspend_thread )( ethread_t*, void* ), NTSTATUS( *ps_resume_thread )( ethread_t*, void* ), NTSTATUS( *psp_get_context_thread_internal )( ethread_t*, CONTEXT*, bool, bool, uint32_t ) )
{
	 static uint64_t wait_functions[ 5 ] = { 0, 0, 0, 0, 0 };

	 if ( !NT_SUCCESS( ps_suspend_thread( thread, nullptr ) ) )
		  return true;

	 uint64_t wow64_base = get_mod_address64( _( L"wow64.dll" ) );
	 uint64_t wow64win_base = get_mod_address64( _( L"wow64win.dll" ) );
	 uint64_t wow64cpu_base = get_mod_address64( _( L"wow64cpu.dll" ) );
	 uint64_t ntdll64_base = get_mod_address64( _( L"ntdll.dll" ) );
	 eprocess_t* old_proc = nullptr;
	 uint64_t old_cr3 = attach( &old_proc );
	 uint64_t wow64_size = reinterpret_cast< IMAGE_NT_HEADERS64* >( wow64_base + reinterpret_cast< IMAGE_DOS_HEADER* >( wow64_base )->e_lfanew )->OptionalHeader.SizeOfImage;
	 uint64_t wow64win_size = reinterpret_cast< IMAGE_NT_HEADERS64* >( wow64win_base + reinterpret_cast< IMAGE_DOS_HEADER* >( wow64win_base )->e_lfanew )->OptionalHeader.SizeOfImage;
	 uint64_t wow64cpu_size = reinterpret_cast< IMAGE_NT_HEADERS64* >( wow64cpu_base + reinterpret_cast< IMAGE_DOS_HEADER* >( wow64cpu_base )->e_lfanew )->OptionalHeader.SizeOfImage;
	 uint64_t ntdll64_size = reinterpret_cast< IMAGE_NT_HEADERS64* >( ntdll64_base + reinterpret_cast< IMAGE_DOS_HEADER* >( ntdll64_base )->e_lfanew )->OptionalHeader.SizeOfImage;
	 detach( old_cr3, old_proc );

	 if ( !wait_functions[ 0 ] )
	 {
		  wait_functions[ 0 ] = get_proc_address86( _( "ntdll.dll" ), HASH( "NtDelayExecution" ) ) + 0xC;
		  wait_functions[ 1 ] = get_proc_address86( _( "ntdll.dll" ), HASH( "NtWaitForSingleObject" ) ) + 0xC;
		  wait_functions[ 2 ] = get_proc_address86( _( "ntdll.dll" ), HASH( "NtWaitForMultipleObjects" ) ) + 0xC;
		  wait_functions[ 3 ] = get_proc_address86( _( "ntdll.dll" ), HASH( "NtSignalAndWaitForSingleObject" ) ) + 0xC;
		  wait_functions[ 4 ] = get_proc_address86( _( "win32u.dll" ), HASH( "NtUserMsgWaitForMultipleObjectsEx" ) ) + 0xC;
	 }

	 CONTEXT ctx;
	 utils::memset( &ctx, 0, sizeof( ctx ) );
	 ctx.ContextFlags = CONTEXT_FULL;

	 if ( !NT_SUCCESS( psp_get_context_thread_internal( thread, &ctx, 0, 1, 1 ) ) )
	 {
		  ps_resume_thread( thread, nullptr );
		  return true;
	 }

#define is_in_range( x, s, l ) ( x >= s && x <= ( s + l ) )

	 if ( is_in_range( ctx.Rip, wow64_base, wow64_size ) || 
			is_in_range( ctx.Rip, wow64win_base, wow64win_size ) ||
			is_in_range( ctx.Rip, ntdll64_base, ntdll64_size ) ||
			is_in_range( ctx.Rip, wow64cpu_base, wow64cpu_size ) )
	 {
		  ps_resume_thread( thread, nullptr );
		  return true;
	 }

	 uint32_t stack[ 6 ];
	 utils::memset( stack, 0, sizeof( stack ) );

	 if ( !NT_SUCCESS( read( stack, ctx.Rsp, sizeof( stack ) ) ) )
	 {
		  ps_resume_thread( thread, nullptr );
		  return true;
	 }

	 if ( ( ctx.Rip == wait_functions[ 0 ] && stack[ 1 ] == 1 ) ||
			( ctx.Rip == wait_functions[ 1 ] && stack[ 2 ] == 1 ) ||
			( ctx.Rip == wait_functions[ 2 ] && stack[ 4 ] == 1 ) ||
			( ctx.Rip == wait_functions[ 3 ] && stack[ 3 ] == 1 ) ||
			( ctx.Rip == wait_functions[ 4 ] && stack[ 5 ] & 2 ) )
	 {
		  ps_resume_thread( thread, nullptr );
		  return true;
	 }

	 return false;
}

uint64_t c_remote_proc::get_proc_address86( const char* mod_name, uint64_t func_hash )
{
	 size_t length = utils::strlen( mod_name );
	 auto wide_mod_name = utils::alloc< wchar_t >( length * 2 + 1 );
	 for ( size_t i = 0; i < length; ++i )
		  wide_mod_name[ i ] = static_cast< wchar_t >( mod_name[ i ] );
	 wide_mod_name[ length ] = 0;

	 uint64_t mod_base = get_mod_address( wide_mod_name.m_ptr );
	 utils::free( wide_mod_name );
	 if ( !mod_base )
	 {
		  __debugbreak( );
		  return 0;
	 }

	 eprocess_t* old_proc = nullptr;
	 uint64_t old_cr3 = attach( &old_proc );

	 IMAGE_NT_HEADERS32* nt = reinterpret_cast< IMAGE_NT_HEADERS32* >( mod_base + reinterpret_cast< IMAGE_DOS_HEADER* >( mod_base )->e_lfanew );

	 IMAGE_EXPORT_DIRECTORY* exports = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( mod_base + nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress );

	 uint32_t* functions = reinterpret_cast< uint32_t* >( exports->AddressOfFunctions + mod_base );
	 uint32_t* names = reinterpret_cast< uint32_t* >( exports->AddressOfNames + mod_base );
	 uint16_t* ordinals = reinterpret_cast< uint16_t* >( exports->AddressOfNameOrdinals + mod_base );

	 if ( func_hash <= 0xFFFF )
	 {
		  uint64_t proc = mod_base + functions[ ordinals[ func_hash ] ];
		  detach( old_cr3, old_proc );
		  return proc;
	 }

	 for ( uint32_t i = 0; i < exports->NumberOfNames; ++i )
	 {
		  if ( HASH_RT( reinterpret_cast< const char* >( mod_base + names[ i ] ) ) == func_hash )
		  {
				uint64_t proc = mod_base + functions[ ordinals[ i ] ];

				char* exp_name = reinterpret_cast< char* >( proc );

				char module_name[ 255 ];
				utils::memset( module_name, 0, 255 );

				bool found = false;

				length = 0;
				while ( exp_name[ length ] )
				{
					 if ( length > 0x20 )
					 {
						  length = 0;
						  break;
					 }

					 ++length;
				}

				for ( uint32_t o = 0; o < length; ++o )
				{
					 if ( exp_name[ o ] == '.' )
					 {
						  module_name[ o ] = '.';
						  module_name[ o + 1 ] = 'd';
						  module_name[ o + 2 ] = 'l';
						  module_name[ o + 3 ] = 'l';
						  module_name[ o + 4 ] = 0;

						  exp_name = exp_name + o + 1;
						  found = true;
						  break;
					 }
					 else
					 {
						  module_name[ o ] = exp_name[ o ];
					 }
				}

				if ( found )
				{
					 uint64_t prob_proc = get_proc_address86( module_name, HASH_RT( exp_name ) );
					 if ( prob_proc )
						  proc = prob_proc;
				}

				detach( old_cr3, old_proc );

				return proc;
		  }
	 }

	 detach( old_cr3, old_proc );

	 return 0;
}

uint64_t c_remote_proc::get_proc_address64( const char* mod_name, uint64_t func_hash )
{
	 UNREFERENCED_PARAMETER( mod_name );
	 UNREFERENCED_PARAMETER( func_hash );

	 return 0;

	 /*size_t length = utils::strlen( mod_name );
	 auto wide_mod_name = utils::alloc< wchar_t >( length * 2 + 1 );
	 for ( size_t i = 0; i < length; ++i )
		  wide_mod_name[ i ] = static_cast< wchar_t >( mod_name[ i ] );
	 wide_mod_name[ length ] = 0;

	 uint64_t mod_base = get_mod_address( wide_mod_name.m_ptr );
	 utils::free( wide_mod_name );
	 if ( !mod_base )
		  return 0;

	 auto hdr = utils::alloc< uint8_t >( 0x1000 );
	 if ( !NT_SUCCESS( read( hdr.m_ptr, mod_base, 0x1000 ) ) )
		  return 0;

	 IMAGE_NT_HEADERS* nt = ( IMAGE_NT_HEADERS* )( hdr.m_ptr + reinterpret_cast< IMAGE_DOS_HEADER* >( hdr.m_ptr )->e_lfanew );

	 auto export_directory = utils::alloc< IMAGE_EXPORT_DIRECTORY >( nt->OptionalHeader.DataDirectory[ 0 ].Size );

	 if ( !NT_SUCCESS( read( export_directory.m_ptr, mod_base + nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress, nt->OptionalHeader.DataDirectory[ 0 ].Size ) ) )
	 {
		  utils::free( hdr );
		  utils::free( export_directory );
		  return 0;
	 }

	 uint64_t delta = reinterpret_cast< uint64_t >( export_directory.m_ptr ) - nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress;

	 uint32_t* functions = reinterpret_cast< uint32_t* >( export_directory->AddressOfFunctions + delta );
	 uint32_t* names = reinterpret_cast< uint32_t* >( export_directory->AddressOfNames + delta );
	 uint16_t* ordinals = reinterpret_cast< uint16_t* >( export_directory->AddressOfNameOrdinals + delta );

	 if ( func_hash <= 0xFFFF )
	 {
		  utils::free( export_directory );
		  uint64_t address = 
		  utils::free( hdr );
		  return mod_base + functions[ ordinals[ func_hash ] ];
	 }

	 for ( uint32_t i = 0; i < export_directory->NumberOfNames; ++i )
	 {
		  if ( HASH_RT( reinterpret_cast< const char* >( names[ i ] + delta ) ) == func_hash )
		  {
				uint64_t address = mod_base + functions[ ordinals[ i ] ];
				utils::free( export_directory );
				utils::free( hdr );
				return address;
		  }
	 }

	 utils::free( export_directory );

	 return 0;*/
}

bool c_remote_proc::init( uint64_t proc_id )
{
	 m_proc = nullptr;
	 if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( proc_id ), reinterpret_cast< PEPROCESS* >( &m_proc ) ) ) || !m_proc || m_proc->m_exit_status != STATUS_PENDING )
		  return false;

	 m_wow64 = m_proc->m_wow64_process ? true : false;

	 return true;
}

bool c_remote_proc::open_handle( )
{
	 if ( !check( ) )
		  return false;

	 OBJECT_ATTRIBUTES obj_attr;
	 InitializeObjectAttributes( &obj_attr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr );
	 CLIENT_ID cid;
	 cid.UniqueProcess = reinterpret_cast< HANDLE >( m_proc->m_process_id );
	 cid.UniqueThread = 0;
	 m_proc_handle = nullptr;
	 return NT_SUCCESS( utils::system_call( NtOpenProcess, &m_proc_handle, 1 | 8, &obj_attr, &cid ) ) && m_proc_handle && m_proc_handle != reinterpret_cast< HANDLE >( -1 );
}

void c_remote_proc::close_handle( )
{
	 if ( m_proc_handle && m_proc_handle != reinterpret_cast< HANDLE >( -1 ) )
		  utils::system_call( NtClose, m_proc_handle );
}

uint64_t c_remote_proc::get_mod_address( const wchar_t* mod_name, bool load_if_not_found )
{
	 if ( !check( ) )
		  return 0;

	 if ( m_wow64 )
		  return get_mod_address86( mod_name, load_if_not_found );
	 else
		  return get_mod_address64( mod_name, load_if_not_found );
}

uint64_t c_remote_proc::get_proc_address( const char* mod_name, uint64_t func_hash )
{
	 if ( !check( ) )
		  return 0;

	 if ( m_wow64 )
		  return get_proc_address86( mod_name, func_hash );
	 else
		  return get_proc_address64( mod_name, func_hash );
}

bool c_remote_proc::start_routine( uint64_t address, uint64_t arg )
{
	 if ( !check( ) )
		  return false;

	 if ( m_wow64 )
		  return start_routine86( static_cast< uint32_t >( address ), static_cast< uint32_t >( arg ) );
	 else
		  return start_routine64( address, arg );
}

TABLE_SEARCH_RESULT find_node_or_parent( rtl_avl_tree_t* table, ULONG_PTR starting_vpn, RTL_BALANCED_NODE** node_or_parent )
{
	 *node_or_parent = nullptr;

	 if ( !table->m_number_generic_table_elements )
		  return TableEmptyTree;

	 RTL_BALANCED_NODE* node_to_examine = table->m_root;

	 TABLE_SEARCH_RESULT result;
	 RTL_BALANCED_NODE* child;

	 for ( ;; )
	 {
		  mm_vad_short_t* vpn_compare = ( mm_vad_short_t* )node_to_examine;
		  ULONG_PTR start_vpn = vpn_compare->m_starting_vpn;
		  ULONG_PTR end_vpn = vpn_compare->m_ending_vpn;

		  start_vpn |= ( uint64_t )vpn_compare->m_starting_vpn_high << 32;
		  end_vpn |= ( uint64_t )vpn_compare->m_ending_vpn_high << 32;

		  if ( starting_vpn < start_vpn )
		  {
				child = node_to_examine->Left;

				if ( child )
				{
					 node_to_examine = child;
				}
				else
				{

					 *node_or_parent = node_to_examine;
					 result = TableInsertAsLeft;
					 break;
				}
		  }
		  else if ( starting_vpn <= end_vpn )
		  {
				*node_or_parent = node_to_examine;
				result = TableFoundNode;
				break;
		  }
		  else
		  {
				child = node_to_examine->Right;

				if ( child )
				{
					 node_to_examine = child;
				}
				else
				{

					 *node_or_parent = node_to_examine;
					 result = TableInsertAsRight;
					 break;
				}
		  }
	 }

	 return result;
}

address_t< uint64_t > c_remote_proc::alloc( size_t size )
{
	 if ( !check( ) )
		  return 0;

	 if ( !open_handle( ) )
	 {
		  __debugbreak( );
		  return address_t< uint64_t >( );
	 }

	 void* address = nullptr;
	 NTSTATUS status = ZwAllocateVirtualMemory( m_proc_handle, &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	 if ( !NT_SUCCESS( status ) )
	 {
		  __debugbreak( );
		  return address_t< uint64_t >( );
	 }

	 close_handle( );

	 eprocess_t* old_proc = nullptr;
	 uint64_t old_cr3 = attach( &old_proc );

	 utils::memset( address, 0xCC, size );

	 detach( old_cr3, old_proc );

	 return address_t< uint64_t >( reinterpret_cast< uint64_t* >( address ) );
}

void c_remote_proc::free( address_t< uint64_t > address )
{
	 if ( !check( ) )
		  return;

	 if ( !open_handle( ) )
		  return;

	 size_t size = 0;

	 ZwFreeVirtualMemory( m_proc_handle, ( void** )&address.m_ptr, &size, MEM_RELEASE );

	 close_handle( );
}

bool c_remote_proc::check( )
{
	 if ( m_proc->m_exit_status != STATUS_PENDING )
		  return false;

	 return true;
}

uint64_t c_remote_proc::attach( eprocess_t** old_proc )
{
	 ethread_t* cur_thread = reinterpret_cast< ethread_t* >( KeGetCurrentThread( ) );
	 uint64_t old_dir_table_base = cur_thread->m_proc->m_directory_table_base;
	 _cli( );
	 *old_proc = cur_thread->m_proc;
	 cur_thread->m_proc = m_proc;
	 __writecr3( m_proc->m_directory_table_base );
	 _sti( );
	 return old_dir_table_base;
}

void c_remote_proc::detach( uint64_t old_cr3, eprocess_t* old_proc )
{
	 _cli( );
	 __writecr3( old_cr3 );
	 reinterpret_cast< ethread_t* >( KeGetCurrentThread( ) )->m_proc = old_proc;
	 _sti( );
}

bool c_remote_proc::is_wow64( )
{
	 return m_wow64;
}

eprocess_t* c_remote_proc::get( )
{
	 return m_proc;
}