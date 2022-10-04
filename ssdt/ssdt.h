#pragma once

#include "../utils/utils.h"

namespace ssdt
{
	 struct ssdt_t
	 {
		  uint32_t* m_service_table;
		  uint64_t pad;
		  uint32_t m_number_of_services;
	 };

	 extern ssdt_t* m_service_desc_table;

	 bool hook( int index, void* function, void** original = nullptr, bool shadow = false );

	 template< typename _ty = void* >
	 _ty get_ssdt_function( int index )
	 {
		  return ( _ty )( reinterpret_cast< uint64_t >( m_service_desc_table->m_service_table ) + ( uint64_t )( m_service_desc_table->m_service_table[ index ] >> 4 ) );
	 }
}