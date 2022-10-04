#pragma once

template< typename _ty >
struct address_t
{
	 _ty* m_ptr;
	 MDL* m_mdl;

	 address_t< _ty >( )
	 {
		  m_ptr = ( _ty* )0;
		  m_mdl = nullptr;
	 }

	 address_t< _ty >( _ty* ptr )
	 {
		  m_ptr = ptr;
		  m_mdl = nullptr;
	 }

	 address_t< _ty >( _ty* ptr, MDL* mdl )
	 {
		  m_ptr = ptr;
		  m_mdl = mdl;
	 }

	 template< typename _cast_type >
	 _cast_type as( )
	 {
		  return ( _cast_type )m_ptr;
	 }

	 template< typename _cast_type >
	 address_t< _cast_type > to( )
	 {
		  return address_t< _cast_type >( reinterpret_cast< _cast_type* >( m_ptr ), m_mdl );
	 }

	 address_t rel( uint64_t offset )
	 {
		  m_ptr = ( *( uint8_t* )( ( uint64_t )m_ptr + offset + 3 ) == 0xFF ) ?
				( _ty* )( ( uint64_t )m_ptr + offset + 4 + *( uint32_t* )( ( uint64_t )m_ptr + offset ) + 0xFFFFFFFF00000000 ) :
				( _ty* )( ( uint64_t )m_ptr + offset + 4 + *( uint32_t* )( ( uint64_t )m_ptr + offset ) );

		  return *this;
	 }

	 operator _ty* ( ) const
	 {
		  return m_ptr;
	 }

	 _ty* operator->( )
	 {
		  return m_ptr;
	 }

	 _ty& operator[ ]( uint64_t index )
	 {
		  return m_ptr[ index ];
	 }
};

namespace utils
{
	 template< typename _ty >
	 address_t< _ty > alloc( size_t size )
	 {
		  uint64_t pages = size / PAGE_SIZE + 1;

		  PHYSICAL_ADDRESS low_address;
		  PHYSICAL_ADDRESS high_address;

		  low_address.QuadPart = 0;
		  high_address.QuadPart = 0xFFFFFFFFFFFFFFFF;

		  MDL* mdl = MmAllocatePagesForMdl( low_address, high_address, low_address, pages * PAGE_SIZE );
		  if ( !mdl )
				return address_t< _ty >( );

		  void* virtual_address = MmMapLockedPagesSpecifyCache( mdl, KernelMode, MmNonCached, nullptr, FALSE, HighPagePriority );

		  if ( !virtual_address )
		  {
				MmFreePagesFromMdl( mdl );
				IoFreeMdl( mdl );
				return address_t< _ty >( );
		  }

		  return address_t< _ty >( ( _ty* )virtual_address, mdl );
	 }

	 template< typename _ty >
	 void free( address_t< _ty > addr )
	 {
		  MmUnmapLockedPages( addr.m_ptr, addr.m_mdl );
		  MmFreePagesFromMdl( addr.m_mdl );
		  IoFreeMdl( addr.m_mdl );
	 }
}