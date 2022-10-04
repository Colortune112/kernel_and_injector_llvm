#pragma once

#include "../utils/utils.h"

class c_ntdll
{
private:
	 struct idx
	 {
		  int m_index;
		  uint64_t m_hash;
	 };

	 idx* m_indexes;
	 int m_count;

public:
	 NTSTATUS initialize( );
	 void shutdown( );
	 int get_ssdt_index( uint64_t export_hash );
};

extern c_ntdll g_ntdll;