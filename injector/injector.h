#pragma once

#include "../utils/remote_proc.h"

class c_injector
{
private:
	 c_remote_proc m_remote_proc;

public:
	 bool init( );
	 bool inject( );
};

inline c_injector g_injector;