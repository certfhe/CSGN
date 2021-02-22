#include "Helpers.h"


using namespace certFHE;

#pragma region Library class

void Library::initializeLibrary()
{
    //Introducing local time as seed for further pseudo random generator calls
	srand(time(NULL));
}

#pragma endregion 

#pragma region Helper class

bool Helper::exists(const uint64_t*v,const uint64_t len,const uint64_t value)
{
    for (int i = 0; i < len; i++)
		if (v[i] == value)
			return true;

	return false;

}

 void Helper::deletePointer(void* pointer, bool isArray)
 {
     if (pointer != NULL)
		if (isArray)
			delete[] pointer;
		else
			delete pointer;
 }

 #pragma endregion