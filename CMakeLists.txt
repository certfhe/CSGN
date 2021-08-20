cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

## Use -std=c++11 as default.
set(CMAKE_CXX_STANDARD 11)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(certFHE
        LANGUAGES CXX)

set(HEADER_FILES ${Plaintext.h}
		 ${ArgClasses.h}
		 ${GlobalParams.h}
		 ${Ciphertext.h}
		 ${Context.h}				
		 ${Permutation.h}
		 ${SecretKey.h}
		 ${Timer.h}
		 ${utils.h}
		 ${Helpers.h}
		 ${ThreadPool.h}
		 ${certFHE.h} )

add_library(certFHE-static STATIC
	    Plaintext.cpp
	    Ciphertext.cpp
	    Context.cpp			
	    Permutation.cpp
	    SecretKey.cpp
	    Timer.cpp
	    Helpers.cpp
	    GlobalParams.cpp
	    GlobalParams.cpp
	    ${HEADER_FILES})


add_executable(tester
	    app.cpp)

target_compile_definitions(certFHE-static PUBLIC -DPUBLIC_DLL)

set_target_properties(certFHE-static PROPERTIES OUTPUT_NAME certFHE)

set_target_properties(tester PROPERTIES OUTPUT_NAME tester)

target_link_libraries(certFHE-static)

target_link_libraries(tester certFHE-static pthread)