cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

## Use -std=c++11 as default.
set(CMAKE_CXX_STANDARD 11)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(certFHE
       	LANGUAGES CXX)

set(HEADER_FILES ${src/Plaintext.h}
				 ${src/Ciphertext.h}
				 ${src/Context.h}				
				 ${src/Permutation.h}
				 ${src/SecretKey.h}
				 ${src/Timer.h}
				 ${src/utils.h}
				 ${src/Helpers.h}
				 ${src/certFHE.h} )

add_library(certFHE-static STATIC
			src/Plaintext.cpp
			src/Ciphertext.cpp
			src/Context.cpp			
			src/Permutation.cpp
			src/SecretKey.cpp
			src/Timer.cpp
			src/Helpers.cpp
			${HEADER_FILES})

add_library(certFHE-shared SHARED
			src/Plaintext.cpp
			src/Ciphertext.cpp
			src/Context.cpp			
			src/Permutation.cpp
			src/SecretKey.cpp
			src/Timer.cpp
			src/Helpers.cpp
			${HEADER_FILES})



add_executable(tester_basic_operations
			tests/basic_operations.cpp)

add_executable(tester_permutations
			tests/permutations.cpp)

add_executable(tester_timings
			tests/timings.cpp)

target_compile_definitions(certFHE-static PUBLIC -DPUBLIC_DLL)
target_compile_definitions(certFHE-shared PUBLIC -DPUBLIC_DLL)

set_target_properties(certFHE-static PROPERTIES OUTPUT_NAME certFHE)
set_target_properties(certFHE-shared PROPERTIES OUTPUT_NAME certFHE)

set_target_properties(tester_basic_operations PROPERTIES OUTPUT_NAME tester_basic_operations)
set_target_properties(tester_permutations PROPERTIES OUTPUT_NAME tester_permutations)
set_target_properties(tester_timings PROPERTIES OUTPUT_NAME tester_timings)

target_link_libraries(certFHE-static)
target_link_libraries(certFHE-shared)

target_link_libraries(tester_basic_operations certFHE-shared)
target_link_libraries(tester_permutations certFHE-shared)
target_link_libraries(tester_timings certFHE-shared)