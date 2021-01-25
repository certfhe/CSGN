cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

## Use -std=c++11 as default.
set(CMAKE_CXX_STANDARD 11)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(certFHE
       	LANGUAGES CXX)



add_library(certFHE-static STATIC
		 main.cpp)

add_library(certFHE-shared SHARED
		 main.cpp)


add_executable(certFHE-tests
			test.cpp)

target_compile_definitions(certFHE-static PUBLIC -DPUBLIC_DLL)
target_compile_definitions(certFHE-shared PUBLIC -DPUBLIC_DLL)

set_target_properties(certFHE-static PROPERTIES OUTPUT_NAME certFHE)
set_target_properties(certFHE-shared PROPERTIES OUTPUT_NAME certFHE)
set_target_properties(certFHE-tests PROPERTIES OUTPUT_NAME certFHE-tests)

target_link_libraries(certFHE-static)
target_link_libraries(certFHE-shared)

target_link_libraries(certFHE-tests certFHE-shared)