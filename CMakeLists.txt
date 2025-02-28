cmake_minimum_required(VERSION 3.20)
project(ics-mka LANGUAGES C CXX)

option(ICS_MKA_BUILD_EXAMPLES "Build MKA examples" OFF)
option(ICS_MKA_LOG_RESULT "Log mka_result_t errors" OFF)
set(ICS_MKA_RESULT_LEVEL 0 CACHE STRING "Result level: ICS_MKA_RESULT_LEVEL = 0 returns only API errors, ICS_MKA_RESULT_LEVEL = 1 returns internal errors")
set(ICS_MKA_MAX_NUM_PEERS 30 CACHE STRING "Set the maximum number of peers")
set(ICS_MKA_MAX_NUM_CAKS 8 CACHE STRING "Set the maximum number of caks")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_library(ics-mka 
	src/mka.c
	src/mka_crypt.c
	src/mka_params.c
	src/mka_pdu.c
	src/mka_utility.c
	src/mka_state.c
	src/mka_result.c
)

include(FetchContent)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Only build static" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable Mbed-TLS executables" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Disable Mbed-TLS testing" FORCE)
FetchContent_Declare(
	MbedTLS
	GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
	GIT_TAG mbedtls-3.6.2 
)

FetchContent_MakeAvailable(MbedTLS)
target_link_libraries(ics-mka PRIVATE MbedTLS::mbedtls)
target_include_directories(ics-mka PUBLIC include)
if(MSVC)
	target_compile_options(ics-mka PRIVATE /W4 /WX /GR-)
else()
	target_compile_options(ics-mka PRIVATE -Wall -Werror -fPIC)
endif()

if(ICS_MKA_LOG_RESULT)
	target_compile_definitions(ics-mka PRIVATE -DICS_MKA_LOG_RESULT=On)
endif()

target_compile_definitions(ics-mka PRIVATE -DICS_MKA_RESULT_LEVEL=${ICS_MKA_RESULT_LEVEL})
target_compile_definitions(ics-mka PRIVATE -DMKA_MAX_NUM_PEERS=${ICS_MKA_MAX_NUM_PEERS})
target_compile_definitions(ics-mka PRIVATE -DMKA_MAX_NUM_CAKS=${ICS_MKA_MAX_NUM_CAKS})

if(ICS_MKA_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()