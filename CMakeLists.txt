# define CMake Version required
cmake_minimum_required(VERSION 2.6)

# define project name
project(BINTYPE)

# recurse into these subdirectories
add_subdirectory(libtracereader)

# add included header files from these directories
include_directories(${BINTYPE_SOURCE_DIR}/)
include_directories(${BINTYPE_SOURCE_DIR}/libtracereader)
include_directories(${BINTYPE_SOURCE_DIR}/xed2/xed2-ia32/include)

# add linked library from these directories
link_directories(${BINTYPE_SOURCE_DIR}/libtracereader)
link_directories(${BINTYPE_SOURCE_DIR}/xed2/xed2-ia32/lib)

# compile options
add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE)
add_definitions(-Wall -O3 -g3 -Wno-unused-result -Wformat=0)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
add_definitions(-D_BINTYPE_DEBUG -D_BINTYPE_COLLECTOR)
endif()

# add all current source files to $DIR_SRCS
aux_source_directory(${BINTYPE_SOURCE_DIR} DIR_SRCS)

# compile these source files into executable
add_executable(trace_creader ${DIR_SRCS})

# link objects to executable
target_link_libraries(trace_creader tracereader xed)

