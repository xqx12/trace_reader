# add included header files from these directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../xed2/xed2-ia32/include)

# add linked library from these directories
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../xed2/xed2-ia32/lib)

# compile options
add_definitions(-O3 -g3 -Wno-unused-result)
add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE)

# create a library
add_library(tracereader trace_interface.c trace_print.c)

# link objects to target
target_link_libraries(tracereader xed)

