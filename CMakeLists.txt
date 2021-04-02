cmake_minimum_required(VERSION 3.6)

set(DynamoRIO_DIR "/home/pavel/DynamoRIO/cmake") # set your path

project(MyDRIOproject)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_CXX_STANDARD 17)
find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS TraceFormat/format.proto)

# For C clients that only rely on the DR API and not on any 3rd party
# library routines, we could shrink the size of the client binary
# by disabling libc via "set(DynamoRIO_USE_LIBC OFF)".
find_package(DynamoRIO 8.0)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)


function (add_sample_client name source_file_list extension_list)
  add_library(${name} SHARED ${source_file_list})
  configure_DynamoRIO_client(${name})
  foreach (ext ${extension_list})
    use_DynamoRIO_extension(${name} ${ext})
  endforeach (ext)
endfunction (add_sample_client)


configure_DynamoRIO_global(OFF ON)

add_sample_client(tracca "tracca.cpp;utils.cpp;${PROTO_SRCS};${PROTO_HDRS}" "drmgr;drreg;drx;drutil")
target_link_libraries(tracca ${Protobuf_LIBRARIES})
