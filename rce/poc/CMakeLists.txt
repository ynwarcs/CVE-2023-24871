cmake_minimum_required (VERSION 3.5)

project(poc)

SET(BTSTACK_ROOT ${CMAKE_SOURCE_DIR}/btstack)

# extra compiler warnings
if ("${CMAKE_C_COMPILER_ID}" MATCHES ".*Clang.*")
	# using Clang
	SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wunused-variable -Wswitch-default -Werror")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	# using GCC
	SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wunused-but-set-variable -Wunused-variable -Wswitch-default -Werror")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")
	# using Intel C++
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
	# using Visual Studio C++
endif()

# to generate .h from .gatt files
find_package (Python REQUIRED COMPONENTS Interpreter)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# local dir for btstack_config.h after build dir to avoid using .h from Makefile
include_directories(.)

include_directories(btstack/3rd-party/bluedroid/decoder/include)
include_directories(btstack/3rd-party/bluedroid/encoder/include)
include_directories(btstack/3rd-party/micro-ecc)
include_directories(btstack/3rd-party/lc3-google/include)
include_directories(btstack/3rd-party/md5)
include_directories(btstack/3rd-party/hxcmod-player)
include_directories(btstack/3rd-party/hxcmod-player/mod)
include_directories(btstack/3rd-party/rijndael)
include_directories(btstack/3rd-party/yxml)
include_directories(btstack/src)
include_directories(btstack/chipset/zephyr)
include_directories(btstack/platform/embedded)
include_directories(btstack/platform/posix)
include_directories(btstack/platform/windows)

file(GLOB SOURCES_SRC       "btstack/src/*.c" "btstack/example/sco_demo_util.c" "btstack/platform/posix/wav_util.c")
file(GLOB SOURCES_BLUEDROID "btstack/3rd-party/bluedroid/encoder/srce/*.c" "btstack/3rd-party/bluedroid/decoder/srce/*.c")
file(GLOB SOURCES_CLASSIC   "btstack/src/classic/*.c")
file(GLOB SOURCES_BLE       "btstack/src/ble/*.c")
file(GLOB SOURCES_GATT      "btstack/src/ble/gatt-service/*.c")
file(GLOB SOURCES_UECC      "btstack/3rd-party/micro-ecc/uECC.c")
file(GLOB SOURCES_HXCMOD    "btstack/3rd-party/hxcmod-player/*.c"  "btstack/3rd-party/hxcmod-player/mods/*.c")
file(GLOB SOURCES_MD5       "btstack/3rd-party/md5/md5.c")
file(GLOB SOURCES_RIJNDAEL  "btstack/3rd-party/rijndael/rijndael.c")
file(GLOB SOURCES_WINDOWS   "btstack/platform/windows/*.c")
file(GLOB SOURCES_ZEPHYR    "btstack/chipset/zephyr/*.c")
file(GLOB SOURCES_LC3_GOOGLE "btstack/3rd-party/lc3-google/src/*.c")
file(GLOB SOURCES_PORT      "*.c")
file(GLOB SOURCES_YXML      "btstack/3rd-party/yxml/yxml.c")

file(GLOB SOURCES_BLE_OFF "btstack/src/ble/le_device_db_memory.c")
list(REMOVE_ITEM SOURCES_BLE   ${SOURCES_BLE_OFF})


set(SOURCES
	${SOURCES_BLE}
	${SOURCES_BLUEDROID}
	${SOURCES_CLASSIC}
	${SOURCES_GATT}
	${SOURCES_HXCMOD}
	${SOURCES_MD5}
	${SOURCES_PORT}
	${SOURCES_RIJNDAEL}
	${SOURCES_SRC}
	${SOURCES_UECC}
	${SOURCES_WINDOWS}
	${SOURCES_YXML}
	${SOURCES_ZEPHYR}
)
list(SORT SOURCES)

# create static lib
add_library(btstack STATIC ${SOURCES})

# get list of examples, skipping mesh_node_demo
set (EXAMPLES poc)
list(REMOVE_DUPLICATES EXAMPLES)

# create targets
foreach(EXAMPLE ${EXAMPLES})
	# get c file
	set (SOURCES_EXAMPLE ${EXAMPLE}.c)
	add_executable(${EXAMPLE} ${SOURCES_EXAMPLE})
	target_link_libraries(${EXAMPLE} btstack setupapi winusb)
endforeach(EXAMPLE)
