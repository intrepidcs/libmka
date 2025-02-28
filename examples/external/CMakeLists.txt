
add_executable(ics-mka-external main.c pcap_internal.c)
target_link_libraries(ics-mka-external PUBLIC ics-mka)

if(WIN32)
	target_include_directories(ics-mka-external PUBLIC ${CMAKE_SOURCE_DIR}/third-party/winpcap/include)
	target_include_directories(ics-mka-external PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
	add_definitions(-DWPCAP -DHAVE_REMOTE -DWIN32_LEAN_AND_MEAN)
else()
	find_package(PCAP REQUIRED)
	target_include_directories(ics-mka-external PUBLIC ${PCAP_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(ics-mka-external PUBLIC ${PCAP_LIBRARY})
endif(WIN32)

