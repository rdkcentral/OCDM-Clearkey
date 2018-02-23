cmake_minimum_required(VERSION 2.8)

set(DRM_PLUGIN_NAME ClearKey)

find_package(ClearKey REQUIRED)

file(GLOB DRM_PLUGIN_INCLUDES *.h)

set(DRM_PLUGIN_LIBS 
    ${CLEARKEY_LIBRARIES})

set(DRM_PLUGIN_SOURCES 
    MediaSession.cpp 
    MediaSystem.cpp
    json_web_key.cpp
    jsmn/jsmn.c
    )

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${CLEARKEY_FLAGS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CEARKEY_INCLUDE_DIRS} "./jsmn")
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBS})
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/${PLUGIN_NAME})
