# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2019-2022 Second State INC

wasmedge_add_library(wasmedgePluginWasiOCR
  SHARED
  wasiocrenv.cpp
  wasiocrfunc.cpp
  wasiocrmodule.cpp
)

target_compile_options(wasmedgePluginWasiOCR
  PUBLIC
  -DWASMEDGE_PLUGIN
)

target_include_directories(wasmedgePluginWasiOCR
        PUBLIC
        $<TARGET_PROPERTY:wasmedgePlugin,INCLUDE_DIRECTORIES>
        ${CMAKE_CURRENT_SOURCE_DIR}
)

set(TESSERACT_DIR "/opt/homebrew/Cellar/tesseract/5.3.3")
set(LEPTONICA_DIR "/opt/homebrew/Cellar/leptonica/1.83.1")

add_library(wasmedgePluginWasmEdgeImageTesseract STATIC IMPORTED GLOBAL)
add_library(wasmedgePluginWasmEdgeImageLeptonica STATIC IMPORTED GLOBAL)

find_library(TESSERACT_STATIC NAMES libtesseract.dylib HINTS ${TESSERACT_DIR}/lib)
find_library(LEPTONICA_STATIC NAMES libleptonica.dylib HINTS ${LEPTONICA_DIR}/lib)

set_target_properties(wasmedgePluginWasmEdgeImageTesseract
        PROPERTIES
        IMPORTED_LOCATION ${TESSERACT_STATIC}
        INTERFACE_INCLUDE_DIRECTORIES "${TESSERACT_DIR}/include"
)
set_target_properties(wasmedgePluginWasmEdgeImageLeptonica
        PROPERTIES
        IMPORTED_LOCATION ${LEPTONICA_STATIC}
        INTERFACE_INCLUDE_DIRECTORIES "${LEPTONICA_DIR}/include"
)

target_link_libraries(wasmedgePluginWasiOCR
  PUBLIC
  wasmedgePluginWasmEdgeImageTesseract
  wasmedgePluginWasmEdgeImageLeptonica
)

#target_link_libraries(wasmedgePluginWasiOCR
#  PUBLIC
#  tesseract
#)

#target_link_options(wasmedgePluginWasiOCR
#  PUBLIC
# -Wl,-U,__ZN8WasmEdge6Plugin14PluginRegisterC1EPKNS0_6Plugin16PluginDescriptorE
# -Wl,-U,__ZN8WasmEdge6Plugin14PluginRegisterD1Ev
#)

#if(APPLE)
#    message(WARNING "apple compile OCR plugin")
##    find_library(LEPTONICA_LIB NAMES libleptonica.a PATHS "${LEPTONICA_DIR}/lib" NO_DEFAULT_PATH)
##    # 确保CMake找到了库
##    if(NOT LEPTONICA_LIB)
##        message(FATAL_ERROR "libleptonica.a not found")
##    endif()
#
#    find_library(GIF_LIB NAMES libgif.a PATHS "/opt/homebrew/Cellar/giflib/5.2.1/lib" NO_DEFAULT_PATH)
#    if(NOT GIF_LIB)
#        message(FATAL_ERROR "GIF library not found")
#    endif()
#
#    find_library(TIFF_LIB NAMES libtiff.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#    if(NOT TIFF_LIB)
#        message(FATAL_ERROR "TIFF library not found")
#    endif()
#
#    find_library(PNG_LIB NAMES libpng.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#    if(NOT PNG_LIB)
#        message(FATAL_ERROR "PNG library not found")
#    endif()
#
#    find_library(JPEG_LIB NAMES libjpeg.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(WEBP_LIB NAMES libwebp.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(WEBPMUX_LIB NAMES libwebpmux.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(OPENJP_2_LIB NAMES libopenjp2.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(LZMA_LIB NAMES liblzma.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(Z_LIB NAMES libz.a PATHS "/opt/homebrew//Cellar/zlib/1.3/lib/" NO_DEFAULT_PATH)
#
#    find_library(ZSTD_LIB NAMES libzstd.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(SHARPYUV_LIB NAMES libsharpyuv.a PATHS "/opt/homebrew/lib/" NO_DEFAULT_PATH)
#
#    find_library(ARCHIVE_LIB NAMES libarchive.a PATHS "/opt/homebrew//Cellar/libarchive/3.7.2/lib/" NO_DEFAULT_PATH)
#
#    find_library(BZ2_LIB NAMES libbz2.a PATHS "/opt/homebrew/Cellar/bzip2/1.0.8/lib/" NO_DEFAULT_PATH)
#
#    find_library(EXPAT_LIB NAMES libexpat.a PATHS "/opt/homebrew/Cellar/expat/2.5.0/lib/" NO_DEFAULT_PATH)
#
#    find_library(CURL_LIB NAMES libcurl.a PATHS "/opt/homebrew/Cellar/curl/8.4.0/lib/" NO_DEFAULT_PATH)
#
#    # 链接静态库到你的可执行文件
#    target_link_libraries(wasmedgePluginWasiOCR
#            PUBLIC
#            "${LEPTONICA_LIB}"
#            ${WEBP_LIB}
#            ${GIF_LIB}
#            ${TIFF_LIB}
#            ${PNG_LIB}
#            ${JPEG_LIB}
#            ${WEBPMUX_LIB}
#            ${OPENJP_2_LIB}
#            ${LZMA_LIB}
#            ${Z_LIB}
#            ${ZSTD_LIB}
#            ${SHARPYUV_LIB}
#            ${ARCHIVE_LIB}
#            ${BZ2_LIB}
#            ${EXPAT_LIB}
#            ${CURL_LIB}
#    )
#endif()

if(WASMEDGE_LINK_PLUGINS_STATIC)
    target_link_libraries(wasmedgePluginWasiOCR
      PRIVATE
      wasmedgeCAPI
    )
else()
    target_link_libraries(wasmedgePluginWasiOCR
      PRIVATE
      wasmedge_shared
    )
endif()

message("install wasmedgePluginWasiOCR" ${CMAKE_INSTALL_LIBDIR}/wasmedge)
install(TARGETS wasmedgePluginWasiOCR DESTINATION ${CMAKE_INSTALL_LIBDIR}/wasmedge)