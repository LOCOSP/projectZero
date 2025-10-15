if(NOT DEFINED DEST)
  message(FATAL_ERROR "post_build.cmake: DEST is not set")
endif()
if(NOT DEFINED BLD)
  message(FATAL_ERROR "post_build.cmake: BLD is not set")
endif()
if(NOT DEFINED APP)
  message(FATAL_ERROR "post_build.cmake: APP is not set")
endif()

# Upewnij się, że katalog docelowy istnieje
file(MAKE_DIRECTORY "${DEST}")

# Usuń TYLKO stare pliki .bin (np. zostaw pythonowe .py w spokoju)
file(GLOB OLD_BINS "${DEST}/*.bin")
if(OLD_BINS)
  file(REMOVE ${OLD_BINS})
endif()

# Zdefiniuj źródła do skopiowania
set(SRCS
  "${BLD}/${APP}"                            # np. build/projectZero.bin
  "${BLD}/bootloader/bootloader.bin"         # bootloader
  "${BLD}/partition_table/partition-table.bin" # tabela partycji (standardowa ścieżka w IDF)
)

# Skopiuj istniejące pliki
foreach(F ${SRCS})
  if(EXISTS "${F}")
    file(COPY "${F}" DESTINATION "${DEST}")
  else()
    message(WARNING "post_build.cmake: Missing file: ${F}")
  endif()
endforeach()
