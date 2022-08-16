ADD_EXECUTABLE(unitTest

        "../thirdparty/libOTe/cryptoTools/cryptoTools/Common/CLP.h"
        "../thirdparty/libOTe/cryptoTools/cryptoTools/Common/CLP.cpp"
        "../thirdparty/libOTe/cryptoTools/cryptoTools/Common/Defines.h"
        "../thirdparty/libOTe/cryptoTools/cryptoTools/Common/Defines.cpp"
        "UnitTest.cpp")

target_link_libraries(unitTest PUBLIC libPSI oc::libOTe_Tests oc::tests_cryptoTools)
# libPSI_Tests
