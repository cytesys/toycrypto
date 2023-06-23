#include <gtest/gtest.h>

#include <toycrypto/internal/common.h>

TEST(RotateTest, ROL1bit) {
    EXPECT_EQ(rol<uint32_t>(0xf0000000u, 1), 0xe0000001u);
}

TEST(RotateTest, ROL8bit) {
    EXPECT_EQ(rol<uint32_t>(0xf0000000u, 8), 0x000000f0u);
}

TEST(RotateTest, ROLlover) {
    EXPECT_EQ(rol<uint32_t>(0xf0000000u, 32), 0xf0000000u);
}

TEST(RotateTest, ROR1bit) {
    EXPECT_EQ(ror<uint32_t>(0xf0000000u, 1), 0x78000000u);
}

TEST(RotateTest, ROR8bit) {
    EXPECT_EQ(ror<uint32_t>(0xf0000000u, 8), 0x00f00000u);
}

TEST(RotateTest, RORlover) {
    EXPECT_EQ(ror<uint32_t>(0xf0000000u, 32), 0xf0000000u);
}
