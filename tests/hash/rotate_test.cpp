#include <gtest/gtest.h>

#include <toycrypto/internal/common.h>

TEST(RotateTest, ROL1bit) {
    EXPECT_EQ(ROL(0xf0000000u, 1, 32), 0xe0000001u);
}

TEST(RotateTest, ROL8bit) {
    EXPECT_EQ(ROL(0xf0000000u, 8, 32), 0x000000f0u);
}

TEST(RotateTest, ROLlover) {
    EXPECT_EQ(ROL(0xf0000000u, 32, 32), 0xf0000000u);
}

TEST(RotateTest, ROR1bit) {
    EXPECT_EQ(ROR(0xf0000000u, 1, 32), 0x78000000u);
}

TEST(RotateTest, ROR8bit) {
    EXPECT_EQ(ROR(0xf0000000u, 8, 32), 0x00f00000u);
}

TEST(RotateTest, RORlover) {
    EXPECT_EQ(ROR(0xf0000000u, 32, 32), 0xf0000000u);
}
