#include <gtest/gtest.h>

TEST(FooTests, TrueEqualsTrue)
{
    const auto expected = true;
    const auto actual = true == true;
    ASSERT_EQ(expected, actual);
}

TEST(FooTests, FalseEqualsFalse)
{
    const auto expected = true;
    const auto actual = false == false;
    ASSERT_EQ(expected, actual);
}

TEST(FooTests, FalseEqualsTrue)
{
    const auto expected = false;
    const auto actual = false==true;
    ASSERT_EQ(expected, actual);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
