#include <gtest/gtest.h>

#include <toycrypto/hash/md2.h>

class Md2Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    MD2 m_hfun{};

    const std::string m_empty_digest = "8350e5a3e24c153df2275c9f80692773";
    const std::string m_fox_digest = "03d85a0d629d2c442e987525319fc471";

    static const size_t m_tv1_len = 65;
    const char m_tv1[m_tv1_len] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const std::string m_tv1_exp = "288786ca38a2be4cc173e6235f627bde";

    static const size_t m_tv2_len = 8;
    const char m_tv2[m_tv2_len] = "AAAAAAA";
    const std::string m_tv2_exp = "98f206c3c2cbbbef1b0101f7a968d4be";
};

TEST_F(Md2Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md2Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md2Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md2Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md2Tests, FullBlock) {
    EXPECT_NO_THROW(m_hfun.update(m_tv1, m_tv1_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv1_exp);
}

TEST_F(Md2Tests, ThousandTimesSevenAs) {
    for (int i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update(m_tv2, m_tv2_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv2_exp);
}

TEST_F(Md2Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Md2Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
