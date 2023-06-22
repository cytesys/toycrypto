#include <gtest/gtest.h>

#include <toycrypto/hash/md4.h>

class Md4Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    MD4 m_hfun{};

    const std::string m_empty_digest = "31d6cfe0d16ae931b73c59d7e0c089c0";
    const std::string m_fox_digest = "1bee69a46ba811185c194762abaeae90";

    static const size_t m_tv1_len = 65;
    const char m_tv1[m_tv1_len] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const std::string m_tv1_exp = "21caceb3a62c434222cdf4913991d761";

    static const size_t m_tv2_len = 8;
    const char m_tv2[m_tv2_len] = "AAAAAAA";
    const std::string m_tv2_exp = "386abcdcf0c696342b7c1b8a15085672";
};

TEST_F(Md4Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md4Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md4Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md4Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md4Tests, FullBlock) {
    EXPECT_NO_THROW(m_hfun.update(m_tv1, m_tv1_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv1_exp);
}

TEST_F(Md4Tests, ThousandTimesSevenAs) {
    for (int i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update(m_tv2, m_tv2_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv2_exp);
}

TEST_F(Md4Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Md4Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
