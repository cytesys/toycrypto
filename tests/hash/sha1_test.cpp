#include <gtest/gtest.h>

#include <toycrypto/hash/sha1.h>

class Sha1Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA1 m_hfun{};

    const std::string m_empty_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const std::string m_fox_digest = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    static const size_t m_tv1_len = 65;
    const char m_tv1[m_tv1_len] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const std::string m_tv1_exp = "30b86e44e6001403827a62c58b08893e77cf121f";

    static const size_t m_tv2_len = 8;
    const char m_tv2[m_tv2_len] = "AAAAAAA";
    const std::string m_tv2_exp = "81b8d15acb6da00ba00cc493805e023f3ff6b981";
};

TEST_F(Sha1Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha1Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha1Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha1Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha1Tests, FullBlock) {
    EXPECT_NO_THROW(m_hfun.update(m_tv1, m_tv1_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv1_exp);
}

TEST_F(Sha1Tests, ThousandTimesSevenAs) {
    for (int i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update(m_tv2, m_tv2_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv2_exp);
}

TEST_F(Sha1Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha1Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
