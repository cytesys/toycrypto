#include <gtest/gtest.h>

#include <toycrypto/hash/sha1.h>

class Sha1Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA1 m_hfun{};

    static const size_t m_buflen = 41;
    char m_buffer[m_buflen]{};

    const char m_empty_digest[m_buflen] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const char m_fox_digest[m_buflen] = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    static const size_t m_tv1_len = 65;
    const char m_tv1[m_tv1_len] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char m_tv1_exp[m_buflen] = "30b86e44e6001403827a62c58b08893e77cf121f";

    static const size_t m_tv2_len = 8;
    const char m_tv2[m_tv2_len] = "AAAAAAA";
    const char m_tv2_exp[m_buflen] = "81b8d15acb6da00ba00cc493805e023f3ff6b981";
};

TEST_F(Sha1Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_NO_THROW(m_hfun.hexdigest(m_buffer, m_buflen));
    EXPECT_STREQ(m_buffer, m_empty_digest);
}

TEST_F(Sha1Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_NO_THROW(m_hfun.hexdigest(m_buffer, m_buflen));
    EXPECT_STREQ(m_buffer, m_empty_digest);
}

TEST_F(Sha1Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_NO_THROW(m_hfun.hexdigest(m_buffer, m_buflen));
    EXPECT_STREQ(m_buffer, m_fox_digest);
}

TEST_F(Sha1Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_NO_THROW(m_hfun.hexdigest(m_buffer, m_buflen));
    EXPECT_STREQ(m_buffer, m_fox_digest);
}

TEST_F(Sha1Tests, FullBlock) {
    EXPECT_NO_THROW(m_hfun.update(m_tv1, m_tv1_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_NO_THROW(m_hfun.hexdigest(m_buffer, m_buflen));
    EXPECT_STREQ(m_buffer, m_tv1_exp);
}

TEST_F(Sha1Tests, ThousandTimesSevenAs) {
    for (int i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update(m_tv2, m_tv2_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_NO_THROW(m_hfun.hexdigest(m_buffer, m_buflen));
    EXPECT_STREQ(m_buffer, m_tv2_exp);
}

TEST_F(Sha1Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha1Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(m_buffer, m_buflen), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(m_buffer, m_buflen), std::invalid_argument);
}
