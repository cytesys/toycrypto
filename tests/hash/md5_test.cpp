#include <gtest/gtest.h>

#include <toycrypto/hash/md5.h>

class Md5Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    MD5 m_hfun{};

    const std::string m_empty_digest = "d41d8cd98f00b204e9800998ecf8427e";
    const std::string m_fox_digest = "9e107d9d372bb6826bd81d3542a419d6";

    static const size_t m_tv1_len = 65;
    const char m_tv1[m_tv1_len] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const std::string m_tv1_exp = "d289a97565bc2d27ac8b8545a5ddba45";

    static const size_t m_tv2_len = 8;
    const char m_tv2[m_tv2_len] = "AAAAAAA";
    const std::string m_tv2_exp = "44c1c8802177da9b3edbddd7c1ec44e2";
};

TEST_F(Md5Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md5Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md5Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md5Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md5Tests, FullBlock) {
    EXPECT_NO_THROW(m_hfun.update(m_tv1, m_tv1_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv1_exp);
}

TEST_F(Md5Tests, ThousandTimesSevenAs) {
    for (int i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update(m_tv2, m_tv2_len - 1));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_tv2_exp);
}

TEST_F(Md5Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Md5Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
