#include <gtest/gtest.h>

#include <toycrypto/hash/sha3.h>

class Sha3_256Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA3_256 m_hfun{};

    const std::string m_empty_digest =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

    const std::string m_fox_digest =
        "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04";

    const std::array<std::string, 134> m_cmp = {
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "1c9ebd6caf02840a5b2b7f0fc870ec1db154886ae9fe621b822b14fd0bf513d6",
        "9b826ddf858be3bc8c8f71f6b87d1bf8a9694b2631fbd8d8d4f13847f58e5c3d",
        "7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa",
        "5ba7fe44cc7b13be0a25d2caccd80443c79835c38aa6945c714ab689d2f10c13",
        "6cf7fc321ff786cf4d13d445933461c34d5e1e726e0900dbfd91d5cd2aaccdf0",
        "3b8565782ee076502c7de9c735b48e847bc27a76de6a3b32dc5282f8bffaf336",
        "d410f00202335e808e822b286b8b3b4f524c58be45a411fbc1e9e7cf5c8ebc6c",
        "4709dc441eca0e976f5ad334fd7a0f412a0de09014c66c0ef329a3d5253f8776",
        "3d166a08b91bf567d9b4f06f18101bc389272d8978f3620ec4c897c1459446ac",
        "4b3a4680784c8cda6917e89ddde124c36df84e2aa08aebf4023d093338d7cc34",
        "56b51deddcacd92f85cc32bbbb877fd1c3638dc1ee9d539edad4aa321bfeb850",
        "59415113e392392d4f9d0649831fce9dc2effc068c5fd98001bc1720e32c097e",
        "1a6a38219fa8f0e0b435e359b2c740646df54913343d31f8abffdca1dc764e88",
        "3c240dd739e7401121926263da5529d15f03ccbb40a441ae14c92f5c4a2df9f9",
        "8dbb26ccf3c85b5d04ea3392ce8bc7b62722a7154a358aac0c13a48be74839f0",
        "24163aabfd8d149f6e1ad9e7472ff2ace7d79295e4baf3d92b7efea4848be250",
        "f31cad9c4488b69f66e9670181ab7b822ce5ca5ef74ba12ef6909bac37fe9acf",
        "95cd1e9081ff7ad4b0de02ae6e3de144a827f56759e5ab81e4c88411364600d0",
        "e449a742d3c9d28e833dc15428510a5598598a5a093c0c17b402a84442e4e4ee",
        "fb8433e7d085eed59206ac3fdbf6daea9289565e2ed95519bfadc4a9da96abfd",
        "1967ecf33884a5b7ca9186a7dbc25c82c06647440696fbf7be83062b6eddc1c8",
        "5b35958d2bb00876532c97c74e3ee8cece9c39acb84f4518bec9582c629b0b0a",
        "b6c5a39d857b18195e1fb5708513c5d997b017fdb1f7687a22bc31e97e1e9fd5",
        "4d2fcc922b3b387212bbf77399a52c64a020429b41fc0c4f56cb79920375d61f",
        "4133c435442d15bef52810d22281e8c924d0aa32ee04ce52733097a670f64003",
        "e19b6410d0244a0c8f7d9f7909936f0650a7c934dd7c5a168d16f10c9fd7abe0",
        "b4dfad7e28a55f145a3ffd7fea2e49c5f3c539a2942c40bf29413b65831615c0",
        "23009443e6f5855f010a97e9dec6eec225b47863d7cf4f93b8fe3b20b118e53c",
        "4503e8b95ac6e7ab9d12019d05ea48d3c6c6b7b35dd538acf2b16d89830cd0cc",
        "b96a8fdf64f443213af404d80c25f8e8685e40fe09647b6c1d5d07e86d36375f",
        "c877315fa8c92002a6ba4087c09e8ef48585e0bd1cd7b661fec4e3107146be1b",
        "49c5bc13ba9bda2424de21409098e3f100c6e573b0a12f91f69d92ae19c85d68",
        "00df6eb7027cdbb023ef0e86b11db480e12382bac30a96070155d6b6acc0fa1e",
        "454fbcb8df17a87862ce4514e2a02dbacd565ed3623554fdb58835fdb2306b34",
        "5cc14716b45d2b07a71e3fd44ab577c81f966131f2ae1513196d41c0d73e7dbe",
        "642142dd79337caa018961d853bb2d88aad20a57d45926d699bf679a2c2166ba",
        "7c927d0e816ffc166164a14cfcb3c0fa65d797343042d17b79972ecdbcf00369",
        "6c19ca34ce01e4df44c86f3412066513d473ee716900eebe9762a280812dc476",
        "4a0753954485a73992fd26377cd1805c8198df5398f7b098ffae60e78b1d55fa",
        "66d3141d93d08278181c1dad007ed15f30008ea305219b4acbf0a87a905f86cd",
        "862588d27fee59234c570191232d781ac90945cdec403d78104572f432392191",
        "ffe2d0c9450196794e1d088c940833d493e215b84e5da83a2fe9ee37ea31537f",
        "fa8457c2de7b1923038719e71c1100d54474c72c913424b05fb5370558c1572f",
        "e7ce2cb14b9bad42c12e103bddb70bbb9962f42b8e49687224323c9e343e6512",
        "cf9e530f1167e909259046a0f179c49f3dce526947253209cda85e4873a2d0be",
        "5bf7dce009bbb3e7ece77109e318e85da14184bc4abd0e3f9d77917741bbab49",
        "7475967636d12cca97db1894de75e9fffb17f4256cd1e6195c991d796df4de06",
        "704aafc63519d894cc0a51db964524afb04d4c726bf0e29f69b822de56f5ac57",
        "db38cc85c1bdc8fba91771badd861a09c531de450a5de4669cbdf7dae80e8c0b",
        "719f372dbb621d74635a3f056a67e76db8a308b46551596ce21d8ca37444ace3",
        "0bae91d593c6c1e817ae8417ec08974e259b2ed2aa01725b1d8b0a844cf1d905",
        "7a6eda86a7ca02ab055ecf5e8b9b23a29d125961ba172399ace1a3cc175a4de4",
        "2f7e9eb29338121c973ebddd6f1432a827f9f6fcadd1181c8395b4da0dd25b0f",
        "365e186a77972d4ca48ee4292f8a6e1a2ea8db9325c628c977cba7ab0083e5a2",
        "0a077e39df923427c3549242fb2a4b48c21bb88cb958951dd2e433f7f9209f47",
        "c73bd195e03e963f4cdd8b93744f97ff9e80c77cc428a5ba5b938fc694fd966b",
        "4d64ae882e7459130df2901f7b936458ec38a2b5d649cfec2f3e56ec4bd003d2",
        "6987cdabf375e242c0b4e1aaa13b8c8d197ce5cb40bb0f93940323f992c4657e",
        "d72fdac924699e571221b542cdd7b832ed573789f48bba5f692a63d633238007",
        "7d3d4b0a984cc644d7c12be2cdced1ef09a952c5f693186ee2256619a9e5fc86",
        "348e4c58c2fd779ecddb75cef1e63f9260572e32451c12da62d077e3851aec9a",
        "8259840c1b85729d719ba8ab37f7218d44a663da46204d528ba43f155c8b6b6a",
        "7eb92800284d0bc0d1caa6a1062209b1348ae32b718668cbcfcb6de752b0bc32",
        "bdebce96df8897e1e69e82fb75d1c2c6ef28fc4aafdedab73acb4f1803ee2b5f",
        "c907fcab42ee8a6ce9c8cc9eeed46112ec49aba4c1c95457201ef13248159660",
        "8ebda7709b99f83e2d25d05fa3b04363fa1b1e73aba12b3c9b8a1d3f6acd0548",
        "1da014387e5a7c28019a218afe67c062de9e4d3c146abe02069a5a50a3cb573b",
        "e6dbec9a70eff81b7c3dd4cc7d72e921c0371bfe6e40040d779626ffba64a1fd",
        "c2206abfb78d139542c53b2a259991ab21959206c678d47a37239ceb94ff7e91",
        "73409d2783e4714c9a62a3dac41a948c2a93f904eb190523626ff5404996791b",
        "66b0598dd27d8f38e00b7e83b80512cf4cbeb7b7d98fe1735a167b39555f8e5a",
        "f57975638bcffdb4a85d3d33be1df18ae081e36f9d48daeae614608a8b91b2e9",
        "ef501fac91d3c52722651bc1dc839a50d0d08c8ccd1687fb241bfafc2f7381a4",
        "c1d27411d05385f09cf784303ea8b75fc4a903d8831840506e208e056a0716f3",
        "a7a6fc3aba558ba0c64cec47bf7705a675361ca53337c6c81c868b76b2cea2f7",
        "ffa0cd76bccb722d8429bc7c8634cddf23750ad2eb3383dcdc3e94477f506ebd",
        "4ae35d3c7168692e8bc3034a241ff33c76eed3e492ea5625e65da73faac58004",
        "3444a927b2672e1045615c4623fa07b64a083a23f5202cfeb8e75b60ba5acdaa",
        "2d50e4bf07dd2099fff647ce05d928b8549bb42d0da88d51959a6e98ca4bbaa9",
        "bf088287e2d30ac64ae7133f57ea1280338090ded9f425cc69fa2d52f280a6fd",
        "c1a8e75d9bb7056c4ac1ec8540ef5c61451e5f933db52ad763ed1fa840a44fac",
        "1fdb5c20e9d54f60e2ed7e346fffabdab37ad2d5e99178dfd9e3e9f8acebfcbc",
        "0612e3d1d72b0eae00003c42bd3b9df6119f7cd85ecc011372c6180ca77a55a5",
        "1bf7cba562fafb6e6f5acff8b7251f9911527cd68775b2169439e3cde7f5a7fb",
        "9c6a32a1144606862d8f930f10434c7de55b06bb3e33c0ea42b5a042eec7bd4c",
        "a3993e62e2d6c3d65fe6492924f096e35f65d9f98205de585fadb971ed2be6eb",
        "51f61ca48207dc76301f919f0beaacb37e0f76171ed0a73b6c8c2f8e1d07d537",
        "877bde60c534acf824e18439eb139857bcc45e50b1ff4ab7d6b5deec4d7496ae",
        "58e29f680b633b41d2932c52c3af0cc51e125633f0fb26d5101e748e3c655c7d",
        "6e9a7925317a484a541255e61870428e491936dac3938cbb257a39921f6449d2",
        "db230c9da9b800b5859d3820732818efccee157c9d5b611fe93252ec32268341",
        "ec2d7ffbe62e6a17dcc74324cf5112fc540990f7dae74e688ecaca8b9a2319ed",
        "863d0640922af437837f4c582e20b33d2c69d047a9021e8199505ec15ac927d0",
        "25729cbfe1de5810d80feb9363cff13c0ffd97a4875e10ec83274ed74255dd1e",
        "d3cd781d79f6e0defc798d1f3be3b3a8f167b242569310e8e5cb1b05f6260509",
        "e801b0da7108e010e6b689822ee35a5fbaaf5a7d943db97bc8ce18a9b9854ca0",
        "02c78717c6af3a13f85dfdb72feeae1ee6f84734849a88eeeb90110f449581ab",
        "81153875a7f32e0a3767ec02d2f259d85e6702a8d6ab0e495483d4559d5235c9",
        "8ce0ae2ab36c63af1618ebb7ecfccf4f69271866c2ff247d9c3c840b4c2077e6",
        "9cdcb647b891b911d3e9d846b5ddf96134900d320e050a82c62d64d9384794d7",
        "fa2c9434a284d6083bc800aea50bd332c414bd0c4d160b30dfa23d6b9fa04bab",
        "eacd13e49344f6d649df6096d3e3160ba97f6fcc714f75997147ab9f3415bcad",
        "50339b5dffbd29f0caea43fc96b2610226d1e0016f1aab4b11243836cc40500f",
        "7c03e4804713737bea06bd3ea10db9a95ac227ca31ff8956877e318eb5950a3d",
        "27326940db366d1f907640e48748ac6a3bd122cc4c74dfb344c01f01b68f7f12",
        "3571e49a58799ec8e2e3fda225b2a818149c1f7565cb35f0f509b5c30dfdbf3e",
        "f204ab388fa8356d424f2842926fc2be09d1dd7beff36fd3f28ac1084fb361fb",
        "99c65a777d5fb27f095cadf736b7f68e95be6425cec5d1c41dd666eeacd326d8",
        "7ee5c538c94821a9ff596e0cc63ba686149342c3da897bfce2778ef8e5c5d522",
        "d04944415a63a210285eb34111a5ee851a204a3d589897c9a07e14fa172d01c9",
        "3a52e0467e27cc4d7e6360a6dfbefa5e500f59d1ff133124c5ac43009466a8ba",
        "85bd0e34cf551cf96fc8b76d245ba271b55acc5f765456384c30f14e19afdeec",
        "4c5903118a5a70b448377579655603a212881c4931a711bdded5cd22dee0d6df",
        "963a2b0dd37c2d71624809d151c987cc3c7dfc7d57134a8933d4d52a8f23922d",
        "bb2148f03c43cded26d0bd9b72a18db87b6026c573af59378de8845d61bda5fc",
        "ac6a87fb2db78cd6813ea5f4d200c23724eccfef91004d604096ed265989f47e",
        "d3cbd818870eb8981739612e457342777c2b089162ba4313b6ef08798d69c382",
        "f186f337d46cd997f6beea97af6693cacc19425e3681674a4570d88e294db41f",
        "9821bbc03c3acc2aa2e296e5a034333d01f83b9dafb9bfaddfceea738b875c24",
        "7d1e3b4182d8f50d671a9037c377b2994286aa7ee5646765a325b13f68b38c05",
        "00b966240665a1f2f2595ae560b6e7562f54a2a1a0273dc65f0d8846783c1195",
        "e858d31ca8e301bf5f8db390e00525bc4c1e49167efb2620be2de1d13136b77c",
        "600d01b79826d192abf6a3bb04a070a602ba2afa87a518fa496c212c7f7acd81",
        "c168d101304c426cc8d991404fcdf649d57ba22e705010b7fff20624a1cad60f",
        "840786532ff633c0894df5e055de753d549ad24c7d55debb37aba69684e567bd",
        "61515b1ce46896ba125df84fb75a65e615252b11356b7876b49b54b041055a6b",
        "2f0721eb90228f69067bd06e0fda2a62253be252eb0402795ac6d6ad333c3a74",
        "8e16409d3e50bfec26054694e0c2f3bd2b230bf5dc53c06c942a8f0167539f71",
        "8e4cbdccaf81a792c6981ef9dea025f7775f1d33db62465ab5972ee39c7c1be3",
        "70781fd34584d5e9192bb19c94d2f4b606ec1784c2e1269022ef866475effa36",
        "3348b87640b35207bd06b9da8d07017172d36bb87a90e98f31c9d0413d4efbd4",
        "9523126cc00bb46cec45788c13dc99dd23f5db785dd9cbfb4a0adb6ffdce472c",
        "9bf068f315c4e5335394e54e834994af3d6c9a4c7eaa8bd1e65b84de43856053"
    };

    const std::string m_7000 =
        "5abf5f9f8b24dbea10f09f08df90fbbc67e5c511ba2dc83e930ae243be5b438c";
};

TEST_F(Sha3_256Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha3_256Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha3_256Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha3_256Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha3_256Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Sha3_256Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Sha3_256Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha3_256Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
