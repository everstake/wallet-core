// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "PublicKey.h"
#include "HexCoding.h"
#include "NEO/Address.h"
#include "NEO/Signer.h"
#include "proto/NEO.pb.h"

#include <gtest/gtest.h>

using namespace std;
using namespace TW;
using namespace TW::NEO;

TEST(NEOSigner, FromPublicPrivateKey) {
    auto hexPrvKey = "4646464646464646464646464646464646464646464646464646464646464646";
    auto hexPubKey = "031bec1250aa8f78275f99a6663688f31085848d0ed92f1203e447125f927b7486";
    auto signer = Signer(PrivateKey(parse_hex(hexPrvKey)));
    auto prvKey = signer.getPrivateKey();
    auto pubKey = signer.getPublicKey();

    EXPECT_EQ(hexPrvKey, hex(prvKey.bytes));
    EXPECT_EQ(hexPubKey, hex(pubKey.bytes));

    auto address = signer.getAddress();
    EXPECT_TRUE(Address::isValid(address.string()));

    EXPECT_EQ(Address(pubKey), address);
}

TEST(NEOSigner, SigningData) {
    auto signer = Signer(PrivateKey(parse_hex("4646464646464646464646464646464646464646464646464646464646464646")));
    auto verScript = "ba7908ddfe5a1177f2c9d3fa1d3dc71c9c289a3325b3bdd977e20c50136959ed02d1411efa5e8b897d970ef7e2325e6c0a3fdee4eb421223f0d86e455879a9ad";
    auto invocationScript = string("401642b3d538e138f34b32330e381a7fe3f5151fcf958f2030991e72e2e25043143e4a1ebd239634efba279c96fa0ab04a15aa15179d73a7ef5a886ac8a06af484401642b3d538e138f34b32330e381a7fe3f5151fcf958f2030991e72e2e25043143e4a1ebd239634efba279c96fa0ab04a15aa15179d73a7ef5a886ac8a06af484401642b3d538e138f34b32330e381a7fe3f5151fcf958f2030991e72e2e25043143e4a1ebd239634efba279c96fa0ab04a15aa15179d73a7ef5a886ac8a06af484");
    invocationScript = string(invocationScript.rbegin(), invocationScript.rend());

    EXPECT_EQ(verScript, hex(signer.sign(parse_hex(invocationScript))));
}

TEST(NEOAccount, validity) {
    auto hexPrvKey = "4646464646464646464646464646464646464646464646464646464646464646";
    auto hexPubKey = "031bec1250aa8f78275f99a6663688f31085848d0ed92f1203e447125f927b7486";
    auto signer = Signer(PrivateKey(parse_hex(hexPrvKey)));
    auto prvKey = signer.getPrivateKey();
    auto pubKey = signer.getPublicKey();
    EXPECT_EQ(hexPrvKey, hex(prvKey.bytes));
    EXPECT_EQ(hexPubKey, hex(pubKey.bytes));
}

TEST(NEOSigner, SigningTransaction) {
    auto signer = Signer(PrivateKey(parse_hex("F18B2F726000E86B4950EBEA7BFF151F69635951BC4A31C44F28EE6AF7AEC128")));
    auto transaction = Transaction();
    transaction.type = TransactionType::TT_ContractTransaction;
    transaction.version = 0x00;

    CoinReference coin;
    coin.prevHash = load(parse_hex("9c85b39cd5677e2bfd6bf8a711e8da93a2f1d172b2a52c6ca87757a4bccc24de")); //reverse hash
    coin.prevIndex = (uint16_t) 1;
    transaction.inInputs.push_back(coin);

    {
        TransactionOutput out;
        out.assetId = load(parse_hex("9b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc5"));
        out.value = (int64_t) 1 * 100000000;
        auto scriptHash = TW::NEO::Address("Ad9A1xPbuA5YBFr1XPznDwBwQzdckAjCev").toScriptHash();
        out.scriptHash = load(scriptHash);
        transaction.outputs.push_back(out);
    }

    {
        TransactionOutput out;
        out.assetId = load(parse_hex("9b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc5"));
        out.value = (int64_t) 892 * 100000000;
        auto scriptHash = TW::NEO::Address("AdtSLMBqACP4jv8tRWwyweXGpyGG46eMXV").toScriptHash();
        out.scriptHash = load(scriptHash);
        transaction.outputs.push_back(out);
    }
    signer.sign(transaction);
    auto signedTx = transaction.serialize();
    EXPECT_EQ(hex(signedTx), "800000019c85b39cd5677e2bfd6bf8a711e8da93a2f1d172b2a52c6ca87757a4bccc24de0100029b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500e1f50500000000ea610aa6db39bd8c8556c9569d94b5e5a5d0ad199b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500fcbbc414000000f2908c7efc0c9e43ffa7e79170ba37e501e1b4ac0141405046619c8e20e1fdeec92ce95f3019f6e7cc057294eb16b2d5e55c105bf32eb27e1fc01c1858576228f1fef8c0945a8ad69688e52a4ed19f5b85f5eff7e961d7232102a41c2aea8568864b106553729d32b1317ec463aa23e7a3521455d95992e17a7aac");
}

TEST(NEOSigner, BigTransactionSignAndPlan) {
    const string NEO_ASSET_ID = "9b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc5";
    const string GAS_ASSET_ID = "e72d286979ee6cb1b7e65dfddfb2e384100b8d148e7758de42e4168b71792c60";

    Proto::SigningInput input;
    auto privateKey = parse_hex("F18B2F726000E86B4950EBEA7BFF151F69635951BC4A31C44F28EE6AF7AEC128");
    input.set_private_key(privateKey.data(), privateKey.size());
    input.set_fee(12345); //too low
    input.set_gas_asset_id(GAS_ASSET_ID);
    input.set_gas_change_address("AdtSLMBqACP4jv8tRWwyweXGpyGG46eMXV");

#define ADD_UTXO_INPUT(hash, index , value, assetId) \
        { \
            auto utxo = input.add_inputs(); \
            utxo->set_prev_hash(hash); \
            utxo->set_prev_index(index); \
            utxo->set_asset_id(assetId); \
            utxo->set_value(value); \
        }

    ADD_UTXO_INPUT("c61508268c5d0343af1875c60e569493100824dbdba108b31789e0e33bcb50fb", 1, 98899890000, GAS_ASSET_ID);
    ADD_UTXO_INPUT("4eb2f96937a0d4dc96b77ba69a29e1de9574cbd62b16d881f1ee2061a291d70b", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("3fee0109d155dcfab272176117306b45b176914c88e8c379933c246a9e29ea0b", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("6ea9ce8c578bfeeecdf281f498e2a764689df3b93d6855a3cc45bd6b5213c426", 0, 400000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("f75ad3cbd277d83ee240e08f99a97ffd7e42a82a868e0f7043414f6d6147262b", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("054734e98f442b3e73a940ca8f594859ece1c7ddac14130b0e2f5e2799b85931", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("8b0c42d448912fc28c674fdcf8e21e4667d7d2133666168eaa0570488a9c5036", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 1, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 2, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 3, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 4, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 5, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 6, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 7, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 8, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 9, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("cf83bce600626b6077e136581c1aecc78a0bbb7d7649b1f580b6be881087ec40", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("9bd7572ba8df685e262369897d24f7217b42be496b9eed16e16a889dd83b394e", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("b4ee250397dde2f1001d782d3c803c38992447d3b351cdc9bf20cfaa2cbf995b", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("e1019ca259a1615f77263324156a70007b76cb4f26b01b2956b8f85e6842ac62", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("bd379df2aca526ac600919aaba0e59d4a1ad4e2f22d18966063cf45e431d016f", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("164c3f843b9b7bfa6a7376a1548f343acb5cdfa0193b8f31e8c9a647ea63ea7d", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("4acec74a76161eafe70e0791b1f504b5ba1d175fd4f340d5bf56804e25505e92", 0, 300000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("895c6629a71c84cbdc8956abea9ca2d9d215e909e6173b1a1a96289186a67796", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("54828143c4c3a0e1b09102e4ed29220b141089c2bc4200b1042eeb12e5e49296", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("5345e4abc86f7ace47112f5a91c129175833bafcaf9f1e1bcbbaf4d019c1c69d", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("c83e19d0d4210df97b3bc7768dc7184ae3acfc1b5b3ac9b05d2be0fe5a636b9f", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("3456b03f5cb688ce26ab1d09b7a15799136c8c886ca7c3c6bcb2363e61bb1bb1", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("048f73d6cc82d9d92b08044eccef66c78a0c22e836988ed25d6f7ffe24fb5b38", 10, 34000000000, NEO_ASSET_ID);
    // all inputs below must be unused in this tx
    ADD_UTXO_INPUT("e5a7887521b8b3aaf2d5426617ddabe8ef8ea3eab31c80a977c3b8f339df5be0", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("1455e9dd3cd6a04d81cd47acc07a7335212029ebbdcd0abc3e52c33f8b77f6eb", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("da711260085211b5573801d0dfe064235c69e61a55f9c15449ac55cc02b9adee", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("04486cfed371103dd51a89205b2c8bcc45ad887c49a768a62465f35810437bef", 0, 500000000, NEO_ASSET_ID);
    ADD_UTXO_INPUT("a5f27055a442db0e65103561900456d37af4233267960daded870c1ab2219ef4", 0, 500000000, NEO_ASSET_ID);

    {
        auto output = input.add_outputs();
        output->set_asset_id(NEO_ASSET_ID);
        output->set_to_address("Ad9A1xPbuA5YBFr1XPznDwBwQzdckAjCev");
        output->set_change_address("AdtSLMBqACP4jv8tRWwyweXGpyGG46eMXV");
        output->set_amount(25000000000);
    }

#define mylog(val) { \
                FILE* f = fopen("/home/s/my.log", "a"); \
                fseek ( f , 0 , SEEK_END ); \
                fwrite(val, strlen(val), 1, f); \
                fwrite("\n", 1, 1, f); \
                fclose(f); \
            }

    auto plan = Signer::planTransaction(input);
    auto output = Signer::sign(input, plan);

    mylog(hex(output.encoded()).c_str());

    ASSERT_EQ(hex(output.encoded()), "dfgdfgdf");;
}