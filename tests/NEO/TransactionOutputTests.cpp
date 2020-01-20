// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "UInt.h"
#include "HexCoding.h"
#include "NEO/TransactionOutput.h"

#include <iostream>
#include <gtest/gtest.h>

using namespace std;
using namespace TW;
using namespace TW::NEO;

TEST(NEOTransactionOutput, Serialize) {
    auto transactionOutput = TransactionOutput();
    string assetId = "bdecbb623eee6f9ade28d5a8ff5fb3ea9c9d73af039e0286201b3b0291fb4d4a";
    string scriptHash = "cbb23e6f9ade28d5a8ff3eac9d73af039e821b1b";
    transactionOutput.value = 1L;
    transactionOutput.assetId = load<uint256_t>(parse_hex(assetId));
    transactionOutput.scriptHash = load<uint160_t>(parse_hex(scriptHash));
    EXPECT_EQ(assetId + "0100000000000000" + scriptHash, hex(transactionOutput.serialize()));

    transactionOutput.value = 0xff01;
    EXPECT_EQ(assetId + "01ff000000000000" + scriptHash, hex(transactionOutput.serialize()));
}

TEST(NEOTransactionOutput, Deserialize) {
    string assetId = "bdecbb623eee6f9ade28d5a8ff5fb3ea9c9d73af039e0286201b3b0291fb4d4a";
    string scriptHash = "cbb23e6f9ade28d5a8ff3eac9d73af039e821b1b";
    auto transactionOutput = TransactionOutput();
    transactionOutput.deserialize(parse_hex(assetId + "0100000000000000" + scriptHash));
    EXPECT_EQ(1, transactionOutput.value);
    EXPECT_EQ(assetId, hex(store(transactionOutput.assetId)));
    EXPECT_EQ(scriptHash, hex(store(transactionOutput.scriptHash)));

    transactionOutput.deserialize(parse_hex(assetId + "01ff000000000000" + scriptHash));
    EXPECT_EQ(0xff01, transactionOutput.value);
    EXPECT_EQ(assetId, hex(store(transactionOutput.assetId)));
    EXPECT_EQ(scriptHash, hex(store(transactionOutput.scriptHash)));
}