// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "../Hash.h"
#include "../PublicKey.h"
#include "../PrivateKey.h"
#include "Script.h"
#include "Signer.h"
#include "../HexCoding.h"

using namespace TW;
using namespace TW::NEO;

Signer::Signer(const PrivateKey &priKey)
    : privateKey(std::move(priKey)) {
    auto pub = privateKey.getPublicKey(TWPublicKeyTypeNIST256p1);
    publicKey = pub.bytes;
    address = Address(pub);
}

PrivateKey Signer::getPrivateKey() const {
    return privateKey;
}

TW::PublicKey Signer::getPublicKey() const {
    return TW::PublicKey(publicKey, TWPublicKeyTypeNIST256p1);
}

Address Signer::getAddress() const {
    return address;
}

void Signer::sign(Transaction &tx) const {
    auto unsignedTx = tx.serialize();
    auto signature = sign(unsignedTx);
    tx.witnesses.clear();
    Witness witness;
    witness.invocationScript = Script::CreateInvocationScript(signature);
    witness.verificationScript = Script::CreateSignatureRedeemScript(publicKey);
    tx.witnesses.push_back(witness);
}

Data Signer::sign(const Data &data) const {
    auto signature = getPrivateKey().sign(TW::Hash::sha256(data), TWCurveNIST256p1);
    signature.pop_back();
    return signature;
}


Proto::TransactionPlan Signer::planTransaction(const Proto::SigningInput& input) {
    Proto::TransactionPlan plan;

    return plan;
}

Transaction Signer::prepareUnsignedTransaction(const Proto::SigningInput &input, const Proto::TransactionPlan& plan) {
    try {
        auto transaction = Transaction();
        transaction.type = TransactionType::TT_ContractTransaction;
        transaction.version = 0;

        for (int i = 0; i < plan.inputs_size(); i++) {
            CoinReference coin;
            Data prevHashReverse(plan.inputs(i).prev_hash().begin(), plan.inputs(i).prev_hash().end());
            std::reverse(prevHashReverse.begin(), prevHashReverse.end());
            coin.prevHash = load(prevHashReverse);
            coin.prevIndex = (uint16_t)plan.inputs(i).prev_index();
            transaction.inInputs.push_back(coin);
        }

        for (int i = 0; i < plan.outputs_size(); i++) {
            if (plan.outputs(i).asset_id() == input.gas_asset_id()) {
                if (plan.outputs(i).amount() + plan.outputs(i).change() + plan.fee()
                    != plan.outputs(i).available_amount())
                    throw "Wrong fee";
            }

            { // to recipient
                TransactionOutput out;
                out.assetId = load(parse_hex(plan.outputs(i).asset_id()));
                out.value = (int64_t) plan.outputs(i).amount();
                auto scriptHash = TW::NEO::Address(plan.outputs(i).to_address()).toScriptHash();
                out.scriptHash = load(scriptHash);
                transaction.outputs.push_back(out);
            }

            // change
            if (plan.outputs(i).change() > 0) {
                TransactionOutput out;
                out.assetId = load(parse_hex(plan.outputs(i).asset_id()));
                out.value = plan.outputs(i).change();
                auto scriptHash = TW::NEO::Address(plan.outputs(i).change_address()).toScriptHash();
                out.scriptHash = load(scriptHash);
                transaction.outputs.push_back(out);
            }
        }
        return transaction;
    } catch (...) {
    }

    return Transaction();
}

Proto::SigningOutput Signer::sign(const Proto::SigningInput &input, const Proto::TransactionPlan& plan) {
    auto output = Proto::SigningOutput();
    try {
        auto signer = Signer(PrivateKey(Data(input.private_key().begin(), input.private_key().end())));
        auto transaction = prepareUnsignedTransaction(input, plan);
        signer.sign(transaction);
        auto signedTx = transaction.serialize();

        output.set_encoded(signedTx.data(), signedTx.size());
    } catch (...) {
    }

    return output;
}