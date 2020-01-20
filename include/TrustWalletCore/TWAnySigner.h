// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "TWBase.h"
#include "TWAnyProto.h"
#include "TWCoinType.h"

TW_EXTERN_C_BEGIN

TW_EXPORT_CLASS
struct TWAnySigner;

/// Signs a transaction.
TW_EXPORT_STATIC_METHOD
TW_Any_Proto_SigningOutput TWAnySignerSign(TW_Any_Proto_SigningInput input);

TW_EXPORT_STATIC_METHOD
bool TWAnySignerIsSignEnabled(enum TWCoinType coinType);

TW_EXTERN_C_END
