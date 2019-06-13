#pragma once

#include "ISerializable.h"
#include "../Data.h"

namespace TW::NEO {
    class Witness : public ISerializable {
    public:
        Data invocationScript;
        Data verificationScript;

        virtual ~Witness() {}

        int64_t size() const override {
            return invocationScript.size() + verificationScript.size();
        }

        void deserialize(const Data &data, int initial_pos = 0) override {
            invocationScript = readVarBytes(data, initial_pos);
            verificationScript = readVarBytes(data, initial_pos + 4 + int(invocationScript.size()));
        }

        Data serialize() const override {
            return concat(writeVarBytes(invocationScript), writeVarBytes(verificationScript));
        }

        bool operator==(const Witness &other) const {
            return this->invocationScript.size() == other.invocationScript.size()
                && this->verificationScript.size() == other.verificationScript.size()
                && this->invocationScript == other.invocationScript
                && this->verificationScript == other.verificationScript;
        }
    };
}