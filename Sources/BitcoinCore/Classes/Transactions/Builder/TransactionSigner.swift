import Foundation

class TransactionSigner {
    enum SignError: Error {
        case notSupportedScriptType
        case noRedeemScript
    }

    private let inputSigner: InputSigner

    init(inputSigner: InputSigner) {
        self.inputSigner = inputSigner
    }

    private func signatureScript(from sigScriptData: [Data]) -> Data {
        sigScriptData.reduce(Data()) {
            $0 + OpCode.push($1)
        }
    }

}

extension TransactionSigner: ITransactionSigner {

    func dataToSign(mutableTransaction: MutableTransaction) throws -> [Data] {
        var ret = [Data]()
        for (index, _) in mutableTransaction.inputsToSign.enumerated() {
            let sigHashData = try inputSigner.sigScriptSignatureHash(
                    transaction: mutableTransaction.transaction,
                    inputsToSign: mutableTransaction.inputsToSign,
                    outputs: mutableTransaction.outputs,
                    index: index
            )
            ret.append(sigHashData)
        }

        return ret
    }

    func sign(mutableTransaction: MutableTransaction) throws {
        for (index, inputToSign) in mutableTransaction.inputsToSign.enumerated() {
            let previousOutput = inputToSign.previousOutput
            let publicKey = inputToSign.previousOutputPublicKey

            var sigScriptData = try inputSigner.sigScriptData(
                    transaction: mutableTransaction.transaction,
                    inputsToSign: mutableTransaction.inputsToSign,
                    outputs: mutableTransaction.outputs,
                    index: index
            )

            switch previousOutput.scriptType {
            case .p2pkh:
                inputToSign.input.signatureScript = signatureScript(from: sigScriptData)
            case .p2wpkh:
                mutableTransaction.transaction.segWit = true
                inputToSign.input.witnessData = sigScriptData
            case .p2wpkhSh:
                mutableTransaction.transaction.segWit = true
                inputToSign.input.witnessData = sigScriptData
                inputToSign.input.signatureScript = OpCode.push(OpCode.scriptWPKH(publicKey.keyHash))
            case .p2sh:
                guard let redeemScript = previousOutput.redeemScript else {
                    throw SignError.noRedeemScript
                }

                if let signatureScriptFunction = previousOutput.signatureScriptFunction {
                    // non-standard P2SH signature script
                    inputToSign.input.signatureScript = signatureScriptFunction(sigScriptData)
                } else {
                    // standard (signature, publicKey, redeemScript) signature script
                    sigScriptData.append(redeemScript)
                    inputToSign.input.signatureScript = signatureScript(from: sigScriptData)
                }
            default: throw SignError.notSupportedScriptType
            }
        }
    }

}
