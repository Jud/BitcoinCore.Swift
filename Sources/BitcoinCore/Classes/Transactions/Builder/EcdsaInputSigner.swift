import Foundation
import HsCryptoKit
import HsExtensions
import HdWalletKit

class EcdsaInputSigner {
    enum SignError: Error {
        case noPreviousOutput
        case noPreviousOutputAddress
        case noPrivateKey
    }

    let hdWallet: IPrivateHDWallet?
    let network: INetwork

    init(hdWallet: IPrivateHDWallet, network: INetwork) {
        self.hdWallet = hdWallet
        self.network = network
    }

    init(network: INetwork) {
        self.hdWallet = nil
        self.network = network
    }
}

extension EcdsaInputSigner: IInputSigner {

    func sigScriptData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> [Data] {
        let input = inputsToSign[index]
        let previousOutput = input.previousOutput
        let pubKey = input.previousOutputPublicKey
        let publicKey = pubKey.raw
        guard let wallet = self.hdWallet else {
            throw SignError.noPrivateKey
        }
        guard let privateKeyData = try? wallet.privateKeyData(account: pubKey.account, index: pubKey.index, external: pubKey.external) else {
            throw SignError.noPrivateKey
        }
        let witness = previousOutput.scriptType == .p2wpkh || previousOutput.scriptType == .p2wpkhSh

        var serializedTransaction = try TransactionSerializer.serializedForSignature(transaction: transaction, inputsToSign: inputsToSign, outputs: outputs, inputIndex: index, forked: witness || network.sigHash.forked)
        serializedTransaction += UInt32(network.sigHash.value)
        let signatureHash = Crypto.doubleSha256(serializedTransaction)
        let signature = try Crypto.sign(data: signatureHash, privateKey: privateKeyData) + Data([network.sigHash.value])

        switch previousOutput.scriptType {
        case .p2pk: return [signature]
        default: return [signature, publicKey]
        }
    }

    func sigScriptSignatureHash(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> Data {
        let input = inputsToSign[index]
        let previousOutput = input.previousOutput

        let witness = previousOutput.scriptType == .p2wpkh || previousOutput.scriptType == .p2wpkhSh

        var serializedTransaction = try TransactionSerializer.serializedForSignature(transaction: transaction, inputsToSign: inputsToSign, outputs: outputs, inputIndex: index, forked: witness || network.sigHash.forked)
        serializedTransaction += UInt32(network.sigHash.value)
        return Crypto.doubleSha256(serializedTransaction)
    }

    func sigScriptDataFromSignatureData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int, data: [Data]) throws -> [Data] {
        let input = inputsToSign[index]
        let previousOutput = input.previousOutput
        let pubKey = input.previousOutputPublicKey
        let publicKey = pubKey.raw

        let signature = data[index] + Data([network.sigHash.value])
        switch previousOutput.scriptType {
        case .p2pk: return [signature]
        default: return [signature, publicKey]
        }
    }
}
