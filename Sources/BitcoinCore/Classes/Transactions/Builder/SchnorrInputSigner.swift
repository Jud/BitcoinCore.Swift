import Foundation
import HdWalletKit
import HsCryptoKit
import HsExtensions

class SchnorrInputSigner {
    enum SignError: Error {
        case noPreviousOutput
        case noPreviousOutputAddress
        case noPrivateKey
    }

    let hdWallet: IPrivateHDWallet?
    let network: INetwork

    init(hdWallet: IPrivateHDWallet) {
        self.hdWallet = hdWallet
    }

    init(network: INetwork) {
        self.hdWallet = nil
        self.network = network
    }
}

extension SchnorrInputSigner: IInputSigner {
    func sigScriptData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> [Data] {
        let input = inputsToSign[index]
        let pubKey = input.previousOutputPublicKey

        guard let privateKeyData = try? hdWallet!.privateKeyData(account: pubKey.account, index: pubKey.index, external: pubKey.external) else {
            throw SignError.noPrivateKey
        }

        let serializedTransaction = try TransactionSerializer.serializedForTaprootSignature(transaction: transaction, inputsToSign: inputsToSign, outputs: outputs, inputIndex: index)

        let signatureHash = try SchnorrHelper.hashTweak(data: serializedTransaction, tag: "TapSighash")
        let signature = try SchnorrHelper.sign(data: signatureHash, privateKey: privateKeyData, publicKey: pubKey.raw)

        return [signature]
    }
}
