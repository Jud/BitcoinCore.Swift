import Foundation
class TransactionBuilder {
    private let recipientSetter: IRecipientSetter
    private let inputSetter: IInputSetter
    private let lockTimeSetter: ILockTimeSetter
    private let outputSetter: IOutputSetter
    private let signer: TransactionSigner?

    init(recipientSetter: IRecipientSetter, inputSetter: IInputSetter, lockTimeSetter: ILockTimeSetter, outputSetter: IOutputSetter) {
        self.recipientSetter = recipientSetter
        self.inputSetter = inputSetter
        self.lockTimeSetter = lockTimeSetter
        self.outputSetter = outputSetter
        self.signer = nil
    }

    init(recipientSetter: IRecipientSetter, inputSetter: IInputSetter, lockTimeSetter: ILockTimeSetter, outputSetter: IOutputSetter, signer: TransactionSigner) {
        self.recipientSetter = recipientSetter
        self.inputSetter = inputSetter
        self.lockTimeSetter = lockTimeSetter
        self.outputSetter = outputSetter
        self.signer = signer
    }
}

extension TransactionBuilder: ITransactionBuilder {
    func buildTransaction(toAddress: String, memo: String?, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, rbfEnabled: Bool, unspentOutputs: [UnspentOutput]?, pluginData: [UInt8: IPluginData]) throws -> MutableTransaction {
        let mutableTransaction = MutableTransaction()

        try recipientSetter.setRecipient(to: mutableTransaction, toAddress: toAddress, memo: memo, value: value, pluginData: pluginData, skipChecks: false)
        try inputSetter.setInputs(to: mutableTransaction, feeRate: feeRate, senderPay: senderPay, unspentOutputs: unspentOutputs, sortType: sortType, rbfEnabled: rbfEnabled)
        lockTimeSetter.setLockTime(to: mutableTransaction)

        outputSetter.setOutputs(to: mutableTransaction, sortType: sortType)

        return mutableTransaction
    }

    func buildUnsignedMutableTransaction(toAddress: String, memo: String?, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, rbfEnabled: Bool, unspentOutputs: [UnspentOutput]?, pluginData: [UInt8: IPluginData]) throws -> (MutableTransaction, [Data]) {
        let mutableTransaction = MutableTransaction()

        try recipientSetter.setRecipient(to: mutableTransaction, toAddress: toAddress, memo: memo, value: value, pluginData: pluginData, skipChecks: false)
        try inputSetter.setInputs(to: mutableTransaction, feeRate: feeRate, senderPay: senderPay, unspentOutputs: unspentOutputs, sortType: sortType, rbfEnabled: rbfEnabled)
        lockTimeSetter.setLockTime(to: mutableTransaction)

        outputSetter.setOutputs(to: mutableTransaction, sortType: sortType)

        return (mutableTransaction, try signer!.dataToSign(mutableTransaction: mutableTransaction))
    }
    
    func finalizeTransaction(tx: MutableTransaction, data: [Data]) throws -> FullTransaction {
        try signer!.signWithSignatureData(mutableTransaction: tx, data: data)
        return tx.build()
    }

    func buildTransaction(from unspentOutput: UnspentOutput, toAddress: String, memo: String?, feeRate: Int, sortType: TransactionDataSortType, rbfEnabled: Bool) throws -> MutableTransaction {
        let mutableTransaction = MutableTransaction(outgoing: false)

        try recipientSetter.setRecipient(to: mutableTransaction, toAddress: toAddress, memo: memo, value: unspentOutput.output.value, pluginData: [:], skipChecks: false)
        try inputSetter.setInputs(to: mutableTransaction, fromUnspentOutput: unspentOutput, feeRate: feeRate, rbfEnabled: rbfEnabled)
        lockTimeSetter.setLockTime(to: mutableTransaction)

        outputSetter.setOutputs(to: mutableTransaction, sortType: sortType)

        return mutableTransaction
    }
}
