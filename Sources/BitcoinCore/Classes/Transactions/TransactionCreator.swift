import Foundation

class TransactionCreator {
    enum CreationError: Error {
        case transactionAlreadyExists
    }

    private let transactionBuilder: ITransactionBuilder
    private let transactionProcessor: IPendingTransactionProcessor
    private let transactionSender: ITransactionSender
    private let transactionSigner: TransactionSigner
    private let bloomFilterManager: IBloomFilterManager

    init(transactionBuilder: ITransactionBuilder, transactionProcessor: IPendingTransactionProcessor, transactionSender: ITransactionSender, transactionSigner: TransactionSigner, bloomFilterManager: IBloomFilterManager) {
        self.transactionBuilder = transactionBuilder
        self.transactionProcessor = transactionProcessor
        self.transactionSender = transactionSender
        self.transactionSigner = transactionSigner
        self.bloomFilterManager = bloomFilterManager
    }

    private func processAndSend(transaction: FullTransaction) throws {
        try transactionSender.verifyCanSend()

        do {
            try transactionProcessor.processCreated(transaction: transaction)
        } catch _ as BloomFilterManager.BloomFilterExpired {
            bloomFilterManager.regenerateBloomFilter()
        }

        transactionSender.send(pendingTransaction: transaction)
    }
}

extension TransactionCreator: ITransactionCreator {
    func build(to address: String, memo: String?, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, rbfEnabled: Bool, unspentOutputs: [UnspentOutput]?, pluginData: [UInt8: IPluginData] = [:]) throws -> (MutableTransaction, [Data]) {
        return try transactionBuilder.buildUnsignedMutableTransaction(
                toAddress: address,
                memo: memo,
                value: value,
                feeRate: feeRate,
                senderPay: senderPay,
                sortType: sortType,
                rbfEnabled: rbfEnabled,
                unspentOutputs: unspentOutputs,
                pluginData: pluginData
        )
    }
    
    func finalize(tx: MutableTransaction, data: [Data]) throws -> FullTransaction {
        let transaction = try transactionBuilder.finalizeTransaction(tx: tx, data: data)
        
        try processAndSend(transaction: transaction)
        return transaction
    }
    
    func create(to address: String, memo: String?, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, rbfEnabled: Bool, unspentOutputs: [UnspentOutput]?, pluginData: [UInt8: IPluginData] = [:]) throws -> FullTransaction {
        let mutableTransaction = try transactionBuilder.buildTransaction(
            toAddress: address,
            memo: memo,
            value: value,
            feeRate: feeRate,
            senderPay: senderPay,
            sortType: sortType,
            rbfEnabled: rbfEnabled,
            unspentOutputs: unspentOutputs,
            pluginData: pluginData
        )

        return try create(from: mutableTransaction)
    }

    func create(from unspentOutput: UnspentOutput, to address: String, memo: String?, feeRate: Int, sortType: TransactionDataSortType, rbfEnabled: Bool) throws -> FullTransaction {
        let mutableTransaction = try transactionBuilder.buildTransaction(
            from: unspentOutput,
            toAddress: address,
            memo: memo,
            feeRate: feeRate,
            sortType: sortType,
            rbfEnabled: rbfEnabled
        )

        return try create(from: mutableTransaction)
    }

    func create(from mutableTransaction: MutableTransaction) throws -> FullTransaction {
        try transactionSigner.sign(mutableTransaction: mutableTransaction)
        let fullTransaction = mutableTransaction.build()

        try processAndSend(transaction: fullTransaction)
        return fullTransaction
    }

    func createRawTransaction(to address: String, memo: String?, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, rbfEnabled: Bool, unspentOutputs: [UnspentOutput]?, pluginData: [UInt8: IPluginData] = [:]) throws -> Data {
        let mutableTransaction = try transactionBuilder.buildTransaction(
            toAddress: address,
            memo: memo,
            value: value,
            feeRate: feeRate,
            senderPay: senderPay,
            sortType: sortType,
            rbfEnabled: rbfEnabled,
            unspentOutputs: unspentOutputs,
            pluginData: pluginData
        )
        try transactionSigner.sign(mutableTransaction: mutableTransaction)
        let fullTransaction = mutableTransaction.build()

        return TransactionSerializer.serialize(transaction: fullTransaction)
    }
}
