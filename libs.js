/*

    simple rating and raputation system for BCH

    version 0.1

    mtrycz

*/

import {BITBOX} from "bitbox-sdk";
let bitbox = new BITBOX()

var claimOpreturnVersion      = Buffer.from('0abcde1d', 'hex');
var transactOpreturnVersion   = Buffer.from('0abcde1e', 'hex');
var rateOpreturnVersion       = Buffer.from('0abcde1f', 'hex');

export function createWallet(seed) {
    seed = seed || bitbox.Mnemonic.fromEntropy(bitbox.Crypto.randomBytes(32));
    let seedBuffer = bitbox.Mnemonic.toSeed(seed)
    return bitbox.HDNode.fromSeed(seedBuffer);
}

export async function getAnUtxo(anAddress, minAmount) {
    minAmount = minAmount || 1000;
    let utxos = await bitbox.Address.utxo(anAddress);
    let utxo = utxos.utxos.find(u => u.satoshis >= 1000);
    if (utxo)
        return utxo;
    else
        throw "No suitable utxo for transaction. Send more funds.";
}

export async function claimAddress(wallet, network) {
    network = network || 'mainnet';
    var transactionBuilder = new bitbox.TransactionBuilder(network);
    let redeemScript;

    let cashAddress = bitbox.HDNode.toCashAddress(wallet);
    let address160  = bitbox.Address.cashToHash160(cashAddress);
    let messageBuffer = Buffer.from(address160, "hex");
    let signature   = bitbox.BitcoinCash.signMessageWithPrivKey(
        wallet.keyPair.toWIF(),
        address160
    );
    let contentBuffer =  Buffer.concat([
        claimOpreturnVersion,
        messageBuffer,
        Buffer.from(signature, 'base64')
    ]);

    console.log(signature);
    let opReturn = bitbox.Script.encode([
        bitbox.Script.opcodes.OP_RETURN,
        contentBuffer,
       ]);

    console.log(opReturn);
    var byteCount = bitbox.BitcoinCash.getByteCount({ P2PKH: 1 }, { P2PKH: 1 });
    byteCount += contentBuffer.length;
    byteCount += signature.length;
    byteCount += 9 // some spare bytes for OP_RETURN etc. 
    
    var utxo = await getAnUtxo(cashAddress);
    transactionBuilder.addInput(utxo.txid, utxo.vout);
    transactionBuilder.addOutput(cashAddress, utxo.satoshis - byteCount);
    transactionBuilder.addOutput(opReturn, 0);
    transactionBuilder.setLockTime(0);
    transactionBuilder.sign(0, wallet.keyPair, redeemScript, transactionBuilder.hashTypes.SIGHASH_ALL, utxo.satoshis, transactionBuilder.signatureAlgorithms.SCHNORR)

    var tx = transactionBuilder.build();
    var hex = tx.toHex();
    console.log("Sending tx from "+ utxo.txid +" with op_return "+ claimOpreturnVersion + messageBuffer.toString() + signature + " contentBuffer length "+ contentBuffer.length)
    let txid = await bitbox.RawTransactions.sendRawTransaction(hex);
    console.log(txid);
    return txid;
}

export async function getClaimDetails(transactionId) {
    var transaction = await bitbox.Transaction.details(transactionId);
    var opReturnOutput = transaction.vout.find(function(out) {return out.scriptPubKey.addresses === undefined;});
    var message = opReturnOutput.scriptPubKey.asm;

    let result = {};
    result.version     = message.substring(10, 18);
    result.versionValid= result.version === '0abcde1d';
    result.address160  = message.substring(18, 58);
    result.address     = bitbox.Address.hash160ToCash(result.address160);
    result.signature   = Buffer.from(message.substring(58), 'hex').toString('base64');

    result.signatureValid = bitbox.BitcoinCash.verifyMessage(
        result.address,
        result.signature,
        result.address160
    );

    return result;
}

export async function transact(fromWallet, toWallet, amount, network) {
    network = network || 'mainnet';
    var transactionBuilder = new bitbox.TransactionBuilder(network);
    let redeemScript;

    let cashAddress1 = bitbox.HDNode.toCashAddress(fromWallet);
    let cashAddress2 = bitbox.HDNode.toCashAddress(toWallet);

    let utxo = await getAnUtxo(cashAddress1, amount);
    var byteCount = bitbox.BitcoinCash.getByteCount({ P2PKH: 1 }, { P2PKH: 2 });

    let originalAmount = utxo.satoshis;
    let amountToSend   = amount;
    let fee            = byteCount;

    transactionBuilder.addInput(utxo.txid, utxo.vout);
    transactionBuilder.addOutput(cashAddress2, amountToSend);
    transactionBuilder.addOutput(cashAddress1, originalAmount - amountToSend - fee);

    transactionBuilder.setLockTime(0);
    transactionBuilder.sign(0, fromWallet.keyPair, redeemScript, transactionBuilder.hashTypes.SIGHASH_ALL, originalAmount, transactionBuilder.signatureAlgorithms.SCHNORR)
    var tx = transactionBuilder.build();
    var hex = tx.toHex();
    return await bitbox.RawTransactions.sendRawTransaction(hex);
}

export function createMessage(reviewee, reviewer, transactionId, rating) {
    var reviewee160 = Buffer.from(bitbox.Address.cashToHash160(reviewee), 'hex');
    var reviewer160 = Buffer.from(bitbox.Address.cashToHash160(reviewer), 'hex');
    var ratedTx     = Buffer.from(transactionId, 'hex');
    rating          = rating.toString().length == 2 ? rating : "0"+rating;
    var rating      = Buffer.from(rating.toString(), 'hex');
    var message     = Buffer.concat([reviewee160, reviewer160, ratedTx, rating]);
    return message;
}

export async function rateTransaction(reviewee, reviewer, transactionId, rating, wallet, network) {
    network = network || 'mainnet';
    var transactionBuilder = new bitbox.TransactionBuilder(network)
    let redeemScript;
    let message = createMessage(reviewee, reviewer, transactionId, rating);
    var signature = bitbox.BitcoinCash.signMessageWithPrivKey(wallet.keyPair.toWIF(), message.toString());
    var contentBuffer = Buffer.concat([
        rateOpreturnVersion,
        message,
        Buffer.from(signature, 'base64')
    ]);

    var opReturn = bitbox.Script.encode([
        bitbox.Script.opcodes.OP_RETURN,
        contentBuffer
    ]);
    console.log(opReturn);
    let utxo = await getAnUtxo(reviewer);

    var byteCount = bitbox.BitcoinCash.getByteCount({ P2PKH: 1 }, { P2PKH: 1 });
    byteCount += contentBuffer.length;
    byteCount += 9 // some spare bytes for OP_RETURN, version etc. 
    var originalAmount = utxo.satoshis;
    transactionBuilder.addInput(utxo.txid, utxo.vout);
    transactionBuilder.addOutput(reviewer, originalAmount - byteCount);
    transactionBuilder.addOutput(opReturn, 0);
    transactionBuilder.setLockTime(0);
    transactionBuilder.sign(0, wallet.keyPair, redeemScript, transactionBuilder.hashTypes.SIGHASH_ALL, originalAmount, transactionBuilder.signatureAlgorithms.SCHNORR)
    var tx = transactionBuilder.build();
    var hex = tx.toHex();
    console.log("Sending tx from "+ utxo.txid +" with op_return "+ rateOpreturnVersion + message + signature + " contentBuffer length "+ contentBuffer.length)
    return await bitbox.RawTransactions.sendRawTransaction(hex);
}

export async function checkRatedTransactionConditions(details) {
    var ratedTransaction = await bitbox.Transaction.details(details.ratedTransaction);
    console.log(ratedTransaction);

    if (ratedTransaction.vin[0].cashAddress === details.reviewer) {
        console.log("from matched with reviewer")
        return ratedTransaction.vout.some(out => {
            return out.scriptPubKey.cashAddrs.some(addr => addr === details.reviewee)
        });

    } else if (ratedTransaction.vin[0].cashAddress === details.reviewee) {
        console.log("from matched with reviewee")

        return ratedTransaction.vout.some(out => {
            return out.scriptPubKey.cashAddrs.some(addr => addr === details.reviewer)
        });

    } else {
        console.log("from matched none")
        return false; //
    }
}

export async function getRatingDetails(transactionId) {
    var transaction = await bitbox.Transaction.details(transactionId);
    var opReturnOutput = transaction.vout.find(function(out) {return out.scriptPubKey.addresses === undefined;});
    var message = opReturnOutput.scriptPubKey.asm;
    
    let details = {};
    details.version     = message.substring(10, 18);
    details.versionValid= details.version === '0abcde1e';
    details.reviewee160 = message.substring(18, 58);
    details.reviewee    = bitbox.Address.hash160ToCash(details.reviewee160);
    details.reviewer160 = message.substring(58, 98);
    details.reviewer    = bitbox.Address.hash160ToCash(details.reviewer160);
    details.ratedTransaction = message.substring(98, 162);
    details.ratingHex   = message.substring(162, 164);
    details.rating      = details.ratingHex.toString('16')
    details.signature   = Buffer.from(message.substring(164), 'hex').toString('base64');
    console.log(details);

    var message = createMessage(details.reviewee, details.reviewer, details.ratedTransaction, details.rating);
    details.signatureValid = bitbox.BitcoinCash.verifyMessage(
        details.reviewer,
        details.signature,
        message.toString()
    );

    details.ratedTransactionValid = await checkRatedTransactionConditions(details)

    
    return details;
}

export async function sendAllToCashAddress(wallet, toAddress, network) {
    network = network || 'mainnet';
    var transactionBuilder = new bitbox.TransactionBuilder(network)
    var u = await bitbox.Address.utxo(bitbox.HDNode.toCashAddress(wallet));
    var sendAmount = 0
    var inputs = [];

    // Loop through each UTXO assigned to this address.
    for (let i = 0; i < u.utxos.length; i++) {
        var thisUtxo = u.utxos[i]
        inputs.push(thisUtxo)
        sendAmount += thisUtxo.satoshis
        transactionBuilder.addInput(thisUtxo.txid, thisUtxo.vout)
    }

    // get byte count to calculate fee. paying 1.2 sat/byte
    var byteCount = bitbox.BitcoinCash.getByteCount(
        { P2PKH: inputs.length },
        { P2PKH: 1 }
    )

    if (sendAmount - byteCount < 0) {
        console.log(
        `Transaction fee costs more combined UTXOs. Can't send transaction.`
        )
        return
    }

    transactionBuilder.addOutput(toAddress, sendAmount - byteCount);

    let redeemScript
    inputs.forEach((input, index) => {
    transactionBuilder.sign(
        index,
        wallet.keyPair,
        redeemScript,
        transactionBuilder.hashTypes.SIGHASH_ALL,
        input.satoshis
    )
    });

    var tx = transactionBuilder.build();
    var hex = tx.toHex();
    var txid = await bitbox.RawTransactions.sendRawTransaction([hex]);
    return txid;
}

export async function getSimpleAverage(wallet, network) {
    network = network || 'mainnet';


    var cashAddress   = bitbox.HDNode.toCashAddress(wallet);
    var hash160       = bitbox.Address.cashToHash160(cashAddress);
    var toencode      = "0abcde1f" + hash160;
    var prefix        = "^"+ Buffer.from(toencode, 'hex').toString('base64');


    var query = {
        "v": 3,
        "q": {
            "find": {
                "out.b1": {
                    "$regex": prefix
                }
            },
            "limit": 999
        },
        "r": {
            "f": "[ length as $array_length | reduce (.[] | .out[1] | .h1[152:154]  | tonumber) as $item (0; . + $item) / $array_length | tostring ]"
        }
    };

    return bitbox.BitDB.get(query);
}

export async function test() {
    let wallet = createWallet('sponsor access milk want fossil govern plate head stuff session banner spice attract dentist dilemma public real common what jar mad world again online');
    let wallet2 = createWallet('excite orbit grit offer soon license city hybrid bring illness forward there false victory access input limb cement creek pumpkin source kitchen butter sea');

    var claimTx1 = await claimAddress(wallet)
    var claimTx2 = await claimAddress(wallet2)

    await getClaimDetails(claimTx1);
    await getClaimDetails(claimTx2);

    var tradeTx = await transact(wallet, wallet2, 546)

    var rateTx = await rateTransaction(bitbox.HDNode.toCashAddress(wallet2),bitbox.HDNode.toCashAddress(wallet),tradeTx,99,wallet,'mainnet')

    return await getRatingDetails(rateTx);
}

