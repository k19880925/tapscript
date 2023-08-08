import { util } from '@cmdcode/crypto-utils'
import { Address, Script, Signer, Tap, Tx } from '@cmdcode/tapscript'

// Create a keypair to use for testing.
const secret = '0a7d01d1c2e1592a02ea7671bb79ecd31d8d5e660b008f4b10e67787f4f24712'
const seckey = util.getSecretKey(secret)
const pubkey = util.getPublicKey(seckey, true)

const script = [
'OP_1', 'OP_1', 
  'OP_IF', 
    'OP_IF', 1, 7, 'OP_ADD', 8, 'OP_EQUALVERIFY', pubkey, 'OP_CHECKSIG', 
    'OP_ELSE',
      'OP_IF', 2, 6, 'OP_ADD', 8, 'OP_EQUALVERIFY', pubkey, 'OP_CHECKSIG',
      'OP_ELSE', 3, 5, 'OP_ADD', 8, 'OP_EQUALVERIFY', pubkey, 'OP_CHECKSIG',
      'OP_ENDIF',
    'OP_ENDIF',
  'OP_ELSE',
    4, 4, 'OP_ADD', 8, 'OP_EQUALVERIFY', pubkey, 'OP_CHECKSIG',
'OP_ENDIF'
]

const sbytes = Script.encode(script)
const tapleaf = Tap.tree.getLeaf(sbytes)

// Generate a tapkey that includes our tree. Also, create a merlke proof 
// (cblock) that targets our leaf and proves its inclusion in the tapkey.
const [ tpubkey, cblock ] = Tap.getPubKey(pubkey, { target: tapleaf })

var cblocksize = cblock.length/2 -1
var cblockblocks = cblocksize/32
var start = 2

console.log("Internal PubKey: ", pubkey.hex)
console.log("Twaeked PubKey: ", tpubkey)
console.log('Cblock %d bytes', (cblocksize+1))

for (var i = 0; i < cblockblocks; i++, start+=64)
  if ( i == 0)
    console.log("   InternalPubkey: ", cblock.substring(start, start+64))
  else
    console.log("   Scripts: ", cblock.substring(start, start+64))
console.log("")

// A taproot address is simply the tweaked public key, encoded in bech32 format.
const address = Address.p2tr.fromPubKey(tpubkey, 'testnet')
console.log("Address: ", address)
console.log("")
/* NOTE: To continue with this example, send 100_000 sats to the above address.
 * You will also need to make a note of the txid and vout of that transaction,
 * so that you can include that information below in the redeem tx.
 */ 

const txdata = Tx.create({
  vin  : [{
    // Use the txid of the funding transaction used to send the sats.
    txid: '31ab23260e87026655275d22303448a21f568bbd9948c4e99163629f1f016c8b',
    // Specify the index value of the output that you are going to spend from.
    vout: 0,
    // Also include the value and script of that ouput.
    prevout: {
      // Feel free to change this if you sent a different amount.
      value: 100_000,
      // This is what our address looks like in script form.
      scriptPubKey: [ 'OP_1', tpubkey ]
    },
  }],
  vout : [{
    // We are leaving behind 1000 sats as a fee to the miners.
    value: 99_000,
    // 돈을 받을 bech32(segwit) 주소
    scriptPubKey: Address.toScriptPubKey('mygSWiaNndarwJyZZ3R3P4yRksCYjaZKA4')
  }]
})

// For this example, we are signing for input 0 of our transaction,
// using the untweaked secret key. We are also extending the signature 
// to include a commitment to the tapleaf script that we wish to use.
const sig = Signer.taproot.sign(seckey, txdata, 0, { extension: tapleaf })

// Add the signature to our witness data for input 0, along with the script
// and merkle proof (cblock) for the script.
txdata.vin[0].witness = [ sig.hex, script, cblock ]

// Check if the signature is valid for the provided public key, and that the
// transaction is also valid (the merkle proof will be validated as well).
const isValid = await  Signer.taproot.verify(txdata, 0, { pubkey })
console.log("Is Valid: %s\n", isValid)
console.log(Tx.encode(txdata).hex)

// non-mandatory-script-verify-flag (Public key version reserved for soft-fork upgrades)
