/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const consensus = require('../lib/protocol/consensus');
const util = require('../lib/utils/util');
const encoding = require('../lib/utils/encoding');
const digest = require('../lib/crypto/digest');
const random = require('../lib/crypto/random');
const WalletDB = require('../lib/wallet/walletdb');
const Validator = require('../lib/utils/validator');
const WorkerPool = require('../lib/workers/workerpool');
const Address = require('../lib/primitives/address');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const KeyRing = require('../lib/primitives/keyring');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const HD = require('../lib/hd');
const fs = require('../lib/utils/fs');
const RPCBase = require('../lib/http/rpcbase');
const RPCError = RPCBase.RPCError;
const errs = RPCBase.errors;
const pkg = require('../lib/pkg');
const Amount = require('../lib/btc/amount');

function parseSecret(raw, network) {
  try {
    return KeyRing.fromSecret(raw, network);
  } catch (e) {
    throw new RPCError(errs.INVALID_ADDRESS_OR_KEY, 'Invalid key.');
  }
}

const KEY1 = 'xprv9s21ZrQH143K3Aj6xQBymM31Zb4BVc7wxqfUhMZrzewdDVCt'
  + 'qUP9iWfcHgJofs25xbaUpCps9GDXj83NiWvQCAkWQhVj5J4CorfnpKX94AZ';

const KEY2 = 'xprv9s21ZrQH143K3mqiSThzPtWAabQ22Pjp3uSNnZ53A5bQ4udp'
  + 'faKekc2m4AChLYH1XDzANhrSdxHYWUeTWjYJwFwWFyHkTMnMeAcW4JyRCZa';

const workers = new WorkerPool({
  enabled: true
});

const wdb = new WalletDB({
  network: 'testnet',
  db: 'ldb',
  location: '../.bcoin/testnet',
  verify: true,
  workers
});

let currentWallet = null;
let importedWallet = null;
let importedKey = null;
let doubleSpendWallet = null;
let doubleSpendCoin = null;

let globalTime = util.now();
let globalHeight = 1;

function nextBlock() {
  const height = globalHeight++;
  const time = globalTime++;

  const prevHead = encoding.U32(height - 1);
  const prevHash = digest.hash256(prevHead);

  const head = encoding.U32(height);
  const hash = digest.hash256(head);

  return {
    hash: hash.toString('hex'),
    height: height,
    prevBlock: prevHash.toString('hex'),
    time: time,
    merkleRoot: encoding.NULL_HASH,
    nonce: 0,
    bits: 0
  };
}

function dummyInput() {
  const hash = random.randomBytes(32).toString('hex');
  return Input.fromOutpoint(new Outpoint(hash, 0));
}

async function testP2PKH(witness, nesting) {
  const flags = Script.flags.STANDARD_VERIFY_FLAGS;

  const wallet = await wdb.create({
    witness
  });

  const addr = Address.fromString(wallet.getAddress('string'));

  const type = witness ? Address.types.WITNESS : Address.types.PUBKEYHASH;
  assert.strictEqual(addr.type, type);

  const src = new MTX();
  src.addInput(dummyInput());
  src.addOutput(nesting ? wallet.getNested() : wallet.getAddress(), 5460 * 2);
  src.addOutput(new Address(), 2 * 5460);

  const mtx = new MTX();
  mtx.addTX(src, 0);
  mtx.addOutput(wallet.getAddress(), 5460);

  await wallet.sign(mtx);

  const [tx, view] = mtx.commit();

  assert(tx.verify(view, flags));
}

async function testP2SH(witness, nesting) {
  const flags = Script.flags.STANDARD_VERIFY_FLAGS;
  const receive = nesting ? 'nested' : 'receive';
  const receiveDepth = nesting ? 'nestedDepth' : 'receiveDepth';
  const vector = witness ? 'witness' : 'script';

  // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
  const options = {
    witness,
    type: 'multisig',
    m: 2,
    n: 3
  };

  const alice = await wdb.create(options);
  const bob = await wdb.create(options);
  const carol = await wdb.create(options);
  const recipient = await wdb.create();

  await alice.addSharedKey(bob.account.accountKey);
  await alice.addSharedKey(carol.account.accountKey);

  await bob.addSharedKey(alice.account.accountKey);
  await bob.addSharedKey(carol.account.accountKey);

  await carol.addSharedKey(alice.account.accountKey);
  await carol.addSharedKey(bob.account.accountKey);

  // Our p2sh address
  const addr1 = alice.account[receive].getAddress();

  if (witness) {
    const type = nesting ? Address.types.SCRIPTHASH : Address.types.WITNESS;
    assert.strictEqual(addr1.type, type);
  } else {
    assert.strictEqual(addr1.type, Address.types.SCRIPTHASH);
  }

  assert(alice.account[receive].getAddress().equals(addr1));
  assert(bob.account[receive].getAddress().equals(addr1));
  assert(carol.account[receive].getAddress().equals(addr1));

  const nestedAddr1 = alice.getNested();

  if (witness) {
    assert(nestedAddr1);
    assert(alice.getNested().equals(nestedAddr1));
    assert(bob.getNested().equals(nestedAddr1));
    assert(carol.getNested().equals(nestedAddr1));
  }

  {
    // Add a shared unspent transaction to our wallets
    const fund = new MTX();
    fund.addInput(dummyInput());
    fund.addOutput(nesting ? nestedAddr1 : addr1, 5460 * 10);

    // Simulate a confirmation
    const block = nextBlock();

    assert.strictEqual(alice.account[receiveDepth], 1);

    await wdb.addBlock(block, [fund.toTX()]);

    assert.strictEqual(alice.account[receiveDepth], 2);
    assert.strictEqual(alice.account.changeDepth, 1);
  }

  const addr2 = alice.account[receive].getAddress();
  assert(!addr2.equals(addr1));

  assert(alice.account[receive].getAddress().equals(addr2));
  assert(bob.account[receive].getAddress().equals(addr2));
  assert(carol.account[receive].getAddress().equals(addr2));

  // Create a tx requiring 2 signatures
  const send = new MTX();

  send.addOutput(recipient.getAddress(), 5460);

  assert(!send.verify(flags));

  await alice.fund(send, {
    rate: 10000,
    round: true
  });

  await alice.sign(send);

  assert(!send.verify(flags));

  await bob.sign(send);

  const [tx, view] = send.commit();
  assert(tx.verify(view, flags));

  assert.strictEqual(alice.account.changeDepth, 1);

  const change = alice.account.change.getAddress();

  assert(alice.account.change.getAddress().equals(change));
  assert(bob.account.change.getAddress().equals(change));
  assert(carol.account.change.getAddress().equals(change));

  // Simulate a confirmation
  {
    const block = nextBlock();

    await wdb.addBlock(block, [tx]);

    assert.strictEqual(alice.account[receiveDepth], 2);
    assert.strictEqual(alice.account.changeDepth, 2);

    assert(alice.account[receive].getAddress().equals(addr2));
    assert(!alice.account.change.getAddress().equals(change));
  }

  const change2 = alice.account.change.getAddress();

  assert(alice.account.change.getAddress().equals(change2));
  assert(bob.account.change.getAddress().equals(change2));
  assert(carol.account.change.getAddress().equals(change2));

  const input = tx.inputs[0];
  input[vector].setData(2, encoding.ZERO_SIG);
  input[vector].compile();

  assert(!tx.verify(view, flags));
  assert.strictEqual(tx.getFee(view), 10000);
}
async function importKey() {
  const data = await fs.readFile('../wallet.txt', 'utf8');
  const lines = data.split(/\n+/);
  const keys = [];
  for (let line of lines) {
    line = line.trim();

    if (line.length === 0)
      continue;

    if (/^\s*#/.test(line))
      continue;

    const parts = line.split(/\s+/);

    if (parts.length < 4)
      throw new RPCError(errs.DESERIALIZATION_ERROR, 'Malformed wallet.');

    const secret = parseSecret(parts[0], wdb.network);
    keys.push(secret);
  }

  for (const key of keys){
    await wallet.importKey(0, key);
  }

  await wdb.rescan(0);
}

async function dumpwallet(){
  let file = '../wallet.txt';
  const tip = await wdb.getTip();
  const time = util.date();

  const out = [
    util.fmt('# Wallet Dump created by Bcoin %s', pkg.version),
    util.fmt('# * Created on %s', time),
    util.fmt('# * Best block at time of backup was %d (%s).',
      tip.height, util.revHex(tip.hash)),
    util.fmt('# * File: %s', file),
    ''
  ];

  const hashes = await wallet.getAddressHashes();

  for (const hash of hashes) {
    const ring = await wallet.getPrivateKey(hash);

    if (!ring)
      continue;

    const addr = ring.getAddress('string');

    let fmt = '%s %s label= addr=%s';

    if (ring.branch === 1)
      fmt = '%s %s change=1 addr=%s';

    const str = util.fmt(fmt, ring.toSecret(), time, addr);

    out.push(str);
  }

  out.push('');
  out.push('# End of dump');
  out.push('');

  const dump = out.join('\n');

  if (fs.unsupported)
    return dump;

  await fs.writeFile(file, dump, 'utf8');
}

async function encryptwallet(){
  const wallet = await wdb.create();
  if (wallet.master.encrypted) {
    throw new RPCError(errs.WALLET_WRONG_ENC_STATE, 'Already running with an encrypted wallet.');
  }

  try {
    await wallet.setPassphrase('', 'helloworld');
  } catch (e) {
    throw new RPCError(errs.WALLET_ENCRYPTION_FAILED, 'Encryption failed.');
  }
}

async function listAddress(){
  for (const path of await wallet.getPaths()) {
    console.log(path, path.toAddress(wdb.network).toString());
  }
}

async function getBalance(){
  let name = 'default';
  const minconf = 0;

  if (name === '')
    name = 'default';

  if (name === '*')
    name = null;

  const balance = await wallet.getBalance(name);

  let value;
  if (minconf > 0)
    value = balance.confirmed;
  else
    value = balance.unconfirmed;

  return Amount.btc(value, true);
}

async function transaction(){
  for(let [key, item] of wdb.wallets){
    wallet = item;
    if(!!wallet){
      // Create new transaction
      const t2 = new MTX();

      const input = new Input();
      input.prevout.hash = 'e3492bcb041e336a01beaf44cb83842de56a4b3b4a4d10e47bd1b7bbeb157f51';
      input.prevout.index = 0;
      input.sequence = 0xffffffff;

      t2.inputs.push(input);
      t2.addOutput(wallet.getAddress(), 1);

      console.log(t2.toRaw().toString('hex'));
      await wallet.sign(t2);
      assert(t2.verify());
    }
  }
}

let wallet = null;
async function run(){
  try{
    await wdb.open();
    //wallet = await wdb.create();    //新建钱包
    await transaction(); //交易
  }
  catch(e){
    consoel.error(e);
  }  
}

run();
