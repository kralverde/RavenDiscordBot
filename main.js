const ElectrumCli = require('electrum-client');
const bitcoin = require('bitcoinjs-lib');
const bip39 = require('bip39');
const bip32 = require('bip32');
const ecc = require('tiny-secp256k1');
const leveldb = require('level');
const crypto = require('crypto');
const mutex = require('async-mutex');
const fs = require('fs');
const base58 = require('bs58');
const ipfsAPI = require('ipfs-http-client');
const diskusage = require('diskusage');

const { Client, Intents, MessageEmbed, Permissions } = require('discord.js');
const { SlashCommandBuilder } = require('@discordjs/builders');
const { REST } = require('@discordjs/rest');
const { Routes } = require('discord-api-types/v9');

require('dotenv').config();

const factory = bip32.BIP32Factory(ecc);

const RAVENCOIN = {
    messagePrefix: '\x16Raven Signed Message:\n',
    bech32: 'rvn',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4,
    },
    pubKeyHash: 0x3C,
    scriptHash: 0x7A,
    wif: 0x80,
    unique_mint_address: 'RXissueUniqueAssetXXXXXXXXXXWEAe58',
  };

const RAVENCOIN_TESTNET = {
    messagePrefix: '\x16Raven Signed Message:\n',
    bech32: 'rvn',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
    pubKeyHash: 111,
    scriptHash: 196,
    wif: 239,
    unique_mint_address: 'n1issueUniqueAssetXXXXXXXXXXS4695i',
  };

const MAIN_ASSET = 'COMMUNITY_TEST';
const COIN = 100000000;

const MINT_COST = 5.1;
const PIN_COST = 0;

const network = RAVENCOIN_TESTNET;

const broadcast_semaphore = new mutex.Mutex();

function script_to_scripthash(script) {
    return crypto.createHash('sha256').update(script).digest('hex').slice(0, 64).match(/[a-fA-F0-9]{2}/g).reverse().join('');
}

class AddressStateBuilder {
    constructor(root, starting_index, db, db_key) {
        this._root = root;
        this._db = db;
        this._db_key = db_key;
        this._index = starting_index;
        this._semaphore = new mutex.Mutex();
    }
    async generate_next_address() {
        let ret_val;
        await this._semaphore.runExclusive(async () => {
            const index = this._index;
            this._index += 1;
            const child = this._root.derive(index);
            const { address } = bitcoin.payments.p2pkh({
                pubkey: child.publicKey,
                network: network
            });
            const script = bitcoin.address.toOutputScript(address, network);
            const scripthash = script_to_scripthash(script);
            try {
                await this._db.put(this._db_key, this._index)
            } catch (e) {
                //TODO: Some kind of exit
                console.log('Generate next address failure: ' + e);
            }
            ret_val = {
                index: index,
                address: address,
                script: script,
                scripthash: scripthash
            };
        });
        return ret_val;
    }

    get_current_address() {
        const index = this._index - 1;
        if (index < 0) {
            return null;
        }
        const child = this._root.derive(index);
        const { address } = bitcoin.payments.p2pkh({
            pubkey: child.publicKey,
            network: network
        });
        const script = bitcoin.address.toOutputScript(address, network);
        const scripthash = script_to_scripthash(script);
        return {
            index: index,
            address: address,
            script: script,
            scripthash: scripthash
        }
    }
}

/* End Definitions */

/* File Structure */
const data_dir = process.env.DATA_DIR ? process.env.DATA_DIR : __dirname;

const requests_dir = data_dir + '/requests';
if (!fs.existsSync(requests_dir)) {
    fs.mkdirSync(requests_dir, 0744);
}

const completed_requests_dir = requests_dir + '/completed';
if (!fs.existsSync(completed_requests_dir)) {
    fs.mkdirSync(completed_requests_dir, 0744);
}

const uncompleted_requests_dir = requests_dir + '/waiting';
if (!fs.existsSync(uncompleted_requests_dir)) {
    fs.mkdirSync(uncompleted_requests_dir, 0744);
}

const server_info = requests_dir + '/serverinfo';
const serverid_to_channelid = {};
if (!fs.existsSync(server_info)) {
    fs.writeFileSync(server_info, '{}');
} else {
    const data = JSON.parse(fs.readFileSync(server_info));
    Object.keys(data).forEach((key) => {
        serverid_to_channelid[key] = data[key];
    });
}

/* End File Structure */

/* Constants */

const ipfs_client = ipfsAPI.create();

(async () => {
    const mnemonic = process.env.MNEMONIC;
    const discord_token = process.env.DISCORD_TOKEN;
    const discord_id = process.env.DISCORD_ID;

    const state_db = leveldb(data_dir + '/state_db');

    var external_index;
    var internal_index;
    var asset_index;

    await get_from_database_or_default_to('external_index', 0).then(x => external_index = Number(x));
    await get_from_database_or_default_to('internal_index', 0).then(x => internal_index = Number(x));
    await get_from_database_or_default_to('asset_index', 1).then(x => asset_index = Number(x));

    const _created_assets = new Set();
    const _waiting_assets = {};
    const scripthash_to_asset = {};
    const snowflake_to_asset = {};
    const timestamp_to_asset = {};

    fs.readdirSync(completed_requests_dir).forEach(file => {
        _created_assets.add(file);
    });

    fs.readdirSync(uncompleted_requests_dir).forEach(file => {
        const data = JSON.parse(fs.readFileSync(uncompleted_requests_dir+'/'+file));
        _waiting_assets[data.name] = data;
        scripthash_to_asset[data.recv.scripthash] = data.name;
        snowflake_to_asset[data.requestor] = data.name;
        timestamp_to_asset[data.timestamp] = data.name;
    });

    const root = factory.fromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
    const _general_root = root
        .deriveHardened(44)
        .deriveHardened(175)
        .deriveHardened(0);
    
    const external_root = _general_root.derive(0);
    const internal_root = _general_root.derive(1);
    // A special derivation to keep track of our ownership asset
    const asset_root = _general_root.derive(2);
    
    const external_generator = new AddressStateBuilder(external_root, external_index, state_db, 'external_index');
    const internal_generator = new AddressStateBuilder(internal_root, internal_index, state_db, 'internal_index');
    const asset_generator = new AddressStateBuilder(asset_root, asset_index, state_db, 'asset_index');

    if (asset_index == 1) {
        const child = asset_root.derive(0);
        const { address } = bitcoin.payments.p2pkh({
            pubkey: child.publicKey,
            network: network
        });
        console.log('Send ownership asset to ' + address + ' to seed the script.');
    }

    /* End Constants */
    
    /* Utility Functions */
    
    function get_op_push(length) {
        if (length < 0x4C) {
            return length.toString(16).padStart(2, '0');
        } else if (length <= 0xFF) {
            return '4C' + length.toString(16).padStart(2, '0');
        } else {
            throw 'This should never happen';
        }
    }

    function already_have_data_embed(data) {
        return new MessageEmbed()
                    .setColor('#009900')
                    .setTitle('Asset Request Information')
                    .addFields(
                        { name: 'You already have a request! Run /clear to remove it.', value: '\u200B' },
                        { name: 'Asset', value: MAIN_ASSET + '#' + data.name },
                        { name: 'To Address', value: data.to},
                        { name: 'IPFS', value: data.ipfs ? data.ipfs : 'None' },
                        { name: 'Send ' + data.amount + 'RVN to this address to recieve your asset.', value: data.recv.address },
                        { name: 'Currently:', value: + data.loaded + 'RVN' }
                    );
    }

    function new_embed_from_request_data(data) {
        return new MessageEmbed()
                    .setColor('#0099ff')
                    .setTitle('Unique Asset Mint Request')
                    .addFields(
                        { name: 'Asset', value: MAIN_ASSET + '#' + data.name },
                        { name: 'To Address', value: data.to },
                        { name: 'IPFS', value: data.ipfs ? data.ipfs : 'None' },
                        { name: '\u200B', value: '\u200B' },
                        { name: 'Send ' + data.amount + 'RVN to this address to recieve your asset.', value: data.recv.address },
                        { name: '\u200B', value: '[Reply](https://support.discord.com/hc/en-us/articles/360057382374-Replies-FAQ) to this message or mention <@' + discord_id + '> to get information about funding. Send a IPFS hash or a file (if you want to pay for hosting) to update the IPFS hash. Remember to run /alive to double check the bot is still running before sending any RVN!' }
                    );
    }

    function current_embed_from_request_data(data) {
        return new MessageEmbed()
                    .setColor('#0099cc')
                    .setTitle('Unique Asset Mint Request')
                    .addFields(
                        { name: 'Asset', value: MAIN_ASSET + '#' + data.name },
                        { name: 'To Address', value: data.to},
                        { name: 'IPFS', value: data.ipfs ? data.ipfs : 'None' },
                        { name: 'Send ' + data.amount + 'RVN to this address to recieve your asset.', value: data.recv.address },
                        { name: 'Currently:', value: + data.loaded + 'RVN' }
                    );
    }

    function get_from_database_or_default_to(key, def) {
        return state_db.get(key).catch(() => def);
    }
    
    function is_asset_valid(name) {
        let re = new RegExp("^[-A-Za-z0-9@$%&*()[\\]{}_.?:]{1,20}$");
        return name.match(re);
    }
    
    function is_asset_created(name) {
        return _created_assets.has(name) || name in _waiting_assets;
    }
    
    function add_or_modify_asset_request_info(asset, data) {
        _waiting_assets[asset] = data;
        fs.writeFileSync(uncompleted_requests_dir+'/'+asset, JSON.stringify(data));
    }

    function remove_asset_request(asset) {
        const data = _waiting_assets[asset];
        if (!data) {
            return;
        }
        delete _waiting_assets[asset];
        delete scripthash_to_asset[data.recv.scripthash];
        delete snowflake_to_asset[data.requestor];
        delete timestamp_to_asset[data.timestamp];
        fs.unlinkSync(uncompleted_requests_dir+'/'+asset);
    }

    function add_or_modify_completed_asset_request_info(asset, data) {
        _created_assets.add(asset);
        fs.writeFileSync(completed_requests_dir+'/'+asset, JSON.stringify(data));
    }

    function remove_completed_asset_request(asset) {
        _created_assets.delete(asset);
        fs.unlinkSync(completed_requests_dir+'/'+asset);
    }

    async function handle_scripthash_and_amount(scripthash, confirmed, unconfirmed) {
        try {
            if (!(scripthash in scripthash_to_asset)) {
                return;
            }
            const asset = scripthash_to_asset[scripthash];
            const data = _waiting_assets[asset];

            data.loaded = (confirmed + unconfirmed) / COIN;

            let channel = undefined;
            if (data.server in serverid_to_channelid) {
                const channel_id = serverid_to_channelid[data.server];
                channel = client.channels.cache.get(channel_id);
                if (!channel) {
                    //fetch requires knowledge of parent
                    await client.guilds.fetch(data.server);
                    channel = await client.channels.fetch(channel_id);
                }
            }

            if (confirmed >= (data.amount * COIN)) {
                //Handle atomically to ensure quick transactions are still good (i.e. prevout still in mempool)
                broadcast_semaphore.runExclusive(async () => {
                    const psbt = new bitcoin.Psbt({ network: network });
                    let sats_avail = 0;
                    let num_internal_inputs = 0;
                    let num_external_inputs = 0;

                    var current_asset_address = asset_generator.get_current_address();
                    var next_asset_address_info = await asset_generator.generate_next_address();
                    var current_internal_address = internal_generator.get_current_address();
                    var next_internal_address_info = await internal_generator.generate_next_address();
                    
                    const asset_utxos = await electrum.blockchain_scripthash_listassets(current_asset_address.scripthash)
                        
                    var valid_utxo = asset_utxos.filter(utxo => utxo.name == MAIN_ASSET + '!');
                    while (valid_utxo.length < 1) {
                        console.log('Unable to find asset utxo! Looking back... Current index: ' + (asset_generator._index - 1));
                        asset_generator._index -= 2;
                        if (asset_generator._index < 1) {
                            throw 'No asset utxo found!';
                        }
                        current_asset_address = asset_generator.get_current_address();
                        next_asset_address_info = await asset_generator.generate_next_address();
                        const asset_utxos = await electrum.blockchain_scripthash_listassets(current_asset_address.scripthash)
                        valid_utxo = asset_utxos.filter(utxo => utxo.name == MAIN_ASSET + '!');
                    }

                    const utxo_data = valid_utxo[0];
                    const asset_txin = await electrum.blockchain_transaction_get(utxo_data.tx_hash);
                    psbt.addInput({
                        hash: utxo_data.tx_hash,
                        index: utxo_data.tx_pos,
                        nonWitnessUtxo: Buffer.from(
                            asset_txin,
                            'hex',
                        )
                    });

                    if (current_internal_address) {
                        let utxos = await electrum.blockchain_scripthash_listunspent(current_internal_address.scripthash);
                        while (utxos.length < 1) {
                            console.log('Unable to find internal utxo! Looking back... Current index: ' + (internal_generator._index - 1));
                            const history = await electrum.blockchain_scripthash_get_history(current_internal_address.scripthash);
                            if (history.length > 0) {
                                console.log('Found an internal address with history. Stopping here.');
                                break;
                            }
                            internal_generator._index -= 2;
                            if (internal_generator._index < 1) {
                                console.log('No internal utxo found. Resetting.');
                                break;
                            }
                            current_internal_address = internal_generator.get_current_address();
                            next_internal_address_info = await internal_generator.generate_next_address();
                            utxos = await electrum.blockchain_scripthash_listunspent(current_internal_address.scripthash)
                        }
                        for (const utxo of utxos) {
                            const txin = await electrum.blockchain_transaction_get(utxo.tx_hash);
                            num_internal_inputs += 1;
                            sats_avail += utxo.value;
                            psbt.addInput({
                                hash: utxo.tx_hash,
                                index: utxo.tx_pos,
                                nonWitnessUtxo: Buffer.from(
                                    txin,
                                    'hex',
                                )
                            });
                        }
                    }

                    const utxos = await electrum.blockchain_scripthash_listunspent(data.recv.scripthash);
                    for (const utxo of utxos) {
                        const txin = await electrum.blockchain_transaction_get(utxo.tx_hash);
                        num_external_inputs += 1;
                        sats_avail += utxo.value;
                        psbt.addInput({
                            hash: utxo.tx_hash,
                            index: utxo.tx_pos,
                            nonWitnessUtxo: Buffer.from(
                                txin,
                                'hex',
                            ),
                        });
                    }

                    if (sats_avail < (5 * COIN)) {
                        throw 'Not enough RVN to mint!';
                    }

                    psbt.addOutput({
                        address: network.unique_mint_address,
                        value: 5 * COIN,
                    });

                    const owner = MAIN_ASSET + '!';
                    const owner_len = owner.length;
                    const asset_part_pre = Buffer.from('72766e74' + owner_len.toString(16).padStart(2, '0'), 'hex');
                    const asset_part_asset = Buffer.from(owner, 'ascii');
                    const asset_part_post = Buffer.from('00e1f5050000000075', 'hex');
                    const asset_prefix = Buffer.from('c0' + get_op_push(asset_part_pre.length + asset_part_asset.length + asset_part_post.length - 1), 'hex');
                    const final_script = Buffer.concat([next_asset_address_info.script, asset_prefix, asset_part_pre, asset_part_asset, asset_part_post]);

                    const script = bitcoin.address.toOutputScript(data.to, network);
                    const new_asset = MAIN_ASSET + '#' + data.name;
                    const new_asset_len = new_asset.length
                    const new_asset_part_pre = Buffer.from('72766e71' + new_asset_len.toString(16).padStart(2, '0'), 'hex');
                    const new_asset_part_asset = Buffer.from(new_asset, 'ascii');
                    const new_asset_part_pre_ipfs = Buffer.from('00e1f505000000000000', 'hex');
                    const new_asset_part_ipfs = Buffer.from((data.ipfs ? '01' + base58.decode(data.ipfs).toString('hex') +  '75' : '0075'), 'hex');
                    const new_asset_prefix = Buffer.from('c0' + get_op_push(new_asset_part_pre.length + new_asset_part_asset.length + new_asset_part_pre_ipfs.length + new_asset_part_ipfs.length - 1 ), 'hex');

                    const final_new_script = Buffer.concat([script, new_asset_prefix, new_asset_part_pre, new_asset_part_asset, new_asset_part_pre_ipfs, new_asset_part_ipfs]);

                    const asset_node = asset_root.derive(current_asset_address.index);
                    const internal_node = current_internal_address ? internal_root.derive(current_internal_address.index) : null;
                    const external_node = external_root.derive(data.recv.index);

                    const temp_psbt = psbt.clone();

                    temp_psbt.addOutput({
                        address: next_internal_address_info.address,
                        value: sats_avail - (5 * COIN),
                    });

                    temp_psbt.addOutput({
                        script: final_new_script,
                        value: 0,
                    });

                    temp_psbt.addOutput({
                        script: final_script,
                        value: 0,
                    });

                    temp_psbt.signInput(0, asset_node);
                    for (let i = 0; i < num_internal_inputs; i++) {
                        temp_psbt.signInput(1 + i, internal_node);
                    }
                    for (let i = 0; i < num_external_inputs; i++) {
                        temp_psbt.signInput(1 + num_internal_inputs + i, external_node);
                    }

                    temp_psbt.finalizeAllInputs();
                    const psbt_size = Math.floor(temp_psbt.extractTransaction().toHex().length / 2);
                    
                    psbt.addOutput({
                        address: next_internal_address_info.address,
                        value: sats_avail - (5 * COIN) - (1050 * psbt_size),
                    });
                    psbt.addOutput({
                        script: final_script,
                        value: 0,
                    });
                    psbt.addOutput({
                        script: final_new_script,
                        value: 0,
                    });

                    psbt.signInput(0, asset_node);
                    for (let i = 0; i < num_internal_inputs; i++) {
                        psbt.signInput(1 + i, internal_node);
                    }
                    for (let i = 0; i < num_external_inputs; i++) {
                        psbt.signInput(1 + num_internal_inputs + i, external_node);
                    }

                    psbt.finalizeAllInputs();
                    const final_tx = psbt.extractTransaction().toHex();

                    await electrum.blockchain_transaction_broadcast(final_tx)
                        .then(res => {
                            if (channel) {
                                channel.send('<@' + data.requestor + '>\nYour asset, ' + MAIN_ASSET + '#' + data.name + ' has been sent!\n'+res);
                            }
                            data.complete = true;
                            remove_asset_request(data.name);
                            add_or_modify_completed_asset_request_info(data.name, data);
                            electrum.blockchain_scripthash_unsubscribe(data.recv.scripthash).catch(e => console.log('Unsubscribe: ' + e));
                        })
                        .catch(err => {
                            console.log('Broadcast: ' +  err);
                            if (channel) {
                                channel.send('<@' + data.requestor + '>\nSomething went wrong! Ping @kralverde#0550');
                            }
                        });
                }).catch(err => {
                    console.log(err);
                    if (channel) {
                        channel.send('<@' + data.requestor + '>\nSomething went wrong! Ping @kralverde#0550');
                    }
                });

            } else if ((confirmed + unconfirmed) >= (data.amount * COIN)) {
                if (channel) {
                    channel.send('<@' + data.requestor + '>\nThe required funds have been sent! They are currently in the mempool... Your asset will be sent when it is confirmed.');
                }
            } else if ((confirmed + unconfirmed) > 0) {
                if (channel) {
                    channel.send('<@' + data.requestor + '>\nThere is now ' + (data.loaded) + 'RVN associated with ' + data.recv.address + '. ' + data.amount + 'RVN is required.');
                }
            } else {
            }

        } catch (e) {console.log('Broadcast 2:' + e)} 
    }

    /* End Utility */
    
    /* Electrum Client */
    
    const electrum = new ElectrumCli(50003, 'rvn4lyfe.com', 'tls');
    electrum.subscribe.on('blockchain.scripthash.subscribe', function (ret) {
        let [ scripthash, status ] = ret;
        electrum.blockchain_scripthash_get_balance(scripthash).then(async res => {
            await handle_scripthash_and_amount(scripthash, res.confirmed, res.unconfirmed);
        }).catch(e => console.log('subscribe event: ' + e));
    });
    
    /* Initialize Discord Commands */
    
    const commands = [
        new SlashCommandBuilder()
            .setName('request')
            .setDescription('Your current request, if any.'),
        new SlashCommandBuilder()
            .setName('clear')
            .setDescription('Clear an asset request. WILL NOT REIMBURSE ANY RVN SENT.'),
        new SlashCommandBuilder()
            .setName('removeipfs')
            .setDescription('Removes the IPFS hash associated with your request'),
        new SlashCommandBuilder()
            .setName('changeipfs')
            .setDescription('Changes the IPFS hash associated with your request')
            .addStringOption(option =>
                option.setName('ipfs')
                    .setDescription('The IPFS hash associated with your asset.')
                    .setRequired(true)),
        new SlashCommandBuilder()
            .setName('setchannel')
            .setDescription('Bot notifications will go in this channel'),
        new SlashCommandBuilder()
            .setName('alive')
            .setDescription('Make sure the bot is running'),
        new SlashCommandBuilder()
            .setName('info')
            .setDescription('Information about this bot'),
        new SlashCommandBuilder()
            .setName('mint')
            .setDescription('Mint a unique asset!')
            .addStringOption(option => 
                option.setName('name')
                    .setDescription('The name of your asset')
                    .setRequired(true))
            .addStringOption(option =>
                option.setName('address')
                    .setDescription('Where to send your asset')
                    .setRequired(true))
            .addStringOption(option =>
                option.setName('ipfs')
                    .setDescription('The IPFS hash associated with this asset (optional, can be changed later)')
                    .setRequired(false)),
                    
    ].map(command => command.toJSON());
    
    const rest = new REST({ version: '9' }).setToken(discord_token);
    
    rest.put(Routes.applicationCommands(discord_id), { body: commands })
        .then(() => console.log('Successfully registered application commands.'))
        .catch(console.error);
    
    /* End Commands */
    
    /* Discord Bot */
    
    const client = new Client({ intents: [ Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES, Intents.FLAGS.DIRECT_MESSAGES ] });
    
    // Handle pings (attachments/ipfs modifications)
    client.on('messageCreate', async message => {
        if (message.author.bot) return;
        let reference_message = null;
        if (message.reference) {
            channel = client.channels.cache.get(message.reference.channelId);
            if (!channel) {
                //fetch requires knowledge of parent
                await client.guilds.fetch(message.reference.guildId);
                channel = await client.channels.fetch(message.reference.channelId);
            }
            if (!channel) {
                return;
            }
            reference_message = channel.messages.cache.get(message.reference.messageId);
            if (!reference_message) {
                reference_message = await channel.messages.fetch(message.reference.messageId);
            }
        }
        if (!message.mentions.has(discord_id) && !reference_message) return;
        if (reference_message && reference_message.author.id != discord_id) return;
        if (message.author.id in snowflake_to_asset) {
            const asset = snowflake_to_asset[message.author.id];
            const file_url = message.attachments.first()?.url;
            if (file_url) {
                let free = 0;
                diskusage.check('/', (err, info) => {
                    free = info.free;
                });
                if (free < 1024 * 1024 * 1024) {
                    message.channel.send('Not enough space to store your file! Ping @kralverde!');
                    return;
                }
                try {
                    const file = await ipfs_client.add(ipfsAPI.urlSource(file_url));
                    
                    const ipfs = file.cid.toV0().toString();

                    if (file.size > 8 * 1024 * 1024) {
                        await ipfs_client.pin.rm(ipfs);
                        message.channel.send('Too big! Only files <8MiB are supported!');
                        return;
                    }
                    let ipfs_length = 0;
                    try {
                        ipfs_length = base58.decode(ipfs).length;
                    } catch (e) {}
                    
                    if (ipfs.startsWith('Qm') && ipfs_length == 34) {
                        const data = _waiting_assets[asset];
                        data.ipfs = ipfs;
                        data.amount += data.hosted ? PIN_COST : 0;
                        data.hosted = true;
                        add_or_modify_asset_request_info(asset, data);
                        message.channel.send('Your asset\'s IPFS hash has been changed: ' + ipfs + '\nYour new total is: ' + data.amount + 'RVN.');
                    } else {
                        message.channel.send('We generated an invalid IPFS hash! Ping @kralverde!');
                    }
                } catch (e) {
                    console.log('IPFS Add: ' + e);
                    message.channel.send('Failed to pin to IPFS.');
                }
            } else {
                const found = message.content.match(/Qm[1-9A-Za-z]{44}/g);
                const maybe_ipfs = found ? found[0] : '';
                let ipfs_length = 0;
                try {
                    ipfs_length = base58.decode(maybe_ipfs).length;
                } catch (e) {}

                if (maybe_ipfs.startsWith('Qm') && ipfs_length == 34) {
                    const data = _waiting_assets[asset];
                    if (data.hosted) {
                        await ipfs_client.pin.rm(data.ipfs);
                        data.amount -= PIN_COST;
                        data.hosted = false;
                    }
                    data.ipfs = maybe_ipfs;

                    add_or_modify_asset_request_info(asset, data);
                    message.channel.send('Your asset\'s IPFS hash has been changed: ' + maybe_ipfs);
                } else {
                    const data = _waiting_assets[asset];
                    const embed = current_embed_from_request_data(data);
                    message.channel.send({ embeds: [ embed ] });
                }
            }
        } else {
            message.channel.send('You don\'t have an asset request! Use /mint to make one.');
        }
    });

    // Handle commands
    client.on('interactionCreate', async interaction => {
        if (!interaction.isCommand()) return;
        if (interaction.commandName === 'setchannel') {
            if (interaction.member.permissions & Permissions.FLAGS.MANAGE_CHANNELS) {
                if (!interaction.guildId || !interaction.channelId) {
                    await interaction.reply({ content: 'You are not in a valid channel!', ephemeral: true });
                } else {
                    serverid_to_channelid[interaction.guildId] = interaction.channelId;
                    fs.writeFileSync(server_info, JSON.stringify(serverid_to_channelid));
                    await interaction.reply('<#' + interaction.channelId + '> set as the notification channel');
                }
            } else {
                await interaction.reply({ content: 'You do not have permissions to set a notification channel.', ephemeral: true });
            }
        } else if (interaction.commandName === 'clear') {
            if (interaction.member.id in snowflake_to_asset) {
                const asset = snowflake_to_asset[interaction.member.id];
                const data = _waiting_assets[asset];
                const scripthash_to_remove = data.recv.scripthash;
                remove_asset_request(asset);
                electrum.blockchain_scripthash_unsubscribe(scripthash_to_remove).catch(e => console.log('Unsubscribe 1: ' + e));
                await interaction.reply({ content: 'Your request was removed!', ephemeral: true });
            } else {
                await interaction.reply({ content: 'You don\'t have any current asset requests!', ephemeral: true });
            }
        } else if (interaction.commandName === 'removeipfs') {
            if (interaction.member.id in snowflake_to_asset) {
                const asset = snowflake_to_asset[interaction.member.id];
                const data = _waiting_assets[asset];
                if (data.hosted) {
                    await ipfs_client.pin.rm(data.ipfs);
                    data.amount -= PIN_COST;
                    data.hosted = false;
                }
                data.ipfs = null;
                add_or_modify_asset_request_info(asset, data);
                await interaction.reply({ content: 'Your IPFS was removed!', ephemeral: true });
            } else {
                await interaction.reply({ content: 'You don\'t have any current asset requests!', ephemeral: true });
            }
        } else if (interaction.commandName === 'request') {
            if (interaction.member.id in snowflake_to_asset) {
                const asset = snowflake_to_asset[interaction.member.id];
                const data = _waiting_assets[asset];
                const embed = current_embed_from_request_data(data);

                await interaction.reply({ embeds: [ embed ] });                
            } else {
                await interaction.reply({ content: 'You don\'t have any current asset requests!', ephemeral: true });
            }
        } else if (interaction.commandName === 'changeipfs') {
            const ipfs = interaction.options.getString('ipfs');
            let ipfs_length = 0;
            try {
                ipfs_length = base58.decode(ipfs).length;
            } catch (e) {}

            if (ipfs && (!ipfs.startsWith('Qm') || ipfs_length != 34)) {
                await interaction.reply({ content: 'Your IPFS hash is invalid!', ephemeral: true });
                return;
            }
            if (interaction.member.id in snowflake_to_asset) {
                const asset = snowflake_to_asset[interaction.member.id];
                const data = _waiting_assets[asset];
                if (data.hosted) {
                    await ipfs_client.pin.rm(data.ipfs);
                    data.amount -= PIN_COST;
                    data.hosted = false;
                }
                data.ipfs = ipfs;
                add_or_modify_asset_request_info(asset, data);
                await interaction.reply({ content: 'Your IPFS was changed!', ephemeral: true });
            } else {
                await interaction.reply({ content: 'You don\'t have any current asset requests!', ephemeral: true });
            }
        } else if (interaction.commandName === 'alive') {
            await interaction.reply({ content: 'Good to go :smile:', ephemeral: true });
        } else if (interaction.commandName === 'info') {
            await interaction.reply('This bot lets you mint unique assets to an address of your choice for a fee of ' + MINT_COST + ' RVN. This bot will also host a file to associate with your unique asset for an extra ' + PIN_COST + 'RVN. Run /mint with (optionally) no IPFS value for more information.');
        } else if (interaction.commandName === 'mint') {
            if (interaction.member.id in snowflake_to_asset) {
                const data = _waiting_assets[snowflake_to_asset[interaction.member.id]];
                const embed = already_have_data_embed(data);
                await interaction.reply({ embeds: [ embed ] });
                return;
            }
            const name = interaction.options.getString('name');
            const address = interaction.options.getString('address');
            const ipfs = interaction.options.getString('ipfs', false);
            if (!is_asset_valid(name)) {
                await interaction.reply({ content: 'Asset name is invalid!', ephemeral: true });
                return;
            }
            if (is_asset_created(name)) {
                await interaction.reply({ content: 'An asset with this name was already created!', ephemeral: true });
                return;
            }

            let ipfs_length = 0;
            try {
                ipfs_length = base58.decode(ipfs).length;
            } catch (e) {}

            if (ipfs && (!ipfs.startsWith('Qm') || ipfs_length != 34)) {
                await interaction.reply({ content: 'Your IPFS hash is invalid!', ephemeral: true });
                return;
            }
            try {
                decodeBase58 = bitcoin.address.fromBase58Check(address);
                if (decodeBase58.version !== network.pubKeyHash && decodeBase58.version !== network.scriptHash) {
                    await interaction.reply({ content: 'Your Address is not a Ravencoin address!', ephemeral: true });
                    return;
                }
            } catch (e) {
                await interaction.reply({ content: 'Your Address is invalid!', ephemeral: true });
                return;
            }
        
            await interaction.deferReply();

            const external_address_info = await external_generator.generate_next_address();
            const now = Math.round(Date.now() / 1000);

            const data = {
                name: name,
                to: address,
                ipfs: ipfs,
                recv: external_address_info,
                amount: MINT_COST,
                complete: false,
                requestor: interaction.member.id,
                server: interaction.guildId,
                timestamp: now,
                loaded: 0,
                hosted: false,
            };

            scripthash_to_asset[external_address_info.scripthash] = name;
            snowflake_to_asset[interaction.member.id] = name;
            timestamp_to_asset[now] = name;

            electrum.blockchain_scripthash_subscribe(external_address_info.scripthash);
            electrum.blockchain_scripthash_get_balance(external_address_info.scripthash).then(async res => {
                await handle_scripthash_and_amount(external_address_info.scripthash, res.confirmed, res.unconfirmed);
            });
            add_or_modify_asset_request_info(name, data);
            const embed = new_embed_from_request_data(data);

            await interaction.editReply({ embeds: [ embed ] });

        }
    });

    Promise.all([
        electrum.connect()
        .then(() => electrum.server_version('DISCORD MINTER', '1.9'))
        .then(() => {
            Object.keys(scripthash_to_asset).forEach(scripthash => {
                electrum.blockchain_scripthash_subscribe(scripthash);
                electrum.blockchain_scripthash_get_balance(scripthash).then(async res => {
                    await handle_scripthash_and_amount(scripthash, res.confirmed, res.unconfirmed);
                });
            })
        }),
        client.login(discord_token),
    ]).catch(e => console.log('Big error: ' + e));
})();