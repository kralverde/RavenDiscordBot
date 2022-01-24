const ElectrumCli = require('electrum-client');
const bitcoin = require('bitcoinjs-lib');
const bip39 = require('bip39');
const bip32 = require('bip32');
const ecc = require('tiny-secp256k1');
const electrumClient = require('electrum-client');
const leveldb = require('level');
const Cache = require('lru-cache-node');
const crypto = require('crypto');
const mutex = require('async-mutex');
require('dotenv').config();
const fs = require('fs');

const { Client, Intents, MessageEmbed } = require('discord.js');
const { SlashCommandBuilder } = require('@discordjs/builders');
const { REST } = require('@discordjs/rest');
const { Routes } = require('discord-api-types/v9');

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
  };

const MAIN_ASSET = 'TEST';
const COIN = 100000000;

/* Electrum JSON RPC */
/*
const elc = new ElectrumCli(50002, 'rvn4lyfe.com', 'tls');

elc.subscribe.on('blockchain.headers.subscribe', (res) => console.log(res));
elc.connect()
    .then(() => elc.server_version("TESTING", "1.9"))
    .then((ver) => console.log(ver))
    .then(() => elc.blockchain_headers_subscribe())
    .then((res) => console.log(res))
    .then(() => elc.close());
*/
/* END JSON RPC */

/* CRYPTO */
/*
const child = root
    .deriveHardened(44)
    .deriveHardened(175)
    .deriveHardened(0)
    .derive(0)
    .derive(0);

const { address } = bitcoin.payments.p2pkh({
    pubkey: child.publicKey,
    network: RAVENCOIN
});


let script = bitcoin.address.toOutputScript(address, RAVENCOIN);

*/

/* Definitions */

const network = RAVENCOIN_TESTNET;

function script_to_scripthash(script) {
    return crypto.createHash('sha256').update(script).digest('hex').slice(0, 64);
}

class AddressStateBuilder {
    constructor(root, starting_index, db, db_key) {
        this._root = root;
        this._db = db;
        this._db_key = db_key;
        this._index = starting_index;
        this._semaphore = new mutex.Mutex();
    }
    generate_next_address() {
        return this._semaphore.runExclusive(() => {
            const index = this._index;
            this._index += 1;
            const child = this._root.derive(index);
            const { address } = bitcoin.payments.p2pkh({
                pubkey: child.publicKey,
                network: network
            });
            const scripthash = script_to_scripthash(bitcoin.address.toOutputScript(address, network));
            return this._db.put(this._db_key, this._index).then(() => {
                return {
                    index: index,
                    address: address,
                    scripthash: scripthash
                };
            }).catch(err => {
                //TODO: Some kind of exit
                console.log(err);
            });
        });
    }
    get_previous_address() {
        const index = this._index - 1;
        const child = this._root.derive(index);
        const { address } = bitcoin.payments.p2pkh({
            pubkey: child.publicKey,
            network: network
        });
        const scripthash = script_to_scripthash(bitcoin.address.toOutputScript(address, network));
        return {
            index: index,
            address: address,
            scripthash: scripthash
        }
    }
}

/* End Definitions */

/* File Structure */

const requests_dir = __dirname + '/requests';
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

/* End File Structure */

/* Constants */

(async () => {
    const mnemonic = process.env.MNEMONIC;
    const discord_token = process.env.DISCORD_TOKEN;
    const discord_id = process.env.DISCORD_ID;

    const state_db = leveldb('state_db');

    var external_index;
    var internal_index;
    var asset_index;
    var discord_channel_id;

    await get_from_database_or_default_to('external_index', 0).then(x => external_index = Number(x));
    await get_from_database_or_default_to('internal_index', 0).then(x => internal_index = Number(x));
    await get_from_database_or_default_to('asset_index', 1).then(x => asset_index = Number(x));
    await get_from_database_or_default_to('discord_channel_id', -1).then(x => discord_channel_id = Number(x));

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
    
    /* End Constants */
    
    /* Utility Functions */
    
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

    function get_from_database_or_default_to(key, def) {
        return state_db.get(key).catch(() => def);
    }
    
    function is_asset_valid(name) {
        let re = new RegExp("^[-A-Za-z0-9@$%&*()[\\]{}_.?:]{1,20}$");
        return name.match(re);
    }
    
    function is_asset_created(name) {
        return name in _created_assets || name in _waiting_assets;
    }
    
    function add_or_modify_asset_request_info(asset, data) {
        _waiting_assets[asset] = data;
        fs.writeFileSync(uncompleted_requests_dir+'/'+asset, JSON.stringify(data));
    }

    function remove_asset_request(asset) {
        delete _waiting_assets[asset];
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

    function handle_scripthash_and_amount(scripthash, confirmed, unconfirmed) {
        try {
            const asset = scripthash_to_asset[scripthash];
            const data = _waiting_assets[asset];
            if (confirmed > (data.amount / COIN)) {

            } else if ((confirmed + unconfirmed) > (data.amount / COIN)) {

            } else {
                console.log(scripthash);
                console.log(confirmed);
                console.log(unconfirmed);
            }
        } catch (e) {} 
    }

    /* End Utility */
    
    /* Electrum Client */
    
    const electrum = new ElectrumCli(50003, 'rvn4lyfe.com', 'tls');
    electrum.subscribe.on('blockchain.scripthash.subscribe', function (scripthash, status) {
        electrum.blockchain_scripthash_get_balance(address_info.scripthash).then(res => {
            handle_scripthash_and_amount(scripthash, res.confirmed, res.unconfirmed);
        });
    });
    
    /* Initialize Discord Commands */
    
    const commands = [
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
    
    const client = new Client({ intents: [ Intents.FLAGS.GUILDS ] });
    
    client.on('interactionCreate', async interaction => {
        if (!interaction.isCommand()) return;
        if (interaction.commandName === 'setchannel') {
            console.log(interaction.member.permissions);
        } else if (interaction.commandName === 'alive') {
            await interaction.reply({ content: 'Good to go :smile:', ephemeral: true });
        } else if (interaction.commandName === 'info') {
            await interaction.reply('This bot lets you mint unique assets to an address of your choice for a fee of 10RVN. This bot will also host a file to associate with your unique asset for an extra 10RVN. Run /mint with (optionally) no IPFS value for more information.');
        } else if (interaction.commandName === 'mint') {
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
            if (ipfs && (!ipfs.startsWith('Qm') || ipfs.length != 48)) {
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

            external_generator.generate_next_address().then(address_info => {

                const now = Math.round(Date.now() / 1000);

                const data = {
                    name: name,
                    to: address,
                    ipfs: ipfs,
                    recv: address_info,
                    amount: 10,
                    complete: false,
                    requestor: interaction.member.id,
                    timestamp: now
                };

                scripthash_to_asset[address_info.scripthash] = name;
                snowflake_to_asset[interaction.member.id] = name;
                timestamp_to_asset[now] = name;

                electrum.blockchain_scripthash_subscribe(address_info.scripthash);
                electrum.blockchain_scripthash_get_balance(address_info.scripthash).then(res => {
                    handle_scripthash_and_amount(address_info.scripthash, res.confirmed, res.unconfirmed);
                });
                add_or_modify_asset_request_info(name, data);
                return new_embed_from_request_data(data);
                
            }).then(async (embed) => {
                await interaction.editReply({ embeds: [ embed ] });
            });
        }
    });

    Promise.all([
        electrum.connect()
        .then(() => electrum.server_version('ASSET MINTER', '1.9'))
        .then(() => {
            Object.keys(scripthash_to_asset).forEach(scripthash => {
                electrum.blockchain_scripthash_subscribe(scripthash);
                electrum.blockchain_scripthash_get_balance(scripthash).then(res => {
                    handle_scripthash_and_amount(scripthash, res.confirmed, res.unconfirmed);
                });
            })
        }),
        client.login(discord_token),
    ]);
    /* End Discord Bot */
    
    /* End Electrum Client */
    
    
    /* Begin Script */
})();