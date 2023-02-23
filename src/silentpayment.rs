use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    OutPoint, bech32::{encode, ToBase32, Variant, decode, FromBase32}, Network,
};
use secp256k1::{
    ecdh::{self, SharedSecret},
    Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};

pub struct Recipient {
    pub m_negated_scan_seckey: SecretKey,
    pub m_shared_secret: Option<SharedSecret>,
    pub m_spend_keys: Vec<(SecretKey, XOnlyPublicKey)>,
    pub m_scan_pubkey: XOnlyPublicKey,
}

pub struct Sender {
    pub m_shared_secret: SharedSecret,
}

impl Recipient {
    pub fn new(spend_seckey: &SecretKey, pool_size: u32) -> Recipient {
        let secp = Secp256k1::new();

        let scan_sec_key =
            SecretKey::from_hashed_data::<sha256::Hash>(&spend_seckey.secret_bytes());
        let (m_scan_pubkey, parity) = scan_sec_key.x_only_public_key(&secp);

        let mut m_negated_scan_seckey = scan_sec_key;
        if parity == Parity::Odd {
            m_negated_scan_seckey = m_negated_scan_seckey.negate();
        }

        let mut m_spend_keys: Vec<(SecretKey, XOnlyPublicKey)> = Vec::new();

        for identifier in 0..pool_size {
            let mut spend_seckey1 = spend_seckey.clone();
            let (_, parity1) = spend_seckey1.x_only_public_key(&secp);

            if parity1 == Parity::Odd {
                spend_seckey1 = spend_seckey1.negate();
            }

            let identifier_bytes = identifier.to_le_bytes();

            let mut tweak_bytes = [0u8; 32];

            for (i, item) in identifier_bytes.iter().enumerate() {
                if i >= 32 {
                    break;
                }
                tweak_bytes[31 - i] = *item;
            }

            let tweak = Scalar::from_le_bytes(tweak_bytes).unwrap();

            let mut spend_seckey2 = spend_seckey1.add_tweak(&tweak).unwrap();

            let (spend_pubkey2, parity2) = spend_seckey2.x_only_public_key(&secp);

            if parity2 == Parity::Odd {
                spend_seckey2 = spend_seckey2.negate();
            }

            m_spend_keys.push((spend_seckey2, spend_pubkey2));
        }

        Recipient {
            m_negated_scan_seckey,
            m_shared_secret: None,
            m_spend_keys,
            m_scan_pubkey,
        }
    }

    pub fn combine_public_keys(
        sender_public_keys: &Vec<PublicKey>,
        sender_x_only_public_key: &Vec<XOnlyPublicKey>,
    ) -> PublicKey {
        let mut v_pubkeys: Vec<PublicKey> = Vec::new();
        v_pubkeys.append(&mut sender_public_keys.clone());

        for xpubkey in sender_x_only_public_key.iter() {
            v_pubkeys.push(xpubkey.public_key(Parity::Even));
        }

        let ref_pubkeys = &v_pubkeys.iter().collect::<Vec<_>>();

        PublicKey::combine_keys(ref_pubkeys.as_slice()).unwrap()
    }

    pub fn set_sender_public_key_hash(
        &mut self,
        sender_x_only_public_key: &PublicKey,
        outpoint_hash: &sha256::Hash,
    ) {
        let binding = outpoint_hash.to_vec();
        let hash: &[u8; 32] = binding.as_slice().try_into().unwrap();

        let tweak = Scalar::from_be_bytes(*hash).unwrap();

        let tweaked_scan_seckey = self.m_negated_scan_seckey.mul_tweak(&tweak).unwrap();

        self.m_shared_secret = Some(ecdh::SharedSecret::new(
            &sender_x_only_public_key,
            &tweaked_scan_seckey,
        ));
    }

    pub fn set_sender_public_key_outpoints(
        &mut self,
        sender_x_only_public_key: &PublicKey,
        tx_outpoints: &Vec<OutPoint>,
    ) {
        let (_, outpoint_hash) = hash_outpoints(&tx_outpoints);
        self.set_sender_public_key_hash(sender_x_only_public_key, &outpoint_hash);
    }

    pub fn get_address(&self, identifier: usize) -> (XOnlyPublicKey, XOnlyPublicKey) {
        let (_, spend_pubkey) = self.m_spend_keys[identifier];
        (self.m_scan_pubkey, spend_pubkey)
    }

    pub fn get_hrp(network: Network) -> String {
        if network == Network::Bitcoin {
            "sp".to_string()
        } else if network == Network::Regtest {
            "sprt".to_string()
        } else {
            "tsp".to_string()
        }
    }

    pub fn get_encoded_address(&self, identifier: usize, network: Network) -> String {
        let (scan_pubkey, spend_pubkey) = self.get_address(identifier);

        let scan_pubkey_bytes = scan_pubkey.serialize();

        let spend_pubkey_bytes = spend_pubkey.serialize();

        let address = [scan_pubkey_bytes, spend_pubkey_bytes].concat();

        let hrp = Self::get_hrp(network);

        encode(hrp.as_str(), address.to_base32(), Variant::Bech32m).unwrap()
    }

    pub fn tweak(&self, identifier: usize) -> (SecretKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();

        let (seckey, xonly_pubkey) = self.m_spend_keys[identifier];

        let tweak = Scalar::from_be_bytes(self.m_shared_secret.unwrap().secret_bytes()).unwrap();

        let result_xonly_pubkey = xonly_pubkey.add_tweak(&secp, &tweak).unwrap().0;

        let result_seckey = seckey.add_tweak(&tweak).unwrap();

        (result_seckey, result_xonly_pubkey)
    }
}

impl Sender {
    pub fn new(
        sender_secret_keys: &Vec<(SecretKey, bool)>,
        tx_outpoints: &Vec<OutPoint>,
        recipient_scan_xonly_pubkey: &XOnlyPublicKey,
    ) -> Sender {
        if sender_secret_keys.is_empty() {
            panic!("There is no keys !");
        }

        let (sender_seckey, is_taproot) = &sender_secret_keys[0];

        let mut sum_seckey = sender_seckey.clone();

        let secp = Secp256k1::new();

        let (_, parity) = sum_seckey.x_only_public_key(&secp);

        if *is_taproot && parity == Parity::Odd {
            sum_seckey = sum_seckey.negate();
        }

        if sender_secret_keys.len() > 1 {
            for i in 1..sender_secret_keys.len() {
                let (sender_seckey, is_taproot) = &sender_secret_keys[i];
                let mut temp_key = sender_seckey.clone();

                let (_, parity) = temp_key.x_only_public_key(&secp);

                if *is_taproot && parity == Parity::Odd {
                    temp_key = temp_key.negate();
                }

                let tweak = Scalar::from_be_bytes(temp_key.secret_bytes()).unwrap();

                sum_seckey = sum_seckey.add_tweak(&tweak).unwrap();
            }
        }

        let recipient_scan_pubkey = recipient_scan_xonly_pubkey.public_key(Parity::Even);

        let (_, outpoint_hash) = hash_outpoints(tx_outpoints);
        let binding = outpoint_hash.to_vec();
        let hash: &[u8; 32] = binding.as_slice().try_into().unwrap();
        let tweak = Scalar::from_be_bytes(*hash).unwrap();

        let tweaked_sum_seckey = sum_seckey.mul_tweak(&tweak).unwrap();

        let m_shared_secret = ecdh::SharedSecret::new(&recipient_scan_pubkey, &tweaked_sum_seckey);

        Sender { m_shared_secret }
    }

    pub fn tweak(&self, spend_xonly_pubkey: &XOnlyPublicKey) -> XOnlyPublicKey {
        let secp = Secp256k1::new();

        let tweak = Scalar::from_be_bytes(self.m_shared_secret.secret_bytes()).unwrap();

        spend_xonly_pubkey.add_tweak(&secp, &tweak).unwrap().0
    }
}

pub fn hash_outpoints(sender_x_only_public_key: &Vec<OutPoint>) -> ([u8; 8], sha256::Hash) {
    let mut sha_engine = sha256::Hash::engine();

    for output in sender_x_only_public_key.iter() {
        sha_engine.input(&output.txid.to_vec().as_slice());

        let mut hash_n = [0u8; 32];
        for (i, item) in output.vout.to_ne_bytes().iter().enumerate() {
            if i >= 32 {
                break;
            }
            hash_n[i] = *item;
        }
        sha_engine.input(&hash_n);
    }

    let result_hash = sha256::Hash::from_engine(sha_engine);

    let binding = result_hash.clone().to_vec();
    let result_hash_bytes = binding.as_slice();

    let mut truncated_hash: [u8; 8] = [0; 8];

    for i in 0..truncated_hash.len() {
        truncated_hash[i] = result_hash_bytes[i];
    }

    let mut sha_engine2 = sha256::Hash::engine();
    sha_engine2.input(&truncated_hash);
    let final_hash = sha256::Hash::from_engine(sha_engine2);

    (truncated_hash, final_hash)
}

pub fn decode_address(address: &str) -> (XOnlyPublicKey, XOnlyPublicKey) {
    let decoded = decode(address).unwrap();
    assert!(["sp", "sprt", "tsp"].contains(&decoded.0.as_str()));
    assert_eq!(decoded.2, Variant::Bech32m);

    let data = Vec::from_base32(&decoded.1).unwrap();

    let scan_pubkey_start = data.len() - 32;
    let spend_pubkey_start = scan_pubkey_start - 32;

    let scan_pubkey_byte = &data[scan_pubkey_start..];
    let spend_pubkey_byte = &data[spend_pubkey_start..scan_pubkey_start];

    let scan_pubkey = XOnlyPublicKey::from_slice(scan_pubkey_byte).unwrap();
    let spend_pubkey = XOnlyPublicKey::from_slice(spend_pubkey_byte).unwrap();

    (scan_pubkey, spend_pubkey)
}