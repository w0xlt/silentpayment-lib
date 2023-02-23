pub mod silentpayment;

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::hex::{FromHex, ToHex},
        OutPoint, PrivateKey, Txid, Network,
    };
    use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

    use crate::silentpayment;

    fn test_silent_recipient(silent_recipient: &silentpayment::Recipient) {
        let negated_scan_prvkey = PrivateKey::from_slice(
            &silent_recipient.m_negated_scan_seckey.secret_bytes(),
            bitcoin::Network::Bitcoin,
        )
        .unwrap();
        assert!(
            "L2HBwB2tkUdGeb2KWx2EaUWD1YjW8u4eZ7uXJfJA8u3ibkrPtvh5" == negated_scan_prvkey.to_wif()
        );
        assert!(
            "bfa2fb9b2d094a039d4b5bf76a159d028f15a8350d5c957651d6dc00af4ccf41"
                == silent_recipient.m_scan_pubkey.to_string()
        );

        let spend_keys = vec![
            (
                "KxFnFy2MjkfxGYbLWXbLztcbM5T5qQnaRaWcnCT9fySCB8XXVfRw",
                "aef5a67267768f18f8efc327ca7add15d2bb9fcd6b6f4911424565eb6db0ae63",
            ),
            (
                "L4jKwLMPDuMhwJzVv3GYbtNdqRng7Zf9tGqfCj277ATejavame9C",
                "3246572723b9aa4c601f2b5a277e9af81b61ca53de8ad88eedfb563dec8c2fce",
            ),
            (
                "KxKfkKVFoTXJipEVvLkazoFntugKGiCGB9nkzgkXTxkCx7nbQ9p4",
                "c2ece65cae45f7475f99a911754189ac2aa999eba8691eab3adb51d711f73cd2",
            ),
            (
                "L4fSSytVACWMV3MLWE7JbyjSHbZSgGFU8hZWzEijKB9dxbeSUA6b",
                "8bc5214b98ad9491ba96b0c2dbb1b9ebf45849e599ac143e487246d783da56e9",
            ),
            (
                "L4dVhof38M5gFuXkoKXgc2QqWgSpxcYdFuvSsza3RBVda73d52bA",
                "c1547a55f2f4fd3bd7dbc94ba751bc0b6108be7ff0b6b995826db2dd0aebddba",
            ),
        ];

        for (i, spend_pubkey) in silent_recipient.m_spend_keys.iter().enumerate() {
            let (seckey, pubkey) = spend_keys[i];

            let spend_prvkey =
                PrivateKey::from_slice(&spend_pubkey.0.secret_bytes(), bitcoin::Network::Bitcoin)
                    .unwrap();
            assert!(seckey == spend_prvkey.to_wif());
            assert!(pubkey == spend_pubkey.1.to_string());
        }
    }

    fn add_sender_keys(
        sender_secret_keys: &mut Vec<(SecretKey, bool)>,
        sender_pub_keys: &mut Vec<PublicKey>,
        sender_x_only_pub_keys: &mut Vec<XOnlyPublicKey>,
    ) {
        let secp = secp256k1::Secp256k1::new();

        let spend_keys = vec![
            (
                "KxeDWuvKtXfBxLGmP6ZT4crvbamCnicJg2xgkgESSLURYyr6kVvu",
                false,
            ),
            (
                "L3nddfqwDWmAeskCjWwLnnF5ZFt1BZXFxNav92eA3sS7kKbh3nT3",
                false,
            ),
            ("KyAWmQjXmkNL8xFaFc3Kp4S4SJSqYmGfvdePvuGwpsb7YyWAW5wS", true),
            ("KzrGQWApg8wpX4pCQM1chMrJhgSfzmwS8fZLfUDujA73sJNgreeF", true),
        ];

        for (wif, is_taproot) in spend_keys.iter() {
            let prvkey = PrivateKey::from_wif(wif).unwrap();
            let seckey = secp256k1::SecretKey::from_slice(&prvkey.inner.secret_bytes()).unwrap();

            sender_secret_keys.push((seckey, *is_taproot));

            if *is_taproot {
                sender_x_only_pub_keys.push(seckey.x_only_public_key(&secp).0)
            } else {
                sender_pub_keys.push(seckey.public_key(&secp))
            }
        }
    }

    fn get_outpoints() -> Vec<OutPoint> {
        let outpoint1 = OutPoint {
            txid: Txid::from_hex(
                "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22",
            )
            .unwrap(),
            vout: 4,
        };

        let outpoint2 = OutPoint {
            txid: Txid::from_hex(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .unwrap(),
            vout: 7,
        };

        let mut tx_outpoints: Vec<OutPoint> = Vec::new();
        tx_outpoints.push(outpoint1);
        tx_outpoints.push(outpoint2);

        tx_outpoints
    }

    #[test]
    fn it_works() {
        let secp = secp256k1::Secp256k1::new();

        let recipient_spend_prv =
            PrivateKey::from_wif("L4mGgWaqFknPASp5cwrAbqhEcLuHqDMzm4UjJyAo1A7f85XPiGVU").unwrap();

        let recipient_spend_seckey =
            secp256k1::SecretKey::from_slice(&recipient_spend_prv.inner.secret_bytes()).unwrap();

        let mut silent_recipient = silentpayment::Recipient::new(&recipient_spend_seckey, 5);

        test_silent_recipient(&silent_recipient);

        let mut sender_secret_keys: Vec<(SecretKey, bool)> = Vec::new();
        let mut sender_pub_keys: Vec<PublicKey> = Vec::new();
        let mut sender_x_only_pub_keys: Vec<XOnlyPublicKey> = Vec::new();

        add_sender_keys(
            &mut sender_secret_keys,
            &mut sender_pub_keys,
            &mut sender_x_only_pub_keys,
        );

        let combined_tx_pubkeys = silentpayment::Recipient::combine_public_keys(
            &sender_pub_keys,
            &sender_x_only_pub_keys,
        );

        assert!(
            combined_tx_pubkeys.to_string()
                == "031ea6a65ac33fd26dd296299dbce0b40b8105af395c68655bc303a943f0f75025"
        );

        let tx_outpoints = get_outpoints();
        let (truncated_hash, outpoint_hash) = silentpayment::hash_outpoints(&tx_outpoints);
        assert!(
            outpoint_hash.to_string()
                == "db30d92d7e60ff38f4ad821d2d94996c0151f0706178d081254732808a9066f5"
        );
        assert!(truncated_hash.to_hex() == "bd37fdb110dc3df7");
        silent_recipient.set_sender_public_key_outpoints(&combined_tx_pubkeys, &tx_outpoints);

        let recipient_shared_secret = PrivateKey::from_slice(
            &silent_recipient.m_shared_secret.unwrap().secret_bytes(),
            bitcoin::Network::Bitcoin,
        )
        .unwrap();

        assert!(
            recipient_shared_secret.to_wif()
                == "Kx2qKiKqFMSRerYZeEUz1d9MRpKATczVXuJinaJZcAPgaTPaJC5v"
        );

        let results = vec![
            (
                "1669506efdf338f5610a6b3314b7a0ad40940383f3314b0af6f4ab9708fd00f9", // sender_tweaked_pubkey and recipient_pub_key
                "Ky4uQ2E3aRqnCASaN4Z27EebvH3kSU527w5ewdQbRtMmiDLWqgyr", // recipient_prv_key
            ),
            (
                "6ceda6fddc975987b642ef3d589b9028ad0b977316fcdc1ad0d7f92c42b60477",
                "L5YT5PZ54aXXrvqjmaEDiEQeQdPLicwbadQhN9yYs5PEGfjzwEqY",
            ),
            (
                "6669869ddb5b0e10e47f3ff76d5258172c7f6b1305993a51072d0354e196d0d3",
                "Ky8ntNgwe8h8eS5jmsiG79HoU7GysmUhsWMoA7hyDsfnVCZP7cvJ",
            ),
        ];

        for identifier in 0..3 {
            let (recipient_scan_pubkey, recipient_spend_pubkey) =
                silent_recipient.get_address(identifier);

            let silent_sender = silentpayment::Sender::new(
                &sender_secret_keys,
                &tx_outpoints,
                &recipient_scan_pubkey,
            );

            assert!(silent_sender.m_shared_secret == silent_recipient.m_shared_secret.unwrap());

            let sender_tweaked_pubkey = silent_sender.tweak(&recipient_spend_pubkey);
            assert!(sender_tweaked_pubkey.to_string() == results[identifier].0);

            let (recipient_sec_key, recipient_pub_key) = silent_recipient.tweak(identifier);
            assert!(sender_tweaked_pubkey == recipient_pub_key);
            let recipient_prv_key = PrivateKey::from_slice(
                &recipient_sec_key.secret_bytes(),
                bitcoin::Network::Bitcoin,
            )
            .unwrap();
            assert!(recipient_prv_key.to_wif() == results[identifier].1);

            assert!(recipient_pub_key == recipient_sec_key.x_only_public_key(&secp).0);
        }
    }

    #[test]
    fn test_hrp_case() {
        let recipient_spend_prv =
            PrivateKey::from_wif("cP8cbSymcBmE36ghaM1FFEUdCvphVeeYFvnyiHMSWVEa9i6jB2Th").unwrap();

        let recipient_spend_seckey =
            secp256k1::SecretKey::from_slice(&recipient_spend_prv.inner.secret_bytes()).unwrap();

        let silent_recipient = silentpayment::Recipient::new(&recipient_spend_seckey, 6);

        let results = vec![
            "sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwl2thhzr9ze7cr4nlz7ragedagakt4u288vga50gjrp4vd23krsgtq67qrmt",
            "sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwltul72dwazf904zkytg29xnxwycfn2nwez45cscvsj3zgwdtgf4fglcq4ml",
            "sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlp6q7ql2u6rxfv6kt8qre26rn3cpmc3jyw8d6zatvaqrw3hszp8kqvrwnt6",
            "sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlrmcmqpqtlrhypawsd5wm0uzxgthaazkmz28zk28yl69zc8s38p3qangva0",
            "sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlt8tjeraq5ygdemakam9eux8d9qrp3ex285z4nfvnx9kcfaq0l22qtltc29",
            "sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlgcqk508uxj3ekneu9k9q4jnwalyds69lun7kclz2sy38musrdnycxaw9s3"
        ];

        for i in 0..results.len() {
            let encoded_addr = silent_recipient.get_encoded_address(i, Network::Regtest);

            assert!(encoded_addr == results[i]);
        }
    }

    #[test]
    fn test_decode() {

        let expected_spend_pubkey = "d1e73076293336f483265b19191ec2c2a66af0f5e3fd732c286dad070c6b03be";

        let results = [
            ("sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwl2thhzr9ze7cr4nlz7ragedagakt4u288vga50gjrp4vd23krsgtq67qrmt", "a5dee219459f60759fc5e1f5196f51db2ebc51cec4768f44861ab1aa8d87042c"),
            ("sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwltul72dwazf904zkytg29xnxwycfn2nwez45cscvsj3zgwdtgf4fglcq4ml", "be7fca6bba2495f51588b428a6999c4c266a9bb22ad310c32128890e6ad09aa5"),
            ("sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlp6q7ql2u6rxfv6kt8qre26rn3cpmc3jyw8d6zatvaqrw3hszp8kqvrwnt6", "1d03c0fab9a1992cd596700f2ad0e71c07788c88e3b742ead9d00dd1bc0413d8"),
            ("sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlrmcmqpqtlrhypawsd5wm0uzxgthaazkmz28zk28yl69zc8s38p3qangva0", "3de3600817f1dc81eba0da3b6fe08c85dfbd15b6251c5651c9fd14583c2270c4"),
            ("sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlt8tjeraq5ygdemakam9eux8d9qrp3ex285z4nfvnx9kcfaq0l22qtltc29", "b3ae591f414221b9df6ddd973c31da500c31c9947a0ab34b2662db09e81ff528"),
            ("sprt168nnqa3fxvm0fqextvv3j8kzc2nx4u84u07hxtpgdkkswrrtqwlgcqk508uxj3ekneu9k9q4jnwalyds69lun7kclz2sy38musrdnycxaw9s3", "8c02d479f86947369e785b141594dddf91b0d17fc9fad8f8950244fbe406d993"),
        ];

        for (address, expected_scan_pubkey) in results {
            let (scan_pubkey,spend_pubkey) = silentpayment::decode_address(address);

            assert!(scan_pubkey.to_string() == expected_scan_pubkey);
            assert!(spend_pubkey.to_string() == expected_spend_pubkey);
        }
    }
}
