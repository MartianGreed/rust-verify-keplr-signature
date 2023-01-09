use ecdsa::signature::DigestVerifier;
use k256::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(rename = "type")]
    pub sig_type: String,
    #[serde(rename = "value")]
    pub sig_value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Signature {
    pub pub_key: PublicKey,
    pub signature: String,
}

fn generate_amino_transaction_string(signer: &str, data: &str) -> String {
    format!("{{\"account_number\":\"0\",\"chain_id\":\"\",\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"\",\"msgs\":[{{\"type\":\"sign/MsgSignData\",\"value\":{{\"data\":\"{}\",\"signer\":\"{}\"}}}}],\"sequence\":\"0\"}}", data, signer)
}

pub fn verify_arbitrary(
    account_addr: &str,
    pubkey: &str,
    data: &[u8],
    signature: &Signature,
) -> bool {
    let rpc_signature_to_compare = hex::encode(base64::decode(&signature.signature).unwrap());
    let signature: k256::ecdsa::Signature =
        ecdsa::Signature::from_str(&rpc_signature_to_compare).unwrap();

    let digest = Sha256::new_with_prefix(generate_amino_transaction_string(
        account_addr,
        &base64::encode(data),
    ));

    let pk = tendermint::PublicKey::from_raw_secp256k1(base64::decode(pubkey).unwrap().as_slice())
        .unwrap();
    let vk = pk.secp256k1().unwrap();

    let verification = vk.verify_digest(digest, &signature);

    verification.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_signature() -> Signature {
        Signature {
            pub_key: PublicKey {
                sig_type: String::from("tendermint/PubKeySecp256k1"),
                sig_value: String::from("Avt8e5UqfoRAh0RBUzHCu9arv7UFEFdfcv657h6TtSZE"),
            },
            signature: String::from("9PrDYrTb1tv/TALC/lgRIIekfwNMBPOra0QpaAqNCbADXT8vR9n0SS7L2OSaXma3UMrOLGTbWlLDImNhcZVgzA==")
        }
    }

    #[test]
    fn it_verifies_signature() {
        let signature = get_signature();

        assert_eq!(
            true,
            verify_arbitrary(
                "juno105asxv7pt0fzxlz642pf4svm29u39zxzdq2ad5",
                "Avt8e5UqfoRAh0RBUzHCu9arv7UFEFdfcv657h6TtSZE",
                b"test",
                &signature
            )
        );
    }

    #[test]
    fn it_doesnt_verifies_signature() {
        let signature = get_signature();

        assert_eq!(
            false,
            verify_arbitrary(
                "juno105asxv7pt0fzxlz642pf4svm29u39zxzdq2ad5",
                "Avt8e5UqfoRAh0RBUzHCu9arv7UFEFdfcv657h6TtSZE",
                b"not test",
                &signature
            )
        );
    }
}
