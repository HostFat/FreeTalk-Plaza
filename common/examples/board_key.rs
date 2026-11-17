//! Compute a board contract id from its board id (owner key, base58).
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::prelude::{ContractCode, ContractKey, Parameters};
use plaza_core::board_state::ChatBoardParametersV1;

fn main() {
    let board_id = std::env::args().nth(1).expect("board id");
    let bytes = bs58::decode(&board_id).into_vec().expect("base58");
    let owner = VerifyingKey::from_bytes(&bytes.try_into().expect("32 bytes")).expect("vk");
    let mut parameters = Vec::new();
    ciborium::ser::into_writer(&ChatBoardParametersV1 { owner }, &mut parameters).expect("params");
    let code = ContractCode::from(&include_bytes!("../../ui/public/contracts/plaza_contract.wasm")[..]);
    let key = ContractKey::from_params_and_code(Parameters::from(parameters), &code);
    println!("{}", bs58::encode(key.id().as_bytes()).into_string());
}
