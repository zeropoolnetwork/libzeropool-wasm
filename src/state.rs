use kvdb_web::Database;
use libzeropool::fawkes_crypto::{BorshDeserialize, BorshSerialize};
use libzeropool::native::account::Account;
use libzeropool::native::note::Note;
use libzeropool::native::params::PoolBN256;
use libzeropool::POOL_PARAMS;

use crate::kv_storage::KvStorage;
use crate::Fr;
use std::ops::Deref;

pub type MerkleTree = crate::merkle::MerkleTree<'static, Database, PoolBN256>;
pub type TxStorage = KvStorage<Database, Transaction>;

const MERKLE_DB_NAME: &str = "zeropool.smt";
const TX_DB_NAME: &str = "zeropool.txs";

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub enum Transaction {
    Own(Account<Fr>, Vec<Note<Fr>>),
    Notes(Vec<Note<Fr>>),
}

pub struct State {
    pub tree: MerkleTree,
    pub transactions: KvStorage<Database, Transaction>,
    pub index: u32,
}

impl State {
    // FIXME: Get latest account index from state
    pub fn new(index: u32) -> Self {
        State {
            tree: MerkleTree::new_web(MERKLE_DB_NAME, &POOL_PARAMS),
            transactions: KvStorage::new_web(TX_DB_NAME),
            index,
        }
    }
}
