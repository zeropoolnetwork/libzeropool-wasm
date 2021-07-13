use js_sys::Array;
use libzeropool::constants;
use libzeropool::fawkes_crypto::native::poseidon::MerkleProof as NativeMerkleProof;
use libzeropool::native::account::Account as NativeAccount;
use libzeropool::native::note::Note as NativeNote;
use libzeropool::native::params::{PoolBN256, PoolParams};
use libzeropool::native::tx::{
    TransferPub as NativeTransferPub, TransferSec as NativeTransferSec, Tx as NativeTx,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub type Fr = <PoolBN256 as PoolParams>::Fr;
pub type Fs = <PoolBN256 as PoolParams>::Fs;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<Note>")]
    pub type Notes;

    #[wasm_bindgen(typescript_type = "Array<string>")]
    pub type MerkleProofSibling;

    #[wasm_bindgen(typescript_type = "Array<bool>")]
    pub type MerkleProofPath;
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Note {
    inner: NativeNote<Fr>,
}

impl Note {
    pub fn inner(&self) -> &NativeNote<Fr> {
        &self.inner
    }
}

#[wasm_bindgen]
impl Note {
    #[wasm_bindgen(getter)]
    pub fn d(&self) -> String {
        self.inner.d.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn p_d(&self) -> String {
        self.inner.p_d.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn b(&self) -> String {
        self.inner.b.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn t(&self) -> String {
        self.inner.t.to_num().to_string()
    }
}

impl From<NativeNote<Fr>> for Note {
    fn from(note: NativeNote<Fr>) -> Note {
        Note { inner: note }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Account {
    inner: NativeAccount<Fr>,
}

impl Account {
    pub fn inner(&self) -> &NativeAccount<Fr> {
        &self.inner
    }
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(getter)]
    pub fn eta(&self) -> String {
        self.inner.eta.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn i(&self) -> String {
        self.inner.i.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn b(&self) -> String {
        self.inner.b.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn e(&self) -> String {
        self.inner.e.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn t(&self) -> String {
        self.inner.t.to_num().to_string()
    }
}

impl From<NativeAccount<Fr>> for Account {
    fn from(account: NativeAccount<Fr>) -> Account {
        Account { inner: account }
    }
}

#[wasm_bindgen]
pub struct Pair {
    account: Account,
    notes: Vec<Note>,
}

impl Pair {
    pub fn new(account: Account, notes: Vec<Note>) -> Self {
        Pair { account, notes }
    }
}

#[wasm_bindgen]
impl Pair {
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> Account {
        self.account.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn notes(&self) -> Notes {
        self.notes
            .iter()
            .cloned()
            .map(JsValue::from)
            .collect::<Array>()
            .unchecked_into::<Notes>()
    }
}

impl From<(&NativeAccount<Fr>, &[NativeNote<Fr>])> for Pair {
    fn from((account, notes): (&NativeAccount<Fr>, &[NativeNote<Fr>])) -> Self {
        let account = Account::from(account.clone());
        let notes = notes.iter().map(|note| Note::from(note.clone())).collect();

        Pair { account, notes }
    }
}

#[wasm_bindgen]
pub struct TransferPub {
    inner: NativeTransferPub<Fr>,
}

impl TransferPub {
    pub fn new(inner: NativeTransferPub<Fr>) -> Self {
        TransferPub { inner }
    }
}

#[wasm_bindgen]
impl TransferPub {
    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> String {
        self.inner.nullifier.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn delta(&self) -> String {
        self.inner.delta.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn memo(&self) -> String {
        self.inner.memo.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn out_commit(&self) -> String {
        self.inner.out_commit.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        self.inner.root.to_string()
    }
}

#[wasm_bindgen]
pub struct TransferSec {
    inner: NativeTransferSec<Fr>,
}

impl TransferSec {
    pub fn new(inner: NativeTransferSec<Fr>) -> Self {
        TransferSec { inner }
    }
}

#[wasm_bindgen]
impl TransferSec {
    #[wasm_bindgen(getter, js_name = eddsaA)]
    pub fn eddsa_a(&self) -> String {
        self.inner.eddsa_a.to_string()
    }

    #[wasm_bindgen(getter, js_name = eddsaR)]
    pub fn eddsa_r(&self) -> String {
        self.inner.eddsa_r.to_string()
    }

    #[wasm_bindgen(getter, js_name = eddsaS)]
    pub fn eddsa_s(&self) -> String {
        self.inner.eddsa_s.to_string()
    }

    // #[wasm_bindgen(getter, js_name = inProof)]
    // pub fn in_proof(&self) -> String {
    //     self.inner.in_proof.to_string()
    // }

    #[wasm_bindgen(getter)]
    pub fn tx(&self) -> Tx {
        Tx {
            inner: self.inner.tx.clone(),
        }
    }
}

#[wasm_bindgen]
pub struct Tx {
    inner: NativeTx<Fr>,
}

#[wasm_bindgen]
impl Tx {
    #[wasm_bindgen(getter)]
    pub fn input(&self) -> Pair {
        Pair::from((&self.inner.input.0, self.inner.input.1.as_slice()))
    }

    #[wasm_bindgen(getter)]
    pub fn output(&self) -> Pair {
        Pair::from((&self.inner.output.0, self.inner.output.1.as_slice()))
    }
}

#[wasm_bindgen]
pub struct MerkleProof {
    inner: NativeMerkleProof<Fr, { constants::HEIGHT }>,
}

impl MerkleProof {
    pub fn inner(&self) -> &NativeMerkleProof<Fr, { constants::HEIGHT }> {
        &self.inner
    }
}

#[wasm_bindgen]
impl MerkleProof {
    #[wasm_bindgen(getter)]
    pub fn sibling(&self) -> MerkleProofSibling {
        self.inner
            .sibling
            .iter()
            .map(|sibling| JsValue::from(sibling.to_string()))
            .collect::<Array>()
            .unchecked_into::<MerkleProofSibling>()
    }

    #[wasm_bindgen(getter)]
    pub fn path(&self) -> MerkleProofPath {
        self.inner
            .path
            .iter()
            .copied()
            .map(JsValue::from)
            .collect::<Array>()
            .unchecked_into::<MerkleProofPath>()
    }
}
