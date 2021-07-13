use kvdb::{DBTransaction, KeyValueDB};
use kvdb_web::Database as WebDatabase;

use borsh::{BorshDeserialize, BorshSerialize};
use std::marker::PhantomData;

/// Provides a more convenient interface over kvdb
pub struct KvStorage<D: KeyValueDB, T: BorshSerialize + BorshDeserialize> {
    db: D,
    _phantom: PhantomData<T>,
}

impl<T> KvStorage<WebDatabase, T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub async fn new_web(name: &str) -> KvStorage<WebDatabase, T> {
        let db = WebDatabase::open(name.to_owned(), 1).await.unwrap();

        KvStorage {
            db,
            _phantom: Default::default(),
        }
    }
}

impl<D: KeyValueDB, T> KvStorage<D, T>
where
    D: KeyValueDB,
    T: BorshSerialize + BorshDeserialize + 'static,
{
    pub fn new(db: D) -> KvStorage<D, T> {
        KvStorage {
            db,
            _phantom: Default::default(),
        }
    }

    pub fn set(&mut self, index: u32, data: &T) {
        let mut batch = self.db.transaction();
        self.set_batched(index, data, &mut batch);
        self.db.write(batch).unwrap();
    }

    pub fn set_multiple<'a, I>(&mut self, items: I)
    where
        I: IntoIterator<Item = &'a (u32, T)>,
    {
        let mut batch = self.db.transaction();

        for (index, item) in items {
            self.set_batched(*index, item, &mut batch);
        }

        self.db.write(batch).unwrap();
    }

    fn set_batched(&mut self, index: u32, data: &T, batch: &mut DBTransaction) {
        let key = index.to_le_bytes();
        let data = data.try_to_vec().unwrap();

        batch.put(0, &key, &data);
    }

    fn get(&self, index: u32) -> Option<T> {
        let key = index.to_le_bytes();

        self.db
            .get(0, &key)
            .unwrap()
            .map(|data| T::try_from_slice(data.as_slice()).unwrap())
    }
}
