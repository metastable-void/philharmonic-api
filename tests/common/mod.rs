#![allow(dead_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use philharmonic_api::{
    ApiStore, PhilharmonicApiBuilder, RequestScope, RequestScopeResolver, ResolverError,
    StubExecutor, StubLowerer,
};
use philharmonic_policy::{
    ApiSigningKey, ApiVerifyingKeyEntry, ApiVerifyingKeyRegistry, VerifyingKey,
};
use philharmonic_store::{
    ContentStore, EntityRow, EntityStore, IdentityStore, RevisionInput, RevisionRef, RevisionRow,
    StoreError,
};
use philharmonic_types::{
    ContentValue, Entity, EntityId, Identity, ScalarValue, Sha256, UnixMillis, Uuid,
};
use zeroize::Zeroizing;

pub const TEST_API_ISSUER: &str = "philharmonic-api.example";
pub const TEST_API_KID: &str = "api.test-2026-04-28-deadbeef";

const TEST_API_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const TEST_API_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

pub struct FixedResolver {
    scope: RequestScope,
}

impl FixedResolver {
    pub fn new(scope: RequestScope) -> Self {
        Self { scope }
    }
}

#[async_trait]
impl RequestScopeResolver for FixedResolver {
    async fn resolve(&self, _parts: &http::request::Parts) -> Result<RequestScope, ResolverError> {
        Ok(self.scope.clone())
    }
}

#[derive(Default)]
pub struct MockStore {
    identities_by_internal: Mutex<HashMap<Uuid, Uuid>>,
    identities_by_public: Mutex<HashMap<Uuid, Uuid>>,
    contents: Mutex<HashMap<Sha256, ContentValue>>,
    entities: Mutex<HashMap<Uuid, EntityRow>>,
    revisions: Mutex<HashMap<(Uuid, u64), RevisionRow>>,
}

impl MockStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert_entity<T: Entity>(&self, id: EntityId<T>) {
        self.insert_entity_row(id.untyped(), T::KIND);
    }

    pub fn insert_entity_row(&self, identity: Identity, kind: Uuid) {
        self.identities_by_internal
            .lock()
            .unwrap()
            .insert(identity.internal, identity.public);
        self.identities_by_public
            .lock()
            .unwrap()
            .insert(identity.public, identity.internal);
        self.entities.lock().unwrap().insert(
            identity.internal,
            EntityRow {
                identity,
                kind,
                created_at: UnixMillis(1),
            },
        );
    }

    pub fn insert_revision(&self, revision: RevisionRow) {
        self.revisions
            .lock()
            .unwrap()
            .insert((revision.entity_id, revision.revision_seq), revision);
    }
}

#[async_trait]
impl IdentityStore for MockStore {
    async fn mint(&self) -> Result<Identity, StoreError> {
        let identity = new_identity();
        self.identities_by_internal
            .lock()
            .unwrap()
            .insert(identity.internal, identity.public);
        self.identities_by_public
            .lock()
            .unwrap()
            .insert(identity.public, identity.internal);
        Ok(identity)
    }

    async fn resolve_public(&self, public: Uuid) -> Result<Option<Identity>, StoreError> {
        let Some(internal) = self
            .identities_by_public
            .lock()
            .unwrap()
            .get(&public)
            .copied()
        else {
            return Ok(None);
        };
        Ok(Some(Identity { internal, public }))
    }

    async fn resolve_internal(&self, internal: Uuid) -> Result<Option<Identity>, StoreError> {
        let Some(public) = self
            .identities_by_internal
            .lock()
            .unwrap()
            .get(&internal)
            .copied()
        else {
            return Ok(None);
        };
        Ok(Some(Identity { internal, public }))
    }
}

#[async_trait]
impl EntityStore for MockStore {
    async fn create_entity(&self, identity: Identity, kind: Uuid) -> Result<(), StoreError> {
        self.insert_entity_row(identity, kind);
        Ok(())
    }

    async fn get_entity(&self, entity_id: Uuid) -> Result<Option<EntityRow>, StoreError> {
        Ok(self.entities.lock().unwrap().get(&entity_id).cloned())
    }

    async fn append_revision(
        &self,
        entity_id: Uuid,
        revision_seq: u64,
        input: &RevisionInput,
    ) -> Result<(), StoreError> {
        self.insert_revision(RevisionRow {
            entity_id,
            revision_seq,
            created_at: UnixMillis(2),
            content_attrs: input.content_attrs.clone(),
            entity_attrs: input.entity_attrs.clone(),
            scalar_attrs: input.scalar_attrs.clone(),
        });
        Ok(())
    }

    async fn get_revision(
        &self,
        entity_id: Uuid,
        revision_seq: u64,
    ) -> Result<Option<RevisionRow>, StoreError> {
        Ok(self
            .revisions
            .lock()
            .unwrap()
            .get(&(entity_id, revision_seq))
            .cloned())
    }

    async fn get_latest_revision(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<RevisionRow>, StoreError> {
        let latest = self
            .revisions
            .lock()
            .unwrap()
            .values()
            .filter(|row| row.entity_id == entity_id)
            .max_by_key(|row| row.revision_seq)
            .cloned();
        Ok(latest)
    }

    async fn list_revisions_referencing(
        &self,
        target_entity_id: Uuid,
        attribute_name: &str,
    ) -> Result<Vec<RevisionRef>, StoreError> {
        let refs = self
            .revisions
            .lock()
            .unwrap()
            .values()
            .filter_map(|row| {
                let attr = row.entity_attrs.get(attribute_name)?;
                if attr.target_entity_id == target_entity_id {
                    Some(RevisionRef::new(row.entity_id, row.revision_seq))
                } else {
                    None
                }
            })
            .collect();
        Ok(refs)
    }

    async fn find_by_scalar(
        &self,
        kind: Uuid,
        attribute_name: &str,
        value: &ScalarValue,
    ) -> Result<Vec<EntityRow>, StoreError> {
        Ok(self.find_latest_by(kind, |revision| {
            revision.scalar_attrs.get(attribute_name) == Some(value)
        }))
    }

    async fn find_by_content(
        &self,
        kind: Uuid,
        attribute_name: &str,
        content_hash: Sha256,
    ) -> Result<Vec<EntityRow>, StoreError> {
        Ok(self.find_latest_by(kind, |revision| {
            revision.content_attrs.get(attribute_name) == Some(&content_hash)
        }))
    }
}

#[async_trait]
impl ContentStore for MockStore {
    async fn put(&self, value: &ContentValue) -> Result<(), StoreError> {
        self.contents
            .lock()
            .unwrap()
            .insert(value.digest(), value.clone());
        Ok(())
    }

    async fn get(&self, hash: Sha256) -> Result<Option<ContentValue>, StoreError> {
        Ok(self.contents.lock().unwrap().get(&hash).cloned())
    }

    async fn exists(&self, hash: Sha256) -> Result<bool, StoreError> {
        Ok(self.contents.lock().unwrap().contains_key(&hash))
    }
}

impl MockStore {
    fn find_latest_by(
        &self,
        kind: Uuid,
        predicate: impl Fn(&RevisionRow) -> bool,
    ) -> Vec<EntityRow> {
        let entities = self.entities.lock().unwrap();
        let revisions = self.revisions.lock().unwrap();
        entities
            .values()
            .filter(|row| row.kind == kind)
            .filter(|row| {
                revisions
                    .values()
                    .filter(|revision| revision.entity_id == row.identity.internal)
                    .max_by_key(|revision| revision.revision_seq)
                    .is_some_and(&predicate)
            })
            .cloned()
            .collect()
    }
}

pub fn builder(
    resolver: Arc<dyn RequestScopeResolver>,
    store: Arc<dyn ApiStore>,
    registry: ApiVerifyingKeyRegistry,
) -> PhilharmonicApiBuilder {
    PhilharmonicApiBuilder::new()
        .request_scope_resolver(resolver)
        .store(store)
        .api_verifying_key_registry(registry)
        .api_signing_key(test_api_signing_key())
        .issuer(TEST_API_ISSUER.to_string())
        .step_executor(Arc::new(StubExecutor))
        .config_lowerer(Arc::new(StubLowerer))
}

pub fn basic_builder() -> PhilharmonicApiBuilder {
    builder(
        Arc::new(FixedResolver::new(RequestScope::Operator)),
        MockStore::new(),
        test_api_verifying_key_registry(),
    )
}

pub fn new_typed_id<T: Entity>() -> EntityId<T> {
    new_identity().typed::<T>().unwrap()
}

pub fn new_identity() -> Identity {
    Identity {
        internal: Uuid::now_v7(),
        public: Uuid::new_v4(),
    }
}

pub fn test_api_signing_key() -> ApiSigningKey {
    ApiSigningKey::from_seed(Zeroizing::new(TEST_API_SEED), TEST_API_KID.to_string())
}

pub fn test_api_verifying_key_registry() -> ApiVerifyingKeyRegistry {
    let now = UnixMillis::now();
    let mut registry = ApiVerifyingKeyRegistry::new();
    registry
        .insert(
            TEST_API_KID.to_string(),
            ApiVerifyingKeyEntry {
                vk: VerifyingKey::from_bytes(&TEST_API_PUBLIC).unwrap(),
                issuer: TEST_API_ISSUER.to_string(),
                not_before: UnixMillis(now.as_i64() - 60_000),
                not_after: UnixMillis(now.as_i64() + 86_400_000),
            },
        )
        .unwrap();
    registry
}
