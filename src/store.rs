//! Store trait surface required by the API layer.

use std::sync::Arc;

use async_trait::async_trait;
use philharmonic_store::{
    ContentStore, EntityRow, EntityStore, IdentityStore, RevisionInput, RevisionRef, RevisionRow,
    StoreError, StoreExt,
};
use philharmonic_types::{ContentValue, Identity, ScalarValue, Sha256, Uuid};

/// Storage capabilities required by the API middleware and handlers.
///
/// Authentication needs identity/entity lookups. Authorization also needs
/// content-addressed blobs because role permission documents live in content
/// slots.
pub trait ApiStore: StoreExt + ContentStore {}

impl<S> ApiStore for S where S: StoreExt + ContentStore {}

#[derive(Clone)]
pub(crate) struct ApiStoreHandle {
    inner: Arc<dyn ApiStore>,
}

impl ApiStoreHandle {
    pub(crate) fn new(inner: Arc<dyn ApiStore>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl IdentityStore for ApiStoreHandle {
    async fn mint(&self) -> Result<Identity, StoreError> {
        self.inner.mint().await
    }

    async fn resolve_public(&self, public: Uuid) -> Result<Option<Identity>, StoreError> {
        self.inner.resolve_public(public).await
    }

    async fn resolve_internal(&self, internal: Uuid) -> Result<Option<Identity>, StoreError> {
        self.inner.resolve_internal(internal).await
    }
}

#[async_trait]
impl EntityStore for ApiStoreHandle {
    async fn create_entity(&self, identity: Identity, kind: Uuid) -> Result<(), StoreError> {
        self.inner.create_entity(identity, kind).await
    }

    async fn get_entity(&self, entity_id: Uuid) -> Result<Option<EntityRow>, StoreError> {
        self.inner.get_entity(entity_id).await
    }

    async fn append_revision(
        &self,
        entity_id: Uuid,
        revision_seq: u64,
        input: &RevisionInput,
    ) -> Result<(), StoreError> {
        self.inner
            .append_revision(entity_id, revision_seq, input)
            .await
    }

    async fn get_revision(
        &self,
        entity_id: Uuid,
        revision_seq: u64,
    ) -> Result<Option<RevisionRow>, StoreError> {
        self.inner.get_revision(entity_id, revision_seq).await
    }

    async fn get_latest_revision(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<RevisionRow>, StoreError> {
        self.inner.get_latest_revision(entity_id).await
    }

    async fn list_revisions_referencing(
        &self,
        target_entity_id: Uuid,
        attribute_name: &str,
    ) -> Result<Vec<RevisionRef>, StoreError> {
        self.inner
            .list_revisions_referencing(target_entity_id, attribute_name)
            .await
    }

    async fn find_by_scalar(
        &self,
        kind: Uuid,
        attribute_name: &str,
        value: &ScalarValue,
    ) -> Result<Vec<EntityRow>, StoreError> {
        self.inner.find_by_scalar(kind, attribute_name, value).await
    }

    async fn find_by_content(
        &self,
        kind: Uuid,
        attribute_name: &str,
        content_hash: Sha256,
    ) -> Result<Vec<EntityRow>, StoreError> {
        self.inner
            .find_by_content(kind, attribute_name, content_hash)
            .await
    }
}

#[async_trait]
impl ContentStore for ApiStoreHandle {
    async fn put(&self, value: &ContentValue) -> Result<(), StoreError> {
        self.inner.put(value).await
    }

    async fn get(&self, hash: Sha256) -> Result<Option<ContentValue>, StoreError> {
        self.inner.get(hash).await
    }

    async fn exists(&self, hash: Sha256) -> Result<bool, StoreError> {
        self.inner.exists(hash).await
    }
}
