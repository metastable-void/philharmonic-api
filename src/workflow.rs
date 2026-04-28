//! Workflow-engine adapter types used by the API layer.

use std::sync::Arc;

use async_trait::async_trait;
use philharmonic_types::{EntityId, JsonValue};
use philharmonic_workflow::{
    ConfigLowerer, ConfigLoweringError, StepExecutionError, StepExecutor, SubjectContext,
    WorkflowEngine, WorkflowInstance,
};
use serde_json::json;

use crate::store::ApiStoreHandle;

/// Shared concrete workflow engine used by API handlers.
pub(crate) type ApiWorkflowEngine =
    WorkflowEngine<ApiStoreHandle, SharedStepExecutor, SharedConfigLowerer>;

/// Shared step-executor trait object wrapper.
#[derive(Clone)]
pub(crate) struct SharedStepExecutor {
    inner: Arc<dyn StepExecutor>,
}

impl SharedStepExecutor {
    pub(crate) fn new(inner: Arc<dyn StepExecutor>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl StepExecutor for SharedStepExecutor {
    async fn execute(
        &self,
        script: &str,
        arg: &JsonValue,
        config: &JsonValue,
    ) -> Result<JsonValue, StepExecutionError> {
        self.inner.execute(script, arg, config).await
    }
}

/// Shared config-lowerer trait object wrapper.
#[derive(Clone)]
pub(crate) struct SharedConfigLowerer {
    inner: Arc<dyn ConfigLowerer>,
}

impl SharedConfigLowerer {
    pub(crate) fn new(inner: Arc<dyn ConfigLowerer>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ConfigLowerer for SharedConfigLowerer {
    async fn lower(
        &self,
        abstract_config: &JsonValue,
        instance_id: EntityId<WorkflowInstance>,
        step_seq: u64,
        subject: &SubjectContext,
    ) -> Result<JsonValue, ConfigLoweringError> {
        self.inner
            .lower(abstract_config, instance_id, step_seq, subject)
            .await
    }
}

/// Placeholder step executor for endpoint-layer wiring and tests.
#[derive(Clone, Default)]
pub struct StubExecutor;

#[async_trait]
impl StepExecutor for StubExecutor {
    async fn execute(
        &self,
        _script: &str,
        arg: &JsonValue,
        _config: &JsonValue,
    ) -> Result<JsonValue, StepExecutionError> {
        let context = arg.get("context").cloned().unwrap_or_else(|| json!({}));
        Ok(json!({
            "context": context,
            "output": { "stub": true },
            "done": false
        }))
    }
}

/// Placeholder config lowerer for endpoint-layer wiring and tests.
#[derive(Clone, Default)]
pub struct StubLowerer;

#[async_trait]
impl ConfigLowerer for StubLowerer {
    async fn lower(
        &self,
        abstract_config: &JsonValue,
        _instance_id: EntityId<WorkflowInstance>,
        _step_seq: u64,
        _subject: &SubjectContext,
    ) -> Result<JsonValue, ConfigLoweringError> {
        Ok(abstract_config.clone())
    }
}
