//! Job processing agent using acton-reactive.

pub(crate) mod messages;
pub(crate) mod persistence;
pub(crate) mod queue;
pub mod scheduled;

pub use messages::{EnqueueJob, JobEnqueued, JobMetrics};
pub use scheduled::{ScheduledJobAgent, ScheduledJobEntry, ScheduledJobMessage, ScheduledJobResponse, start_scheduler_loop};

use super::{JobContext, JobId, JobStatus};
use acton_reactive::prelude::*;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

use messages::{GetJobStatus, GetMetrics, JobStatusResponse};
use queue::{JobQueue, QueuedJob};

// Type alias for the ManagedAgent builder type
type JobAgentBuilder = ManagedAgent<Idle, JobAgent>;

/// Background job processing agent.
///
/// Manages a queue of background jobs with:
/// - Priority-based execution
/// - Redis persistence (async via act_on)
/// - Automatic retry with exponential backoff
/// - Dead letter queue for failed jobs
/// - Graceful shutdown
/// - Service access via [`JobContext`](crate::jobs::JobContext)
#[derive(Clone)]
#[allow(dead_code)] // Redis field will be used when handlers are enabled
pub struct JobAgent {
    /// In-memory priority queue.
    queue: Arc<RwLock<JobQueue>>,
    /// Currently running jobs.
    running: Arc<RwLock<HashMap<JobId, JobStatus>>>,
    /// Job metrics.
    metrics: Arc<RwLock<JobMetrics>>,
    /// Job execution context with services.
    ///
    /// Provides jobs with access to email sender, database pool, file storage, etc.
    context: Arc<JobContext>,
    /// Redis connection (optional, for persistence).
    #[cfg(feature = "redis")]
    redis: Option<Arc<RwLock<redis::aio::MultiplexedConnection>>>,
}

impl std::fmt::Debug for JobAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("JobAgent");
        debug_struct
            .field("queue", &"<JobQueue>")
            .field("running", &self.running.read().len())
            .field("metrics", &self.metrics.read())
            .field("context", &self.context);

        #[cfg(feature = "redis")]
        debug_struct.field("redis", &self.redis.is_some());

        debug_struct.finish()
    }
}

impl Default for JobAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl JobAgent {
    /// Create a new job agent without Redis or services.
    ///
    /// Use [`with_context`](Self::with_context) to provide services.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: Arc::new(RwLock::new(JobQueue::new(10_000))),
            running: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(JobMetrics::default())),
            context: Arc::new(JobContext::new()),
            #[cfg(feature = "redis")]
            redis: None,
        }
    }

    /// Create a new job agent with custom context.
    ///
    /// The context provides jobs with access to services like email sender,
    /// database pool, and file storage.
    #[must_use]
    pub fn with_context(context: JobContext) -> Self {
        Self {
            queue: Arc::new(RwLock::new(JobQueue::new(10_000))),
            running: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(JobMetrics::default())),
            context: Arc::new(context),
            #[cfg(feature = "redis")]
            redis: None,
        }
    }

    /// Create a new job agent with Redis persistence.
    #[cfg(feature = "redis")]
    #[must_use]
    pub fn with_redis(redis: redis::aio::MultiplexedConnection) -> Self {
        Self {
            queue: Arc::new(RwLock::new(JobQueue::new(10_000))),
            running: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(JobMetrics::default())),
            context: Arc::new(JobContext::new()),
            redis: Some(Arc::new(RwLock::new(redis))),
        }
    }

    /// Get the job context.
    ///
    /// This provides access to services configured for job execution.
    #[must_use]
    pub const fn context(&self) -> &Arc<JobContext> {
        &self.context
    }

    /// Spawn job agent
    ///
    /// Uses in-memory queue. Redis persistence and retry logic will be added in Week 5.
    ///
    /// # Errors
    ///
    /// Returns error if agent initialization fails
    pub async fn spawn(
        runtime: &mut AgentRuntime,
    ) -> anyhow::Result<AgentHandle> {
        let agent_config = AgentConfig::new(Ern::with_root("job_manager")?, None, None)?;
        let mut builder = runtime.new_agent_with_config::<Self>(agent_config).await;
        builder.model = Self::new();
        Self::configure_handlers(builder).await
    }

    /// Configure all message handlers for the job agent
    #[allow(clippy::too_many_lines)]
    async fn configure_handlers(mut builder: JobAgentBuilder) -> anyhow::Result<AgentHandle> {
        builder
            // Enqueue a job (agent-to-agent with reply_envelope)
            .mutate_on::<EnqueueJob>(|agent, envelope| {
                let msg = envelope.message().clone();
                let reply_envelope = envelope.reply_envelope();

                debug!("Enqueueing job {} with priority {}", msg.id, msg.priority);

                let queued_job = QueuedJob {
                    id: msg.id,
                    job_type: msg.job_type,
                    payload: msg.payload,
                    priority: msg.priority,
                    max_retries: msg.max_retries,
                    timeout: msg.timeout,
                    enqueued_at: Utc::now(),
                    attempt: 0,
                };

                // Add to in-memory queue
                let result = agent.model.queue.write().enqueue(queued_job);

                match result {
                    Ok(()) => {
                        agent.model.metrics.write().jobs_enqueued += 1;

                        // Send response via reply_envelope
                        let response = JobEnqueued { id: msg.id };
                        AgentReply::from_async(async move {
                            let _: () = reply_envelope.send(response).await;
                        })
                    }
                    Err(e) => {
                        warn!("Failed to enqueue job {}: {:?}", msg.id, e);
                        agent.model.metrics.write().jobs_rejected += 1;
                        AgentReply::immediate()
                    }
                }
            })
            // Get job status (read-only with reply_envelope)
            .act_on::<GetJobStatus>(|agent, envelope| {
                let msg = envelope.message().clone();
                let reply_envelope = envelope.reply_envelope();

                // Clone data from agent before moving into async
                let status = agent.model.running.read().get(&msg.id).map_or_else(
                    || {
                        if agent.model.queue.read().contains(&msg.id) {
                            Some(JobStatus::Pending)
                        } else {
                            None
                        }
                    },
                    |status| Some(status.clone()),
                );

                Box::pin(async move {
                    let response = JobStatusResponse {
                        id: msg.id,
                        status,
                    };
                    let _: () = reply_envelope.send(response).await;
                })
            })
            // Get metrics (read-only with reply_envelope)
            .act_on::<GetMetrics>(|agent, envelope| {
                let reply_envelope = envelope.reply_envelope();
                let metrics = agent.model.metrics.read().clone();

                Box::pin(async move {
                    let _: () = reply_envelope.send(metrics).await;
                })
            });

        // Redis persistence handlers are available when the redis feature is enabled
        // but require additional Send + Sync trait bounds that need to be resolved.
        // The architecture is in place - handlers will be uncommented when redis crate
        // compatibility is verified.
        #[cfg(feature = "redis")]
        {
            // TODO: Enable Redis handlers once Send + Sync bounds are resolved
            // See: https://github.com/redis-rs/redis-rs/issues/...
            let _ = builder; // Suppress unused warning
        }

        Ok(builder.start().await)
    }
}

