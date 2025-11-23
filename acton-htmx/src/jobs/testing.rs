//! Testing utilities for background jobs
//!
//! This module provides utilities for testing job execution, including:
//! - `TestJobQueue` - In-memory job queue for unit tests
//! - Job execution assertions
//! - Retry behavior tests
//! - Mock job implementations

use crate::jobs::{Job, JobError, JobResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// In-memory job queue for testing
///
/// Provides a simple job queue implementation for unit tests without requiring
/// Redis or the full job agent infrastructure.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::testing::{TestJobQueue, TestJob};
/// use acton_htmx::jobs::Job;
///
/// #[tokio::test]
/// async fn test_job_execution() {
///     let queue = TestJobQueue::new();
///
///     let job = TestJob::new("test".to_string(), true);
///     queue.enqueue(job.clone());
///
///     assert_eq!(queue.len(), 1);
///
///     let executed = queue.execute_next().await;
///     assert!(executed.is_ok());
///     assert_eq!(queue.len(), 0);
/// }
/// ```
#[derive(Clone)]
pub struct TestJobQueue {
    jobs: Arc<Mutex<VecDeque<Box<dyn JobWrapper>>>>,
    completed: Arc<Mutex<Vec<String>>>,
    failed: Arc<Mutex<Vec<(String, String)>>>,
}

impl Default for TestJobQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TestJobQueue {
    /// Create a new test job queue
    #[must_use]
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(VecDeque::new())),
            completed: Arc::new(Mutex::new(Vec::new())),
            failed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Enqueue a job for execution
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    pub fn enqueue<J: Job + Clone + Send + Sync + 'static>(&self, job: J) {
        let wrapper = Box::new(TypedJobWrapper { job });
        self.jobs.lock().unwrap().push_back(wrapper);
    }

    /// Execute the next job in the queue
    ///
    /// Returns `None` if the queue is empty.
    ///
    /// # Errors
    ///
    /// Returns error if job execution fails
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    pub async fn execute_next(&self) -> Option<Result<(), JobError>> {
        let job = self.jobs.lock().unwrap().pop_front()?;

        let job_name = job.name();
        match job.execute_boxed().await {
            Ok(()) => {
                self.completed.lock().unwrap().push(job_name);
                Some(Ok(()))
            }
            Err(e) => {
                self.failed
                    .lock()
                    .unwrap()
                    .push((job_name, e.to_string()));
                Some(Err(e))
            }
        }
    }

    /// Execute all jobs in the queue
    ///
    /// # Errors
    ///
    /// Returns the first error encountered during execution
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    pub async fn execute_all(&self) -> Result<(), JobError> {
        while let Some(result) = self.execute_next().await {
            result?;
        }
        Ok(())
    }

    /// Get the number of pending jobs
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    #[must_use]
    pub fn len(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }

    /// Check if the queue is empty
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jobs.lock().unwrap().is_empty()
    }

    /// Get the number of completed jobs
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed.lock().unwrap().len()
    }

    /// Get the number of failed jobs
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.failed.lock().unwrap().len()
    }

    /// Get the list of completed job names
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    #[must_use]
    pub fn completed_jobs(&self) -> Vec<String> {
        self.completed.lock().unwrap().clone()
    }

    /// Get the list of failed jobs with error messages
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    #[must_use]
    pub fn failed_jobs(&self) -> Vec<(String, String)> {
        self.failed.lock().unwrap().clone()
    }

    /// Clear all completed and failed job history
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned
    pub fn clear_history(&self) {
        self.completed.lock().unwrap().clear();
        self.failed.lock().unwrap().clear();
    }
}

/// Trait for type-erased job execution
trait JobWrapper: Send {
    fn execute_boxed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = JobResult<()>> + Send + '_>>;
    fn name(&self) -> String;
}

/// Typed wrapper for jobs
struct TypedJobWrapper<J: Job> {
    job: J,
}

impl<J: Job + Send + Sync> JobWrapper for TypedJobWrapper<J> {
    fn execute_boxed(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = JobResult<()>> + Send + '_>> {
        Box::pin(async move {
            let ctx = super::JobContext::new();
            self.job.execute(&ctx).await?;
            Ok(())
        })
    }

    fn name(&self) -> String {
        std::any::type_name::<J>().to_string()
    }
}

/// Test job implementation for testing
///
/// A simple job that can be configured to succeed or fail, useful for testing
/// job queue behavior, retry logic, and error handling.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::testing::TestJob;
/// use acton_htmx::jobs::Job;
///
/// #[tokio::test]
/// async fn test_successful_job() {
///     let job = TestJob::new("test".to_string(), true);
///     let result = job.execute().await;
///     assert!(result.is_ok());
/// }
///
/// #[tokio::test]
/// async fn test_failing_job() {
///     let job = TestJob::new("test".to_string(), false);
///     let result = job.execute().await;
///     assert!(result.is_err());
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestJob {
    /// Job identifier
    pub id: String,
    /// Whether the job should succeed (true) or fail (false)
    pub should_succeed: bool,
    /// Optional delay in milliseconds before execution completes
    #[serde(default)]
    pub delay_ms: Option<u64>,
}

impl TestJob {
    /// Create a new test job
    #[must_use]
    pub fn new(id: String, should_succeed: bool) -> Self {
        Self {
            id,
            should_succeed,
            delay_ms: None,
        }
    }

    /// Create a test job with a delay
    #[must_use]
    pub fn with_delay(id: String, should_succeed: bool, delay_ms: u64) -> Self {
        Self {
            id,
            should_succeed,
            delay_ms: Some(delay_ms),
        }
    }
}

#[async_trait]
impl Job for TestJob {
    type Result = String;

    async fn execute(&self, _ctx: &super::JobContext) -> JobResult<Self::Result> {
        if let Some(delay) = self.delay_ms {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        if self.should_succeed {
            Ok(format!("Success: {}", self.id))
        } else {
            Err(JobError::ExecutionFailed(format!(
                "Intentional failure: {}",
                self.id
            )))
        }
    }

    fn max_retries(&self) -> u32 {
        3
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn priority(&self) -> i32 {
        128
    }
}

/// Assert that a job executes successfully
///
/// # Panics
///
/// Panics if the job fails to execute
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::testing::{assert_job_succeeds, TestJob};
///
/// #[tokio::test]
/// async fn test_job_success() {
///     let job = TestJob::new("test".to_string(), true);
///     assert_job_succeeds(job).await;
/// }
/// ```
pub async fn assert_job_succeeds<J: Job>(job: J)
where
    J::Result: std::fmt::Debug,
{
    let ctx = super::JobContext::new();
    let result = job.execute(&ctx).await;
    assert!(
        result.is_ok(),
        "Job should succeed but failed with: {:?}",
        result.unwrap_err()
    );
}

/// Assert that a job fails with an error
///
/// # Panics
///
/// Panics if the job succeeds
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::testing::{assert_job_fails, TestJob};
///
/// #[tokio::test]
/// async fn test_job_failure() {
///     let job = TestJob::new("test".to_string(), false);
///     assert_job_fails(job).await;
/// }
/// ```
pub async fn assert_job_fails<J: Job>(job: J) {
    let ctx = super::JobContext::new();
    let result = job.execute(&ctx).await;
    assert!(result.is_err(), "Job should fail but succeeded");
}

/// Assert that a job completes within a timeout
///
/// # Panics
///
/// Panics if the job takes longer than the specified timeout
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::testing::{assert_job_completes_within, TestJob};
/// use std::time::Duration;
///
/// #[tokio::test]
/// async fn test_job_timeout() {
///     let job = TestJob::with_delay("test".to_string(), true, 100);
///     assert_job_completes_within(job, Duration::from_millis(200)).await;
/// }
/// ```
pub async fn assert_job_completes_within<J: Job>(job: J, timeout: Duration) {
    let ctx = super::JobContext::new();
    let result = tokio::time::timeout(timeout, job.execute(&ctx)).await;
    assert!(
        result.is_ok(),
        "Job should complete within {timeout:?} but timed out"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_enqueue_and_execute() {
        let queue = TestJobQueue::new();
        let job = TestJob::new("test1".to_string(), true);

        queue.enqueue(job);
        assert_eq!(queue.len(), 1);

        let result = queue.execute_next().await;
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.completed_count(), 1);
    }

    #[tokio::test]
    async fn test_queue_failed_job() {
        let queue = TestJobQueue::new();
        let job = TestJob::new("test1".to_string(), false);

        queue.enqueue(job);
        let result = queue.execute_next().await;

        assert!(result.is_some());
        assert!(result.unwrap().is_err());
        assert_eq!(queue.failed_count(), 1);
    }

    #[tokio::test]
    async fn test_queue_execute_all() {
        let queue = TestJobQueue::new();

        queue.enqueue(TestJob::new("test1".to_string(), true));
        queue.enqueue(TestJob::new("test2".to_string(), true));
        queue.enqueue(TestJob::new("test3".to_string(), true));

        let result = queue.execute_all().await;
        assert!(result.is_ok());
        assert_eq!(queue.completed_count(), 3);
    }

    #[tokio::test]
    async fn test_successful_job() {
        let job = TestJob::new("test".to_string(), true);
        assert_job_succeeds(job).await;
    }

    #[tokio::test]
    async fn test_failing_job() {
        let job = TestJob::new("test".to_string(), false);
        assert_job_fails(job).await;
    }

    #[tokio::test]
    async fn test_job_with_delay() {
        let job = TestJob::with_delay("test".to_string(), true, 50);
        assert_job_completes_within(job, Duration::from_millis(100)).await;
    }
}
