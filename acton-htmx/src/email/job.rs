//! Background job for sending emails
//!
//! Integrates with the job system to send emails asynchronously.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::email::Email;
use crate::jobs::{Job, JobContext, JobError, JobResult};

/// Background job for sending emails
///
/// Use this to send emails asynchronously via the job queue.
///
/// # Examples
///
/// ```rust,no_run
/// use acton_htmx::email::{Email, SendEmailJob};
/// use acton_htmx::jobs::{Job, JobAgent};
///
/// # async fn example(job_agent: &JobAgent) -> Result<(), Box<dyn std::error::Error>> {
/// let email = Email::new()
///     .to("user@example.com")
///     .from("noreply@myapp.com")
///     .subject("Welcome!")
///     .text("Welcome to our app!");
///
/// let job = SendEmailJob::new(email);
/// job_agent.enqueue(job).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEmailJob {
    /// The email to send
    pub email: Email,
}

impl SendEmailJob {
    /// Create a new email sending job
    #[must_use]
    pub const fn new(email: Email) -> Self {
        Self { email }
    }
}

#[async_trait]
impl Job for SendEmailJob {
    type Result = ();

    async fn execute(&self, ctx: &JobContext) -> JobResult<Self::Result> {
        // Validate email first
        self.email.validate()
            .map_err(|e| JobError::ExecutionFailed(format!("Email validation failed: {e}")))?;

        // Get email sender from context
        let Some(email_sender) = ctx.email_sender() else {
            return Err(JobError::ExecutionFailed(
                "Email sender not available in JobContext".to_string()
            ));
        };

        // Send the email
        email_sender.send(self.email.clone()).await
            .map_err(|e| JobError::ExecutionFailed(format!("Email send failed: {e}")))?;

        Ok(())
    }

    fn max_retries(&self) -> u32 {
        // Retry email sending up to 3 times
        3
    }

    fn timeout(&self) -> std::time::Duration {
        // Email sending should complete within 30 seconds
        std::time::Duration::from_secs(30)
    }
}

// Note: In a future iteration, we could add an EmailJobExt trait
// to provide convenient methods for enqueueing email jobs directly

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::sender::MockEmailSender;  // Use mockall-generated mock
    use std::sync::Arc;

    #[test]
    fn test_send_email_job_creation() {
        let email = Email::new()
            .to("user@example.com")
            .from("noreply@myapp.com")
            .subject("Test")
            .text("Hello");

        let job = SendEmailJob::new(email.clone());

        assert_eq!(job.email.to, email.to);
        assert_eq!(job.email.from, email.from);
        assert_eq!(job.email.subject, email.subject);
    }

    #[test]
    fn test_send_email_job_serialization() {
        let email = Email::new()
            .to("user@example.com")
            .from("noreply@myapp.com")
            .subject("Test")
            .text("Hello");

        let job = SendEmailJob::new(email);

        // Test that the job can be serialized and deserialized
        let serialized = serde_json::to_string(&job).unwrap();
        let deserialized: SendEmailJob = serde_json::from_str(&serialized).unwrap();

        assert_eq!(job.email.to, deserialized.email.to);
        assert_eq!(job.email.from, deserialized.email.from);
    }

    #[tokio::test]
    async fn test_send_email_job_execute_with_sender() {
        let mut mock_sender = MockEmailSender::new();
        mock_sender.expect_send().times(1).returning(|_| Ok(()));

        let ctx = JobContext::new().with_email_sender(Arc::new(mock_sender));

        let email = Email::new()
            .to("user@example.com")
            .from("noreply@myapp.com")
            .subject("Test")
            .text("Hello");

        let job = SendEmailJob::new(email);

        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_email_job_no_sender() {
        let ctx = JobContext::new(); // No email sender

        let email = Email::new()
            .to("user@example.com")
            .from("noreply@myapp.com")
            .subject("Test")
            .text("Hello");

        let job = SendEmailJob::new(email);

        let result = job.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not available"));
    }

    #[tokio::test]
    async fn test_send_email_job_invalid_email() {
        let mut mock_sender = MockEmailSender::new();
        // Should not be called because validation fails first
        mock_sender.expect_send().times(0);

        let ctx = JobContext::new().with_email_sender(Arc::new(mock_sender));

        // Create an invalid email (no recipients)
        let email = Email::new()
            .from("noreply@myapp.com")
            .subject("Test")
            .text("Hello");

        let job = SendEmailJob::new(email);

        let result = job.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("validation failed"));
    }
}
