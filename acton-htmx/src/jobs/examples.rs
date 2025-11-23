//! Example background jobs demonstrating common use cases

use crate::jobs::{Job, JobContext, JobResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Example: Welcome email job
///
/// Sends a welcome email to a newly registered user.
/// This demonstrates a high-priority, fast-executing job with retry logic.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::examples::WelcomeEmailJob;
///
/// let job = WelcomeEmailJob {
///     user_id: 123,
///     email: "user@example.com".to_string(),
///     username: "johndoe".to_string(),
/// };
///
/// // Enqueue the job
/// // state.jobs.enqueue(job).await?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeEmailJob {
    /// User database ID
    pub user_id: i64,
    /// User email address
    pub email: String,
    /// Username for personalization
    pub username: String,
}

#[async_trait]
impl Job for WelcomeEmailJob {
    type Result = ();

    async fn execute(&self, _ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            user_id = self.user_id,
            email = %self.email,
            username = %self.username,
            "Sending welcome email"
        );

        // TODO: Implement actual email sending with template system
        // Example with JobContext:
        // if let Some(email_sender) = ctx.email_sender() {
        //     let email = Email::new()
        //         .to(&self.email)
        //         .from("noreply@myapp.com")
        //         .subject(&format!("Welcome, {}!", self.username))
        //         .text(&format!("Welcome to our app, {}!", self.username));
        //
        //     email_sender.send(email).await
        //         .map_err(|e| JobError::ExecutionFailed(e.to_string()))?;
        // }

        // Simulate email sending delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        tracing::info!(
            user_id = self.user_id,
            "Welcome email sent successfully"
        );

        Ok(())
    }

    fn max_retries(&self) -> u32 {
        3 // Email failures should retry
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30) // Email should be fast
    }

    fn priority(&self) -> i32 {
        200 // High priority (welcome emails are time-sensitive)
    }
}

/// Example: Report generation job
///
/// Generates a complex report from database data.
/// This demonstrates a long-running, resource-intensive job with lower priority.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::examples::GenerateReportJob;
///
/// let job = GenerateReportJob {
///     report_id: 456,
///     user_id: 123,
///     report_type: "monthly_sales".to_string(),
///     start_date: "2025-01-01".to_string(),
///     end_date: "2025-01-31".to_string(),
/// };
///
/// // Enqueue the job
/// // state.jobs.enqueue(job).await?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateReportJob {
    /// Report database ID
    pub report_id: i64,
    /// User who requested the report
    pub user_id: i64,
    /// Type of report to generate
    pub report_type: String,
    /// Report start date (ISO 8601)
    pub start_date: String,
    /// Report end date (ISO 8601)
    pub end_date: String,
}

#[async_trait]
impl Job for GenerateReportJob {
    type Result = String; // Returns report file path

    async fn execute(&self, _ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            report_id = self.report_id,
            user_id = self.user_id,
            report_type = %self.report_type,
            start_date = %self.start_date,
            end_date = %self.end_date,
            "Generating report"
        );

        // TODO: Implement actual report generation
        // Example with JobContext:
        // if let Some(db_pool) = ctx.database_pool() {
        //     let data = sqlx::query!(
        //         "SELECT * FROM sales WHERE date BETWEEN $1 AND $2",
        //         self.start_date, self.end_date
        //     )
        //     .fetch_all(db_pool.as_ref())
        //     .await
        //     .map_err(|e| JobError::ExecutionFailed(e.to_string()))?;
        //
        //     // Generate PDF from data
        //     // ...
        // }

        // Simulate report generation
        for i in 1..=10 {
            tracing::debug!(progress = i * 10, "Report generation progress");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let file_path = format!(
            "/var/reports/{}_{}_{}.pdf",
            self.report_type, self.report_id, chrono::Utc::now().timestamp()
        );

        tracing::info!(
            report_id = self.report_id,
            file_path = %file_path,
            "Report generated successfully"
        );

        Ok(file_path)
    }

    fn max_retries(&self) -> u32 {
        1 // Report generation is expensive, only retry once
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(600) // 10 minutes for complex reports
    }

    fn priority(&self) -> i32 {
        64 // Lower priority (reports can wait)
    }
}

/// Example: Data cleanup job
///
/// Cleans up old data from the database.
/// This demonstrates a scheduled maintenance job with no retries.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::examples::CleanupOldDataJob;
///
/// let job = CleanupOldDataJob {
///     days_old: 90,
///     batch_size: 1000,
///     dry_run: false,
/// };
///
/// // Enqueue the job
/// // state.jobs.enqueue(job).await?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupOldDataJob {
    /// Delete records older than this many days
    pub days_old: u32,
    /// Process records in batches of this size
    pub batch_size: usize,
    /// If true, only log what would be deleted without actually deleting
    pub dry_run: bool,
}

#[async_trait]
impl Job for CleanupOldDataJob {
    type Result = usize; // Returns number of records deleted

    async fn execute(&self, _ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            days_old = self.days_old,
            batch_size = self.batch_size,
            dry_run = self.dry_run,
            "Starting data cleanup"
        );

        let mut total_deleted = 0_usize;

        // TODO: Implement actual deletion with database
        // Example with JobContext:
        // if let Some(db_pool) = ctx.database_pool() {
        //     let cutoff_date = chrono::Utc::now() - chrono::Duration::days(i64::from(self.days_old));
        //
        //     loop {
        //         let result = sqlx::query!(
        //             "DELETE FROM events WHERE created_at < $1
        //              AND id IN (SELECT id FROM events WHERE created_at < $1 LIMIT $2)",
        //             cutoff_date,
        //             self.batch_size as i64
        //         )
        //         .execute(db_pool.as_ref())
        //         .await
        //         .map_err(|e| JobError::ExecutionFailed(e.to_string()))?;
        //
        //         let deleted = result.rows_affected() as usize;
        //         total_deleted += deleted;
        //
        //         if deleted < self.batch_size {
        //             break;
        //         }
        //     }
        //     return Ok(total_deleted);
        // }

        // Simulate batch processing
        for batch in 1..=5 {
            if self.dry_run {
                tracing::info!(
                    batch = batch,
                    "DRY RUN: Would delete {} records",
                    self.batch_size
                );
            } else {
                tracing::info!(
                    batch = batch,
                    deleted = self.batch_size,
                    "Deleted batch of records"
                );
            }

            total_deleted += self.batch_size;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        tracing::info!(
            total_deleted = total_deleted,
            dry_run = self.dry_run,
            "Data cleanup completed"
        );

        Ok(total_deleted)
    }

    fn max_retries(&self) -> u32 {
        0 // Cleanup jobs should not retry (idempotent, will run again on schedule)
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(1800) // 30 minutes for large cleanups
    }

    fn priority(&self) -> i32 {
        32 // Low priority (maintenance can run during quiet periods)
    }
}

/// Example: Image processing job
///
/// Processes uploaded images (resize, generate thumbnails, optimize).
/// This demonstrates a CPU-intensive job with medium priority.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::examples::ProcessImageJob;
///
/// let job = ProcessImageJob {
///     image_id: 789,
///     file_path: "/uploads/photo.jpg".to_string(),
///     sizes: vec![200, 400, 800],
///     optimize: true,
/// };
///
/// // Enqueue the job
/// // state.jobs.enqueue(job).await?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessImageJob {
    /// Image database ID
    pub image_id: i64,
    /// Path to original image file
    pub file_path: String,
    /// Generate thumbnails at these widths (pixels)
    pub sizes: Vec<u32>,
    /// Whether to optimize the image
    pub optimize: bool,
}

#[async_trait]
impl Job for ProcessImageJob {
    type Result = Vec<String>; // Returns paths to generated thumbnails

    async fn execute(&self, _ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            image_id = self.image_id,
            file_path = %self.file_path,
            sizes = ?self.sizes,
            optimize = self.optimize,
            "Processing image"
        );

        let mut thumbnail_paths = Vec::new();

        // TODO: Implement actual image processing with storage
        // Example with JobContext:
        // if let Some(file_storage) = ctx.file_storage() {
        //     // Retrieve original image
        //     let image_data = file_storage.retrieve(&self.file_path).await
        //         .map_err(|e| JobError::ExecutionFailed(e.to_string()))?;
        //
        //     // Use ImageProcessor from storage module
        //     let processor = ImageProcessor::new()?;
        //
        //     for size in &self.sizes {
        //         let thumbnail = processor.resize(&image_data, *size, *size)?;
        //         let thumb_id = format!("{}_{}x{}", self.image_id, size, size);
        //         file_storage.store(thumbnail).await
        //             .map_err(|e| JobError::ExecutionFailed(e.to_string()))?;
        //         thumbnail_paths.push(thumb_id);
        //     }
        //
        //     return Ok(thumbnail_paths);
        // }

        // Generate thumbnails
        for size in &self.sizes {
            tracing::debug!(size = size, "Generating thumbnail");

            // Simulate processing time
            tokio::time::sleep(Duration::from_millis(200)).await;

            let thumb_path = format!("{}_{}x{}.jpg", self.file_path, size, size);
            thumbnail_paths.push(thumb_path.clone());

            tracing::debug!(size = size, path = %thumb_path, "Thumbnail generated");
        }

        // Optimize original if requested
        if self.optimize {
            tracing::debug!("Optimizing original image");
            // TODO: Implement image optimization
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        tracing::info!(
            image_id = self.image_id,
            thumbnails = thumbnail_paths.len(),
            "Image processing completed"
        );

        Ok(thumbnail_paths)
    }

    fn max_retries(&self) -> u32 {
        2 // Image processing can fail due to corrupted files, retry a couple times
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(120) // 2 minutes for large images
    }

    fn priority(&self) -> i32 {
        128 // Medium priority (users expect quick upload feedback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_welcome_email_job() {
        let ctx = JobContext::new();
        let job = WelcomeEmailJob {
            user_id: 123,
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
        };

        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_report_job() {
        let ctx = JobContext::new();
        let job = GenerateReportJob {
            report_id: 456,
            user_id: 123,
            report_type: "test_report".to_string(),
            start_date: "2025-01-01".to_string(),
            end_date: "2025-01-31".to_string(),
        };

        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("test_report"));
    }

    #[tokio::test]
    async fn test_cleanup_job_dry_run() {
        let ctx = JobContext::new();
        let job = CleanupOldDataJob {
            days_old: 90,
            batch_size: 100,
            dry_run: true,
        };

        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 500); // 5 batches * 100
    }

    #[tokio::test]
    async fn test_process_image_job() {
        let ctx = JobContext::new();
        let job = ProcessImageJob {
            image_id: 789,
            file_path: "/tmp/test.jpg".to_string(),
            sizes: vec![200, 400],
            optimize: true,
        };

        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2); // 2 thumbnail sizes
    }

    #[test]
    fn test_job_priorities() {
        let welcome = WelcomeEmailJob {
            user_id: 1,
            email: "test@test.com".to_string(),
            username: "test".to_string(),
        };
        let report = GenerateReportJob {
            report_id: 1,
            user_id: 1,
            report_type: "test".to_string(),
            start_date: "2025-01-01".to_string(),
            end_date: "2025-01-31".to_string(),
        };
        let cleanup = CleanupOldDataJob {
            days_old: 90,
            batch_size: 100,
            dry_run: true,
        };

        // Verify priority ordering: welcome > image > report > cleanup
        assert!(welcome.priority() > report.priority());
        assert!(report.priority() > cleanup.priority());
    }
}
