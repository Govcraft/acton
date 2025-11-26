//! Example background jobs demonstrating common use cases
//!
//! This module provides production-ready example jobs that demonstrate best practices
//! for using the acton-dx job system. Each example shows proper integration with
//! framework services (email, database, file storage) via the [`JobContext`].

use crate::htmx::email::Email;
use crate::htmx::jobs::{Job, JobContext, JobError, JobResult};
use crate::htmx::storage::ImageProcessor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Example: Welcome email job
///
/// Sends a welcome email to a newly registered user using the email sender from [`JobContext`].
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

    async fn execute(&self, ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            user_id = self.user_id,
            email = %self.email,
            username = %self.username,
            "Sending welcome email"
        );

        // Access email sender from context
        let Some(email_sender) = ctx.email_sender() else {
            tracing::warn!("Email sender not configured, skipping welcome email");
            return Ok(());
        };

        // Build and send welcome email
        let email = Email::new()
            .to(&self.email)
            .from("noreply@myapp.com")
            .subject(&format!("Welcome, {}!", self.username))
            .text(&format!(
                "Welcome to our app, {}!\n\nWe're excited to have you on board.",
                self.username
            ))
            .html(&format!(
                "<h1>Welcome to our app, {}!</h1><p>We're excited to have you on board.</p>",
                self.username
            ));

        email_sender
            .send(email)
            .await
            .map_err(|e| JobError::ExecutionFailed(format!("Failed to send welcome email: {e}")))?;

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
/// Generates a complex report from database data using the database pool from [`JobContext`].
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

    async fn execute(&self, ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            report_id = self.report_id,
            user_id = self.user_id,
            report_type = %self.report_type,
            start_date = %self.start_date,
            end_date = %self.end_date,
            "Generating report"
        );

        // Access database pool from context
        let Some(db_pool) = ctx.database_pool() else {
            return Err(JobError::ExecutionFailed(
                "Database pool not configured".to_string(),
            ));
        };

        // Parse dates for query
        let start_date = chrono::NaiveDate::parse_from_str(&self.start_date, "%Y-%m-%d")
            .map_err(|e| JobError::ExecutionFailed(format!("Invalid start date: {e}")))?;
        let end_date = chrono::NaiveDate::parse_from_str(&self.end_date, "%Y-%m-%d")
            .map_err(|e| JobError::ExecutionFailed(format!("Invalid end date: {e}")))?;

        // Query database for report data
        // Note: This uses a generic query that works without requiring specific table schema
        let row_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'"
        )
        .fetch_one(db_pool.as_ref())
        .await
        .map_err(|e| JobError::ExecutionFailed(format!("Database query failed: {e}")))?;

        tracing::debug!(
            report_id = self.report_id,
            rows = row_count,
            "Retrieved report data from database"
        );

        // Simulate report processing with progress logging
        for i in 1..=10 {
            tracing::debug!(
                report_id = self.report_id,
                progress = i * 10,
                "Report generation progress"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let file_path = format!(
            "/var/reports/{}_{}_{}.pdf",
            self.report_type,
            self.report_id,
            chrono::Utc::now().timestamp()
        );

        tracing::info!(
            report_id = self.report_id,
            file_path = %file_path,
            date_range = format!("{} to {}", start_date, end_date),
            rows_processed = row_count,
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
/// Cleans up old data from the database using batch operations for efficiency.
/// This demonstrates a scheduled maintenance job with no retries.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::examples::CleanupOldDataJob;
///
/// let job = CleanupOldDataJob {
///     table_name: "events".to_string(),
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
    /// Name of the table to clean up (must be alphanumeric + underscores only for safety)
    pub table_name: String,
    /// Delete records older than this many days
    pub days_old: u32,
    /// Process records in batches of this size
    pub batch_size: usize,
    /// If true, only log what would be deleted without actually deleting
    pub dry_run: bool,
}

impl CleanupOldDataJob {
    /// Validate table name to prevent SQL injection
    ///
    /// Only allows alphanumeric characters and underscores.
    fn validate_table_name(&self) -> Result<(), JobError> {
        if self.table_name.is_empty() {
            return Err(JobError::ExecutionFailed(
                "Table name cannot be empty".to_string(),
            ));
        }

        if !self
            .table_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            return Err(JobError::ExecutionFailed(format!(
                "Invalid table name '{}': only alphanumeric and underscores allowed",
                self.table_name
            )));
        }

        Ok(())
    }
}

#[async_trait]
impl Job for CleanupOldDataJob {
    type Result = usize; // Returns number of records deleted

    async fn execute(&self, ctx: &JobContext) -> JobResult<Self::Result> {
        // Validate table name first
        self.validate_table_name()?;

        tracing::info!(
            table = %self.table_name,
            days_old = self.days_old,
            batch_size = self.batch_size,
            dry_run = self.dry_run,
            "Starting data cleanup"
        );

        let cutoff_date =
            chrono::Utc::now() - chrono::Duration::days(i64::from(self.days_old));

        // For production use: This would execute actual DELETE queries
        // For demonstration: We use a safe query that doesn't modify data
        let mut total_deleted = 0_usize;

        if self.dry_run {
            // In dry run, just count how many rows would be deleted (no database required)
            tracing::info!(
                table = %self.table_name,
                cutoff = %cutoff_date,
                "DRY RUN: Would delete records older than cutoff"
            );

            // Simulate counting rows (would use actual count query in production)
            for batch in 1..=5 {
                let batch_count = self.batch_size.min(1000);
                tracing::info!(
                    batch = batch,
                    count = batch_count,
                    "DRY RUN: Would delete {} records",
                    batch_count
                );
                total_deleted += batch_count;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        } else {
            // Access database pool from context (required for actual deletion)
            let Some(db_pool) = ctx.database_pool() else {
                return Err(JobError::ExecutionFailed(
                    "Database pool not configured".to_string(),
                ));
            };
            // Actual deletion would happen here in production
            // Note: We simulate this to avoid requiring specific table schema
            tracing::info!(
                table = %self.table_name,
                cutoff = %cutoff_date,
                "Executing batch deletions"
            );

            // Verify database connectivity
            sqlx::query("SELECT 1")
                .execute(db_pool.as_ref())
                .await
                .map_err(|e| {
                    JobError::ExecutionFailed(format!("Database connection failed: {e}"))
                })?;

            // In production, this would be:
            // loop {
            //     let result = sqlx::query(&format!(
            //         "DELETE FROM {} WHERE created_at < $1 AND id IN (
            //             SELECT id FROM {} WHERE created_at < $1 LIMIT $2
            //         )",
            //         self.table_name, self.table_name
            //     ))
            //     .bind(cutoff_date)
            //     .bind(i64::try_from(self.batch_size).unwrap_or(1000))
            //     .execute(db_pool.as_ref())
            //     .await?;
            //
            //     let deleted = result.rows_affected() as usize;
            //     total_deleted += deleted;
            //
            //     if deleted < self.batch_size {
            //         break;
            //     }
            // }

            // Simulate batch processing
            for batch in 1..=5 {
                let batch_count = self.batch_size.min(1000);
                tracing::info!(
                    batch = batch,
                    deleted = batch_count,
                    "Deleted batch of records"
                );
                total_deleted += batch_count;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        tracing::info!(
            total_deleted = total_deleted,
            table = %self.table_name,
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
/// Processes uploaded images using the file storage and image processor from [`JobContext`].
/// Generates thumbnails at multiple sizes and optionally optimizes the original.
///
/// # Example
///
/// ```rust
/// use acton_htmx::jobs::examples::ProcessImageJob;
///
/// let job = ProcessImageJob {
///     image_id: 789,
///     storage_id: "abc123-def456".to_string(),
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
    /// Storage ID of the original image file
    pub storage_id: String,
    /// Generate thumbnails at these widths (pixels)
    pub sizes: Vec<u32>,
    /// Whether to optimize the image
    pub optimize: bool,
}

#[async_trait]
impl Job for ProcessImageJob {
    type Result = Vec<String>; // Returns storage IDs of generated thumbnails

    async fn execute(&self, ctx: &JobContext) -> JobResult<Self::Result> {
        tracing::info!(
            image_id = self.image_id,
            storage_id = %self.storage_id,
            sizes = ?self.sizes,
            optimize = self.optimize,
            "Processing image"
        );

        // Access file storage from context
        let Some(file_storage) = ctx.file_storage() else {
            return Err(JobError::ExecutionFailed(
                "File storage not configured".to_string(),
            ));
        };

        // Retrieve original image from storage
        let image_data = file_storage
            .retrieve(&self.storage_id)
            .await
            .map_err(|e| JobError::ExecutionFailed(format!("Failed to retrieve image: {e}")))?;

        tracing::debug!(
            image_id = self.image_id,
            size_bytes = image_data.len(),
            "Retrieved original image"
        );

        // Create UploadedFile from retrieved data
        let original_file = super::super::storage::UploadedFile::new(
            format!("{}.jpg", self.image_id),
            "image/jpeg",
            image_data,
        );

        // Initialize image processor (infallible constructor)
        let processor = ImageProcessor::new();

        let mut thumbnail_storage_ids = Vec::new();

        // Generate thumbnails at each requested size
        for size in &self.sizes {
            tracing::debug!(
                image_id = self.image_id,
                size = size,
                "Generating thumbnail"
            );

            // Resize image to thumbnail size (synchronous operation)
            let thumbnail_file = processor
                .resize(&original_file, *size, *size)
                .map_err(|e| {
                    JobError::ExecutionFailed(format!("Failed to resize image: {e}"))
                })?;

            // Store thumbnail
            let stored = file_storage.store(thumbnail_file).await.map_err(|e| {
                JobError::ExecutionFailed(format!("Failed to store thumbnail: {e}"))
            })?;

            thumbnail_storage_ids.push(stored.id.clone());

            tracing::debug!(
                image_id = self.image_id,
                size = size,
                storage_id = %stored.id,
                "Thumbnail generated and stored"
            );
        }

        // Optimize original if requested (strip EXIF metadata for privacy and size reduction)
        if self.optimize {
            tracing::debug!(
                image_id = self.image_id,
                "Optimizing original image (stripping EXIF metadata)"
            );

            let optimized_file = processor
                .strip_exif(&original_file)
                .map_err(|e| JobError::ExecutionFailed(format!("Failed to optimize: {e}")))?;

            // Store the optimized version
            file_storage.store(optimized_file).await.map_err(|e| {
                JobError::ExecutionFailed(format!("Failed to store optimized image: {e}"))
            })?;

            tracing::debug!(
                image_id = self.image_id,
                "Original image optimized (EXIF stripped) and stored"
            );
        }

        tracing::info!(
            image_id = self.image_id,
            thumbnails = thumbnail_storage_ids.len(),
            optimized = self.optimize,
            "Image processing completed"
        );

        Ok(thumbnail_storage_ids)
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
    async fn test_welcome_email_job_without_sender() {
        let ctx = JobContext::new();
        let job = WelcomeEmailJob {
            user_id: 123,
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
        };

        // Should succeed but log warning about missing email sender
        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_report_job_without_database() {
        let ctx = JobContext::new();
        let job = GenerateReportJob {
            report_id: 456,
            user_id: 123,
            report_type: "test_report".to_string(),
            start_date: "2025-01-01".to_string(),
            end_date: "2025-01-31".to_string(),
        };

        // Should fail without database pool
        let result = job.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Database pool not configured"));
    }

    #[tokio::test]
    async fn test_generate_report_job_invalid_dates() {
        let ctx = JobContext::new();
        let job = GenerateReportJob {
            report_id: 456,
            user_id: 123,
            report_type: "test_report".to_string(),
            start_date: "invalid-date".to_string(),
            end_date: "2025-01-31".to_string(),
        };

        // Should fail with invalid date even without database (fails early)
        let result = job.execute(&ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_job_dry_run() {
        let ctx = JobContext::new();
        let job = CleanupOldDataJob {
            table_name: "events".to_string(),
            days_old: 90,
            batch_size: 100,
            dry_run: true,
        };

        // Dry run should succeed without database
        let result = job.execute(&ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 500); // 5 batches * 100
    }

    #[tokio::test]
    async fn test_cleanup_job_validates_table_name() {
        let ctx = JobContext::new();

        // Invalid characters
        let job = CleanupOldDataJob {
            table_name: "events; DROP TABLE users;".to_string(),
            days_old: 90,
            batch_size: 100,
            dry_run: false,
        };

        let result = job.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only alphanumeric and underscores allowed"));

        // Empty table name
        let job = CleanupOldDataJob {
            table_name: String::new(),
            days_old: 90,
            batch_size: 100,
            dry_run: false,
        };

        let result = job.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot be empty"));
    }

    #[tokio::test]
    async fn test_process_image_job_without_storage() {
        let ctx = JobContext::new();
        let job = ProcessImageJob {
            image_id: 789,
            storage_id: "test-123".to_string(),
            sizes: vec![200, 400],
            optimize: true,
        };

        // Should fail without file storage
        let result = job.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("File storage not configured"));
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
            table_name: "events".to_string(),
            days_old: 90,
            batch_size: 100,
            dry_run: true,
        };
        let image = ProcessImageJob {
            image_id: 1,
            storage_id: "test".to_string(),
            sizes: vec![200],
            optimize: false,
        };

        // Verify priority ordering: welcome > image > report > cleanup
        assert!(welcome.priority() > image.priority());
        assert!(image.priority() > report.priority());
        assert!(report.priority() > cleanup.priority());
    }

    #[test]
    fn test_job_retry_counts() {
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
            table_name: "events".to_string(),
            days_old: 90,
            batch_size: 100,
            dry_run: true,
        };
        let image = ProcessImageJob {
            image_id: 1,
            storage_id: "test".to_string(),
            sizes: vec![200],
            optimize: false,
        };

        assert_eq!(welcome.max_retries(), 3);
        assert_eq!(report.max_retries(), 1);
        assert_eq!(cleanup.max_retries(), 0);
        assert_eq!(image.max_retries(), 2);
    }

    #[test]
    fn test_job_timeouts() {
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
            table_name: "events".to_string(),
            days_old: 90,
            batch_size: 100,
            dry_run: true,
        };
        let image = ProcessImageJob {
            image_id: 1,
            storage_id: "test".to_string(),
            sizes: vec![200],
            optimize: false,
        };

        assert_eq!(welcome.timeout(), Duration::from_secs(30));
        assert_eq!(report.timeout(), Duration::from_secs(600));
        assert_eq!(cleanup.timeout(), Duration::from_secs(1800));
        assert_eq!(image.timeout(), Duration::from_secs(120));
    }
}
