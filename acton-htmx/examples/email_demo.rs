//! Email System Demo
//!
//! Demonstrates the acton-htmx email system with multiple backends and templates.
//!
//! Run with: `cargo run --example email_demo`

use acton_htmx::email::{ConsoleBackend, Email, EmailError, EmailSender, EmailTemplate};
use askama::Template;

// ============================================================================
// Example 1: Inline templates using Askama's source attribute
// ============================================================================

/// Welcome email HTML template (inline for demo purposes)
#[derive(Template)]
#[template(
    source = r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
        .content { background-color: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
        .button { display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 4px; }
        .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to {{ app_name }}!</h1>
    </div>
    <div class="content">
        <p>Hello {{ name }},</p>
        <p>Thank you for joining {{ app_name }}! We're excited to have you on board.</p>
        <p>To get started, please verify your email address:</p>
        <p style="text-align: center;">
            <a href="{{ verification_url }}" class="button">Verify Email Address</a>
        </p>
        <p>If the button doesn't work, copy this link: {{ verification_url }}</p>
        <p>Best regards,<br>The {{ app_name }} Team</p>
    </div>
    <div class="footer">
        <p>This email was sent to {{ email }}</p>
    </div>
</body>
</html>"#,
    ext = "html"
)]
struct WelcomeEmailHtml {
    app_name: String,
    name: String,
    email: String,
    verification_url: String,
}

/// Welcome email plain text template
#[derive(Template)]
#[template(
    source = r#"Welcome to {{ app_name }}!

Hello {{ name }},

Thank you for joining {{ app_name }}! We're excited to have you on board.

To get started, please verify your email address by visiting:
{{ verification_url }}

If you didn't create an account, please ignore this email.

Best regards,
The {{ app_name }} Team

---
This email was sent to {{ email }}"#,
    ext = "txt"
)]
struct WelcomeEmailText {
    app_name: String,
    name: String,
    email: String,
    verification_url: String,
}

/// Combined welcome email with both HTML and text versions
struct WelcomeEmail {
    app_name: String,
    name: String,
    email: String,
    verification_url: String,
}

impl EmailTemplate for WelcomeEmail {
    fn render_email(&self) -> Result<(Option<String>, Option<String>), EmailError> {
        let html_template = WelcomeEmailHtml {
            app_name: self.app_name.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            verification_url: self.verification_url.clone(),
        };

        let text_template = WelcomeEmailText {
            app_name: self.app_name.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            verification_url: self.verification_url.clone(),
        };

        let html = html_template.render().map_err(EmailError::from)?;
        let text = text_template.render().map_err(EmailError::from)?;

        Ok((Some(html), Some(text)))
    }
}

// ============================================================================
// Example 2: Password reset email
// ============================================================================

#[derive(Template)]
#[template(
    source = r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
        .alert { background-color: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .code { background-color: #f8f9fa; padding: 15px; font-size: 24px; font-family: monospace; text-align: center; border-radius: 4px; letter-spacing: 4px; }
    </style>
</head>
<body>
    <h1>Password Reset Request</h1>
    <p>Hello {{ name }},</p>
    <p>We received a request to reset your password. Use the code below:</p>
    <div class="code">{{ reset_code }}</div>
    <p>This code expires in {{ expires_in_minutes }} minutes.</p>
    <div class="alert">
        <strong>Security notice:</strong> If you didn't request this reset, please ignore this email.
    </div>
</body>
</html>"#,
    ext = "html"
)]
struct PasswordResetHtml {
    name: String,
    reset_code: String,
    expires_in_minutes: u32,
}

impl acton_htmx::email::SimpleEmailTemplate for PasswordResetHtml {
    fn render_text(&self) -> Result<Option<String>, EmailError> {
        Ok(Some(format!(
            "Password Reset Request\n\n\
             Hello {},\n\n\
             We received a request to reset your password.\n\n\
             Your reset code: {}\n\n\
             This code expires in {} minutes.\n\n\
             If you didn't request this reset, please ignore this email.",
            self.name, self.reset_code, self.expires_in_minutes
        )))
    }
}

// ============================================================================
// Main demo
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║            acton-htmx Email System Demo                       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // Create a console backend for development (prints emails instead of sending)
    let backend = ConsoleBackend::new();

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 1: Simple email without templates
    // ─────────────────────────────────────────────────────────────────────────
    println!("📧 Demo 1: Simple Email (no template)\n");

    let simple_email = Email::new()
        .to("user@example.com")
        .from("noreply@myapp.com")
        .subject("Hello from acton-htmx!")
        .text("This is a simple plain text email.")
        .html("<h1>Hello!</h1><p>This is a simple HTML email.</p>");

    backend.send(simple_email).await?;

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 2: Welcome email with full template
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📧 Demo 2: Welcome Email (with template)\n");

    let welcome = WelcomeEmail {
        app_name: "Acton Demo".to_string(),
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        verification_url: "https://myapp.com/verify/abc123xyz".to_string(),
    };

    let welcome_email = Email::from_template(&welcome)?
        .to("alice@example.com")
        .from("noreply@myapp.com")
        .subject("Welcome to Acton Demo!");

    backend.send(welcome_email).await?;

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 3: Password reset with SimpleEmailTemplate
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📧 Demo 3: Password Reset Email (SimpleEmailTemplate)\n");

    let password_reset = PasswordResetHtml {
        name: "Bob".to_string(),
        reset_code: "847291".to_string(),
        expires_in_minutes: 15,
    };

    let reset_email = Email::from_template(&password_reset)?
        .to("bob@example.com")
        .from("security@myapp.com")
        .reply_to("support@myapp.com")
        .subject("Password Reset Request");

    backend.send(reset_email).await?;

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 4: Email with CC, BCC, and custom headers
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n📧 Demo 4: Email with CC, BCC, and Headers\n");

    let advanced_email = Email::new()
        .to("team-lead@example.com")
        .cc("manager@example.com")
        .bcc("hr@example.com")
        .from("notifications@myapp.com")
        .reply_to("no-reply@myapp.com")
        .subject("Weekly Status Report")
        .text("Please find attached the weekly status report.\n\nBest regards,\nAutomated System")
        .header("X-Priority", "1")
        .header("X-Auto-Generated", "true");

    backend.send(advanced_email).await?;

    // ─────────────────────────────────────────────────────────────────────────
    // Summary
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║                     Demo Complete!                            ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║ The ConsoleBackend prints emails to stdout for development.   ║");
    println!("║                                                               ║");
    println!("║ For production, use:                                          ║");
    println!("║   • SmtpBackend::from_env()  - SMTP server                    ║");
    println!("║   • AwsSesBackend::new()     - AWS SES (requires feature)     ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    Ok(())
}
