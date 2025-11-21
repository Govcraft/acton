# acton-htmx

> **Status**: 🚧 Pre-alpha / Active Development (Phase 1)

**Opinionated Rust web framework for server-rendered HTMX applications**

acton-htmx is a production-grade web framework that gets you from idea to deployment in minutes, not days. Built on battle-tested components from the Acton ecosystem, it combines Axum's performance with HTMX's hypermedia-driven architecture.

## Design Principles

1. **Convention Over Configuration** - Smart defaults everywhere, no decision paralysis
2. **Security by Default** - CSRF protection, secure sessions, security headers enabled out-of-the-box
3. **HTMX-First Architecture** - Response helpers and patterns designed for hypermedia
4. **Type Safety Without Ceremony** - Compile-time guarantees via Rust's type system
5. **Idiomatic Excellence** - Generated code exemplifies Rust best practices

## Features

- ✅ **Zero-configuration setup** - `acton-htmx new myapp` and you're running
- ✅ **HTMX response helpers** - Type-safe wrappers for HX-Redirect, HX-Trigger, HX-Swap-OOB, etc.
- ✅ **Session-based authentication** - Secure HTTP-only cookies with automatic CSRF protection
- ✅ **Template integration** - Compile-time checked Askama templates
- ✅ **Form handling** - Declarative forms with validation and HTMX-aware error rendering
- ✅ **Background jobs** - Type-safe actor-based job system (acton-reactive)
- ✅ **Flash messages** - Automatic coordination via actors with OOB swaps
- ✅ **Production-ready** - OpenTelemetry, health checks, graceful shutdown

## Quick Start

```bash
# Install CLI
cargo install acton-htmx-cli

# Create new project
acton-htmx new blog
cd blog

# Start development server with hot reload
acton-htmx dev
```

Visit `http://localhost:3000` to see your app running!

## Example: HTMX Handler

```rust
use acton_htmx::prelude::*;

#[derive(Template)]
#[template(path = "posts/index.html")]
struct PostsIndexTemplate {
    posts: Vec<Post>,
}

pub async fn index(
    State(state): State<ActonHtmxState>,
    hx: HxRequest,
) -> Result<HxResponse> {
    let posts = Post::find_all(&state.db()).await?;

    let template = PostsIndexTemplate { posts };

    // Automatically returns full page or partial based on HX-Request header
    Ok(hx.auto_render(template))
}

pub async fn create(
    State(state): State<ActonHtmxState>,
    Form(form): Form<PostForm>,
) -> Result<HxResponse> {
    let post = Post::create(&state.db(), form).await?;

    // Redirect with HTMX support
    Ok(HxRedirect::to(&format!("/posts/{}", post.id)))
}
```

## Architecture

acton-htmx reuses **60-70% of production infrastructure** from the Acton ecosystem:

### From [acton-service](https://github.com/GovCraft/acton-service)
- Configuration (XDG + figment)
- Observability (OpenTelemetry)
- Middleware (compression, CORS, rate limiting)
- Connection pools (PostgreSQL, Redis)
- Health checks

### From [acton-reactive](https://github.com/GovCraft/acton-reactive)
- Actor runtime for background jobs
- Session state management
- Flash message coordination
- Real-time features (SSE)
- Cache coordination

### HTMX-specific (new in acton-htmx)
- Response helpers (HxRedirect, HxTrigger, etc.)
- Template integration (Askama)
- Form handling with CSRF
- Session-based authentication

## Documentation

- [Vision Document](./acton-htmx-vision.md) - Project goals and philosophy
- [Architecture Overview](./.claude/architecture-overview.md) - System design
- [Implementation Plan](./.claude/phase-1-implementation-plan.md) - Development roadmap
- [API Documentation](https://docs.rs/acton-htmx) - Generated API docs (coming soon)

## Development Status

**Current Phase**: Phase 1 - Foundation (Weeks 1-12)

**Completed**:
- ✅ Workspace structure
- ✅ CI/CD pipeline
- ✅ Crate scaffolding

**In Progress**:
- 🔄 Core integration (acton-service + acton-reactive)
- 🔄 HTMX response layer
- 🔄 Template engine integration

**Next Up**:
- ⏳ Authentication & sessions
- ⏳ CSRF protection
- ⏳ CLI implementation

See [Phase 1 Implementation Plan](./.claude/phase-1-implementation-plan.md) for detailed timeline.

## Contributing

We welcome contributions! See [Development Workflow](./.claude/development-workflow.md) for setup instructions.

**Development Standards**:
- Zero `unsafe` code (enforced via `#![forbid(unsafe_code)]`)
- Clippy pedantic + nursery (no warnings)
- 90%+ test coverage
- Conventional Commits
- API documentation for all public items

## Comparison to Other Frameworks

| Feature | acton-htmx | Loco | Axum | Rails |
|---------|-----------|------|------|-------|
| **Time to First App** | 5 min | 10 min | 60 min | 10 min |
| **HTMX Integration** | First-class | Supported | Manual | Manual |
| **Auth for Browsers** | Session-based | JWT-focused | Manual | Session-based |
| **CSRF Protection** | Built-in | Manual | Manual | Built-in |
| **Template Type Safety** | Compile-time | Runtime | N/A | Runtime |
| **Security Defaults** | Opinionated | Configurable | Manual | Opinionated |
| **Performance** | Excellent | Excellent | Excellent | Good |

## License

MIT

## Credits

Built on:
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [acton-service](https://github.com/GovCraft/acton-service) - Microservice infrastructure
- [acton-reactive](https://github.com/GovCraft/acton-reactive) - Actor runtime
- [Askama](https://github.com/djc/askama) - Template engine
- [HTMX](https://htmx.org) - Hypermedia library

## Status

**Phase 1 (Foundation)**: 🟡 Active Development
**Target Release**: v1.0.0-alpha (Week 12)
**Production Ready**: Not yet - use at your own risk!

---

For questions, see [.claude/README.md](./.claude/README.md) or open an issue.
