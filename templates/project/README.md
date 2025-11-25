# acton-htmx Project Templates

This directory contains templates for generating new acton-htmx projects with the `acton-htmx new` command.

## Structure

```
project/
├── common/                 # Templates shared between SQLite and PostgreSQL
│   ├── src/handlers/       # Shared handler modules
│   ├── templates/          # Shared Askama templates
│   └── static/             # Shared static assets
├── sqlite/                 # SQLite-specific templates
│   ├── src/                # SQLite-specific source files
│   ├── migrations/         # SQLite migrations
│   └── config/             # SQLite config files
├── postgres/               # PostgreSQL-specific templates
│   ├── src/                # PostgreSQL-specific source files
│   ├── migrations/         # PostgreSQL migrations
│   └── config/             # PostgreSQL config files
└── manifest.toml           # Template manifest (lists all files)
```

## Template Variables

Templates use Handlebars syntax with the following variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{project_name}}` | Project name as provided | `my-app` |
| `{{project_name_snake}}` | Project name in snake_case | `my_app` |

## Customization

Users can customize templates by:

1. Copy templates to `$XDG_CONFIG_HOME/acton-htmx/templates/project/`
2. Edit the copied templates
3. The CLI will use customized templates from XDG config directory first

## Adding New Templates

1. Add the template file to the appropriate directory (`common/`, `sqlite/`, or `postgres/`)
2. Update `manifest.toml` to include the new template
3. Update the `TemplateManager` in the CLI if needed

## Template Guidelines

- Use `.hbs` extension for all template files
- Include clear comments explaining purpose
- Follow acton-htmx code style guidelines
- Keep templates minimal and focused
- Test generated code compiles without warnings
