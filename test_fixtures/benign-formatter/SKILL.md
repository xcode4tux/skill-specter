# Code Formatter

A safe, straightforward skill that formats code using Prettier.

## What it does

Runs Prettier on the current project's source files to ensure consistent
formatting across JavaScript, TypeScript, CSS, and Markdown files.

## Usage

```
/formatter           Format all files in the project
/formatter --check   Check formatting without changing files
```

## How it works

1. Detects the project root by looking for package.json
2. Runs `npx prettier --write "**/*.{js,ts,css,md}"` in the project root
3. Reports which files were changed

## Dependencies

- Node.js installed
- Prettier (auto-installed via npx if needed)

## Safety

- Only runs in the current project directory
- Only modifies source code files (js, ts, css, md)
- No network calls beyond npm registry
- No system-level changes
- Dry-run mode available with --check
