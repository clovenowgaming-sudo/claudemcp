# Termux MCP Server

An MCP server designed to expose selected Termux workspace tools
to compatible MCP clients through an authenticated HTTPS endpoint.

## Features

- List workspace files
- Read text files
- Write files (where implemented)
- Run supported scripts (where implemented)
- OAuth-based authentication

## Requirements

- Android with Termux
- Node.js and npm
- A compatible MCP client
- HTTPS endpoint for remote access

## Installation

```bash
git clone YOUR_REPOSITORY_URL
cd termux-mcp
npm install
```

Configure your OAuth password and public HTTPS endpoint
using the instructions in the project documentation.

Start the server:

```bash
node server.js
```

## Security

- Never commit passwords, OAuth tokens, or OAuth databases.
- Use HTTPS for remote access.
- Restrict file operations to the configured workspace.
- Review OAuth and PKCE validation before exposing the server publicly.
- Do not expose the server directly to the public internet without authentication.

## License

Choose a license before distributing this project.
