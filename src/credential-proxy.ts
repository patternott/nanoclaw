/**
 * Credential proxy for container isolation.
 * Containers connect here instead of directly to the Anthropic API.
 * The proxy injects real credentials so containers never see them.
 *
 * Two auth modes:
 *   API key:  Proxy injects x-api-key on every request.
 *   OAuth:    Container CLI exchanges its placeholder token for a temp
 *             API key via /api/oauth/claude_cli/create_api_key.
 *             Proxy injects real OAuth token on that exchange request;
 *             subsequent requests carry the temp key which is valid as-is.
 */
import { createServer, Server } from 'http';
import { request as httpsRequest } from 'https';
import { request as httpRequest, RequestOptions } from 'http';
import { homedir } from 'os';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';

const OAUTH_TOKEN_URL = 'https://platform.claude.com/v1/oauth/token';
const OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const REFRESH_BUFFER_MS = 15 * 60 * 1000; // refresh 15 min before expiry

export type AuthMode = 'api-key' | 'oauth';

export interface ProxyConfig {
  authMode: AuthMode;
}

interface ClaudeOAuthCredentials {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  scopes: string[];
  [key: string]: unknown;
}

interface ClaudeCredentialsFile {
  claudeAiOauth?: ClaudeOAuthCredentials;
  [key: string]: unknown;
}

const CREDENTIALS_PATH = join(homedir(), '.claude', '.credentials.json');

/** Reads and parses ~/.claude/.credentials.json. Returns undefined on any error. */
export function readClaudeCredentials(): ClaudeCredentialsFile | undefined {
  try {
    return JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf8')) as ClaudeCredentialsFile;
  } catch {
    return undefined;
  }
}

/** Returns just the accessToken from the Claude credential store, or undefined. */
export function readClaudeCredentialToken(): string | undefined {
  return readClaudeCredentials()?.claudeAiOauth?.accessToken;
}

/** Refreshes the OAuth token using the stored refresh token and writes the result back. */
export async function refreshOAuthToken(): Promise<void> {
  const creds = readClaudeCredentials();
  const oauth = creds?.claudeAiOauth;
  if (!oauth?.refreshToken) {
    logger.warn('refreshOAuthToken: no refresh token available');
    return;
  }

  const body = JSON.stringify({
    grant_type: 'refresh_token',
    refresh_token: oauth.refreshToken,
    client_id: OAUTH_CLIENT_ID,
    scope: oauth.scopes.join(' '),
  });

  return new Promise((resolve) => {
    const url = new URL(OAUTH_TOKEN_URL);
    const req = httpsRequest(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString()) as {
              access_token: string;
              refresh_token?: string;
              expires_in?: number;
            };
            if (!data.access_token) {
              logger.error({ status: res.statusCode }, 'refreshOAuthToken: no access_token in response');
              return resolve();
            }
            const updated: ClaudeCredentialsFile = {
              ...creds,
              claudeAiOauth: {
                ...oauth,
                accessToken: data.access_token,
                refreshToken: data.refresh_token ?? oauth.refreshToken,
                expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
              },
            };
            writeFileSync(CREDENTIALS_PATH, JSON.stringify(updated, null, 2), { mode: 0o600 });
            logger.info('refreshOAuthToken: token refreshed successfully');
          } catch (err) {
            logger.error({ err }, 'refreshOAuthToken: failed to parse response');
          }
          resolve();
        });
      },
    );
    req.on('error', (err) => {
      logger.error({ err }, 'refreshOAuthToken: request failed');
      resolve();
    });
    req.write(body);
    req.end();
  });
}

/** Starts a background timer that proactively refreshes the OAuth token before it expires. */
export function startOAuthRefreshTimer(): void {
  const check = () => {
    const creds = readClaudeCredentials();
    const expiresAt = creds?.claudeAiOauth?.expiresAt;
    if (expiresAt && Date.now() >= expiresAt - REFRESH_BUFFER_MS) {
      refreshOAuthToken().catch((err) => logger.error({ err }, 'startOAuthRefreshTimer: refresh error'));
    }
  };

  check();
  const timer = setInterval(check, 5 * 60 * 1000);
  timer.unref();
}

export function startCredentialProxy(
  port: number,
  host = '127.0.0.1',
): Promise<Server> {
  const secrets = readEnvFile([
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
  ]);

  const authMode: AuthMode = secrets.ANTHROPIC_API_KEY ? 'api-key' : 'oauth';
  const envOauthToken =
    secrets.CLAUDE_CODE_OAUTH_TOKEN || secrets.ANTHROPIC_AUTH_TOKEN;

  if (authMode === 'oauth' && !envOauthToken) {
    startOAuthRefreshTimer();
  }

  const upstreamUrl = new URL(
    secrets.ANTHROPIC_BASE_URL || 'https://api.anthropic.com',
  );
  const isHttps = upstreamUrl.protocol === 'https:';
  const makeRequest = isHttps ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string | number | string[] | undefined> =
          {
            ...(req.headers as Record<string, string>),
            host: upstreamUrl.host,
            'content-length': body.length,
          };

        // Strip hop-by-hop headers that must not be forwarded by proxies
        delete headers['connection'];
        delete headers['keep-alive'];
        delete headers['transfer-encoding'];

        if (authMode === 'api-key') {
          // API key mode: inject x-api-key on every request
          delete headers['x-api-key'];
          headers['x-api-key'] = secrets.ANTHROPIC_API_KEY;
        } else {
          // OAuth mode: replace placeholder Bearer token with the real one
          // only when the container actually sends an Authorization header
          // (exchange request + auth probes). Post-exchange requests use
          // x-api-key only, so they pass through without token injection.
          if (headers['authorization']) {
            delete headers['authorization'];
            const oauthToken = envOauthToken || readClaudeCredentialToken();
            if (oauthToken) {
              headers['authorization'] = `Bearer ${oauthToken}`;
            }
          }
        }

        const upstream = makeRequest(
          {
            hostname: upstreamUrl.hostname,
            port: upstreamUrl.port || (isHttps ? 443 : 80),
            path: req.url,
            method: req.method,
            headers,
          } as RequestOptions,
          (upRes) => {
            res.writeHead(upRes.statusCode!, upRes.headers);
            upRes.pipe(res);
          },
        );

        upstream.on('error', (err) => {
          logger.error(
            { err, url: req.url },
            'Credential proxy upstream error',
          );
          if (!res.headersSent) {
            res.writeHead(502);
            res.end('Bad Gateway');
          }
        });

        upstream.write(body);
        upstream.end();
      });
    });

    server.listen(port, host, () => {
      logger.info({ port, host, authMode }, 'Credential proxy started');
      resolve(server);
    });

    server.on('error', reject);
  });
}

/** Detect which auth mode the host is configured for. */
export function detectAuthMode(): AuthMode {
  const secrets = readEnvFile(['ANTHROPIC_API_KEY']);
  return secrets.ANTHROPIC_API_KEY ? 'api-key' : 'oauth';
}

/** Returns true if any OAuth credential source is available. */
export function hasOAuthCredentials(): boolean {
  const secrets = readEnvFile(['CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_AUTH_TOKEN']);
  return !!(
    secrets.CLAUDE_CODE_OAUTH_TOKEN ||
    secrets.ANTHROPIC_AUTH_TOKEN ||
    readClaudeCredentialToken()
  );
}
