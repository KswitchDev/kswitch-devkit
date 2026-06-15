/**
 * M2M token management for Keycloak / Logto client_credentials flow.
 * Handles token fetch, caching, and automatic refresh.
 */

export interface TokenConfig {
  clientId: string;
  clientSecret: string;
  tokenEndpoint?: string;
  keycloakUrl?: string;
  keycloakRealm?: string;
  resource?: string;
}

interface CachedToken {
  accessToken: string;
  expiresAt: number; // epoch ms
}

export class TokenManager {
  private readonly config: TokenConfig;
  private cached: CachedToken | null = null;
  private pendingRefresh: Promise<string> | null = null;

  constructor(config: TokenConfig) {
    this.config = config;
  }

  /**
   * Resolve the OIDC token endpoint URL.
   */
  private getTokenEndpoint(): string {
    if (this.config.tokenEndpoint) {
      return this.config.tokenEndpoint;
    }
    if (this.config.keycloakUrl) {
      const realm = this.config.keycloakRealm ?? "kswitch";
      return `${this.config.keycloakUrl.replace(/\/+$/, "")}/realms/${realm}/protocol/openid-connect/token`;
    }
    throw new Error(
      "TokenManager: either tokenEndpoint or keycloakUrl must be provided",
    );
  }

  /**
   * Get a valid access token, refreshing if needed.
   * De-duplicates concurrent refresh requests.
   */
  async getToken(): Promise<string> {
    // Return cached if still valid (with 60s buffer)
    if (this.cached && this.cached.expiresAt > Date.now() + 60_000) {
      return this.cached.accessToken;
    }
    // De-duplicate concurrent refreshes
    if (this.pendingRefresh) {
      return this.pendingRefresh;
    }
    this.pendingRefresh = this.fetchToken();
    try {
      return await this.pendingRefresh;
    } finally {
      this.pendingRefresh = null;
    }
  }

  /**
   * Invalidate the cached token, forcing a refresh on next getToken().
   */
  invalidate(): void {
    this.cached = null;
  }

  /**
   * Fetch a fresh token via client_credentials grant.
   */
  private async fetchToken(): Promise<string> {
    const endpoint = this.getTokenEndpoint();

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    if (this.config.resource) {
      body.set("resource", this.config.resource);
    }

    const resp = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(10_000),
    });

    if (!resp.ok) {
      // Do not log response body — it may contain sensitive error details from the IdP
      throw new Error(
        `Token fetch failed with status ${resp.status}`,
      );
    }

    const data = (await resp.json()) as {
      access_token: string;
      expires_in?: number;
    };

    const expiresIn = (data.expires_in ?? 3600) * 1000; // to ms
    this.cached = {
      accessToken: data.access_token,
      expiresAt: Date.now() + expiresIn,
    };

    return data.access_token;
  }
}
