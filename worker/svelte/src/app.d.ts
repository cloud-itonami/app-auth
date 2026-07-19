import type { D1Database } from "@cloudflare/workers-types";

declare global {
  namespace App {
    interface Platform {
      env?: {
        AUTH_DB?: D1Database;
        SS_AT_SESSION_SECRET?: string;
      };
    }
  }
}

export {};
