import { originOf, signInProof } from "../protocol/auth-proof";
import { HqcWrapper } from "../protocol/hqc";
import { newSigningKey, type SigningKey, signConnect } from "../protocol/mqtt-proof";
import { ApiError, requestJson } from "./http";
import type { Identity } from "./identity";

interface Grant {
  sessionToken?: string;
  mqttKeyId?: string;
  serverTime?: number;
}

/**
 * Sign-in and MQTT credentials. Sign-in answers the server's KEM challenge
 * with `authProof` and registers a per-session Ed25519 key; every MQTT CONNECT
 * then carries a fresh signed proof (`mqttPassword`), timestamped in server time.
 */
export class Auth {
  private token = "";
  private signing: SigningKey | null = null;
  private keyId = "";
  private clockOffsetSec = 0;

  constructor(
    private readonly baseUrl: string,
    private readonly identity: Identity,
  ) {}

  /** The REST session bearer, or "" before sign-in. */
  get bearer(): string {
    return this.token;
  }

  /** Server time in unix seconds. */
  nowSec(): number {
    return Date.now() / 1000 + this.clockOffsetSec;
  }

  /** Runs the KEM sign-in and registers a new MQTT signing key. */
  async signIn(): Promise<void> {
    const origin = originOf(this.baseUrl);
    if (!origin) throw new Error(`not an http(s) origin: ${this.baseUrl}`);
    const init = await requestJson<{ ct?: string }>(`${this.baseUrl}/auth/init`, {
      method: "POST",
      body: { pk: this.identity.pkHex, origin },
    });
    if (typeof init.ct !== "string") throw new Error("/auth/init returned no challenge");
    const ct = Buffer.from(init.ct, "base64");
    const ss = HqcWrapper.decapsulate(this.identity.sk, ct);
    const signing = newSigningKey();
    const grant = await requestJson<Grant>(`${this.baseUrl}/auth/verify`, {
      method: "POST",
      body: {
        pk: this.identity.pkHex,
        solution: signInProof(ss, origin, Buffer.from(this.identity.pkHex, "hex"), ct).toString("base64"),
        mqttSigningKey: signing.publicKeyB64,
      },
    });
    if (typeof grant.sessionToken !== "string") throw new Error("/auth/verify returned no session");
    this.token = grant.sessionToken;
    this.adopt(signing, grant);
  }

  /** Registers a new MQTT signing key on the current session; false when the session has lapsed. */
  async refresh(): Promise<boolean> {
    if (!this.token) return false;
    const signing = newSigningKey();
    try {
      this.adopt(
        signing,
        await requestJson<Grant>(`${this.baseUrl}/auth/refresh`, {
          method: "POST",
          bearer: this.token,
          body: { mqttSigningKey: signing.publicKeyB64 },
        }),
      );
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return false;
      throw e;
    }
  }

  /** Fresh MQTT credentials, signing in again when the session has lapsed. */
  async renew(): Promise<void> {
    if (!(await this.refresh())) await this.signIn();
  }

  /** A fresh CONNECT password for `clientId`. */
  mqttPassword(clientId = this.identity.id): string {
    if (!this.signing || !this.keyId) throw new Error("not signed in");
    return signConnect({
      clientid: clientId,
      keyId: this.keyId,
      privateKey: this.signing.privateKey,
      nowSec: this.nowSec(),
    });
  }

  private adopt(signing: SigningKey, grant: Grant): void {
    if (typeof grant.mqttKeyId !== "string") throw new Error("the server returned no MQTT signing-key id");
    this.signing = signing;
    this.keyId = grant.mqttKeyId;
    if (typeof grant.serverTime === "number") this.clockOffsetSec = grant.serverTime - Date.now() / 1000;
  }
}
