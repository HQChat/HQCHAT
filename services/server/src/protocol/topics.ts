/**
 * MQTT topic names (the broker's policy is infra/emqx/acl.conf).
 *
 * `cv/{convoId}` and `hs/{handshakeId}` are capabilities: random ids minted per
 * friendship and given only to its two members. `u/{id}/…` topics are addressed
 * by client id: presence is owner-publish, inbox and graph owner-subscribe.
 */

/** A topic id: 64 lowercase hex characters. */
export const TOPIC_ID = /^[0-9a-f]{64}$/;

export function conversationTopic(convoId: string): string {
  return `cv/${convoId}`;
}

export function handshakeTopic(handshakeId: string): string {
  return `hs/${handshakeId}`;
}

export function presenceTopic(id: string): string {
  return `u/${id}/presence`;
}

export function inboxTopic(id: string): string {
  return `u/${id}/inbox`;
}

/** Where the server signals that a client's friend graph changed. */
export function graphTopic(id: string): string {
  return `u/${id}/graph`;
}
