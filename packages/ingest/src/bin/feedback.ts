#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

/**
 * Triage queue for reader-submitted corrections.
 *
 *   npm run feedback                              # everything still new
 *   npm run feedback -- --status all
 *   npm run feedback -- --accept 42 --note "fixed in 657471b"
 *   npm run feedback -- --reject 43 --note "not reproducible"
 *
 * Accepting opens a GitHub issue to track the fix. That issue is created HERE,
 * by the already-authenticated `gh` on your machine — not by the Worker. It is
 * why no GitHub write token is stored in Cloudflare at all, and why spam never
 * reaches a public issue: nothing becomes public until a human accepts it.
 *
 * Reads the admin token from ~/.cybercve_admin_token (mode 600) and never prints
 * it. Override the file with CYBERCVE_ADMIN_TOKEN_FILE.
 */

const { values } = parseArgs({
  options: {
    base: { type: 'string', default: 'https://cybercve.com' },
    status: { type: 'string', default: 'new' },
    limit: { type: 'string', default: '50' },
    accept: { type: 'string' },
    reject: { type: 'string' },
    duplicate: { type: 'string' },
    note: { type: 'string' },
    /** Mark triaged without opening an issue — for corrections fixed on the spot. */
    'no-issue': { type: 'boolean', default: false },
    repo: { type: 'string', default: 'historiantech-eng/cybercves' },
  },
});

function adminToken(): string {
  const path = process.env.CYBERCVE_ADMIN_TOKEN_FILE ?? join(homedir(), '.cybercve_admin_token');
  try {
    const token = readFileSync(path, 'utf8').trim();
    if (!token) throw new Error('empty');
    return token;
  } catch {
    console.error(
      `No admin token at ${path}.\n` +
        'That file holds the same secret as the ADMIN_TOKEN Worker secret.\n' +
        'Create it with mode 600; do not paste the token into a terminal that logs.',
    );
    process.exit(1);
  }
}

const TOKEN = adminToken();

async function api(path: string, init: RequestInit = {}): Promise<unknown> {
  const res = await fetch(`${values.base}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      accept: 'application/json',
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...(init.headers ?? {}),
    },
  });
  if (res.status === 401) {
    console.error('Unauthorized — the local token does not match the ADMIN_TOKEN secret.');
    process.exit(1);
  }
  if (!res.ok) {
    console.error(`${init.method ?? 'GET'} ${path} failed: ${res.status}`);
    process.exit(1);
  }
  return res.json();
}

interface Item {
  id: number;
  created_at: string;
  kind: string;
  cve_id: string | null;
  page_url: string | null;
  body: string;
  evidence_url: string | null;
  reporter_email: string | null;
  status: string;
  triage_note: string | null;
  github_issue: number | null;
}

function openIssue(item: Item, note: string | undefined): number | null {
  const title = `[feedback] ${item.kind}${item.cve_id ? `: ${item.cve_id}` : ''}`;
  // Only the report itself goes public. The reporter's email is deliberately
  // absent — they gave it so we could reply, not so it could be published.
  const body = [
    item.cve_id ? `**Record:** ${item.cve_id}` : null,
    item.page_url ? `**Reported from:** https://cybercve.com${item.page_url}` : null,
    item.evidence_url ? `**Evidence:** ${item.evidence_url}` : null,
    '',
    '### Report',
    '',
    item.body,
    '',
    note ? `### Triage note\n\n${note}\n` : null,
    '---',
    `Submitted via cybercve.com on ${item.created_at.slice(0, 10)} (feedback #${item.id}).`,
  ]
    .filter((line) => line !== null)
    .join('\n');

  try {
    const url = execFileSync(
      'gh',
      ['issue', 'create', '--repo', values.repo, '--title', title, '--body', body, '--label', 'feedback'],
      { encoding: 'utf8' },
    ).trim();
    console.log(`  issue: ${url}`);
    const n = Number.parseInt(url.split('/').pop() ?? '', 10);
    return Number.isInteger(n) ? n : null;
  } catch (err) {
    // Never fatal: the correction is already accepted in the queue, and losing
    // the issue is recoverable by hand while losing the triage state is not.
    console.warn(`  could not create issue (${(err as Error).message.split('\n')[0]})`);
    console.warn('  the item is still marked accepted; open an issue by hand if you want one.');
    return null;
  }
}

async function triage(
  id: number,
  status: 'accepted' | 'rejected' | 'duplicate',
): Promise<void> {
  const { items } = (await api(`/api/v1/admin/feedback?status=all&limit=200`)) as {
    items: Item[];
  };
  const item = items.find((i) => i.id === id);
  if (!item) {
    console.error(`No feedback #${id}.`);
    process.exit(1);
  }

  let issue: number | null = null;
  if (status === 'accepted' && !values['no-issue']) issue = openIssue(item, values.note);

  await api(`/api/v1/admin/feedback/${id}`, {
    method: 'POST',
    body: JSON.stringify({ status, note: values.note ?? null, githubIssue: issue }),
  });
  console.log(`#${id} → ${status}`);
  if (item.reporter_email && status === 'accepted') {
    console.log(`  reporter left an address: ${item.reporter_email}`);
  }
}

const target = values.accept ?? values.reject ?? values.duplicate;
if (target) {
  const id = Number.parseInt(target, 10);
  if (!Number.isInteger(id)) {
    console.error('Pass a numeric feedback id.');
    process.exit(1);
  }
  await triage(
    id,
    values.accept ? 'accepted' : values.reject ? 'rejected' : 'duplicate',
  );
} else {
  const { items } = (await api(
    `/api/v1/admin/feedback?status=${encodeURIComponent(values.status)}&limit=${values.limit}`,
  )) as { items: Item[] };

  if (!items.length) {
    console.log(
      values.status === 'new' ? 'Nothing new to triage.' : `No feedback with status "${values.status}".`,
    );
  } else {
    for (const item of items) {
      const flags = [
        item.status !== 'new' ? item.status : null,
        item.github_issue ? `#${item.github_issue}` : null,
      ]
        .filter(Boolean)
        .join(' ');
      console.log(
        `\n#${item.id}  ${item.created_at.slice(0, 10)}  ${item.kind}` +
          `${item.cve_id ? `  ${item.cve_id}` : ''}${flags ? `  [${flags}]` : ''}`,
      );
      if (item.page_url) console.log(`     page: ${item.page_url}`);
      if (item.evidence_url) console.log(`     link: ${item.evidence_url}`);
      console.log(`     ${item.body.replace(/\s+/g, ' ').slice(0, 300)}`);
      console.log(`     from: ${item.reporter_email ?? '(anonymous)'}`);
      if (item.triage_note) console.log(`     note: ${item.triage_note}`);
    }
    console.log(
      `\n${items.length} item(s).  Accept: npm run feedback -- --accept <id> --note "…"`,
    );
  }
}
