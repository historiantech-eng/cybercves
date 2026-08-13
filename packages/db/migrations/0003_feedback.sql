-- Reader-submitted corrections.
--
-- The site makes factual claims about named companies' security records, so being
-- correctable is the point: /methodology has invited corrections since launch with
-- no mechanism to send one.
--
-- THIS TABLE IS THE ONLY DATA HERE THAT CANNOT BE REBUILT FROM SOURCE.
--
-- Every other table is derived from the CVE List, KEV, EPSS or the committed
-- taxonomy, and `push:d1` restores them nightly by truncating and reinserting.
-- Feedback exists only in D1. It must therefore never appear in the TABLES list
-- in packages/ingest/src/bin/push-d1.ts — a test asserts this, because adding it
-- there "for completeness" would silently destroy every correction ever sent and
-- nothing would look broken afterwards.

CREATE TABLE IF NOT EXISTS feedback (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT NOT NULL,

  -- What kind of problem is being reported. Constrained so the triage queue can
  -- be filtered and so a malformed submission is rejected at the edge.
  kind          TEXT NOT NULL CHECK (kind IN (
                  'wrong-category', 'wrong-vendor', 'wrong-discovery',
                  'missing-cve', 'other'
                )),

  -- Context captured from the page the report came from, so a correction can be
  -- acted on without a round trip asking "which record?".
  cve_id        TEXT,
  page_url      TEXT,

  body          TEXT NOT NULL,
  evidence_url  TEXT,

  -- Optional, and only ever used to follow up on this report. Never displayed,
  -- never published to a GitHub issue, never mailed anything else.
  reporter_email TEXT,

  status        TEXT NOT NULL DEFAULT 'new' CHECK (status IN (
                  'new', 'accepted', 'rejected', 'duplicate'
                )),
  triaged_at    TEXT,
  triage_note   TEXT,
  -- Set when triage promotes an accepted report to a public issue.
  github_issue  INTEGER,

  -- Salted hash, never the raw address: enough to spot one source flooding the
  -- form, not enough to be a log of who reads the site. The salt lives in a
  -- Worker secret, so the column is useless on its own.
  ip_hash       TEXT,
  user_agent    TEXT
);

-- The triage queue is "everything still new, oldest first".
CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status, created_at);

-- Abuse checks count recent submissions per source.
CREATE INDEX IF NOT EXISTS idx_feedback_ip ON feedback(ip_hash, created_at);
