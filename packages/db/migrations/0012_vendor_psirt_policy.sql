-- Link to each vendor's published PSIRT / vulnerability-handling policy, from
-- `psirtPolicyUrl` in data/vendors/*.yaml. Separate from psirt_url, which is the
-- advisory listing: one says what they disclosed, the other how they decide to.
ALTER TABLE vendor ADD COLUMN psirt_policy_url TEXT;
