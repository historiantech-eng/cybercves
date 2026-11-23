import { describe, expect, it } from 'vitest';
import { toSecurityRows, type CveRow, type SecurityProducts } from '../src/lib/cve-rows';

const row = (p: string[], v: string[], g: string[], k = 0): CveRow => ({
  i: `CVE-2026-${p.join('-')}`,
  d: '2026-01-01',
  s: 'HIGH',
  c: 7.5,
  x: null,
  w: null,
  k,
  e: null,
  v,
  p,
  g,
});

// Routers are deliberately absent: the map holds security products only.
const SECURITY: SecurityProducts = {
  'cisco-asa': ['cisco', 'firewall'],
  'splunk-enterprise': ['cisco', 'siem-logging'],
  'fortinet-fortigate': ['fortinet', 'firewall'],
};

describe('toSecurityRows', () => {
  it('drops a CVE whose only products are non-security', () => {
    expect(toSecurityRows([row(['cisco-ios-xe'], ['cisco'], ['routing-switching'])], SECURITY)).toEqual([]);
  });

  it('drops a CVE mapped to no product, as the vendor rollup does', () => {
    expect(toSecurityRows([row([], [], [])], SECURITY)).toEqual([]);
  });

  it('keeps a mixed CVE but strips the non-security product and category', () => {
    const [out] = toSecurityRows(
      [row(['cisco-asa', 'cisco-ios-xe'], ['cisco'], ['firewall', 'routing-switching'])],
      SECURITY,
    );
    expect(out.p).toEqual(['cisco-asa']);
    expect(out.g).toEqual(['firewall']);
    expect(out.v).toEqual(['cisco']);
  });

  it('does not credit a vendor whose only product on the CVE is non-security', () => {
    // Cisco's router and Fortinet's firewall on one record: the rollup counts it
    // for Fortinet only, so the chart must too.
    const [out] = toSecurityRows(
      [
        row(
          ['cisco-ios-xe', 'fortinet-fortigate'],
          ['cisco', 'fortinet'],
          ['routing-switching', 'firewall'],
        ),
      ],
      SECURITY,
    );
    expect(out.v).toEqual(['fortinet']);
  });

  it('keeps the CVE-level fields untouched', () => {
    const [out] = toSecurityRows([row(['splunk-enterprise'], ['cisco'], ['siem-logging'], 1)], SECURITY);
    expect(out).toMatchObject({ s: 'HIGH', c: 7.5, k: 1 });
  });
});
