import { describe, expect, it } from 'vitest';
import { exposureFromVector } from '../src/cvss.js';

describe('exposureFromVector', () => {
  it('flags a 3.1 pre-auth network bug (CVE-2024-3400)', () => {
    expect(exposureFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe('remote-unauth');
  });

  it('ignores temporal metrics appended to a 3.1 vector (CVE-2025-32756)', () => {
    expect(
      exposureFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:X/RC:C'),
    ).toBe('remote-unauth');
  });

  it('reads a 4.0 vector with supplemental metrics (CVE-2024-0012)', () => {
    expect(
      exposureFromVector(
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N/AU:N/R:U/V:C/RE:H/U:Red',
      ),
    ).toBe('remote-unauth');
  });

  it('needs both no privileges and no interaction (CVE-2024-0007)', () => {
    expect(exposureFromVector('CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H')).toBe('remote');
    expect(exposureFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H')).toBe('remote');
    expect(exposureFromVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBe(
      'remote',
    );
  });

  it('treats adjacent, local and physical vectors as other', () => {
    expect(exposureFromVector('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe('other');
    expect(exposureFromVector('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe('other');
    expect(exposureFromVector('CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBe(
      'other',
    );
  });

  it('does not read environmental MAV as the base attack vector', () => {
    expect(exposureFromVector('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:N')).toBe('other');
  });

  it('will not claim "no auth" from a v2 vector, which has no PR/UI', () => {
    expect(exposureFromVector('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBe('remote');
  });

  it('returns null when there is nothing to read', () => {
    expect(exposureFromVector(null)).toBeNull();
    expect(exposureFromVector('')).toBeNull();
    expect(exposureFromVector('garbage')).toBeNull();
  });
});
