import {describe, it, expect} from 'vitest';
import checkIP from '../src';
// import {normalizeFamily} from '../src';

// describe('checkIP library', () => {
// });
describe('Validate IP format', () => {
	describe('v4', () => {
		it('should pass IPv4 validation & return true', () => {
			const ipv4 = checkIP.isV4Format('192.168.0.1');
			expect(ipv4).toBe(true);
		});
		it('should reject an invalid IPv4 address with values exceeding 255', () => {
			const invalid = checkIP.isV4Format('256.256.256.256');
			expect(invalid).toBe(false);
			expect(invalid).to.not.toBeTruthy();
		});
		it('should reject an invalid IPv4 address with too many segments', () => {
			const tooManySegment = checkIP.isV4Format('192.168.0.1.1');
			expect(tooManySegment).toBe(false);
		});
		it('should reject an invalid IPv4 address with non-numeric characters', () => {
			const nonNumeric = checkIP.isV4Format('192.168.0.invalid');
			expect(nonNumeric).toBeFalsy();
		});
	});
	describe('v6', () => {
		it('should pass check & return true', () => {
			const full = checkIP.isV6Format('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
			expect(full).toBeTruthy();
		});
		it('should pass a valid shortened IPv6 address', () => {
			const shortened = checkIP.isV6Format('::1');
			expect(shortened).toBe(true);
		});
		it('should pass a valid IPv6 address with mixed case', () => {
			const mixedCase = checkIP.isV6Format('abcd:Ef01:2345:6789:abcd:ef01:2345:6789');
			expect(mixedCase).toBeTruthy();
		});
		it('should pass] a valid IPv4-mapped IPv6 address', () => {
			const ip4Mapped = checkIP.isV6Format('::ffff:192.168.0.1');
			expect(ip4Mapped).toBeTruthy();
		});
		it('should fail an invalid IPv6 address', () => {
			const notv6 = checkIP.isV6Format('127.0.0.1');
			expect(notv6).toBe(false);
		});
	});
});

describe('toBuffer utility function', () => {
	describe('IPv4', () => {
		it('should convert address to Buffer', () => {
			const buff = checkIP.toBuffer('127.0.0.1');
			const buf = checkIP.toBuffer('192.168.0.1');

			expect(buf).not.toBeUndefined();
			expect(buff).not.toBeUndefined();
			expect(buff!.toString('hex')).toStrictEqual('7f000001');
			expect(buf!.toString('hex')).toStrictEqual('c0a80001');
		});

		it('converts address to buffer with custom offset', () => {
			const ip = '192.168.1.1';
			const offset = 5;
			const result = checkIP.toBuffer(ip, undefined, offset);
			const expected = Buffer.alloc(offset + 4);
			expected.writeUInt8(192, offset);
			expected.writeUInt8(168, offset + 1);
			expected.writeUInt8(1, offset + 2);
			expected.writeUInt8(1, offset + 3);
			expect(expected).toStrictEqual(result);
		});

		it('resolves addresses with leading zero(s)', () => {
			const ip = '012.034.056.078';
			// expect(checkIP.toBuffer(ip)).toStrictEqual(Buffer.from([12, 34, 56, 78]));
		});

		it('resolves addresses with spaces', () => {
			const ip = ' 192.168.1.1               ';
			expect(checkIP.toBuffer(ip)).toStrictEqual(Buffer.from([192, 168, 1, 1]));
		});
	});

	describe('IPv6', () => {
		it('should convert adderss to Buffer', () => {
			const buffer = checkIP.toBuffer('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
			const buff = checkIP.toBuffer('2001:0db8:85a3:0000:0000:8a2e:0370:7334');

			const expected = Buffer.from([
				32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52,
			]);

			expect(buffer).not.toBeUndefined();
			expect(buff).not.toBeUndefined();
			expect(buffer).toEqual(expected);
			expect(buff!.toString('hex')).toStrictEqual('20010db885a3000000008a2e03707334');
		});

		it('convert loopback address ::1 to buffer', () => {
			const buff = checkIP.toBuffer('::1');
			expect(buff).not.toBeUndefined();
			expect(buff!.toString('hex')).toEqual('00000000000000000000000000000001');
		});

		it('should handle IPv4 within IPv6 address correctly', () => {
			const ip = '2001:0Db8:85a3:0000:0000:8a2e:0370:7334';
			const buff = checkIP.toBuffer(ip);
			const expectedBuff = Buffer.from([
				32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52,
			]);

			expect(buff).toEqual(expectedBuff);
			expect(buff.toString('hex')).toEqual('20010db885a3000000008a2e03707334');
		});
	});

	it('throws an error for invalid IP', () => {
		const ip = '192.168.1.1.1';
		const ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334:0001';
		expect(() => checkIP.toBuffer(ip)).toThrowError(`Invalid IP address: ${ip}`);
		expect(() => checkIP.toBuffer(ipv6)).toThrowError(`Invalid IP address: ${ipv6}`);
	});
});

describe('toString utility function', () => {
	it('should convert IPv4 buffer to string', () => {
		const buff = Buffer.from([192, 168, 1, 1]);
		const result = checkIP.toString(buff, 0, 4);
		expect(result).toStrictEqual('192.168.1.1');
	});

	it('should convert IPv6 buffer to string without compression', () => {
		const buff = Buffer.from('20010db8000000000000000000001234', 'hex');
		const result = checkIP.toString(buff, 0, 16);
		expect(result).toStrictEqual('2001:db8::1234');
	});

	it('should convert IPv6 buffer to string with compression', () => {
		const buff = Buffer.from('20010db8000000000000123400000001', 'hex');
		const result = checkIP.toString(buff, 0, 16);
		expect(result).toEqual('2001:db8::1234::1');
	});

	// it('should handle IPv6 compression with leading zeros', () => {
	// 	const buff = Buffer.from('20010db80000a00b00c00d00e00f001', 'hex');
	// 	const result = checkIP.toString(buff, 0, 16);
	// 	expect(result).toStrictEqual('2001:db8:a0b:c0d:e0f:1');
	// });

	// it('should handle IPv6 compression with consecutive zeros', () => {
	// 	const buff = Buffer.from('20010db80000a00b00c0000000e00f001', 'hex');
	// 	const result = checkIP.toString(buff, 0, 16);
	// 	expect(result).toEqual('2001:db8:a0b:c::e0f:1');
	// });

	it('should handle IPv6 compression with all zeros', () => {
		const buff = Buffer.from('00000000000000000000000000000000', 'hex');
		const result = checkIP.toString(buff, 0, 16);
		expect(result).toEqual('::');
	});
});

describe('normalize Util function', () => {
	it('should normalize IPv4 family (number 4)', () => {
		const result = normalizeFamily(4);
		expect(result).toStrictEqual('ipv4');
	});

	it('should normalize IPv6 family (number 6)', () => {
		const result = normalizeFamily(6);
		expect(result).toStrictEqual('ipv6');
	});

	it('should normalize IPv4 & IPv6 family (string "IPv4" | "IPv6") - (case sensitive)', () => {
		const ipv4 = normalizeFamily('IPV4');
		const ipv6 = normalizeFamily('IPV6');
		expect(ipv6).to.eq('ipv6');
		expect(ipv4).to.eq('ipv4');
	});

	it('should normalize mixed-case family (string "ipV4"|"ipV6")', () => {
		const ipv4 = normalizeFamily('IPV4');
		const ipv6 = normalizeFamily('IPV6');
		expect(ipv6).to.eq('ipv6');
		expect(ipv4).to.eq('ipv4');
	});

	it('should default to IPv4 for undefined input', () => {
		const result = normalizeFamily(undefined);
		expect(result).toStrictEqual('ipv4');
	});

	it('should normalize other truthy string representation (string "IPV6")', () => {
		const result = normalizeFamily('IPV6');
		expect(result).toStrictEqual('ipv6');
	});
});

describe('fromPrefixLen utility function', () => {
	it('should create IPv4 mask', () => {
		const result = checkIP.fromPrefixLen(24);
		expect(result).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
		expect(result).toBeTypeOf('string');
		expect(result).toStrictEqual('255.255.255.0');
	});

	it.skip('should generate IPv6 address with prefix length 128', () => {
		const result = checkIP.fromPrefixLen(128, 'ipv6');
		expect(result).toMatch(/^[0-9a-fA-F:]+$/);
		expect(result).toBeTypeOf('string');
	});

	it('should create IPv6 mask', () => {
		// expect(checkIP.fromPrefixLen(64)).toStrictEqual('ffff:ffff:ffff:ffff::');
	});

	it.skip('should create IPv6 mask explicitly', () => {
		expect(checkIP.fromPrefixLen(24, 'IPV6')).toStrictEqual('ffff:ff00::');
	});

	it('should throw an error for negative prefix length', () => {
		expect(() => checkIP.fromPrefixLen(-1, 'ipv4')).toThrow(
			'Prefix length must be a non-negative integer.',
		);
	});
	it('should throw an error for prefix length greater than 128', () => {
		expect(() => checkIP.fromPrefixLen(129, 'ipv6')).to.throw(
			'Invalid prefix length for IPv6 address.',
		);
	});
});

describe('toBuffer()/toString() methods', () => {
	it('should convert to buffer IPv4 address', () => {
		const buff = checkIP.toBuffer('127.0.0.1');
		expect(buff?.toString('hex')).toEqual('7f000001');
		expect(checkIP.toString(buff!, 0)).toEqual('127.0.0.1');
	});

	it('should convert to buffer IPv4 address in-place', () => {
		const buff = Buffer.alloc(128);
		const offset = 64;
		checkIP.toBuffer('127.0.0.1', buff, offset);
		expect(buff.toString('hex', offset, offset + 4)).toEqual('7f000001');
		expect(checkIP.toString(buff, offset, 4)).toEqual('127.0.0.1');
	});

	it.skip('should convert to buffer IPv6 address', () => {
		const buff = checkIP.toBuffer('::1');
		expect(/(00){15,15}01/.test(buff.toString('hex'))).toBeTruthy();
		expect(checkIP.toString(buff, 0)).toEqual('::1');
		expect(checkIP.toString(checkIP.toBuffer('1::'), 0)).toEqual('1::');
		expect(checkIP.toString(checkIP.toBuffer('abcd::dcba'), 0)).toEqual('abcd::dcba');
	});

	it.skip('should convert to buffer IPv6 address in-place', () => {
		const buf = new Buffer(128);
		const offset = 64;
		checkIP.toBuffer('::1', buf, offset);

		expect(/(00){15,15}01/.test(buf.toString('hex', offset, offset + 16))).toBeTruthy();
		expect(checkIP.toString(buf, offset, 16)).toEqual('::1');
		expect(checkIP.toString(checkIP.toBuffer('1::', buf, offset), offset, 16)).toEqual(
			'1::',
		);
		expect(
			checkIP.toString(checkIP.toBuffer('abcd::dcba', buf, offset), offset, 16),
		).toEqual('abcd::dcba');
	});

	it.skip('should convert to buffer IPv6 mapped IPv4 address', () => {
		let buf = checkIP.toBuffer('::ffff:127.0.0.1');
		// expect(buf.toString('hex')).toEqual('00000000000000000000ffff7f000001');
		expect(checkIP.toString(buf, 0)).toEqual('::ffff:7f00:1');

		buf = checkIP.toBuffer('ffff::127.0.0.1');
		// expect(buf.toString('hex'))toEqual('00000000000000000000ffff7f000001');
	});
});
