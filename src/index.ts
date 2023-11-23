import {isIPv4, isIPv6} from 'net';

export type IPFamily = 'ipv4' | 'ipv6';
export type IPBuffer = Buffer;

/** IP v4 version Regex */
const ipv4Regex =
	/^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])){3}$/;
/** IP v6 version Regex */
const ipv6Regex =
	/^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^([0-9a-fA-F]{1,4}:){1,6}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,5}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,6}$|^([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4})$|^::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}$|^::1$/;

/**
 * Checks if the provided string is in IPv4 format.
 *
 * @param ip The string to check.
 * @returns True if the string is in IPv4 format, false otherwise.
 */
export const isV4Format = (ip: string): boolean => ipv4Regex.test(ip);

/**
 * Checks if the provided string is in IPv6 format.
 *
 * @param ip The string to check.
 * @returns True if the string is in IPv6 format, false otherwise.
 */
export const isV6Format = (ip: string): boolean => ipv6Regex.test(ip);

const address = () => {};

const mask = () => {};

const version = () => {};

/**
 * Converts an IP address to a Buffer.
 *
 * @param ip {string} - The IP address to convert
 * @param buffer {Buffer} - The Buffer to store the result (optional)
 * @param offset {number} - The offset in the Buffer to start writing.
 * @returns The Buffer representation of the IP address.
 * @throws {Error} If the provided IP address is invalid.
 *
 */
export const toBuffer = (ip: string, buffer?: Buffer, offset: number = 0): Buffer => {
	offset = Math.floor(offset);

	ip = ip.trim();
	let result: Buffer | undefined;

	if (isIPv4(ip)) {
		result = buffer || Buffer.alloc(offset + 4);
		const bytes = ip.split('.').map((byte) => parseInt(byte, 10) & 0xff);
		result.set(bytes, offset);
	} else if (isIPv6(ip)) {
		result = buffer || Buffer.alloc(offset + 16);

		// Handle IPv6 loopback address
		if (ip === '::1') {
			result.fill(0, offset, offset + 16);
			result.writeUInt16BE(1, offset + 14); // Set the last 16 bits to 1
		} else {
			const parsedIPv6 = ip.split(':').map((section) => parseInt(section, 16));

			for (let i = 0; i < 8; i++) {
				result.writeUInt16BE(parsedIPv6[i] || 0, offset);
				offset += 2;
			}
		}
	}

	if (!result) throw new Error(`Invalid IP address: ${ip}`);

	return result;
};

const isEqual = () => {};

const isIP = () => {};

const checkIP = {
	toBuffer,
};
export default checkIP;
