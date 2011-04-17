/**
 * A JavaScript implementation of the bcrypt key derivation function.
 */

function scrypt(password, salt, N, r, p, bytes)
{
    var XYBuf = new ArrayBuffer(256 * r);
    var VBuf = new ArrayBuffer(128 * r * N);
    
    var XY = new Uint8Array(XYBuf);
    var V = new Uint8Array(VBuf);
    
    // Step 1: buf <-- PBKDF2(P, S, 1, p * MFLen)
    buf = Crypto.PBKDF2(password, salt, p * 128 * r, 
                             { iterations: 1,
                               hasher: Crypto.SHA256,
                               asBytes: true });
    
    // Step 2: for i = 0 to p - 1 do
    for (i = 0; i < p; i++)
    {
        // Step 3: B_i <-- MF(B_i, N)
        smix(buf, r, N, V, XY, 128 * i * r);
    }
    
    // Step 5: DK <-- PBKDF2(P, B, 1, dkLen)
    return Crypto.PBKDF2(password, buf, bytes,
                         { iterations: 1,
                           hasher: Crypto.SHA256,
                           asBytes: true });
}

function smix(B, r, N, V, XY, bOffset)
{
    var X = XY;
    var Y = XY.subarray(128 * r);
    
    var i, j;
    
    // Step 1: X <-- B
	X = blkcpy(X, B, 128 * r, 0, bOffset);
    
    // 2: for i = 0 to N - 1 do
	for (i = 0; i < N; i++)
    {
		// Step 3: V_i <-- X
		V = blkcpy(V, X, 128 * r, i * 128 * r, 0);
        
        // Step 4: X <-- H(X)
		X = blockmix_salsa8(X, Y, r);
    }
    
    // Step 6: for i = 0 to N - 1 do
	for (i = 0; i < N; i++) {
		// Step 7: j <-- Integerify(X) mod N 
		j = integerify(X, r) & (N - 1);

		// Step 8: X <-- H(X \xor V_j)
		blkxor(X, V, 128 * r, 0, j * 128 * r);
		X = blockmix_salsa8(X, Y, r);
	}

	// Step 10: B' <-- X
	B = blkcpy(B, X, 128 * r, 0, 0);
}

function integerify(B, r)
{
	var X = B[(2 * r - 1) * 64];

	//return (le64dec(X));
    return X;
}

function blkcpy(dest, src, len, destOffset, srcOffset)
{
    var i;
    
    for (i = 0; i < len; i++)
    {
        dest[i + destOffset] = src[i + srcOffset];
    }
    
    return dest;
}

function blkxor(dest, src, len, destOffset, srcOffset)
{
	var i;

	for (i = 0; i < len; i++)
		dest[i + destOffset] ^= src[i + srcOffset];
}

function blockmix_salsa8(B, Y, r)
{
    var XBuf = new ArrayBuffer(64);
    var X = new Uint8Array(XBuf);
    
    var i;
    
    // Step 1: X <-- B_{2r - 1}
	X = blkcpy(X, B, 64, 0, (2 * r - 1) * 64);
    
    // Step 2: for i = 0 to 2r - 1 do
	for (i = 0; i < 2 * r; i++) {
		// Step 3: X <-- H(X \xor B_i)
		blkxor(X, B, 64, 0, i * 64);
		salsa20_8(X);

		// Step 4: Y_i <-- X
		Y = blkcpy(Y, X, 64, i * 64, 0);
	}

	// Step 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1})
	for (i = 0; i < r; i++)
		B = blkcpy(B, Y, 64, i * 64, (i * 2) * 64);

    for (i = 0; i < r; i++)
		B = blkcpy(B, Y, 64, (i + r) * 64, (i * 2 + 1) * 64);
        // blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);

    return B;
}

function salsa20_8(B)
{
    var B32Buf = new ArrayBuffer(16 * 4);
    var B32 = new Uint32Array(B32Buf);
	
    var xBuf = new ArrayBuffer(16 * 4);
    var x = new Uint32Array(xBuf);

	var i;

	/* Convert little-endian values in. */
	for (i = 0; i < 16; i++)
		B32[i] = le32dec(B, i * 4);

	/* Compute x = doubleround^4(B32). */
	for (i = 0; i < 16; i++)
		x[i] = B32[i];
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

		/* Operate on rows. */
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
//#undef R
	}

	/* Compute B32 = B32 + x. */
	for (i = 0; i < 16; i++)
		B32[i] += x[i];

	/* Convert little-endian values out. */
	for (i = 0; i < 16; i++)
		le32enc(B, B32[i], 4 * i);
}

function R(a, b)
{
    return (((a) << (b)) | ((a) >> (32 - (b))));
}

function le32dec(p, bOffset)
{
    return ((p[bOffset]) + ((p[1+bOffset]) << 8) +
           ((p[2+bOffset]) << 16) + ((p[3+bOffset]) << 24));
}

function le32enc(p, x, pOffset)
{
	p[pOffset] = x & 0xff;
	p[1+pOffset] = (x >> 8) & 0xff;
	p[2+pOffset] = (x >> 16) & 0xff;
	p[3+pOffset] = (x >> 24) & 0xff;
}

function toHex(arr)
{
	var str = '';

	for (var i = 0; i < arr.length; i++)
	{
		str += arr[i].toString(16);
		str += ' ';
	}
	return str;
}