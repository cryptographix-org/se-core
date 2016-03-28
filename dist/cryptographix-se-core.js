  import { ByteArray, ByteEncoding, Kind, KindBuilder, Message } from 'cryptographix-sim-core';

export class Key {
    constructor() {
        this._type = 0;
        this._size = -1;
        this._componentArray = [];
    }
    setType(keyType) {
        this._type = keyType;
    }
    getType() {
        return this._type;
    }
    setSize(size) {
        this._size = size;
    }
    getSize() {
        return this._size;
    }
    setComponent(comp, value) {
        this._componentArray[comp] = value;
    }
    getComponent(comp) {
        return this._componentArray[comp];
    }
}
Key.SECRET = 1;
Key.PRIVATE = 2;
Key.PUBLIC = 3;
Key.DES = 1;
Key.AES = 2;
Key.MODULUS = 3;
Key.EXPONENT = 4;
Key.CRT_P = 5;
Key.CRT_Q = 6;
Key.CRT_DP1 = 7;
Key.CRT_DQ1 = 8;
Key.CRT_PQ = 9;



export class Crypto {
    constructor() {
    }
    encrypt(key, mech, data) {
        var k = key.getComponent(Key.SECRET).byteArray;
        if (k.length == 16) {
            var orig = k;
            k = new ByteArray([]).setLength(24);
            k.setBytesAt(0, orig);
            k.setBytesAt(16, orig.viewAt(0, 8));
        }
        var cryptoText = new ByteArray(this.des(k.backingArray, data.byteArray.backingArray, 1, 0));
        return new ByteString(cryptoText);
    }
    decrypt(key, mech, data) {
        return data;
    }
    sign(key, mech, data, iv) {
        var k = key.getComponent(Key.SECRET).byteArray;
        var keyData = k;
        if (k.length == 16) {
            keyData = new ByteArray();
            keyData
                .setLength(24)
                .setBytesAt(0, k)
                .setBytesAt(16, k.bytesAt(0, 8));
        }
        if (iv == undefined)
            iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        var cryptoText = new ByteArray(this.des(keyData.backingArray, data.byteArray.backingArray, 1, 1, iv, 4));
        return new ByteString(cryptoText).bytes(-8);
    }
    des(key, message, encrypt, mode, iv, padding) {
        function des_createKeys(key) {
            if (Crypto.desPC == undefined) {
                Crypto.desPC = {
                    pc2bytes0: new Uint32Array([0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204]),
                    pc2bytes1: new Uint32Array([0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101]),
                    pc2bytes2: new Uint32Array([0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808]),
                    pc2bytes3: new Uint32Array([0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000]),
                    pc2bytes4: new Uint32Array([0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010]),
                    pc2bytes5: new Uint32Array([0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420]),
                    pc2bytes6: new Uint32Array([0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002]),
                    pc2bytes7: new Uint32Array([0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800]),
                    pc2bytes8: new Uint32Array([0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002]),
                    pc2bytes9: new Uint32Array([0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408]),
                    pc2bytes10: new Uint32Array([0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020]),
                    pc2bytes11: new Uint32Array([0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200]),
                    pc2bytes12: new Uint32Array([0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010]),
                    pc2bytes13: new Uint32Array([0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105])
                };
            }
            var iterations = key.length > 8 ? 3 : 1;
            var keys = new Uint32Array(32 * iterations);
            var shifts = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];
            var lefttemp, righttemp, m = 0, n = 0, temp;
            for (var j = 0; j < iterations; j++) {
                left = (key[m++] << 24) | (key[m++] << 16) | (key[m++] << 8) | key[m++];
                right = (key[m++] << 24) | (key[m++] << 16) | (key[m++] << 8) | key[m++];
                temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
                right ^= temp;
                left ^= (temp << 4);
                temp = ((right >>> -16) ^ left) & 0x0000ffff;
                left ^= temp;
                right ^= (temp << -16);
                temp = ((left >>> 2) ^ right) & 0x33333333;
                right ^= temp;
                left ^= (temp << 2);
                temp = ((right >>> -16) ^ left) & 0x0000ffff;
                left ^= temp;
                right ^= (temp << -16);
                temp = ((left >>> 1) ^ right) & 0x55555555;
                right ^= temp;
                left ^= (temp << 1);
                temp = ((right >>> 8) ^ left) & 0x00ff00ff;
                left ^= temp;
                right ^= (temp << 8);
                temp = ((left >>> 1) ^ right) & 0x55555555;
                right ^= temp;
                left ^= (temp << 1);
                temp = (left << 8) | ((right >>> 20) & 0x000000f0);
                left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
                right = temp;
                for (var i = 0; i < shifts.length; i++) {
                    if (shifts[i]) {
                        left = (left << 2) | (left >>> 26);
                        right = (right << 2) | (right >>> 26);
                    }
                    else {
                        left = (left << 1) | (left >>> 27);
                        right = (right << 1) | (right >>> 27);
                    }
                    left &= -0xf;
                    right &= -0xf;
                    lefttemp = Crypto.desPC.pc2bytes0[left >>> 28] | Crypto.desPC.pc2bytes1[(left >>> 24) & 0xf]
                        | Crypto.desPC.pc2bytes2[(left >>> 20) & 0xf] | Crypto.desPC.pc2bytes3[(left >>> 16) & 0xf]
                        | Crypto.desPC.pc2bytes4[(left >>> 12) & 0xf] | Crypto.desPC.pc2bytes5[(left >>> 8) & 0xf]
                        | Crypto.desPC.pc2bytes6[(left >>> 4) & 0xf];
                    righttemp = Crypto.desPC.pc2bytes7[right >>> 28] | Crypto.desPC.pc2bytes8[(right >>> 24) & 0xf]
                        | Crypto.desPC.pc2bytes9[(right >>> 20) & 0xf] | Crypto.desPC.pc2bytes10[(right >>> 16) & 0xf]
                        | Crypto.desPC.pc2bytes11[(right >>> 12) & 0xf] | Crypto.desPC.pc2bytes12[(right >>> 8) & 0xf]
                        | Crypto.desPC.pc2bytes13[(right >>> 4) & 0xf];
                    temp = ((righttemp >>> 16) ^ lefttemp) & 0x0000ffff;
                    keys[n++] = lefttemp ^ temp;
                    keys[n++] = righttemp ^ (temp << 16);
                }
            }
            return keys;
        }
        if (Crypto.desSP == undefined) {
            Crypto.desSP = {
                spfunction1: new Uint32Array([0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004]),
                spfunction2: new Uint32Array([-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000, 0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x108000]),
                spfunction3: new Uint32Array([0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200]),
                spfunction4: new Uint32Array([0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080]),
                spfunction5: new Uint32Array([0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100]),
                spfunction6: new Uint32Array([0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010]),
                spfunction7: new Uint32Array([0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002]),
                spfunction8: new Uint32Array([0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000]),
            };
        }
        var keys = des_createKeys(key);
        var m = 0, i, j, temp, left, right, looping;
        var cbcleft, cbcleft2, cbcright, cbcright2;
        var len = message.length;
        var iterations = keys.length == 32 ? 3 : 9;
        if (iterations == 3) {
            looping = encrypt ? [0, 32, 2] : [30, -2, -2];
        }
        else {
            looping = encrypt ? [0, 32, 2, 62, 30, -2, 64, 96, 2] : [94, 62, -2, 32, 64, 2, 30, -2, -2];
        }
        if ((padding != undefined) && (padding != 4)) {
            var unpaddedMessage = message;
            var pad = 8 - (len % 8);
            message = new Uint8Array(len + 8);
            message.set(unpaddedMessage, 0);
            switch (padding) {
                case 0:
                    message.set(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), len);
                    break;
                case 1:
                    {
                        message.set(new Uint8Array([pad, pad, pad, pad, pad, pad, pad, pad]), 8);
                        if (pad == 8)
                            len += 8;
                        break;
                    }
                case 2:
                    message.set(new Uint8Array([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20]), 8);
                    break;
            }
            len += 8 - (len % 8);
        }
        var result = new Uint8Array(len);
        if (mode == 1) {
            var m = 0;
            cbcleft = (iv[m++] << 24) | (iv[m++] << 16) | (iv[m++] << 8) | iv[m++];
            cbcright = (iv[m++] << 24) | (iv[m++] << 16) | (iv[m++] << 8) | iv[m++];
        }
        var rm = 0;
        while (m < len) {
            left = (message[m++] << 24) | (message[m++] << 16) | (message[m++] << 8) | message[m++];
            right = (message[m++] << 24) | (message[m++] << 16) | (message[m++] << 8) | message[m++];
            if (mode == 1) {
                if (encrypt) {
                    left ^= cbcleft;
                    right ^= cbcright;
                }
                else {
                    cbcleft2 = cbcleft;
                    cbcright2 = cbcright;
                    cbcleft = left;
                    cbcright = right;
                }
            }
            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
            right ^= temp;
            left ^= (temp << 4);
            temp = ((left >>> 16) ^ right) & 0x0000ffff;
            right ^= temp;
            left ^= (temp << 16);
            temp = ((right >>> 2) ^ left) & 0x33333333;
            left ^= temp;
            right ^= (temp << 2);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff;
            left ^= temp;
            right ^= (temp << 8);
            temp = ((left >>> 1) ^ right) & 0x55555555;
            right ^= temp;
            left ^= (temp << 1);
            left = ((left << 1) | (left >>> 31));
            right = ((right << 1) | (right >>> 31));
            for (j = 0; j < iterations; j += 3) {
                var endloop = looping[j + 1];
                var loopinc = looping[j + 2];
                for (i = looping[j]; i != endloop; i += loopinc) {
                    var right1 = right ^ keys[i];
                    var right2 = ((right >>> 4) | (right << 28)) ^ keys[i + 1];
                    temp = left;
                    left = right;
                    right = temp ^ (Crypto.desSP.spfunction2[(right1 >>> 24) & 0x3f] | Crypto.desSP.spfunction4[(right1 >>> 16) & 0x3f]
                        | Crypto.desSP.spfunction6[(right1 >>> 8) & 0x3f] | Crypto.desSP.spfunction8[right1 & 0x3f]
                        | Crypto.desSP.spfunction1[(right2 >>> 24) & 0x3f] | Crypto.desSP.spfunction3[(right2 >>> 16) & 0x3f]
                        | Crypto.desSP.spfunction5[(right2 >>> 8) & 0x3f] | Crypto.desSP.spfunction7[right2 & 0x3f]);
                }
                temp = left;
                left = right;
                right = temp;
            }
            left = ((left >>> 1) | (left << 31));
            right = ((right >>> 1) | (right << 31));
            temp = ((left >>> 1) ^ right) & 0x55555555;
            right ^= temp;
            left ^= (temp << 1);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff;
            left ^= temp;
            right ^= (temp << 8);
            temp = ((right >>> 2) ^ left) & 0x33333333;
            left ^= temp;
            right ^= (temp << 2);
            temp = ((left >>> 16) ^ right) & 0x0000ffff;
            right ^= temp;
            left ^= (temp << 16);
            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
            right ^= temp;
            left ^= (temp << 4);
            if (mode == 1) {
                if (encrypt) {
                    cbcleft = left;
                    cbcright = right;
                }
                else {
                    left ^= cbcleft2;
                    right ^= cbcright2;
                }
            }
            result.set(new Uint8Array([(left >>> 24) & 0xff, (left >>> 16) & 0xff, (left >>> 8) & 0xff, (left) & 0xff, (right >>> 24) & 0xff, (right >>> 16) & 0xff, (right >>> 8) & 0xff, (right) & 0xff]), rm);
            rm += 8;
        }
        return result;
    }
    verify(key, mech, data, signature, iv) {
        return data;
    }
    digest(mech, data) {
        return data;
    }
}
Crypto.DES_CBC = 2;
Crypto.DES_ECB = 5;
Crypto.DES_MAC = 8;
Crypto.DES_MAC_EMV = 9;
Crypto.ISO9797_METHOD_1 = 11;
Crypto.ISO9797_METHOD_2 = 12;
Crypto.MD5 = 13;
Crypto.RSA = 14;
Crypto.SHA_1 = 15;
Crypto.SHA_512 = 25;



export class ByteString {
    constructor(value, encoding) {
        if (!encoding) {
            if (value instanceof ByteString)
                this.byteArray = value.byteArray.clone();
            else if (value instanceof ByteArray)
                this.byteArray = value.clone();
        }
        else {
            switch (encoding) {
                case ByteString.HEX:
                    this.byteArray = new ByteArray(value, ByteArray.HEX);
                    break;
                default:
                    throw "ByteString unsupported encoding";
            }
        }
    }
    get length() {
        return this.byteArray.length;
    }
    bytes(offset, count) {
        return new ByteString(this.byteArray.viewAt(offset, count));
    }
    byteAt(offset) {
        return this.byteArray.byteAt(offset);
    }
    equals(otherByteString) {
    }
    concat(value) {
        this.byteArray.concat(value.byteArray);
        return this;
    }
    left(count) {
        return new ByteString(this.byteArray.viewAt(0));
    }
    right(count) {
        return new ByteString(this.byteArray.viewAt(-count));
    }
    not() {
        return new ByteString(this.byteArray.clone().not());
    }
    and(value) {
        return new ByteString(this.byteArray.clone().and(value.byteArray));
    }
    or(value) {
        return new ByteString(this.byteArray.clone().or(value.byteArray));
    }
    pad(method, optional) {
        var bs = new ByteBuffer(this.byteArray);
        if (optional == undefined)
            optional = false;
        if (((bs.length & 7) != 0) || (!optional)) {
            var newlen = ((bs.length + 8) & ~7);
            if (method == Crypto.ISO9797_METHOD_1)
                bs.append(0x80);
            while (bs.length < newlen)
                bs.append(0x00);
        }
        return bs.toByteString();
    }
    toString(encoding) {
        return this.byteArray.toString(ByteArray.HEX);
    }
}
ByteString.HEX = ByteEncoding.HEX;
ByteString.BASE64 = ByteEncoding.BASE64;
export const HEX = ByteString.HEX;
export const BASE64 = ByteString.BASE64;


export class ByteBuffer {
    constructor(value, encoding) {
        if (value instanceof ByteArray) {
            this.byteArray = value.clone();
        }
        else if (value instanceof ByteString) {
            this.byteArray = value.byteArray.clone();
        }
        else if (encoding != undefined) {
            this.byteArray = new ByteString(value, encoding).byteArray.clone();
        }
        else
            this.byteArray = new ByteArray([]);
    }
    get length() {
        return this.byteArray.length;
    }
    toByteString() {
        return new ByteString(this.byteArray);
    }
    clear() {
        this.byteArray = new ByteArray([]);
    }
    append(value) {
        let valueArray;
        if ((value instanceof ByteString) || (value instanceof ByteBuffer)) {
            valueArray = value.byteArray;
        }
        else if (typeof value == "number") {
            valueArray = new ByteArray([(value & 0xff)]);
        }
        this.byteArray.concat(valueArray);
        return this;
    }
}

export class BaseTLV {
    constructor(tag, value, encoding) {
        this.encoding = encoding || BaseTLV.Encodings.EMV;
        switch (this.encoding) {
            case BaseTLV.Encodings.EMV:
                {
                    var tlvBuffer = new ByteArray([]);
                    if (tag >= 0x100)
                        tlvBuffer.addByte((tag >> 8) & 0xFF);
                    tlvBuffer.addByte(tag & 0xFF);
                    var len = value.length;
                    if (len > 0xFF) {
                        tlvBuffer.addByte(0x82);
                        tlvBuffer.addByte((len >> 8) & 0xFF);
                    }
                    else if (len > 0x7F)
                        tlvBuffer.addByte(0x81);
                    tlvBuffer.addByte(len & 0xFF);
                    tlvBuffer.concat(value);
                    this.byteArray = tlvBuffer;
                    break;
                }
        }
    }
    static parseTLV(buffer, encoding) {
        var res = { tag: 0, len: 0, value: undefined, lenOffset: 0, valueOffset: 0 };
        var off = 0;
        var bytes = buffer.backingArray;
        switch (encoding) {
            case BaseTLV.Encodings.EMV:
                {
                    while ((off < bytes.length) && ((bytes[off] == 0x00) || (bytes[off] == 0xFF)))
                        ++off;
                    if (off >= bytes.length)
                        return res;
                    if ((bytes[off] & 0x1F) == 0x1F) {
                        res.tag = bytes[off++] << 8;
                        if (off >= bytes.length) {
                            return null;
                        }
                    }
                    res.tag |= bytes[off++];
                    res.lenOffset = off;
                    if (off >= bytes.length) {
                        return null;
                    }
                    var ll = (bytes[off] & 0x80) ? (bytes[off++] & 0x7F) : 1;
                    while (ll-- > 0) {
                        if (off >= bytes.length) {
                            return null;
                        }
                        res.len = (res.len << 8) | bytes[off++];
                    }
                    res.valueOffset = off;
                    if (off + res.len > bytes.length) {
                        return null;
                    }
                    res.value = bytes.slice(res.valueOffset, res.valueOffset + res.len);
                    break;
                }
        }
        return res;
    }
    get tag() {
        return BaseTLV.parseTLV(this.byteArray, this.encoding).tag;
    }
    get value() {
        return BaseTLV.parseTLV(this.byteArray, this.encoding).value;
    }
    get len() {
        return BaseTLV.parseTLV(this.byteArray, this.encoding).len;
    }
}
BaseTLV.Encodings = {
    EMV: 1,
    DGI: 2
};
BaseTLV.Encodings["CTV"] = 4;



export class TLV {
    constructor(tag, value, encoding) {
        this.tlv = new BaseTLV(tag, value.byteArray, encoding);
        this.encoding = encoding;
    }
    getTLV() {
        return new ByteString(this.tlv.byteArray);
    }
    getTag() {
        return this.tlv.tag;
    }
    getValue() {
        return new ByteString(this.tlv.value);
    }
    getL() {
        var info = BaseTLV.parseTLV(this.tlv.byteArray, this.encoding);
        return new ByteString(this.tlv.byteArray.viewAt(info.lenOffset, info.valueOffset));
    }
    getLV() {
        var info = BaseTLV.parseTLV(this.tlv.byteArray, this.encoding);
        return new ByteString(this.tlv.byteArray.viewAt(info.lenOffset, info.valueOffset + info.len));
    }
    static parseTLV(buffer, encoding) {
        let info = BaseTLV.parseTLV(buffer.byteArray, encoding);
        return {
            tag: info.tag,
            len: info.len,
            value: new ByteString(info.value),
            lenOffset: info.lenOffset,
            valueOffset: info.valueOffset
        };
    }
}
TLV.EMV = BaseTLV.Encodings.EMV;
TLV.DGI = BaseTLV.Encodings.DGI;


export class TLVList {
    constructor(tlvStream, encoding) {
        this._tlvs = [];
        var off = 0;
        while (off < tlvStream.length) {
            var tlvInfo = TLV.parseTLV(tlvStream.bytes(off), encoding);
            if (tlvInfo == null) {
                break;
            }
            else {
                if (tlvInfo.valueOffset == 0)
                    break;
                this._tlvs.push(new TLV(tlvInfo.tag, tlvInfo.value, encoding));
                off += tlvInfo.valueOffset + tlvInfo.len;
            }
        }
    }
    index(index) {
        return this._tlvs[index];
    }
}

export class CommandAPDU {
    constructor(attributes) {
        this.INS = 0;
        this.P1 = 0;
        this.P2 = 0;
        this.data = new ByteArray();
        this.Le = 0;
        Kind.initFields(this, attributes);
    }
    get Lc() { return this.data.length; }
    get header() { return new ByteArray([this.CLA, this.INS, this.P1, this.P2]); }
    static init(CLA, INS, P1, P2, data, expectedLen) {
        return (new CommandAPDU()).set(CLA, INS, P1, P2, data, expectedLen);
    }
    set(CLA, INS, P1, P2, data, expectedLen) {
        this.CLA = CLA;
        this.INS = INS;
        this.P1 = P1;
        this.P2 = P2;
        this.data = data || new ByteArray();
        this.Le = expectedLen || 0;
        return this;
    }
    setCLA(CLA) { this.CLA = CLA; return this; }
    setINS(INS) { this.INS = INS; return this; }
    setP1(P1) { this.P1 = P1; return this; }
    setP2(P2) { this.P2 = P2; return this; }
    setData(data) { this.data = data; return this; }
    setLe(Le) { this.Le = Le; return this; }
    toJSON() {
        return {
            CLA: this.CLA,
            INS: this.INS,
            P1: this.P1,
            P2: this.P2,
            data: this.data,
            Le: this.Le
        };
    }
    encodeBytes(options) {
        let dlen = ((this.Lc > 0) ? 1 + this.Lc : 0);
        let len = 4 + dlen + ((this.Le > 0) ? 1 : 0);
        let ba = new ByteArray().setLength(len);
        ba.setBytesAt(0, this.header);
        if (this.Lc) {
            ba.setByteAt(4, this.Lc);
            ba.setBytesAt(5, this.data);
        }
        if (this.Le > 0) {
            ba.setByteAt(4 + dlen, this.Le);
        }
        return ba;
    }
    decodeBytes(byteArray, options) {
        if (byteArray.length < 4)
            throw new Error('CommandAPDU: Invalid buffer');
        let offset = 0;
        this.CLA = byteArray.byteAt(offset++);
        this.INS = byteArray.byteAt(offset++);
        this.P1 = byteArray.byteAt(offset++);
        this.P2 = byteArray.byteAt(offset++);
        if (byteArray.length > offset + 1) {
            var Lc = byteArray.byteAt(offset++);
            this.data = byteArray.bytesAt(offset, Lc);
            offset += Lc;
        }
        if (byteArray.length > offset)
            this.Le = byteArray.byteAt(offset++);
        if (byteArray.length != offset)
            throw new Error('CommandAPDU: Invalid buffer');
        return this;
    }
}
KindBuilder.init(CommandAPDU, 'ISO7816 Command APDU')
    .byteField('CLA', 'Class')
    .byteField('INS', 'Instruction')
    .byteField('P1', 'P1 Param')
    .byteField('P2', 'P2 Param')
    .integerField('Lc', 'Command Length', { calculated: true })
    .field('data', 'Command Data', ByteArray)
    .integerField('Le', 'Expected Length');

export var ISO7816;
(function (ISO7816) {
    ISO7816[ISO7816["CLA_ISO"] = 0] = "CLA_ISO";
    ISO7816[ISO7816["INS_EXTERNAL_AUTHENTICATE"] = 130] = "INS_EXTERNAL_AUTHENTICATE";
    ISO7816[ISO7816["INS_GET_CHALLENGE"] = 132] = "INS_GET_CHALLENGE";
    ISO7816[ISO7816["INS_INTERNAL_AUTHENTICATE"] = 136] = "INS_INTERNAL_AUTHENTICATE";
    ISO7816[ISO7816["INS_SELECT_FILE"] = 164] = "INS_SELECT_FILE";
    ISO7816[ISO7816["INS_READ_RECORD"] = 178] = "INS_READ_RECORD";
    ISO7816[ISO7816["INS_UPDATE_RECORD"] = 220] = "INS_UPDATE_RECORD";
    ISO7816[ISO7816["INS_VERIFY"] = 32] = "INS_VERIFY";
    ISO7816[ISO7816["INS_BLOCK_APPLICATION"] = 30] = "INS_BLOCK_APPLICATION";
    ISO7816[ISO7816["INS_UNBLOCK_APPLICATION"] = 24] = "INS_UNBLOCK_APPLICATION";
    ISO7816[ISO7816["INS_UNBLOCK_CHANGE_PIN"] = 36] = "INS_UNBLOCK_CHANGE_PIN";
    ISO7816[ISO7816["INS_GET_DATA"] = 202] = "INS_GET_DATA";
    ISO7816[ISO7816["TAG_APPLICATION_TEMPLATE"] = 97] = "TAG_APPLICATION_TEMPLATE";
    ISO7816[ISO7816["TAG_FCI_PROPRIETARY_TEMPLATE"] = 165] = "TAG_FCI_PROPRIETARY_TEMPLATE";
    ISO7816[ISO7816["TAG_FCI_TEMPLATE"] = 111] = "TAG_FCI_TEMPLATE";
    ISO7816[ISO7816["TAG_AID"] = 79] = "TAG_AID";
    ISO7816[ISO7816["TAG_APPLICATION_LABEL"] = 80] = "TAG_APPLICATION_LABEL";
    ISO7816[ISO7816["TAG_LANGUAGE_PREFERENCES"] = 24365] = "TAG_LANGUAGE_PREFERENCES";
    ISO7816[ISO7816["TAG_APPLICATION_EFFECTIVE_DATE"] = 24357] = "TAG_APPLICATION_EFFECTIVE_DATE";
    ISO7816[ISO7816["TAG_APPLICATION_EXPIRY_DATE"] = 24356] = "TAG_APPLICATION_EXPIRY_DATE";
    ISO7816[ISO7816["TAG_CARDHOLDER_NAME"] = 24352] = "TAG_CARDHOLDER_NAME";
    ISO7816[ISO7816["TAG_ISSUER_COUNTRY_CODE"] = 24360] = "TAG_ISSUER_COUNTRY_CODE";
    ISO7816[ISO7816["TAG_ISSUER_URL"] = 24400] = "TAG_ISSUER_URL";
    ISO7816[ISO7816["TAG_PAN"] = 90] = "TAG_PAN";
    ISO7816[ISO7816["TAG_PAN_SEQUENCE_NUMBER"] = 24372] = "TAG_PAN_SEQUENCE_NUMBER";
    ISO7816[ISO7816["TAG_SERVICE_CODE"] = 24368] = "TAG_SERVICE_CODE";
    ISO7816[ISO7816["ISO_PINBLOCK_SIZE"] = 8] = "ISO_PINBLOCK_SIZE";
    ISO7816[ISO7816["APDU_LEN_LE_MAX"] = 256] = "APDU_LEN_LE_MAX";
    ISO7816[ISO7816["SW_SUCCESS"] = 36864] = "SW_SUCCESS";
    ISO7816[ISO7816["SW_WARNING_NV_MEMORY_UNCHANGED"] = 25088] = "SW_WARNING_NV_MEMORY_UNCHANGED";
    ISO7816[ISO7816["SW_PART_OF_RETURN_DATA_CORRUPTED"] = 25217] = "SW_PART_OF_RETURN_DATA_CORRUPTED";
    ISO7816[ISO7816["SW_END_FILE_REACHED_BEFORE_LE_BYTE"] = 25218] = "SW_END_FILE_REACHED_BEFORE_LE_BYTE";
    ISO7816[ISO7816["SW_SELECTED_FILE_INVALID"] = 25219] = "SW_SELECTED_FILE_INVALID";
    ISO7816[ISO7816["SW_FCI_NOT_FORMATTED_TO_ISO"] = 25220] = "SW_FCI_NOT_FORMATTED_TO_ISO";
    ISO7816[ISO7816["SW_WARNING_NV_MEMORY_CHANGED"] = 25344] = "SW_WARNING_NV_MEMORY_CHANGED";
    ISO7816[ISO7816["SW_FILE_FILLED_BY_LAST_WRITE"] = 25473] = "SW_FILE_FILLED_BY_LAST_WRITE";
    ISO7816[ISO7816["SW_WRONG_LENGTH"] = 26368] = "SW_WRONG_LENGTH";
    ISO7816[ISO7816["SW_FUNCTIONS_IN_CLA_NOT_SUPPORTED"] = 26624] = "SW_FUNCTIONS_IN_CLA_NOT_SUPPORTED";
    ISO7816[ISO7816["SW_LOGICAL_CHANNEL_NOT_SUPPORTED"] = 26753] = "SW_LOGICAL_CHANNEL_NOT_SUPPORTED";
    ISO7816[ISO7816["SW_SECURE_MESSAGING_NOT_SUPPORTED"] = 26754] = "SW_SECURE_MESSAGING_NOT_SUPPORTED";
    ISO7816[ISO7816["SW_COMMAND_NOT_ALLOWED"] = 26880] = "SW_COMMAND_NOT_ALLOWED";
    ISO7816[ISO7816["SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE"] = 27009] = "SW_COMMAND_INCOMPATIBLE_WITH_FILE_STRUCTURE";
    ISO7816[ISO7816["SW_SECURITY_STATUS_NOT_SATISFIED"] = 27010] = "SW_SECURITY_STATUS_NOT_SATISFIED";
    ISO7816[ISO7816["SW_FILE_INVALID"] = 27011] = "SW_FILE_INVALID";
    ISO7816[ISO7816["SW_DATA_INVALID"] = 27012] = "SW_DATA_INVALID";
    ISO7816[ISO7816["SW_CONDITIONS_NOT_SATISFIED"] = 27013] = "SW_CONDITIONS_NOT_SATISFIED";
    ISO7816[ISO7816["SW_COMMAND_NOT_ALLOWED_AGAIN"] = 27014] = "SW_COMMAND_NOT_ALLOWED_AGAIN";
    ISO7816[ISO7816["SW_EXPECTED_SM_DATA_OBJECTS_MISSING"] = 27015] = "SW_EXPECTED_SM_DATA_OBJECTS_MISSING";
    ISO7816[ISO7816["SW_SM_DATA_OBJECTS_INCORRECT"] = 27016] = "SW_SM_DATA_OBJECTS_INCORRECT";
    ISO7816[ISO7816["SW_WRONG_PARAMS"] = 27136] = "SW_WRONG_PARAMS";
    ISO7816[ISO7816["SW_WRONG_DATA"] = 27264] = "SW_WRONG_DATA";
    ISO7816[ISO7816["SW_FUNC_NOT_SUPPORTED"] = 27265] = "SW_FUNC_NOT_SUPPORTED";
    ISO7816[ISO7816["SW_FILE_NOT_FOUND"] = 27266] = "SW_FILE_NOT_FOUND";
    ISO7816[ISO7816["SW_RECORD_NOT_FOUND"] = 27267] = "SW_RECORD_NOT_FOUND";
    ISO7816[ISO7816["SW_NOT_ENOUGH_SPACE_IN_FILE"] = 27268] = "SW_NOT_ENOUGH_SPACE_IN_FILE";
    ISO7816[ISO7816["SW_LC_INCONSISTENT_WITH_TLV"] = 27269] = "SW_LC_INCONSISTENT_WITH_TLV";
    ISO7816[ISO7816["SW_INCORRECT_P1P2"] = 27270] = "SW_INCORRECT_P1P2";
    ISO7816[ISO7816["SW_LC_INCONSISTENT_WITH_P1P2"] = 27271] = "SW_LC_INCONSISTENT_WITH_P1P2";
    ISO7816[ISO7816["SW_REFERENCED_DATA_NOT_FOUND"] = 27272] = "SW_REFERENCED_DATA_NOT_FOUND";
    ISO7816[ISO7816["SW_WRONG_P1P2"] = 27392] = "SW_WRONG_P1P2";
    ISO7816[ISO7816["SW_INS_NOT_SUPPORTED"] = 27904] = "SW_INS_NOT_SUPPORTED";
    ISO7816[ISO7816["SW_CLA_NOT_SUPPORTED"] = 28160] = "SW_CLA_NOT_SUPPORTED";
    ISO7816[ISO7816["SW_UNKNOWN"] = 28416] = "SW_UNKNOWN";
})(ISO7816 || (ISO7816 = {}));


export class ResponseAPDU {
    constructor(attributes) {
        this.SW = ISO7816.SW_SUCCESS;
        this.data = new ByteArray();
        Kind.initFields(this, attributes);
    }
    get La() { return this.data.length; }
    static init(sw, data) {
        return (new ResponseAPDU()).set(sw, data);
    }
    set(sw, data) {
        this.SW = sw;
        this.data = data || new ByteArray();
        return this;
    }
    setSW(SW) { this.SW = SW; return this; }
    setSW1(SW1) { this.SW = (this.SW & 0xFF) | (SW1 << 8); return this; }
    setSW2(SW2) { this.SW = (this.SW & 0xFF00) | SW2; return this; }
    setData(data) { this.data = data; return this; }
    encodeBytes(options) {
        let ba = new ByteArray().setLength(this.La + 2);
        ba.setBytesAt(0, this.data);
        ba.setByteAt(this.La, (this.SW >> 8) & 0xff);
        ba.setByteAt(this.La + 1, (this.SW >> 0) & 0xff);
        return ba;
    }
    decodeBytes(byteArray, options) {
        if (byteArray.length < 2)
            throw new Error('ResponseAPDU Buffer invalid');
        let la = byteArray.length - 2;
        this.SW = byteArray.wordAt(la);
        this.data = (la) ? byteArray.bytesAt(0, la) : new ByteArray();
        return this;
    }
}
KindBuilder.init(ResponseAPDU, 'ISO7816 Response APDU')
    .integerField('SW', 'Status Word', { maximum: 0xFFFF })
    .integerField('La', 'Actual Length', { calculated: true })
    .field('Data', 'Response Data', ByteArray);




export class SlotProtocolHandler {
    constructor() {
    }
    linkSlot(slot, endPoint) {
        let me = this;
        this.endPoint = endPoint;
        this.slot = slot;
        endPoint.onMessage((msg, ep) => {
            me.onMessage(msg, ep);
        });
    }
    unlinkSlot() {
        this.endPoint.onMessage(null);
        this.endPoint = null;
        this.slot = null;
    }
    onMessage(packet, receivingEndPoint) {
        let hdr = packet.header;
        let payload = packet.payload;
        let response;
        let replyHeader = { method: hdr.method, isResponse: true };
        switch (hdr.method) {
            case "executeAPDU":
                if (!(payload instanceof CommandAPDU))
                    break;
                response = this.slot.executeAPDU(payload);
                response.then((responseAPDU) => {
                    let replyPacket = new Message(replyHeader, responseAPDU);
                    receivingEndPoint.sendMessage(replyPacket);
                });
                break;
            case "powerOff":
                response = this.slot.powerOff()
                    .then((respData) => {
                    receivingEndPoint.sendMessage(new Message(replyHeader, new ByteArray()));
                });
                break;
            case "powerOn":
                response = this.slot.powerOn()
                    .then((respData) => {
                    receivingEndPoint.sendMessage(new Message(replyHeader, respData));
                });
                break;
            case "reset":
                response = this.slot.reset()
                    .then((respData) => {
                    receivingEndPoint.sendMessage(new Message(replyHeader, respData));
                });
                break;
            default:
                response = Promise.reject(new Error("Invalid method" + hdr.method));
                break;
        }
        response.catch((e) => {
            let errorPacket = new Message({ method: "error" }, e);
            receivingEndPoint.sendMessage(errorPacket);
        });
    }
}

class JSSimulatedSlot {
    OnMessage(e) {
        if (this.stop)
            return;
        if (e.data.command == "debug") {
            console.log(e.data.data);
        }
        else if (e.data.command == "executeAPDU") {
            if (this.onAPDUResponse) {
                var bs = e.data.data, len = bs.length;
                this.onAPDUResponse((bs[len - 2] << 8) | bs[len - 1], (len > 2) ? new ByteArray(bs.subarray(0, len - 2)) : null);
            }
        }
        else {
            console.log("cmd: " + e.data.command + " data: " + e.data.data);
        }
    }
    init() {
        this.cardWorker = new Worker("js/SmartCardSlotSimulator/SmartCardSlotWorker.js");
        this.cardWorker.onmessage = this.OnMessage.bind(this);
        this.cardWorker.onerror = function (e) {
        };
    }
    sendToWorker(command, data) {
        this.cardWorker.postMessage({
            "command": command,
            "data": data
        });
    }
    executeAPDUCommand(bCLA, bINS, bP1, bP2, commandData, wLe, onAPDUResponse) {
        var cmd = [bCLA, bINS, bP1, bP2];
        var len = 4;
        var bsCommandData = (commandData instanceof ByteArray) ? commandData : new ByteArray(commandData, ByteArray.HEX);
        if (bsCommandData.length > 0) {
            cmd[len++] = bsCommandData.length;
            for (var i = 0; i < bsCommandData.length; ++i)
                cmd[len++] = bsCommandData.byteAt(i);
        }
        else if (wLe != undefined)
            cmd[len++] = wLe & 0xFF;
        this.sendToWorker("executeAPDU", cmd);
        this.onAPDUResponse = onAPDUResponse;
        return;
    }
}




export class JSIMScriptApplet {
    selectApplication(commandAPDU) {
        return Promise.resolve(new ResponseAPDU({ sw: 0x9000 }));
    }
    deselectApplication() {
    }
    executeAPDU(commandAPDU) {
        return Promise.resolve(new ResponseAPDU({ sw: 0x6D00 }));
    }
}

export class JSIMScriptCard {
    constructor() {
        this.applets = [];
        this._atr = new ByteArray([]);
    }
    loadApplication(aid, applet) {
        this.applets.push({ aid: aid, applet: applet });
    }
    get isPowered() {
        return this._powerIsOn;
    }
    powerOn() {
        this._powerIsOn = true;
        return Promise.resolve(this._atr);
    }
    powerOff() {
        this._powerIsOn = false;
        this.selectedApplet = undefined;
        return Promise.resolve();
    }
    reset() {
        this._powerIsOn = true;
        this.selectedApplet = undefined;
        return Promise.resolve(this._atr);
    }
    exchangeAPDU(commandAPDU) {
        if (commandAPDU.INS == 0xA4) {
            if (this.selectedApplet) {
                this.selectedApplet.deselectApplication();
                this.selectedApplet = undefined;
            }
            this.selectedApplet = this.applets[0].applet;
            return this.selectedApplet.selectApplication(commandAPDU);
        }
        return this.selectedApplet.executeAPDU(commandAPDU);
    }
}

export class JSIMSlot {
    constructor(card) {
        this.card = card;
    }
    get isPresent() {
        return !!this.card;
    }
    get isPowered() {
        return this.isPresent && this.card.isPowered;
    }
    powerOn() {
        if (!this.isPresent)
            return Promise.reject(new Error("JSIM: Card not present"));
        return this.card.powerOn();
    }
    powerOff() {
        if (!this.isPresent)
            return Promise.reject(new Error("JSIM: Card not present"));
        return this.card.powerOff();
    }
    reset() {
        if (!this.isPresent)
            return Promise.reject(new Error("JSIM: Card not present"));
        return this.card.reset();
    }
    executeAPDU(commandAPDU) {
        if (!this.isPresent)
            return Promise.reject(new Error("JSIM: Card not present"));
        if (!this.isPowered)
            return Promise.reject(new Error("JSIM: Card unpowered"));
        return this.card.exchangeAPDU(commandAPDU);
    }
    insertCard(card) {
        if (this.card)
            this.ejectCard();
        this.card = card;
    }
    ejectCard() {
        if (this.card) {
            if (this.card.isPowered)
                this.card.powerOff();
            this.card = undefined;
        }
    }
}

export function hex2(val) { return ("00" + val.toString(16).toUpperCase()).substr(-2); }
export function hex4(val) { return ("0000" + val.toString(16).toUpperCase()).substr(-4); }
export var MEMFLAGS;
(function (MEMFLAGS) {
    MEMFLAGS[MEMFLAGS["READ_ONLY"] = 1] = "READ_ONLY";
    MEMFLAGS[MEMFLAGS["TRANSACTIONABLE"] = 2] = "TRANSACTIONABLE";
    MEMFLAGS[MEMFLAGS["TRACE"] = 4] = "TRACE";
})(MEMFLAGS || (MEMFLAGS = {}));
export class Segment {
    constructor(segType, size, flags, base) {
        this.inTransaction = false;
        this.transBlocks = [];
        this.memType = segType;
        this.readOnly = (flags & MEMFLAGS.READ_ONLY) ? true : false;
        if (base) {
            this.memData = new ByteArray(base);
        }
        else {
            this.memData = new ByteArray([]).setLength(size);
        }
    }
    getType() { return this.memType; }
    getLength() { return this.memData.length; }
    getFlags() { return this.flags; }
    getDebug() { return { memData: this.memData, memType: this.memType, readOnly: this.readOnly, inTransaction: this.inTransaction, transBlocks: this.transBlocks }; }
    beginTransaction() {
        this.inTransaction = true;
        this.transBlocks = [];
    }
    endTransaction(commit) {
        if (!commit && this.inTransaction) {
            this.inTransaction = false;
            for (var i = 0; i < this.transBlocks.length; i++) {
                var block = this.transBlocks[i];
                this.writeBytes(block.addr, block.data);
            }
        }
        this.transBlocks = [];
    }
    readByte(addr) {
        return this.memData[addr];
    }
    zeroBytes(addr, len) {
        for (var i = 0; i < len; ++i)
            this.memData[addr + i] = 0;
    }
    readBytes(addr, len) {
        return this.memData.viewAt(addr, len);
    }
    copyBytes(fromAddr, toAddr, len) {
        this.writeBytes(toAddr, this.readBytes(fromAddr, len));
    }
    writeBytes(addr, val) {
        if (this.inTransaction && (this.flags & MEMFLAGS.TRANSACTIONABLE)) {
            this.transBlocks.push({ addr: addr, data: this.readBytes(addr, val.length) });
        }
        this.memData.setBytesAt(addr, val);
    }
    newAccessor(addr, len, name) {
        return new Accessor(this, addr, len, name);
    }
}
export class Accessor {
    constructor(seg, addr, len, name) {
        this.seg = seg;
        this.offset = addr;
        this.length = len;
        this.id = name;
    }
    traceMemoryOp(op, addr, len, addr2) {
        if (this.id != "code")
            this.seg.memTraces.push({ op: op, name: this.id, addr: addr, len: len, addr2: addr2 });
    }
    traceMemoryValue(val) {
        if (this.id != "code") {
            var memTrace = this.seg.memTraces[this.seg.memTraces.length - 1];
            memTrace.val = val;
        }
    }
    zeroBytes(addr, len) {
        if (addr + len > this.length) {
            this.traceMemoryOp("ZR-error", addr, this.length);
            throw new Error("MM: Invalid Zero");
        }
        this.traceMemoryOp("ZR", addr, len);
        this.seg.zeroBytes(this.offset + addr, len);
        this.traceMemoryValue([0]);
    }
    readByte(addr) {
        if (addr + 1 > this.length) {
            this.traceMemoryOp("RD-error", addr, 1);
            throw new Error("MM: Invalid Read");
        }
        this.traceMemoryOp("RD", addr, 1);
        var val = this.seg.readByte(this.offset + addr);
        this.traceMemoryValue([val]);
        return val;
    }
    readBytes(addr, len) {
        if (addr + len > this.length) {
            this.traceMemoryOp("RD-error", addr, len);
            throw new Error("MM: Invalid Read");
        }
        this.traceMemoryOp("RD", addr, len);
        var val = this.seg.readBytes(this.offset + addr, len);
        this.traceMemoryValue(val);
        return val;
    }
    copyBytes(fromAddr, toAddr, len) {
        if ((fromAddr + len > this.length) || (toAddr + len > this.length)) {
            this.traceMemoryOp("CP-error", fromAddr, len, toAddr);
            throw new Error("MM: Invalid Read");
        }
        {
            this.traceMemoryOp("CP", fromAddr, len, toAddr);
            var val = this.seg.readBytes(this.offset + fromAddr, len);
            this.traceMemoryValue(val);
        }
        this.seg.copyBytes(this.offset + fromAddr, this.offset + toAddr, len);
        return val;
    }
    writeByte(addr, val) {
        if (addr + 1 > this.length) {
            this.traceMemoryOp("WR-error", addr, 1);
            throw new Error("MM: Invalid Write");
        }
        this.traceMemoryOp("WR", addr, 1);
        this.seg.writeBytes(this.offset + addr, new ByteArray([val]));
        this.traceMemoryValue([val]);
    }
    writeBytes(addr, val) {
        if (addr + val.length > this.length) {
            this.traceMemoryOp("WR-error", addr, val.length);
            throw new Error("MM: Invalid Write");
        }
        this.traceMemoryOp("WR", addr, val.length);
        this.seg.writeBytes(this.offset + addr, val);
        this.traceMemoryValue(val);
    }
    getType() { return this.seg.getType(); }
    getLength() { return this.length; }
    getID() { return this.id; }
    getDebug() { return { offset: this.offset, length: this.length, seg: this.seg }; }
}
function sliceData(base, offset, size) {
    return base.subarray(offset, offset + size);
}
export class MemoryManager {
    constructor() {
        this.memorySegments = [];
        this.memTraces = [];
    }
    newSegment(memType, size, flags) {
        let newSeg = new Segment(memType, size, flags);
        this.memorySegments[memType] = newSeg;
        newSeg.memTraces = this.memTraces;
        return newSeg;
    }
    getMemTrace() { return this.memTraces; }
    initMemTrace() { this.memTraces = []; }
    getSegment(type) { return this.memorySegments[type]; }
}

export var MELINST;
(function (MELINST) {
    MELINST[MELINST["melSYSTEM"] = 0] = "melSYSTEM";
    MELINST[MELINST["melBRANCH"] = 1] = "melBRANCH";
    MELINST[MELINST["melJUMP"] = 2] = "melJUMP";
    MELINST[MELINST["melCALL"] = 3] = "melCALL";
    MELINST[MELINST["melSTACK"] = 4] = "melSTACK";
    MELINST[MELINST["melPRIMRET"] = 5] = "melPRIMRET";
    MELINST[MELINST["melINVALID"] = 6] = "melINVALID";
    MELINST[MELINST["melLOAD"] = 7] = "melLOAD";
    MELINST[MELINST["melSTORE"] = 8] = "melSTORE";
    MELINST[MELINST["melLOADI"] = 9] = "melLOADI";
    MELINST[MELINST["melSTOREI"] = 10] = "melSTOREI";
    MELINST[MELINST["melLOADA"] = 11] = "melLOADA";
    MELINST[MELINST["melINDEX"] = 12] = "melINDEX";
    MELINST[MELINST["melSETB"] = 13] = "melSETB";
    MELINST[MELINST["melCMPB"] = 14] = "melCMPB";
    MELINST[MELINST["melADDB"] = 15] = "melADDB";
    MELINST[MELINST["melSUBB"] = 16] = "melSUBB";
    MELINST[MELINST["melSETW"] = 17] = "melSETW";
    MELINST[MELINST["melCMPW"] = 18] = "melCMPW";
    MELINST[MELINST["melADDW"] = 19] = "melADDW";
    MELINST[MELINST["melSUBW"] = 20] = "melSUBW";
    MELINST[MELINST["melCLEARN"] = 21] = "melCLEARN";
    MELINST[MELINST["melTESTN"] = 22] = "melTESTN";
    MELINST[MELINST["melINCN"] = 23] = "melINCN";
    MELINST[MELINST["melDECN"] = 24] = "melDECN";
    MELINST[MELINST["melNOTN"] = 25] = "melNOTN";
    MELINST[MELINST["melCMPN"] = 26] = "melCMPN";
    MELINST[MELINST["melADDN"] = 27] = "melADDN";
    MELINST[MELINST["melSUBN"] = 28] = "melSUBN";
    MELINST[MELINST["melANDN"] = 29] = "melANDN";
    MELINST[MELINST["melORN"] = 30] = "melORN";
    MELINST[MELINST["melXORN"] = 31] = "melXORN";
})(MELINST || (MELINST = {}));
;
export var MELTAGADDR;
(function (MELTAGADDR) {
    MELTAGADDR[MELTAGADDR["melAddrTOS"] = 0] = "melAddrTOS";
    MELTAGADDR[MELTAGADDR["melAddrSB"] = 1] = "melAddrSB";
    MELTAGADDR[MELTAGADDR["melAddrST"] = 2] = "melAddrST";
    MELTAGADDR[MELTAGADDR["melAddrDB"] = 3] = "melAddrDB";
    MELTAGADDR[MELTAGADDR["melAddrLB"] = 4] = "melAddrLB";
    MELTAGADDR[MELTAGADDR["melAddrDT"] = 5] = "melAddrDT";
    MELTAGADDR[MELTAGADDR["melAddrPB"] = 6] = "melAddrPB";
    MELTAGADDR[MELTAGADDR["melAddrPT"] = 7] = "melAddrPT";
})(MELTAGADDR || (MELTAGADDR = {}));
;
export var MELTAGCOND;
(function (MELTAGCOND) {
    MELTAGCOND[MELTAGCOND["melCondSPEC"] = 0] = "melCondSPEC";
    MELTAGCOND[MELTAGCOND["melCondEQ"] = 1] = "melCondEQ";
    MELTAGCOND[MELTAGCOND["melCondLT"] = 2] = "melCondLT";
    MELTAGCOND[MELTAGCOND["melCondLE"] = 3] = "melCondLE";
    MELTAGCOND[MELTAGCOND["melCondGT"] = 4] = "melCondGT";
    MELTAGCOND[MELTAGCOND["melCondGE"] = 5] = "melCondGE";
    MELTAGCOND[MELTAGCOND["melCondNE"] = 6] = "melCondNE";
    MELTAGCOND[MELTAGCOND["melCondALL"] = 7] = "melCondALL";
})(MELTAGCOND || (MELTAGCOND = {}));
;
export var MELTAGSYSTEM;
(function (MELTAGSYSTEM) {
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemNOP"] = 0] = "melSystemNOP";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemSetSW"] = 1] = "melSystemSetSW";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemSetLa"] = 2] = "melSystemSetLa";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemSetSWLa"] = 3] = "melSystemSetSWLa";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemExit"] = 4] = "melSystemExit";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemExitSW"] = 5] = "melSystemExitSW";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemExitLa"] = 6] = "melSystemExitLa";
    MELTAGSYSTEM[MELTAGSYSTEM["melSystemExitSWLa"] = 7] = "melSystemExitSWLa";
})(MELTAGSYSTEM || (MELTAGSYSTEM = {}));
;
export var MELTAGSTACK;
(function (MELTAGSTACK) {
    MELTAGSTACK[MELTAGSTACK["melStackPUSHZ"] = 0] = "melStackPUSHZ";
    MELTAGSTACK[MELTAGSTACK["melStackPUSHB"] = 1] = "melStackPUSHB";
    MELTAGSTACK[MELTAGSTACK["melStackPUSHW"] = 2] = "melStackPUSHW";
    MELTAGSTACK[MELTAGSTACK["melStackXX4"] = 3] = "melStackXX4";
    MELTAGSTACK[MELTAGSTACK["melStackPOPN"] = 4] = "melStackPOPN";
    MELTAGSTACK[MELTAGSTACK["melStackPOPB"] = 5] = "melStackPOPB";
    MELTAGSTACK[MELTAGSTACK["melStackPOPW"] = 6] = "melStackPOPW";
    MELTAGSTACK[MELTAGSTACK["melStackXX7"] = 7] = "melStackXX7";
})(MELTAGSTACK || (MELTAGSTACK = {}));
;
export var MELTAGPRIMRET;
(function (MELTAGPRIMRET) {
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM0"] = 0] = "melPrimRetPRIM0";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM1"] = 1] = "melPrimRetPRIM1";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM2"] = 2] = "melPrimRetPRIM2";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM3"] = 3] = "melPrimRetPRIM3";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRET"] = 4] = "melPrimRetRET";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRETI"] = 5] = "melPrimRetRETI";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRETO"] = 6] = "melPrimRetRETO";
    MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRETIO"] = 7] = "melPrimRetRETIO";
})(MELTAGPRIMRET || (MELTAGPRIMRET = {}));
;
export var MELPARAMDEF;
(function (MELPARAMDEF) {
    MELPARAMDEF[MELPARAMDEF["melParamDefNone"] = 0] = "melParamDefNone";
    MELPARAMDEF[MELPARAMDEF["melParamDefTopOfStack"] = 1] = "melParamDefTopOfStack";
    MELPARAMDEF[MELPARAMDEF["melParamDefByteOperLen"] = 17] = "melParamDefByteOperLen";
    MELPARAMDEF[MELPARAMDEF["melParamDefByteImmediate"] = 18] = "melParamDefByteImmediate";
    MELPARAMDEF[MELPARAMDEF["melParamDefByteCodeRelative"] = 24] = "melParamDefByteCodeRelative";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordImmediate"] = 32] = "melParamDefWordImmediate";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetSB"] = 33] = "melParamDefWordOffsetSB";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetST"] = 34] = "melParamDefWordOffsetST";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetDB"] = 35] = "melParamDefWordOffsetDB";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetLB"] = 36] = "melParamDefWordOffsetLB";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetDT"] = 37] = "melParamDefWordOffsetDT";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetPB"] = 38] = "melParamDefWordOffsetPB";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordOffsetPT"] = 39] = "melParamDefWordOffsetPT";
    MELPARAMDEF[MELPARAMDEF["melParamDefWordCodeAddress"] = 40] = "melParamDefWordCodeAddress";
})(MELPARAMDEF || (MELPARAMDEF = {}));
;
function MELPARAM4(a, b, c, d) { return ((d << 24) | (c << 16) | (b << 8) | (a << 0)); }
function OPTAG2MELINST(opCode, tag) { return (((opCode & 0x1f) << 3) | tag); }
export function MEL2OPCODE(byteCode) { return ((byteCode >> 3) & 0x1f); }
export function MEL2INST(byteCode) { return MEL2OPCODE(byteCode); }
export function MEL2TAG(byteCode) { return ((byteCode) & 7); }
;
function MELPARAMSIZE(paramType) {
    return (paramType == MELPARAMDEF.melParamDefNone)
        ? 0
        : (paramType < MELPARAMDEF.melParamDefWordImmediate) ? 1 : 2;
}
export class MEL {
}
MEL.melDecode = [];
function setMelDecode(byteCode, instName, param1, param2, param3, param4) {
    param1 = param1 || MELPARAMDEF.melParamDefNone;
    param2 = param2 || MELPARAMDEF.melParamDefNone;
    param3 = param3 || MELPARAMDEF.melParamDefNone;
    param4 = param4 || MELPARAMDEF.melParamDefNone;
    MEL.melDecode[byteCode] = {
        byteCode: byteCode,
        instLen: 1 + MELPARAMSIZE(param1) + MELPARAMSIZE(param2) + MELPARAMSIZE(param3) + MELPARAMSIZE(param4),
        instName: instName,
        paramDefs: MELPARAM4(param1, param2, param3, param4)
    };
}
function setMelDecodeStdModes(melInst, instName, param1Def) {
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrSB), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetSB);
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrST), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetST);
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrDB), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetDB);
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrLB), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetLB);
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrDT), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetDT);
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrPB), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetPB);
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrPT), instName, param1Def, MELPARAMDEF.melParamDefWordOffsetPT);
}
function setMelDecodeStdModesAndTOS(melInst, instName, param1Def) {
    setMelDecode(OPTAG2MELINST(melInst, MELTAGADDR.melAddrTOS), instName, param1Def, MELPARAMDEF.melParamDefTopOfStack);
    setMelDecodeStdModes(melInst, instName, param1Def);
}
function fillMelDecode() {
    setMelDecodeStdModesAndTOS(MELINST.melLOAD, "LOAD", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melSTORE, "STORE", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melLOADI, "LOADI", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melSTOREI, "STOREI", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrSB), "LOADA", MELPARAMDEF.melParamDefWordOffsetSB);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrST), "LOADA", MELPARAMDEF.melParamDefWordOffsetST);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrDB), "LOADA", MELPARAMDEF.melParamDefWordOffsetDB);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrLB), "LOADA", MELPARAMDEF.melParamDefWordOffsetLB);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrDT), "LOADA", MELPARAMDEF.melParamDefWordOffsetDT);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrPB), "LOADA", MELPARAMDEF.melParamDefWordOffsetPB);
    setMelDecode(OPTAG2MELINST(MELINST.melLOADA, MELTAGADDR.melAddrPT), "LOADA", MELPARAMDEF.melParamDefWordOffsetPT);
    setMelDecodeStdModes(MELINST.melINDEX, "INDEX", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melSETB, "SETB", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melCMPB, "CMPB", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melADDB, "ADDB", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melSUBB, "SUBB", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melSETW, "SETW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melCMPW, "CMPW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melADDW, "ADDW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melSUBW, "SUBW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecodeStdModesAndTOS(MELINST.melCLEARN, "CLEARN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melTESTN, "TESTN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melINCN, "INCN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melDECN, "DECN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melNOTN, "NOTN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melCMPN, "CMPN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melADDN, "ADDN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melSUBN, "SUBN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melANDN, "ANDN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melORN, "ORN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecodeStdModesAndTOS(MELINST.melXORN, "XORN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemNOP), "NOP");
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemSetSW), "SETSW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemSetLa), "SETLA", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemSetSWLa), "SETSWLA", MELPARAMDEF.melParamDefWordImmediate, MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExit), "EXIT");
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExitSW), "EXITSW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExitLa), "EXITA", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSYSTEM, MELTAGSYSTEM.melSystemExitSWLa), "EXITSWLA", MELPARAMDEF.melParamDefWordImmediate, MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondEQ), "BEQ", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondLT), "BLT", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondLE), "BLE", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondGT), "BGT", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondGE), "BGE", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondNE), "BNE", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melBRANCH, MELTAGCOND.melCondALL), "BA", MELPARAMDEF.melParamDefByteCodeRelative);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondSPEC), "JA", MELPARAMDEF.melParamDefNone);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondEQ), "JEQ", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondLT), "JLT", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondLE), "JLE", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondGT), "JGT", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondGE), "JGE", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondNE), "JNE", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melJUMP, MELTAGCOND.melCondALL), "JA", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondSPEC), "CA", MELPARAMDEF.melParamDefNone);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondEQ), "CEQ", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondLT), "CLT", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondLE), "CLE", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondGT), "CGT", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondGE), "CGE", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondNE), "CNE", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melCALL, MELTAGCOND.melCondALL), "CA", MELPARAMDEF.melParamDefWordCodeAddress);
    setMelDecode(OPTAG2MELINST(MELINST.melSTACK, MELTAGSTACK.melStackPUSHZ), "PUSHZ", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecode(OPTAG2MELINST(MELINST.melSTACK, MELTAGSTACK.melStackPUSHB), "PUSHB", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSTACK, MELTAGSTACK.melStackPUSHW), "PUSHW", MELPARAMDEF.melParamDefWordImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melSTACK, MELTAGSTACK.melStackPOPN), "POPN", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecode(OPTAG2MELINST(MELINST.melSTACK, MELTAGSTACK.melStackPOPB), "POPB");
    setMelDecode(OPTAG2MELINST(MELINST.melSTACK, MELTAGSTACK.melStackPOPW), "POPW");
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM0), "PRIM", MELPARAMDEF.melParamDefByteImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM1), "PRIM", MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM2), "PRIM", MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetPRIM3), "PRIM", MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate, MELPARAMDEF.melParamDefByteImmediate);
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRET), "RET");
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRETI), "RET", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRETO), "RET", MELPARAMDEF.melParamDefByteOperLen);
    setMelDecode(OPTAG2MELINST(MELINST.melPRIMRET, MELTAGPRIMRET.melPrimRetRETIO), "RET", MELPARAMDEF.melParamDefByteOperLen, MELPARAMDEF.melParamDefByteOperLen);
}
fillMelDecode();
export var MELDecode = MEL.melDecode;
export const MEL_CCR_Z = 0x01;
export const MEL_CCR_C = 0x02;



function hex(val) { return val.toString(16); }
function hex2(val) { return ("00" + val.toString(16)).substr(-2); }
function hex4(val) { return ("0000" + val.toString(16)).substr(-4); }
function ljust(str, w) { return (str + Array(w + 1).join(" ")).substr(0, w); }
function rjust(str, w) { return (Array(w + 1).join(" ") + str).substr(-w); }
function BA2W(val) {
    return (val[0] << 8) | val[1];
}
function W2BA(val) {
    return new ByteArray([val >> 8, val & 0xFF]);
}
export class MELVirtualMachine {
    constructor() {
        this.segs = ["", "SB", "ST", "DB", "LB", "DT", "PB", "PT"];
    }
    initMVM(params) {
        this.romSegment = params.romSegment;
        this.ramSegment = params.ramSegment;
        this.publicArea = this.ramSegment.newAccessor(0, 512, "P");
    }
    disassembleCode(resetIP, stepToNextIP) {
        var dismText = "";
        function print(str) { dismText += str; }
        if (resetIP)
            this.currentIP = 0;
        if (this.currentIP >= this.codeArea.getLength())
            return null;
        try {
            var nextIP = this.currentIP;
            var instByte = this.codeArea.readByte(nextIP++);
            var paramCount = 0;
            var paramVal = [];
            var paramDef = [];
            var melInst = MEL.MELDecode[instByte];
            if (melInst == undefined) {
                print("[" + hex4(this.currentIP) + "]          " + ljust("ERROR:" + hex2(instByte), 8) + " ********\n");
            }
            else {
                var paramDefs = melInst.paramDefs;
                while (paramDefs != 0) {
                    paramDef[paramCount] = paramDefs & 0xFF;
                    switch (paramDefs & 0xF0) {
                        case 0x00: break;
                        case 0x10:
                            paramVal[paramCount] = this.codeArea.readByte(nextIP++);
                            break;
                        case 0x20:
                            paramVal[paramCount] = BA2W([this.codeArea.readByte(nextIP++), this.codeArea.readByte(nextIP++)]);
                            break;
                    }
                    paramCount++;
                    paramDefs >>= 8;
                }
                print("[" + hex4(this.currentIP) + "]          " + ljust(melInst.instName, 8));
                if ((paramCount > 1)
                    && ((paramDef[0] == MEL.MELPARAMDEF.melParamDefByteOperLen)
                        || (paramDef[0] == MEL.MELPARAMDEF.melParamDefByteImmediate)
                        || (paramDef[0] == MEL.MELPARAMDEF.melParamDefWordImmediate))
                    && (paramDef[1] != MEL.MELPARAMDEF.melParamDefByteImmediate)
                    && (paramDef[1] != MEL.MELPARAMDEF.melParamDefByteOperLen)) {
                    var tempVal = paramVal[1];
                    paramVal[1] = paramVal[0];
                    paramVal[0] = tempVal;
                    var tempDef = paramDef[1];
                    paramDef[1] = paramDef[0];
                    paramDef[0] = tempDef;
                }
                for (var paramIndex = 0; paramIndex < paramCount; ++paramIndex) {
                    var v = paramVal[paramIndex];
                    var d = paramDef[paramIndex];
                    switch (d) {
                        case MEL.MELPARAMDEF.melParamDefByteOperLen:
                            if (v > 0)
                                print("0x" + hex(v));
                            else
                                print(v);
                            break;
                        case MEL.MELPARAMDEF.melParamDefByteImmediate:
                            if (v > 0)
                                print("0x" + hex(v));
                            else
                                print(v);
                            break;
                        case MEL.MELPARAMDEF.melParamDefWordImmediate:
                            print("0x" + hex(v));
                            break;
                        case MEL.MELPARAMDEF.melParamDefWordCodeAddress:
                            print(hex4(v));
                            break;
                        case MEL.MELPARAMDEF.melParamDefByteCodeRelative:
                            print(hex4(this.currentIP + 2 + v));
                            break;
                        case MEL.MELPARAMDEF.melParamDefWordOffsetSB:
                        case MEL.MELPARAMDEF.melParamDefWordOffsetST:
                        case MEL.MELPARAMDEF.melParamDefWordOffsetDB:
                        case MEL.MELPARAMDEF.melParamDefWordOffsetLB:
                        case MEL.MELPARAMDEF.melParamDefWordOffsetDT:
                        case MEL.MELPARAMDEF.melParamDefWordOffsetPB:
                        case MEL.MELPARAMDEF.melParamDefWordOffsetPT:
                            {
                                var seg = ["", "SB", "ST", "DB", "LB", "DT", "PB", "PT"];
                                print(seg[d & 0x07]);
                                if (v > 0)
                                    print("[0x" + hex(v) + "]");
                                else
                                    print("[" + v + "]");
                                break;
                            }
                    }
                    if (paramIndex < paramCount - 1)
                        print(", ");
                }
                print("\n");
            }
            if (stepToNextIP)
                this.currentIP = nextIP;
        }
        catch (e) {
            print(e);
        }
        ;
        return dismText;
    }
    mapToSegmentAddr(addrTag, addrOffset) {
        var targetAccess = this.checkDataAccess(addrTag, addrOffset, 0);
        switch (addrTag) {
            case MEL.MELTAGADDR.melAddrTOS:
            case MEL.MELTAGADDR.melAddrDB:
            case MEL.MELTAGADDR.melAddrLB:
            case MEL.MELTAGADDR.melAddrDT:
                return 0x8000 + targetAccess.dataOffset;
            case MEL.MELTAGADDR.melAddrSB:
            case MEL.MELTAGADDR.melAddrST:
                return targetAccess.dataOffset;
            case MEL.MELTAGADDR.melAddrPB:
            case MEL.MELTAGADDR.melAddrPT:
                return 0xF000 + targetAccess.dataOffset;
        }
    }
    mapFromSegmentAddr(segmentAddr) {
        if (segmentAddr & 0x8000) {
            if (segmentAddr >= 0xF000) {
                return {
                    dataArea: this.publicArea,
                    dataAddrTag: MEL.MELTAGADDR.melAddrPB,
                    dataOffset: segmentAddr & 0x0FFF
                };
            }
            else {
                return {
                    dataArea: this.dynamicArea,
                    dataAddrTag: MEL.MELTAGADDR.melAddrDB,
                    dataOffset: segmentAddr & 0x3FFF
                };
            }
        }
        else {
            return {
                dataArea: this.staticArea,
                dataAddrTag: MEL.MELTAGADDR.melAddrSB,
                dataOffset: segmentAddr & 0x7FFF
            };
        }
    }
    checkDataAccess(addrTag, offset, length) {
        var dataArea;
        var dataOffset = offset;
        var areaLimit;
        switch (addrTag) {
            case MEL.MELTAGADDR.melAddrTOS:
                dataArea = this.dynamicArea;
                areaLimit = this.dynamicArea.getLength();
                dataOffset += this.localBase;
                break;
            case MEL.MELTAGADDR.melAddrDB:
                dataArea = this.dynamicArea;
                areaLimit = this.dynamicArea.getLength();
                break;
            case MEL.MELTAGADDR.melAddrLB:
                dataArea = this.dynamicArea;
                areaLimit = this.dynamicArea.getLength();
                dataOffset += this.localBase;
                break;
            case MEL.MELTAGADDR.melAddrDT:
                dataArea = this.dynamicArea;
                areaLimit = this.dynamicArea.getLength();
                dataOffset += this.dynamicTop;
                break;
            case MEL.MELTAGADDR.melAddrSB:
                dataArea = this.staticArea;
                areaLimit = this.staticArea.getLength();
                break;
            case MEL.MELTAGADDR.melAddrST:
                dataArea = this.staticArea;
                areaLimit = this.staticArea.getLength();
                dataOffset += areaLimit;
                break;
            case MEL.MELTAGADDR.melAddrPB:
                dataArea = this.publicArea;
                areaLimit = this.publicArea.getLength();
                break;
            case MEL.MELTAGADDR.melAddrPT:
                dataArea = this.publicArea;
                areaLimit = this.publicArea.getLength();
                dataOffset += areaLimit;
                break;
        }
        dataOffset &= 0xffff;
        if ((dataOffset < areaLimit) && (dataOffset + length < areaLimit)) {
            return {
                dataArea: dataArea,
                dataOffset: dataOffset
            };
        }
    }
    readSegmentData(addrTag, offset, length) {
        var targetAccess = this.checkDataAccess(addrTag, offset, 1);
        if (targetAccess == undefined)
            return;
        return targetAccess.dataArea.readBytes(targetAccess.dataOffset, length);
    }
    writeSegmentData(addrTag, offset, val) {
        var targetAccess = this.checkDataAccess(addrTag, offset, 1);
        if (targetAccess == undefined)
            return;
        targetAccess.dataArea.writeBytes(targetAccess.dataOffset, val);
    }
    pushZerosToStack(cnt) {
        this.dynamicArea.zeroBytes(this.dynamicTop, cnt);
        this.dynamicTop += cnt;
    }
    pushConstToStack(cnt, val) {
        if (cnt == 1)
            this.dynamicArea.writeBytes(this.dynamicTop, [val]);
        else
            this.dynamicArea.writeBytes(this.dynamicTop, W2BA(val));
        this.dynamicTop += cnt;
    }
    copyOnStack(fromOffset, toOffset, cnt) {
        this.dynamicArea.copyBytes(fromOffset, toOffset, cnt);
    }
    pushToStack(addrTag, offset, cnt) {
        this.dynamicTop += cnt;
        this.dynamicArea.writeBytes(this.dynamicTop, this.readSegmentData(addrTag, offset, cnt));
    }
    popFromStackAndStore(addrTag, offset, cnt) {
        this.dynamicTop -= cnt;
        this.writeSegmentData(addrTag, offset, this.dynamicArea.readBytes(this.dynamicTop, cnt));
    }
    popFromStack(cnt) {
        this.dynamicTop -= cnt;
        return this.dynamicArea.readBytes(this.dynamicTop, cnt);
    }
    setupApplication(execParams) {
        this.codeArea = execParams.codeArea;
        this.staticArea = execParams.staticArea;
        this.sessionSize = execParams.sessionSize;
        this.dynamicArea = this.ramSegment.newAccessor(0, 512, "D");
        this.initExecution();
    }
    initExecution() {
        this.currentIP = 0;
        this.isExecuting = true;
        this.localBase = this.sessionSize;
        this.dynamicTop = this.localBase;
        this.conditionCodeReg = 0;
    }
    constByteBinaryOperation(opCode, constVal, addrTag, addrOffset) {
        var targetAccess = this.checkDataAccess(addrTag, addrOffset, 1);
        if (targetAccess == undefined)
            return;
        var tempVal = targetAccess.dataArea.readByte(targetAccess.dataOffset);
        switch (opCode) {
            case MEL.MELINST.melADDB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = (tempVal + constVal);
                if (tempVal < constVal)
                    this.conditionCodeReg |= MEL.MEL_CCR_C;
                break;
            case MEL.MELINST.melSUBB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = (tempVal - constVal);
                if (tempVal > constVal)
                    this.conditionCodeReg |= MEL.MEL_CCR_C;
                break;
            case MEL.MELINST.melCMPB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = (tempVal - constVal);
                if (tempVal > constVal)
                    this.conditionCodeReg |= MEL.MEL_CCR_C;
                break;
            case MEL.MELINST.melSETB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = constVal;
                break;
        }
        if (tempVal == 0)
            this.conditionCodeReg |= MEL.MEL_CCR_Z;
        if (opCode != MEL.MELINST.melCMPB) {
            targetAccess.dataArea.writeByte(targetAccess.dataOffset, tempVal);
        }
    }
    constWordBinaryOperation(opCode, constVal, addrTag, addrOffset) {
        var targetAccess = this.checkDataAccess(addrTag, addrOffset, 2);
        if (targetAccess == undefined)
            return;
        var tempVal = BA2W(targetAccess.dataArea.readBytes(targetAccess.dataOffset, 2));
        switch (opCode) {
            case MEL.MELINST.melADDB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = (tempVal + constVal);
                if (tempVal < constVal)
                    this.conditionCodeReg |= MEL.MEL_CCR_C;
                break;
            case MEL.MELINST.melSUBB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = (tempVal - constVal);
                if (tempVal > constVal)
                    this.conditionCodeReg |= MEL.MEL_CCR_C;
                break;
            case MEL.MELINST.melCMPB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = (tempVal - constVal);
                if (tempVal > constVal)
                    this.conditionCodeReg |= MEL.MEL_CCR_C;
                break;
            case MEL.MELINST.melSETB:
                this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                tempVal = constVal;
                break;
        }
        if (tempVal == 0)
            this.conditionCodeReg |= MEL.MEL_CCR_Z;
        if (opCode != MEL.MELINST.melCMPW) {
            targetAccess.dataArea.writeBytes(targetAccess.dataOffset, W2BA(tempVal));
        }
    }
    binaryOperation(opCode, opSize, addrTag, addrOffset) {
        var targetAccess = this.checkDataAccess(addrTag, addrOffset, 1);
        if (targetAccess == undefined)
            return;
        this.checkDataAccess(-opSize - 1, opSize, MEL.MELTAGADDR.melAddrTOS);
    }
    unaryOperation(opCode, opSize, addrTag, addrOffset) {
        var targetAccess = this.checkDataAccess(addrTag, addrOffset, 1);
        if (targetAccess == undefined)
            return;
        switch (opCode) {
            case MEL.MELINST.melCLEARN:
                targetAccess.dataArea.zeroBytes(targetAccess.dataOffset, opSize);
                break;
            case MEL.MELINST.melTESTN:
            case MEL.MELINST.melINCN:
            case MEL.MELINST.melDECN:
            case MEL.MELINST.melNOTN:
                ;
        }
    }
    handleReturn(inBytes, outBytes) {
        var retValOffset = this.dynamicTop - outBytes;
        var returnIP = BA2W(this.dynamicArea.readBytes(this.localBase - 2, 2));
        this.localBase = BA2W(this.dynamicArea.readBytes(this.localBase - 4, 2));
        this.dynamicTop = this.localBase + outBytes;
        if (outBytes)
            this.copyOnStack(retValOffset, this.localBase, outBytes);
        return returnIP;
    }
    isCondition(tag) {
        switch (tag) {
            case MEL.MELTAGCOND.melCondEQ:
                return (this.conditionCodeReg & MEL.MEL_CCR_Z);
            case MEL.MELTAGCOND.melCondLT:
                return !(this.conditionCodeReg & MEL.MEL_CCR_C);
            case MEL.MELTAGCOND.melCondLE:
                return (this.conditionCodeReg & MEL.MEL_CCR_Z) || !(this.conditionCodeReg & MEL.MEL_CCR_C);
            case MEL.MELTAGCOND.melCondGT:
                return (this.conditionCodeReg & MEL.MEL_CCR_C);
            case MEL.MELTAGCOND.melCondGE:
                return (this.conditionCodeReg & MEL.MEL_CCR_Z) || (this.conditionCodeReg & MEL.MEL_CCR_C);
            case MEL.MELTAGCOND.melCondNE:
                return !(this.conditionCodeReg & MEL.MEL_CCR_Z);
            case MEL.MELTAGCOND.melCondALL:
                return true;
            default:
        }
        return false;
    }
    executeStep() {
        try {
            var nextIP = this.currentIP;
            var instByte = this.codeArea.readByte(nextIP++);
            var paramCount = 0;
            var paramVal = [];
            var paramDef = [];
            var melInst = MEL.MELDecode[instByte];
            if (melInst == undefined) {
                return null;
            }
            else {
                var paramDefs = melInst.paramDefs;
                while (paramDefs != 0) {
                    paramDef[paramCount] = paramDefs & 0xFF;
                    switch (paramDefs & 0xF0) {
                        case 0x00: break;
                        case 0x10:
                            paramVal[paramCount] = this.codeArea.readByte(nextIP++);
                            break;
                        case 0x20:
                            paramVal[paramCount] = BA2W([this.codeArea.readByte(nextIP++), this.codeArea.readByte(nextIP++)]);
                            break;
                    }
                    paramCount++;
                    paramDefs >>= 8;
                }
            }
            var opCode = MEL.MEL2OPCODE(instByte);
            var tag = MEL.MEL2TAG(instByte);
            switch (opCode) {
                case MEL.MELINST.melSYSTEM:
                    {
                        var publicTop = this.publicArea.getLength();
                        switch (tag) {
                            case MEL.MELTAGSYSTEM.melSystemExit:
                                this.isExecuting = false;
                            case MEL.MELTAGSYSTEM.melSystemNOP:
                                break;
                            case MEL.MELTAGSYSTEM.melSystemExitSW:
                                this.isExecuting = false;
                            case MEL.MELTAGSYSTEM.melSystemSetSW:
                                this.publicArea.writeBytes(publicTop - 2, W2BA(paramVal[0]));
                                break;
                            case MEL.MELTAGSYSTEM.melSystemExitLa:
                                this.isExecuting = false;
                            case MEL.MELTAGSYSTEM.melSystemSetLa:
                                this.publicArea.writeBytes(publicTop - 4, W2BA(paramVal[0]));
                                break;
                            case MEL.MELTAGSYSTEM.melSystemExitSWLa:
                                this.isExecuting = false;
                            case MEL.MELTAGSYSTEM.melSystemSetSWLa:
                                this.publicArea.writeBytes(publicTop - 2, W2BA(paramVal[0]));
                                this.publicArea.writeBytes(publicTop - 4, W2BA(paramVal[1]));
                                break;
                        }
                        break;
                    }
                case MEL.MELINST.melBRANCH:
                    if (this.isCondition(tag))
                        nextIP = nextIP + paramVal[0];
                    break;
                case MEL.MELINST.melJUMP:
                    if (this.isCondition(tag))
                        nextIP = paramVal[0];
                    break;
                case MEL.MELINST.melCALL:
                    if (this.isCondition(tag)) {
                        this.pushConstToStack(2, this.localBase);
                        this.pushConstToStack(2, nextIP);
                        nextIP = paramVal[0];
                        this.localBase = this.dynamicTop;
                    }
                    break;
                case MEL.MELINST.melSTACK:
                    {
                        switch (tag) {
                            case MEL.MELTAGSTACK.melStackPUSHZ:
                                {
                                    this.pushZerosToStack(paramVal[0]);
                                    break;
                                }
                            case MEL.MELTAGSTACK.melStackPUSHB:
                                this.pushConstToStack(1, paramVal[0]);
                                break;
                            case MEL.MELTAGSTACK.melStackPUSHW:
                                this.pushConstToStack(2, paramVal[0]);
                                break;
                            case MEL.MELTAGSTACK.melStackPOPN:
                                this.popFromStack(paramVal[0]);
                                break;
                            case MEL.MELTAGSTACK.melStackPOPB:
                                this.popFromStack(1);
                                break;
                            case MEL.MELTAGSTACK.melStackPOPW:
                                this.popFromStack(2);
                                break;
                        }
                        break;
                    }
                case MEL.MELINST.melPRIMRET:
                    {
                        switch (tag) {
                            case MEL.MELTAGPRIMRET.melPrimRetPRIM0:
                            case MEL.MELTAGPRIMRET.melPrimRetPRIM1:
                            case MEL.MELTAGPRIMRET.melPrimRetPRIM2:
                            case MEL.MELTAGPRIMRET.melPrimRetPRIM3:
                                break;
                            case MEL.MELTAGPRIMRET.melPrimRetRET:
                                nextIP = this.handleReturn(0, 0);
                                break;
                            case MEL.MELTAGPRIMRET.melPrimRetRETI:
                                nextIP = this.handleReturn(paramVal[0], 0);
                                break;
                            case MEL.MELTAGPRIMRET.melPrimRetRETO:
                                nextIP = this.handleReturn(0, paramVal[0]);
                                break;
                            case MEL.MELTAGPRIMRET.melPrimRetRETIO:
                                nextIP = this.handleReturn(paramVal[0], paramVal[1]);
                                break;
                        }
                        break;
                    }
                case MEL.MELINST.melLOAD:
                    if (tag == MEL.MELTAGADDR.melAddrTOS) {
                        this.copyOnStack(this.dynamicTop - paramVal[0], this.dynamicTop, paramVal[0]);
                        this.dynamicTop += paramVal[0];
                    }
                    else
                        this.pushToStack(tag, paramVal[1], paramVal[0]);
                    break;
                case MEL.MELINST.melSTORE:
                    if (tag == MEL.MELTAGADDR.melAddrTOS) {
                        this.dynamicTop -= paramVal[0];
                        this.copyOnStack(this.dynamicTop, this.dynamicTop - paramVal[0], paramVal[0]);
                    }
                    else
                        this.popFromStackAndStore(tag, paramVal[1], paramVal[0]);
                    break;
                case MEL.MELINST.melLOADI:
                    {
                        var segmentAddr = BA2W(this.readSegmentData(tag, paramVal[1], 2));
                        var targetAccess = this.mapFromSegmentAddr(segmentAddr);
                        this.pushToStack(targetAccess.dataAddrTag, targetAccess.dataOffset, paramVal[0]);
                        break;
                    }
                case MEL.MELINST.melSTOREI:
                    {
                        var segmentAddr = BA2W(this.readSegmentData(tag, paramVal[1], 2));
                        var targetAccess = this.mapFromSegmentAddr(segmentAddr);
                        this.popFromStackAndStore(targetAccess.dataAddrTag, targetAccess.dataOffset, paramVal[0]);
                        break;
                    }
                case MEL.MELINST.melLOADA:
                    this.pushConstToStack(2, this.mapToSegmentAddr(tag, paramVal[0]));
                    break;
                case MEL.MELINST.melINDEX:
                    break;
                case MEL.MELINST.melSETB:
                case MEL.MELINST.melCMPB:
                case MEL.MELINST.melADDB:
                case MEL.MELINST.melSUBB:
                    if (tag == MEL.MELTAGADDR.melAddrTOS)
                        this.constByteBinaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -1);
                    else
                        this.constByteBinaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                    break;
                case MEL.MELINST.melSETW:
                case MEL.MELINST.melCMPW:
                case MEL.MELINST.melADDW:
                case MEL.MELINST.melSUBW:
                    if (tag == MEL.MELTAGADDR.melAddrTOS)
                        this.constWordBinaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -2);
                    else
                        this.constWordBinaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                    break;
                case MEL.MELINST.melCLEARN:
                case MEL.MELINST.melTESTN:
                case MEL.MELINST.melINCN:
                case MEL.MELINST.melDECN:
                case MEL.MELINST.melNOTN:
                    if (tag == MEL.MELTAGADDR.melAddrTOS)
                        this.unaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -1 * paramVal[0]);
                    else
                        this.unaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                    break;
                case MEL.MELINST.melCMPN:
                case MEL.MELINST.melADDN:
                case MEL.MELINST.melSUBN:
                case MEL.MELINST.melANDN:
                case MEL.MELINST.melORN:
                case MEL.MELINST.melXORN:
                    if (tag == MEL.MELTAGADDR.melAddrTOS)
                        this.binaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -2 * paramVal[0]);
                    else
                        this.binaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                    break;
            }
            this.currentIP = nextIP;
        }
        catch (e) {
        }
    }
    setCommandAPDU(commandAPDU) {
        var publicTop = this.publicArea.getLength();
        this.publicArea.writeBytes(publicTop - 2, W2BA(0x9000));
        this.publicArea.writeBytes(publicTop - 4, W2BA(0x0000));
        this.publicArea.writeBytes(publicTop - 6, W2BA(commandAPDU.Le));
        this.publicArea.writeBytes(publicTop - 8, W2BA(commandAPDU.data.length));
        this.publicArea.writeBytes(publicTop - 13, commandAPDU.header);
        this.publicArea.writeBytes(0, commandAPDU.data);
        this.initExecution();
    }
    getResponseAPDU() {
        var publicTop = this.publicArea.getLength();
        var la = BA2W(this.publicArea.readBytes(publicTop - 4, 2));
        return new ResponseAPDU({ sw: BA2W(this.publicArea.readBytes(publicTop - 2, 2)), data: this.publicArea.readBytes(0, la) });
    }
    get getDebug() {
        return {
            ramSegment: this.ramSegment,
            dynamicArea: this.dynamicArea,
            publicArea: this.publicArea,
            staticArea: this.staticArea,
            currentIP: this.currentIP,
            dynamicTop: this.dynamicTop,
            localBase: this.localBase
        };
    }
}




function BA2W(val) {
    return (val[0] << 8) | val[1];
}
export class JSIMMultosApplet {
    constructor(codeArea, staticArea, sessionSize) {
        this.codeArea = codeArea;
        this.staticArea = staticArea;
        this.sessionSize = sessionSize;
    }
}
export class JSIMMultosCard {
    constructor(config) {
        if (config)
            this.cardConfig = config;
        else
            this.cardConfig = JSIMMultosCard.defaultConfig;
        this.atr = new ByteArray([]);
        this.applets = [];
    }
    loadApplication(aid, alu) {
        var len = 0;
        var off = 8;
        len = alu.wordAt(off);
        off += 2;
        let codeArea = this.nvramSegment.newAccessor(0, len, "code");
        codeArea.writeBytes(0, alu.viewAt(off, len));
        off += len;
        len = alu.wordAt(off);
        off += 2;
        let staticArea = this.nvramSegment.newAccessor(codeArea.getLength(), len, "S");
        staticArea.writeBytes(0, alu.viewAt(off, len));
        off += len;
        let applet = new JSIMMultosApplet(codeArea, staticArea, 0);
        this.applets.push({ aid: aid, applet: applet });
    }
    get isPowered() {
        return this.powerIsOn;
    }
    powerOn() {
        this.powerIsOn = true;
        this.initializeVM(this.cardConfig);
        return Promise.resolve(this.atr);
    }
    powerOff() {
        this.powerIsOn = false;
        this.resetVM();
        this.selectedApplet = undefined;
        return Promise.resolve();
    }
    reset() {
        this.powerIsOn = true;
        this.selectedApplet = undefined;
        this.shutdownVM();
        return Promise.resolve(this.atr);
    }
    exchangeAPDU(commandAPDU) {
        if (commandAPDU.INS == 0xA4) {
            if (this.selectedApplet) {
                this.selectedApplet = undefined;
            }
            this.selectedApplet = this.applets[0].applet;
            let fci = new ByteArray([0x6F, 0x00]);
            this.mvm.setupApplication(this.selectedApplet);
            return Promise.resolve(new ResponseAPDU({ sw: 0x9000, data: fci }));
        }
        this.mvm.setCommandAPDU(commandAPDU);
        return Promise.resolve(new ResponseAPDU({ sw: 0x9000, data: [] }));
    }
    initializeVM(config) {
        this.memoryManager = new MemoryManager();
        this.romSegment = this.memoryManager.newSegment(0, this.cardConfig.romSize, MEMFLAGS.READ_ONLY);
        this.ramSegment = this.memoryManager.newSegment(1, this.cardConfig.ramSize, 0);
        this.nvramSegment = this.memoryManager.newSegment(2, this.cardConfig.nvramSize, MEMFLAGS.TRANSACTIONABLE);
        this.mvm = new MELVirtualMachine();
        this.resetVM();
    }
    resetVM() {
        var mvmParams = {
            ramSegment: this.ramSegment,
            romSegment: this.romSegment,
            publicSize: this.cardConfig.publicSize
        };
        this.mvm.initMVM(mvmParams);
    }
    shutdownVM() {
        this.resetVM();
        this.mvm = null;
    }
    selectApplication(applet, sessionSize) {
        var execParams = {
            codeArea: applet.codeArea,
            staticArea: applet.staticArea,
            sessionSize: sessionSize
        };
        this.mvm.execApplication(execParams);
    }
    executeStep() {
        return this.mvm.executeStep();
    }
}
JSIMMultosCard.defaultConfig = {
    romSize: 0,
    ramSize: 1024,
    publicSize: 512,
    nvramSize: 32768
};

var setZeroPrimitives = {
    0x01: {
        name: "CHECK_CASE",
        proc: function () {
        }
    },
    0x02: {
        name: "RESET_WWT",
        proc: function () {
        }
    },
    0x05: {
        name: "LOAD_CCR",
        proc: function () {
        }
    },
    0x06: {
        name: "STORE_CCR",
        proc: function () {
        }
    },
    0x07: {
        name: "SET_ATR_FILE_RECORD",
        proc: function () {
        }
    },
    0x08: {
        name: "SET_ATR_HISTORICAL_CHARACTERS",
        proc: function () {
        }
    },
    0x09: {
        name: "GET_MEMORY_RELIABILITY",
        proc: function () {
        }
    },
    0xa: {
        name: "LOOKUP",
        proc: function () {
        }
    },
    0xb: {
        name: "MEMORY_COMPARE",
        proc: function () {
        }
    },
    0xc: {
        name: "MEMORY_COPY",
        proc: function () {
        }
    },
    0xd: {
        name: "QUERY_INTERFACE_TYPE",
        proc: function () {
        }
    },
    0x10: {
        name: "CONTROL_AUTO_RESET_WWT",
        proc: function () {
        }
    },
    0x11: {
        name: "SET_FCI_FILE_RECORD",
        proc: function () {
        }
    },
    0x80: {
        name: "DELEGATE",
        proc: function () {
        }
    },
    0x81: {
        name: "RESET_SESSION_DATA",
        proc: function () {
        }
    },
    0x82: {
        name: "CHECKSUM",
        proc: function () {
        }
    },
    0x83: {
        name: "CALL_CODELET",
        proc: function () {
        }
    },
    0x84: {
        name: "QUERY_CODELET",
        proc: function () {
        }
    },
    0xc1: {
        name: "DES_ECB_ENCIPHER",
        proc: function () {
        }
    },
    0xc2: {
        name: "MODULAR_MULTIPLICATION",
        proc: function () {
        }
    },
    0xc3: {
        name: "MODULAR_REDUCTION",
        proc: function () {
        }
    },
    0xc4: {
        name: "GET_RANDOM_NUMBER",
        proc: function () {
        }
    },
    0xc5: {
        name: "DES_ECB_DECIPHER",
        proc: function () {
        }
    },
    0xc6: {
        name: "GENERATE_DES_CBC_SIGNATURE",
        proc: function () {
        }
    },
    0xc7: {
        name: "GENERATE_TRIPLE_DES_CBC_SIGNATURE",
        proc: function () {
        }
    },
    0xc8: {
        name: "MODULAR_EXPONENTIATION",
        proc: function () {
        }
    },
    0xc9: {
        name: "MODULAR_EXPONENTIATION_CRT",
        proc: function () {
        }
    },
    0xca: {
        name: "SHA1",
        proc: function () {
        }
    },
    0xcc: {
        name: "GENERATE_RANDOM_PRIME",
        proc: function () {
        }
    },
    0xcd: {
        name: "SEED_ECB_DECIPHER",
        proc: function () {
        }
    },
    0xce: {
        name: "SEED_ECB_ENCIPHER",
        proc: function () {
        }
    }
};
var setOnePrimitives = {
    0x00: {
        name: "QUERY0",
        proc: function () {
        }
    },
    0x01: {
        name: "QUERY1",
        proc: function () {
        }
    },
    0x02: {
        name: "QUERY2",
        proc: function () {
        }
    },
    0x03: {
        name: "QUERY3",
        proc: function () {
        }
    },
    0x08: {
        name: "DIVIDEN",
        proc: function () {
        }
    },
    0x09: {
        name: "GET_DIR_FILE_RECORD",
        proc: function () {
        }
    },
    0x0a: {
        name: "GET_FILE_CONTROL_INFORMATION",
        proc: function () {
        }
    },
    0x0b: {
        name: "GET_MANUFACTURER_DATA",
        proc: function () {
        }
    },
    0x0c: {
        name: "GET_MULTOS_DATA",
        proc: function () {
        }
    },
    0x0d: {
        name: "GET_PURSE_TYPE",
        proc: function () {
        }
    },
    0x0e: {
        name: "MEMORY_COPY_FIXED_LENGTH",
        proc: function () {
        }
    },
    0x0f: {
        name: "MEMORY_COMPARE_FIXED_LENGTH",
        proc: function () {
        }
    },
    0x10: {
        name: "MULTIPLYN",
        proc: function () {
        }
    },
    0x80: {
        name: "SET_TRANSACTION_PROTECTION",
        proc: function () {
        }
    },
    0x81: {
        name: "GET_DELEGATOR_AID",
        proc: function () {
        }
    },
    0xc4: {
        name: "GENERATE_ASYMMETRIC_HASH",
        proc: function () {
        }
    }
};
function bitManipulate(bitmap, literal, data) {
    var modify = ((bitmap & (1 << 7)) == (1 << 7));
    if (bitmap & 0x7c)
        throw new Error("Undefined arguments");
    switch (bitmap & 3) {
        case 3:
            data &= literal;
            break;
        case 2:
            data |= literal;
            break;
        case 1:
            data = ~(data ^ literal);
            break;
        case 0:
            data ^= literal;
            break;
    }
    return modify;
}
var setTwoPrimitives = {
    0x01: {
        name: "BIT_MANIPULATE_BYTE",
        proc: function () {
        }
    },
    0x02: {
        name: "SHIFT_LEFT",
        proc: function () {
        }
    },
    0x03: {
        name: "SHIFT_RIGHT",
        proc: function () {
        }
    },
    0x04: {
        name: "SET_SELECT_SW",
        proc: function () {
        }
    },
    0x05: {
        name: "CARD_BLOCK",
        proc: function () {
        }
    },
    0x80: {
        name: "RETURN_FROM_CODELET",
        proc: function () {
        }
    }
};
var setThreePrimitives = {
    0x01: {
        name: "BIT_MANIPULATE_WORD",
        proc: function () {
        }
    },
    0x80: {
        name: "CALL_EXTENSION_PRIMITIVE0",
        proc: function () {
        }
    },
    0x81: {
        name: "CALL_EXTENSION_PRIMITIVE1",
        proc: function () {
        }
    },
    0x82: {
        name: "CALL_EXTENSION_PRIMITIVE2",
        proc: function () {
        }
    },
    0x83: {
        name: "CALL_EXTENSION_PRIMITIVE3",
        proc: function () {
        }
    },
    0x84: {
        name: "CALL_EXTENSION_PRIMITIVE4",
        proc: function () {
        }
    },
    0x85: {
        name: "CALL_EXTENSION_PRIMITIVE5",
        proc: function () {
        }
    },
    0x86: {
        name: "CALL_EXTENSION_PRIMITIVE6",
        proc: function () {
        }
    }
};
var primitiveSets = [
    setZeroPrimitives,
    setOnePrimitives,
    setTwoPrimitives,
    setThreePrimitives
];
export function callPrimitive(ctx, prim, set, arg1, arg2, arg3) {
    var primInfo = primitiveSets[set][prim];
    if (primInfo) {
        switch (set) {
            case 0:
                primInfo.proc();
                break;
            case 1:
                primInfo.proc(arg1);
                break;
            case 2:
                primInfo.proc(arg1, arg2);
                break;
            case 3:
                primInfo.proc(arg1, arg2, arg3);
                break;
        }
    }
    else {
        throw new Error("Primitive not Implemented");
    }
}

export class SecurityManager {
    initSecurity() {
    }
    processAPDU(apdu) {
        return false;
    }
}

export class ADC {
}

export class ALC {
}

export class ALU {
    constructor(attributes) {
        this.code = new ByteArray();
        this.data = new ByteArray();
        this.fci = new ByteArray();
        this.dir = new ByteArray();
        if (attributes) {
            for (let field in ALU.kindInfo.fields)
                if (attributes[field.id])
                    this[field.id] = attributes[field.id];
        }
    }
    toJSON() {
        return {
            code: this.code,
            data: this.data,
            fci: this.fci,
            dir: this.dir
        };
    }
    getALUSegment(bytes, segmentID) {
        var offset = 8;
        while ((segmentID > 1) && (offset < bytes.length)) {
            offset += 2 + bytes.wordAt(offset);
            --segmentID;
        }
        return bytes.viewAt(offset + 2, bytes.wordAt(offset));
    }
    decodeBytes(bytes, options) {
        this.code = this.getALUSegment(bytes, 1);
        this.data = this.getALUSegment(bytes, 2);
        this.dir = this.getALUSegment(bytes, 3);
        this.fci = this.getALUSegment(bytes, 4);
        return this;
    }
    encodeBytes(options) {
        return new ByteArray([]);
    }
}
KindBuilder.init(ALU, "MULTOS Application Load Unit")
    .field("code", "Code Segment", ByteArray)
    .field("data", "Data Segment", ByteArray)
    .field("fci", "FCI Segment", ByteArray)
    .field("dir", "DIR Segment", ByteArray);











//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcva2V5LnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9jcnlwdG8udHMiLCJnbG9iYWwtcGxhdGZvcm0tc2NyaXB0aW5nL2J5dGUtc3RyaW5nLnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9ieXRlLWJ1ZmZlci50cyIsImlzbzc4MTYvYmFzZS10bHYudHMiLCJnbG9iYWwtcGxhdGZvcm0tc2NyaXB0aW5nL3Rsdi50cyIsImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcvdGx2LWxpc3QudHMiLCJpc283ODE2L2NvbW1hbmQtYXBkdS50cyIsImlzbzc4MTYvaXNvNzgxNi50cyIsImlzbzc4MTYvcmVzcG9uc2UtYXBkdS50cyIsImlzbzc4MTYvc2xvdC5qcyIsImlzbzc4MTYvc2xvdC1wcm90b2NvbC1oYW5kbGVyLnRzIiwianNpbS1jYXJkL1Nsb3RzLnRzIiwianNpbS1jYXJkL2pzaW0tY2FyZC5qcyIsImpzaW0tY2FyZC9qc2ltLXNjcmlwdC1hcHBsZXQudHMiLCJqc2ltLWNhcmQvanNpbS1zY3JpcHQtY2FyZC50cyIsImpzaW0tY2FyZC9qc2ltLXNsb3QudHMiLCJqc2ltLW11bHRvcy9tZW1vcnktbWFuYWdlci50cyIsImpzaW0tbXVsdG9zL21lbC1kZWZpbmVzLnRzIiwianNpbS1tdWx0b3MvdmlydHVhbC1tYWNoaW5lLnRzIiwianNpbS1tdWx0b3MvanNpbS1tdWx0b3MtY2FyZC50cyIsImpzaW0tbXVsdG9zL3ByaW1pdGl2ZXMudHMiLCJqc2ltLW11bHRvcy9zZWN1cml0eS1tYW5hZ2VyLnRzIiwibXVsdG9zL2FkYy50cyIsIm11bHRvcy9hbGMudHMiLCJtdWx0b3MvYWx1LnRzIiwiY29tcG9uZW50cy9ieXRlLWRhdGEtaW5wdXQuanMiLCJjb21wb25lbnRzL2J5dGUtZGF0YS1vdXRwdXQuanMiLCJjb21wb25lbnRzL2NyeXB0b3ItYm94LmpzIiwiY29tcG9uZW50cy9yc2Eta2V5LWJ1aWxkZXIuanMiLCJjb21wb25lbnRzL3NlY3JldC1rZXktYnVpbGRlci5qcyJdLCJuYW1lcyI6WyJLZXkiLCJLZXkuY29uc3RydWN0b3IiLCJLZXkuc2V0VHlwZSIsIktleS5nZXRUeXBlIiwiS2V5LnNldFNpemUiLCJLZXkuZ2V0U2l6ZSIsIktleS5zZXRDb21wb25lbnQiLCJLZXkuZ2V0Q29tcG9uZW50IiwiQ3J5cHRvIiwiQ3J5cHRvLmNvbnN0cnVjdG9yIiwiQ3J5cHRvLmVuY3J5cHQiLCJDcnlwdG8uZGVjcnlwdCIsIkNyeXB0by5zaWduIiwiQ3J5cHRvLmRlcyIsIkNyeXB0by5kZXMuZGVzX2NyZWF0ZUtleXMiLCJDcnlwdG8udmVyaWZ5IiwiQ3J5cHRvLmRpZ2VzdCIsIkJ5dGVTdHJpbmciLCJCeXRlU3RyaW5nLmNvbnN0cnVjdG9yIiwiQnl0ZVN0cmluZy5sZW5ndGgiLCJCeXRlU3RyaW5nLmJ5dGVzIiwiQnl0ZVN0cmluZy5ieXRlQXQiLCJCeXRlU3RyaW5nLmVxdWFscyIsIkJ5dGVTdHJpbmcuY29uY2F0IiwiQnl0ZVN0cmluZy5sZWZ0IiwiQnl0ZVN0cmluZy5yaWdodCIsIkJ5dGVTdHJpbmcubm90IiwiQnl0ZVN0cmluZy5hbmQiLCJCeXRlU3RyaW5nLm9yIiwiQnl0ZVN0cmluZy5wYWQiLCJCeXRlU3RyaW5nLnRvU3RyaW5nIiwiQnl0ZUJ1ZmZlciIsIkJ5dGVCdWZmZXIuY29uc3RydWN0b3IiLCJCeXRlQnVmZmVyLmxlbmd0aCIsIkJ5dGVCdWZmZXIudG9CeXRlU3RyaW5nIiwiQnl0ZUJ1ZmZlci5jbGVhciIsIkJ5dGVCdWZmZXIuYXBwZW5kIiwiQmFzZVRMViIsIkJhc2VUTFYuY29uc3RydWN0b3IiLCJCYXNlVExWLnBhcnNlVExWIiwiQmFzZVRMVi50YWciLCJCYXNlVExWLnZhbHVlIiwiQmFzZVRMVi5sZW4iLCJUTFYiLCJUTFYuY29uc3RydWN0b3IiLCJUTFYuZ2V0VExWIiwiVExWLmdldFRhZyIsIlRMVi5nZXRWYWx1ZSIsIlRMVi5nZXRMIiwiVExWLmdldExWIiwiVExWLnBhcnNlVExWIiwiVExWTGlzdCIsIlRMVkxpc3QuY29uc3RydWN0b3IiLCJUTFZMaXN0LmluZGV4IiwiQ29tbWFuZEFQRFUiLCJDb21tYW5kQVBEVS5jb25zdHJ1Y3RvciIsIkNvbW1hbmRBUERVLkxjIiwiQ29tbWFuZEFQRFUuaGVhZGVyIiwiQ29tbWFuZEFQRFUuaW5pdCIsIkNvbW1hbmRBUERVLnNldCIsIkNvbW1hbmRBUERVLnNldENMQSIsIkNvbW1hbmRBUERVLnNldElOUyIsIkNvbW1hbmRBUERVLnNldFAxIiwiQ29tbWFuZEFQRFUuc2V0UDIiLCJDb21tYW5kQVBEVS5zZXREYXRhIiwiQ29tbWFuZEFQRFUuc2V0TGUiLCJDb21tYW5kQVBEVS50b0pTT04iLCJDb21tYW5kQVBEVS5lbmNvZGVCeXRlcyIsIkNvbW1hbmRBUERVLmRlY29kZUJ5dGVzIiwiSVNPNzgxNiIsIlJlc3BvbnNlQVBEVSIsIlJlc3BvbnNlQVBEVS5jb25zdHJ1Y3RvciIsIlJlc3BvbnNlQVBEVS5MYSIsIlJlc3BvbnNlQVBEVS5pbml0IiwiUmVzcG9uc2VBUERVLnNldCIsIlJlc3BvbnNlQVBEVS5zZXRTVyIsIlJlc3BvbnNlQVBEVS5zZXRTVzEiLCJSZXNwb25zZUFQRFUuc2V0U1cyIiwiUmVzcG9uc2VBUERVLnNldERhdGEiLCJSZXNwb25zZUFQRFUuZW5jb2RlQnl0ZXMiLCJSZXNwb25zZUFQRFUuZGVjb2RlQnl0ZXMiLCJTbG90UHJvdG9jb2xIYW5kbGVyIiwiU2xvdFByb3RvY29sSGFuZGxlci5jb25zdHJ1Y3RvciIsIlNsb3RQcm90b2NvbEhhbmRsZXIubGlua1Nsb3QiLCJTbG90UHJvdG9jb2xIYW5kbGVyLnVubGlua1Nsb3QiLCJTbG90UHJvdG9jb2xIYW5kbGVyLm9uTWVzc2FnZSIsIkpTU2ltdWxhdGVkU2xvdCIsIkpTU2ltdWxhdGVkU2xvdC5Pbk1lc3NhZ2UiLCJKU1NpbXVsYXRlZFNsb3QuaW5pdCIsIkpTU2ltdWxhdGVkU2xvdC5zZW5kVG9Xb3JrZXIiLCJKU1NpbXVsYXRlZFNsb3QuZXhlY3V0ZUFQRFVDb21tYW5kIiwiSlNJTVNjcmlwdEFwcGxldCIsIkpTSU1TY3JpcHRBcHBsZXQuc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNU2NyaXB0QXBwbGV0LmRlc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNU2NyaXB0QXBwbGV0LmV4ZWN1dGVBUERVIiwiSlNJTVNjcmlwdENhcmQiLCJKU0lNU2NyaXB0Q2FyZC5jb25zdHJ1Y3RvciIsIkpTSU1TY3JpcHRDYXJkLmxvYWRBcHBsaWNhdGlvbiIsIkpTSU1TY3JpcHRDYXJkLmlzUG93ZXJlZCIsIkpTSU1TY3JpcHRDYXJkLnBvd2VyT24iLCJKU0lNU2NyaXB0Q2FyZC5wb3dlck9mZiIsIkpTSU1TY3JpcHRDYXJkLnJlc2V0IiwiSlNJTVNjcmlwdENhcmQuZXhjaGFuZ2VBUERVIiwiSlNJTVNsb3QiLCJKU0lNU2xvdC5jb25zdHJ1Y3RvciIsIkpTSU1TbG90LmlzUHJlc2VudCIsIkpTSU1TbG90LmlzUG93ZXJlZCIsIkpTSU1TbG90LnBvd2VyT24iLCJKU0lNU2xvdC5wb3dlck9mZiIsIkpTSU1TbG90LnJlc2V0IiwiSlNJTVNsb3QuZXhlY3V0ZUFQRFUiLCJKU0lNU2xvdC5pbnNlcnRDYXJkIiwiSlNJTVNsb3QuZWplY3RDYXJkIiwiaGV4MiIsImhleDQiLCJNRU1GTEFHUyIsIlNlZ21lbnQiLCJTZWdtZW50LmNvbnN0cnVjdG9yIiwiU2VnbWVudC5nZXRUeXBlIiwiU2VnbWVudC5nZXRMZW5ndGgiLCJTZWdtZW50LmdldEZsYWdzIiwiU2VnbWVudC5nZXREZWJ1ZyIsIlNlZ21lbnQuYmVnaW5UcmFuc2FjdGlvbiIsIlNlZ21lbnQuZW5kVHJhbnNhY3Rpb24iLCJTZWdtZW50LnJlYWRCeXRlIiwiU2VnbWVudC56ZXJvQnl0ZXMiLCJTZWdtZW50LnJlYWRCeXRlcyIsIlNlZ21lbnQuY29weUJ5dGVzIiwiU2VnbWVudC53cml0ZUJ5dGVzIiwiU2VnbWVudC5uZXdBY2Nlc3NvciIsIkFjY2Vzc29yIiwiQWNjZXNzb3IuY29uc3RydWN0b3IiLCJBY2Nlc3Nvci50cmFjZU1lbW9yeU9wIiwiQWNjZXNzb3IudHJhY2VNZW1vcnlWYWx1ZSIsIkFjY2Vzc29yLnplcm9CeXRlcyIsIkFjY2Vzc29yLnJlYWRCeXRlIiwiQWNjZXNzb3IucmVhZEJ5dGVzIiwiQWNjZXNzb3IuY29weUJ5dGVzIiwiQWNjZXNzb3Iud3JpdGVCeXRlIiwiQWNjZXNzb3Iud3JpdGVCeXRlcyIsIkFjY2Vzc29yLmdldFR5cGUiLCJBY2Nlc3Nvci5nZXRMZW5ndGgiLCJBY2Nlc3Nvci5nZXRJRCIsIkFjY2Vzc29yLmdldERlYnVnIiwic2xpY2VEYXRhIiwiTWVtb3J5TWFuYWdlciIsIk1lbW9yeU1hbmFnZXIuY29uc3RydWN0b3IiLCJNZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQiLCJNZW1vcnlNYW5hZ2VyLmdldE1lbVRyYWNlIiwiTWVtb3J5TWFuYWdlci5pbml0TWVtVHJhY2UiLCJNZW1vcnlNYW5hZ2VyLmdldFNlZ21lbnQiLCJNRUxJTlNUIiwiTUVMVEFHQUREUiIsIk1FTFRBR0NPTkQiLCJNRUxUQUdTWVNURU0iLCJNRUxUQUdTVEFDSyIsIk1FTFRBR1BSSU1SRVQiLCJNRUxQQVJBTURFRiIsIk1FTFBBUkFNNCIsIk9QVEFHMk1FTElOU1QiLCJNRUwyT1BDT0RFIiwiTUVMMklOU1QiLCJNRUwyVEFHIiwiTUVMUEFSQU1TSVpFIiwiTUVMIiwic2V0TWVsRGVjb2RlIiwic2V0TWVsRGVjb2RlU3RkTW9kZXMiLCJzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyIsImZpbGxNZWxEZWNvZGUiLCJoZXgiLCJsanVzdCIsInJqdXN0IiwiQkEyVyIsIlcyQkEiLCJNRUxWaXJ0dWFsTWFjaGluZSIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0cnVjdG9yIiwiTUVMVmlydHVhbE1hY2hpbmUuaW5pdE1WTSIsIk1FTFZpcnR1YWxNYWNoaW5lLmRpc2Fzc2VtYmxlQ29kZSIsIk1FTFZpcnR1YWxNYWNoaW5lLmRpc2Fzc2VtYmxlQ29kZS5wcmludCIsIk1FTFZpcnR1YWxNYWNoaW5lLm1hcFRvU2VnbWVudEFkZHIiLCJNRUxWaXJ0dWFsTWFjaGluZS5tYXBGcm9tU2VnbWVudEFkZHIiLCJNRUxWaXJ0dWFsTWFjaGluZS5jaGVja0RhdGFBY2Nlc3MiLCJNRUxWaXJ0dWFsTWFjaGluZS5yZWFkU2VnbWVudERhdGEiLCJNRUxWaXJ0dWFsTWFjaGluZS53cml0ZVNlZ21lbnREYXRhIiwiTUVMVmlydHVhbE1hY2hpbmUucHVzaFplcm9zVG9TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2hDb25zdFRvU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5jb3B5T25TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2hUb1N0YWNrIiwiTUVMVmlydHVhbE1hY2hpbmUucG9wRnJvbVN0YWNrQW5kU3RvcmUiLCJNRUxWaXJ0dWFsTWFjaGluZS5wb3BGcm9tU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5zZXR1cEFwcGxpY2F0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuaW5pdEV4ZWN1dGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0Qnl0ZUJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0V29yZEJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLnVuYXJ5T3BlcmF0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuaGFuZGxlUmV0dXJuIiwiTUVMVmlydHVhbE1hY2hpbmUuaXNDb25kaXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS5leGVjdXRlU3RlcCIsIk1FTFZpcnR1YWxNYWNoaW5lLnNldENvbW1hbmRBUERVIiwiTUVMVmlydHVhbE1hY2hpbmUuZ2V0UmVzcG9uc2VBUERVIiwiTUVMVmlydHVhbE1hY2hpbmUuZ2V0RGVidWciLCJKU0lNTXVsdG9zQXBwbGV0IiwiSlNJTU11bHRvc0FwcGxldC5jb25zdHJ1Y3RvciIsIkpTSU1NdWx0b3NDYXJkIiwiSlNJTU11bHRvc0NhcmQuY29uc3RydWN0b3IiLCJKU0lNTXVsdG9zQ2FyZC5sb2FkQXBwbGljYXRpb24iLCJKU0lNTXVsdG9zQ2FyZC5pc1Bvd2VyZWQiLCJKU0lNTXVsdG9zQ2FyZC5wb3dlck9uIiwiSlNJTU11bHRvc0NhcmQucG93ZXJPZmYiLCJKU0lNTXVsdG9zQ2FyZC5yZXNldCIsIkpTSU1NdWx0b3NDYXJkLmV4Y2hhbmdlQVBEVSIsIkpTSU1NdWx0b3NDYXJkLmluaXRpYWxpemVWTSIsIkpTSU1NdWx0b3NDYXJkLnJlc2V0Vk0iLCJKU0lNTXVsdG9zQ2FyZC5zaHV0ZG93blZNIiwiSlNJTU11bHRvc0NhcmQuc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNTXVsdG9zQ2FyZC5leGVjdXRlU3RlcCIsImJpdE1hbmlwdWxhdGUiLCJjYWxsUHJpbWl0aXZlIiwiU2VjdXJpdHlNYW5hZ2VyIiwiU2VjdXJpdHlNYW5hZ2VyLmluaXRTZWN1cml0eSIsIlNlY3VyaXR5TWFuYWdlci5wcm9jZXNzQVBEVSIsIkFEQyIsIkFMQyIsIkFMVSIsIkFMVS5jb25zdHJ1Y3RvciIsIkFMVS50b0pTT04iLCJBTFUuZ2V0QUxVU2VnbWVudCIsIkFMVS5kZWNvZGVCeXRlcyIsIkFMVS5lbmNvZGVCeXRlcyJdLCJtYXBwaW5ncyI6IkFBRUE7SUFNRUE7UUFFRUMsSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDZkEsSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDaEJBLElBQUlBLENBQUNBLGVBQWVBLEdBQUdBLEVBQUVBLENBQUNBO0lBQzVCQSxDQUFDQTtJQUVERCxPQUFPQSxDQUFFQSxPQUFlQTtRQUV0QkUsSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsT0FBT0EsQ0FBQ0E7SUFDdkJBLENBQUNBO0lBRURGLE9BQU9BO1FBRUxHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBO0lBQ3BCQSxDQUFDQTtJQUVESCxPQUFPQSxDQUFFQSxJQUFZQTtRQUVuQkksSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7SUFDcEJBLENBQUNBO0lBRURKLE9BQU9BO1FBRUxLLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBO0lBQ3BCQSxDQUFDQTtJQUVETCxZQUFZQSxDQUFFQSxJQUFZQSxFQUFFQSxLQUFpQkE7UUFFM0NNLElBQUlBLENBQUNBLGVBQWVBLENBQUVBLElBQUlBLENBQUVBLEdBQUdBLEtBQUtBLENBQUNBO0lBQ3ZDQSxDQUFDQTtJQUVETixZQUFZQSxDQUFFQSxJQUFZQTtRQUV4Qk8sTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0FBZ0JIUCxDQUFDQTtBQWJRLFVBQU0sR0FBRyxDQUFDLENBQUM7QUFDWCxXQUFPLEdBQUcsQ0FBQyxDQUFDO0FBQ1osVUFBTSxHQUFHLENBQUMsQ0FBQztBQUVYLE9BQUcsR0FBRyxDQUFDLENBQUM7QUFDUixPQUFHLEdBQUcsQ0FBQyxDQUFDO0FBQ1IsV0FBTyxHQUFHLENBQUMsQ0FBQztBQUNaLFlBQVEsR0FBRyxDQUFDLENBQUM7QUFDYixTQUFLLEdBQUcsQ0FBQyxDQUFDO0FBQ1YsU0FBSyxHQUFHLENBQUMsQ0FBQztBQUNWLFdBQU8sR0FBRyxDQUFDLENBQUM7QUFDWixXQUFPLEdBQUcsQ0FBQyxDQUFDO0FBQ1osVUFBTSxHQUFHLENBQUMsQ0FDbEI7O09DM0RNLEVBQUUsU0FBUyxFQUFFLE1BQU0sd0JBQXdCO09BQzNDLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZTtPQUVuQyxFQUFFLEdBQUcsRUFBRSxNQUFNLE9BQU87QUFFM0I7SUFFRVE7SUFFQUMsQ0FBQ0E7SUFFREQsT0FBT0EsQ0FBRUEsR0FBUUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBZ0JBO1FBRXZDRSxJQUFJQSxDQUFDQSxHQUFjQSxHQUFHQSxDQUFDQSxZQUFZQSxDQUFFQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQSxTQUFTQSxDQUFDQTtRQUU1REEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBR0EsQ0FBQ0EsQ0FDckJBLENBQUNBO1lBQ0NBLElBQUlBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBO1lBRWJBLENBQUNBLEdBQUdBLElBQUlBLFNBQVNBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1lBRXhDQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtZQUN4QkEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDMUNBLENBQUNBO1FBRURBLElBQUlBLFVBQVVBLEdBQUdBLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBLENBQUNBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLFlBQVlBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO1FBRWhHQSxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFREYsT0FBT0EsQ0FBRUEsR0FBR0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUE7UUFFdEJHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRURILElBQUlBLENBQUVBLEdBQVFBLEVBQUVBLElBQUlBLEVBQUVBLElBQWdCQSxFQUFFQSxFQUFHQTtRQUV6Q0ksSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFFakRBLElBQUlBLE9BQU9BLEdBQUdBLENBQUNBLENBQUNBO1FBRWhCQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFHQSxDQUFDQSxDQUNyQkEsQ0FBQ0E7WUFDQ0EsT0FBT0EsR0FBR0EsSUFBSUEsU0FBU0EsRUFBRUEsQ0FBQ0E7WUFFMUJBLE9BQU9BO2lCQUNKQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQTtpQkFDZkEsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUE7aUJBQ2xCQSxVQUFVQSxDQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUN6Q0EsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsSUFBSUEsU0FBVUEsQ0FBQ0E7WUFDcEJBLEVBQUVBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUVBLENBQUVBLENBQUNBO1FBSTVFQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFFQSxPQUFPQSxDQUFDQSxZQUFZQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxZQUFZQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUU3R0EsTUFBTUEsQ0FBQ0EsSUFBSUEsVUFBVUEsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7SUFDbERBLENBQUNBO0lBS09KLEdBQUdBLENBQUVBLEdBQWVBLEVBQUVBLE9BQW1CQSxFQUFFQSxPQUFlQSxFQUFFQSxJQUFZQSxFQUFFQSxFQUFlQSxFQUFFQSxPQUFnQkE7UUFLakhLLHdCQUF5QkEsR0FBR0E7WUFFMUJDLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLENBQUNBLEtBQUtBLElBQUlBLFNBQVVBLENBQUNBLENBQ2hDQSxDQUFDQTtnQkFFQ0EsTUFBTUEsQ0FBQ0EsS0FBS0EsR0FBR0E7b0JBQ2JBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUVBLENBQUVBO29CQUM1S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3ZLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDckpBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUM5S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsSUFBSUEsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsSUFBSUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsQ0FBQ0EsQ0FBRUE7b0JBQzNJQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxJQUFJQSxFQUFDQSxLQUFLQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxJQUFJQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdkpBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLEdBQUdBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLEdBQUdBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUNyS0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQ2pMQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxHQUFHQSxFQUFDQSxPQUFPQSxFQUFDQSxHQUFHQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDN0pBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLEdBQUdBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLEdBQUdBLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUM3SkEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7b0JBQ25KQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDbkxBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE1BQU1BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLElBQUlBLEVBQUNBLE1BQU1BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN0S0EsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsQ0FBQ0EsQ0FBRUE7aUJBQzlHQSxDQUFDQTtZQUNKQSxDQUFDQTtZQUdEQSxJQUFJQSxVQUFVQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUV4Q0EsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsV0FBV0EsQ0FBQ0EsRUFBRUEsR0FBR0EsVUFBVUEsQ0FBQ0EsQ0FBQ0E7WUFFNUNBLElBQUlBLE1BQU1BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBRWhFQSxJQUFJQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQTtZQUV4Q0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsVUFBVUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFDL0JBLENBQUNBO2dCQUNDQSxJQUFJQSxHQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDekVBLEtBQUtBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUV6RUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ25GQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDbkZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFHL0VBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBLENBQUNBO2dCQUVuREEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3RHQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtnQkFHYkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsTUFBTUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFDcENBLENBQUNBO29CQUVDQSxFQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTt3QkFDQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBQUNBLEtBQUtBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO29CQUM1RUEsQ0FBQ0E7b0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO3dCQUNDQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTt3QkFBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7b0JBQzVFQSxDQUFDQTtvQkFDREEsSUFBSUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBO29CQU01QkEsUUFBUUEsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ2pGQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDekZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUN4RkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ3REQSxTQUFTQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDbkZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUM1RkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzVGQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtvQkFDekRBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLFNBQVNBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO29CQUNwREEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQUNBLElBQUlBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLFNBQVNBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNwRUEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFFREEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFDZEEsQ0FBQ0E7UUFHREQsRUFBRUEsQ0FBQ0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsS0FBS0EsSUFBSUEsU0FBVUEsQ0FBQ0EsQ0FDaENBLENBQUNBO1lBQ0NBLE1BQU1BLENBQUNBLEtBQUtBLEdBQUdBO2dCQUNiQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxHQUFHQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtnQkFDemlCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDcm9CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxDQUFDQSxDQUFFQTtnQkFDemlCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxHQUFHQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDamZBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLFNBQVNBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO2dCQUNqb0JBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLE1BQU1BLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO2dCQUNybUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUN6akJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO2FBQ3RsQkEsQ0FBQ0E7UUFDSkEsQ0FBQ0E7UUFHREEsSUFBSUEsSUFBSUEsR0FBR0EsY0FBY0EsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFakNBLElBQUlBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLEtBQUtBLEVBQUVBLE9BQU9BLENBQUNBO1FBQzFDQSxJQUFJQSxPQUFPQSxFQUFFQSxRQUFRQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxDQUFBQTtRQUMxQ0EsSUFBSUEsR0FBR0EsR0FBR0EsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7UUFHekJBLElBQUlBLFVBQVVBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLElBQUlBLEVBQUVBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBRTNDQSxFQUFFQSxDQUFDQSxDQUFDQSxVQUFVQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNwQkEsQ0FBQ0E7WUFDQ0EsT0FBT0EsR0FBR0EsT0FBT0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDcERBLENBQUNBO1FBQ0RBLElBQUlBLENBQ0pBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLE9BQU9BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO1FBQ2xHQSxDQUFDQTtRQUdEQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxPQUFPQSxJQUFJQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFFQSxPQUFPQSxJQUFJQSxDQUFDQSxDQUFHQSxDQUFDQSxDQUNuREEsQ0FBQ0E7WUFDQ0EsSUFBSUEsZUFBZUEsR0FBR0EsT0FBT0EsQ0FBQ0E7WUFDOUJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUNBLENBQUNBLEdBQUdBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBRXBCQSxPQUFPQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUNwQ0EsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsZUFBZUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFbENBLE1BQU1BLENBQUFBLENBQUVBLE9BQVFBLENBQUNBLENBQ2pCQSxDQUFDQTtnQkFDQ0EsS0FBS0EsQ0FBQ0E7b0JBQ0pBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUVBLENBQUVBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO29CQUN6RkEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLENBQUNBO29CQUNOQSxDQUFDQTt3QkFDQ0EsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsR0FBR0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7d0JBRTlFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFFQSxDQUFFQSxDQUFDQTs0QkFDWEEsR0FBR0EsSUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBRVRBLEtBQUtBLENBQUNBO29CQUNSQSxDQUFDQTtnQkFFREEsS0FBS0EsQ0FBQ0E7b0JBQ0pBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUVBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO29CQUN2RkEsS0FBS0EsQ0FBQ0E7WUFFVkEsQ0FBQ0E7WUFFREEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQUE7UUFDbEJBLENBQUNBO1FBR0RBLElBQUlBLE1BQU1BLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRW5DQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUVWQSxPQUFPQSxHQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUN4RUEsUUFBUUEsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7UUFDMUVBLENBQUNBO1FBRURBLElBQUlBLEVBQUVBLEdBQUdBLENBQUNBLENBQUNBO1FBR1hBLE9BQU9BLENBQUNBLEdBQUdBLEdBQUdBLEVBQ2RBLENBQUNBO1lBQ0NBLElBQUlBLEdBQUlBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBQ3pGQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUd6RkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7Z0JBQ0NBLEVBQUVBLENBQUNBLENBQUNBLE9BQU9BLENBQUNBLENBQ1pBLENBQUNBO29CQUNDQSxJQUFJQSxJQUFJQSxPQUFPQSxDQUFDQTtvQkFBQ0EsS0FBS0EsSUFBSUEsUUFBUUEsQ0FBQ0E7Z0JBQ3JDQSxDQUFDQTtnQkFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7b0JBQ0NBLFFBQVFBLEdBQUdBLE9BQU9BLENBQUNBO29CQUNuQkEsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7b0JBQ3JCQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDZkEsUUFBUUEsR0FBR0EsS0FBS0EsQ0FBQ0E7Z0JBQ25CQSxDQUFDQTtZQUNIQSxDQUFDQTtZQUdEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDakZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFFL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBQ3JDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUd4Q0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsVUFBVUEsRUFBRUEsQ0FBQ0EsSUFBRUEsQ0FBQ0EsRUFDNUJBLENBQUNBO2dCQUNDQSxJQUFJQSxPQUFPQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDM0JBLElBQUlBLE9BQU9BLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUczQkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBRUEsT0FBT0EsRUFBRUEsQ0FBQ0EsSUFBRUEsT0FBT0EsRUFDekNBLENBQUNBO29CQUNDQSxJQUFJQSxNQUFNQSxHQUFHQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFDN0JBLElBQUlBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUd6REEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ1pBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBO29CQUNiQSxLQUFLQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDbkdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQU1BLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBOzBCQUMxRkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQ25HQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDOUdBLENBQUNBO2dCQUVEQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0E7Z0JBQUNBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBO1lBQzFDQSxDQUFDQTtZQUdEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNyQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHeENBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQ2pGQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUcvRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7Z0JBQ0NBLEVBQUVBLENBQUNBLENBQUNBLE9BQU9BLENBQUNBLENBQ1pBLENBQUNBO29CQUNDQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDZkEsUUFBUUEsR0FBR0EsS0FBS0EsQ0FBQ0E7Z0JBQ25CQSxDQUFDQTtnQkFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7b0JBQ0NBLElBQUlBLElBQUlBLFFBQVFBLENBQUNBO29CQUNqQkEsS0FBS0EsSUFBSUEsU0FBU0EsQ0FBQ0E7Z0JBQ3JCQSxDQUFDQTtZQUNIQSxDQUFDQTtZQUVEQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFHQSxDQUFFQSxDQUFDQSxJQUFJQSxLQUFHQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxJQUFJQSxLQUFHQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxJQUFJQSxLQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxLQUFLQSxLQUFHQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxLQUFLQSxLQUFHQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxLQUFLQSxLQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxDQUFDQSxLQUFLQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxFQUFFQSxDQUFFQSxDQUFD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RUEsU0FBU0EsRUFBRUEsQ0FBQ0EsRUFBRUEsV0FBV0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7UUFDN0VBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO1FBQ1pBLElBQUlBLEtBQUtBLEdBQUdBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBO1FBRWhDQSxNQUFNQSxDQUFBQSxDQUFFQSxRQUFTQSxDQUFDQSxDQUNsQkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsT0FBT0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsR0FBR0E7Z0JBQzFCQSxDQUFDQTtvQkFDQ0EsT0FBT0EsQ0FBRUEsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsS0FBS0EsQ0FBRUEsR0FBR0EsQ0FBRUEsSUFBSUEsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBRUEsS0FBS0EsQ0FBRUEsR0FBR0EsQ0FBRUEsSUFBSUEsSUFBSUEsQ0FBRUEsQ0FBRUE7d0JBQ3ZGQSxFQUFFQSxHQUFHQSxDQUFDQTtvQkFFUkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsS0FBS0EsQ0FBQ0EsTUFBT0EsQ0FBQ0E7d0JBQ3hCQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFFYkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsS0FBS0EsQ0FBRUEsR0FBR0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsSUFBS0EsQ0FBQ0EsQ0FDdENBLENBQUNBO3dCQUNDQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxDQUFDQTt3QkFDOUJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBLENBQzFCQSxDQUFDQTs0QkFBZ0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO3dCQUFDQSxDQUFDQTtvQkFDakNBLENBQUNBO29CQUVEQSxHQUFHQSxDQUFDQSxHQUFHQSxJQUFJQSxLQUFLQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFFQSxDQUFDQTtvQkFFMUJBLEdBQUdBLENBQUNBLFNBQVNBLEdBQUdBLEdBQUdBLENBQUNBO29CQUVwQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsS0FBS0EsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDMUJBLENBQUNBO3dCQUFnQkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7b0JBQUNBLENBQUNBO29CQUUvQkEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsS0FBS0EsQ0FBRUEsR0FBR0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsR0FBR0EsQ0FBRUEsS0FBS0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ2pFQSxPQUFPQSxFQUFFQSxFQUFFQSxHQUFHQSxDQUFDQSxFQUNmQSxDQUFDQTt3QkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsS0FBS0EsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDMUJBLENBQUNBOzRCQUE0Q0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7d0JBQUNBLENBQUNBO3dCQUUzREEsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsS0FBS0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBRUEsQ0FBQ0E7b0JBQzlDQSxDQUFDQTtvQkFFREEsR0FBR0EsQ0FBQ0EsV0FBV0EsR0FBR0EsR0FBR0EsQ0FBQ0E7b0JBQ3RCQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUNyQ0EsQ0FBQ0E7d0JBQWdCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtvQkFBQ0EsQ0FBQ0E7b0JBQzdCQSxHQUFHQSxDQUFDQSxLQUFLQSxHQUFHQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFDQSxXQUFXQSxFQUFFQSxHQUFHQSxDQUFDQSxXQUFXQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFFQSxDQUFDQTtvQkFHdEVBLEtBQUtBLENBQUNBO2dCQUNSQSxDQUFDQTtRQUNIQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUNiQSxDQUFDQTtJQXVDREYsSUFBSUEsR0FBR0E7UUFFTEcsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDL0RBLENBQUNBO0lBRURILElBQUlBLEtBQUtBO1FBRVBJLE1BQU1BLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFFBQVFBLENBQUVBLENBQUNBLEtBQUtBLENBQUNBO0lBQ2pFQSxDQUFDQTtJQUVESixJQUFJQSxHQUFHQTtRQUVMSyxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUMvREEsQ0FBQ0E7QUFDSEwsQ0FBQ0E7QUE1R2UsaUJBQVMsR0FBRztJQUN4QixHQUFHLEVBQUUsQ0FBQztJQUNOLEdBQUcsRUFBRSxDQUFDO0NBQ1AsQ0F5R0Y7QUFFRCxPQUFPLENBQUMsU0FBUyxDQUFFLEtBQUssQ0FBRSxHQUFHLENBQUMsQ0FBQztPQ2xIeEIsRUFBRSxPQUFPLElBQUksT0FBTyxFQUFFLE1BQU0scUJBQXFCO09BQ2pELEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZTtBQUcxQztJQUtFTSxZQUFjQSxHQUFXQSxFQUFFQSxLQUFpQkEsRUFBRUEsUUFBZ0JBO1FBRTVEQyxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxLQUFLQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQTtRQUV6REEsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsUUFBUUEsQ0FBQ0E7SUFDM0JBLENBQUNBO0lBRURELE1BQU1BO1FBRUpFLE1BQU1BLENBQUNBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO0lBQzlDQSxDQUFDQTtJQUVERixNQUFNQTtRQUVKRyxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUN0QkEsQ0FBQ0E7SUFFREgsUUFBUUE7UUFFTkksTUFBTUEsQ0FBQ0EsSUFBSUEsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBRUEsQ0FBQ0E7SUFDMUNBLENBQUNBO0lBRURKLElBQUlBO1FBRUZLLElBQUlBLElBQUlBLEdBQUdBLE9BQU9BLENBQUNBLFFBQVFBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFFBQVFBLENBQUVBLENBQUNBO1FBRWpFQSxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQTtJQUN6RkEsQ0FBQ0E7SUFFREwsS0FBS0E7UUFFSE0sSUFBSUEsSUFBSUEsR0FBR0EsT0FBT0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0E7UUFFakVBLE1BQU1BLENBQUNBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFdB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QSxDQUFDQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN4RU4sTUFBTUEsQ0FBRUEsR0FBV0EsSUFBdUJPLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQ3hFUCxLQUFLQSxDQUFFQSxFQUFVQSxJQUF5QlEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDdEVSLEtBQUtBLENBQUVBLEVBQVVBLElBQXlCUyxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN0RVQsT0FBT0EsQ0FBRUEsSUFBZUEsSUFBa0JVLElBQUlBLENBQUNBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQzFFVixLQUFLQSxDQUFFQSxFQUFVQSxJQUF5QlcsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLdEVYLE1BQU1BO1FBRVhZLE1BQU1BLENBQUNBO1lBQ0xBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ2JBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ2JBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1lBQ1hBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1lBQ1hBLElBQUlBLEVBQUVBLElBQUlBLENBQUNBLElBQUlBO1lBQ2ZBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ1pBLENBQUNBO0lBQ0pBLENBQUNBO0lBS01a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Q0FBQ0E7SUFDdkVMLE1BQU1BLENBQUVBLEdBQVdBLElBQXdCTSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN0R04sTUFBTUEsQ0FBRUEsR0FBV0EsSUFBd0JPLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLE1BQU1BLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQy9GUCxPQUFPQSxDQUFFQSxJQUFlQSxJQUFtQlEsSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLM0VSLFdBQVdBLENBQUVBLE9BQVlBO1FBRTlCUyxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVsREEsRUFBRUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFDOUJBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEVBQU1BLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO1FBQ3JEQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxD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QU1BLENBQUNBLElBQUlBLENBQUNBLE9BQU9BLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO0lBQzFDQSxDQUFDQTtJQUVEVixTQUFTQSxDQUFFQSxRQUFRQSxFQUFFQSxNQUFNQSxFQUFFQSxHQUFHQTtRQUU5QlcsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsUUFBUUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDN0RBLENBQUNBO0lBRURYLFVBQVVBLENBQUVBLElBQVlBLEVBQUVBLEdBQWNBO1FBRXRDWSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxhQUFhQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQSxRQUFRQSxDQUFDQSxlQUFlQSxDQUFHQSxDQUFDQSxDQUN0RUEsQ0FBQ0E7WUFFQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsSUFBSUEsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDcEZBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLE9BQU9BLENBQUNBLFVBQVVBLENBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO0lBQ3ZDQSxDQUFDQTtJQUVEWixXQUFXQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQTtRQUUxQmEsTUFBTUEsQ0FBQ0EsSUFBSUEsUUFBUUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDL0NBLENBQUNBO0FBQ0hiLENBQUNBO0FBRUQ7SUFPRWMsWUFBYUEsR0FBR0EsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUE7UUFFL0JD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QUNBLENBQUNBO1FBRWhDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUNiQSxDQUFDQTtJQUVETCxTQUFTQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQTtRQUVsQk0sRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDL0JBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQzVDQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxrQkFBa0JBLENBQUVBLENBQUNBO1FBQ3hDQSxDQUFDQTtRQUVEQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN0Q0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDeERBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFN0JBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRUROLFNBQVNBLENBQUVBLFFBQWdCQSxFQUFFQSxNQUFjQSxFQUFFQSxHQUFXQTtRQUV0RE8sRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsUUFBUUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBR0EsQ0FBQ0EsQ0FDekVBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO1lBQ3hEQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxrQkFBa0JBLENBQUVBLENBQUNBO1FBQ3hDQSxDQUFDQTtRQUdEQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtZQUNsREEsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsUUFBUUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7WUFDNURBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDL0JBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBQ3hFQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUNiQSxDQUFDQTtJQUVEUCxTQUFTQSxDQUFFQSxJQUFZQSxFQUFFQSxHQUFXQTtRQUVsQ1EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDN0JBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLElBQUlBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBQzFDQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxtQkFBbUJBLENBQUVBLENBQUNBO1FBQ3pDQSxDQUFDQTtRQUVEQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEs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QTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBRTlGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBRXRIQSxvQkFBb0JBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUdBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFFekZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBRTlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFFBQVFBLEVBQUVBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBR0EsT0FBT0EsRUFBR0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE1BQU1BLEVBQUtBLEtBQUtBLEVBQUtBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUU5RkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7SUFDckZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGNBQWNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDL0hBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGNBQWNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDL0hBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsRUFBRUEsU0FBU0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ3pLQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUN2RkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUNqSUEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUNoSUEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsaUJBQWlCQSxDQUFFQSxFQUFFQSxVQUFVQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFHM0tBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFFekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFdBQVdBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLGVBQWVBLENBQUVBLENBQUNBO0lBQzVHQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBRXRIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxXQUFXQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQTtJQUM1R0EsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUV0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUMxSEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM1SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUU1SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUN4SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDcEZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFdBQVdBLENBQUNBLFlBQVlBLENBQUVBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO0lBR3BGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ2pJQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDdktBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFVBQVVBLEVBQUVBLGFBQWFBLENBQUNBLGVBQWVBLENBQUVBLEVBQUVBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzdNQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FB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QSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFBQ0EsS0FBS0EsQ0FBQ0E7b0JBQ2hJQSxDQUFDQTtvQkFDREEsVUFBVUEsRUFBRUEsQ0FBQ0E7b0JBQ2JBLFNBQVNBLEtBQUtBLENBQUNBLENBQUNBO2dCQUNsQkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLEdBQUdBLGFBQWFBLEdBQUdBLEtBQUtBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dCQUVyRkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBRUE7dUJBQ2xCQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBOzJCQUMzREEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQTsyQkFDN0RBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLElBQUlBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBRUE7dUJBQ2pFQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBO3VCQUM3REEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFHQSxDQUFDQSxDQUNsRUEsQ0FBQ0E7b0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUFDQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQzVFQSxJQUFJQSxPQUFPQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQUNBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBO2dCQUM5RUEsQ0FBQ0E7Z0JBRURBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLFVBQVVBLEdBQUdBLENBQUNBLEVBQUVBLFVBQVVBLEdBQUdBLFVBQVVBLEVBQUVBLEVBQUVBLFVBQVVBLEVBQzlEQSxDQUFDQTtvQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7b0JBQy9CQSxJQUFJQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtvQkFFL0JBLE1BQU1BLENBQUFBLENBQUVBLENBQUVBLENBQUNBLENBQ1hBLENBQUNBO3dCQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBOzRCQUN6Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBQ0E7Z0NBQ1ZBLEtBQUtBLENBQUVBLElBQUlBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUMzQkEsSUFBSUE7Z0NBQ0ZBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBOzRCQUNiQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQTs0QkFDM0NBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO2dDQUNWQSxLQUFLQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDM0JBLElBQUlBO2dDQUNGQSxLQUFLQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTs0QkFDYkEsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkE7NEJBQzNDQSxLQUFLQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDekJBLEtBQUtBLENBQUNBO3dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSwwQkFBMEJBOzRCQUM3Q0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ25CQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsMkJBQTJCQTs0QkFDOUNBLEtBQUtBLENBQUVBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUN4Q0EsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkE7NEJBQzVDQSxDQUFDQTtnQ0FDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0NBQzNEQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFFQSxDQUFDQTtnQ0FDekJBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO29DQUNWQSxLQUFLQSxDQUFFQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDbENBLElBQUlBO29DQUNGQSxLQUFLQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDekJBLEtBQUtBLENBQUNBOzRCQUNSQSxDQUFDQTtvQkFDSEEsQ0FBQ0E7b0JBRURBLEVBQUVBLENBQUNBLENBQUVBLFVBQVVBLEdBQUdBLFVBQVVBLEdBQUdBLENBQUVBLENBQUNBO3dCQUNoQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xCQSxDQUFDQTtnQkFDREEsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDaEJBLENBQUNBO1lBRURBLEVBQUVBLENBQUNBLENBQUVBLFlBQWFBLENBQUNBO2dCQUNqQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFDNUJBLENBQ0FBO1FBQUFBLEtBQUtBLENBQUFBLENBQUVBLENBQUVBLENBQUNBLENBQ1ZBLENBQUNBO1lBQ0NBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2JBLENBQUNBO1FBQUFBLENBQUNBO1FBR0ZBLE1BQU1BLENBQUNBLFFBQVFBLENBQUNBO0lBQ2xCQSxDQUFDQTtJQVFPSCxnQkFBZ0JBLENBQUVBLE9BQU9BLEVBQUVBLFVBQVVBO1FBRTNDSyxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVsRUEsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO1lBQ0NBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUNBO1lBQy9CQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM5QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDOUJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsR0FBR0EsWUFBWUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7WUFFMUNBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUNBO1lBQzlCQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLFVBQVVBLENBQUNBO1lBRWpDQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM5QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxNQUFNQSxHQUFHQSxZQUFZQSxDQUFDQSxVQUFVQSxDQUFDQTtRQUM1Q0EsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFT0wsa0JBQWtCQSxDQUFFQSxXQUFXQTtRQUVyQ00sRUFBRUEsQ0FBQ0EsQ0FBRUEsV0FBV0EsR0FBR0EsTUFBT0EsQ0FBQ0EsQ0FDM0JBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFdBQVdBLElBQUlBLE1BQU9BLENBQUNBLENBQzVCQSxDQUFDQTtnQkFDQ0EsTUFBTUEsQ0FBQ0E7b0JBQ0xBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO29CQUN6QkEsV0FBV0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7b0JBQ3JDQSxVQUFVQSxFQUFFQSxXQUFXQSxHQUFHQSxNQUFNQTtpQkFDakNBLENBQUNBO1lBQ0pBLENBQUNBO1lBQ0RBLElBQUlBLENBQ0pBLENBQUNBO2dCQUNDQSxNQUFNQSxDQUFDQTtvQkFDTEEsUUFBUUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0E7b0JBQzFCQSxXQUFXQSxFQUFFQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtvQkFDckNBLFVBQVVBLEVBQUVBLFdBQVdBLEdBQUdBLE1BQU1BO2lCQUNqQ0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ0xBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO2dCQUN6QkEsV0FBV0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQ3JDQSxVQUFVQSxFQUFFQSxXQUFXQSxHQUFHQSxNQUFNQTthQUNqQ0EsQ0FBQ0E7UUFDSkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFRT04sZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsTUFBTUE7UUFFOUNPLElBQUlBLFFBQVFBLENBQUNBO1FBQ2JBLElBQUlBLFVBQVVBLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3hCQSxJQUFJQSxTQUFTQSxDQUFDQTtRQUVkQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUE7Z0JBQzVCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQTtnQkFDNUJBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN6Q0EsVUFBVUEsSUFBSUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7Z0JBQzdCQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO2dCQUM1QkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3pDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO2dCQUM1QkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3pDQSxVQUFVQSxJQUFJQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQTtnQkFDN0JBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0E7Z0JBQzVCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDekNBLFVBQVVBLElBQUlBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUM5QkEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtnQkFDM0JBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN4Q0EsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtnQkFDM0JBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN4Q0EsVUFBVUEsSUFBSUEsU0FBU0EsQ0FBQ0E7Z0JBQ3hCQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUMzQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3hDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUMzQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3hDQSxVQUFVQSxJQUFJQSxTQUFTQSxDQUFDQTtnQkFDeEJBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLFVBQVVBLElBQUlBLE1BQU1BLENBQUNBO1FBQ3JCQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxVQUFVQSxHQUFHQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFFQSxVQUFVQSxHQUFHQSxNQUFNQSxHQUFHQSxTQUFTQSxDQUFHQSxDQUFDQSxDQUN4RUEsQ0FBQ0E7WUFDQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ0xBLFFBQVFBLEVBQUVBLFFBQVFBO2dCQUNsQkEsVUFBVUEsRUFBRUEsVUFBVUE7YUFDdkJBLENBQUNBO1FBQ0pBLENBQUNBO0lBQ0hBLENBQUNBO0lBTU9QLGVBQWVBLENBQUVBLE9BQU9BLEVBQUVBLE1BQU1BLEVBQUVBLE1BQU1BO1FBRTlDUSxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxNQUFNQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUM5REEsRUFBRUEsQ0FBQ0EsQ0FBRUEsWUFBWUEsSUFBSUEsU0FBVUEsQ0FBQ0E7WUFDOUJBLE1BQU1BLENBQUNBO1FBRVRBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBLFlBQVlBLENBQUNBLFVBQVVBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO0lBQzVFQSxDQUFDQTtJQU1PUixnQkFBZ0JBLENBQUVBLE9BQU9BLEVBQUVBLE1BQU1BLEVBQUVBLEdBQUdBO1FBRTVDUyxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxNQUFNQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUM5REEsRUFBRUEsQ0FBQ0EsQ0FBRUEsWUFBWUEsSUFBSUEsU0FBVUEsQ0FBQ0E7WUFDOUJBLE1BQU1BLENBQUNBO1FBRVRBLFlBQVlBLENBQUNBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLFlBQVlBLENBQUNBLFVBQVVBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO0lBQ25FQSxDQUFDQTtJQUVPVCxnQkFBZ0JBLENBQUVBLEdBQUdBO1FBRTNCVSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVuREEsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsR0FBR0EsQ0FBQ0E7SUFDekJBLENBQUNBO0lBRU9WLGdCQUFnQkEsQ0FBRUEsR0FBR0EsRUFBRUEsR0FBR0E7UUFFaENXLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO1lBQ2JBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFVBQVVBLENBQUVBLElBQUlBLENBQUNBLFVBQVVBLEVBQUVBLENBQUVBLEdBQUdBLENBQUVBLENBQUVBLENBQUNBO1FBQzFEQSxJQUFJQTtZQUNGQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUU5REEsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsR0FBR0EsQ0FBQ0E7SUFDekJBLENBQUNBO0lBRU9YLFdBQVdBLENBQUVBLFVBQVVBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBO1FBRTVDWSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxDQUFFQSxVQUFVQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtJQUMxREEsQ0FBQ0E7SUFFT1osV0FBV0EsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsR0FBR0E7UUFFdkNhLElBQUlBLENBQUNBLFVBQVVBLElBQUlBLEdBQUdBLENBQUNBO1FBQ3ZCQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxNQUFNQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFFQSxDQUFDQTtJQUMvRkEsQ0FBQ0E7SUFFT2Isb0JBQW9CQSxDQUFFQSxPQUFPQSxFQUFFQSxNQUFNQSxFQUFFQSxHQUFHQTtRQUVoRGMsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsR0FBR0EsQ0FBQ0E7UUFFdkJBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDL0ZBLENBQUNBO0lBRU9kLFlBQVlBLENBQUVBLEdBQUdBO1FBRXZCZSxJQUFJQSxDQUFDQSxVQUFVQSxJQUFJQSxHQUFHQSxDQUFDQTtRQUV2QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7SUFDNURBLENBQUNBO0lBR0RmLGdCQUFnQkEsQ0FBRUEsVUFBVUE7UUFFMUJnQixJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxVQUFVQSxDQUFDQSxRQUFRQSxDQUFDQTtRQUNwQ0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7UUFDeENBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFVBQVVBLENBQUNBLFdBQVdBLENBQUNBO1FBRTFDQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxXQUFXQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUU5REEsSUFBSUEsQ0FBQ0EsYUFBYUEsRUFBRUEsQ0FBQ0E7SUFDdkJBLENBQUNBO0lBRU9oQixhQUFhQTtRQUVuQmlCLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLENBQUNBO1FBQ25CQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUd4QkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0E7UUFDbENBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLENBQUNBLENBQUNBO0lBQzVCQSxDQUFDQTtJQUlPakIsd0JBQXdCQSxDQUFFQSxNQUFNQSxFQUFFQSxRQUFRQSxFQUFFQSxPQUFPQSxFQUFFQSxVQUFVQTtRQUVyRWtCLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGVBQWVBLENBQUVBLE9BQU9BLEVBQUVBLFVBQVVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2xFQSxFQUFFQSxDQUFDQSxDQUFFQSxZQUFZQSxJQUFJQSxTQUFVQSxDQUFDQTtZQUM5QkEsTUFBTUEsQ0FBQ0E7UUFFVEEsSUFBSUEsT0FBT0EsR0FBR0EsWUFBWUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsWUFBWUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0E7UUFFeEVBLE1BQU1BLENBQUFBLENBQUVBLE1BQU9BLENBQUNBLENBQ2hCQSxDQUFDQTtZQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQTtnQkFDdEJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBQ0EsU0FBU0EsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7Z0JBQzVEQSxPQUFPQSxHQUFHQSxDQUFFQSxPQUFPQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQTtnQkFDakNBLEVBQUVBLENBQUNBLENBQUVBLE9BQU9BLEdBQUdBLFFBQVNBLENBQUNBO29CQUN2QkEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxJQUFJQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFDQTtnQkFDekNBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO2dCQUN0QkEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxTQUFTQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtnQkFDNURBLE9BQU9BLEdBQUdBLENBQUVBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBO2dCQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsR0FBR0EsUUFBU0EsQ0FBQ0E7b0JBQ3ZCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLElBQUlBLEdBQUdBLENBQUNBLFNBQVNBLENBQUNBO2dCQUN6Q0EsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0E7Z0JBQ3RCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLENBQUNBLFNBQVNBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO2dCQUM1REEsT0FBT0EsR0FBR0EsQ0FBRUEsT0FBT0EsR0FBR0EsUUFBUUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2pDQSxFQUFFQSxDQUFDQSxDQUFFQSxPQUFPQSxHQUFHQSxRQUFTQSxDQUFDQTtvQkFDdkJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBQ0E7Z0JBQ3pDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQTtnQkFDdEJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBQ0EsU0FBU0EsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7Z0JBQzVEQSxPQUFPQSxHQUFHQSxRQUFRQSxDQUFDQTtnQkFDbkJBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUVBLE9BQU9BLElBQUlBLENBQUVBLENBQUNBO1lBQ2pCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLElBQUlBLEdBQUdBLENBQUNBLFNBQVNBLENBQUNBO1FBRXpDQSxFQUFFQSxDQUFDQSxDQUFFQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFRQSxDQUFDQSxDQUNwQ0EsQ0FBQ0E7WUFDQ0EsWUFBWUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsWUFBWUEsQ0FBQ0EsVUFBVUEsRUFBRUEsT0FBT0EsQ0FBRUEsQ0FBQ0E7UUFDdEVBLENBQUNBO0lBQ0hBLENBQUNBO0lBRU9sQix3QkFBd0JBLENBQUVBLE1BQU1BLEVBQUVBLFFBQVFBLEVBQUVBLE9BQU9BLEVBQUVBLFVBQVVBO1FBRXJFbUIsSUFBSUEsWUFBWUEsR0FBR0EsSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsVUFBVUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEVBLEVBQUVBLENBQUNBLENBQUVBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBO1lBQzlCQSxNQUFNQSxDQUFDQTtRQUVUQSxJQUFJQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFFQSxZQUFZQSxDQUFDQSxRQUFRQSxDQUFDQSxTQUFTQSxDQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUVwRkEsTUFBTUEsQ0FBQUEsQ0FBRUEsTUFBT0EsQ0FBQ0EsQ0FDaEJBLENBQUNBO1lBQ0NBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO2dCQUN0QkEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxTQUFTQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtnQkFDNURBLE9BQU9BLEdBQUdBLENBQUVBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBO2dCQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsR0FBR0EsUUFBU0EsQ0FBQ0E7b0JBQ3ZCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLElBQUlBLEdBQUdBLENBQUNBLFNBQVNBLENBQUNBO2dCQUN6Q0EsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0E7Z0JBQ3RCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLENBQUNBLFNBQVNBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO2dCQUM1REEsT0FBT0EsR0FBR0EsQ0FBRUEsT0FBT0EsR0FBR0EsUUFBUUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2pDQSxFQUFFQSxDQUFDQSxDQUFFQSxPQUFPQSxHQUFHQSxRQUFTQSxDQUFDQTtvQkFDdkJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBQ0E7Z0JBQ3pDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQTtnQkFDdEJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBQ0EsU0FBU0EsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7Z0JBQzVEQSxPQUFPQSxHQUFHQSxDQUFFQSxPQUFPQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQTtnQkFDakNBLEVBQUVBLENBQUNBLENBQUVBLE9BQU9BLEdBQUdBLFFBQVNBLENBQUNBO29CQUN2QkEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxJQUFJQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFDQTtnQkFDekNBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO2dCQUN0QkEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxTQUFTQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtnQkFDNURBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUNBO2dCQUNuQkEsS0FBS0EsQ0FBQ0E7UUFDVkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDakJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFFekNBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLElBQUlBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQVFBLENBQUNBLENBQ3BDQSxDQUFDQTtZQUNDQSxZQUFZQSxDQUFDQSxRQUFRQSxDQUFDQSxVQUFVQSxDQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFFQSxPQUFPQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUMvRUEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFT25CLGVBQWVBLENBQUVBLE1BQU1BLEVBQUVBLE1BQU1BLEVBQUVBLE9BQU9BLEVBQUVBLFVBQVVBO1FBRTFEb0IsSUFBSUEsWUFBWUEsR0FBR0EsSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsVUFBVUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEVBLEVBQUVBLENBQUNBLENBQUVBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBO1lBQzlCQSxNQUFNQSxDQUFDQTtRQUVUQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxFQUFFQSxNQUFNQSxFQUFFQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQTtJQUd6RUEsQ0FBQ0E7SUFFT3BCLGNBQWNBLENBQUVBLE1BQU1BLEVBQUVBLE1BQU1BLEVBQUVBLE9BQU9BLEVBQUVBLFVBQVVBO1FBRXpEcUIsSUFBSUEsWUFBWUEsR0FBR0EsSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsVUFBVUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEVBLEVBQUVBLENBQUNBLENBQUVBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBO1lBQzlCQSxNQUFNQSxDQUFDQTtRQUVUQSxNQUFNQSxDQUFBQSxDQUFFQSxNQUFPQSxDQUFDQSxDQUNoQkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsU0FBU0E7Z0JBQ3hCQSxZQUFZQSxDQUFDQSxRQUFRQSxDQUFDQSxTQUFTQSxDQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtnQkFDbkVBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBLENBQUNBO1lBQzFCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtZQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7WUFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO2dCQUN0QkEsQ0FBQ0E7UUFDTEEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFT3JCLFlBQVlBLENBQUVBLE9BQU9BLEVBQUVBLFFBQVFBO1FBRXJDc0IsSUFBSUEsWUFBWUEsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsUUFBUUEsQ0FBQ0E7UUFFOUNBLElBQUlBLFFBQVFBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO1FBQzNFQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUU3RUEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7UUFDNUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVNBLENBQUNBO1lBQ2JBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBO1FBRTdEQSxNQUFNQSxDQUFDQSxRQUFRQSxDQUFDQTtJQUNsQkEsQ0FBQ0E7SUFFT3RCLFdBQVdBLENBQUVBLEdBQUdBO1FBRXRCdUIsTUFBTUEsQ0FBQUEsQ0FBRUEsR0FBSUEsQ0FBQ0EsQ0FDYkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ25EQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ2pHQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDbkRBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ2hHQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBO2dCQUM1QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7WUFDZEEsUUFBUUE7UUFDVkEsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7SUFDZkEsQ0FBQ0E7SUFFRHZCLFdBQVdBO1FBRVR3QixJQUNBQSxDQUFDQTtZQUNDQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFD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QVdBLENBQUVBLEdBQUdBLENBQUdBLENBQUNBO3dCQUM1QkEsTUFBTUEsR0FBR0EsTUFBTUEsR0FBR0EsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ2xDQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0E7b0JBQ3RCQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxDQUFHQSxDQUFDQTt3QkFDNUJBLE1BQU1BLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO29CQUN6QkEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO29CQUN0QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsR0FBR0EsQ0FBR0EsQ0FBQ0EsQ0FDOUJBLENBQUNBO3dCQUNDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO3dCQUMzQ0EsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxDQUFDQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTt3QkFFbkNBLE1BQU1BLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUN2QkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7b0JBQ25DQSxDQUFDQTtvQkFDREEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBO29CQUN6QkEsQ0FBQ0E7d0JBQ0NBLE1BQU1BLENBQUFBLENBQUVBLEdBQUlBLENBQUNBLENBQ2JBLENBQUNBOzRCQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxhQUFhQTtnQ0FDbENBLENBQUNBO29DQUNDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLFFBQVFBLENBQUVB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RUEsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBV0EsQ0FBQ0EsQ0FDdkNBLENBQUNBO3dCQUVDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDcEZBLElBQUlBLENBQUNBLFVBQVVBLElBQUlBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO29CQUNuQ0EsQ0FBQ0E7b0JBQ0RBLElBQUlBO3dCQUNGQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDeERBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDdkJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVdBLENBQUNBLENBQ3ZDQSxDQUFDQTt3QkFFQ0EsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7d0JBQ2pDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDdEZBLENBQUNBO29CQUNEQSxJQUFJQTt3QkFDRkEsSUFBSUEsQ0FBQ0Esb0JBQW9CQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDakVBLEtBQUtBLENBQUNBO2dCQUdSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDekJBLENBQUNBO3dCQUNDQSxJQUFJQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDeEVBLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGtCQUFrQkEsQ0FBRUEsV0FBV0EsQ0FBRUEsQ0FBQ0E7d0JBQzFEQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxZQUFZQSxDQUFDQSxXQUFXQSxFQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDckZBLEtBQUtBLENBQUNBO29CQUNSQSxDQUFDQTtnQkFFREEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsU0FBU0E7b0JBQzFCQSxDQUFDQTt3QkFDQ0EsSUFBSUEsV0FBV0EsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsR0FBR0EsRUFBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7d0JBQ3hFQSxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxrQkFBa0JBLENBQUVBLFdBQVdBLENBQUVBLENBQUNBO3dCQUMxREEsSUFBSUEsQ0FBQ0Esb0JBQW9CQSxDQUFFQSxZQUFZQSxDQUFDQSxXQUFXQSxFQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDOUZBLEtBQUtBLENBQUNBO29CQUNSQSxDQUFDQTtnQkFFREEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUE7b0JBQ3ZCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsRUFBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7b0JBQ3hFQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUE7b0JBQ3ZCQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0E7b0JBQ3RCQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFXQSxDQUFDQTt3QkFDckNBLElBQUlBLENBQUNBLHdCQUF3QkEsQ0FBRUEsTUFBTUEsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3JGQSxJQUFJQTt3QkFDRkEsSUFBSUEsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDekVBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxL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S0EsQ0FBQUEsQ0FBRUEsQ0FBRUEsQ0FBQ0EsQ0FDVkEsQ0FBQ0E7UUFFREEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFRHhCLGNBQWNBLENBQUVBLFdBQXdCQTtRQUV0Q3lCLElBQUlBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO1FBRzVDQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUc1REEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFHNURBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLFdBQVdBLENBQUNBLEVBQUVBLENBQUVBLENBQUVBLENBQUNBO1FBR3BFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxXQUFXQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUM3RUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsR0FBR0EsRUFBRUEsRUFBRUEsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFFakVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLFdBQVdBLENBQUNBLElBQUlBLENBQUVBLENBQUNBO1FBRWxEQSxJQUFJQSxDQUFDQSxhQUFhQSxFQUFFQSxDQUFDQTtJQUN2QkEsQ0FBQ0E7SUFFRHpCLGVBQWVBO1FBRWIwQixJQUFJQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxT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QkFBZ0JBLENBQUVBLElBQUlBLENBQUNBLGNBQWNBLENBQUVBLENBQUNBO1lBRWpEQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFnQkEsSUFBSUEsWUFBWUEsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDekZBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLGNBQWNBLENBQUVBLFdBQVdBLENBQUNBLENBQUNBO1FBTXRDQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFnQkEsSUFBSUEsWUFBWUEsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsRUFBRUEsRUFBRUEsRUFBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFHeEZBLENBQUNBO0lBV0RQLFlBQVlBLENBQUVBLE1BQU1BO1FBRWxCUSxJQUFJQSxDQUFDQSxhQUFhQSxHQUFHQSxJQUFJQSxhQUFhQSxFQUFFQSxDQUFDQTtRQUV6Q0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQUE7UUFDakdBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLElBQUlBLENBQUNBLGFBQWFBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLE9BQU9BLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2pGQSxJQUFJQSxDQUFDQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQTtR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Q0FBQ0EsQ0FBRUEsVUFBVUEsQ0FBRUEsS0FBS0EsQ0FBQ0EsRUFBRUEsQ0FBR0EsQ0FBQ0E7b0JBQzNCQSxJQUFJQSxDQUFFQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFFQSxHQUFHQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNoREEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFLTUQsTUFBTUE7UUFFWEUsTUFBTUEsQ0FBQ0E7WUFDTEEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUE7WUFDZkEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUE7WUFDZkEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7WUFDYkEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7U0FDZEEsQ0FBQ0E7SUFDSkEsQ0FBQ0E7SUFFT0YsYUFBYUEsQ0FBRUEsS0FBZ0JBLEVBQUVBLFNBQWlCQTtRQUV4REcsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFZkEsT0FBT0EsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFDckRBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLENBQUVBLE1BQU1BLENBQUVBLENBQUNBO1lBQ3JDQSxFQUFFQSxTQUFTQSxDQUFDQTtRQUNkQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxHQUFHQSxDQUFDQSxFQUFFQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtJQUM1REEsQ0FBQ0E7SUFLTUgsV0FBV0EsQ0FBRUEsS0FBZ0JBLEVBQUVBLE9BQWdCQTtRQUVwREksSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDM0NBLElBQUlBLENBQUNBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLEtBQUtBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQzNDQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMxQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFFMUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBS01KLFdBQVdBLENBQUVBLE9BQVlBO1FBRzlCSyxNQUFNQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7QUFDSEwsQ0FBQ0E7QUFFRCxXQUFXLENBQUMsSUFBSSxDQUFFLEdBQUcsRUFBRSw4QkFBOEIsQ0FBRTtLQUNwRCxLQUFLLENBQUUsTUFBTSxFQUFFLGNBQWMsRUFBRSxTQUFTLENBQUU7S0FDMUMsS0FBSyxDQUFFLE1BQU0sRUFBRSxjQUFjLEVBQUUsU0FBUyxDQUFFO0tBQzFDLEtBQUssQ0FBRSxLQUFLLEVBQUUsYUFBYSxFQUFFLFNBQVMsQ0FBRTtLQUN4QyxLQUFLLENBQUUsS0FBSyxFQUFFLGFBQWEsRUFBRSxTQUFTLENBQUUsQ0FDeEM7QUNqRkg7QUFDQTtBQ0RBO0FBQ0E7QUNEQTtBQUNBO0FDREE7QUFDQTtBQ0RBO0FBQ0EiLCJmaWxlIjoiY3J5cHRvZ3JhcGhpeC1zZS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5cclxuZXhwb3J0IGNsYXNzIEtleVxyXG57XHJcbiAgX3R5cGU6IG51bWJlcjtcclxuICBfc2l6ZTogbnVtYmVyO1xyXG4gIF9jb21wb25lbnRBcnJheTogQnl0ZVN0cmluZ1tdO1xyXG5cclxuICBjb25zdHJ1Y3RvcigpXHJcbiAge1xyXG4gICAgdGhpcy5fdHlwZSA9IDA7XHJcbiAgICB0aGlzLl9zaXplID0gLTE7XHJcbiAgICB0aGlzLl9jb21wb25lbnRBcnJheSA9IFtdO1xyXG4gIH1cclxuXHJcbiAgc2V0VHlwZSgga2V5VHlwZTogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl90eXBlID0ga2V5VHlwZTtcclxuICB9XHJcblxyXG4gIGdldFR5cGUoKTogbnVtYmVyXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3R5cGU7XHJcbiAgfVxyXG5cclxuICBzZXRTaXplKCBzaXplOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHRoaXMuX3NpemUgPSBzaXplO1xyXG4gIH1cclxuXHJcbiAgZ2V0U2l6ZSgpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5fc2l6ZTtcclxuICB9XHJcblxyXG4gIHNldENvbXBvbmVudCggY29tcDogbnVtYmVyLCB2YWx1ZTogQnl0ZVN0cmluZyApXHJcbiAge1xyXG4gICAgdGhpcy5fY29tcG9uZW50QXJyYXlbIGNvbXAgXSA9IHZhbHVlO1xyXG4gIH1cclxuXHJcbiAgZ2V0Q29tcG9uZW50KCBjb21wOiBudW1iZXIgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLl9jb21wb25lbnRBcnJheVsgY29tcCBdO1xyXG4gIH1cclxuXHJcblxyXG4gIHN0YXRpYyBTRUNSRVQgPSAxO1xyXG4gIHN0YXRpYyBQUklWQVRFID0gMjtcclxuICBzdGF0aWMgUFVCTElDID0gMztcclxuXHJcbiAgc3RhdGljIERFUyA9IDE7XHJcbiAgc3RhdGljIEFFUyA9IDI7XHJcbiAgc3RhdGljIE1PRFVMVVMgPSAzO1xyXG4gIHN0YXRpYyBFWFBPTkVOVCA9IDQ7XHJcbiAgc3RhdGljIENSVF9QID0gNTtcclxuICBzdGF0aWMgQ1JUX1EgPSA2O1xyXG4gIHN0YXRpYyBDUlRfRFAxID0gNztcclxuICBzdGF0aWMgQ1JUX0RRMSA9IDg7XHJcbiAgc3RhdGljIENSVF9QUSA9IDk7XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5pbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XG5pbXBvcnQgeyBLZXkgfSBmcm9tICcuL2tleSc7XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9cbntcbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cblxuICBlbmNyeXB0KCBrZXk6IEtleSwgbWVjaCwgZGF0YTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXG4gIHtcbiAgICB2YXIgazogQnl0ZUFycmF5ID0ga2V5LmdldENvbXBvbmVudCggS2V5LlNFQ1JFVCApLmJ5dGVBcnJheTtcblxuICAgIGlmICggay5sZW5ndGggPT0gMTYgKSAgLy8gM0RFUyBEb3VibGUgLT4gVHJpcGxlXG4gICAge1xuICAgICAgdmFyIG9yaWcgPSBrO1xuXG4gICAgICBrID0gbmV3IEJ5dGVBcnJheSggW10gKS5zZXRMZW5ndGgoIDI0ICk7XG5cbiAgICAgIGsuc2V0Qnl0ZXNBdCggMCwgb3JpZyApO1xuICAgICAgay5zZXRCeXRlc0F0KCAxNiwgb3JpZy52aWV3QXQoIDAsIDggKSApO1xuICAgIH1cblxuICAgIHZhciBjcnlwdG9UZXh0ID0gbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGsuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDAgKSApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCBjcnlwdG9UZXh0ICk7XG4gIH1cblxuICBkZWNyeXB0KCBrZXksIG1lY2gsIGRhdGEgKVxuICB7XG4gICAgcmV0dXJuIGRhdGE7XG4gIH1cblxuICBzaWduKCBrZXk6IEtleSwgbWVjaCwgZGF0YTogQnl0ZVN0cmluZywgaXY/ICk6IEJ5dGVTdHJpbmdcbiAge1xuICAgIHZhciBrID0ga2V5LmdldENvbXBvbmVudCggS2V5LlNFQ1JFVCApLmJ5dGVBcnJheTtcblxuICAgIHZhciBrZXlEYXRhID0gaztcblxuICAgIGlmICggay5sZW5ndGggPT0gMTYgKSAgLy8gM0RFUyBEb3VibGUgLT4gVHJpcGxlXG4gICAge1xuICAgICAga2V5RGF0YSA9IG5ldyBCeXRlQXJyYXkoKTtcblxuICAgICAga2V5RGF0YVxuICAgICAgICAuc2V0TGVuZ3RoKCAyNCApXG4gICAgICAgIC5zZXRCeXRlc0F0KCAwLCBrIClcbiAgICAgICAgLnNldEJ5dGVzQXQoIDE2LCBrLmJ5dGVzQXQoIDAsIDggKSApO1xuICAgIH1cblxuICAgIGlmICggaXYgPT0gdW5kZWZpbmVkIClcbiAgICAgIGl2ID0gbmV3IFVpbnQ4QXJyYXkoIFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdICk7XG5cbiAgICAvLyBmdW5jdGlvbigga2V5LCBtZXNzYWdlLCBlbmNyeXB0LCBtb2RlLCBpdiwgcGFkZGluZyApXG4gICAgLy8gbW9kZT0xIENCQywgcGFkZGluZz00IG5vLXBhZFxuICAgIHZhciBjcnlwdG9UZXh0ID0gbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGtleURhdGEuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDEsIGl2LCA0ICkgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggY3J5cHRvVGV4dCApLmJ5dGVzKCAtOCApO1xuICB9XG5cbiAgc3RhdGljIGRlc1BDO1xuICBzdGF0aWMgZGVzU1A7XG5cbiAgcHJpdmF0ZSBkZXMoIGtleTogVWludDhBcnJheSwgbWVzc2FnZTogVWludDhBcnJheSwgZW5jcnlwdDogbnVtYmVyLCBtb2RlOiBudW1iZXIsIGl2PzogVWludDhBcnJheSwgcGFkZGluZz86IG51bWJlciApOiBVaW50OEFycmF5XG4gIHtcbiAgICAvL2Rlc19jcmVhdGVLZXlzXG4gICAgLy90aGlzIHRha2VzIGFzIGlucHV0IGEgNjQgYml0IGtleSAoZXZlbiB0aG91Z2ggb25seSA1NiBiaXRzIGFyZSB1c2VkKVxuICAgIC8vYXMgYW4gYXJyYXkgb2YgMiBpbnRlZ2VycywgYW5kIHJldHVybnMgMTYgNDggYml0IGtleXNcbiAgICBmdW5jdGlvbiBkZXNfY3JlYXRlS2V5cyAoa2V5KVxuICAgIHtcbiAgICAgIGlmICggQ3J5cHRvLmRlc1BDID09IHVuZGVmaW5lZCApXG4gICAgICB7XG4gICAgICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgICAgIENyeXB0by5kZXNQQyA9IHtcbiAgICAgICAgICBwYzJieXRlczAgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgyMDAwMDAwMCwweDIwMDAwMDA0LDB4MTAwMDAsMHgxMDAwNCwweDIwMDEwMDAwLDB4MjAwMTAwMDQsMHgyMDAsMHgyMDQsMHgyMDAwMDIwMCwweDIwMDAwMjA0LDB4MTAyMDAsMHgxMDIwNCwweDIwMDEwMjAwLDB4MjAwMTAyMDQgXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MSwweDEwMDAwMCwweDEwMDAwMSwweDQwMDAwMDAsMHg0MDAwMDAxLDB4NDEwMDAwMCwweDQxMDAwMDEsMHgxMDAsMHgxMDEsMHgxMDAxMDAsMHgxMDAxMDEsMHg0MDAwMTAwLDB4NDAwMDEwMSwweDQxMDAxMDAsMHg0MTAwMTAxXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDgsMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAwMDAwLDB4ODAwMDAwMCwweDgyMDAwMDAsMHgyMDAwLDB4MjAyMDAwLDB4ODAwMjAwMCwweDgyMDIwMDAsMHgyMDAwMCwweDIyMDAwMCwweDgwMjAwMDAsMHg4MjIwMDAwLDB4MjIwMDAsMHgyMjIwMDAsMHg4MDIyMDAwLDB4ODIyMjAwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczQgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwLDB4MjAsMHg0MjAsMCwweDQwMCwweDIwLDB4NDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjBdICksXG4gICAgICAgICAgcGMyYnl0ZXM2IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyLDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAsMHg4MDAsMHgxMDgwMCwweDIwMDAwMDAwLDB4MjAwMTAwMDAsMHgyMDAwMDgwMCwweDIwMDEwODAwLDB4MjAwMDAsMHgzMDAwMCwweDIwODAwLDB4MzA4MDAsMHgyMDAyMDAwMCwweDIwMDMwMDAwLDB4MjAwMjA4MDAsMHgyMDAzMDgwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczggOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDAsMHg0MDAwMCwweDIsMHg0MDAwMiwweDIsMHg0MDAwMiwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAyLDB4MjA0MDAwMiwweDIwMDAwMDIsMHgyMDQwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMCwwLDB4MjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgyMDAwLDB4MjAyMCwweDIwMDAsMHgyMDIwLDB4MTAyMDAwLDB4MTAyMDIwLDB4MTAyMDAwLDB4MTAyMDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTE6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMCwweDIwMCwweDEwMDAyMDAsMHgyMDAwMDAsMHgxMjAwMDAwLDB4MjAwMjAwLDB4MTIwMDIwMCwweDQwMDAwMDAsMHg1MDAwMDAwLDB4NDAwMDIwMCwweDUwMDAyMDAsMHg0MjAwMDAwLDB4NTIwMDAwMCwweDQyMDAyMDAsMHg1MjAwMjAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTI6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMCwweDgwMDAwMDAsMHg4MDAxMDAwLDB4ODAwMDAsMHg4MTAwMCwweDgwODAwMDAsMHg4MDgxMDAwLDB4MTAsMHgxMDEwLDB4ODAwMDAxMCwweDgwMDEwMTAsMHg4MDAxMCwweDgxMDEwLDB4ODA4MDAxMCwweDgwODEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMzogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MTAwLDB4MTA0LDAsMHg0LDB4MTAwLDB4MTA0LDB4MSwweDUsMHgxMDEsMHgxMDUsMHgxLDB4NSwweDEwMSwweDEwNV0gKVxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICAvL2hvdyBtYW55IGl0ZXJhdGlvbnMgKDEgZm9yIGRlcywgMyBmb3IgdHJpcGxlIGRlcylcbiAgICAgIHZhciBpdGVyYXRpb25zID0ga2V5Lmxlbmd0aCA+IDggPyAzIDogMTsgLy9jaGFuZ2VkIGJ5IFBhdWwgMTYvNi8yMDA3IHRvIHVzZSBUcmlwbGUgREVTIGZvciA5KyBieXRlIGtleXNcbiAgICAgIC8vc3RvcmVzIHRoZSByZXR1cm4ga2V5c1xuICAgICAgdmFyIGtleXMgPSBuZXcgVWludDMyQXJyYXkoMzIgKiBpdGVyYXRpb25zKTtcbiAgICAgIC8vbm93IGRlZmluZSB0aGUgbGVmdCBzaGlmdHMgd2hpY2ggbmVlZCB0byBiZSBkb25lXG4gICAgICB2YXIgc2hpZnRzID0gWyAwLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwIF07XG4gICAgICAvL290aGVyIHZhcmlhYmxlc1xuICAgICAgdmFyIGxlZnR0ZW1wLCByaWdodHRlbXAsIG09MCwgbj0wLCB0ZW1wO1xuXG4gICAgICBmb3IgKHZhciBqPTA7IGo8aXRlcmF0aW9uczsgaisrKVxuICAgICAgeyAvL2VpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuICAgICAgICBsZWZ0ID0gIChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG4gICAgICAgIHJpZ2h0ID0gKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcblxuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDIpIF4gcmlnaHQpICYgMHgzMzMzMzMzMzsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAyKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgICAvL3RoZSByaWdodCBzaWRlIG5lZWRzIHRvIGJlIHNoaWZ0ZWQgYW5kIHRvIGdldCB0aGUgbGFzdCBmb3VyIGJpdHMgb2YgdGhlIGxlZnQgc2lkZVxuICAgICAgICB0ZW1wID0gKGxlZnQgPDwgOCkgfCAoKHJpZ2h0ID4+PiAyMCkgJiAweDAwMDAwMGYwKTtcbiAgICAgICAgLy9sZWZ0IG5lZWRzIHRvIGJlIHB1dCB1cHNpZGUgZG93blxuICAgICAgICBsZWZ0ID0gKHJpZ2h0IDw8IDI0KSB8ICgocmlnaHQgPDwgOCkgJiAweGZmMDAwMCkgfCAoKHJpZ2h0ID4+PiA4KSAmIDB4ZmYwMCkgfCAoKHJpZ2h0ID4+PiAyNCkgJiAweGYwKTtcbiAgICAgICAgcmlnaHQgPSB0ZW1wO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlc2Ugc2hpZnRzIG9uIHRoZSBsZWZ0IGFuZCByaWdodCBrZXlzXG4gICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHNoaWZ0cy5sZW5ndGg7IGkrKylcbiAgICAgICAge1xuICAgICAgICAgIC8vc2hpZnQgdGhlIGtleXMgZWl0aGVyIG9uZSBvciB0d28gYml0cyB0byB0aGUgbGVmdFxuICAgICAgICAgIGlmIChzaGlmdHNbaV0pXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDIpIHwgKGxlZnQgPj4+IDI2KTsgcmlnaHQgPSAocmlnaHQgPDwgMikgfCAocmlnaHQgPj4+IDI2KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZWxzZVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAyNyk7IHJpZ2h0ID0gKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAyNyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGxlZnQgJj0gLTB4ZjsgcmlnaHQgJj0gLTB4ZjtcblxuICAgICAgICAgIC8vbm93IGFwcGx5IFBDLTIsIGluIHN1Y2ggYSB3YXkgdGhhdCBFIGlzIGVhc2llciB3aGVuIGVuY3J5cHRpbmcgb3IgZGVjcnlwdGluZ1xuICAgICAgICAgIC8vdGhpcyBjb252ZXJzaW9uIHdpbGwgbG9vayBsaWtlIFBDLTIgZXhjZXB0IG9ubHkgdGhlIGxhc3QgNiBiaXRzIG9mIGVhY2ggYnl0ZSBhcmUgdXNlZFxuICAgICAgICAgIC8vcmF0aGVyIHRoYW4gNDggY29uc2VjdXRpdmUgYml0cyBhbmQgdGhlIG9yZGVyIG9mIGxpbmVzIHdpbGwgYmUgYWNjb3JkaW5nIHRvXG4gICAgICAgICAgLy9ob3cgdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9ucyB3aWxsIGJlIGFwcGxpZWQ6IFMyLCBTNCwgUzYsIFM4LCBTMSwgUzMsIFM1LCBTN1xuICAgICAgICAgIGxlZnR0ZW1wID0gQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMFtsZWZ0ID4+PiAyOF0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMyWyhsZWZ0ID4+PiAyMCkgJiAweGZdIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzM1sobGVmdCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzNFsobGVmdCA+Pj4gMTIpICYgMHhmXSB8IENyeXB0by5kZXNQQy5wYzJieXRlczVbKGxlZnQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzNlsobGVmdCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHJpZ2h0dGVtcCA9IENyeXB0by5kZXNQQy5wYzJieXRlczdbcmlnaHQgPj4+IDI4XSB8IENyeXB0by5kZXNQQy5wYzJieXRlczhbKHJpZ2h0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzOVsocmlnaHQgPj4+IDIwKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMVsocmlnaHQgPj4+IDEyKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMlsocmlnaHQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNQQy5wYzJieXRlczEzWyhyaWdodCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjtcbiAgICAgICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICAgICAgfVxuICAgICAgfSAvL2ZvciBlYWNoIGl0ZXJhdGlvbnNcblxuICAgICAgcmV0dXJuIGtleXM7XG4gICAgfSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG4gICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICBpZiAoIENyeXB0by5kZXNTUCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIENyeXB0by5kZXNTUCA9IHtcbiAgICAgICAgc3BmdW5jdGlvbjE6IG5ldyBVaW50MzJBcnJheSggWzB4MTAxMDQwMCwwLDB4MTAwMDAsMHgxMDEwNDA0LDB4MTAxMDAwNCwweDEwNDA0LDB4NCwweDEwMDAwLDB4NDAwLDB4MTAxMDQwMCwweDEwMTA0MDQsMHg0MDAsMHgxMDAwNDA0LDB4MTAxMDAwNCwweDEwMDAwMDAsMHg0LDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMHgxMDQwMCwweDEwNDAwLDB4MTAxMDAwMCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDQsMHgxMDAwMDA0LDB4MTAwMDAwNCwweDEwMDA0LDAsMHg0MDQsMHgxMDQwNCwweDEwMDAwMDAsMHgxMDAwMCwweDEwMTA0MDQsMHg0LDB4MTAxMDAwMCwweDEwMTA0MDAsMHgxMDAwMDAwLDB4MTAwMDAwMCwweDQwMCwweDEwMTAwMDQsMHgxMDAwMCwweDEwNDAwLDB4MTAwMDAwNCwweDQwMCwweDQsMHgxMDAwNDA0LDB4MTA0MDQsMHgxMDEwNDA0LDB4MTAwMDQsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDAwMDQsMHg0MDQsMHgxMDQwNCwweDEwMTA0MDAsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwwLDB4MTAwMDQsMHgxMDQwMCwwLDB4MTAxMDAwNF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjI6IG5ldyBVaW50MzJBcnJheSggWy0weDdmZWY3ZmUwLC0weDdmZmY4MDAwLDB4ODAwMCwweDEwODAyMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLC0weDdmZWY3ZmUwLC0weDdmZWY4MDAwLC0weDgwMDAwMDAwLC0weDdmZmY4MDAwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsMHgxMDgwMDAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsMCwtMHg4MDAwMDAwMCwweDgwMDAsMHgxMDgwMjAsLTB4N2ZmMDAwMDAsMHgxMDAwMjAsLTB4N2ZmZmZmZTAsMCwweDEwODAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsLTB4N2ZmMDAwMDAsMHg4MDIwLDAsMHgxMDgwMjAsLTB4N2ZlZmZmZTAsMHgxMDAwMDAsLTB4N2ZmZjdmZTAsLTB4N2ZmMDAwMDAsLTB4N2ZlZjgwMDAsMHg4MDAwLC0weDdmZjAwMDAwLC0weDdmZmY4MDAwLDB4MjAsLTB4N2ZlZjdmZTAsMHgxMDgwMjAsMHgyMCwweDgwMDAsLTB4ODAwMDAwMDAsMHg4MDIwLC0weDdmZWY4MDAwLDB4MTAwMDAwLC0weDdmZmZmZmUwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLDB4MTAwMDIwLDB4MTA4MDAwLDAsLTB4N2ZmZjgwMDAsMHg4MDIwLC0weDgwMDAwMDAwLC0weDdmZWZmZmUwLC0weDdmZWY3ZmUwLDB4MTA4MDAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uMzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDgsMHg4MDIwMjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwMCwwLDB4MjAyMDgsMHg4MDAwMjAwLDB4MjAwMDgsMHg4MDAwMDA4LDB4ODAwMDAwOCwweDIwMDAwLDB4ODAyMDIwOCwweDIwMDA4LDB4ODAyMDAwMCwweDIwOCwweDgwMDAwMDAsMHg4LDB4ODAyMDIwMCwweDIwMCwweDIwMjAwLDB4ODAyMDAwMCwweDgwMjAwMDgsMHgyMDIwOCwweDgwMDAyMDgsMHgyMDIwMCwweDIwMDAwLDB4ODAwMDIwOCwweDgsMHg4MDIwMjA4LDB4MjAwLDB4ODAwMDAwMCwweDgwMjAyMDAsMHg4MDAwMDAwLDB4MjAwMDgsMHgyMDgsMHgyMDAwMCwweDgwMjAyMDAsMHg4MDAwMjAwLDAsMHgyMDAsMHgyMDAwOCwweDgwMjAyMDgsMHg4MDAwMjAwLDB4ODAwMDAwOCwweDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDgsMHgyMDAwMCwweDgwMDAwMDAsMHg4MDIwMjA4LDB4OCwweDIwMjA4LDB4MjAyMDAsMHg4MDAwMDA4LDB4ODAyMDAwMCwweDgwMDAyMDgsMHgyMDgsMHg4MDIwMDAwLDB4MjAyMDgsMHg4LDB4ODAyMDAwOCwweDIwMjAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNDogbmV3IFVpbnQzMkFycmF5KCBbMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgwLDB4ODAwMDgxLDB4ODAwMDAxLDB4MjAwMSwwLDB4ODAyMDAwLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwweDgwMDA4MCwweDgwMDAwMSwweDEsMHgyMDAwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAxLDB4MjA4MCwweDgwMDA4MSwweDEsMHgyMDgwLDB4ODAwMDgwLDB4MjAwMCwweDgwMjA4MCwweDgwMjA4MSwweDgxLDB4ODAwMDgwLDB4ODAwMDAxLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwwLDB4ODAyMDAwLDB4MjA4MCwweDgwMDA4MCwweDgwMDA4MSwweDEsMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgxLDB4ODEsMHgxLDB4MjAwMCwweDgwMDAwMSwweDIwMDEsMHg4MDIwODAsMHg4MDAwODEsMHgyMDAxLDB4MjA4MCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMCwweDgwMjA4MF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjU6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwLDB4MjA4MDEwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDgwMDAwLDB4MTAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDAwODAxMDAsMHg4MDAwMCwweDIwMDAxMDAsMHg0MDA4MDEwMCwweDQyMDAwMTAwLDB4NDIwODAwMDAsMHg4MDEwMCwweDQwMDAwMDAwLDB4MjAwMDAwMCwweDQwMDgwMDAwLDB4NDAwODAwMDAsMCwweDQwMDAwMTAwLDB4NDIwODAxMDAsMHg0MjA4MDEwMCwweDIwMDAxMDAsMHg0MjA4MDAwMCwweDQwMDAwMTAwLDAsMHg0MjAwMDAwMCwweDIwODAxMDAsMHgyMDAwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDgwMDAwLDB4NDIwMDAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg0MDA4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDAwMCwweDQyMDgwMDAwLDB4MjA4MDEwMCwweDQwMDgwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQyMDgwMDAwLDB4NDIwODAxMDAsMHg4MDEwMCwweDQyMDAwMDAwLDB4NDIwODAxMDAsMHgyMDgwMDAwLDAsMHg0MDA4MDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAxMDAsMHg4MDAwMCwwLDB4NDAwODAwMDAsMHgyMDgwMTAwLDB4NDAwMDAxMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb242OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMDEwLDB4MjA0MDAwMDAsMHg0MDAwLDB4MjA0MDQwMTAsMHgyMDQwMDAwMCwweDEwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDQwNDAxMCwweDQwMDAwMCwweDIwMDAwMDEwLDB4NDAwMDEwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMCwweDQwMDAxMCwweDIwMDA0MDEwLDB4NDAwMCwweDQwNDAwMCwweDIwMDA0MDEwLDB4MTAsMHgyMDQwMDAxMCwweDIwNDAwMDEwLDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwweDQwMTAsMHg0MDQwMDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4MjAwMDQwMDAsMHgxMCwweDIwNDAwMDEwLDB4NDA0MDAwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4MjA0MDQwMTAsMHg0MDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDIwNDA0MDAwLDAsMHgyMDQwMDAxMCwweDEwLDB4NDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4NDAwMCwweDQwMDAxMCwweDIwMDA0MDEwLDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4NDAwMDEwLDB4MjAwMDQwMTBdICksXG4gICAgICAgIHNwZnVuY3Rpb243OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMCwweDQyMDAwMDIsMHg0MDAwODAyLDAsMHg4MDAsMHg0MDAwODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDQyMDA4MDIsMHgyMDAwMDAsMCwweDQwMDAwMDIsMHgyLDB4NDAwMDAwMCwweDQyMDAwMDIsMHg4MDIsMHg0MDAwODAwLDB4MjAwODAyLDB4MjAwMDAyLDB4NDAwMDgwMCwweDQwMDAwMDIsMHg0MjAwMDAwLDB4NDIwMDgwMCwweDIwMDAwMiwweDQyMDAwMDAsMHg4MDAsMHg4MDIsMHg0MjAwODAyLDB4MjAwODAwLDB4MiwweDQwMDAwMDAsMHgyMDA4MDAsMHg0MDAwMDAwLDB4MjAwODAwLDB4MjAwMDAwLDB4NDAwMDgwMiwweDQwMDA4MDIsMHg0MjAwMDAyLDB4NDIwMDAwMiwweDIsMHgyMDAwMDIsMHg0MDAwMDAwLDB4NDAwMDgwMCwweDIwMDAwMCwweDQyMDA4MDAsMHg4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4ODAyLDB4NDAwMDAwMiwweDQyMDA4MDIsMHg0MjAwMDAwLDB4MjAwODAwLDAsMHgyLDB4NDIwMDgwMiwwLDB4MjAwODAyLDB4NDIwMDAwMCwweDgwMCwweDQwMDAwMDIsMHg0MDAwODAwLDB4ODAwLDB4MjAwMDAyXSApLFxuICAgICAgICBzcGZ1bmN0aW9uODogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAwMTA0MCwweDEwMDAsMHg0MDAwMCwweDEwMDQxMDQwLDB4MTAwMDAwMDAsMHgxMDAwMTA0MCwweDQwLDB4MTAwMDAwMDAsMHg0MDA0MCwweDEwMDQwMDAwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDEwMDQxMDAwLDB4NDEwNDAsMHgxMDAwLDB4NDAsMHgxMDA0MDAwMCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHgxMDQwLDB4NDEwMDAsMHg0MDA0MCwweDEwMDQwMDQwLDB4MTAwNDEwMDAsMHgxMDQwLDAsMCwweDEwMDQwMDQwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDQxMDQwLDB4NDAwMDAsMHg0MTA0MCwweDQwMDAwLDB4MTAwNDEwMDAsMHgxMDAwLDB4NDAsMHgxMDA0MDA0MCwweDEwMDAsMHg0MTA0MCwweDEwMDAxMDAwLDB4NDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwNDAwNDAsMHgxMDAwMDAwMCwweDQwMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDAwNDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwMDEwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDQxMDAwLDB4MTA0MCwweDEwNDAsMHg0MDA0MCwweDEwMDAwMDAwLDB4MTAwNDEwMDBdICksXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vY3JlYXRlIHRoZSAxNiBvciA0OCBzdWJrZXlzIHdlIHdpbGwgbmVlZFxuICAgIHZhciBrZXlzID0gZGVzX2NyZWF0ZUtleXMoIGtleSApO1xuXG4gICAgdmFyIG09MCwgaSwgaiwgdGVtcCwgbGVmdCwgcmlnaHQsIGxvb3Bpbmc7XG4gICAgdmFyIGNiY2xlZnQsIGNiY2xlZnQyLCBjYmNyaWdodCwgY2JjcmlnaHQyXG4gICAgdmFyIGxlbiA9IG1lc3NhZ2UubGVuZ3RoO1xuXG4gICAgLy9zZXQgdXAgdGhlIGxvb3BzIGZvciBzaW5nbGUgYW5kIHRyaXBsZSBkZXNcbiAgICB2YXIgaXRlcmF0aW9ucyA9IGtleXMubGVuZ3RoID09IDMyID8gMyA6IDk7IC8vc2luZ2xlIG9yIHRyaXBsZSBkZXNcblxuICAgIGlmIChpdGVyYXRpb25zID09IDMpXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyIF0gOiBbIDMwLCAtMiwgLTIgXTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiwgNjIsIDMwLCAtMiwgNjQsIDk2LCAyIF0gOiBbIDk0LCA2MiwgLTIsIDMyLCA2NCwgMiwgMzAsIC0yLCAtMiBdO1xuICAgIH1cblxuICAgIC8vIHBhZCB0aGUgbWVzc2FnZSBkZXBlbmRpbmcgb24gdGhlIHBhZGRpbmcgcGFyYW1ldGVyXG4gICAgaWYgKCAoIHBhZGRpbmcgIT0gdW5kZWZpbmVkICkgJiYgKCBwYWRkaW5nICE9IDQgKSApXG4gICAge1xuICAgICAgdmFyIHVucGFkZGVkTWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICB2YXIgcGFkID0gOC0obGVuJTgpO1xuXG4gICAgICBtZXNzYWdlID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiArIDggKTtcbiAgICAgIG1lc3NhZ2Uuc2V0KCB1bnBhZGRlZE1lc3NhZ2UsIDAgKTtcblxuICAgICAgc3dpdGNoKCBwYWRkaW5nIClcbiAgICAgIHtcbiAgICAgICAgY2FzZSAwOiAvLyB6ZXJvLXBhZFxuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwIF0gKSwgbGVuICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgY2FzZSAxOiAvLyBQS0NTNyBwYWRkaW5nXG4gICAgICAgIHtcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWRdICksIDggKTtcblxuICAgICAgICAgIGlmICggcGFkPT04IClcbiAgICAgICAgICAgIGxlbis9ODtcblxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG5cbiAgICAgICAgY2FzZSAyOiAgLy8gcGFkIHRoZSBtZXNzYWdlIHdpdGggc3BhY2VzXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAgXSApLCA4ICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgIH1cblxuICAgICAgbGVuICs9IDgtKGxlbiU4KVxuICAgIH1cblxuICAgIC8vIHN0b3JlIHRoZSByZXN1bHQgaGVyZVxuICAgIHZhciByZXN1bHQgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG5cbiAgICBpZiAobW9kZSA9PSAxKVxuICAgIHsgLy9DQkMgbW9kZVxuICAgICAgdmFyIG0gPSAwO1xuXG4gICAgICBjYmNsZWZ0ID0gIChpdlttKytdIDw8IDI0KSB8IChpdlttKytdIDw8IDE2KSB8IChpdlttKytdIDw8IDgpIHwgaXZbbSsrXTtcbiAgICAgIGNiY3JpZ2h0ID0gKGl2W20rK10gPDwgMjQpIHwgKGl2W20rK10gPDwgMTYpIHwgKGl2W20rK10gPDwgOCkgfCBpdlttKytdO1xuICAgIH1cblxuICAgIHZhciBybSA9IDA7XG5cbiAgICAvL2xvb3AgdGhyb3VnaCBlYWNoIDY0IGJpdCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgIHdoaWxlIChtIDwgbGVuKVxuICAgIHtcbiAgICAgIGxlZnQgPSAgKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG4gICAgICByaWdodCA9IChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBsZWZ0IF49IGNiY2xlZnQ7IHJpZ2h0IF49IGNiY3JpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGNiY2xlZnQyID0gY2JjbGVmdDtcbiAgICAgICAgICBjYmNyaWdodDIgPSBjYmNyaWdodDtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vZmlyc3QgZWFjaCA2NCBidXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2UgbXVzdCBiZSBwZXJtdXRlZCBhY2NvcmRpbmcgdG8gSVBcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICBsZWZ0ID0gKChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDMxKSk7XG4gICAgICByaWdodCA9ICgocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDMxKSk7XG5cbiAgICAgIC8vZG8gdGhpcyBlaXRoZXIgMSBvciAzIHRpbWVzIGZvciBlYWNoIGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgICBmb3IgKGo9MDsgajxpdGVyYXRpb25zOyBqKz0zKVxuICAgICAge1xuICAgICAgICB2YXIgZW5kbG9vcCA9IGxvb3BpbmdbaisxXTtcbiAgICAgICAgdmFyIGxvb3BpbmMgPSBsb29waW5nW2orMl07XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uXG4gICAgICAgIGZvciAoaT1sb29waW5nW2pdOyBpIT1lbmRsb29wOyBpKz1sb29waW5jKVxuICAgICAgICB7IC8vZm9yIGVmZmljaWVuY3lcbiAgICAgICAgICB2YXIgcmlnaHQxID0gcmlnaHQgXiBrZXlzW2ldO1xuICAgICAgICAgIHZhciByaWdodDIgPSAoKHJpZ2h0ID4+PiA0KSB8IChyaWdodCA8PCAyOCkpIF4ga2V5c1tpKzFdO1xuXG4gICAgICAgICAgLy90aGUgcmVzdWx0IGlzIGF0dGFpbmVkIGJ5IHBhc3NpbmcgdGhlc2UgYnl0ZXMgdGhyb3VnaCB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zXG4gICAgICAgICAgdGVtcCA9IGxlZnQ7XG4gICAgICAgICAgbGVmdCA9IHJpZ2h0O1xuICAgICAgICAgIHJpZ2h0ID0gdGVtcCBeIChDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjJbKHJpZ2h0MSA+Pj4gMjQpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjRbKHJpZ2h0MSA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb242WyhyaWdodDEgPj4+ICA4KSAmIDB4M2ZdIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb244W3JpZ2h0MSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uM1socmlnaHQyID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjVbKHJpZ2h0MiA+Pj4gIDgpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjdbcmlnaHQyICYgMHgzZl0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdGVtcCA9IGxlZnQ7IGxlZnQgPSByaWdodDsgcmlnaHQgPSB0ZW1wOyAvL3VucmV2ZXJzZSBsZWZ0IGFuZCByaWdodFxuICAgICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgICAgbGVmdCA9ICgobGVmdCA+Pj4gMSkgfCAobGVmdCA8PCAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpO1xuXG4gICAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDI7XG4gICAgICAgICAgcmlnaHQgXj0gY2JjcmlnaHQyO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc3VsdC5zZXQoIG5ldyBVaW50OEFycmF5ICggWyAobGVmdD4+PjI0KSAmIDB4ZmYsIChsZWZ0Pj4+MTYpICYgMHhmZiwgKGxlZnQ+Pj44KSAmIDB4ZmYsIChsZWZ0KSAmIDB4ZmYsIChyaWdodD4+PjI0KSAmIDB4ZmYsIChyaWdodD4+PjE2KSAmIDB4ZmYsIChyaWdodD4+PjgpICYgMHhmZiwgKHJpZ2h0KSAmIDB4ZmYgXSApLCBybSApO1xuXG4gICAgICBybSArPSA4O1xuICAgIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9IC8vZW5kIG9mIGRlc1xuXG4gIHZlcmlmeSgga2V5LCBtZWNoLCBkYXRhLCBzaWduYXR1cmUsIGl2IClcbiAge1xuICAgIHJldHVybiBkYXRhO1xuICB9XG5cbiAgZGlnZXN0KCBtZWNoLCBkYXRhIClcbiAge1xuICAgIHJldHVybiBkYXRhO1xuICB9XG5cbiAgc3RhdGljIERFU19DQkM6IE51bWJlciA9IDI7XG4gIHN0YXRpYyBERVNfRUNCID0gNTtcbiAgc3RhdGljIERFU19NQUMgPSA4O1xuICBzdGF0aWMgREVTX01BQ19FTVYgPSA5O1xuICBzdGF0aWMgSVNPOTc5N19NRVRIT0RfMSA9IDExO1xuICBzdGF0aWMgSVNPOTc5N19NRVRIT0RfMiA9IDEyO1xuXG4gIHN0YXRpYyBNRDUgPSAxMztcbiAgc3RhdGljIFJTQSA9IDE0O1xuICBzdGF0aWMgU0hBXzEgPSAxNTtcbiAgc3RhdGljIFNIQV81MTIgPSAyNTtcbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSwgQnl0ZUVuY29kaW5nIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcblxyXG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XHJcbmltcG9ydCB7IENyeXB0byB9IGZyb20gJy4vY3J5cHRvJztcclxuXHJcbmV4cG9ydCBjbGFzcyBCeXRlU3RyaW5nXHJcbntcclxuICBwdWJsaWMgYnl0ZUFycmF5OiBCeXRlQXJyYXk7XHJcblxyXG4gIHB1YmxpYyBzdGF0aWMgSEVYID0gQnl0ZUVuY29kaW5nLkhFWDtcclxuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCB2YWx1ZTogc3RyaW5nIHwgQnl0ZVN0cmluZyB8IEJ5dGVBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIgKVxyXG4gIHtcclxuICAgIGlmICggIWVuY29kaW5nIClcclxuICAgIHtcclxuICAgICAgaWYgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVTdHJpbmcgKVxyXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICAgIGVsc2UgaWYgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVBcnJheSApXHJcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5jbG9uZSgpO1xyXG4vLyAgICAgIGVsc2VcclxuLy8gICAgICAgIHN1cGVyKCBVaW50OEFycmF5KCB2YWx1ZSApICk7XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICB7XHJcbiAgICAgIHN3aXRjaCggZW5jb2RpbmcgKVxyXG4gICAgICB7XHJcbiAgICAgICAgY2FzZSBCeXRlU3RyaW5nLkhFWDpcclxuICAgICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggPHN0cmluZz52YWx1ZSwgQnl0ZUFycmF5LkhFWCApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICB0aHJvdyBcIkJ5dGVTdHJpbmcgdW5zdXBwb3J0ZWQgZW5jb2RpbmdcIjtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xyXG4gIH1cclxuXHJcbiAgYnl0ZXMoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS52aWV3QXQoIG9mZnNldCwgY291bnQgKSApO1xyXG4gIH1cclxuXHJcbiAgYnl0ZUF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQgKTtcclxuICB9XHJcblxyXG4gIGVxdWFscyggb3RoZXJCeXRlU3RyaW5nOiBCeXRlU3RyaW5nIClcclxuICB7XHJcbi8vICAgIHJldHVybiAhKCB0aGlzLl9ieXRlcyA8IG90aGVyQnl0ZVN0cmluZy5fYnl0ZXMgKSAmJiAhKCB0aGlzLl9ieXRlcyA+IG90aGVyQnl0ZVN0cmluZy5fYnl0ZXMgKTtcclxuICB9XHJcblxyXG4gIGNvbmNhdCggdmFsdWU6IEJ5dGVTdHJpbmcgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHRoaXMuYnl0ZUFycmF5LmNvbmNhdCggdmFsdWUuYnl0ZUFycmF5ICk7XHJcblxyXG4gICAgcmV0dXJuIHRoaXM7XHJcbiAgfVxyXG5cclxuICBsZWZ0KCBjb3VudDogbnVtYmVyIClcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LnZpZXdBdCggMCApICk7XHJcbiAgfVxyXG5cclxuICByaWdodCggY291bnQ6IG51bWJlciApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS52aWV3QXQoIC1jb3VudCApICk7XHJcbiAgfVxyXG5cclxuICBub3QoICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LmNsb25lKCkubm90KCkgKTtcclxuICB9XHJcblxyXG4gIGFuZCggdmFsdWU6IEJ5dGVTdHJpbmcgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkuY2xvbmUoKS5hbmQoIHZhbHVlLmJ5dGVBcnJheSkgKTtcclxuICB9XHJcblxyXG4gIG9yKCB2YWx1ZTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS5jbG9uZSgpLm9yKCB2YWx1ZS5ieXRlQXJyYXkpICk7XHJcbiAgfVxyXG5cclxuICBwYWQoIG1ldGhvZDogbnVtYmVyLCBvcHRpb25hbD86IGJvb2xlYW4gKVxyXG4gIHtcclxuICAgIHZhciBicyA9IG5ldyBCeXRlQnVmZmVyKCB0aGlzLmJ5dGVBcnJheSApO1xyXG5cclxuICAgIGlmICggb3B0aW9uYWwgPT0gdW5kZWZpbmVkIClcclxuICAgICAgb3B0aW9uYWwgPSBmYWxzZTtcclxuXHJcbiAgICBpZiAoICggKCBicy5sZW5ndGggJiA3ICkgIT0gMCApIHx8ICggIW9wdGlvbmFsICkgKVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV3bGVuID0gKCAoIGJzLmxlbmd0aCArIDggKSAmIH43ICk7XHJcbiAgICAgIGlmICggbWV0aG9kID09IENyeXB0by5JU085Nzk3X01FVEhPRF8xIClcclxuICAgICAgICBicy5hcHBlbmQoIDB4ODAgKTtcclxuXHJcbiAgICAgIHdoaWxlKCBicy5sZW5ndGggPCBuZXdsZW4gKVxyXG4gICAgICAgIGJzLmFwcGVuZCggMHgwMCApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBicy50b0J5dGVTdHJpbmcoKTtcclxuICB9XHJcblxyXG4gIHRvU3RyaW5nKCBlbmNvZGluZz86IG51bWJlciApOiBzdHJpbmdcclxuICB7XHJcbiAgICAvL1RPRE86IGVuY29kaW5nIC4uLlxyXG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5LnRvU3RyaW5nKCBCeXRlQXJyYXkuSEVYICk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY29uc3QgSEVYID0gQnl0ZVN0cmluZy5IRVg7XHJcbi8vZXhwb3J0IGNvbnN0IEFTQ0lJID0gQnl0ZVN0cmluZy5BU0NJSTtcclxuZXhwb3J0IGNvbnN0IEJBU0U2NCA9IEJ5dGVTdHJpbmcuQkFTRTY0O1xyXG4vL2V4cG9ydCBjb25zdCBVVEY4ID0gQnl0ZVN0cmluZy5VVEY4O1xyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5cclxuZXhwb3J0IGNsYXNzIEJ5dGVCdWZmZXJcclxue1xyXG4gIGJ5dGVBcnJheTogQnl0ZUFycmF5O1xyXG5cclxuICBjb25zdHJ1Y3RvciAoIHZhbHVlPzogQnl0ZUFycmF5IHwgQnl0ZVN0cmluZyB8IHN0cmluZywgZW5jb2Rpbmc/IClcclxuICB7XHJcbiAgICBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5jbG9uZSgpO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZVN0cmluZyApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggZW5jb2RpbmcgIT0gdW5kZWZpbmVkIClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgQnl0ZVN0cmluZyggdmFsdWUsIGVuY29kaW5nICkuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggW10gKTtcclxuICB9XHJcblxyXG4gIGdldCBsZW5ndGgoKVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XHJcbiAgfVxyXG5cclxuICB0b0J5dGVTdHJpbmcoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkgKTtcclxuICB9XHJcblxyXG4gIGNsZWFyKClcclxuICB7XHJcbiAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcbiAgfVxyXG5cclxuICBhcHBlbmQoIHZhbHVlOiBCeXRlU3RyaW5nIHwgQnl0ZUJ1ZmZlciB8IG51bWJlciApOiBCeXRlQnVmZmVyXHJcbiAge1xyXG4gICAgbGV0IHZhbHVlQXJyYXk6IEJ5dGVBcnJheTtcclxuXHJcbiAgICBpZiAoICggdmFsdWUgaW5zdGFuY2VvZiBCeXRlU3RyaW5nICkgfHwgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVCdWZmZXIgKSApXHJcbiAgICB7XHJcbiAgICAgIHZhbHVlQXJyYXkgPSB2YWx1ZS5ieXRlQXJyYXk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggdHlwZW9mIHZhbHVlID09IFwibnVtYmVyXCIgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggWyAoIDxudW1iZXI+dmFsdWUgJiAweGZmICkgXSApO1xyXG4gICAgfVxyXG4vKiAgICBlbHNlIGlmICggdHlwZW9mIHZhbHVlID09IFwic3RyaW5nXCIgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIHZhbHVlLmxlbmd0aCApO1xyXG4gICAgICBmb3IoIHZhciBpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgKytpIClcclxuICAgICAgICB2YWx1ZUFycmF5W2ldID0gdmFsdWUuY2hhckF0KCBpICk7XHJcbiAgICB9Ki9cclxuLy8gICAgZWxzZVxyXG4vLyAgICAgIHZhbHVlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCB2YWx1ZSApO1xyXG5cclxuICAgIHRoaXMuYnl0ZUFycmF5LmNvbmNhdCggdmFsdWVBcnJheSApO1xyXG5cclxuICAgIHJldHVybiB0aGlzO1xyXG4gIH1cclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuZXhwb3J0IGNsYXNzIEJhc2VUTFZcbntcbiAgcHVibGljIHN0YXRpYyBFbmNvZGluZ3MgPSB7XG4gICAgRU1WOiAxLFxuICAgIERHSTogMlxuICB9O1xuXG4gIHN0YXRpYyBwYXJzZVRMViggYnVmZmVyOiBCeXRlQXJyYXksIGVuY29kaW5nOiBudW1iZXIgKTogeyB0YWc6IG51bWJlciwgbGVuOiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXksIGxlbk9mZnNldDogbnVtYmVyLCB2YWx1ZU9mZnNldDogbnVtYmVyIH1cbiAge1xuICAgIHZhciByZXMgPSB7IHRhZzogMCwgbGVuOiAwLCB2YWx1ZTogdW5kZWZpbmVkLCBsZW5PZmZzZXQ6IDAsIHZhbHVlT2Zmc2V0OiAwIH07XG4gICAgdmFyIG9mZiA9IDA7XG4gICAgdmFyIGJ5dGVzID0gYnVmZmVyLmJhY2tpbmdBcnJheTsgIC8vIFRPRE86IFVzZSBieXRlQXQoIC4uIClcblxuICAgIHN3aXRjaCggZW5jb2RpbmcgKVxuICAgIHtcbiAgICAgIGNhc2UgQmFzZVRMVi5FbmNvZGluZ3MuRU1WOlxuICAgICAge1xuICAgICAgICB3aGlsZSggKCBvZmYgPCBieXRlcy5sZW5ndGggKSAmJiAoICggYnl0ZXNbIG9mZiBdID09IDB4MDAgKSB8fCAoIGJ5dGVzWyBvZmYgXSA9PSAweEZGICkgKSApXG4gICAgICAgICAgKytvZmY7XG5cbiAgICAgICAgaWYgKCBvZmYgPj0gYnl0ZXMubGVuZ3RoIClcbiAgICAgICAgICByZXR1cm4gcmVzO1xuXG4gICAgICAgIGlmICggKCBieXRlc1sgb2ZmIF0gJiAweDFGICkgPT0gMHgxRiApXG4gICAgICAgIHtcbiAgICAgICAgICByZXMudGFnID0gYnl0ZXNbIG9mZisrIF0gPDwgODtcbiAgICAgICAgICBpZiAoIG9mZiA+PSBieXRlcy5sZW5ndGggKVxuICAgICAgICAgIHsgLypsb2coXCIxXCIpOyovICByZXR1cm4gbnVsbDsgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmVzLnRhZyB8PSBieXRlc1sgb2ZmKysgXTtcblxuICAgICAgICByZXMubGVuT2Zmc2V0ID0gb2ZmO1xuXG4gICAgICAgIGlmICggb2ZmID49IGJ5dGVzLmxlbmd0aCApXG4gICAgICAgIHsgLypsb2coXCIyXCIpOyovICByZXR1cm4gbnVsbDsgfVxuXG4gICAgICAgIHZhciBsbCA9ICggYnl0ZXNbIG9mZiBdICYgMHg4MCApID8gKCBieXRlc1sgb2ZmKysgXSAmIDB4N0YgKSA6IDE7XG4gICAgICAgIHdoaWxlKCBsbC0tID4gMCApXG4gICAgICAgIHtcbiAgICAgICAgICBpZiAoIG9mZiA+PSBieXRlcy5sZW5ndGggKVxuICAgICAgICAgIHsgLypsb2coXCIzOlwiICsgb2ZmICsgXCI6XCIgKyBieXRlcy5sZW5ndGgpOyAgKi9yZXR1cm4gbnVsbDsgfVxuXG4gICAgICAgICAgcmVzLmxlbiA9ICggcmVzLmxlbiA8PCA4ICkgfCBieXRlc1sgb2ZmKysgXTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJlcy52YWx1ZU9mZnNldCA9IG9mZjtcbiAgICAgICAgaWYgKCBvZmYgKyByZXMubGVuID4gYnl0ZXMubGVuZ3RoIClcbiAgICAgIHsgLypsb2coXCI0XCIpOyovICByZXR1cm4gbnVsbDsgfVxuICAgICAgICByZXMudmFsdWUgPSBieXRlcy5zbGljZSggcmVzLnZhbHVlT2Zmc2V0LCByZXMudmFsdWVPZmZzZXQgKyByZXMubGVuICk7XG5cbiAgLy8gICAgICBsb2coIHJlcy52YWx1ZU9mZnNldCArIFwiK1wiICsgcmVzLmxlbiArIFwiPVwiICsgYnl0ZXMgKTtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcztcbiAgfVxuXG4gIHB1YmxpYyBieXRlQXJyYXk6IEJ5dGVBcnJheTtcbiAgZW5jb2Rpbmc6IG51bWJlcjtcblxuICBjb25zdHJ1Y3RvciAoIHRhZzogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5LCBlbmNvZGluZz86IG51bWJlciApXG4gIHtcbiAgICB0aGlzLmVuY29kaW5nID0gZW5jb2RpbmcgfHwgQmFzZVRMVi5FbmNvZGluZ3MuRU1WO1xuXG4gICAgc3dpdGNoKCB0aGlzLmVuY29kaW5nIClcbiAgICB7XG4gICAgICBjYXNlIEJhc2VUTFYuRW5jb2RpbmdzLkVNVjpcbiAgICAgIHtcbiAgICAgICAgdmFyIHRsdkJ1ZmZlciA9IG5ldyBCeXRlQXJyYXkoW10pO1xuXG4gICAgICAgIGlmICggdGFnID49ICAweDEwMCApXG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoICggdGFnID4+IDggKSAmIDB4RkYgKTtcbiAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoIHRhZyAmIDB4RkYgKTtcblxuICAgICAgICB2YXIgbGVuID0gdmFsdWUubGVuZ3RoO1xuICAgICAgICBpZiAoIGxlbiA+IDB4RkYgKVxuICAgICAgICB7XG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoIDB4ODIgKTtcbiAgICAgICAgICB0bHZCdWZmZXIuYWRkQnl0ZSggKCBsZW4gPj4gOCApICYgMHhGRiApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCBsZW4gPiAweDdGIClcbiAgICAgICAgICB0bHZCdWZmZXIuYWRkQnl0ZSggMHg4MSApO1xuXG4gICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCBsZW4gJiAweEZGICk7XG5cbiAgICAgICAgdGx2QnVmZmVyLmNvbmNhdCggdmFsdWUgKTtcblxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IHRsdkJ1ZmZlcjtcblxuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBnZXQgdGFnKCk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIEJhc2VUTFYucGFyc2VUTFYoIHRoaXMuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICkudGFnO1xuICB9XG5cbiAgZ2V0IHZhbHVlKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIEJhc2VUTFYucGFyc2VUTFYoIHRoaXMuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICkudmFsdWU7XG4gIH1cblxuICBnZXQgbGVuKCk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIEJhc2VUTFYucGFyc2VUTFYoIHRoaXMuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICkubGVuO1xuICB9XG59XG5cbkJhc2VUTFYuRW5jb2RpbmdzWyBcIkNUVlwiIF0gPSA0Oy8vIHsgcGFyc2U6IDAsIGJ1aWxkOiAxIH07XG4iLCJpbXBvcnQgeyBCYXNlVExWIGFzIEJhc2VUTFYgfSBmcm9tICcuLi9pc283ODE2L2Jhc2UtdGx2JztcclxuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XHJcblxyXG5leHBvcnQgY2xhc3MgVExWXHJcbntcclxuICB0bHY6IEJhc2VUTFY7XHJcbiAgZW5jb2Rpbmc6IG51bWJlcjtcclxuXHJcbiAgY29uc3RydWN0b3IgKCB0YWc6IG51bWJlciwgdmFsdWU6IEJ5dGVTdHJpbmcsIGVuY29kaW5nOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHRoaXMudGx2ID0gbmV3IEJhc2VUTFYoIHRhZywgdmFsdWUuYnl0ZUFycmF5LCBlbmNvZGluZyApO1xyXG5cclxuICAgIHRoaXMuZW5jb2RpbmcgPSBlbmNvZGluZztcclxuICB9XHJcblxyXG4gIGdldFRMVigpOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkgKTtcclxuICB9XHJcblxyXG4gIGdldFRhZygpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy50bHYudGFnO1xyXG4gIH1cclxuXHJcbiAgZ2V0VmFsdWUoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy50bHYudmFsdWUgKTtcclxuICB9XHJcblxyXG4gIGdldEwoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHZhciBpbmZvID0gQmFzZVRMVi5wYXJzZVRMViggdGhpcy50bHYuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkudmlld0F0KCBpbmZvLmxlbk9mZnNldCwgaW5mby52YWx1ZU9mZnNldCApICk7XHJcbiAgfVxyXG5cclxuICBnZXRMVigpXHJcbiAge1xyXG4gICAgdmFyIGluZm8gPSBCYXNlVExWLnBhcnNlVExWKCB0aGlzLnRsdi5ieXRlQXJyYXksIHRoaXMuZW5jb2RpbmcgKTtcclxuXHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMudGx2LmJ5dGVBcnJheS52aWV3QXQoIGluZm8ubGVuT2Zmc2V0LCBpbmZvLnZhbHVlT2Zmc2V0ICsgaW5mby5sZW4gKSApO1xyXG4gIH1cclxuXHJcbiAgc3RhdGljIHBhcnNlVExWKCBidWZmZXI6IEJ5dGVTdHJpbmcsIGVuY29kaW5nOiBudW1iZXIgKTogeyB0YWc6IG51bWJlciwgbGVuOiBudW1iZXIsIHZhbHVlOiBCeXRlU3RyaW5nLCBsZW5PZmZzZXQ6IG51bWJlciwgdmFsdWVPZmZzZXQ6IG51bWJlciB9XHJcbiAge1xyXG4gICAgbGV0IGluZm8gPSBCYXNlVExWLnBhcnNlVExWKCBidWZmZXIuYnl0ZUFycmF5LCBlbmNvZGluZyApO1xyXG5cclxuICAgIHJldHVybiB7XHJcbiAgICAgIHRhZzogaW5mby50YWcsXHJcbiAgICAgIGxlbjogaW5mby5sZW4sXHJcbiAgICAgIHZhbHVlOiBuZXcgQnl0ZVN0cmluZyggaW5mby52YWx1ZSApLFxyXG4gICAgICBsZW5PZmZzZXQ6IGluZm8ubGVuT2Zmc2V0LFxyXG4gICAgICB2YWx1ZU9mZnNldDogaW5mby52YWx1ZU9mZnNldFxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIHN0YXRpYyBFTVYgPSBCYXNlVExWLkVuY29kaW5ncy5FTVY7XHJcbiAgc3RhdGljIERHSSA9IEJhc2VUTFYuRW5jb2RpbmdzLkRHSTtcclxuLy8gIHN0YXRpYyBMMTYgPSBCYXNlVExWLkwxNjtcclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XHJcbmltcG9ydCB7IFRMViB9IGZyb20gJy4vdGx2JztcclxuXHJcbmV4cG9ydCBjbGFzcyBUTFZMaXN0XHJcbntcclxuICBfdGx2czogVExWW107XHJcblxyXG4gIGNvbnN0cnVjdG9yKCB0bHZTdHJlYW06IEJ5dGVTdHJpbmcsIGVuY29kaW5nPzogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl90bHZzID0gW107XHJcblxyXG4gICAgdmFyIG9mZiA9IDA7XHJcblxyXG4gICAgd2hpbGUoIG9mZiA8IHRsdlN0cmVhbS5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB2YXIgdGx2SW5mbyA9IFRMVi5wYXJzZVRMViggdGx2U3RyZWFtLmJ5dGVzKCBvZmYgKSwgZW5jb2RpbmcgKVxyXG5cclxuICAgICAgaWYgKCB0bHZJbmZvID09IG51bGwgKVxyXG4gICAgICB7XHJcbiAgICAgICAgLy8gZXJyb3IgLi4uXHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgLy8gbm8gbW9yZSAuLi4gP1xyXG4gICAgICAgIGlmICggdGx2SW5mby52YWx1ZU9mZnNldCA9PSAwIClcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICB0aGlzLl90bHZzLnB1c2goIG5ldyBUTFYoIHRsdkluZm8udGFnLCB0bHZJbmZvLnZhbHVlLCBlbmNvZGluZyApICk7XHJcbiAgICAgICAgb2ZmICs9IHRsdkluZm8udmFsdWVPZmZzZXQgKyB0bHZJbmZvLmxlbjtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgaW5kZXgoIGluZGV4OiBudW1iZXIgKTogVExWXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3RsdnNbIGluZGV4IF07XHJcbiAgfVxyXG59XHJcbiIsImltcG9ydCB7ICBCeXRlQXJyYXksIEtpbmQsIEtpbmRCdWlsZGVyLCBLaW5kSW5mbyB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG4vKipcbiAqIEVuY29kZXIvRGVjb2RvciBLaW5kIGZvciBhIEFQRFUgQ29tbWFuZFxuICovXG5leHBvcnQgY2xhc3MgQ29tbWFuZEFQRFUgaW1wbGVtZW50cyBLaW5kXG57XG4gIENMQTogbnVtYmVyOyAvLyA9IDA7XG4gIElOUzogbnVtYmVyID0gMDtcbiAgUDE6IG51bWJlciA9IDA7XG4gIFAyOiBudW1iZXIgPSAwO1xuICBkYXRhOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XG4gIExlOiBudW1iZXIgPSAwO1xuXG4vLyAgc3RhdGljIGtpbmRJbmZvOiBLaW5kSW5mbztcblxuICAvKipcbiAgICogQGNvbnN0cnVjdG9yXG4gICAqXG4gICAqIERlc2VyaWFsaXplIGZyb20gYSBKU09OIG9iamVjdFxuICAgKi9cbiAgY29uc3RydWN0b3IoIGF0dHJpYnV0ZXM/OiB7fSApXG4gIHtcbiAgICBLaW5kLmluaXRGaWVsZHMoIHRoaXMsIGF0dHJpYnV0ZXMgKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgTGMoKTpudW1iZXIgICAgICAgICAgeyByZXR1cm4gdGhpcy5kYXRhLmxlbmd0aDsgfVxuICBwdWJsaWMgZ2V0IGhlYWRlcigpOiBCeXRlQXJyYXkgIHsgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIFsgdGhpcy5DTEEsIHRoaXMuSU5TLCB0aGlzLlAxLCB0aGlzLlAyIF0gKTsgfVxuXG4gIC8qKlxuICAgKiBGbHVlbnQgQnVpbGRlclxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBpbml0KCBDTEE/OiBudW1iZXIsIElOUz86IG51bWJlciwgUDE/OiBudW1iZXIsIFAyPzogbnVtYmVyLCBkYXRhPzogQnl0ZUFycmF5LCBleHBlY3RlZExlbj86IG51bWJlciApOiBDb21tYW5kQVBEVVxuICB7XG4gICAgcmV0dXJuICggbmV3IENvbW1hbmRBUERVKCkgKS5zZXQoIENMQSwgSU5TLCBQMSwgUDIsIGRhdGEsIGV4cGVjdGVkTGVuICk7XG4gIH1cblxuICBwdWJsaWMgc2V0KCBDTEE6IG51bWJlciwgSU5TOiBudW1iZXIsIFAxOiBudW1iZXIsIFAyOiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXksIGV4cGVjdGVkTGVuPzogbnVtYmVyICk6IENvbW1hbmRBUERVXG4gIHtcbiAgICB0aGlzLkNMQSA9IENMQTtcbiAgICB0aGlzLklOUyA9IElOUztcbiAgICB0aGlzLlAxID0gUDE7XG4gICAgdGhpcy5QMiA9IFAyO1xuICAgIHRoaXMuZGF0YSA9IGRhdGEgfHwgbmV3IEJ5dGVBcnJheSgpO1xuICAgIHRoaXMuTGUgPSBleHBlY3RlZExlbiB8fCAwO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgc2V0Q0xBKCBDTEE6IG51bWJlciApOiBDb21tYW5kQVBEVSAgICAgIHsgdGhpcy5DTEEgPSBDTEE7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXRJTlMoIElOUzogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgeyB0aGlzLklOUyA9IElOUzsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldFAxKCBQMTogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgICB7IHRoaXMuUDEgPSBQMTsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldFAyKCBQMjogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgICB7IHRoaXMuUDIgPSBQMjsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldERhdGEoIGRhdGE6IEJ5dGVBcnJheSApOiBDb21tYW5kQVBEVSB7IHRoaXMuZGF0YSA9IGRhdGE7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXRMZSggTGU6IG51bWJlciApOiBDb21tYW5kQVBEVSAgICAgICAgeyB0aGlzLkxlID0gTGU7IHJldHVybiB0aGlzOyB9XG5cbiAgLyoqXG4gICAqIFNlcmlhbGl6YXRpb24sIHJldHVybnMgYSBKU09OIG9iamVjdFxuICAgKi9cbiAgcHVibGljIHRvSlNPTigpOiB7fVxuICB7XG4gICAgcmV0dXJuIHtcbiAgICAgIENMQTogdGhpcy5DTEEsXG4gICAgICBJTlM6IHRoaXMuSU5TLFxuICAgICAgUDE6IHRoaXMuUDEsXG4gICAgICBQMjogdGhpcy5QMixcbiAgICAgIGRhdGE6IHRoaXMuZGF0YSxcbiAgICAgIExlOiB0aGlzLkxlXG4gICAgfTtcbiAgfVxuXG4gIC8qKlxuICAgKiBFbmNvZGVyXG4gICAqL1xuICBwdWJsaWMgZW5jb2RlQnl0ZXMoIG9wdGlvbnM/OiB7fSApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBkbGVuID0gKCAoIHRoaXMuTGMgPiAwICkgPyAxICsgdGhpcy5MYyA6IDAgKTtcbiAgICBsZXQgbGVuID0gNCArIGRsZW4gKyAoICggdGhpcy5MZSA+IDAgKSA/IDEgOiAwICk7XG4gICAgbGV0IGJhID0gbmV3IEJ5dGVBcnJheSgpLnNldExlbmd0aCggbGVuICk7XG5cbiAgICAvLyByZWJ1aWxkIGJpbmFyeSBBUERVQ29tbWFuZFxuICAgIGJhLnNldEJ5dGVzQXQoIDAsIHRoaXMuaGVhZGVyICk7XG4gICAgaWYgKCB0aGlzLkxjICkge1xuICAgICAgYmEuc2V0Qnl0ZUF0KCA0LCB0aGlzLkxjICk7XG4gICAgICBiYS5zZXRCeXRlc0F0KCA1LCB0aGlzLmRhdGEgKTtcbiAgICB9XG5cbiAgICBpZiAoIHRoaXMuTGUgPiAwICkge1xuICAgICAgYmEuc2V0Qnl0ZUF0KCA0ICsgZGxlbiwgdGhpcy5MZSApO1xuICAgIH1cblxuICAgIHJldHVybiBiYTtcbiAgfVxuXG4gIC8qKlxuICAqIERlY29kZXJcbiAgKi9cbiAgcHVibGljIGRlY29kZUJ5dGVzKCBieXRlQXJyYXk6IEJ5dGVBcnJheSwgb3B0aW9ucz86IHt9ICk6IENvbW1hbmRBUERVXG4gIHtcbiAgICBpZiAoIGJ5dGVBcnJheS5sZW5ndGggPCA0IClcbiAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbW1hbmRBUERVOiBJbnZhbGlkIGJ1ZmZlcicgKTtcblxuICAgIGxldCBvZmZzZXQgPSAwO1xuXG4gICAgdGhpcy5DTEEgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuICAgIHRoaXMuSU5TID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcbiAgICB0aGlzLlAxID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcbiAgICB0aGlzLlAyID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcblxuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA+IG9mZnNldCArIDEgKVxuICAgIHtcbiAgICAgIHZhciBMYyA9IGJ5dGVBcnJheS5ieXRlQXQoIG9mZnNldCsrICk7XG4gICAgICB0aGlzLmRhdGEgPSBieXRlQXJyYXkuYnl0ZXNBdCggb2Zmc2V0LCBMYyApO1xuICAgICAgb2Zmc2V0ICs9IExjO1xuICAgIH1cblxuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA+IG9mZnNldCApXG4gICAgICB0aGlzLkxlID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcblxuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCAhPSBvZmZzZXQgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tbWFuZEFQRFU6IEludmFsaWQgYnVmZmVyJyApO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbn1cblxuS2luZEJ1aWxkZXIuaW5pdCggQ29tbWFuZEFQRFUsICdJU083ODE2IENvbW1hbmQgQVBEVScgKVxuICAuYnl0ZUZpZWxkKCAnQ0xBJywgJ0NsYXNzJyApXG4gIC5ieXRlRmllbGQoICdJTlMnLCAnSW5zdHJ1Y3Rpb24nIClcbiAgLmJ5dGVGaWVsZCggJ1AxJywgJ1AxIFBhcmFtJyApXG4gIC5ieXRlRmllbGQoICdQMicsICdQMiBQYXJhbScgKVxuICAuaW50ZWdlckZpZWxkKCAnTGMnLCAnQ29tbWFuZCBMZW5ndGgnLCB7IGNhbGN1bGF0ZWQ6IHRydWUgfSApXG4gIC5maWVsZCggJ2RhdGEnLCAnQ29tbWFuZCBEYXRhJywgQnl0ZUFycmF5IClcbiAgLmludGVnZXJGaWVsZCggJ0xlJywgJ0V4cGVjdGVkIExlbmd0aCcgKVxuICA7XG4iLCJleHBvcnQgZW51bSBJU083ODE2XHJcbntcclxuICAvLyBJU08gY2xhc3MgY29kZVxyXG4gIENMQV9JU08gPSAweDAwLFxyXG5cclxuICAvLyBFeHRlcm5hbCBleHRlcm5hbCBhdXRoZW50aWNhdGUgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19FWFRFUk5BTF9BVVRIRU5USUNBVEUgPSAweDgyLFxyXG5cclxuICAvLyBHZXQgY2hhbGxlbmdlIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfR0VUX0NIQUxMRU5HRSA9IDB4ODQsXHJcblxyXG4gIC8vIEludGVybmFsIGF1dGhlbnRpY2F0ZSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0lOVEVSTkFMX0FVVEhFTlRJQ0FURSA9IDB4ODgsXHJcblxyXG4gIC8vIFNlbGVjdCBmaWxlIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfU0VMRUNUX0ZJTEUgPSAweEE0LFxyXG5cclxuICAvLyBSZWFkIHJlY29yZCBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1JFQURfUkVDT1JEID0gMHhCMixcclxuXHJcbiAgLy8gVXBkYXRlIHJlY29yZCBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1VQREFURV9SRUNPUkQgPSAweERDLFxyXG5cclxuICAvLyBWZXJpZnkgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19WRVJJRlkgPSAweDIwLFxyXG5cclxuICAvLyBCbG9jayBBcHBsaWNhdGlvbiBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0JMT0NLX0FQUExJQ0FUSU9OID0gMHgxRSxcclxuXHJcbiAgLy8gVW5ibG9jayBhcHBsaWNhdGlvbiBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1VOQkxPQ0tfQVBQTElDQVRJT04gPSAweDE4LFxyXG5cclxuICAvLyBVbmJsb2NrIGNoYW5nZSBQSU4gaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19VTkJMT0NLX0NIQU5HRV9QSU4gPSAweDI0LFxyXG5cclxuICAvLyBHZXQgZGF0YSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0dFVF9EQVRBID0gMHhDQSxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gVGVtcGxhdGVcclxuICBUQUdfQVBQTElDQVRJT05fVEVNUExBVEUgPSAweDYxLFxyXG5cclxuICAvLyBGQ0kgUHJvcHJpZXRhcnkgVGVtcGxhdGVcclxuICBUQUdfRkNJX1BST1BSSUVUQVJZX1RFTVBMQVRFID0gMHhBNSxcclxuXHJcbiAgLy8gRkNJIFRlbXBsYXRlXHJcbiAgVEFHX0ZDSV9URU1QTEFURSA9IDB4NkYsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIElkZW50aWZpZXIgKEFJRCkgLSBjYXJkXHJcbiAgVEFHX0FJRCA9IDB4NEYsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIExhYmVsXHJcbiAgVEFHX0FQUExJQ0FUSU9OX0xBQkVMID0gMHg1MCxcclxuXHJcbiAgLy8gTGFuZ3VhZ2UgUHJlZmVyZW5jZVxyXG4gIFRBR19MQU5HVUFHRV9QUkVGRVJFTkNFUyA9IDB4NUYyRCxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gRWZmZWN0aXZlIERhdGFcclxuICBUQUdfQVBQTElDQVRJT05fRUZGRUNUSVZFX0RBVEUgPSAweDVGMjUsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIEV4cGlyYXRpb24gRGF0ZVxyXG4gIFRBR19BUFBMSUNBVElPTl9FWFBJUllfREFURSA9IDB4NUYyNCxcclxuXHJcbiAgLy8gQ2FyZCBIb2xkZXIgTmFtZVxyXG4gIFRBR19DQVJESE9MREVSX05BTUUgPSAweDVGMjAsXHJcblxyXG4gIC8vIElzc3VlciBDb3VudHJ5IENvZGVcclxuICBUQUdfSVNTVUVSX0NPVU5UUllfQ09ERSA9IDB4NUYyOCxcclxuXHJcbiAgLy8gSXNzdWVyIFVSTFxyXG4gIFRBR19JU1NVRVJfVVJMID0gMHg1RjUwLFxyXG5cclxuICAvLyBBcHBsaWNhdGlvbiBQcmltYXJ5IEFjY291bnQgTnVtYmVyIChQQU4pXHJcbiAgVEFHX1BBTiA9IDB4NWEsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIFByaW1hcnkgQWNjb3VudCBOdW1iZXIgKFBBTikgU2VxdWVuY2UgTnVtYmVyXHJcbiAgVEFHX1BBTl9TRVFVRU5DRV9OVU1CRVIgPSAweDVGMzQsXHJcblxyXG4gIC8vIFNlcnZpY2UgQ29kZVxyXG4gIFRBR19TRVJWSUNFX0NPREUgPSAweDVGMzAsXHJcblxyXG4gIElTT19QSU5CTE9DS19TSVpFID0gOCwgICAvLzwgU2l6ZSBvZiBhbiBJU08gUElOIGJsb2NrXHJcblxyXG4gIEFQRFVfTEVOX0xFX01BWCA9IDI1NiwgICAvLzwgTWF4aW11bSBzaXplIGZvciBMZVxyXG5cclxuICBTV19TVUNDRVNTID0gMHg5MDAwLFxyXG4gIC8vICBTV19CWVRFU19SRU1BSU5JTkcoU1cyKSA9IDB4NjEjI1NXMixcclxuICBTV19XQVJOSU5HX05WX01FTU9SWV9VTkNIQU5HRUQgPSAweDYyMDAgLFxyXG4gIFNXX1BBUlRfT0ZfUkVUVVJOX0RBVEFfQ09SUlVQVEVEID0gMHg2MjgxLFxyXG4gIFNXX0VORF9GSUxFX1JFQUNIRURfQkVGT1JFX0xFX0JZVEUgPSAweDYyODIsXHJcbiAgU1dfU0VMRUNURURfRklMRV9JTlZBTElEID0gMHg2MjgzLFxyXG4gIFNXX0ZDSV9OT1RfRk9STUFUVEVEX1RPX0lTTyA9IDB4NjI4NCxcclxuICBTV19XQVJOSU5HX05WX01FTU9SWV9DSEFOR0VEID0gMHg2MzAwLFxyXG4gIFNXX0ZJTEVfRklMTEVEX0JZX0xBU1RfV1JJVEUgPSAweDYzODEsXHJcbiAgLy8gIFNXX0NPVU5URVJfUFJPVklERURfQllfWChYKSA9IDB4NjNDIyNYLFxyXG4gIC8vICBTV19FUlJPUl9OVl9NRU1PUllfVU5DSEFOR0VEKFNXMikgPSAweDY0IyNTVzIsXHJcbiAgLy8gIFNXX0VSUk9SX05WX01FTU9SWV9DSEFOR0VEKFNXMikgPSAweDY1IyNTVzIgLFxyXG4gIC8vICBTV19SRVNFUlZFRChTVzIpID0gMHg2NiMjU1cyLFxyXG4gIFNXX1dST05HX0xFTkdUSCA9IDB4NjcwMCAsXHJcbiAgU1dfRlVOQ1RJT05TX0lOX0NMQV9OT1RfU1VQUE9SVEVEID0gMHg2ODAwLFxyXG4gIFNXX0xPR0lDQUxfQ0hBTk5FTF9OT1RfU1VQUE9SVEVEID0gMHg2ODgxLFxyXG4gIFNXX1NFQ1VSRV9NRVNTQUdJTkdfTk9UX1NVUFBPUlRFRCA9IDB4Njg4MixcclxuICBTV19DT01NQU5EX05PVF9BTExPV0VEID0gMHg2OTAwLFxyXG4gIFNXX0NPTU1BTkRfSU5DT01QQVRJQkxFX1dJVEhfRklMRV9TVFJVQ1RVUkUgPSAweDY5ODEsXHJcbiAgU1dfU0VDVVJJVFlfU1RBVFVTX05PVF9TQVRJU0ZJRUQgPSAweDY5ODIsXHJcbiAgU1dfRklMRV9JTlZBTElEID0gMHg2OTgzLFxyXG4gIFNXX0RBVEFfSU5WQUxJRCA9IDB4Njk4NCxcclxuICBTV19DT05ESVRJT05TX05PVF9TQVRJU0ZJRUQgPSAweDY5ODUsXHJcbiAgU1dfQ09NTUFORF9OT1RfQUxMT1dFRF9BR0FJTiA9IDB4Njk4NixcclxuICBTV19FWFBFQ1RFRF9TTV9EQVRBX09CSkVDVFNfTUlTU0lORyA9IDB4Njk4NyAsXHJcbiAgU1dfU01fREFUQV9PQkpFQ1RTX0lOQ09SUkVDVCA9IDB4Njk4OCxcclxuICBTV19XUk9OR19QQVJBTVMgPSAweDZBMDAgICAsXHJcbiAgU1dfV1JPTkdfREFUQSA9IDB4NkE4MCxcclxuICBTV19GVU5DX05PVF9TVVBQT1JURUQgPSAweDZBODEsXHJcbiAgU1dfRklMRV9OT1RfRk9VTkQgPSAweDZBODIsXHJcbiAgU1dfUkVDT1JEX05PVF9GT1VORCA9IDB4NkE4MyxcclxuICBTV19OT1RfRU5PVUdIX1NQQUNFX0lOX0ZJTEUgPSAweDZBODQsXHJcbiAgU1dfTENfSU5DT05TSVNURU5UX1dJVEhfVExWID0gMHg2QTg1LFxyXG4gIFNXX0lOQ09SUkVDVF9QMVAyID0gMHg2QTg2LFxyXG4gIFNXX0xDX0lOQ09OU0lTVEVOVF9XSVRIX1AxUDIgPSAweDZBODcsXHJcbiAgU1dfUkVGRVJFTkNFRF9EQVRBX05PVF9GT1VORCA9IDB4NkE4OCxcclxuICBTV19XUk9OR19QMVAyID0gMHg2QjAwLFxyXG4gIC8vU1dfQ09SUkVDVF9MRU5HVEgoU1cyKSA9IDB4NkMjI1NXMixcclxuICBTV19JTlNfTk9UX1NVUFBPUlRFRCA9IDB4NkQwMCxcclxuICBTV19DTEFfTk9UX1NVUFBPUlRFRCA9IDB4NkUwMCxcclxuICBTV19VTktOT1dOID0gMHg2RjAwLFxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSwgS2luZCwgS2luZEluZm8sIEtpbmRCdWlsZGVyIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5pbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi9pc283ODE2JztcblxuLyoqXG4gKiBFbmNvZGVyL0RlY29kb3IgZm9yIGEgQVBEVSBSZXNwb25zZVxuICovXG5leHBvcnQgY2xhc3MgUmVzcG9uc2VBUERVIGltcGxlbWVudHMgS2luZFxue1xuICBTVzogbnVtYmVyID0gSVNPNzgxNi5TV19TVUNDRVNTO1xuICBkYXRhOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XG5cbi8vICBzdGF0aWMga2luZEluZm86IEtpbmRJbmZvO1xuXG4gIC8qKlxuICAgKiBAY29uc3RydWN0b3JcbiAgICpcbiAgICogRGVzZXJpYWxpemUgZnJvbSBhIEpTT04gb2JqZWN0XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYXR0cmlidXRlcz86IHt9IClcbiAge1xuICAgIEtpbmQuaW5pdEZpZWxkcyggdGhpcywgYXR0cmlidXRlcyApO1xuICB9XG5cbiAgcHVibGljIGdldCBMYSgpIHsgcmV0dXJuIHRoaXMuZGF0YS5sZW5ndGg7IH1cblxuICBwdWJsaWMgc3RhdGljIGluaXQoIHN3OiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXkgKTogUmVzcG9uc2VBUERVXG4gIHtcbiAgICByZXR1cm4gKCBuZXcgUmVzcG9uc2VBUERVKCkgKS5zZXQoIHN3LCBkYXRhICk7XG4gIH1cblxuICBwdWJsaWMgc2V0KCBzdzogbnVtYmVyLCBkYXRhPzogQnl0ZUFycmF5ICk6IFJlc3BvbnNlQVBEVVxuICB7XG4gICAgdGhpcy5TVyA9IHN3O1xuICAgIHRoaXMuZGF0YSA9IGRhdGEgfHwgbmV3IEJ5dGVBcnJheSgpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgc2V0U1coIFNXOiBudW1iZXIgKTogUmVzcG9uc2VBUERVICAgICAgICB7IHRoaXMuU1cgPSBTVzsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldFNXMSggU1cxOiBudW1iZXIgKTogUmVzcG9uc2VBUERVICAgICAgeyB0aGlzLlNXID0gKCB0aGlzLlNXICYgMHhGRiApIHwgKCBTVzEgPDwgOCApOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0U1cyKCBTVzI6IG51bWJlciApOiBSZXNwb25zZUFQRFUgICAgICB7IHRoaXMuU1cgPSAoIHRoaXMuU1cgJiAweEZGMDAgKSB8IFNXMjsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldERhdGEoIGRhdGE6IEJ5dGVBcnJheSApOiBSZXNwb25zZUFQRFUgeyB0aGlzLmRhdGEgPSBkYXRhOyByZXR1cm4gdGhpczsgfVxuXG4gIC8qKlxuICAgKiBFbmNvZGVyIGZ1bmN0aW9uLCByZXR1cm5zIGEgYmxvYiBmcm9tIGFuIEFQRFVSZXNwb25zZSBvYmplY3RcbiAgICovXG4gIHB1YmxpYyBlbmNvZGVCeXRlcyggb3B0aW9ucz86IHt9ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gbmV3IEJ5dGVBcnJheSgpLnNldExlbmd0aCggdGhpcy5MYSArIDIgKTtcblxuICAgIGJhLnNldEJ5dGVzQXQoIDAsIHRoaXMuZGF0YSApO1xuICAgIGJhLnNldEJ5dGVBdCggdGhpcy5MYSAgICAsICggdGhpcy5TVyA+PiA4ICkgJiAweGZmICk7XG4gICAgYmEuc2V0Qnl0ZUF0KCB0aGlzLkxhICsgMSwgKCB0aGlzLlNXID4+IDAgKSAmIDB4ZmYgKTtcblxuICAgIHJldHVybiBiYTtcbiAgfVxuXG4gIHB1YmxpYyBkZWNvZGVCeXRlcyggYnl0ZUFycmF5OiBCeXRlQXJyYXksIG9wdGlvbnM/OiB7fSApOiBSZXNwb25zZUFQRFVcbiAge1xuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA8IDIgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnUmVzcG9uc2VBUERVIEJ1ZmZlciBpbnZhbGlkJyApO1xuXG4gICAgbGV0IGxhID0gYnl0ZUFycmF5Lmxlbmd0aCAtIDI7XG5cbiAgICB0aGlzLlNXID0gYnl0ZUFycmF5LndvcmRBdCggbGEgKTtcbiAgICB0aGlzLmRhdGEgPSAoIGxhICkgPyBieXRlQXJyYXkuYnl0ZXNBdCggMCwgbGEgKSA6IG5ldyBCeXRlQXJyYXkoKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG59XG5cbktpbmRCdWlsZGVyLmluaXQoIFJlc3BvbnNlQVBEVSwgJ0lTTzc4MTYgUmVzcG9uc2UgQVBEVScgKVxuICAuaW50ZWdlckZpZWxkKCAnU1cnLCAnU3RhdHVzIFdvcmQnLCB7IG1heGltdW06IDB4RkZGRiB9IClcbiAgLmludGVnZXJGaWVsZCggJ0xhJywgJ0FjdHVhbCBMZW5ndGgnLCAgeyBjYWxjdWxhdGVkOiB0cnVlIH0gKVxuICAuZmllbGQoICdEYXRhJywgJ1Jlc3BvbnNlIERhdGEnLCBCeXRlQXJyYXkgKVxuICA7XG4iLG51bGwsImltcG9ydCB7IEJ5dGVBcnJheSwgRW5kUG9pbnQsIE1lc3NhZ2UsIE1lc3NhZ2VIZWFkZXIsIERpcmVjdGlvbiwgQ2hhbm5lbCB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBTbG90IH0gZnJvbSAnLi4vaXNvNzgxNi9zbG90JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9yZXNwb25zZS1hcGR1JztcblxuZXhwb3J0IGNsYXNzIFNsb3RQcm90b2NvbEhhbmRsZXJcbntcbiAgZW5kUG9pbnQ6IEVuZFBvaW50O1xuICBzbG90OiBTbG90O1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICB9XG5cbiAgbGlua1Nsb3QoIHNsb3Q6IFNsb3QsIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5lbmRQb2ludCA9IGVuZFBvaW50O1xuICAgIHRoaXMuc2xvdCA9IHNsb3Q7XG5cbiAgICBlbmRQb2ludC5vbk1lc3NhZ2UoICggbXNnLCBlcCApID0+IHtcbiAgICAgIG1lLm9uTWVzc2FnZSggbXNnLGVwICk7XG4gICAgfSApO1xuICB9XG5cbiAgdW5saW5rU2xvdCgpXG4gIHtcbiAgICB0aGlzLmVuZFBvaW50Lm9uTWVzc2FnZSggbnVsbCApO1xuICAgIHRoaXMuZW5kUG9pbnQgPSBudWxsO1xuICAgIHRoaXMuc2xvdCA9IG51bGw7XG4gIH1cblxuICBvbk1lc3NhZ2UoIHBhY2tldDogTWVzc2FnZTxhbnk+LCByZWNlaXZpbmdFbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgbGV0IGhkcjogYW55ID0gcGFja2V0LmhlYWRlcjtcbiAgICBsZXQgcGF5bG9hZCA9IHBhY2tldC5wYXlsb2FkO1xuXG4gICAgbGV0IHJlc3BvbnNlOiBQcm9taXNlPGFueT47XG4gICAgbGV0IHJlcGx5SGVhZGVyID0geyBtZXRob2Q6IGhkci5tZXRob2QsIGlzUmVzcG9uc2U6IHRydWUgfTtcblxuICAgIHN3aXRjaCggaGRyLm1ldGhvZCApXG4gICAge1xuICAgICAgY2FzZSBcImV4ZWN1dGVBUERVXCI6XG4gICAgICAgIGlmICggISggcGF5bG9hZCBpbnN0YW5jZW9mIENvbW1hbmRBUERVICkgKVxuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgIHJlc3BvbnNlID0gdGhpcy5zbG90LmV4ZWN1dGVBUERVKCA8Q29tbWFuZEFQRFU+cGF5bG9hZCApO1xuXG4gICAgICAgIHJlc3BvbnNlLnRoZW4oICggcmVzcG9uc2VBUERVOiBSZXNwb25zZUFQRFUgKSA9PiB7XG4gICAgICAgICAgbGV0IHJlcGx5UGFja2V0ID0gbmV3IE1lc3NhZ2U8UmVzcG9uc2VBUERVPiggcmVwbHlIZWFkZXIsIHJlc3BvbnNlQVBEVSApO1xuXG4gICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIHJlcGx5UGFja2V0ICk7XG4gICAgICAgIH0pO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBcInBvd2VyT2ZmXCI6XG4gICAgICAgIHJlc3BvbnNlID0gdGhpcy5zbG90LnBvd2VyT2ZmKClcbiAgICAgICAgICAudGhlbiggKCByZXNwRGF0YTogQnl0ZUFycmF5ICk9PiB7XG4gICAgICAgICAgICByZWNlaXZpbmdFbmRQb2ludC5zZW5kTWVzc2FnZSggbmV3IE1lc3NhZ2U8Qnl0ZUFycmF5PiggcmVwbHlIZWFkZXIsIG5ldyBCeXRlQXJyYXkoKSApICk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFwicG93ZXJPblwiOlxuICAgICAgICByZXNwb25zZSA9IHRoaXMuc2xvdC5wb3dlck9uKClcbiAgICAgICAgICAudGhlbiggKCByZXNwRGF0YTogQnl0ZUFycmF5ICk9PiB7XG4gICAgICAgICAgICByZWNlaXZpbmdFbmRQb2ludC5zZW5kTWVzc2FnZSggbmV3IE1lc3NhZ2U8Qnl0ZUFycmF5PiggcmVwbHlIZWFkZXIsIHJlc3BEYXRhICkgKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgXCJyZXNldFwiOlxuICAgICAgICByZXNwb25zZSA9IHRoaXMuc2xvdC5yZXNldCgpXG4gICAgICAgICAgLnRoZW4oICggcmVzcERhdGE6IEJ5dGVBcnJheSApPT4ge1xuICAgICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIG5ldyBNZXNzYWdlPEJ5dGVBcnJheT4oIHJlcGx5SGVhZGVyLCByZXNwRGF0YSApICk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICByZXNwb25zZSA9IFByb21pc2UucmVqZWN0PEVycm9yPiggbmV3IEVycm9yKCBcIkludmFsaWQgbWV0aG9kXCIgKyBoZHIubWV0aG9kICkgKTtcbiAgICAgICAgYnJlYWs7XG4gICAgfSAvLyBzd2l0Y2hcblxuICAgIC8vIHRyYXAgYW5kIHJldHVybiBhbnkgZXJyb3JzXG4gICAgcmVzcG9uc2UuY2F0Y2goICggZTogYW55ICkgPT4ge1xuICAgICAgbGV0IGVycm9yUGFja2V0ID0gbmV3IE1lc3NhZ2U8RXJyb3I+KCB7IG1ldGhvZDogXCJlcnJvclwiIH0sIGUgKTtcblxuICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIGVycm9yUGFja2V0ICk7XG4gICAgfSk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuY2xhc3MgSlNTaW11bGF0ZWRTbG90XHJcbntcclxuICBjYXJkV29ya2VyO1xyXG4gIG9uQVBEVVJlc3BvbnNlO1xyXG4gIHN0b3A7XHJcblxyXG4gIE9uTWVzc2FnZShlKVxyXG4gIHtcclxuICAgIGlmICh0aGlzLnN0b3ApIHJldHVybjtcclxuXHJcbiAgICBpZiAoZS5kYXRhLmNvbW1hbmQgPT0gXCJkZWJ1Z1wiKVxyXG4gICAge1xyXG4gICAgICBjb25zb2xlLmxvZyhlLmRhdGEuZGF0YSk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmIChlLmRhdGEuY29tbWFuZCA9PSBcImV4ZWN1dGVBUERVXCIpXHJcbiAgICB7XHJcbiAgICAgIC8vIGNvbnNvbGUubG9nKCBuZXcgQnl0ZVN0cmluZyggZS5kYXRhLmRhdGEgKS50b1N0cmluZygpICk7XHJcblxyXG4gICAgICBpZiAoIHRoaXMub25BUERVUmVzcG9uc2UgKVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIGJzID0gPFVpbnQ4QXJyYXk+ZS5kYXRhLmRhdGEsIGxlbiA9IGJzLmxlbmd0aDtcclxuXHJcbiAgICAgICAgdGhpcy5vbkFQRFVSZXNwb25zZSggKCBic1sgbGVuIC0gMiBdIDw8IDggKSB8IGJzWyBsZW4gLSAxIF0sICggbGVuID4gMiApID8gbmV3IEJ5dGVBcnJheSggYnMuc3ViYXJyYXkoIDAsIGxlbi0yICkgKSA6IG51bGwgKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgZWxzZVxyXG4gICAge1xyXG4gICAgICBjb25zb2xlLmxvZyggXCJjbWQ6IFwiICsgZS5kYXRhLmNvbW1hbmQgKyBcIiBkYXRhOiBcIiArIGUuZGF0YS5kYXRhICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBpbml0KClcclxuICB7XHJcbiAgICB0aGlzLmNhcmRXb3JrZXIgPSBuZXcgV29ya2VyKCBcImpzL1NtYXJ0Q2FyZFNsb3RTaW11bGF0b3IvU21hcnRDYXJkU2xvdFdvcmtlci5qc1wiICk7XHJcbiAgICB0aGlzLmNhcmRXb3JrZXIub25tZXNzYWdlID0gdGhpcy5Pbk1lc3NhZ2UuYmluZCggdGhpcyApO1xyXG5cclxuICAgIHRoaXMuY2FyZFdvcmtlci5vbmVycm9yID0gZnVuY3Rpb24oZTogRXZlbnQpXHJcbiAgICB7XHJcbiAgICAgIC8vYWxlcnQoIFwiRXJyb3IgYXQgXCIgKyBlLmZpbGVuYW1lICsgXCI6XCIgKyBlLmxpbmVubyArIFwiOiBcIiArIGUubWVzc2FnZSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgc2VuZFRvV29ya2VyKCBjb21tYW5kLCBkYXRhIClcclxuICB7XHJcbiAgICB0aGlzLmNhcmRXb3JrZXIucG9zdE1lc3NhZ2UoXHJcbiAgICAgIHtcclxuICAgICAgICBcImNvbW1hbmRcIjogY29tbWFuZCxcclxuICAgICAgICBcImRhdGFcIjogZGF0YVxyXG4gICAgICB9XHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZUFQRFVDb21tYW5kKCBiQ0xBLCBiSU5TLCBiUDEsIGJQMiwgY29tbWFuZERhdGEsIHdMZSwgb25BUERVUmVzcG9uc2UgKVxyXG4gIHtcclxuICAgIHZhciBjbWQgPSBbIGJDTEEsIGJJTlMsIGJQMSwgYlAyIF07XHJcbiAgICB2YXIgbGVuID0gNDtcclxuICAgIHZhciBic0NvbW1hbmREYXRhID0gKCBjb21tYW5kRGF0YSBpbnN0YW5jZW9mIEJ5dGVBcnJheSApID8gY29tbWFuZERhdGEgOiBuZXcgQnl0ZUFycmF5KCBjb21tYW5kRGF0YSwgQnl0ZUFycmF5LkhFWCApO1xyXG4gICAgaWYgKCBic0NvbW1hbmREYXRhLmxlbmd0aCA+IDAgKVxyXG4gICAge1xyXG4gICAgICBjbWRbbGVuKytdID0gYnNDb21tYW5kRGF0YS5sZW5ndGg7XHJcbiAgICAgIGZvciggdmFyIGkgPSAwOyBpIDwgYnNDb21tYW5kRGF0YS5sZW5ndGg7ICsraSApXHJcbiAgICAgICAgY21kW2xlbisrXSA9IGJzQ29tbWFuZERhdGEuYnl0ZUF0KCBpICk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggd0xlICE9IHVuZGVmaW5lZCApXHJcbiAgICAgICAgY21kW2xlbisrXSA9IHdMZSAmIDB4RkY7XHJcblxyXG4gICAgdGhpcy5zZW5kVG9Xb3JrZXIoIFwiZXhlY3V0ZUFQRFVcIiwgY21kICk7XHJcblxyXG4gICAgdGhpcy5vbkFQRFVSZXNwb25zZSA9IG9uQVBEVVJlc3BvbnNlO1xyXG5cclxuICAgIC8vIG9uIHN1Y2Nlc3MvZmFpbHVyZSwgd2lsbCBjYWxsYmFja1xyXG4gICAgLy8gaWYgKCByZXNwID09IG51bGwgKVxyXG4gICAgcmV0dXJuO1xyXG4gIH1cclxufVxyXG4iLG51bGwsImltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuLi9pc283ODE2L0lTTzc4MTYnO1xyXG5pbXBvcnQgeyBDb21tYW5kQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvY29tbWFuZC1hcGR1JztcclxuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9yZXNwb25zZS1hcGR1JztcclxuXHJcbmV4cG9ydCBjbGFzcyBKU0lNU2NyaXB0QXBwbGV0XHJcbntcclxuICBzZWxlY3RBcHBsaWNhdGlvbiggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVICk6IFByb21pc2U8UmVzcG9uc2VBUERVPlxyXG4gIHtcclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmU8UmVzcG9uc2VBUERVPiggbmV3IFJlc3BvbnNlQVBEVSggeyBzdzogMHg5MDAwIH0gKSApO1xyXG4gIH1cclxuXHJcbiAgZGVzZWxlY3RBcHBsaWNhdGlvbigpXHJcbiAge1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cclxuICB7XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4NkQwMCB9ICkgKTtcclxuICB9XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuLi9pc283ODE2L0lTTzc4MTYnO1xuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9pc283ODE2L2NvbW1hbmQtYXBkdSc7XG5pbXBvcnQgeyBSZXNwb25zZUFQRFUgfSBmcm9tICcuLi9pc283ODE2L3Jlc3BvbnNlLWFwZHUnO1xuXG5pbXBvcnQgeyBKU0lNQ2FyZCB9IGZyb20gJy4vanNpbS1jYXJkJztcbmltcG9ydCB7IEpTSU1TY3JpcHRBcHBsZXQgfSBmcm9tICcuL2pzaW0tc2NyaXB0LWFwcGxldCc7XG5cbmV4cG9ydCBjbGFzcyBKU0lNU2NyaXB0Q2FyZCBpbXBsZW1lbnRzIEpTSU1DYXJkXG57XG4gIHByaXZhdGUgX3Bvd2VySXNPbjogYm9vbGVhbjtcbiAgcHJpdmF0ZSBfYXRyOiBCeXRlQXJyYXk7XG5cbiAgYXBwbGV0czogeyBhaWQ6IEJ5dGVBcnJheSwgYXBwbGV0OiBKU0lNU2NyaXB0QXBwbGV0IH1bXSA9IFtdO1xuXG4gIHNlbGVjdGVkQXBwbGV0OiBKU0lNU2NyaXB0QXBwbGV0O1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMuX2F0ciA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XG4gIH1cblxuICBsb2FkQXBwbGljYXRpb24oIGFpZDogQnl0ZUFycmF5LCBhcHBsZXQ6IEpTSU1TY3JpcHRBcHBsZXQgKVxuICB7XG4gICAgdGhpcy5hcHBsZXRzLnB1c2goIHsgYWlkOiBhaWQsIGFwcGxldDogYXBwbGV0IH0gKTtcbiAgfVxuXG4gIGdldCBpc1Bvd2VyZWQoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Bvd2VySXNPbjtcbiAgfVxuXG4gIHBvd2VyT24oKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICB0aGlzLl9wb3dlcklzT24gPSB0cnVlO1xuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxCeXRlQXJyYXk+KCB0aGlzLl9hdHIgKTtcbiAgfVxuXG4gIHBvd2VyT2ZmKCk6IFByb21pc2U8YW55PlxuICB7XG4gICAgdGhpcy5fcG93ZXJJc09uID0gZmFsc2U7XG5cbiAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICB9XG5cbiAgcmVzZXQoKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICB0aGlzLl9wb3dlcklzT24gPSB0cnVlO1xuXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcblxuICAgIC8vIFRPRE86IFJlc2V0XG5cbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPEJ5dGVBcnJheT4oIHRoaXMuX2F0ciApO1xuICB9XG5cbiAgZXhjaGFuZ2VBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XG4gIHtcbiAgICBpZiAoIGNvbW1hbmRBUERVLklOUyA9PSAweEE0IClcbiAgICB7XG4gICAgICBpZiAoIHRoaXMuc2VsZWN0ZWRBcHBsZXQgKVxuICAgICAge1xuICAgICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0LmRlc2VsZWN0QXBwbGljYXRpb24oKTtcblxuICAgICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xuICAgICAgfVxuXG4gICAgICAvL1RPRE86IExvb2t1cCBBcHBsaWNhdGlvblxuICAgICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHRoaXMuYXBwbGV0c1sgMCBdLmFwcGxldDtcblxuICAgICAgcmV0dXJuIHRoaXMuc2VsZWN0ZWRBcHBsZXQuc2VsZWN0QXBwbGljYXRpb24oIGNvbW1hbmRBUERVICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc2VsZWN0ZWRBcHBsZXQuZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBTbG90IH0gZnJvbSAnLi4vaXNvNzgxNi9zbG90JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9yZXNwb25zZS1hcGR1JztcbmltcG9ydCB7IEpTSU1DYXJkIH0gZnJvbSAnLi9qc2ltLWNhcmQnO1xuXG5leHBvcnQgY2xhc3MgSlNJTVNsb3QgaW1wbGVtZW50cyBTbG90XG57XG4gIHB1YmxpYyBjYXJkOiBKU0lNQ2FyZDtcblxuICBjb25zdHJ1Y3RvciggY2FyZD86IEpTSU1DYXJkIClcbiAge1xuICAgIHRoaXMuY2FyZCA9IGNhcmQ7XG4gIH1cblxuICBnZXQgaXNQcmVzZW50KCk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiAhIXRoaXMuY2FyZDtcbiAgfVxuXG4gIGdldCBpc1Bvd2VyZWQoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuaXNQcmVzZW50ICYmIHRoaXMuY2FyZC5pc1Bvd2VyZWQ7XG4gIH1cblxuICBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgaWYgKCAhdGhpcy5pc1ByZXNlbnQgKVxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIG5ldyBFcnJvciggXCJKU0lNOiBDYXJkIG5vdCBwcmVzZW50XCIgKSApO1xuXG4gICAgcmV0dXJuIHRoaXMuY2FyZC5wb3dlck9uKCk7XG4gIH1cblxuICBwb3dlck9mZigpOiBQcm9taXNlPEJ5dGVBcnJheT5cbiAge1xuICAgIGlmICggIXRoaXMuaXNQcmVzZW50IClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBuZXcgRXJyb3IoIFwiSlNJTTogQ2FyZCBub3QgcHJlc2VudFwiICkgKTtcblxuICAgIHJldHVybiB0aGlzLmNhcmQucG93ZXJPZmYoKTtcbiAgfVxuXG4gIHJlc2V0KCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgaWYgKCAhdGhpcy5pc1ByZXNlbnQgKVxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIG5ldyBFcnJvciggXCJKU0lNOiBDYXJkIG5vdCBwcmVzZW50XCIgKSApO1xuXG4gICAgcmV0dXJuIHRoaXMuY2FyZC5yZXNldCgpO1xuICB9XG5cbiAgZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cbiAge1xuICAgIGlmICggIXRoaXMuaXNQcmVzZW50IClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxSZXNwb25zZUFQRFU+KCBuZXcgRXJyb3IoIFwiSlNJTTogQ2FyZCBub3QgcHJlc2VudFwiICkgKTtcblxuICAgIGlmICggIXRoaXMuaXNQb3dlcmVkIClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxSZXNwb25zZUFQRFU+KCBuZXcgRXJyb3IoIFwiSlNJTTogQ2FyZCB1bnBvd2VyZWRcIiApICk7XG5cbiAgICByZXR1cm4gdGhpcy5jYXJkLmV4Y2hhbmdlQVBEVSggY29tbWFuZEFQRFUgKTtcbiAgfVxuXG4gIGluc2VydENhcmQoIGNhcmQ6IEpTSU1DYXJkIClcbiAge1xuICAgIGlmICggdGhpcy5jYXJkIClcbiAgICAgIHRoaXMuZWplY3RDYXJkKCk7XG5cbiAgICB0aGlzLmNhcmQgPSBjYXJkO1xuICB9XG5cbiAgZWplY3RDYXJkKClcbiAge1xuICAgIGlmICggdGhpcy5jYXJkIClcbiAgICB7XG4gICAgICBpZiAoIHRoaXMuY2FyZC5pc1Bvd2VyZWQgKVxuICAgICAgICB0aGlzLmNhcmQucG93ZXJPZmYoKTtcblxuICAgICAgdGhpcy5jYXJkID0gdW5kZWZpbmVkO1xuICAgIH1cbiAgfVxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gaGV4MiggdmFsICkgeyByZXR1cm4gKCBcIjAwXCIgKyB2YWwudG9TdHJpbmcoIDE2ICkudG9VcHBlckNhc2UoKSApLnN1YnN0ciggLTIgKTsgfVxyXG5leHBvcnQgZnVuY3Rpb24gaGV4NCggdmFsICkgeyByZXR1cm4gKCBcIjAwMDBcIiArIHZhbC50b1N0cmluZyggMTYgKS50b1VwcGVyQ2FzZSgpICkuc3Vic3RyKCAtNCApOyB9XHJcblxyXG5leHBvcnQgZW51bSBNRU1GTEFHUyB7XHJcbiAgUkVBRF9PTkxZID0gMSA8PCAwLFxyXG4gIFRSQU5TQUNUSU9OQUJMRSA9IDEgPDwgMSxcclxuICBUUkFDRSA9IDEgPDwgMlxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgU2VnbWVudFxyXG57XHJcbiAgcHJpdmF0ZSBtZW1EYXRhOiBCeXRlQXJyYXk7XHJcbiAgcHJpdmF0ZSBtZW1UeXBlO1xyXG4gIHByaXZhdGUgcmVhZE9ubHk7XHJcbiAgcHJpdmF0ZSBmbGFncztcclxuICBwcml2YXRlIGluVHJhbnNhY3Rpb24gPSBmYWxzZTtcclxuICBwcml2YXRlIHRyYW5zQmxvY2tzID0gW107XHJcbiAgbWVtVHJhY2VzO1xyXG5cclxuICBjb25zdHJ1Y3Rvciggc2VnVHlwZSwgc2l6ZSwgZmxhZ3M/LCBiYXNlPzogQnl0ZUFycmF5IClcclxuICB7XHJcbiAgICB0aGlzLm1lbVR5cGUgPSBzZWdUeXBlO1xyXG4gICAgdGhpcy5yZWFkT25seSA9ICggZmxhZ3MgJiBNRU1GTEFHUy5SRUFEX09OTFkgKSA/IHRydWUgOiBmYWxzZTtcclxuXHJcbiAgICBpZiAoIGJhc2UgKVxyXG4gICAge1xyXG4gICAgICB0aGlzLm1lbURhdGEgPSBuZXcgQnl0ZUFycmF5KCBiYXNlIClcclxuICAgIH1cclxuICAgIGVsc2VcclxuICAgIHtcclxuICAgICAgdGhpcy5tZW1EYXRhID0gbmV3IEJ5dGVBcnJheSggW10gKS5zZXRMZW5ndGgoIHNpemUgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGdldFR5cGUoKSB7IHJldHVybiB0aGlzLm1lbVR5cGU7IH1cclxuICBnZXRMZW5ndGgoKSB7IHJldHVybiB0aGlzLm1lbURhdGEubGVuZ3RoOyB9XHJcbiAgZ2V0RmxhZ3MoKSB7IHJldHVybiB0aGlzLmZsYWdzOyB9XHJcbiAgZ2V0RGVidWcoKSB7IHJldHVybiB7IG1lbURhdGE6IHRoaXMubWVtRGF0YSwgbWVtVHlwZTogdGhpcy5tZW1UeXBlLCByZWFkT25seTogdGhpcy5yZWFkT25seSwgaW5UcmFuc2FjdGlvbjogdGhpcy5pblRyYW5zYWN0aW9uLCB0cmFuc0Jsb2NrczogdGhpcy50cmFuc0Jsb2NrcyB9OyB9XHJcblxyXG4gIGJlZ2luVHJhbnNhY3Rpb24oKVxyXG4gIHtcclxuICAgIHRoaXMuaW5UcmFuc2FjdGlvbiA9IHRydWU7XHJcbiAgICB0aGlzLnRyYW5zQmxvY2tzID0gW107XHJcbiAgfVxyXG5cclxuICBlbmRUcmFuc2FjdGlvbiggY29tbWl0IClcclxuICB7XHJcbiAgICBpZiAoICFjb21taXQgJiYgdGhpcy5pblRyYW5zYWN0aW9uIClcclxuICAgIHtcclxuICAgICAgdGhpcy5pblRyYW5zYWN0aW9uID0gZmFsc2U7XHJcblxyXG4gICAgICAvLyByb2xsYmFjayB0cmFuc2FjdGlvbnNcclxuICAgICAgZm9yKCB2YXIgaT0wOyBpIDwgdGhpcy50cmFuc0Jsb2Nrcy5sZW5ndGg7IGkrKyApXHJcbiAgICAgIHtcclxuICAgICAgICB2YXIgYmxvY2sgPSB0aGlzLnRyYW5zQmxvY2tzWyBpIF07XHJcblxyXG4gICAgICAgIHRoaXMud3JpdGVCeXRlcyggYmxvY2suYWRkciwgYmxvY2suZGF0YSApO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFuc0Jsb2NrcyA9IFtdO1xyXG4gIH1cclxuXHJcbiAgcmVhZEJ5dGUoIGFkZHIgKVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLm1lbURhdGFbIGFkZHIgXTtcclxuICB9XHJcblxyXG4gIHplcm9CeXRlcyggYWRkciwgbGVuIClcclxuICB7XHJcbiAgICBmb3IoIHZhciBpID0gMDsgaSA8IGxlbjsgKytpIClcclxuICAgICAgdGhpcy5tZW1EYXRhWyBhZGRyICsgaSBdID0gMDtcclxuICB9XHJcblxyXG4gIHJlYWRCeXRlcyggYWRkciwgbGVuICk6IEJ5dGVBcnJheVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLm1lbURhdGEudmlld0F0KCBhZGRyLCBsZW4gKTtcclxuICB9XHJcblxyXG4gIGNvcHlCeXRlcyggZnJvbUFkZHIsIHRvQWRkciwgbGVuIClcclxuICB7XHJcbiAgICB0aGlzLndyaXRlQnl0ZXMoIHRvQWRkciwgdGhpcy5yZWFkQnl0ZXMoIGZyb21BZGRyLCBsZW4gKSApO1xyXG4gIH1cclxuXHJcbiAgd3JpdGVCeXRlcyggYWRkcjogbnVtYmVyLCB2YWw6IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgaWYgKCB0aGlzLmluVHJhbnNhY3Rpb24gJiYgKCB0aGlzLmZsYWdzICYgTUVNRkxBR1MuVFJBTlNBQ1RJT05BQkxFICkgKVxyXG4gICAge1xyXG4gICAgICAvLyBzYXZlIHByZXZpb3VzIEVFUFJPTSBjb250ZW50c1xyXG4gICAgICB0aGlzLnRyYW5zQmxvY2tzLnB1c2goIHsgYWRkcjogYWRkciwgZGF0YTogdGhpcy5yZWFkQnl0ZXMoIGFkZHIsIHZhbC5sZW5ndGggKSB9ICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5tZW1EYXRhLnNldEJ5dGVzQXQoIGFkZHIsIHZhbCApO1xyXG4gIH1cclxuXHJcbiAgbmV3QWNjZXNzb3IoIGFkZHIsIGxlbiwgbmFtZSApOiBBY2Nlc3NvclxyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQWNjZXNzb3IoIHRoaXMsIGFkZHIsIGxlbiwgbmFtZSApO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIEFjY2Vzc29yXHJcbntcclxuICBvZmZzZXQ6IG51bWJlcjtcclxuICBsZW5ndGg6IG51bWJlcjtcclxuICBpZDogc3RyaW5nO1xyXG4gIHNlZzogU2VnbWVudDtcclxuXHJcbiAgY29uc3RydWN0b3IoIHNlZywgYWRkciwgbGVuLCBuYW1lIClcclxuICB7XHJcbiAgICB0aGlzLnNlZyA9IHNlZztcclxuXHJcbiAgICB0aGlzLm9mZnNldCA9IGFkZHI7XHJcbiAgICB0aGlzLmxlbmd0aCA9IGxlbjtcclxuICAgIHRoaXMuaWQgPSBuYW1lO1xyXG4gIH1cclxuXHJcbiAgdHJhY2VNZW1vcnlPcCggb3AsIGFkZHIsIGxlbiwgYWRkcjI/IClcclxuICB7XHJcbiAgICBpZiAoIHRoaXMuaWQgIT0gXCJjb2RlXCIgKVxyXG4gICAgICB0aGlzLnNlZy5tZW1UcmFjZXMucHVzaCggeyBvcDogb3AsIG5hbWU6IHRoaXMuaWQsIGFkZHI6IGFkZHIsIGxlbjogbGVuLCBhZGRyMjogYWRkcjIgfSApO1xyXG4gIH1cclxuXHJcbiAgdHJhY2VNZW1vcnlWYWx1ZSggdmFsIClcclxuICB7XHJcbiAgICBpZiAoIHRoaXMuaWQgIT0gXCJjb2RlXCIgKVxyXG4gICAge1xyXG4gICAgICB2YXIgbWVtVHJhY2UgPSB0aGlzLnNlZy5tZW1UcmFjZXNbIHRoaXMuc2VnLm1lbVRyYWNlcy5sZW5ndGggLSAxIF07XHJcblxyXG4gICAgICBtZW1UcmFjZS52YWwgPSB2YWw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICB6ZXJvQnl0ZXMoIGFkZHI6IG51bWJlciwgbGVuOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIGlmICggYWRkciArIGxlbiA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlpSLWVycm9yXCIsIGFkZHIsIHRoaXMubGVuZ3RoICk7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvciggXCJNTTogSW52YWxpZCBaZXJvXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiWlJcIiwgYWRkciwgbGVuICk7XHJcbiAgICB0aGlzLnNlZy56ZXJvQnl0ZXMoIHRoaXMub2Zmc2V0ICsgYWRkciwgbGVuICk7XHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIFsgMCBdICk7XHJcbiAgfVxyXG5cclxuICByZWFkQnl0ZSggYWRkcjogbnVtYmVyICk6IG51bWJlclxyXG4gIHtcclxuICAgIGlmICggYWRkciArIDEgPiB0aGlzLmxlbmd0aCApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJSRC1lcnJvclwiLCBhZGRyLCAxICk7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvciggXCJNTTogSW52YWxpZCBSZWFkXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiUkRcIiwgYWRkciwgMSApO1xyXG5cclxuICAgIHZhciB2YWwgPSB0aGlzLnNlZy5yZWFkQnl0ZSggdGhpcy5vZmZzZXQgKyBhZGRyICk7XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCBbIHZhbCBdKTtcclxuXHJcbiAgICByZXR1cm4gdmFsO1xyXG4gIH1cclxuXHJcbiAgcmVhZEJ5dGVzKCBhZGRyLCBsZW4gKTogQnl0ZUFycmF5XHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgbGVuID4gdGhpcy5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiUkQtZXJyb3JcIiwgYWRkciwgbGVuICk7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvciggXCJNTTogSW52YWxpZCBSZWFkXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiUkRcIiwgYWRkciwgbGVuICk7XHJcbiAgICB2YXIgdmFsID0gdGhpcy5zZWcucmVhZEJ5dGVzKCB0aGlzLm9mZnNldCArIGFkZHIsIGxlbiApO1xyXG4gICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCB2YWwgKTtcclxuXHJcbiAgICByZXR1cm4gdmFsO1xyXG4gIH1cclxuXHJcbiAgY29weUJ5dGVzKCBmcm9tQWRkcjogbnVtYmVyLCB0b0FkZHI6IG51bWJlciwgbGVuOiBudW1iZXIgKTogQnl0ZUFycmF5XHJcbiAge1xyXG4gICAgaWYgKCAoIGZyb21BZGRyICsgbGVuID4gdGhpcy5sZW5ndGggKSB8fCAoIHRvQWRkciArIGxlbiA+IHRoaXMubGVuZ3RoICkgKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiQ1AtZXJyb3JcIiwgZnJvbUFkZHIsIGxlbiwgdG9BZGRyICk7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvciggXCJNTTogSW52YWxpZCBSZWFkXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICAvL2lmICggbWVtVHJhY2luZyApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJDUFwiLCBmcm9tQWRkciwgbGVuLCB0b0FkZHIgKTtcclxuICAgICAgdmFyIHZhbCA9IHRoaXMuc2VnLnJlYWRCeXRlcyggdGhpcy5vZmZzZXQgKyBmcm9tQWRkciwgbGVuICk7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggdmFsICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5zZWcuY29weUJ5dGVzKCB0aGlzLm9mZnNldCArIGZyb21BZGRyLCB0aGlzLm9mZnNldCArIHRvQWRkciwgbGVuICk7XHJcbiAgICByZXR1cm4gdmFsO1xyXG4gIH1cclxuXHJcbiAgd3JpdGVCeXRlKCBhZGRyOiBudW1iZXIsIHZhbDogbnVtYmVyIClcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyAxID4gdGhpcy5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiV1ItZXJyb3JcIiwgYWRkciwgMSApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgV3JpdGVcIiApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJXUlwiLCBhZGRyLCAxICk7XHJcbiAgICB0aGlzLnNlZy53cml0ZUJ5dGVzKCB0aGlzLm9mZnNldCArIGFkZHIsIG5ldyBCeXRlQXJyYXkoIFsgdmFsIF0gKSApO1xyXG4gICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCBbIHZhbCBdICk7XHJcbiAgfVxyXG5cclxuICB3cml0ZUJ5dGVzKCBhZGRyOiBudW1iZXIsIHZhbDogQnl0ZUFycmF5IClcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyB2YWwubGVuZ3RoID4gdGhpcy5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiV1ItZXJyb3JcIiwgYWRkciwgdmFsLmxlbmd0aCApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgV3JpdGVcIiApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJXUlwiLCBhZGRyLCB2YWwubGVuZ3RoICk7XHJcbiAgICB0aGlzLnNlZy53cml0ZUJ5dGVzKCB0aGlzLm9mZnNldCArIGFkZHIsIHZhbCApO1xyXG4gICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCB2YWwgKTtcclxuICB9XHJcblxyXG4gIGdldFR5cGUoKSB7IHJldHVybiB0aGlzLnNlZy5nZXRUeXBlKCk7IH1cclxuICBnZXRMZW5ndGgoKSB7IHJldHVybiB0aGlzLmxlbmd0aDsgfVxyXG4gIGdldElEKCkgeyByZXR1cm4gdGhpcy5pZDsgfVxyXG4vLyAgICAgICAgYmVnaW5UcmFuc2FjdGlvbjogYmVnaW5UcmFuc2FjdGlvbixcclxuLy8gICAgICAgIGluVHJhbnNhY3Rpb246IGZ1bmN0aW9uKCkgeyByZXR1cm4gaW5UcmFuc2FjdGlvbjsgfSxcclxuLy8gICAgICAgIGVuZFRyYW5zYWN0aW9uOiBlbmRUcmFuc2FjdGlvbixcclxuICBnZXREZWJ1ZygpIHsgcmV0dXJuIHsgb2Zmc2V0OiB0aGlzLm9mZnNldCwgbGVuZ3RoOiB0aGlzLmxlbmd0aCwgc2VnOiB0aGlzLnNlZyB9OyB9XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNsaWNlRGF0YSggYmFzZSwgb2Zmc2V0LCBzaXplICk6IFVpbnQ4QXJyYXlcclxue1xyXG4gIHJldHVybiBiYXNlLnN1YmFycmF5KCBvZmZzZXQsIG9mZnNldCArIHNpemUgKTtcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE1lbW9yeU1hbmFnZXJcclxue1xyXG4gIHByaXZhdGUgbWVtb3J5U2VnbWVudHMgPSBbXTtcclxuXHJcbiAgcHJpdmF0ZSBtZW1UcmFjZXMgPSBbXTtcclxuXHJcbiAgbmV3U2VnbWVudCggbWVtVHlwZSwgc2l6ZSwgZmxhZ3M/ICApOiBTZWdtZW50XHJcbiAge1xyXG4gICAgbGV0IG5ld1NlZyA9IG5ldyBTZWdtZW50KCBtZW1UeXBlLCBzaXplLCBmbGFncyApO1xyXG5cclxuICAgIHRoaXMubWVtb3J5U2VnbWVudHNbIG1lbVR5cGUgXSA9IG5ld1NlZztcclxuXHJcbiAgICBuZXdTZWcubWVtVHJhY2VzID0gdGhpcy5tZW1UcmFjZXM7XHJcblxyXG4gICAgcmV0dXJuIG5ld1NlZztcclxuICB9XHJcblxyXG4gIGdldE1lbVRyYWNlKCkgeyByZXR1cm4gdGhpcy5tZW1UcmFjZXM7IH1cclxuXHJcbiAgaW5pdE1lbVRyYWNlKCkgeyB0aGlzLm1lbVRyYWNlcyA9IFtdOyB9XHJcblxyXG4gIGdldFNlZ21lbnQoIHR5cGUgKSB7IHJldHVybiB0aGlzLm1lbW9yeVNlZ21lbnRzWyB0eXBlIF07IH1cclxufVxyXG4iLCJleHBvcnQgZW51bSBNRUxJTlNUIHtcclxuICBtZWxTWVNURU0gPSAgMHgwMCxcclxuICBtZWxCUkFOQ0ggPSAgMHgwMSxcclxuICBtZWxKVU1QID0gICAgMHgwMixcclxuICBtZWxDQUxMID0gICAgMHgwMyxcclxuICBtZWxTVEFDSyA9ICAgMHgwNCxcclxuICBtZWxQUklNUkVUID0gMHgwNSxcclxuICBtZWxJTlZBTElEID0gMHgwNixcclxuICBtZWxMT0FEID0gICAgMHgwNyxcclxuICBtZWxTVE9SRSA9ICAgMHgwOCxcclxuICBtZWxMT0FESSA9ICAgMHgwOSxcclxuICBtZWxTVE9SRUkgPSAgMHgwQSxcclxuICBtZWxMT0FEQSA9ICAgMHgwQixcclxuICBtZWxJTkRFWCA9ICAgMHgwQyxcclxuICBtZWxTRVRCID0gICAgMHgwRCxcclxuICBtZWxDTVBCID0gICAgMHgwRSxcclxuICBtZWxBRERCID0gICAgMHgwRixcclxuICBtZWxTVUJCID0gICAgMHgxMCxcclxuICBtZWxTRVRXID0gICAgMHgxMSxcclxuICBtZWxDTVBXID0gICAgMHgxMixcclxuICBtZWxBRERXID0gICAgMHgxMyxcclxuICBtZWxTVUJXID0gICAgMHgxNCxcclxuICBtZWxDTEVBUk4gPSAgMHgxNSxcclxuICBtZWxURVNUTiA9ICAgMHgxNixcclxuICBtZWxJTkNOID0gICAgMHgxNyxcclxuICBtZWxERUNOID0gICAgMHgxOCxcclxuICBtZWxOT1ROID0gICAgMHgxOSxcclxuICBtZWxDTVBOID0gICAgMHgxQSxcclxuICBtZWxBREROID0gICAgMHgxQixcclxuICBtZWxTVUJOID0gICAgMHgxQyxcclxuICBtZWxBTkROID0gICAgMHgxRCxcclxuICBtZWxPUk4gPSAgICAgMHgxRSxcclxuICBtZWxYT1JOID0gICAgMHgxRlxyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHQUREUiB7XHJcbiAgbWVsQWRkclRPUyA9IDB4MDAsXHJcbiAgbWVsQWRkclNCID0gIDB4MDEsXHJcbiAgbWVsQWRkclNUID0gIDB4MDIsXHJcbiAgbWVsQWRkckRCID0gIDB4MDMsXHJcbiAgbWVsQWRkckxCID0gIDB4MDQsXHJcbiAgbWVsQWRkckRUID0gIDB4MDUsXHJcbiAgbWVsQWRkclBCID0gIDB4MDYsXHJcbiAgbWVsQWRkclBUID0gIDB4MDdcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFRBR0NPTkQge1xyXG4gIG1lbENvbmRTUEVDID0gIDB4MDAsIC8vIFNwZWNpYWxcclxuICBtZWxDb25kRVEgPSAgICAweDAxLCAvLyBFcXVhbFxyXG4gIG1lbENvbmRMVCA9ICAgIDB4MDIsIC8vIExlc3MgdGhhblxyXG4gIG1lbENvbmRMRSA9ICAgIDB4MDMsIC8vIExlc3MgdGhhbiwgZXF1YWwgdG9cclxuICBtZWxDb25kR1QgPSAgICAweDA0LCAvLyBHcmVhdGVyIHRoYW5cclxuICBtZWxDb25kR0UgPSAgICAweDA1LCAvLyBHcmVhdGVyIHRoYW4sIGVxdWFsIHRvXHJcbiAgbWVsQ29uZE5FID0gICAgMHgwNiwgLy8gTm90IGVxdWFsIHRvXHJcbiAgbWVsQ29uZEFMTCA9ICAgMHgwNyAgLy8gQWx3YXlzXHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxUQUdTWVNURU0ge1xyXG4gIG1lbFN5c3RlbU5PUCA9ICAgICAgIDB4MDAsIC8vIE5PUFxyXG4gIG1lbFN5c3RlbVNldFNXID0gICAgIDB4MDEsIC8vIFNFVFNXXHJcbiAgbWVsU3lzdGVtU2V0TGEgPSAgICAgMHgwMiwgLy8gU0VUTEFcclxuICBtZWxTeXN0ZW1TZXRTV0xhID0gICAweDAzLCAvLyBTRVRTV0xBXHJcbiAgbWVsU3lzdGVtRXhpdCA9ICAgICAgMHgwNCwgLy8gRVhJVFxyXG4gIG1lbFN5c3RlbUV4aXRTVyA9ICAgIDB4MDUsIC8vIEVYSVRTV1xyXG4gIG1lbFN5c3RlbUV4aXRMYSA9ICAgIDB4MDYsIC8vIEVYSVRMQVxyXG4gIG1lbFN5c3RlbUV4aXRTV0xhID0gIDB4MDcgIC8vIEVYSVRTV0xBXHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxUQUdTVEFDSyB7XHJcbiAgbWVsU3RhY2tQVVNIWiA9ICAweDAwLCAvLyBQVVNIWlxyXG4gIG1lbFN0YWNrUFVTSEIgPSAgMHgwMSwgLy8gUFVTSEJcclxuICBtZWxTdGFja1BVU0hXID0gIDB4MDIsIC8vIFBVU0hXXHJcbiAgbWVsU3RhY2tYWDQgPSAgICAweDAzLCAvLyBJbGxlZ2FsXHJcbiAgbWVsU3RhY2tQT1BOID0gICAweDA0LCAvLyBQT1BOXHJcbiAgbWVsU3RhY2tQT1BCID0gICAweDA1LCAvLyBQT1BCXHJcbiAgbWVsU3RhY2tQT1BXID0gICAweDA2LCAvLyBQT1BXXHJcbiAgbWVsU3RhY2tYWDcgPSAgICAweDA3ICAvLyBJbGxlZ2FsXHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxUQUdQUklNUkVUIHtcclxuICBtZWxQcmltUmV0UFJJTTAgPSAgMHgwMCwgLy8gUFJJTSAwXHJcbiAgbWVsUHJpbVJldFBSSU0xID0gIDB4MDEsIC8vIFBSSU0gMVxyXG4gIG1lbFByaW1SZXRQUklNMiA9ICAweDAyLCAvLyBQUklNIDJcclxuICBtZWxQcmltUmV0UFJJTTMgPSAgMHgwMywgLy8gUFJJTSAzXHJcbiAgbWVsUHJpbVJldFJFVCA9ICAgIDB4MDQsIC8vIFJFVFxyXG4gIG1lbFByaW1SZXRSRVRJID0gICAweDA1LCAvLyBSRVQgSW5cclxuICBtZWxQcmltUmV0UkVUTyA9ICAgMHgwNiwgLy8gUkVUIE91dFxyXG4gIG1lbFByaW1SZXRSRVRJTyA9ICAweDA3ICAvLyBSRVQgSW5PdXRcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFBBUkFNREVGIHtcclxuICBtZWxQYXJhbURlZk5vbmUgPSAgICAgICAgICAgICAgMHgwMCxcclxuICBtZWxQYXJhbURlZlRvcE9mU3RhY2sgPSAgICAgICAgMHgwMSxcclxuICBtZWxQYXJhbURlZkJ5dGVPcGVyTGVuID0gICAgICAgMHgxMSxcclxuICBtZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgPSAgICAgMHgxMixcclxuICBtZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgPSAgMHgxOCxcclxuICBtZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgPSAgICAgMHgyMCxcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXRTQiA9ICAgICAgMHgyMSxcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXRTVCA9ICAgICAgMHgyMixcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXREQiA9ICAgICAgMHgyMyxcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXRMQiA9ICAgICAgMHgyNCxcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXREVCA9ICAgICAgMHgyNSxcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXRQQiA9ICAgICAgMHgyNixcclxuICBtZWxQYXJhbURlZldvcmRPZmZzZXRQVCA9ICAgICAgMHgyNyxcclxuICBtZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyA9ICAgMHgyOFxyXG59O1xyXG5cclxuZnVuY3Rpb24gTUVMUEFSQU00KCBhLCBiLCBjLCBkICkgICAgICAgIHsgcmV0dXJuICggKGQ8PDI0KSB8IChjPDwxNikgfCAoYjw8OCkgfCAoYTw8MCkgKTsgfVxyXG5mdW5jdGlvbiBPUFRBRzJNRUxJTlNUKCBvcENvZGUsIHRhZyApICAgeyByZXR1cm4gKCAoICggb3BDb2RlICYgMHgxZiApIDw8IDMgKSB8IHRhZyApOyB9XHJcbmV4cG9ydCBmdW5jdGlvbiBNRUwyT1BDT0RFKCBieXRlQ29kZSApICAgICAgICAgeyByZXR1cm4gKCAoIGJ5dGVDb2RlID4+IDMgKSAmIDB4MWYgKTsgfVxyXG5leHBvcnQgZnVuY3Rpb24gTUVMMklOU1QoIGJ5dGVDb2RlICkgICAgICAgICAgIHsgcmV0dXJuIE1FTDJPUENPREUoIGJ5dGVDb2RlICk7IH1cclxuZXhwb3J0IGZ1bmN0aW9uIE1FTDJUQUcoIGJ5dGVDb2RlICkgICAgICAgICAgICB7IHJldHVybiAoIChieXRlQ29kZSkgJiA3ICkgfTtcclxuXHJcbmZ1bmN0aW9uIE1FTFBBUkFNU0laRSggcGFyYW1UeXBlIClcclxue1xyXG4gIHJldHVybiAoIHBhcmFtVHlwZSA9PSBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmUgKVxyXG4gICAgICAgICA/IDBcclxuICAgICAgICAgOiAoIHBhcmFtVHlwZSA8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSkgPyAxIDogMjtcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE1FTFxyXG57XHJcbiAgcHVibGljIHN0YXRpYyBtZWxEZWNvZGUgPSBbXTtcclxuXHJcbiAgcHVibGljIHN0YXRpYyBNRUxJTlNUOiBNRUxJTlNUO1xyXG4gIHB1YmxpYyBzdGF0aWMgTUVMVEFHU1RBQ0s6IE1FTFRBR1NUQUNLO1xyXG4gIHB1YmxpYyBzdGF0aWMgTUVMUEFSQU1ERUY6IE1FTFBBUkFNREVGO1xyXG4gIHB1YmxpYyBzdGF0aWMgTUVMVEFHQUREUjogTUVMVEFHQUREUjtcclxuXHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNldE1lbERlY29kZSggYnl0ZUNvZGU6IG51bWJlciwgaW5zdE5hbWU6IHN0cmluZywgcGFyYW0xPywgcGFyYW0yPywgcGFyYW0zPywgcGFyYW00PyApXHJcbntcclxuICBwYXJhbTEgPSBwYXJhbTEgfHwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lO1xyXG4gIHBhcmFtMiA9IHBhcmFtMiB8fCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmU7XHJcbiAgcGFyYW0zID0gcGFyYW0zIHx8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZTtcclxuICBwYXJhbTQgPSBwYXJhbTQgfHwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lO1xyXG5cclxuICBNRUwubWVsRGVjb2RlWyBieXRlQ29kZSBdID0ge1xyXG4gICAgYnl0ZUNvZGU6IGJ5dGVDb2RlLFxyXG4gICAgaW5zdExlbjogMSArIE1FTFBBUkFNU0laRSggcGFyYW0xICkgKyBNRUxQQVJBTVNJWkUoIHBhcmFtMiApICsgTUVMUEFSQU1TSVpFKCBwYXJhbTMgKSArIE1FTFBBUkFNU0laRSggcGFyYW00ICksXHJcbiAgICBpbnN0TmFtZTogaW5zdE5hbWUsXHJcbiAgICBwYXJhbURlZnM6IE1FTFBBUkFNNCggcGFyYW0xLCBwYXJhbTIsIHBhcmFtMywgcGFyYW00IClcclxuICB9O1xyXG59XHJcblxyXG5mdW5jdGlvbiBzZXRNZWxEZWNvZGVTdGRNb2RlcyggbWVsSW5zdDogTUVMSU5TVCwgaW5zdE5hbWU6IHN0cmluZywgcGFyYW0xRGVmOiBNRUxQQVJBTURFRiApXHJcbntcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclNCICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJTVCApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTVCApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyREIgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0REIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkckxCICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldExCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJEVCApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREVCApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyUEIgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UEIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclBUICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBUICk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBtZWxJbnN0OiBNRUxJTlNULCBpbnN0TmFtZTogc3RyaW5nLCBwYXJhbTFEZWY6IE1FTFBBUkFNREVGIClcclxue1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyVE9TICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmVG9wT2ZTdGFjayApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzKCBtZWxJbnN0LCBpbnN0TmFtZSwgcGFyYW0xRGVmICk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGZpbGxNZWxEZWNvZGUoKVxyXG57XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsTE9BRCwgICBcIkxPQURcIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU1RPUkUsICBcIlNUT1JFXCIsICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsTE9BREksICBcIkxPQURJXCIsICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU1RPUkVJLCBcIlNUT1JFSVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyU0IgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyU1QgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTVCApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyREIgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyTEIgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRMQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyRFQgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREVCApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyUEIgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxMT0FEQSwgTUVMVEFHQUREUi5tZWxBZGRyUFQgKSwgXCJMT0FEQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQVCApO1xyXG5cclxuICBzZXRNZWxEZWNvZGVTdGRNb2RlcyggTUVMSU5TVC5tZWxJTkRFWCwgIFwiSU5ERVhcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcblxyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNFVEIsICAgXCJTRVRCXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbENNUEIsICAgXCJDTVBCXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbEFEREIsICAgXCJBRERCXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNVQkIsICAgXCJTVUJCXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNFVFcsICAgXCJTRVRXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbENNUFcsICAgXCJDTVBXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbEFERFcsICAgXCJBRERXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNVQlcsICAgXCJTVUJXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG5cclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxDTEVBUk4sIFwiQ0xFQVJOXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxURVNUTiwgIFwiVEVTVE5cIiwgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxJTkNOLCAgIFwiSU5DTlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxERUNOLCAgIFwiREVDTlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxOT1ROLCAgIFwiTk9UTlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxDTVBOLCAgIFwiQ01QTlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxBREROLCAgIFwiQURETlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVUJOLCAgIFwiU1VCTlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxBTkROLCAgIFwiQU5ETlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxPUk4sICAgIFwiT1JOXCIsICAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxYT1JOLCAgIFwiWE9STlwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbU5PUCApLCBcIk5PUFwiICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbVNldFNXICksIFwiU0VUU1dcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbVNldExhICksIFwiU0VUTEFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbVNldFNXTGEgKSwgXCJTRVRTV0xBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbUV4aXQgKSwgXCJFWElUXCIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtRXhpdFNXICksIFwiRVhJVFNXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1FeGl0TGEgKSwgXCJFWElUQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtRXhpdFNXTGEgKSwgXCJFWElUU1dMQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG5cclxuICAvLyBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEJSQU5DSCwgbWVsQ29uZFNQRUMgKSwgXCItLS1cIiwgMCwgbWVsQWRkclRPUyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZEVRICksIFwiQkVRXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZExUICksIFwiQkxUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZExFICksIFwiQkxFXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZEdUICksIFwiQkdUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZEdFICksIFwiQkdFXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZE5FICksIFwiQk5FXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxCUkFOQ0gsIE1FTFRBR0NPTkQubWVsQ29uZEFMTCApLCBcIkJBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kU1BFQyApLCBcIkpBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRFUSApLCBcIkpFUVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRMVCApLCBcIkpMVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRMRSApLCBcIkpMRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRHVCApLCBcIkpHVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRHRSApLCBcIkpHRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRORSApLCBcIkpORVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRBTEwgKSwgXCJKQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kU1BFQyApLCBcIkNBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRFUSApLCBcIkNFUVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRMVCApLCBcIkNMVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRMRSApLCBcIkNMRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRHVCApLCBcIkNHVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRHRSApLCBcIkNHRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRORSApLCBcIkNORVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRBTEwgKSwgXCJDQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzcyApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSFogKSwgXCJQVVNIWlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BVU0hCICksIFwiUFVTSEJcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BVU0hXICksIFwiUFVTSFdcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgLy8gc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxTVEFDSywgbWVsU3RhY2tYWDQgKSwgXCItLVwiICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BPUE4gKSwgXCJQT1BOXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QQiApLCBcIlBPUEJcIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BXICksIFwiUE9QV1wiICk7XHJcbiAgLy8gc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxTVEFDSywgbWVsU3RhY2tYWDcgKSwgXCItLVwiICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMCApLCBcIlBSSU1cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0xICksIFwiUFJJTVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMiApLCBcIlBSSU1cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMyApLCBcIlBSSU1cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVCApLCBcIlJFVFwiICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVEkgKSwgXCJSRVRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRPICksIFwiUkVUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUSU8gKSwgXCJSRVRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG59XHJcblxyXG5cclxuZmlsbE1lbERlY29kZSgpO1xyXG5cclxuZXhwb3J0IHZhciBNRUxEZWNvZGUgPSBNRUwubWVsRGVjb2RlO1xyXG5leHBvcnQgY29uc3QgTUVMX0NDUl9aID0gMHgwMTtcclxuZXhwb3J0IGNvbnN0IE1FTF9DQ1JfQyA9IDB4MDI7XHJcbiIsImltcG9ydCAqIGFzIE1FTCBmcm9tICcuL21lbC1kZWZpbmVzJztcclxuaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcblxyXG5pbXBvcnQgeyBDb21tYW5kQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvY29tbWFuZC1hcGR1JztcclxuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9yZXNwb25zZS1hcGR1JztcclxuXHJcbmZ1bmN0aW9uIGhleCggdmFsICkgeyByZXR1cm4gdmFsLnRvU3RyaW5nKCAxNiApOyB9XHJcbmZ1bmN0aW9uIGhleDIoIHZhbCApIHsgcmV0dXJuICggXCIwMFwiICsgdmFsLnRvU3RyaW5nKCAxNiApICkuc3Vic3RyKCAtMiApOyB9XHJcbmZ1bmN0aW9uIGhleDQoIHZhbCApIHsgcmV0dXJuICggXCIwMDAwXCIgKyB2YWwudG9TdHJpbmcoIDE2ICkgKS5zdWJzdHIoIC00ICk7IH1cclxuZnVuY3Rpb24gbGp1c3QoIHN0ciwgdyApIHsgcmV0dXJuICggc3RyICsgQXJyYXkoIHcgKyAxICkuam9pbiggXCIgXCIgKSApLnN1YnN0ciggMCwgdyApOyB9XHJcbmZ1bmN0aW9uIHJqdXN0KCBzdHIsIHcgKSB7IHJldHVybiAoIEFycmF5KCB3ICsgMSApLmpvaW4oIFwiIFwiICkgKyBzdHIgKS5zdWJzdHIoIC13ICk7IH1cclxuXHJcbmZ1bmN0aW9uICAgQkEyVyggdmFsIClcclxue1xyXG4gIHJldHVybiAoIHZhbFsgMCBdIDw8IDggKSB8IHZhbFsgMSBdO1xyXG59XHJcblxyXG5mdW5jdGlvbiAgIFcyQkEoIHZhbCApXHJcbntcclxuXHJcbiAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIFsgdmFsID4+IDgsIHZhbCAmIDB4RkYgXSApO1xyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgTUVMVmlydHVhbE1hY2hpbmUge1xyXG4gIC8vIGNhcmRcclxuICByYW1TZWdtZW50O1xyXG4gIHJvbVNlZ21lbnQ7XHJcblxyXG4gIC8vIGFwcGxpY2F0aW9uXHJcbiAgY29kZUFyZWE7XHJcbiAgc3RhdGljQXJlYTtcclxuICBwdWJsaWNBcmVhO1xyXG4gIGR5bmFtaWNBcmVhO1xyXG4gIHNlc3Npb25TaXplO1xyXG5cclxuICAvLyBleGVjdXRpb25cclxuICBpc0V4ZWN1dGluZztcclxuICBjdXJyZW50SVA7XHJcbiAgbG9jYWxCYXNlO1xyXG4gIGR5bmFtaWNUb3A7XHJcbiAgY29uZGl0aW9uQ29kZVJlZztcclxuXHJcbiAgaW5pdE1WTSggcGFyYW1zIClcclxuICB7XHJcbiAgICB0aGlzLnJvbVNlZ21lbnQgPSBwYXJhbXMucm9tU2VnbWVudDtcclxuICAgIHRoaXMucmFtU2VnbWVudCA9IHBhcmFtcy5yYW1TZWdtZW50O1xyXG5cclxuICAgIHRoaXMucHVibGljQXJlYSA9IHRoaXMucmFtU2VnbWVudC5uZXdBY2Nlc3NvciggMCwgNTEyLCBcIlBcIiApO1xyXG4gIH1cclxuXHJcbiAgZGlzYXNzZW1ibGVDb2RlKCByZXNldElQLCBzdGVwVG9OZXh0SVAgKVxyXG4gIHtcclxuICAgIHZhciBkaXNtVGV4dCA9IFwiXCI7XHJcbiAgICBmdW5jdGlvbiBwcmludCggc3RyICkgeyBkaXNtVGV4dCArPSBzdHI7IH1cclxuXHJcbiAgICBpZiAoIHJlc2V0SVAgKVxyXG4gICAgICB0aGlzLmN1cnJlbnRJUCA9IDA7XHJcblxyXG4gICAgaWYgKCB0aGlzLmN1cnJlbnRJUCA+PSB0aGlzLmNvZGVBcmVhLmdldExlbmd0aCgpIClcclxuICAgICAgcmV0dXJuIG51bGw7XHJcblxyXG4gICAgdHJ5XHJcbiAgICB7XHJcbiAgICAgIHZhciBuZXh0SVAgPSB0aGlzLmN1cnJlbnRJUDtcclxuICAgICAgdmFyIGluc3RCeXRlID0gdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKTtcclxuICAgICAgdmFyIHBhcmFtQ291bnQgPSAwO1xyXG4gICAgICB2YXIgcGFyYW1WYWwgPSBbXTtcclxuICAgICAgdmFyIHBhcmFtRGVmID0gW107XHJcblxyXG4gICAgICB2YXIgbWVsSW5zdCA9IE1FTC5NRUxEZWNvZGVbIGluc3RCeXRlIF07XHJcblxyXG4gICAgICBpZiAoIG1lbEluc3QgPT0gdW5kZWZpbmVkIClcclxuICAgICAge1xyXG4gICAgICAgIHByaW50KCBcIltcIiArIGhleDQoIHRoaXMuY3VycmVudElQICkgKyBcIl0gICAgICAgICAgXCIgKyBsanVzdCggXCJFUlJPUjpcIiArIGhleDIoIGluc3RCeXRlICksIDggKSArIFwiICoqKioqKioqXFxuXCIgKTtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICB2YXIgcGFyYW1EZWZzID0gbWVsSW5zdC5wYXJhbURlZnM7XHJcbiAgICAgICAgd2hpbGUoIHBhcmFtRGVmcyAhPSAwIClcclxuICAgICAgICB7XHJcbiAgICAgICAgICBwYXJhbURlZlsgcGFyYW1Db3VudCBdID0gcGFyYW1EZWZzICYgMHhGRjtcclxuICAgICAgICAgIHN3aXRjaCggcGFyYW1EZWZzICYgMHhGMCApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgMHgwMDogYnJlYWs7XHJcbiAgICAgICAgICAgIGNhc2UgMHgxMDogcGFyYW1WYWxbIHBhcmFtQ291bnQgXSA9IHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICk7IGJyZWFrO1xyXG4gICAgICAgICAgICBjYXNlIDB4MjA6IHBhcmFtVmFsWyBwYXJhbUNvdW50IF0gPSBCQTJXKCBbIHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICksIHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICkgXSApOyBicmVhaztcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHBhcmFtQ291bnQrKztcclxuICAgICAgICAgIHBhcmFtRGVmcyA+Pj0gODtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHByaW50KCBcIltcIiArIGhleDQoIHRoaXMuY3VycmVudElQICkgKyBcIl0gICAgICAgICAgXCIgKyBsanVzdCggbWVsSW5zdC5pbnN0TmFtZSwgOCApICk7XHJcblxyXG4gICAgICAgIGlmICggKCBwYXJhbUNvdW50ID4gMSApXHJcbiAgICAgICAgICAmJiAoICggcGFyYW1EZWZbIDAgXSA9PSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApXHJcbiAgICAgICAgICAgIHx8ICggcGFyYW1EZWZbIDAgXSA9PSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlIClcclxuICAgICAgICAgICAgfHwgKCBwYXJhbURlZlsgMCBdID09IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKSApXHJcbiAgICAgICAgICAmJiAoIHBhcmFtRGVmWyAxIF0gIT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApXHJcbiAgICAgICAgICAmJiAoIHBhcmFtRGVmWyAxIF0gIT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKSApXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIHRlbXBWYWwgPSBwYXJhbVZhbFsxXTsgcGFyYW1WYWxbMV0gPSBwYXJhbVZhbFswXTsgcGFyYW1WYWxbMF0gPSB0ZW1wVmFsO1xyXG4gICAgICAgICAgdmFyIHRlbXBEZWYgPSBwYXJhbURlZlsxXTsgcGFyYW1EZWZbMV0gPSBwYXJhbURlZlswXTsgcGFyYW1EZWZbMF0gPSB0ZW1wRGVmO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgZm9yKCB2YXIgcGFyYW1JbmRleCA9IDA7IHBhcmFtSW5kZXggPCBwYXJhbUNvdW50OyArK3BhcmFtSW5kZXggKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciB2ID0gcGFyYW1WYWxbIHBhcmFtSW5kZXggXTtcclxuICAgICAgICAgIHZhciBkID0gcGFyYW1EZWZbIHBhcmFtSW5kZXggXTtcclxuXHJcbiAgICAgICAgICBzd2l0Y2goIGQgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuOlxyXG4gICAgICAgICAgICAgIGlmICggdiA+IDAgKVxyXG4gICAgICAgICAgICAgICAgcHJpbnQoIFwiMHhcIiArIGhleCggdiApICk7XHJcbiAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgcHJpbnQoIHYgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZTpcclxuICAgICAgICAgICAgICBpZiAoIHYgPiAwIClcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIjB4XCIgKyBoZXgoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHByaW50KCB2ICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGU6XHJcbiAgICAgICAgICAgICAgcHJpbnQoIFwiMHhcIiArIGhleCggdiApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRDb2RlQWRkcmVzczpcclxuICAgICAgICAgICAgICBwcmludCggaGV4NCggdiApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmU6XHJcbiAgICAgICAgICAgICAgcHJpbnQoIGhleDQoIHRoaXMuY3VycmVudElQICsgMiArIHYgKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U0I6ICAvLyAwMVxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTVDogIC8vIDAyXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERCOiAgLy8gMDNcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0TEI6ICAvLyAwNFxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREVDogIC8vIDA1XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBCOiAgLy8gMDZcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UFQ6ICAvLyAwN1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgdmFyIHNlZyA9IFsgXCJcIiwgXCJTQlwiLCBcIlNUXCIsIFwiREJcIiwgXCJMQlwiLCBcIkRUXCIsIFwiUEJcIiwgXCJQVFwiIF07XHJcbiAgICAgICAgICAgICAgcHJpbnQoIHNlZ1sgZCAmIDB4MDcgXSApO1xyXG4gICAgICAgICAgICAgIGlmICggdiA+IDAgKVxyXG4gICAgICAgICAgICAgICAgcHJpbnQoIFwiWzB4XCIgKyBoZXgoIHYgKSArIFwiXVwiICk7XHJcbiAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgcHJpbnQoIFwiW1wiICsgdiArIFwiXVwiICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICBpZiAoIHBhcmFtSW5kZXggPCBwYXJhbUNvdW50IC0gMSApXHJcbiAgICAgICAgICAgIHByaW50KCBcIiwgXCIgKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcHJpbnQoIFwiXFxuXCIgKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCBzdGVwVG9OZXh0SVAgKVxyXG4gICAgICAgIHRoaXMuY3VycmVudElQID0gbmV4dElQO1xyXG4gICAgfVxyXG4gICAgY2F0Y2goIGUgKVxyXG4gICAge1xyXG4gICAgICBwcmludCggZSApO1xyXG4gICAgfTtcclxuXHJcblxyXG4gICAgcmV0dXJuIGRpc21UZXh0O1xyXG4gIH1cclxuXHJcbiAgLy9cclxuICAvLyBNVUxUT1MgYWRkcmVzc2VzIGFyZSAxNi1iaXQgbGluZWFyIHZhbHVlcywgd2hlbiBwdXNoZWQgb250byBzdGFja1xyXG4gIC8vIGFuZCB1c2VkIGZvciBpbmRpcmVjdGlvbi4gV2UgbWFwIGFkZHJlc3MtdGFnIGFuZCBvZmZzZXQgcGFpcnMgdG8gbGluZWFyXHJcbiAgLy8gYWRkcmVzc2VzLCBhbmQgYmFjayBhZ2FpbiwgYnkgYmFzaW5nIHN0YXRpYyBhdCAweDAwMDAsIGR5bmFtaWMgYXQgMHg4MDAwXHJcbiAgLy8gYW5kIHB1YmxpYyBhdCAweEYwMDAuXHJcbiAgLy9cclxuICBwcml2YXRlIG1hcFRvU2VnbWVudEFkZHIoIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMCApO1xyXG5cclxuICAgIHN3aXRjaCggYWRkclRhZyApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUzpcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyREI6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckxCOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVDpcclxuICAgICAgICByZXR1cm4gMHg4MDAwICsgdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQ7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJTQjpcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU1Q6XHJcbiAgICAgICAgcmV0dXJuIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0O1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUEI6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclBUOlxyXG4gICAgICAgIHJldHVybiAweEYwMDAgKyB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldDtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgbWFwRnJvbVNlZ21lbnRBZGRyKCBzZWdtZW50QWRkciApXHJcbiAge1xyXG4gICAgaWYgKCBzZWdtZW50QWRkciAmIDB4ODAwMCApXHJcbiAgICB7XHJcbiAgICAgIGlmICggc2VnbWVudEFkZHIgPj0gMHhGMDAwIClcclxuICAgICAge1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhQXJlYTogdGhpcy5wdWJsaWNBcmVhLFxyXG4gICAgICAgICAgZGF0YUFkZHJUYWc6IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJQQixcclxuICAgICAgICAgIGRhdGFPZmZzZXQ6IHNlZ21lbnRBZGRyICYgMHgwRkZGXHJcbiAgICAgICAgfTtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YUFyZWE6IHRoaXMuZHluYW1pY0FyZWEsXHJcbiAgICAgICAgICBkYXRhQWRkclRhZzogTUVMLk1FTFRBR0FERFIubWVsQWRkckRCLFxyXG4gICAgICAgICAgZGF0YU9mZnNldDogc2VnbWVudEFkZHIgJiAweDNGRkZcclxuICAgICAgICB9O1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YUFyZWE6IHRoaXMuc3RhdGljQXJlYSxcclxuICAgICAgICBkYXRhQWRkclRhZzogTUVMLk1FTFRBR0FERFIubWVsQWRkclNCLFxyXG4gICAgICAgIGRhdGFPZmZzZXQ6IHNlZ21lbnRBZGRyICYgMHg3RkZGXHJcbiAgICAgIH07XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvL1xyXG4gIC8vIHZhbGlkYXRlIGEgbXVsdGktYnl0ZSBtZW1vcnkgYWNjZXNzLCBzcGVjaWZpZWQgYnkgYWRkcmVzcy10YWcvb2Zmc2V0IHBhaXJcclxuICAvLyBhbmQgbGVuZ3RoIHZhbHVlcy4gSWYgb2ssIG1hcCB0byBhbiBhcmVhIGFuZCBvZmZzZXQgd2l0aGluIHRoYXQgYXJlYS5cclxuICAvLyBDYW4gYWNjZXB0IHBvc2l0aXZlL25lZ2F0aXZlIG9mZnNldHMsIHNpbmNlIHRoZXkgYXJlYSByZWxhdGl2ZSB0byB0aGVcclxuICAvLyB0aGUgdG9wIG9yIHRoZSBib3R0b20gb2YgdGhlIHNwZWNpZmllZCBhcmVhLCBhcyBpbmRpY2F0ZWQgYnkgdGhlIHRhZy5cclxuICAvL1xyXG4gIHByaXZhdGUgY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBvZmZzZXQsIGxlbmd0aCApXHJcbiAge1xyXG4gICAgdmFyIGRhdGFBcmVhO1xyXG4gICAgdmFyIGRhdGFPZmZzZXQgPSBvZmZzZXQ7XHJcbiAgICB2YXIgYXJlYUxpbWl0O1xyXG5cclxuICAgIHN3aXRjaCggYWRkclRhZyApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUzpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMuZHluYW1pY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5keW5hbWljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBkYXRhT2Zmc2V0ICs9IHRoaXMubG9jYWxCYXNlO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyREI6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLmR5bmFtaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuZHluYW1pY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJMQjpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMuZHluYW1pY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5keW5hbWljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBkYXRhT2Zmc2V0ICs9IHRoaXMubG9jYWxCYXNlO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQ6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLmR5bmFtaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuZHluYW1pY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSB0aGlzLmR5bmFtaWNUb3A7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJTQjpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMuc3RhdGljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLnN0YXRpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJTVDpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMuc3RhdGljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLnN0YXRpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSBhcmVhTGltaXQ7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJQQjpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMucHVibGljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLnB1YmxpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJQVDpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMucHVibGljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLnB1YmxpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSBhcmVhTGltaXQ7XHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICB9XHJcblxyXG4gICAgZGF0YU9mZnNldCAmPSAweGZmZmY7IC8vIDE2IGJpdHMgYWRkcmVzc2VzXHJcbiAgICBpZiAoICggZGF0YU9mZnNldCA8IGFyZWFMaW1pdCApICYmICggZGF0YU9mZnNldCArIGxlbmd0aCA8IGFyZWFMaW1pdCApIClcclxuICAgIHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhQXJlYTogZGF0YUFyZWEsXHJcbiAgICAgICAgZGF0YU9mZnNldDogZGF0YU9mZnNldFxyXG4gICAgICB9O1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLy9cclxuICAvLyBwZXJmb3JtIGEgdmFsaWRhdGVkIG11bHRpLWJ5dGUgcmVhZCwgc3BlY2lmaWVkIGJ5IGFkZHJlc3MtdGFnL29mZnNldCBwYWlyIGFuZFxyXG4gIC8vIGxlbmd0aCB2YWx1ZXMuIFJldHVybiBkYXRhLWFycmF5LCBvciB1bmRlZmluZWRcclxuICAvL1xyXG4gIHByaXZhdGUgcmVhZFNlZ21lbnREYXRhKCBhZGRyVGFnLCBvZmZzZXQsIGxlbmd0aCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBvZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICByZXR1cm4gdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLnJlYWRCeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIGxlbmd0aCApO1xyXG4gIH1cclxuXHJcbiAgLy9cclxuICAvLyBwZXJmb3JtIGEgdmFsaWRhdGVkIG11bHRpLWJ5dGUgd3JpdGUsIHNwZWNpZmllZCBieSBhZGRyZXNzLXRhZy9vZmZzZXQgcGFpciBhbmRcclxuICAvLyBkYXRhLWFycmF5IHRvIGJlIHdyaXR0ZW4uXHJcbiAgLy9cclxuICBwcml2YXRlIHdyaXRlU2VnbWVudERhdGEoIGFkZHJUYWcsIG9mZnNldCwgdmFsIClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIG9mZnNldCwgMSApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS53cml0ZUJ5dGVzKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgdmFsICk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHB1c2haZXJvc1RvU3RhY2soIGNudCApXHJcbiAge1xyXG4gICAgdGhpcy5keW5hbWljQXJlYS56ZXJvQnl0ZXMoIHRoaXMuZHluYW1pY1RvcCwgY250ICk7XHJcblxyXG4gICAgdGhpcy5keW5hbWljVG9wICs9IGNudDtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgcHVzaENvbnN0VG9TdGFjayggY250LCB2YWwgKVxyXG4gIHtcclxuICAgIGlmICggY250ID09IDEgKVxyXG4gICAgICB0aGlzLmR5bmFtaWNBcmVhLndyaXRlQnl0ZXMoIHRoaXMuZHluYW1pY1RvcCwgWyB2YWwgXSApO1xyXG4gICAgZWxzZVxyXG4gICAgICB0aGlzLmR5bmFtaWNBcmVhLndyaXRlQnl0ZXMoIHRoaXMuZHluYW1pY1RvcCwgVzJCQSggdmFsICkgKTtcclxuXHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgKz0gY250O1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBjb3B5T25TdGFjayggZnJvbU9mZnNldCwgdG9PZmZzZXQsIGNudCApXHJcbiAge1xyXG4gICAgdGhpcy5keW5hbWljQXJlYS5jb3B5Qnl0ZXMoIGZyb21PZmZzZXQsIHRvT2Zmc2V0LCBjbnQgKTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgcHVzaFRvU3RhY2soIGFkZHJUYWcsIG9mZnNldCwgY250IClcclxuICB7XHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgKz0gY250O1xyXG4gICAgdGhpcy5keW5hbWljQXJlYS53cml0ZUJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIHRoaXMucmVhZFNlZ21lbnREYXRhKCBhZGRyVGFnLCBvZmZzZXQsIGNudCApICk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBvcEZyb21TdGFja0FuZFN0b3JlKCBhZGRyVGFnLCBvZmZzZXQsIGNudCApXHJcbiAge1xyXG4gICAgdGhpcy5keW5hbWljVG9wIC09IGNudDtcclxuXHJcbiAgICB0aGlzLndyaXRlU2VnbWVudERhdGEoIGFkZHJUYWcsIG9mZnNldCwgdGhpcy5keW5hbWljQXJlYS5yZWFkQnl0ZXMoIHRoaXMuZHluYW1pY1RvcCwgY250ICkgKTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgcG9wRnJvbVN0YWNrKCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY1RvcCAtPSBjbnQ7XHJcblxyXG4gICAgcmV0dXJuIHRoaXMuZHluYW1pY0FyZWEucmVhZEJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIGNudCApO1xyXG4gIH1cclxuXHJcbiAgLy8gc2V0dXAgYXBwbGljYXRpb24gZm9yIGV4ZWN1dGlvblxyXG4gIHNldHVwQXBwbGljYXRpb24oIGV4ZWNQYXJhbXMgKVxyXG4gIHtcclxuICAgIHRoaXMuY29kZUFyZWEgPSBleGVjUGFyYW1zLmNvZGVBcmVhO1xyXG4gICAgdGhpcy5zdGF0aWNBcmVhID0gZXhlY1BhcmFtcy5zdGF0aWNBcmVhO1xyXG4gICAgdGhpcy5zZXNzaW9uU2l6ZSA9IGV4ZWNQYXJhbXMuc2Vzc2lvblNpemU7XHJcblxyXG4gICAgdGhpcy5keW5hbWljQXJlYSA9IHRoaXMucmFtU2VnbWVudC5uZXdBY2Nlc3NvciggMCwgNTEyLCBcIkRcIiApOyAvL1RPRE86IGV4ZWNQYXJhbXMuc2Vzc2lvblNpemVcclxuXHJcbiAgICB0aGlzLmluaXRFeGVjdXRpb24oKTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgaW5pdEV4ZWN1dGlvbigpXHJcbiAge1xyXG4gICAgdGhpcy5jdXJyZW50SVAgPSAwO1xyXG4gICAgdGhpcy5pc0V4ZWN1dGluZyA9IHRydWU7XHJcblxyXG4gICAgLy8gVE9ETzogU2VwYXJhdGUgc3RhY2sgYW5kIHNlc3Npb25cclxuICAgIHRoaXMubG9jYWxCYXNlID0gdGhpcy5zZXNzaW9uU2l6ZTtcclxuICAgIHRoaXMuZHluYW1pY1RvcCA9IHRoaXMubG9jYWxCYXNlO1xyXG5cclxuICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyA9IDA7XHJcbiAgfVxyXG5cclxuICBzZWdzID0gWyBcIlwiLCBcIlNCXCIsIFwiU1RcIiwgXCJEQlwiLCBcIkxCXCIsIFwiRFRcIiwgXCJQQlwiLCBcIlBUXCIgXTtcclxuXHJcbiAgcHJpdmF0ZSBjb25zdEJ5dGVCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgY29uc3RWYWwsIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMSApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHZhciB0ZW1wVmFsID0gdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLnJlYWRCeXRlKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCApO1xyXG5cclxuICAgIHN3aXRjaCggb3BDb2RlIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBRERCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgKyBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA8IGNvbnN0VmFsICkgIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1VCQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsIC0gY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPiBjb25zdFZhbCApICAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENNUEI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCAtIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsID4gY29uc3RWYWwgKSAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVEI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9IGNvbnN0VmFsO1xyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICggdGVtcFZhbCA9PSAwIClcclxuICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX1o7XHJcblxyXG4gICAgaWYgKCBvcENvZGUgIT0gTUVMLk1FTElOU1QubWVsQ01QQiApXHJcbiAgICB7XHJcbiAgICAgIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS53cml0ZUJ5dGUoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCB0ZW1wVmFsICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGNvbnN0V29yZEJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBjb25zdFZhbCwgYWRkclRhZywgYWRkck9mZnNldCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBhZGRyT2Zmc2V0LCAyICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgdmFyIHRlbXBWYWwgPSBCQTJXKCB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEucmVhZEJ5dGVzKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgMiApICk7XHJcblxyXG4gICAgc3dpdGNoKCBvcENvZGUgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEFEREI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCArIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsIDwgY29uc3RWYWwgKSAgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVUJCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgLSBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA+IGNvbnN0VmFsICkgIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ01QQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsIC0gY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPiBjb25zdFZhbCApIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU0VUQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gY29uc3RWYWw7XHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCB0ZW1wVmFsID09IDAgKVxyXG4gICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfWjtcclxuXHJcbiAgICBpZiAoIG9wQ29kZSAhPSBNRUwuTUVMSU5TVC5tZWxDTVBXIClcclxuICAgIHtcclxuICAgICAgdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLndyaXRlQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBXMkJBKCB0ZW1wVmFsICkgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgYmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIG9wU2l6ZSwgYWRkclRhZywgYWRkck9mZnNldCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBhZGRyT2Zmc2V0LCAxICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgdGhpcy5jaGVja0RhdGFBY2Nlc3MoIC1vcFNpemUgLSAxLCBvcFNpemUsIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKTsgLy8gRmlyc3RcclxuXHJcbiAgICAvLyB0b2RvOlxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSB1bmFyeU9wZXJhdGlvbiggb3BDb2RlLCBvcFNpemUsIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMSApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHN3aXRjaCggb3BDb2RlIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTEVBUk46XHJcbiAgICAgICAgdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLnplcm9CeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIG9wU2l6ZSApO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxURVNUTjogICAgICAgICAvLyAxNlxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbElOQ046ICAgICAgICAgIC8vIDE3XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsREVDTjogICAgICAgICAgLy8gMThcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxOT1ROOiAgICAgICAgICAvLyAxOVxyXG4gICAgICAgIDtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgaGFuZGxlUmV0dXJuKCBpbkJ5dGVzLCBvdXRCeXRlcyApXHJcbiAge1xyXG4gICAgdmFyIHJldFZhbE9mZnNldCA9IHRoaXMuZHluYW1pY1RvcCAtIG91dEJ5dGVzO1xyXG5cclxuICAgIHZhciByZXR1cm5JUCA9IEJBMlcoIHRoaXMuZHluYW1pY0FyZWEucmVhZEJ5dGVzKCB0aGlzLmxvY2FsQmFzZSAtIDIsIDIgKSApO1xyXG4gICAgdGhpcy5sb2NhbEJhc2UgPSBCQTJXKCB0aGlzLmR5bmFtaWNBcmVhLnJlYWRCeXRlcyggdGhpcy5sb2NhbEJhc2UgLSA0LCAyICkgKTtcclxuXHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgPSB0aGlzLmxvY2FsQmFzZSArIG91dEJ5dGVzO1xyXG4gICAgaWYgKCBvdXRCeXRlcyApXHJcbiAgICAgIHRoaXMuY29weU9uU3RhY2soIHJldFZhbE9mZnNldCwgdGhpcy5sb2NhbEJhc2UsIG91dEJ5dGVzICk7XHJcblxyXG4gICAgcmV0dXJuIHJldHVybklQO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBpc0NvbmRpdGlvbiggdGFnIClcclxuICB7XHJcbiAgICBzd2l0Y2goIHRhZyApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZEVROlxyXG4gICAgICAgIHJldHVybiAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kTFQ6XHJcbiAgICAgICAgcmV0dXJuICEoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX0MgKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kTEU6XHJcbiAgICAgICAgcmV0dXJuICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfWiApIHx8ICEoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX0MgKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kR1Q6XHJcbiAgICAgICAgcmV0dXJuICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfQyApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRHRTpcclxuICAgICAgICByZXR1cm4gKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9aICkgfHwgKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9DICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZE5FOlxyXG4gICAgICAgIHJldHVybiAhKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZEFMTDpcclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgZGVmYXVsdDogLy8gbWVsQ29uZFNQRUNcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gZmFsc2U7XHJcbiAgfVxyXG5cclxuICBleGVjdXRlU3RlcCgpXHJcbiAge1xyXG4gICAgdHJ5XHJcbiAgICB7XHJcbiAgICAgIHZhciBuZXh0SVAgPSB0aGlzLmN1cnJlbnRJUDtcclxuICAgICAgdmFyIGluc3RCeXRlID0gdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKTtcclxuICAgICAgdmFyIHBhcmFtQ291bnQgPSAwO1xyXG4gICAgICB2YXIgcGFyYW1WYWwgPSBbXTtcclxuICAgICAgdmFyIHBhcmFtRGVmID0gW107XHJcblxyXG4gICAgICB2YXIgbWVsSW5zdCA9IE1FTC5NRUxEZWNvZGVbIGluc3RCeXRlIF07XHJcblxyXG4gICAgICBpZiAoIG1lbEluc3QgPT0gdW5kZWZpbmVkIClcclxuICAgICAge1xyXG4gICAgICAgIHJldHVybiBudWxsO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIHZhciBwYXJhbURlZnMgPSBtZWxJbnN0LnBhcmFtRGVmcztcclxuXHJcbiAgICAgICAgd2hpbGUoIHBhcmFtRGVmcyAhPSAwIClcclxuICAgICAgICB7XHJcbiAgICAgICAgICBwYXJhbURlZlsgcGFyYW1Db3VudCBdID0gcGFyYW1EZWZzICYgMHhGRjtcclxuICAgICAgICAgIHN3aXRjaCggcGFyYW1EZWZzICYgMHhGMCApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgMHgwMDogYnJlYWs7XHJcbiAgICAgICAgICAgIGNhc2UgMHgxMDogcGFyYW1WYWxbIHBhcmFtQ291bnQgXSA9IHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICk7IGJyZWFrO1xyXG4gICAgICAgICAgICBjYXNlIDB4MjA6IHBhcmFtVmFsWyBwYXJhbUNvdW50IF0gPSBCQTJXKCBbIHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICksIHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICkgXSApOyBicmVhaztcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHBhcmFtQ291bnQrKztcclxuICAgICAgICAgIHBhcmFtRGVmcyA+Pj0gODtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHZhciBvcENvZGUgPSBNRUwuTUVMMk9QQ09ERSggaW5zdEJ5dGUgKTtcclxuICAgICAgdmFyIHRhZyA9IE1FTC5NRUwyVEFHKCBpbnN0Qnl0ZSApO1xyXG5cclxuICAgICAgc3dpdGNoKCBvcENvZGUgKVxyXG4gICAgICB7XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTWVNURU06ICAgICAgICAvLyAwMFxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciBwdWJsaWNUb3AgPSB0aGlzLnB1YmxpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcblxyXG4gICAgICAgICAgc3dpdGNoKCB0YWcgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbUV4aXQ6XHJcbiAgICAgICAgICAgICAgdGhpcy5pc0V4ZWN1dGluZyA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgIC8vbm8gYnJlYWtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1OT1A6XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbUV4aXRTVzpcclxuICAgICAgICAgICAgICB0aGlzLmlzRXhlY3V0aW5nID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgLy9ubyBicmVha1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbVNldFNXOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSAyLCBXMkJBKCBwYXJhbVZhbFsgMCBdICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtRXhpdExhOlxyXG4gICAgICAgICAgICAgIHRoaXMuaXNFeGVjdXRpbmcgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAvL25vIGJyZWFrXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtU2V0TGE6XHJcbiAgICAgICAgICAgICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDQsIFcyQkEoIHBhcmFtVmFsWyAwIF0gKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1FeGl0U1dMYTpcclxuICAgICAgICAgICAgICB0aGlzLmlzRXhlY3V0aW5nID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgLy9ubyBicmVha1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbVNldFNXTGE6XHJcbiAgICAgICAgICAgICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDIsIFcyQkEoIHBhcmFtVmFsWyAwIF0gKSApO1xyXG4gICAgICAgICAgICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSA0LCBXMkJBKCBwYXJhbVZhbFsgMSBdICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxCUkFOQ0g6ICAgICAgICAvLyAwMVxyXG4gICAgICAgICAgaWYgKCB0aGlzLmlzQ29uZGl0aW9uKCB0YWcgKSApXHJcbiAgICAgICAgICAgIG5leHRJUCA9IG5leHRJUCArIHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxKVU1QOiAgICAgICAgICAvLyAwMlxyXG4gICAgICAgICAgaWYgKCB0aGlzLmlzQ29uZGl0aW9uKCB0YWcgKSApXHJcbiAgICAgICAgICAgIG5leHRJUCA9IHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDQUxMOiAgICAgICAgICAvLyAwM1xyXG4gICAgICAgICAgaWYgKCB0aGlzLmlzQ29uZGl0aW9uKCB0YWcgKSApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMiwgdGhpcy5sb2NhbEJhc2UgKTtcclxuICAgICAgICAgICAgdGhpcy5wdXNoQ29uc3RUb1N0YWNrKCAyLCBuZXh0SVAgKTtcclxuXHJcbiAgICAgICAgICAgIG5leHRJUCA9IHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICAgIHRoaXMubG9jYWxCYXNlID0gdGhpcy5keW5hbWljVG9wO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1RBQ0s6ICAgICAgICAgLy8gMDRcclxuICAgICAgICB7XHJcbiAgICAgICAgICBzd2l0Y2goIHRhZyApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSFo6XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICB0aGlzLnB1c2haZXJvc1RvU3RhY2soIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BVU0hCOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMSwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIVzpcclxuICAgICAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDIsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QTjpcclxuICAgICAgICAgICAgICB0aGlzLnBvcEZyb21TdGFjayggcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BCOlxyXG4gICAgICAgICAgICAgIHRoaXMucG9wRnJvbVN0YWNrKCAxICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BPUFc6XHJcbiAgICAgICAgICAgICAgdGhpcy5wb3BGcm9tU3RhY2soIDIgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxQUklNUkVUOiAgICAgICAvLyAwNVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHN3aXRjaCggdGFnIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTA6XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0xOlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMjpcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTM6XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVQ6XHJcbiAgICAgICAgICAgICAgbmV4dElQID0gdGhpcy5oYW5kbGVSZXR1cm4oIDAsIDAgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVEk6XHJcbiAgICAgICAgICAgICAgbmV4dElQID0gdGhpcy5oYW5kbGVSZXR1cm4oIHBhcmFtVmFsWyAwIF0sIDAgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVE86XHJcbiAgICAgICAgICAgICAgbmV4dElQID0gdGhpcy5oYW5kbGVSZXR1cm4oIDAsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVElPOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCBwYXJhbVZhbFsgMCBdLCBwYXJhbVZhbFsgMSBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTE9BRDogICAgICAgICAgLy8gMDdcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICAvLyBEVVAgVE9TXHJcbiAgICAgICAgICAgIHRoaXMuY29weU9uU3RhY2soIHRoaXMuZHluYW1pY1RvcCAtIHBhcmFtVmFsWyAwIF0sIHRoaXMuZHluYW1pY1RvcCwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgICB0aGlzLmR5bmFtaWNUb3AgKz0gcGFyYW1WYWxbIDAgXTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5wdXNoVG9TdGFjayggdGFnLCBwYXJhbVZhbFsgMSBdLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVE9SRTogICAgICAgICAvLyAwOFxyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIC8vIFNISUZUIFRPU1xyXG4gICAgICAgICAgICB0aGlzLmR5bmFtaWNUb3AgLT0gcGFyYW1WYWxbIDAgXTtcclxuICAgICAgICAgICAgdGhpcy5jb3B5T25TdGFjayggdGhpcy5keW5hbWljVG9wLCB0aGlzLmR5bmFtaWNUb3AgLSBwYXJhbVZhbFsgMCBdLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMucG9wRnJvbVN0YWNrQW5kU3RvcmUoIHRhZywgcGFyYW1WYWxbIDEgXSwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbExPQURJOiAgICAgICAgIC8vIDA5XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIHNlZ21lbnRBZGRyID0gQkEyVyggdGhpcy5yZWFkU2VnbWVudERhdGEoIHRhZywgcGFyYW1WYWxbIDEgXSwgMiApICk7XHJcbiAgICAgICAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5tYXBGcm9tU2VnbWVudEFkZHIoIHNlZ21lbnRBZGRyICk7XHJcbiAgICAgICAgICB0aGlzLnB1c2hUb1N0YWNrKCB0YXJnZXRBY2Nlc3MuZGF0YUFkZHJUYWcsIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1RPUkVJOiAgICAgICAgLy8gMEFcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgc2VnbWVudEFkZHIgPSBCQTJXKCB0aGlzLnJlYWRTZWdtZW50RGF0YSggdGFnLCBwYXJhbVZhbFsgMSBdLCAyICkgKTtcclxuICAgICAgICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLm1hcEZyb21TZWdtZW50QWRkciggc2VnbWVudEFkZHIgKTtcclxuICAgICAgICAgIHRoaXMucG9wRnJvbVN0YWNrQW5kU3RvcmUoIHRhcmdldEFjY2Vzcy5kYXRhQWRkclRhZywgdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxMT0FEQTogICAgICAgICAvLyAwQlxyXG4gICAgICAgICAgdGhpcy5wdXNoQ29uc3RUb1N0YWNrKCAyLCB0aGlzLm1hcFRvU2VnbWVudEFkZHIoIHRhZywgcGFyYW1WYWxbIDAgXSApICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxJTkRFWDogICAgICAgICAvLyAwQ1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU0VUQjogICAgICAgICAgLy8gMERcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENNUEI6ICAgICAgICAgIC8vIDBFXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBRERCOiAgICAgICAgICAvLyAwRlxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1VCQjogICAgICAgICAgLy8gMTBcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAgICB0aGlzLmNvbnN0Qnl0ZUJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgTUVMLk1FTFRBR0FERFIubWVsQWRkckRULCAtMSApO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLmNvbnN0Qnl0ZUJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgdGFnLCBwYXJhbVZhbFsxXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU0VUVzogICAgICAgICAgLy8gMTFcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENNUFc6ICAgICAgICAgIC8vIDEyXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBRERXOiAgICAgICAgICAvLyAxM1xyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1VCVzogICAgICAgICAgLy8gMTRcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAgICB0aGlzLmNvbnN0V29yZEJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgTUVMLk1FTFRBR0FERFIubWVsQWRkckRULCAtMiApO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLmNvbnN0V29yZEJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgdGFnLCBwYXJhbVZhbFsxXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ0xFQVJOOiAgICAgICAgLy8gMTVcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFRFU1ROOiAgICAgICAgIC8vIDE2XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxJTkNOOiAgICAgICAgICAvLyAxN1xyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsREVDTjogICAgICAgICAgLy8gMThcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbE5PVE46ICAgICAgICAgIC8vIDE5XHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy51bmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgTUVMLk1FTFRBR0FERFIubWVsQWRkckRULCAtMSAqIHBhcmFtVmFsWzBdICk7XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMudW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIHRhZywgcGFyYW1WYWxbMV0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENNUE46ICAgICAgICAgIC8vIDFBXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBREROOiAgICAgICAgICAvLyAxQlxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1VCTjogICAgICAgICAgLy8gMUNcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEFORE46ICAgICAgICAgIC8vIDFEXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxPUk46ICAgICAgICAgICAvLyAxRVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsWE9STjogICAgICAgICAgLy8gMUZcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAgICB0aGlzLmJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgTUVMLk1FTFRBR0FERFIubWVsQWRkckRULCAtMiAqIHBhcmFtVmFsWzBdICk7XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMuYmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCB0YWcsIHBhcmFtVmFsWzFdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5jdXJyZW50SVAgPSBuZXh0SVA7XHJcbiAgICB9XHJcbiAgICBjYXRjaCggZSApXHJcbiAgICB7XHJcbiAgICAgIC8vcHJpbnQoIGUgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHNldENvbW1hbmRBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKVxyXG4gIHtcclxuICAgIHZhciBwdWJsaWNUb3AgPSB0aGlzLnB1YmxpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcblxyXG4gICAgLy8gLTIsLTEgPSBTVzEyXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gMiwgVzJCQSggMHg5MDAwICkgKTtcclxuXHJcbiAgICAvLyAtNCwtMyA9IExhXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gNCwgVzJCQSggMHgwMDAwICkgKTtcclxuXHJcbiAgICAvLyAtNiwtNSA9IExlXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gNiwgVzJCQSggY29tbWFuZEFQRFUuTGUgKSApO1xyXG5cclxuICAgIC8vIC04LC03ID0gTGNcclxuICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSA4LCBXMkJBKCBjb21tYW5kQVBEVS5kYXRhLmxlbmd0aCApICk7XHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gMTMsIGNvbW1hbmRBUERVLmhlYWRlciApO1xyXG5cclxuICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCAwLCBjb21tYW5kQVBEVS5kYXRhICk7XHJcblxyXG4gICAgdGhpcy5pbml0RXhlY3V0aW9uKCk7XHJcbiAgfVxyXG5cclxuICBnZXRSZXNwb25zZUFQRFUoKTogUmVzcG9uc2VBUERVXHJcbiAge1xyXG4gICAgdmFyIHB1YmxpY1RvcCA9IHRoaXMucHVibGljQXJlYS5nZXRMZW5ndGgoKTtcclxuXHJcbiAgICB2YXIgbGEgPSBCQTJXKCB0aGlzLnB1YmxpY0FyZWEucmVhZEJ5dGVzKCBwdWJsaWNUb3AgLSA0LCAyICkgKTtcclxuXHJcbiAgICByZXR1cm4gbmV3IFJlc3BvbnNlQVBEVSggeyBzdzogQkEyVyggdGhpcy5wdWJsaWNBcmVhLnJlYWRCeXRlcyggcHVibGljVG9wIC0gMiwgMiApICksIGRhdGE6IHRoaXMucHVibGljQXJlYS5yZWFkQnl0ZXMoIDAsIGxhICkgIH0gKVxyXG5cclxuICB9XHJcblxyXG4gIGdldCBnZXREZWJ1ZygpOiB7fVxyXG4gIHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIHJhbVNlZ21lbnQ6IHRoaXMucmFtU2VnbWVudCxcclxuICAgICAgZHluYW1pY0FyZWE6IHRoaXMuZHluYW1pY0FyZWEsXHJcbiAgICAgIHB1YmxpY0FyZWE6IHRoaXMucHVibGljQXJlYSxcclxuICAgICAgc3RhdGljQXJlYTogdGhpcy5zdGF0aWNBcmVhLFxyXG4gICAgICBjdXJyZW50SVA6IHRoaXMuY3VycmVudElQLFxyXG4gICAgICBkeW5hbWljVG9wOiB0aGlzLmR5bmFtaWNUb3AsXHJcbiAgICAgIGxvY2FsQmFzZTogdGhpcy5sb2NhbEJhc2VcclxuICAgIH07XHJcbiAgfVxyXG4vLyAgaXNFeGVjdXRpbmc6IGZ1bmN0aW9uKCkgeyByZXR1cm4gaXNFeGVjdXRpbmc7IH0sXHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcbmltcG9ydCB7IE1lbW9yeU1hbmFnZXIsIE1FTUZMQUdTIH0gZnJvbSAnLi9tZW1vcnktbWFuYWdlcic7XHJcbmltcG9ydCB7IE1FTFZpcnR1YWxNYWNoaW5lIH0gZnJvbSAnLi92aXJ0dWFsLW1hY2hpbmUnO1xyXG5cclxuaW1wb3J0IHsgSVNPNzgxNiB9IGZyb20gJy4uL2lzbzc4MTYvSVNPNzgxNic7XHJcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9jb21tYW5kLWFwZHUnO1xyXG5pbXBvcnQgeyBSZXNwb25zZUFQRFUgfSBmcm9tICcuLi9pc283ODE2L3Jlc3BvbnNlLWFwZHUnO1xyXG5cclxuaW1wb3J0IHsgSlNJTUNhcmQgfSBmcm9tICcuLi9qc2ltLWNhcmQvanNpbS1jYXJkJztcclxuXHJcbmZ1bmN0aW9uICBCQTJXKCB2YWwgKVxyXG57XHJcbiAgcmV0dXJuICggdmFsWyAwIF0gPDwgOCApIHwgdmFsWyAxIF07XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBKU0lNTXVsdG9zQXBwbGV0XHJcbntcclxuICBzZXNzaW9uU2l6ZTtcclxuICBjb2RlQXJlYTtcclxuICBzdGF0aWNBcmVhO1xyXG5cclxuICBjb25zdHJ1Y3RvciggY29kZUFyZWEsIHN0YXRpY0FyZWEsIHNlc3Npb25TaXplIClcclxuICB7XHJcbiAgICB0aGlzLmNvZGVBcmVhID0gY29kZUFyZWE7XHJcbiAgICB0aGlzLnN0YXRpY0FyZWEgPSBzdGF0aWNBcmVhO1xyXG4gICAgdGhpcy5zZXNzaW9uU2l6ZSA9IHNlc3Npb25TaXplO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIEpTSU1NdWx0b3NDYXJkIGltcGxlbWVudHMgSlNJTUNhcmRcclxue1xyXG4gIHByaXZhdGUgY2FyZENvbmZpZztcclxuXHJcbiAgc3RhdGljIGRlZmF1bHRDb25maWcgPSB7XHJcbiAgICByb21TaXplOiAwLFxyXG4gICAgcmFtU2l6ZTogMTAyNCxcclxuICAgIHB1YmxpY1NpemU6IDUxMixcclxuICAgIG52cmFtU2l6ZTogMzI3NjhcclxuICB9O1xyXG5cclxuICBwcml2YXRlIHBvd2VySXNPbjogYm9vbGVhbjtcclxuICBwcml2YXRlIGF0cjogQnl0ZUFycmF5O1xyXG5cclxuICBhcHBsZXRzOiB7IGFpZDogQnl0ZUFycmF5LCBhcHBsZXQ6IEpTSU1NdWx0b3NBcHBsZXQgfVtdO1xyXG5cclxuICBzZWxlY3RlZEFwcGxldDogSlNJTU11bHRvc0FwcGxldDtcclxuXHJcbiAgY29uc3RydWN0b3IoIGNvbmZpZz8gKVxyXG4gIHtcclxuICAgIGlmICggY29uZmlnIClcclxuICAgICAgdGhpcy5jYXJkQ29uZmlnID0gY29uZmlnO1xyXG4gICAgZWxzZVxyXG4gICAgICB0aGlzLmNhcmRDb25maWcgPSBKU0lNTXVsdG9zQ2FyZC5kZWZhdWx0Q29uZmlnO1xyXG5cclxuICAgIHRoaXMuYXRyID0gbmV3IEJ5dGVBcnJheSggW10gKTtcclxuXHJcbiAgICB0aGlzLmFwcGxldHMgPSBbXTtcclxuICB9XHJcblxyXG4gIGxvYWRBcHBsaWNhdGlvbiggYWlkOiBCeXRlQXJyYXksIGFsdTogQnl0ZUFycmF5IClcclxuICB7XHJcbiAgICB2YXIgbGVuID0gMDtcclxuXHJcbiAgICB2YXIgb2ZmID0gODtcclxuXHJcbiAgICAvLyBMRU46OkNPREVcclxuICAgIGxlbiA9IGFsdS53b3JkQXQoIG9mZiApO1xyXG4gICAgb2ZmICs9IDI7XHJcblxyXG4gICAgbGV0IGNvZGVBcmVhID0gdGhpcy5udnJhbVNlZ21lbnQubmV3QWNjZXNzb3IoIDAsIGxlbiwgXCJjb2RlXCIgKTtcclxuICAgIGNvZGVBcmVhLndyaXRlQnl0ZXMoIDAsIGFsdS52aWV3QXQoIG9mZiwgbGVuICkgKTtcclxuICAgIG9mZiArPSBsZW47XHJcblxyXG4gICAgLy8gTEVOOjpEQVRBXHJcbiAgICBsZW4gPSBhbHUud29yZEF0KCBvZmYgKTtcclxuICAgIG9mZiArPSAyO1xyXG5cclxuICAgIGxldCBzdGF0aWNBcmVhID0gdGhpcy5udnJhbVNlZ21lbnQubmV3QWNjZXNzb3IoIGNvZGVBcmVhLmdldExlbmd0aCgpLCBsZW4sIFwiU1wiICk7XHJcbiAgICBzdGF0aWNBcmVhLndyaXRlQnl0ZXMoIDAsIGFsdS52aWV3QXQoIG9mZiwgbGVuICkgKTtcclxuICAgIG9mZiArPSBsZW47XHJcblxyXG4gICAgbGV0IGFwcGxldCA9IG5ldyBKU0lNTXVsdG9zQXBwbGV0KCBjb2RlQXJlYSwgc3RhdGljQXJlYSwgMCApO1xyXG5cclxuICAgIHRoaXMuYXBwbGV0cy5wdXNoKCB7IGFpZDogYWlkLCBhcHBsZXQ6IGFwcGxldCB9ICk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgZ2V0IGlzUG93ZXJlZCgpOiBib29sZWFuXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMucG93ZXJJc09uO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHBvd2VyT24oKTogUHJvbWlzZTxCeXRlQXJyYXk+XHJcbiAge1xyXG4gICAgdGhpcy5wb3dlcklzT24gPSB0cnVlO1xyXG5cclxuICAgIHRoaXMuaW5pdGlhbGl6ZVZNKCB0aGlzLmNhcmRDb25maWcgKTtcclxuXHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCB0aGlzLmF0ciApO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHBvd2VyT2ZmKCk6IFByb21pc2U8YW55PlxyXG4gIHtcclxuICAgIHRoaXMucG93ZXJJc09uID0gZmFsc2U7XHJcblxyXG4gICAgdGhpcy5yZXNldFZNKCk7XHJcblxyXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcclxuXHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCAgKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyByZXNldCgpOiBQcm9taXNlPEJ5dGVBcnJheT5cclxuICB7XHJcbiAgICB0aGlzLnBvd2VySXNPbiA9IHRydWU7XHJcblxyXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcclxuXHJcbiAgICB0aGlzLnNodXRkb3duVk0oKTtcclxuXHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCB0aGlzLmF0ciApO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIGV4Y2hhbmdlQVBEVSggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVICk6IFByb21pc2U8UmVzcG9uc2VBUERVPlxyXG4gIHtcclxuICAgIGlmICggY29tbWFuZEFQRFUuSU5TID09IDB4QTQgKVxyXG4gICAge1xyXG4gICAgICBpZiAoIHRoaXMuc2VsZWN0ZWRBcHBsZXQgKVxyXG4gICAgICB7XHJcbiAgICAgICAgLy90aGlzLnNlbGVjdGVkQXBwbGV0LmRlc2VsZWN0QXBwbGljYXRpb24oKTtcclxuXHJcbiAgICAgICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcclxuICAgICAgfVxyXG5cclxuICAgICAgLy9UT0RPOiBMb29rdXAgQXBwbGljYXRpb25cclxuICAgICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHRoaXMuYXBwbGV0c1sgMCBdLmFwcGxldDtcclxuXHJcbiAgICAgIGxldCBmY2kgPSBuZXcgQnl0ZUFycmF5KCBbIDB4NkYsIDB4MDAgXSApO1xyXG5cclxuICAgICAgdGhpcy5tdm0uc2V0dXBBcHBsaWNhdGlvbiggdGhpcy5zZWxlY3RlZEFwcGxldCApO1xyXG5cclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxSZXNwb25zZUFQRFU+KCBuZXcgUmVzcG9uc2VBUERVKCB7IHN3OiAweDkwMDAsIGRhdGE6IGZjaSAgfSApICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5tdm0uc2V0Q29tbWFuZEFQRFUoIGNvbW1hbmRBUERVKTtcclxuXHJcbi8vICAgIGdldFJlc3BvbnNlQVBEVSgpXHJcbi8vICAgIHtcclxuLy8gICAgICByZXR1cm4gdGhpcy5tdm0uZ2V0UmVzcG9uc2VBUERVKCk7XHJcbi8vICAgIH1cclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmU8UmVzcG9uc2VBUERVPiggbmV3IFJlc3BvbnNlQVBEVSggeyBzdzogMHg5MDAwLCBkYXRhOiBbXSAgfSApICk7XHJcblxyXG4gICAgLy9yZXR1cm4gdGhpcy5leGVjdXRlQVBEVSggY29tbWFuZEFQRFUgKTtcclxuICB9XHJcblxyXG4gIG1lbW9yeU1hbmFnZXI6IE1lbW9yeU1hbmFnZXI7XHJcblxyXG4gIC8vIENhcmQgTWVtb3J5IFNlZ21lbnRzXHJcbiAgcm9tU2VnbWVudDsgICAgICAvLyBST006IGNvZGVsZXRzXHJcbiAgbnZyYW1TZWdtZW50OyAgICAvLyBOVlJBTTogYXBwbGV0cyBjb2RlICsgZGF0YVxyXG4gIHJhbVNlZ21lbnQ7ICAgICAgLy8gUkFNOiB3b3Jrc3BhY2VcclxuXHJcbiAgbXZtO1xyXG5cclxuICBpbml0aWFsaXplVk0oIGNvbmZpZyApXHJcbiAge1xyXG4gICAgdGhpcy5tZW1vcnlNYW5hZ2VyID0gbmV3IE1lbW9yeU1hbmFnZXIoKTtcclxuXHJcbiAgICB0aGlzLnJvbVNlZ21lbnQgPSB0aGlzLm1lbW9yeU1hbmFnZXIubmV3U2VnbWVudCggMCwgdGhpcy5jYXJkQ29uZmlnLnJvbVNpemUsIE1FTUZMQUdTLlJFQURfT05MWSApXHJcbiAgICB0aGlzLnJhbVNlZ21lbnQgPSB0aGlzLm1lbW9yeU1hbmFnZXIubmV3U2VnbWVudCggMSwgdGhpcy5jYXJkQ29uZmlnLnJhbVNpemUsIDAgKTtcclxuICAgIHRoaXMubnZyYW1TZWdtZW50ID0gdGhpcy5tZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQoIDIsIHRoaXMuY2FyZENvbmZpZy5udnJhbVNpemUsIE1FTUZMQUdTLlRSQU5TQUNUSU9OQUJMRSApO1xyXG5cclxuICAgIHRoaXMubXZtID0gbmV3IE1FTFZpcnR1YWxNYWNoaW5lKCk7XHJcblxyXG4gICAgdGhpcy5yZXNldFZNKCk7XHJcbiAgfVxyXG5cclxuICByZXNldFZNKClcclxuICB7XHJcbiAgICAvLyBmaXJzdCB0aW1lIC4uLlxyXG4gICAgLy8gaW5pdCBWaXJ0dWFsTWFjaGluZVxyXG4gICAgdmFyIG12bVBhcmFtcyA9IHtcclxuICAgICAgcmFtU2VnbWVudDogdGhpcy5yYW1TZWdtZW50LFxyXG4gICAgICByb21TZWdtZW50OiB0aGlzLnJvbVNlZ21lbnQsXHJcbiAgICAgIHB1YmxpY1NpemU6IHRoaXMuY2FyZENvbmZpZy5wdWJsaWNTaXplXHJcbiAgICB9O1xyXG5cclxuICAgIHRoaXMubXZtLmluaXRNVk0oIG12bVBhcmFtcyApO1xyXG4gIH1cclxuXHJcbiAgc2h1dGRvd25WTSgpXHJcbiAge1xyXG4gICAgdGhpcy5yZXNldFZNKCk7XHJcbiAgICB0aGlzLm12bSA9IG51bGw7XHJcbiAgfVxyXG5cclxuICBzZWxlY3RBcHBsaWNhdGlvbiggYXBwbGV0OiBKU0lNTXVsdG9zQXBwbGV0LCBzZXNzaW9uU2l6ZSApXHJcbiAge1xyXG4gICAgdmFyIGV4ZWNQYXJhbXMgPSB7XHJcbiAgICAgIGNvZGVBcmVhOiBhcHBsZXQuY29kZUFyZWEsXHJcbiAgICAgIHN0YXRpY0FyZWE6IGFwcGxldC5zdGF0aWNBcmVhLFxyXG4gICAgICBzZXNzaW9uU2l6ZTogc2Vzc2lvblNpemVcclxuICAgIH07XHJcblxyXG4gICAgdGhpcy5tdm0uZXhlY0FwcGxpY2F0aW9uKCBleGVjUGFyYW1zICk7XHJcbiAgfVxyXG5cclxuICBleGVjdXRlU3RlcCgpXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMubXZtLmV4ZWN1dGVTdGVwKCk7XHJcbiAgfVxyXG59XHJcbiIsInZhciBzZXRaZXJvUHJpbWl0aXZlcyA9XHJcbntcclxuICAweDAxOiB7XHJcbiAgICBuYW1lOiBcIkNIRUNLX0NBU0VcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gIFx0ICB2YXIgZXhwZWN0ZWRJU089IHBvcEJ5dGUoKTtcclxuXHJcbiAgXHQgIGlmIChleHBlY3RlZElTTzwgMSB8fCBleHBlY3RlZElTTz4gNClcclxuICBcdCAgICBTZXRDQ1JGbGFnKFpmbGFnLCBmYWxzZSk7XHJcbiAgXHQgIGVsc2VcclxuICBcdCAgICBTZXRDQ1JGbGFnKFpmbGFnLCBDaGVja0lTT0Nhc2UoZXhwZWN0ZWRJU09DYXNlKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDI6IHtcclxuICAgIG5hbWU6IFwiUkVTRVRfV1dUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgc2VuZFdhaXRSZXF1ZXN0KCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDU6IHtcclxuICAgIG5hbWU6IFwiTE9BRF9DQ1JcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBwdXNoQnl0ZShDQ1IoKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDY6IHtcclxuICAgIG5hbWU6IFwiU1RPUkVfQ0NSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQ0NSKCkgPSBwb3BCeXRlKCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDc6IHtcclxuICAgIG5hbWU6IFwiU0VUX0FUUl9GSUxFX1JFQ09SRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0Qnl0ZShhZGRyKTtcclxuXHJcbiAgICAgIE1FTEFwcGxpY2F0aW9uICphID0gc3RhdGUuYXBwbGljYXRpb247XHJcbiAgICAgIGlmIChhLkFUUkZpbGVSZWNvcmRTaXplKVxyXG4gICAgICAgIGRlbGV0ZSBbXWEuQVRSRmlsZVJlY29yZDtcclxuXHJcbiAgICAgIGEuQVRSRmlsZVJlY29yZFNpemUgPSBsZW47XHJcblxyXG4gICAgICBpZiAobGVuKVxyXG4gICAgICB7XHJcbiAgICAgICAgYS5BVFJGaWxlUmVjb3JkID0gbmV3IHZhcltsZW5dO1xyXG4gICAgICAgIHJlYWQoYWRkciwgbGVuLCBhLkFUUkZpbGVSZWNvcmQpO1xyXG4gICAgICB9XHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgcHVzaEJ5dGUobGVuKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwODoge1xyXG4gICAgbmFtZTogXCJTRVRfQVRSX0hJU1RPUklDQUxfQ0hBUkFDVEVSU1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0Qnl0ZShhZGRyKTtcclxuICAgICAgdmFyIHdyaXR0ZW47XHJcbiAgICAgIHZhciBva2F5ID0gc2V0QVRSSGlzdG9yaWNhbENoYXJhY3RlcnMobGVuLCBhZGRyKzEsIHdyaXR0ZW4pO1xyXG5cclxuICAgICAgRFQoLTIpO1xyXG4gICAgICBwdXNoQnl0ZSh3cml0dGVuKTtcclxuICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgd3JpdHRlbiA8IGxlbik7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsICFva2F5KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwOToge1xyXG4gICAgbmFtZTogXCJHRVRfTUVNT1JZX1JFTElBQklMSVRZXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgZmFsc2UpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBmYWxzZSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YToge1xyXG4gICAgbmFtZTogXCJMT09LVVBcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgdmFsdWUgPSBnZXRCeXRlKGR5bmFtaWNUb3AtMyk7XHJcbiAgICAgIHZhciBhcnJBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgRFQoLTIpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBmYWxzZSk7XHJcblxyXG4gICAgICB2YXIgYXJybGVuID0gZ2V0Qnl0ZShhcnJBZGRyKTtcclxuICAgICAgZm9yICh2YXIgaT0wO2k8YXJybGVuO2krKylcclxuICAgICAgICBpZiAoZ2V0Qnl0ZShhcnJBZGRyK2krMSkgPT0gdmFsdWUpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgc2V0Qnl0ZShkeW5hbWljVG9wLTEsICh2YXIpaSk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCB0cnVlKTtcclxuICAgICAgICAgIGkgPSBhcnJsZW47XHJcbiAgICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGI6IHtcclxuICAgIG5hbWU6IFwiTUVNT1JZX0NPTVBBUkVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICB2YXIgb3AxID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgb3AyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgYmxvY2tDb21wYXJlKG9wMSwgb3AyLCBsZW4pO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Yzoge1xyXG4gICAgbmFtZTogXCJNRU1PUllfQ09QWVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBudW0gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgIHZhciBkc3QgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBzcmMgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBjb3B5KGRzdCwgc3JjLCBudW0pO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ZDoge1xyXG4gICAgbmFtZTogXCJRVUVSWV9JTlRFUkZBQ0VfVFlQRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGZhbHNlKTsgLy8gY29udGFjdFxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDEwOiB7XHJcbiAgICBuYW1lOiBcIkNPTlRST0xfQVVUT19SRVNFVF9XV1RcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICAvLyBEb2Vzbid0IGRvIGFueXRoaW5nXHJcbiAgICAgIERUKC0yKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgxMToge1xyXG4gICAgbmFtZTogXCJTRVRfRkNJX0ZJTEVfUkVDT1JEXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIHZhciBsZW4gPSBnZXRCeXRlKGFkZHIpO1xyXG5cclxuICAgICAgTUVMQXBwbGljYXRpb24gKmEgPSBzdGF0ZS5hcHBsaWNhdGlvbjtcclxuXHJcbiAgICAgIGlmIChhLkZDSVJlY29yZFNpemUpXHJcbiAgICAgICAgZGVsZXRlIFtdYS5GQ0lSZWNvcmQ7XHJcblxyXG4gICAgICBhLkZDSVJlY29yZFNpemUgPSBsZW47XHJcbiAgICAgIGEuRkNJUmVjb3JkID0gbmV3IHZhcltsZW5dO1xyXG4gICAgICByZWFkKGFkZHIgKyAxLCBsZW4sIGEuRkNJUmVjb3JkKTtcclxuICAgICAgRFQoLTIpO1xyXG4gICAgICBwdXNoQnl0ZShsZW4pO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgwOiB7XHJcbiAgICBuYW1lOiBcIkRFTEVHQVRFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgLy8gcm9sbGJhY2sgYW5kIHR1cm4gb2ZmIHRyYW5zYWN0aW9uIHByb3RlY3Rpb25cclxuICAgICAgdmFyIG0gPSBzdGF0ZS5hcHBsaWNhdGlvbi5zdGF0aWNEYXRhO1xyXG4gICAgICBpZiAobS5vbilcclxuICAgICAge1xyXG4gICAgICAgIG0uZGlzY2FyZCgpO1xyXG4gICAgICAgIG0ub24gPSBmYWxzZTtcclxuICAgICAgfVxyXG5cclxuICAgICAgdmFyIEFJREFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIERUKC0yKTtcclxuXHJcbiAgICAgIHZhciBBSURsZW4gPSBnZXRCeXRlKEFJREFkZHIpO1xyXG4gICAgICBpZiAoQUlEbGVuIDwgMSB8fCBBSURsZW4gPiAxNilcclxuICAgICAgICBzZXRXb3JkKFBUKCkrU1cxLCAweDZhODMpO1xyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICB2YXIgQUlEID0gbmV3IHZhcltBSURsZW5dO1xyXG5cclxuICAgICAgICByZWFkKEFJREFkZHIrMSwgQUlEbGVuLCBBSUQpO1xyXG4gICAgICAgIGlmICghZGVsZWdhdGVBcHBsaWNhdGlvbihBSURsZW4sIEFJRCkpXHJcbiAgICAgICAgICBzZXRXb3JkKFBUKCkrU1cxLCAweDZhODMpO1xyXG4gICAgICB9XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODE6IHtcclxuICAgIG5hbWU6IFwiUkVTRVRfU0VTU0lPTl9EQVRBXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaWYgKHN0YXRlLmFwcGxpY2F0aW9uLmlzU2hlbGxBcHApXHJcbiAgICAgICAgUmVzZXRTZXNzaW9uRGF0YSgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgyOiB7XHJcbiAgICBuYW1lOiBcIkNIRUNLU1VNXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbmd0aCA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIHZhciBjaGVja3N1bVs0XSA9IHsgMHg1YSwgMHhhNSwgMHg1YSwgMHhhNSB9O1xyXG5cclxuICAgICAgdmFyIG0gPSBzdGF0ZS5hcHBsaWNhdGlvbi5zdGF0aWNEYXRhO1xyXG4gICAgICB2YXIgYWNjb3VudEZvclRyYW5zYWN0aW9uUHJvdGVjdGlvbiA9IChhZGRyID49IG0uc3RhcnQoKSAmJiBhZGRyIDw9IG0uc3RhcnQoKSArIG0uc2l6ZSgpICYmIG0ub24pO1xyXG5cclxuICAgICAgZm9yICh2YXIgaj0wOyBqIDwgbGVuZ3RoOyBqKyspXHJcbiAgICAgIHtcclxuICAgICAgICBpZiAoYWNjb3VudEZvclRyYW5zYWN0aW9uUHJvdGVjdGlvbilcclxuICAgICAgICAgIGNoZWNrc3VtWzBdICs9ICh2YXIpbS5yZWFkUGVuZGluZ0J5dGVNZW1vcnkoYWRkcitqKTtcclxuICAgICAgICBlbHNlXHJcbiAgICAgICAgICBjaGVja3N1bVswXSArPSAodmFyKWdldEJ5dGUoYWRkciArIGopO1xyXG5cclxuICAgICAgICBjaGVja3N1bVsxXSArPSBjaGVja3N1bVswXTtcclxuICAgICAgICBjaGVja3N1bVsyXSArPSBjaGVja3N1bVsxXTtcclxuICAgICAgICBjaGVja3N1bVszXSArPSBjaGVja3N1bVsyXTtcclxuICAgICAgfVxyXG4gICAgICB3cml0ZShkeW5hbWljVG9wLTQsIDQsIGNoZWNrc3VtKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4Mzoge1xyXG4gICAgbmFtZTogXCJDQUxMX0NPREVMRVRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgY29kZWxldElkID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgY29kZWFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBEVCgtNCk7XHJcbiAgICAgIGNhbGxDb2RlbGV0KGNvZGVsZXRJZCwgY29kZWFkZHIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDg0OiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZX0NPREVMRVRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgY29kZWxldElkID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgcXVlcnlDb2RlbGV0KGNvZGVsZXRJZCkpO1xyXG4gICAgICBEVCgtMik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzE6IHtcclxuICAgIG5hbWU6IFwiREVTX0VDQl9FTkNJUEhFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSw4KTtcclxuICAgICAgdmFyIHBsYWludGV4dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgdmFyICpjaXBoZXJ0ZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSw4KTtcclxuICAgICAgdmFyIHBsYWludGV4dFs4XTtcclxuXHJcbiAgICAgIG10aF9kZXMoREVTX0RFQ1JZUFQsIGtleSwgY2lwaGVydGV4dCwgcGxhaW50ZXh0KTtcclxuICAgICAgd3JpdGUocGxhaW50ZXh0QWRkciwgOCwgcGxhaW50ZXh0KTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGMyOiB7XHJcbiAgICBuYW1lOiBcIk1PRFVMQVJfTVVMVElQTElDQVRJT05cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbW9kbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICBjb25zdCB2YXIgKmxocyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBtb2RsZW4pO1xyXG4gICAgICBjb25zdCB2YXIgKnJocyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBtb2RsZW4pO1xyXG4gICAgICBjb25zdCB2YXIgKm1vZCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBtb2RsZW4pO1xyXG4gICAgICB2YXIgKnJlcyA9IG5ldyB2YXJbbW9kbGVuXTtcclxuICAgICAgbXRoX21vZF9tdWx0KGxocywgbW9kbGVuLCByaHMsIG1vZGxlbiwgbW9kLCBtb2RsZW4sIHJlcyk7XHJcbiAgICAgIHdyaXRlKGdldFdvcmQoZHluYW1pY1RvcC02KSwgbW9kbGVuLCByZXMpO1xyXG4gICAgICBEVCgtOCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzM6IHtcclxuICAgIG5hbWU6IFwiTU9EVUxBUl9SRURVQ1RJT05cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgb3BsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtOCk7XHJcbiAgICAgIHZhciBtb2RsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgIGNvbnN0IHZhciAqb3AgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgb3BsZW4pO1xyXG4gICAgICBjb25zdCB2YXIgKm1vZCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBvcGxlbik7XHJcbiAgICAgIHZhciAqcmVzID0gbmV3IHZhcltvcGxlbl07XHJcbiAgICAgIG10aF9tb2RfcmVkKG9wLCBvcGxlbiwgbW9kLCBtb2RsZW4sIHJlcyk7XHJcbiAgICAgIHdyaXRlKGdldFdvcmQoZHluYW1pY1RvcC00KSwgb3BsZW4sIHJlcyk7XHJcbiAgICAgIERUKC04KTtcclxuICAgICAgZGVsZXRlIFtdcmVzO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM0OiB7XHJcbiAgICBuYW1lOiBcIkdFVF9SQU5ET01fTlVNQkVSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIHJhbmRbOF07XHJcbiAgICAgIHJhbmRkYXRhKHJhbmQsIDgpO1xyXG4gICAgICBEVCg4KTtcclxuICAgICAgd3JpdGUoZHluYW1pY1RvcC04LCA4LCByYW5kKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNToge1xyXG4gICAgbmFtZTogXCJERVNfRUNCX0RFQ0lQSEVSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyICprZXkgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDYpLDgpO1xyXG4gICAgICB2YXIgY2lwaGVyQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgKnBsYWludGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksOCk7XHJcbiAgICAgIHZhciBjaXBoZXJ0ZXh0WzhdO1xyXG5cclxuICAgICAgbXRoX2RlcyhERVNfRU5DUllQVCwga2V5LCBwbGFpbnRleHQsIGNpcGhlcnRleHQpO1xyXG4gICAgICB3cml0ZShjaXBoZXJBZGRyLCA4LCBjaXBoZXJ0ZXh0KTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM2OiB7XHJcbiAgICBuYW1lOiBcIkdFTkVSQVRFX0RFU19DQkNfU0lHTkFUVVJFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIHBsYWluVGV4dExlbmd0aCA9IGdldFdvcmQoZHluYW1pY1RvcC0weGEpO1xyXG4gICAgICB2YXIgSVZhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4OCk7XHJcbiAgICAgIHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSwgOCk7XHJcbiAgICAgIHZhciBzaWduYXR1cmVBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIHZhciAqcGxhaW5UZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSwgcGxhaW5UZXh0TGVuZ3RoKTtcclxuICAgICAgdmFyIHNpZ25hdHVyZVs4XTtcclxuXHJcbiAgICAgIHJlYWQoSVZhZGRyLCA4LCBzaWduYXR1cmUpO1xyXG4gICAgICB3aGlsZSAocGxhaW5UZXh0TGVuZ3RoID49IDgpXHJcbiAgICAgIHtcclxuICAgICAgICBmb3IgKHZhciBpPTA7aTw4O2krKylcclxuICAgICAgICAgIHNpZ25hdHVyZVtpXSBePSBwbGFpblRleHRbaV07XHJcblxyXG4gICAgICAgIHZhciBlbmNyeXB0ZWRTaWduYXR1cmVbOF07XHJcblxyXG4gICAgICAgIG10aF9kZXMoREVTX0VOQ1JZUFQsIGtleSwgc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUpO1xyXG4gICAgICAgIG1lbWNweShzaWduYXR1cmUsIGVuY3J5cHRlZFNpZ25hdHVyZSwgOCk7XHJcbiAgICAgICAgcGxhaW5UZXh0TGVuZ3RoIC09IDg7XHJcbiAgICAgICAgcGxhaW5UZXh0ICs9IDg7XHJcbiAgICAgIH1cclxuICAgICAgd3JpdGUoc2lnbmF0dXJlQWRkciwgOCwgc2lnbmF0dXJlKTtcclxuICAgICAgRFQoLTEwKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNzoge1xyXG4gICAgbmFtZTogXCJHRU5FUkFURV9UUklQTEVfREVTX0NCQ19TSUdOQVRVUkVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpbnQgcGxhaW5UZXh0TGVuZ3RoID0gZ2V0V29yZChkeW5hbWljVG9wLTB4YSk7XHJcbiAgICAgIHZhciBJVmFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg4KTtcclxuICAgICAgdmFyIGtleTEgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDYpLCAxNik7XHJcbiAgICAgIHZhciBrZXkyID0ga2V5MSArIDg7XHJcbiAgICAgIHZhciBzaWduYXR1cmVBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIHZhciBwbGFpblRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDIpLCBwbGFpblRleHRMZW5ndGgpO1xyXG4gICAgICB2YXIgc2lnbmF0dXJlWzhdO1xyXG5cclxuICAgICAgcmVhZChJVmFkZHIsIDgsIHNpZ25hdHVyZSk7XHJcbiAgICAgIHdoaWxlIChwbGFpblRleHRMZW5ndGggPiAwKVxyXG4gICAgICB7XHJcbiAgICAgICAgZm9yICh2YXIgaT0wO2k8ODtpKyspXHJcbiAgICAgICAgICBzaWduYXR1cmVbaV0gXj0gcGxhaW5UZXh0W2ldO1xyXG5cclxuICAgICAgICB2YXIgZW5jcnlwdGVkU2lnbmF0dXJlWzhdO1xyXG5cclxuICAgICAgICBtdGhfZGVzKERFU19FTkNSWVBULCBrZXkxLCBzaWduYXR1cmUsIGVuY3J5cHRlZFNpZ25hdHVyZSk7XHJcbiAgICAgICAgbXRoX2RlcyhERVNfREVDUllQVCwga2V5MiwgZW5jcnlwdGVkU2lnbmF0dXJlLCBzaWduYXR1cmUpO1xyXG4gICAgICAgIG10aF9kZXMoREVTX0VOQ1JZUFQsIGtleTEsIHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlKTtcclxuICAgICAgICBtZW1jcHkoc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUsIDgpO1xyXG4gICAgICAgIHBsYWluVGV4dExlbmd0aCAtPSA4O1xyXG4gICAgICAgIHBsYWluVGV4dCArPSA4O1xyXG4gICAgICB9XHJcbiAgICAgIHdyaXRlKHNpZ25hdHVyZUFkZHIsIDgsIHNpZ25hdHVyZSk7XHJcbiAgICAgIERUKC0xMCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Yzg6IHtcclxuICAgIG5hbWU6IFwiTU9EVUxBUl9FWFBPTkVOVElBVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBleHBsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHhjKTtcclxuICAgICAgdmFyIG1vZGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0weGEpO1xyXG4gICAgICB2YXIgZXhwb25lbnQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDgpLCBleHBsZW4pO1xyXG4gICAgICB2YXIgbW9kID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSwgbW9kbGVuKTtcclxuICAgICAgdmFyIGJhc2UgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDQpLCBtb2RsZW4pO1xyXG4gICAgICB2YXIgcmVzQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDIpO1xyXG4gICAgICB2YXIgcmVzID0gbmV3IHZhclttb2RsZW5dO1xyXG5cclxuICAgICAgbXRoX21vZF9leHAoYmFzZSwgbW9kbGVuLCBleHBvbmVudCwgZXhwbGVuLCBtb2QsIG1vZGxlbiwgcmVzKTtcclxuICAgICAgd3JpdGUocmVzQWRkciwgbW9kbGVuLCByZXMpO1xyXG4gICAgICBEVCgtMTIpO1xyXG5cclxuICAgICAgZGVsZXRlIFtdcmVzO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM5OiB7XHJcbiAgICBuYW1lOiBcIk1PRFVMQVJfRVhQT05FTlRJQVRJT05fQ1JUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG1vZHVsdXNfbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgdmFyIGRwZHEgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC04KSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICB2YXIgcHF1ICA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBtb2R1bHVzX2xlbiAqIDMgLyAyKTtcclxuICAgICAgdmFyIGJhc2UgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICB2YXIgb3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIHJlcyA9IG5ldyB2YXJbbW9kdWx1c19sZW5dO1xyXG5cclxuICAgICAgbXRoX21vZF9leHBfY3J0KG1vZHVsdXNfbGVuLCBkcGRxLCBwcXUsIGJhc2UsIHJlcyk7XHJcbiAgICAgIHdyaXRlKG91dEFkZHIsIG1vZHVsdXNfbGVuLCByZXMpO1xyXG4gICAgICBEVCgtMTApO1xyXG4gICAgICBkZWxldGVbXSByZXM7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Y2E6IHtcclxuICAgIG5hbWU6IFwiU0hBMVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBwbGFpbnRleHRMZW5ndGggPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KTtcclxuICAgICAgdmFyIGhhc2hEaWdlc3RBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIHZhciBwbGFpbnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDIpLCBwbGFpbnRleHRMZW5ndGgpO1xyXG4gICAgICB2YXIgbG9uZyBoYXNoRGlnZXN0WzVdOyAvLyAyMCBieXRlIGhhc2hcclxuXHJcbiAgICAgIG10aF9zaGFfaW5pdChoYXNoRGlnZXN0KTtcclxuXHJcbiAgICAgIHdoaWxlIChwbGFpbnRleHRMZW5ndGggPiA2NClcclxuICAgICAge1xyXG4gICAgICAgIG10aF9zaGFfdXBkYXRlKGhhc2hEaWdlc3QsICh2YXIgKilwbGFpbnRleHQpO1xyXG4gICAgICAgIHBsYWludGV4dCArPSA2NDtcclxuICAgICAgICBwbGFpbnRleHRMZW5ndGggLT0gNjQ7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIG10aF9zaGFfZmluYWwoaGFzaERpZ2VzdCwgKHZhciAqKXBsYWludGV4dCwgcGxhaW50ZXh0TGVuZ3RoKTtcclxuXHJcbiAgICAgIGZvciAoaW50IGk9MDtpPDU7aSsrKVxyXG4gICAgICAgIHdyaXRlTnVtYmVyKGhhc2hEaWdlc3RBZGRyKyhpKjQpLCA0LCBoYXNoRGlnZXN0W2ldKTtcclxuXHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjYzoge1xyXG4gICAgbmFtZTogXCJHRU5FUkFURV9SQU5ET01fUFJJTUVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgZ2NkRmxhZyA9IGdldEJ5dGUoZHluYW1pY1RvcC0xMyk7XHJcbiAgICAgIHZhciBjb25mID0gZ2V0V29yZChkeW5hbWljVG9wLTEyKTtcclxuICAgICAgdmFyIHRpbWVvdXQgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICB2YXIgcmdFeHAgPSBnZXRXb3JkKGR5bmFtaWNUb3AtOCk7XHJcbiAgICAgIGNvbnN0IHZhciAqbWluTG9jID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIDQpO1xyXG4gICAgICBjb25zdCB2YXIgKm1heExvYyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCA0KTtcclxuICAgICAgdmFyIHJlc0FkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKTtcclxuICAgICAgaWYgKChyZ0V4cCA8IDUpIHx8IChyZ0V4cCA+IDI1NikpXHJcbiAgICAgIHtcclxuICAgICAgICBBYmVuZChcInJnRXhwIHBhcmFtZXRlciBvdXQgb2YgcmFuZ2VcIik7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgc3RhdGljIGNvbnN0IHZsb25nIG9uZSgxKTtcclxuICAgICAgICBzdGF0aWMgY29uc3QgdmxvbmcgdGhyZWUoMyk7XHJcbiAgICAgICAgc3RkOjp2ZWN0b3I8dmFyPiBjYW5kaWRhdGUocmdFeHApO1xyXG4gICAgICAgIGZvciAoOzspXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgc3RkOjpnZW5lcmF0ZShjYW5kaWRhdGUuYmVnaW4oKSwgY2FuZGlkYXRlLmVuZCgpLCByYW5kKTtcclxuICAgICAgICAgIGlmIChzdGQ6OmxleGljb2dyYXBoaWNhbF9jb21wYXJlKFxyXG4gICAgICAgICAgICAgICAgY2FuZGlkYXRlLmJlZ2luKCksIGNhbmRpZGF0ZS5lbmQoKSxcclxuICAgICAgICAgICAgICAgIG1pbkxvYywgbWluTG9jICsgNCkpXHJcbiAgICAgICAgICAgIGNvbnRpbnVlO1xyXG4gICAgICAgICAgaWYgKHN0ZDo6bGV4aWNvZ3JhcGhpY2FsX2NvbXBhcmUoXHJcbiAgICAgICAgICAgICAgICBtYXhMb2MsIG1heExvYyArIDQsXHJcbiAgICAgICAgICAgICAgICBjYW5kaWRhdGUuYmVnaW4oKSwgY2FuZGlkYXRlLmVuZCgpKSlcclxuICAgICAgICAgICAgY29udGludWU7XHJcbiAgICAgICAgICB2bG9uZyB2bG9uZ19jYW5kaWRhdGUoY2FuZGlkYXRlLnNpemUoKSwgJmNhbmRpZGF0ZVswXSk7XHJcbiAgICAgICAgICBpZiAoMHg4MCA9PSBnY2RGbGFnKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBpZiAob25lICE9IGdjZCh0aHJlZSwgdmxvbmdfY2FuZGlkYXRlKSlcclxuICAgICAgICAgICAgICBjb250aW51ZTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGlmICghaXNfcHJvYmFibGVfcHJpbWUodmxvbmdfY2FuZGlkYXRlKSlcclxuICAgICAgICAgICAgY29udGludWU7XHJcblxyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHdyaXRlKHJlc0FkZHIsIHJnRXhwLCAmY2FuZGlkYXRlWzBdKTtcclxuICAgICAgICBEVCgtMTMpO1xyXG4gICAgICB9XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Y2Q6IHtcclxuICAgIG5hbWU6IFwiU0VFRF9FQ0JfREVDSVBIRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBzdGF0aWMgY29uc3QgdmFyIGJsb2NrX3NpemUgPSAxNjtcclxuXHJcbiAgICAgIGNvbnN0IHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIGJsb2NrX3NpemUpO1xyXG4gICAgICB2YXIgcmVzQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICBjb25zdCB2YXIgKnBsYWludGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBibG9ja19zaXplKTtcclxuXHJcbiAgICAgIHZhciBidWZmZXJbYmxvY2tfc2l6ZV07XHJcbiAgICAgIG1lbWNweShidWZmZXIsIGtleSwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIERXT1JEIHJvdW5kX2tleVsyICogYmxvY2tfc2l6ZV07XHJcbiAgICAgIFNlZWRFbmNSb3VuZEtleShyb3VuZF9rZXksIGJ1ZmZlcik7XHJcbiAgICAgIG1lbWNweShidWZmZXIsIHBsYWludGV4dCwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIFNlZWREZWNyeXB0KGJ1ZmZlciwgcm91bmRfa2V5KTtcclxuXHJcbiAgICAgIHdyaXRlKHJlc0FkZHIsIGJsb2NrX3NpemUsIGJ1ZmZlcik7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjZToge1xyXG4gICAgbmFtZTogXCJTRUVEX0VDQl9FTkNJUEhFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHN0YXRpYyBjb25zdCB2YXIgYmxvY2tfc2l6ZSA9IDE2O1xyXG5cclxuICAgICAgY29uc3QgdmFyICprZXkgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIHZhciByZXNBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIGNvbnN0IHZhciAqcGxhaW50ZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIGJsb2NrX3NpemUpO1xyXG5cclxuICAgICAgdmFyIGJ1ZmZlcltibG9ja19zaXplXTtcclxuICAgICAgbWVtY3B5KGJ1ZmZlciwga2V5LCBibG9ja19zaXplKTtcclxuICAgICAgRFdPUkQgcm91bmRfa2V5WzIgKiBibG9ja19zaXplXTtcclxuICAgICAgU2VlZEVuY1JvdW5kS2V5KHJvdW5kX2tleSwgYnVmZmVyKTtcclxuICAgICAgbWVtY3B5KGJ1ZmZlciwgcGxhaW50ZXh0LCBibG9ja19zaXplKTtcclxuICAgICAgU2VlZEVuY3J5cHQoYnVmZmVyLCByb3VuZF9rZXkpO1xyXG5cclxuICAgICAgd3JpdGUocmVzQWRkciwgYmxvY2tfc2l6ZSwgYnVmZmVyKTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfVxyXG59O1xyXG5cclxudmFyIHNldE9uZVByaW1pdGl2ZXMgPVxyXG57XHJcbiAgMHgwMDoge1xyXG4gICAgbmFtZTogXCJRVUVSWTBcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpID0gcHJpbTAuZmluZChhcmcxKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgaSAhPSBwcmltMC5lbmQoKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDE6IHtcclxuICAgIG5hbWU6IFwiUVVFUlkxXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaSA9IHByaW0xLmZpbmQoYXJnMSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGkgIT0gcHJpbTEuZW5kKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAyOiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZMlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGkgPSBwcmltMi5maW5kKGFyZzEpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBpICE9IHByaW0yLmVuZCgpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMzoge1xyXG4gICAgbmFtZTogXCJRVUVSWTNcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpID0gcHJpbTMuZmluZChhcmcxKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgaSAhPSBwcmltMy5lbmQoKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDg6IHtcclxuICAgIG5hbWU6IFwiRElWSURFTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW4gPSBhcmcxO1xyXG4gICAgICB2YXIgKmRlbm9taW5hdG9yID0gZHVtcChkeW5hbWljVG9wLWxlbiwgbGVuKTtcclxuICAgICAgaWYgKGJsb2NrSXNaZXJvKGRlbm9taW5hdG9yLCBsZW4pKVxyXG4gICAgICB7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgdHJ1ZSk7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgY29uc3QgdmFyICpudW1lcmF0b3IgPSBkdW1wKGR5bmFtaWNUb3AtMipsZW4sIGxlbik7XHJcbiAgICAgICAgdmFyICpxdW90aWVudCA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgICB2YXIgKnJlbWFpbmRlciA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgICBtdGhfZGl2KG51bWVyYXRvciwgZGVub21pbmF0b3IsIGxlbiwgcXVvdGllbnQsIHJlbWFpbmRlcik7XHJcbiAgICAgICAgd3JpdGUoZHluYW1pY1RvcC0yKmxlbiwgbGVuLCBxdW90aWVudCk7XHJcbiAgICAgICAgd3JpdGUoZHluYW1pY1RvcC1sZW4sIGxlbiwgcmVtYWluZGVyKTtcclxuICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCBmYWxzZSk7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgYmxvY2tJc1plcm8ocXVvdGllbnQsbGVuKSk7XHJcbiAgICAgICAgZGVsZXRlIFtdcXVvdGllbnQ7XHJcbiAgICAgICAgZGVsZXRlIFtdcmVtYWluZGVyO1xyXG4gICAgICB9XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDk6IHtcclxuICAgIG5hbWU6IFwiR0VUX0RJUl9GSUxFX1JFQ09SRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIC8vIFNhbWUgYXMgYmVsb3dcclxuICAgICAgTVVMVE9TLlByaW1pdGl2ZXMuc2V0T25lUHJpbWl0aXZlc1sgMHgwYSBdLnByb2MoKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwYToge1xyXG4gICAgbmFtZTogXCJHRVRfRklMRV9DT05UUk9MX0lORk9STUFUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGFyZzE7XHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTMpO1xyXG4gICAgICB2YXIgcmVjb3JkTnVtYmVyID0gZ2V0Qnl0ZShkeW5hbWljVG9wLTEpO1xyXG4gICAgICB2YXIgb2theTtcclxuICAgICAgdmFyICpkYXRhO1xyXG4gICAgICB2YXIgZGF0YWxlbjtcclxuICAgICAgaWYgKHByaW0gPT0gR0VUX0RJUl9GSUxFX1JFQ09SRClcclxuICAgICAgICBva2F5ID0gZ2V0RGlyRmlsZVJlY29yZChyZWNvcmROdW1iZXItMSwgJmRhdGFsZW4sICZkYXRhKTtcclxuICAgICAgZWxzZVxyXG4gICAgICAgIG9rYXkgPSBnZXRGQ0kocmVjb3JkTnVtYmVyLTEsICZkYXRhbGVuLCAmZGF0YSk7XHJcbiAgICAgIGlmIChva2F5KVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciBjb3BpZWQgPSBsZW4gPCBkYXRhbGVuID8gbGVuIDogZGF0YWxlbjtcclxuICAgICAgICAgIGlmIChjb3BpZWQpXHJcbiAgICAgICAgICAgIHdyaXRlKGFkZHIsIGNvcGllZCwgZGF0YSk7XHJcbiAgICAgICAgICBwdXNoQnl0ZShjb3BpZWQpO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgKGNvcGllZCA8IGxlbikpO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgMCk7XHJcbiAgICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcHVzaEJ5dGUoMCk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCAxKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoWmZsYWcsIDEpO1xyXG4gICAgICAgIH1cclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwYjoge1xyXG4gICAgbmFtZTogXCJHRVRfTUFOVUZBQ1RVUkVSX0RBVEFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgRFQoLTEpO1xyXG4gICAgICB2YXIgbWFudWZhY3R1cmVyWzI1Nl07XHJcbiAgICAgIHZhciBsZW4gPSBnZXRNYW51ZmFjdHVyZXJEYXRhKG1hbnVmYWN0dXJlcik7XHJcbiAgICAgIGxlbiA9IGFyZzEgPCBsZW4gPyBhcmcxIDogbGVuO1xyXG4gICAgICBpZiAobGVuKVxyXG4gICAgICAgIHdyaXRlKGFkZHIsIGxlbiwgbWFudWZhY3R1cmVyKTtcclxuICAgICAgc2V0Qnl0ZShkeW5hbWljVG9wLTEsICh2YXIpbGVuKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwYzoge1xyXG4gICAgbmFtZTogXCJHRVRfTVVMVE9TX0RBVEFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgRFQoLTEpO1xyXG4gICAgICB2YXIgTVVMVE9TRGF0YVsyNTZdO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0TVVMVE9TRGF0YShNVUxUT1NEYXRhKTtcclxuICAgICAgaWYgKGxlbilcclxuICAgICAgICBsZW4gPSBhcmcxIDwgbGVuID8gYXJnMSA6IGxlbjtcclxuICAgICAgd3JpdGUoYWRkciwgbGVuLCBNVUxUT1NEYXRhKTtcclxuICAgICAgc2V0Qnl0ZShkeW5hbWljVG9wLTEsICh2YXIpbGVuKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwZDoge1xyXG4gICAgbmFtZTogXCJHRVRfUFVSU0VfVFlQRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGU6IHtcclxuICAgIG5hbWU6IFwiTUVNT1JZX0NPUFlfRklYRURfTEVOR1RIXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGRzdCA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIHNyYyA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIGNvcHkoZHN0LCBzcmMsIGFyZzEpO1xyXG4gICAgICBEVCgtNCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGY6IHtcclxuICAgIG5hbWU6IFwiTUVNT1JZX0NPTVBBUkVfRklYRURfTEVOR1RIXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG9wMSA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIG9wMiA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgYmxvY2tDb21wYXJlKG9wMSwgb3AyLCBhcmcxKTtcclxuICAgICAgRFQoLTQpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDEwOiB7XHJcbiAgICBuYW1lOiBcIk1VTFRJUExZTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW4gPSBhcmcxO1xyXG4gICAgICBjb25zdCB2YXIgKm9wMSA9IGR1bXAoZHluYW1pY1RvcC0yKmxlbiwgbGVuKTtcclxuICAgICAgY29uc3QgdmFyICpvcDIgPSBkdW1wKGR5bmFtaWNUb3AtbGVuLCBsZW4pO1xyXG4gICAgICB2YXIgKnJlcyA9IG5ldyB2YXJbbGVuKjJdO1xyXG4gICAgICBtdGhfbXVsKG9wMSwgb3AyLCBsZW4sIHJlcyk7XHJcbiAgICAgIHdyaXRlKGR5bmFtaWNUb3AtMipsZW4sIGxlbioyLCByZXMpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBibG9ja0lzWmVybyhyZXMsbGVuKjIpKTtcclxuICAgICAgZGVsZXRlIFtdcmVzO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgwOiB7XHJcbiAgICBuYW1lOiBcIlNFVF9UUkFOU0FDVElPTl9QUk9URUNUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG0gPSBzdGF0ZS5hcHBsaWNhdGlvbi5zdGF0aWNEYXRhO1xyXG4gICAgICBpZiAobS5vbilcclxuICAgICAgICB7XHJcbiAgICAgICAgICBpZiAoYXJnMSAmIDEpXHJcbiAgICAgICAgICAgIG0uY29tbWl0KCk7XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIG0uZGlzY2FyZCgpO1xyXG4gICAgICAgIH1cclxuICAgICAgaWYgKGFyZzEgJiAyKVxyXG4gICAgICAgIG0ub24gPSB0cnVlO1xyXG4gICAgICBlbHNlXHJcbiAgICAgICAgbS5vbiA9IGZhbHNlO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgxOiB7XHJcbiAgICBuYW1lOiBcIkdFVF9ERUxFR0FUT1JfQUlEXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIEFJREFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgTUVMRXhlY3V0aW9uU3RhdGUgKmUgPSBnZXREZWxlZ2F0b3JTdGF0ZSgpO1xyXG4gICAgICBpZiAoZSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgbGVuO1xyXG4gICAgICAgICAgaWYgKCBhcmcxIDwgZS5hcHBsaWNhdGlvbi5BSURsZW5ndGgpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICBsZW4gPSBhcmcxO1xyXG4gICAgICAgICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIHRydWUpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICBsZW4gPSAgZS5hcHBsaWNhdGlvbi5BSURsZW5ndGg7XHJcbiAgICAgICAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgZmFsc2UpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICBzZXRCeXRlKEFJREFkZHIsICh2YXIpbGVuKTtcclxuICAgICAgICAgIEFJREFkZHIrKztcclxuICAgICAgICAgIGZvciAodmFyIGk9MDsgaSA8IGxlbjsgaSsrKVxyXG4gICAgICAgICAgICBzZXRCeXRlKEFJREFkZHIraSwgZS5hcHBsaWNhdGlvbi5BSURbaV0pO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG4gICAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICAgIFNldENDUkZsYWcoWmZsYWcsIHRydWUpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM0OiB7XHJcbiAgICBuYW1lOiBcIkdFTkVSQVRFX0FTWU1NRVRSSUNfSEFTSFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGNvbnN0IHZhciAqaXY7XHJcbiAgICAgIHZhciBwbGFpbl9sZW47XHJcbiAgICAgIHZhciBkaWdlc3RPdXRBZGRyO1xyXG4gICAgICBjb25zdCB2YXIgKnBsYWluO1xyXG4gICAgICBNRUxLZXkqIGFoYXNoS2V5O1xyXG4gICAgICBpbnQgZHR2YWw7XHJcbiAgICAgIHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4gc21rdztcclxuICAgICAgdmFyIGhjbCA9IDE2O1xyXG5cclxuICAgICAgc3dpdGNoIChhcmcxKVxyXG4gICAgICB7XHJcbiAgICAgICAgY2FzZSAwOlxyXG4gICAgICAgICAgaXYgPSAwO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICBhaGFzaEtleSA9IGdldEFIYXNoS2V5KCk7XHJcbiAgICAgICAgICBkdHZhbCA9IC02O1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgMTpcclxuICAgICAgICAgIGl2ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtOCksIDE2KTtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBnZXRBSGFzaEtleSgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtNjtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIDI6XHJcbiAgICAgICAgICBpdiA9IDA7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1cyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgICAgICBzbWt3ID0gc3RkOjphdXRvX3B0cjxTaW1wbGVNRUxLZXlXcmFwcGVyPihuZXcgU2ltcGxlTUVMS2V5V3JhcHBlcihtb2R1bHVzX2xlbiwgbW9kdWx1cykpO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBzbWt3LmdldCgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtMTA7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSAzOlxyXG4gICAgICAgICAgaXYgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0xMiksIDE2KTtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgICAgIGNvbnN0IHZhciogbW9kdWx1cyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgICAgICBzbWt3ID0gc3RkOjphdXRvX3B0cjxTaW1wbGVNRUxLZXlXcmFwcGVyPihuZXcgU2ltcGxlTUVMS2V5V3JhcHBlcihtb2R1bHVzX2xlbiwgbW9kdWx1cykpO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBzbWt3LmdldCgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtMTI7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSA0OlxyXG4gICAgICAgICAgaXYgPSAwO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEyKTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC04KSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgICAgIGNvbnN0IHZhciogbW9kdWx1cyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgICAgICBzbWt3ID0gc3RkOjphdXRvX3B0cjxTaW1wbGVNRUxLZXlXcmFwcGVyPihuZXcgU2ltcGxlTUVMS2V5V3JhcHBlcihtb2R1bHVzX2xlbiwgbW9kdWx1cykpO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBzbWt3LmdldCgpO1xyXG4gICAgICAgICAgaGNsID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtMTI7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSA1OlxyXG4gICAgICAgICAgaGNsID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICAgICAgaXYgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0xNCksIGhjbCk7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTIpO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTgpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXNfbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICAgICAgY29uc3QgdmFyKiBtb2R1bHVzID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgICAgIHNta3cgPSBzdGQ6OmF1dG9fcHRyPFNpbXBsZU1FTEtleVdyYXBwZXI+KG5ldyBTaW1wbGVNRUxLZXlXcmFwcGVyKG1vZHVsdXNfbGVuLCBtb2R1bHVzKSk7XHJcbiAgICAgICAgICBhaGFzaEtleSA9IHNta3cuZ2V0KCk7XHJcbiAgICAgICAgICBkdHZhbCA9IC0xNDtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgQWJlbmQoXCJiYWQgYjIgdmFsdWUgZm9yIEdlbmVyYXRlQXN5bW1ldHJpY0hhc2ggcHJpbWl0aXZlXCIpO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHN0ZDo6dmVjdG9yPHZhcj4gaGFzaChoY2wpO1xyXG4gICAgICBBSGFzaChhaGFzaEtleSwgcGxhaW5fbGVuLCBwbGFpbiwgJmhhc2hbMF0sIGl2LCBoY2wpO1xyXG4gICAgICB3cml0ZShkaWdlc3RPdXRBZGRyLCBoY2wsICZoYXNoWzBdKTtcclxuICAgICAgRFQoZHR2YWwpO1xyXG4gICAgKi99XHJcbiAgfVxyXG59O1xyXG5cclxuZnVuY3Rpb24gYml0TWFuaXB1bGF0ZShiaXRtYXAsIGxpdGVyYWwsIGRhdGEpXHJcbntcclxuICB2YXIgbW9kaWZ5ID0gKChiaXRtYXAgJiAoMTw8NykpID09ICgxPDw3KSk7XHJcbiAgaWYgKGJpdG1hcCAmIDB4N2MpIC8vIGJpdHMgNi0yIHNob3VsZCBiZSB6ZXJvXHJcbiAgICB0aHJvdyBuZXcgRXJyb3IoIFwiVW5kZWZpbmVkIGFyZ3VtZW50c1wiKTtcclxuXHJcbiAgc3dpdGNoIChiaXRtYXAgJiAzKVxyXG4gIHtcclxuICAgIGNhc2UgMzpcclxuICAgICAgZGF0YSAmPSBsaXRlcmFsO1xyXG4gICAgICBicmVhaztcclxuICAgIGNhc2UgMjpcclxuICAgICAgZGF0YSB8PSBsaXRlcmFsO1xyXG4gICAgICBicmVhaztcclxuICAgIGNhc2UgMTpcclxuICAgICAgZGF0YSA9IH4oZGF0YSBeIGxpdGVyYWwpO1xyXG4gICAgICBicmVhaztcclxuICAgIGNhc2UgMDpcclxuICAgICAgZGF0YSBePSBsaXRlcmFsO1xyXG4gICAgICBicmVhaztcclxuICB9XHJcblxyXG4gIC8vU2V0Q0NSRmxhZyhaZmxhZywgZGF0YT09MCk7XHJcblxyXG4gIHJldHVybiBtb2RpZnk7IC8vVE9ETzogcmV0dXJuIGRhdGFcclxufVxyXG5cclxudmFyIHNldFR3b1ByaW1pdGl2ZXMgPVxyXG57XHJcbiAgMHgwMToge1xyXG4gICAgbmFtZTogXCJCSVRfTUFOSVBVTEFURV9CWVRFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLyovKlxyXG4gICAgICB2YXIgYiA9IGdldEJ5dGUoZHluYW1pY1RvcC0xKTtcclxuXHJcbiAgICAgIGlmIChiaXRNYW5pcHVsYXRlKGFyZzEsIGFyZzIsIGIpKVxyXG4gICAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAyOiB7XHJcbiAgICBuYW1lOiBcIlNISUZUX0xFRlRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICAvLyBzYW1lIGFzIFNISUZUX1JJR0hUXHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDM6IHtcclxuICAgIG5hbWU6IFwiU0hJRlRfUklHSFRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gYXJnMTtcclxuICAgICAgdmFyIG51bVNoaWZ0Qml0cyA9IGFyZzI7XHJcbiAgICAgIGlmICghbGVuIHx8ICFudW1TaGlmdEJpdHMgfHwgbnVtU2hpZnRCaXRzPj04KmxlbilcclxuICAgICAgICBBYmVuZChcInVuZGVmaW5lZCBzaGlmdCBhcmd1bWVudHNcIik7XHJcblxyXG4gICAgICB2YXIgKmRhdGEgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgIHJlYWQoZHluYW1pY1RvcC1sZW4sIGxlbiwgZGF0YSk7XHJcblxyXG4gICAgICBpZiAocHJpbSA9PSBTSElGVF9MRUZUKVxyXG4gICAgICB7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgYmxvY2tCaXRTZXQobGVuLCBkYXRhLCBsZW4qOC1udW1TaGlmdEJpdHMpKTtcclxuICAgICAgICBtdGhfc2hsKGRhdGEsIGxlbiwgbnVtU2hpZnRCaXRzKTtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCBibG9ja0JpdFNldChsZW4sIGRhdGEsIG51bVNoaWZ0Qml0cy0xKSk7XHJcbiAgICAgICAgbXRoX3NocihkYXRhLCBsZW4sIG51bVNoaWZ0Qml0cyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHdyaXRlKGR5bmFtaWNUb3AtbGVuLCBsZW4sIGRhdGEpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBibG9ja0lzWmVybyhkYXRhLGxlbikpO1xyXG4gICAgICBkZWxldGUgW11kYXRhO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA0OiB7XHJcbiAgICBuYW1lOiBcIlNFVF9TRUxFQ1RfU1dcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBzZXRTZWxlY3RTVyhhcmcxLCBhcmcyKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwNToge1xyXG4gICAgbmFtZTogXCJDQVJEX0JMT0NLXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MDoge1xyXG4gICAgbmFtZTogXCJSRVRVUk5fRlJPTV9DT0RFTEVUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgcmV0dXJuRnJvbUNvZGVsZXQoYXJnMSwgYXJnMik7XHJcbiAgICAqL31cclxuICB9XHJcbn1cclxuXHJcbnZhciBzZXRUaHJlZVByaW1pdGl2ZXMgPVxyXG57XHJcbiAgMHgwMToge1xyXG4gICAgbmFtZTogXCJCSVRfTUFOSVBVTEFURV9XT1JEXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIHcgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBpZiAoYml0TWFuaXB1bGF0ZShhcmcxLCBta1dvcmQoYXJnMiwgYXJnMyksIHcpKVxyXG4gICAgICAgIHNldFdvcmQoZHluYW1pY1RvcC0yLCB3KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MDoge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkUwXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MToge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkUxXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4Mjoge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkUyXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4Mzoge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkUzXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4NDoge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkU0XCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4NToge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkU1XCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4Njoge1xyXG4gICAgbmFtZTogXCJDQUxMX0VYVEVOU0lPTl9QUklNSVRJVkU2XCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH1cclxufTtcclxuXHJcbnZhciBwcmltaXRpdmVTZXRzID0gW1xyXG4gIHNldFplcm9QcmltaXRpdmVzLFxyXG4gIHNldE9uZVByaW1pdGl2ZXMsXHJcbiAgc2V0VHdvUHJpbWl0aXZlcyxcclxuICBzZXRUaHJlZVByaW1pdGl2ZXNcclxuXTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBjYWxsUHJpbWl0aXZlKCBjdHgsIHByaW0sIHNldCwgYXJnMSwgYXJnMiwgYXJnMyApXHJcbntcclxuICB2YXIgcHJpbUluZm8gPSBwcmltaXRpdmVTZXRzWyBzZXQgXVsgcHJpbSBdO1xyXG5cclxuICBpZiAoIHByaW1JbmZvIClcclxuICB7XHJcbiAgICBzd2l0Y2goIHNldCApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgMDogcHJpbUluZm8ucHJvYygpOyBicmVhaztcclxuICAgICAgY2FzZSAxOiBwcmltSW5mby5wcm9jKCBhcmcxICk7IGJyZWFrO1xyXG4gICAgICBjYXNlIDI6IHByaW1JbmZvLnByb2MoIGFyZzEsIGFyZzIgKTsgYnJlYWs7XHJcbiAgICAgIGNhc2UgMzogcHJpbUluZm8ucHJvYyggYXJnMSwgYXJnMiwgYXJnMyApOyBicmVhaztcclxuICAgIH1cclxuICB9XHJcbiAgZWxzZVxyXG4gIHtcclxuICAgIC8vIG5vIHByaW1cclxuICAgIHRocm93IG5ldyBFcnJvciggXCJQcmltaXRpdmUgbm90IEltcGxlbWVudGVkXCIgKTtcclxuICB9XHJcbn1cclxuIiwiZXhwb3J0IGNsYXNzIFNlY3VyaXR5TWFuYWdlclxyXG57XHJcbiAgaW5pdFNlY3VyaXR5KClcclxuICB7XHJcbiAgfVxyXG5cclxuICBwcm9jZXNzQVBEVSggYXBkdSApXHJcbiAge1xyXG4gICAgcmV0dXJuIGZhbHNlO1xyXG4gIH1cclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXksS2luZCxLaW5kSW5mbyB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5leHBvcnQgY2xhc3MgQURDXG57XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXksS2luZCxLaW5kSW5mbyB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5leHBvcnQgY2xhc3MgQUxDXG57XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXksIEtpbmQsIEtpbmRJbmZvLCBLaW5kQnVpbGRlciB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuLyoqXHJcbiAqIEVuY29kZXIvRGVjb2RvciBmb3IgYSBNVUxUT1MgQXBwbGljYXRpb24gTG9hZCBVbml0XHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgQUxVIGltcGxlbWVudHMgS2luZFxyXG57XHJcbiAgc3RhdGljIGtpbmRJbmZvOiBLaW5kSW5mbztcclxuXHJcbiAgY29kZTogQnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSgpO1xyXG4gIGRhdGE6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcclxuICBmY2k6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcclxuICBkaXI6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcclxuXHJcbiAgLyoqXHJcbiAgICogQGNvbnN0cnVjdG9yXHJcbiAgICovXHJcbiAgY29uc3RydWN0b3IoIGF0dHJpYnV0ZXM/OiB7fSApXHJcbiAge1xyXG4gICAgaWYgKCBhdHRyaWJ1dGVzIClcclxuICAgIHtcclxuICAgICAgZm9yKCBsZXQgZmllbGQgaW4gQUxVLmtpbmRJbmZvLmZpZWxkcyApXHJcbiAgICAgICAgaWYgKCBhdHRyaWJ1dGVzWyBmaWVsZC5pZCBdIClcclxuICAgICAgICAgIHRoaXNbIGZpZWxkLmlkIF0gPSBhdHRyaWJ1dGVzWyBmaWVsZC5pZCBdO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogU2VyaWFsaXphdGlvbiwgcmV0dXJucyBhIEpTT04gb2JqZWN0XHJcbiAgICovXHJcbiAgcHVibGljIHRvSlNPTigpOiB7fVxyXG4gIHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGNvZGU6IHRoaXMuY29kZSxcclxuICAgICAgZGF0YTogdGhpcy5kYXRhLFxyXG4gICAgICBmY2k6IHRoaXMuZmNpLFxyXG4gICAgICBkaXI6IHRoaXMuZGlyXHJcbiAgICB9O1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBnZXRBTFVTZWdtZW50KCBieXRlczogQnl0ZUFycmF5LCBzZWdtZW50SUQ6IG51bWJlciApXHJcbiAge1xyXG4gICAgdmFyIG9mZnNldCA9IDg7XHJcblxyXG4gICAgd2hpbGUoICggc2VnbWVudElEID4gMSApICYmICggb2Zmc2V0IDwgYnl0ZXMubGVuZ3RoICkgKVxyXG4gICAge1xyXG4gICAgICBvZmZzZXQgKz0gMiArIGJ5dGVzLndvcmRBdCggb2Zmc2V0ICk7XHJcbiAgICAgIC0tc2VnbWVudElEO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBieXRlcy52aWV3QXQoIG9mZnNldCArIDIsIGJ5dGVzLndvcmRBdCggb2Zmc2V0ICkgKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIERlY29kZXIgZmFjdG9yeSBmdW5jdGlvbiwgZGVjb2RlcyBhIGJsb2IgaW50byBhIE11bHRvc0FMVSBvYmplY3RcclxuICAgKi9cclxuICBwdWJsaWMgZGVjb2RlQnl0ZXMoIGJ5dGVzOiBCeXRlQXJyYXksIG9wdGlvbnM/OiBPYmplY3QgKTogQUxVXHJcbiAge1xyXG4gICAgdGhpcy5jb2RlID0gdGhpcy5nZXRBTFVTZWdtZW50KCBieXRlcywgMSApO1xyXG4gICAgdGhpcy5kYXRhID0gdGhpcy5nZXRBTFVTZWdtZW50KCBieXRlcywgMiApO1xyXG4gICAgdGhpcy5kaXIgPSB0aGlzLmdldEFMVVNlZ21lbnQoIGJ5dGVzLCAzICk7XHJcbiAgICB0aGlzLmZjaSA9IHRoaXMuZ2V0QUxVU2VnbWVudCggYnl0ZXMsIDQgKTtcclxuXHJcbiAgICByZXR1cm4gdGhpcztcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEVuY29kZXIgZnVuY3Rpb24sIHJldHVybnMgYSBibG9iIGZyb20gYSBNdWx0b3NBTFUgb2JqZWN0XHJcbiAgICovXHJcbiAgcHVibGljIGVuY29kZUJ5dGVzKCBvcHRpb25zPzoge30gKTogQnl0ZUFycmF5XHJcbiAge1xyXG4gICAgLy9AIFRPRE86IHJlYnVpbGQgYmluYXJ5IEFMVVxyXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcbiAgfVxyXG59XHJcblxyXG5LaW5kQnVpbGRlci5pbml0KCBBTFUsIFwiTVVMVE9TIEFwcGxpY2F0aW9uIExvYWQgVW5pdFwiIClcclxuICAuZmllbGQoIFwiY29kZVwiLCBcIkNvZGUgU2VnbWVudFwiLCBCeXRlQXJyYXkgKVxyXG4gIC5maWVsZCggXCJkYXRhXCIsIFwiRGF0YSBTZWdtZW50XCIsIEJ5dGVBcnJheSApXHJcbiAgLmZpZWxkKCBcImZjaVwiLCBcIkZDSSBTZWdtZW50XCIsIEJ5dGVBcnJheSApXHJcbiAgLmZpZWxkKCBcImRpclwiLCBcIkRJUiBTZWdtZW50XCIsIEJ5dGVBcnJheSApXHJcbiAgO1xyXG4iLG51bGwsbnVsbCxudWxsLG51bGwsbnVsbF0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
