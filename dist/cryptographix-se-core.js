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




export class SlotProtocol {
    static getHandler() {
        return new SlotProtocolHandler();
    }
    static getProxy(endPoint) {
        return new SlotProtocolProxy(endPoint);
    }
}
export class SlotProtocolProxy {
    constructor(endPoint) {
        this.endPoint = endPoint;
        let me = this;
        endPoint.onMessage((msg) => {
            let pendingOp = me.pending;
            if (pendingOp) {
                if (msg.header.isResponse && (msg.header.method == pendingOp.method)) {
                    pendingOp.resolve(msg.payload);
                    return;
                }
                else {
                    pendingOp.reject(msg.payload);
                }
            }
        });
    }
    powerCommand(method) {
        let me = this;
        return new Promise((resolve, reject) => {
            me.pending = {
                method: method,
                resolve: resolve,
                reject: reject
            };
            me.endPoint.sendMessage(new Message({ method: method }, null));
        });
    }
    powerOn() {
        return this.powerCommand('powerOn');
    }
    reset() {
        return this.powerCommand('reset');
    }
    powerOff() {
        return this.powerCommand('powerOff');
    }
    get isPresent() {
        return false;
    }
    get isPowered() {
        return false;
    }
    executeAPDU(cmd) {
        let me = this;
        return new Promise((resolve, reject) => {
            me.pending = {
                method: 'executeAPDU',
                resolve: resolve,
                reject: reject
            };
            me.endPoint.sendMessage(new Message({ method: 'executeAPDU' }, cmd));
        });
    }
}
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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcva2V5LnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9jcnlwdG8udHMiLCJnbG9iYWwtcGxhdGZvcm0tc2NyaXB0aW5nL2J5dGUtc3RyaW5nLnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9ieXRlLWJ1ZmZlci50cyIsImlzbzc4MTYvYmFzZS10bHYudHMiLCJnbG9iYWwtcGxhdGZvcm0tc2NyaXB0aW5nL3Rsdi50cyIsImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcvdGx2LWxpc3QudHMiLCJjb21wb25lbnRzL2J5dGUtZGF0YS1pbnB1dC5qcyIsImNvbXBvbmVudHMvYnl0ZS1kYXRhLW91dHB1dC5qcyIsImNvbXBvbmVudHMvY3J5cHRvci1ib3guanMiLCJjb21wb25lbnRzL3JzYS1rZXktYnVpbGRlci5qcyIsImNvbXBvbmVudHMvc2VjcmV0LWtleS1idWlsZGVyLmpzIiwiaXNvNzgxNi9jb21tYW5kLWFwZHUudHMiLCJpc283ODE2L2lzbzc4MTYudHMiLCJpc283ODE2L3Jlc3BvbnNlLWFwZHUudHMiLCJpc283ODE2L3Nsb3QuanMiLCJpc283ODE2L3Nsb3QtcHJvdG9jb2wtaGFuZGxlci50cyIsImpzaW0tY2FyZC9TbG90cy50cyIsImpzaW0tY2FyZC9qc2ltLWNhcmQuanMiLCJqc2ltLWNhcmQvanNpbS1zY3JpcHQtYXBwbGV0LnRzIiwianNpbS1jYXJkL2pzaW0tc2NyaXB0LWNhcmQudHMiLCJqc2ltLWNhcmQvanNpbS1zbG90LnRzIiwianNpbS1tdWx0b3MvbWVtb3J5LW1hbmFnZXIudHMiLCJqc2ltLW11bHRvcy9tZWwtZGVmaW5lcy50cyIsImpzaW0tbXVsdG9zL3ZpcnR1YWwtbWFjaGluZS50cyIsImpzaW0tbXVsdG9zL2pzaW0tbXVsdG9zLWNhcmQudHMiLCJqc2ltLW11bHRvcy9wcmltaXRpdmVzLnRzIiwianNpbS1tdWx0b3Mvc2VjdXJpdHktbWFuYWdlci50cyIsIm11bHRvcy9hZGMudHMiLCJtdWx0b3MvYWxjLnRzIiwibXVsdG9zL2FsdS50cyJdLCJuYW1lcyI6WyJLZXkiLCJLZXkuY29uc3RydWN0b3IiLCJLZXkuc2V0VHlwZSIsIktleS5nZXRUeXBlIiwiS2V5LnNldFNpemUiLCJLZXkuZ2V0U2l6ZSIsIktleS5zZXRDb21wb25lbnQiLCJLZXkuZ2V0Q29tcG9uZW50IiwiQ3J5cHRvIiwiQ3J5cHRvLmNvbnN0cnVjdG9yIiwiQ3J5cHRvLmVuY3J5cHQiLCJDcnlwdG8uZGVjcnlwdCIsIkNyeXB0by5zaWduIiwiQ3J5cHRvLmRlcyIsIkNyeXB0by5kZXMuZGVzX2NyZWF0ZUtleXMiLCJDcnlwdG8udmVyaWZ5IiwiQ3J5cHRvLmRpZ2VzdCIsIkJ5dGVTdHJpbmciLCJCeXRlU3RyaW5nLmNvbnN0cnVjdG9yIiwiQnl0ZVN0cmluZy5sZW5ndGgiLCJCeXRlU3RyaW5nLmJ5dGVzIiwiQnl0ZVN0cmluZy5ieXRlQXQiLCJCeXRlU3RyaW5nLmVxdWFscyIsIkJ5dGVTdHJpbmcuY29uY2F0IiwiQnl0ZVN0cmluZy5sZWZ0IiwiQnl0ZVN0cmluZy5yaWdodCIsIkJ5dGVTdHJpbmcubm90IiwiQnl0ZVN0cmluZy5hbmQiLCJCeXRlU3RyaW5nLm9yIiwiQnl0ZVN0cmluZy5wYWQiLCJCeXRlU3RyaW5nLnRvU3RyaW5nIiwiQnl0ZUJ1ZmZlciIsIkJ5dGVCdWZmZXIuY29uc3RydWN0b3IiLCJCeXRlQnVmZmVyLmxlbmd0aCIsIkJ5dGVCdWZmZXIudG9CeXRlU3RyaW5nIiwiQnl0ZUJ1ZmZlci5jbGVhciIsIkJ5dGVCdWZmZXIuYXBwZW5kIiwiQmFzZVRMViIsIkJhc2VUTFYuY29uc3RydWN0b3IiLCJCYXNlVExWLnBhcnNlVExWIiwiQmFzZVRMVi50YWciLCJCYXNlVExWLnZhbHVlIiwiQmFzZVRMVi5sZW4iLCJUTFYiLCJUTFYuY29uc3RydWN0b3IiLCJUTFYuZ2V0VExWIiwiVExWLmdldFRhZyIsIlRMVi5nZXRWYWx1ZSIsIlRMVi5nZXRMIiwiVExWLmdldExWIiwiVExWLnBhcnNlVExWIiwiVExWTGlzdCIsIlRMVkxpc3QuY29uc3RydWN0b3IiLCJUTFZMaXN0LmluZGV4IiwiQ29tbWFuZEFQRFUiLCJDb21tYW5kQVBEVS5jb25zdHJ1Y3RvciIsIkNvbW1hbmRBUERVLkxjIiwiQ29tbWFuZEFQRFUuaGVhZGVyIiwiQ29tbWFuZEFQRFUuaW5pdCIsIkNvbW1hbmRBUERVLnNldCIsIkNvbW1hbmRBUERVLnNldENMQSIsIkNvbW1hbmRBUERVLnNldElOUyIsIkNvbW1hbmRBUERVLnNldFAxIiwiQ29tbWFuZEFQRFUuc2V0UDIiLCJDb21tYW5kQVBEVS5zZXREYXRhIiwiQ29tbWFuZEFQRFUuc2V0TGUiLCJDb21tYW5kQVBEVS50b0pTT04iLCJDb21tYW5kQVBEVS5lbmNvZGVCeXRlcyIsIkNvbW1hbmRBUERVLmRlY29kZUJ5dGVzIiwiSVNPNzgxNiIsIlJlc3BvbnNlQVBEVSIsIlJlc3BvbnNlQVBEVS5jb25zdHJ1Y3RvciIsIlJlc3BvbnNlQVBEVS5MYSIsIlJlc3BvbnNlQVBEVS5pbml0IiwiUmVzcG9uc2VBUERVLnNldCIsIlJlc3BvbnNlQVBEVS5zZXRTVyIsIlJlc3BvbnNlQVBEVS5zZXRTVzEiLCJSZXNwb25zZUFQRFUuc2V0U1cyIiwiUmVzcG9uc2VBUERVLnNldERhdGEiLCJSZXNwb25zZUFQRFUuZW5jb2RlQnl0ZXMiLCJSZXNwb25zZUFQRFUuZGVjb2RlQnl0ZXMiLCJTbG90UHJvdG9jb2wiLCJTbG90UHJvdG9jb2wuZ2V0SGFuZGxlciIsIlNsb3RQcm90b2NvbC5nZXRQcm94eSIsIlNsb3RQcm90b2NvbFByb3h5IiwiU2xvdFByb3RvY29sUHJveHkuY29uc3RydWN0b3IiLCJTbG90UHJvdG9jb2xQcm94eS5wb3dlckNvbW1hbmQiLCJTbG90UHJvdG9jb2xQcm94eS5wb3dlck9uIiwiU2xvdFByb3RvY29sUHJveHkucmVzZXQiLCJTbG90UHJvdG9jb2xQcm94eS5wb3dlck9mZiIsIlNsb3RQcm90b2NvbFByb3h5LmlzUHJlc2VudCIsIlNsb3RQcm90b2NvbFByb3h5LmlzUG93ZXJlZCIsIlNsb3RQcm90b2NvbFByb3h5LmV4ZWN1dGVBUERVIiwiU2xvdFByb3RvY29sSGFuZGxlciIsIlNsb3RQcm90b2NvbEhhbmRsZXIuY29uc3RydWN0b3IiLCJTbG90UHJvdG9jb2xIYW5kbGVyLmxpbmtTbG90IiwiU2xvdFByb3RvY29sSGFuZGxlci51bmxpbmtTbG90IiwiU2xvdFByb3RvY29sSGFuZGxlci5vbk1lc3NhZ2UiLCJKU1NpbXVsYXRlZFNsb3QiLCJKU1NpbXVsYXRlZFNsb3QuT25NZXNzYWdlIiwiSlNTaW11bGF0ZWRTbG90LmluaXQiLCJKU1NpbXVsYXRlZFNsb3Quc2VuZFRvV29ya2VyIiwiSlNTaW11bGF0ZWRTbG90LmV4ZWN1dGVBUERVQ29tbWFuZCIsIkpTSU1TY3JpcHRBcHBsZXQiLCJKU0lNU2NyaXB0QXBwbGV0LnNlbGVjdEFwcGxpY2F0aW9uIiwiSlNJTVNjcmlwdEFwcGxldC5kZXNlbGVjdEFwcGxpY2F0aW9uIiwiSlNJTVNjcmlwdEFwcGxldC5leGVjdXRlQVBEVSIsIkpTSU1TY3JpcHRDYXJkIiwiSlNJTVNjcmlwdENhcmQuY29uc3RydWN0b3IiLCJKU0lNU2NyaXB0Q2FyZC5sb2FkQXBwbGljYXRpb24iLCJKU0lNU2NyaXB0Q2FyZC5pc1Bvd2VyZWQiLCJKU0lNU2NyaXB0Q2FyZC5wb3dlck9uIiwiSlNJTVNjcmlwdENhcmQucG93ZXJPZmYiLCJKU0lNU2NyaXB0Q2FyZC5yZXNldCIsIkpTSU1TY3JpcHRDYXJkLmV4Y2hhbmdlQVBEVSIsIkpTSU1TbG90IiwiSlNJTVNsb3QuY29uc3RydWN0b3IiLCJKU0lNU2xvdC5pc1ByZXNlbnQiLCJKU0lNU2xvdC5pc1Bvd2VyZWQiLCJKU0lNU2xvdC5wb3dlck9uIiwiSlNJTVNsb3QucG93ZXJPZmYiLCJKU0lNU2xvdC5yZXNldCIsIkpTSU1TbG90LmV4ZWN1dGVBUERVIiwiSlNJTVNsb3QuaW5zZXJ0Q2FyZCIsIkpTSU1TbG90LmVqZWN0Q2FyZCIsImhleDIiLCJoZXg0IiwiTUVNRkxBR1MiLCJTZWdtZW50IiwiU2VnbWVudC5jb25zdHJ1Y3RvciIsIlNlZ21lbnQuZ2V0VHlwZSIsIlNlZ21lbnQuZ2V0TGVuZ3RoIiwiU2VnbWVudC5nZXRGbGFncyIsIlNlZ21lbnQuZ2V0RGVidWciLCJTZWdtZW50LmJlZ2luVHJhbnNhY3Rpb24iLCJTZWdtZW50LmVuZFRyYW5zYWN0aW9uIiwiU2VnbWVudC5yZWFkQnl0ZSIsIlNlZ21lbnQuemVyb0J5dGVzIiwiU2VnbWVudC5yZWFkQnl0ZXMiLCJTZWdtZW50LmNvcHlCeXRlcyIsIlNlZ21lbnQud3JpdGVCeXRlcyIsIlNlZ21lbnQubmV3QWNjZXNzb3IiLCJBY2Nlc3NvciIsIkFjY2Vzc29yLmNvbnN0cnVjdG9yIiwiQWNjZXNzb3IudHJhY2VNZW1vcnlPcCIsIkFjY2Vzc29yLnRyYWNlTWVtb3J5VmFsdWUiLCJBY2Nlc3Nvci56ZXJvQnl0ZXMiLCJBY2Nlc3Nvci5yZWFkQnl0ZSIsIkFjY2Vzc29yLnJlYWRCeXRlcyIsIkFjY2Vzc29yLmNvcHlCeXRlcyIsIkFjY2Vzc29yLndyaXRlQnl0ZSIsIkFjY2Vzc29yLndyaXRlQnl0ZXMiLCJBY2Nlc3Nvci5nZXRUeXBlIiwiQWNjZXNzb3IuZ2V0TGVuZ3RoIiwiQWNjZXNzb3IuZ2V0SUQiLCJBY2Nlc3Nvci5nZXREZWJ1ZyIsInNsaWNlRGF0YSIsIk1lbW9yeU1hbmFnZXIiLCJNZW1vcnlNYW5hZ2VyLmNvbnN0cnVjdG9yIiwiTWVtb3J5TWFuYWdlci5uZXdTZWdtZW50IiwiTWVtb3J5TWFuYWdlci5nZXRNZW1UcmFjZSIsIk1lbW9yeU1hbmFnZXIuaW5pdE1lbVRyYWNlIiwiTWVtb3J5TWFuYWdlci5nZXRTZWdtZW50IiwiTUVMSU5TVCIsIk1FTFRBR0FERFIiLCJNRUxUQUdDT05EIiwiTUVMVEFHU1lTVEVNIiwiTUVMVEFHU1RBQ0siLCJNRUxUQUdQUklNUkVUIiwiTUVMUEFSQU1ERUYiLCJNRUxQQVJBTTQiLCJPUFRBRzJNRUxJTlNUIiwiTUVMMk9QQ09ERSIsIk1FTDJJTlNUIiwiTUVMMlRBRyIsIk1FTFBBUkFNU0laRSIsIk1FTCIsInNldE1lbERlY29kZSIsInNldE1lbERlY29kZVN0ZE1vZGVzIiwic2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MiLCJmaWxsTWVsRGVjb2RlIiwiaGV4IiwibGp1c3QiLCJyanVzdCIsIkJBMlciLCJXMkJBIiwiTUVMVmlydHVhbE1hY2hpbmUiLCJNRUxWaXJ0dWFsTWFjaGluZS5jb25zdHJ1Y3RvciIsIk1FTFZpcnR1YWxNYWNoaW5lLmluaXRNVk0iLCJNRUxWaXJ0dWFsTWFjaGluZS5kaXNhc3NlbWJsZUNvZGUiLCJNRUxWaXJ0dWFsTWFjaGluZS5kaXNhc3NlbWJsZUNvZGUucHJpbnQiLCJNRUxWaXJ0dWFsTWFjaGluZS5tYXBUb1NlZ21lbnRBZGRyIiwiTUVMVmlydHVhbE1hY2hpbmUubWFwRnJvbVNlZ21lbnRBZGRyIiwiTUVMVmlydHVhbE1hY2hpbmUuY2hlY2tEYXRhQWNjZXNzIiwiTUVMVmlydHVhbE1hY2hpbmUucmVhZFNlZ21lbnREYXRhIiwiTUVMVmlydHVhbE1hY2hpbmUud3JpdGVTZWdtZW50RGF0YSIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2haZXJvc1RvU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5wdXNoQ29uc3RUb1N0YWNrIiwiTUVMVmlydHVhbE1hY2hpbmUuY29weU9uU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5wdXNoVG9TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnBvcEZyb21TdGFja0FuZFN0b3JlIiwiTUVMVmlydHVhbE1hY2hpbmUucG9wRnJvbVN0YWNrIiwiTUVMVmlydHVhbE1hY2hpbmUuc2V0dXBBcHBsaWNhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmluaXRFeGVjdXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS5jb25zdEJ5dGVCaW5hcnlPcGVyYXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS5jb25zdFdvcmRCaW5hcnlPcGVyYXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS5iaW5hcnlPcGVyYXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS51bmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmhhbmRsZVJldHVybiIsIk1FTFZpcnR1YWxNYWNoaW5lLmlzQ29uZGl0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuZXhlY3V0ZVN0ZXAiLCJNRUxWaXJ0dWFsTWFjaGluZS5zZXRDb21tYW5kQVBEVSIsIk1FTFZpcnR1YWxNYWNoaW5lLmdldFJlc3BvbnNlQVBEVSIsIk1FTFZpcnR1YWxNYWNoaW5lLmdldERlYnVnIiwiSlNJTU11bHRvc0FwcGxldCIsIkpTSU1NdWx0b3NBcHBsZXQuY29uc3RydWN0b3IiLCJKU0lNTXVsdG9zQ2FyZCIsIkpTSU1NdWx0b3NDYXJkLmNvbnN0cnVjdG9yIiwiSlNJTU11bHRvc0NhcmQubG9hZEFwcGxpY2F0aW9uIiwiSlNJTU11bHRvc0NhcmQuaXNQb3dlcmVkIiwiSlNJTU11bHRvc0NhcmQucG93ZXJPbiIsIkpTSU1NdWx0b3NDYXJkLnBvd2VyT2ZmIiwiSlNJTU11bHRvc0NhcmQucmVzZXQiLCJKU0lNTXVsdG9zQ2FyZC5leGNoYW5nZUFQRFUiLCJKU0lNTXVsdG9zQ2FyZC5pbml0aWFsaXplVk0iLCJKU0lNTXVsdG9zQ2FyZC5yZXNldFZNIiwiSlNJTU11bHRvc0NhcmQuc2h1dGRvd25WTSIsIkpTSU1NdWx0b3NDYXJkLnNlbGVjdEFwcGxpY2F0aW9uIiwiSlNJTU11bHRvc0NhcmQuZXhlY3V0ZVN0ZXAiLCJiaXRNYW5pcHVsYXRlIiwiY2FsbFByaW1pdGl2ZSIsIlNlY3VyaXR5TWFuYWdlciIsIlNlY3VyaXR5TWFuYWdlci5pbml0U2VjdXJpdHkiLCJTZWN1cml0eU1hbmFnZXIucHJvY2Vzc0FQRFUiLCJBREMiLCJBTEMiLCJBTFUiLCJBTFUuY29uc3RydWN0b3IiLCJBTFUudG9KU09OIiwiQUxVLmdldEFMVVNlZ21lbnQiLCJBTFUuZGVjb2RlQnl0ZXMiLCJBTFUuZW5jb2RlQnl0ZXMiXSwibWFwcGluZ3MiOiJBQUVBO0lBTUVBO1FBRUVDLElBQUlBLENBQUNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBO1FB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QUdBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBO1FBRXRCRyxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVESCxJQUFJQSxDQUFFQSxHQUFRQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFnQkEsRUFBRUEsRUFBR0E7UUFFekNJLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLFlBQVlBLENBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLFNBQVNBLENBQUNBO1FBRWpEQSxJQUFJQSxPQUFPQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVoQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBR0EsQ0FBQ0EsQ0FDckJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBO1lBRTFCQSxPQUFPQTtpQkFDSkEsU0FBU0EsQ0FBRUEsRUFBRUEsQ0FBRUE7aUJBQ2ZBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBO2lCQUNsQkEsVUFBVUEsQ0FBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDekNBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLFNBQVVBLENBQUNBO1lBQ3BCQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUk1RUEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsT0FBT0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFN0dBLE1BQU1BLENBQUNBLElBQUlBLFVBQVVBLENBQUVBLFVBQVVBLENBQUVBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO0lBQ2xEQSxDQUFDQTtJQUtPSixHQUFHQSxDQUFFQSxHQUFlQSxFQUFFQSxPQUFtQkEsRUFBRUEsT0FBZUEsRUFBRUEsSUFBWUEsRUFBRUEsRUFBZUEsRUFBRUEsT0FBZ0JBO1FBS2pISyx3QkFBeUJBLEdBQUdBO1lBRTFCQyxFQUFFQSxDQUFDQSxDQUFFQSxNQUFNQSxDQUFDQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUNoQ0EsQ0FBQ0E7Z0JBRUNBLE1BQU1BLENBQUNBLEtBQUtBLEdBQUdBO29CQUNiQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFFQSxDQUFFQTtvQkFDNUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3JKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDOUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO29CQUMzSUEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3ZKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDcktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUNqTEEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDN0pBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO29CQUNuSkEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ25MQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdEtBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLENBQUNBLENBQUVBO2lCQUM5R0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7WUFHREEsSUFBSUEsVUFBVUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFeENBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFdBQVdBLENBQUNBLEVBQUVBLEdBQUdBLFVBQVVBLENBQUNBLENBQUNBO1lBRTVDQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVoRUEsSUFBSUEsUUFBUUEsRUFBRUEsU0FBU0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0E7WUFFeENBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQy9CQSxDQUFDQTtnQkFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3pFQSxLQUFLQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFFekVBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ25GQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtnQkFFbkRBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUN0R0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBR2JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLE1BQU1BLEVBQUVBLENBQUNBLEVBQUVBLEVBQ3BDQSxDQUFDQTtvQkFFQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTt3QkFDQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBQUNBLEtBQUtBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO29CQUM1RUEsQ0FBQ0E7b0JBQ0RBLElBQUlBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFNNUJBLFFBQVFBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNqRkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ3pGQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDeEZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUN0REEsU0FBU0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ25GQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDNUZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUM1RkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ3pEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxTQUFTQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtvQkFDcERBLElBQUlBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBO29CQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxTQUFTQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDcEVBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBQ2RBLENBQUNBO1FBR0RELEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLENBQUNBLEtBQUtBLElBQUlBLFNBQVVBLENBQUNBLENBQ2hDQSxDQUFDQTtZQUNDQSxNQUFNQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDYkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pmQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDam9CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDcm1CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDempCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTthQUN0bEJBLENBQUNBO1FBQ0pBLENBQUNBO1FBR0RBLElBQUlBLElBQUlBLEdBQUdBLGNBQWNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxPQUFPQSxDQUFDQTtRQUMxQ0EsSUFBSUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBQUE7UUFDMUNBLElBQUlBLEdBQUdBLEdBQUdBLE9BQU9BLENBQUNBLE1BQU1BLENBQUNBO1FBR3pCQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUUzQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLE9BQU9BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO1FBQ3BEQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNsR0EsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsT0FBT0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FDbkRBLENBQUNBO1lBQ0NBLElBQUlBLGVBQWVBLEdBQUdBLE9BQU9BLENBQUNBO1lBQzlCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUVwQkEsT0FBT0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDcENBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLGVBQWVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBRWxDQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7Z0JBQ0NBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtvQkFDekZBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxDQUFDQTtvQkFDTkEsQ0FBQ0E7d0JBQ0NBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUU5RUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ1hBLEdBQUdBLElBQUVBLENBQUNBLENBQUNBO3dCQUVUQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDdkZBLEtBQUtBLENBQUNBO1lBRVZBLENBQUNBO1lBRURBLEdBQUdBLElBQUlBLENBQUNBLEdBQUNBLENBQUNBLEdBQUdBLEdBQUNBLENBQUNBLENBQUNBLENBQUFBO1FBQ2xCQSxDQUFDQTtRQUdEQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVuQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFVkEsT0FBT0EsR0FBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDeEVBLFFBQVFBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1FBQzFFQSxDQUFDQTtRQUVEQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdYQSxPQUFPQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUNkQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUN6RkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFHekZBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsT0FBT0EsQ0FBQ0E7b0JBQUNBLEtBQUtBLElBQUlBLFFBQVFBLENBQUNBO2dCQUNyQ0EsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtvQkFDbkJBLFNBQVNBLEdBQUdBLFFBQVFBLENBQUNBO29CQUNyQkEsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQ2pGQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRS9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNyQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHeENBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLElBQUVBLENBQUNBLEVBQzVCQSxDQUFDQTtnQkFDQ0EsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzNCQSxJQUFJQSxPQUFPQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFHM0JBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLE9BQU9BLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQ3pDQSxDQUFDQTtvQkFDQ0EsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzdCQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFHekRBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO29CQUNaQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtvQkFDYkEsS0FBS0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQ25HQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDMUZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNuR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzlHQSxDQUFDQTtnQkFFREEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUFDQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtZQUMxQ0EsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHL0VBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxJQUFJQSxJQUFJQSxRQUFRQSxDQUFDQTtvQkFDakJBLEtBQUtBLElBQUlBLFNBQVNBLENBQUNBO2dCQUNyQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFFREEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBR0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FB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WUFBY0EsR0FBV0EsRUFBRUEsS0FBZ0JBLEVBQUVBLFFBQWlCQTtRQUU1REMsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsUUFBUUEsSUFBSUEsT0FBT0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0E7UUFFbERBLE1BQU1BLENBQUFBLENBQUVBLElBQUlBLENBQUNBLFFBQVNBLENBQUNBLENBQ3ZCQSxDQUFDQTtZQUNDQSxLQUFLQSxPQUFPQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQTtnQkFDMUJBLENBQUNBO29CQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFFbENBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUtBLEtBQU1BLENBQUNBO3dCQUNsQkEsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7b0JBQzNDQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFDQTtvQkFFaENBLElBQUlBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLENBQUNBO29CQUN2QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBS0EsQ0FBQ0EsQ0FDakJBLENBQUNBO3dCQUNDQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTt3QkFDMUJBLFNBQVNBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO29CQUMzQ0EsQ0FBQ0E7b0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLEdBQUdBLElBQUtBLENBQUNBO3dCQUNwQkEsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7b0JBRTVCQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFDQTtvQkFFaENBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLEtBQUtBLENBQUVBLENBQUNBO29CQUUxQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsU0FBU0EsQ0FBQ0E7b0JBRTNCQSxLQUFLQSxDQUFDQTtnQkFDUkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUF2RkRELE9BQU9BLFFBQVFBLENBQUVBLE1BQWlCQSxFQUFFQSxRQUFnQkE7UUFFbERFLElBQUlBLEdBQUdBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEtBQUtBLEVBQUVBLFNBQVNBLEVBQUVBLFNBQVNBLEVBQUVBLENBQUNBLEVBQUVBLFdBQVdBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBO1FBQzdFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNaQSxJQUFJQSxLQUFLQSxHQUFHQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQTtRQUVoQ0EsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FDbEJBLENBQUNBO1lBQ0NBLEtBQUtBLE9BQU9BLENBQUNBLFNBQVNBLENBQUNBLEdBQUdBO2dCQUMxQkEsQ0FBQ0E7b0JBQ0NBLE9BQU9BLENBQUVBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUVBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLElBQUlBLElBQUlBLENBQUVBLElBQUlBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLElBQUlBLElBQUlBLENBQUVBLENBQUVBO3dCQUN2RkEsRUFBRUEsR0FBR0EsQ0FBQ0E7b0JBRVJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBO3dCQUN4QkEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBRWJBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLElBQUtBLENBQUNBLENBQ3RDQSxDQUFDQTt3QkFDQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBQ0E7d0JBQzlCQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxLQUFLQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUMxQkEsQ0FBQ0E7NEJBQWdCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTt3QkFBQ0EsQ0FBQ0E7b0JBQ2pDQSxDQUFDQTtvQkFFREEsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsS0FBS0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBRUEsQ0FBQ0E7b0JBRTFCQSxHQUFHQSxDQUFDQSxTQUFTQSxHQUFHQSxHQUFHQSxDQUFDQTtvQkFFcEJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBLENBQzFCQSxDQUFDQTt3QkFBZ0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO29CQUFDQSxDQUFDQTtvQkFFL0JBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLEdBQUdBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLEVBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBO29CQUNqRUEsT0FBT0EsRUFBRUEsRUFBRUEsR0FBR0EsQ0FBQ0EsRUFDZkEsQ0FBQ0E7d0JBQ0NBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBLENBQzFCQSxDQUFDQTs0QkFBNENBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO3dCQUFDQSxDQUFDQTt3QkFFM0RBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUVBLEdBQUdBLENBQUNBLEdBQUdBLElBQUlBLENB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QSxDQUFFQSxFQUFVQSxJQUF5QlcsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLdEVYLE1BQU1BO1FBRVhZLE1BQU1BLENBQUNBO1lBQ0xBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ2JBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ2JBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1lBQ1hBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1lBQ1hBLElBQUlBLEVBQUVBLElBQUlBLENBQUNBLElBQUlBO1lBQ2ZBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ1pBLENBQUNBO0lBQ0pBLENBQUNBO0lBS01aLFdBQVdBLENBQUVBLE9BQVlBO1FBRTlCYSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNqREEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBRUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDakRBLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRzFDQSxFQUFFQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUNoQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDZEEsRUFBRUEsQ0FBQ0EsU0FBU0EsQ0FB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QUlBLFlBQVlBLEVBQUVBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO0lBQ2hEQSxDQUFDQTtJQUVNSCxHQUFHQSxDQUFFQSxFQUFVQSxFQUFFQSxJQUFnQkE7UUFFdENJLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO1FBQ2JBLElBQUlBLENBQUNBLElBQUlBLEdBQUdBLElBQUlBLElBQUlBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBO1FBRXBDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNSixLQUFLQSxDQUFFQSxFQUFVQSxJQUEwQkssSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDdkVMLE1BQU1BLENBQUVBLEdBQVdBLElBQXdCTSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN0R04sTUFBTUEsQ0FBRUEsR0FBV0EsSUFBd0JPLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLE1BQU1BLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQy9GUCxPQUFPQSxDQUFFQSxJQUFlQSxJQUFtQlEsSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLM0VSLFdBQVdBLENBQUVBLE9BQVlBO1FBRTlCUyxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVsREEsRUFBRUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFDOUJBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEVBQU1BLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO1FBQ3JEQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUVyREEsTUFBTUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7SUFDWkEsQ0FBQ0E7SUFFTVQsV0FBV0EsQ0FBRUEsU0FBb0JBLEVBQUVBLE9BQVlBO1FBRXBEVSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQTtZQUN6QkEsTUFBTUEsSUFBSUEsS0FBS0EsQ0FBRUEsNkJBQTZCQSxDQUFFQSxDQUFDQTtRQUVuREEsSUFBSUEsRUFBRUEsR0FBR0EsU0FBU0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFOUJBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBQ2pDQSxJQUFJQSxDQUFDQSxJQUFJQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxHQUFHQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxDQUFFQSxHQUFHQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQTtRQUVsRUEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7QUFDSFYsQ0FBQ0E7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QUVEQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN0Q0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDeERBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFN0JBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRUROLFNBQVNBLENBQUVBLFFBQWdCQSxFQUFFQSxNQUFjQSxFQUFFQSxHQUFXQTtRQUV0RE8sRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsUUFBUUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBR0EsQ0FBQ0EsQ0FDekVBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO1lBQ3hEQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxrQkFBa0JBLENBQUVBLENBQUNBO1FBQ3hDQSxDQUFDQTtRQUdEQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtZQUNsREEsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsUUFBUUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7WUFDNURBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDL0JBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBQ3hFQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUNiQSxDQUFDQTtJQUVEUCxTQUFTQSxDQUFFQSxJQUFZQSxFQUFFQSxHQUFXQTtRQUVsQ1EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDN0JBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLElBQUlBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBQzFDQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxtQkFBbUJBLENBQUVBLENBQUNBO1FBQ3pDQSxDQUFDQTtRQUVEQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsRUFBRUEsSUFBSUEsU0FBU0EsQ0FBRUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDcEVBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDbkNBLENBQUNBO0lBRURSLFVBQVVBLENBQUVBLElBQVlBLEVBQUVBLEdBQWNBO1FBRXRDUyxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUN0Q0EsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsVUFBVUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7WUFDbkRBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLG1CQUFtQkEsQ0FBRUEsQ0FBQ0E7UUFDekNBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBO1FBQzdDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUMvQ0EsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtJQUMvQkEsQ0FBQ0E7SUFFRFQsT0FBT0EsS0FBS1UsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDeENWLFNBQVNBLEtBQUtXLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBO0lBQ25DWCxLQUFLQSxLQUFLWSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUkzQlosUUFBUUEsS0FBS2EsTUFBTUEsQ0FBQ0EsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDcEZiLENBQUNBO0FBRUQsbUJBQW9CLElBQUksRUFBRSxNQUFNLEVBQUUsSUFBSTtJQUVwQ2MsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsTUFBTUEsRUFBRUEsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7QUFDaERBLENBQUNBO0FBRUQ7SUFBQUM7UUFFVUMsbUJBQWNBLEdBQUdBLEVBQUVBLENBQUNBO1FBRXBCQSxjQUFTQSxHQUFHQSxFQUFFQSxDQUFDQTtJQWtCekJBLENBQUNBO0lBaEJDRCxVQUFVQSxDQUFFQSxPQUFPQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFNQTtRQUUvQkUsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsT0FBT0EsQ0FBRUEsT0FBT0EsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7UUFFakRBLElBQUlBLENBQUNBLGNBQWNBLENBQUVBLE9BQU9BLENBQUVBLEdBQUdBLE1BQU1BLENBQUNBO1FBRXhDQSxNQUFNQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQTtRQUVsQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7SUFDaEJBLENBQUNBO0lBRURGLFdBQVdBLEtBQUtHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLENBQUNBO0lBRXhDSCxZQUFZQSxLQUFLSSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUV2Q0osVUFBVUEsQ0FBRUEsSUFBSUEsSUFBS0ssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDNURMLENBQUNBO0FBQUEsQUNyUUQsV0FBWSxPQWlDWDtBQWpDRCxXQUFZLE9BQU87SUFDakJNLCtDQUFpQkEsQ0FBQUE7SUFDakJBLCtDQUFpQkEsQ0FBQUE7SUFDakJBLDJDQUFpQkEsQ0FBQUE7SUFDakJBLDJDQUFpQkEsQ0FBQUE7SUFDakJBLDZDQUFpQkEsQ0FBQUE7SUFDakJBLGlEQUFpQkEsQ0FBQUE7SUFDakJBLGlEQUFpQkEsQ0FBQUE7SUFDakJBLDJDQUFpQkEsQ0FBQUE7SUFDakJBLDZDQUFpQkEsQ0FBQUE7SUFDakJBLDZDQUFpQkEsQ0FBQUE7SUFDakJBLGdEQUFpQkEsQ0FBQUE7SUFDakJBLDhDQUFpQkEsQ0FBQUE7SUFDakJBLDhDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLGdEQUFpQkEsQ0FBQUE7SUFDakJBLDhDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDBDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7QUFDbkJBLENBQUNBLEVBakNXLE9BQU8sS0FBUCxPQUFPLFFBaUNsQjtBQUFBLENBQUM7QUFFRixXQUFZLFVBU1g7QUFURCxXQUFZLFVBQVU7SUFDcEJDLHVEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7QUFDbkJBLENBQUNBLEVBVFcsVUFBVSxLQUFWLFVBQVUsUUFTckI7QUFBQSxDQUFDO0FBRUYsV0FBWSxVQVNYO0FBVEQsV0FBWSxVQUFVO0lBQ3BCQyx5REFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSx1REFBbUJBLENBQUFBO0FBQ3JCQSxDQUFDQSxFQVRXLFVBQVUsS0FBVixVQUFVLFFBU3JCO0FBQUEsQ0FBQztBQUVGLFdBQVksWUFTWDtBQVRELFdBQVksWUFBWTtJQUN0QkMsK0RBQXlCQSxDQUFBQTtJQUN6QkEsbUVBQXlCQSxDQUFBQTtJQUN6QkEsbUVBQXlCQSxDQUFBQTtJQUN6QkEsdUVBQXlCQSxDQUFBQTtJQUN6QkEsaUVBQXlCQSxDQUFBQTtJQUN6QkEscUVBQXlCQSxDQUFBQTtJQUN6QkEscUVBQXlCQSxDQUFBQTtJQUN6QkEseUVBQXlCQSxDQUFBQTtBQUMzQkEsQ0FBQ0EsRUFUVyxZQUFZLEtBQVosWUFBWSxRQVN2QjtBQUFBLENBQUM7QUFFRixXQUFZLFdBU1g7QUFURCxXQUFZLFdBQVc7SUFDckJDLCtEQUFxQkEsQ0FBQUE7SUFDckJBLCtEQUFxQkEsQ0FBQUE7SUFDckJBLCtEQUFxQkEsQ0FBQUE7SUFDckJBLDJEQUFxQkEsQ0FBQUE7SUFDckJBLDZEQUFxQkEsQ0FBQUE7SUFDckJBLDZEQUFxQkEsQ0FBQUE7SUFDckJBLDZEQUFxQkEsQ0FBQUE7SUFDckJBLDJEQUFxQkEsQ0FBQUE7QUFDdkJBLENBQUNBLEVBVFcsV0FBVyxLQUFYLFdBQVcsUUFTdEI7QUFBQSxDQUFDO0FBRUYsV0FBWSxhQVNYO0FBVEQsV0FBWSxhQUFhO0lBQ3ZCQyx1RUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0lBQ3ZCQSxtRUFBdUJBLENBQUFBO0lBQ3ZCQSxxRUFBdUJBLENBQUFBO0lBQ3ZCQSxxRUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0FBQ3pCQSxDQUFDQSxFQVRXLGFBQWEsS0FBYixhQUFhLFFBU3hCO0FBQUEsQ0FBQztBQUVGLFdBQVksV0FlWDtBQWZELFdBQVksV0FBVztJQUNyQkMsbUVBQW1DQSxDQUFBQTtJQUNuQ0EsK0VBQW1DQSxDQUFBQTtJQUNuQ0Esa0ZBQW1DQSxDQUFBQTtJQUNuQ0Esc0ZBQW1DQSxDQUFBQTtJQUNuQ0EsNEZBQW1DQSxDQUFBQTtJQUNuQ0Esc0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0EsMEZBQW1DQSxDQUFBQTtBQUNyQ0EsQ0FBQ0EsRUFmVyxXQUFXLEtBQVgsV0FBVyxRQWV0QjtBQUFBLENBQUM7QUFFRixtQkFBb0IsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxJQUFZQyxNQUFNQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxJQUFFQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFFQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtBQUMzRix1QkFBd0IsTUFBTSxFQUFFLEdBQUcsSUFBT0MsTUFBTUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDeEYsMkJBQTRCLFFBQVEsSUFBYUMsTUFBTUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsUUFBUUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDdkYseUJBQTBCLFFBQVEsSUFBZUMsTUFBTUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDakYsd0JBQXlCLFFBQVEsSUFBZ0JDLE1BQU1BLENBQUNBLENBQUVBLENBQUNBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUFBLENBQUNBLENBQUNBO0FBQUEsQ0FBQztBQUU3RSxzQkFBdUIsU0FBUztJQUU5QkMsTUFBTUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsSUFBSUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBRUE7VUFDMUNBLENBQUNBO1VBQ0RBLENBQUVBLFNBQVNBLEdBQUdBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7QUFDdkVBLENBQUNBO0FBRUQ7QUFTQUMsQ0FBQ0E7QUFQZSxhQUFTLEdBQUcsRUFBRSxDQU83QjtBQUVELHNCQUF1QixRQUFnQixFQUFFLFFBQWdCLEVBQUUsTUFBTyxFQUFFLE1BQU8sRUFBRSxNQUFPLEVBQUUsTUFBTztJQUUzRkMsTUFBTUEsR0FBR0EsTUFBTUEsSUFBSUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBQ0E7SUFDL0NBLE1BQU1BLEdBQUdBLE1BQU1BLElBQUlBLFdBQVdBLENBQUNBLGVBQWVBLENBQUNBO0lBQy9DQSxNQUFNQSxHQUFHQSxNQUFNQSxJQUFJQSxXQUFXQSxDQUFDQSxlQUFlQSxDQUFDQTtJQUMvQ0EsTUFBTUEsR0FBR0EsTUFBTUEsSUFBSUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBQ0E7SUFFL0NBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLFFBQVFBLENBQUVBLEdBQUdBO1FBQzFCQSxRQUFRQSxFQUFFQSxRQUFRQTtRQUNsQkEsT0FBT0EsRUFBRUEsQ0FBQ0EsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUEsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUEsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUEsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUE7UUFDOUdBLFFBQVFBLEVBQUVBLFFBQVFBO1FBQ2xCQSxTQUFTQSxFQUFFQSxTQUFTQSxDQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxDQUFFQTtLQUN2REEsQ0FBQ0E7QUFDSkEsQ0FBQ0E7QUFFRCw4QkFBK0IsT0FBZ0IsRUFBRSxRQUFnQixFQUFFLFNBQXNCO0lBRXZGQyxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0FBQzNIQSxDQUFDQTtBQUVELG9DQUFxQyxPQUFnQixFQUFFLFFBQWdCLEVBQUUsU0FBc0I7SUFFN0ZDLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLFFBQVFBLEVBQUVBLFNBQVNBLEVBQUVBLFdBQVdBLENBQUNBLHFCQUFxQkEsQ0FBRUEsQ0FBQ0E7SUFDeEhBLG9CQUFvQkEsQ0FBRUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7QUFDdkRBLENBQUNBO0FBRUQ7SUFFRUMsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUdBLE9BQU9BLEVBQUdBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBR0EsT0FBT0EsRUFBR0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBRTlGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBRXRIQSxvQkFBb0JBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUdBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFFekZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBRTlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFFBQVFBLEVBQUVBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBR0EsT0FBT0EsRUFBR0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE1BQU1BLEVBQUtBLEtBQUtBLEVBQUtBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUU5RkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7SUFDckZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGNBQWNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDL0hBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGNBQWNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDL0hBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsRUFBRUEsU0FBU0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ3pLQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUN2RkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUNqSUEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUNoSUEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsaUJBQWlCQSxDQUFFQSxFQUFFQSxVQUFVQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFHM0tBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFFekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFdBQVdBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLGVBQWVBLENBQUVBLENBQUNBO0lBQzVHQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBRXRIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxXQUFXQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQTtJQUM1R0EsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUV0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUMxSEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM1SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUU1SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUN4SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDcEZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFdBQVdBLENBQUNBLFlBQVlBLENBQUVBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO0lBR3BGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFF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QUFVQSxDQUFDQTtRQUVwQ0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7SUFDL0RBLENBQUNBO0lBRURGLGVBQWVBLENBQUVBLE9BQU9BLEVBQUVBLFlBQVlBO1FBRXBDRyxJQUFJQSxRQUFRQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNsQkEsZUFBZ0JBLEdBQUdBLElBQUtDLFFBQVFBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO1FBRTFDRCxFQUFFQSxDQUFDQSxDQUFFQSxPQUFRQSxDQUFDQTtZQUNaQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVyQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsSUFBSUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsU0FBU0EsRUFBR0EsQ0FBQ0E7WUFDaERBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBRWRBLElBQ0FBLENBQUNBO1lBQ0NBLElBQUlBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1lBQzVCQSxJQUFJQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUNsREEsSUFBSUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDbkJBLElBQUlBLFFBQVFBLEdBQUdBLEVBQUVBLENBQUNBO1lBQ2xCQSxJQUFJQSxRQUFRQSxHQUFHQSxFQUFFQSxDQUFDQTtZQUVsQkEsSUFBSUEsT0FBT0EsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0E7WUFFeENBLEVBQUVBLENBQUNBLENBQUVBLE9BQU9BLElBQUlBLFNBQVVBLENBQUNBLENBQzNCQSxDQUFDQTtnQkFDQ0EsS0FBS0EsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsR0FBR0EsYUFBYUEsR0FBR0EsS0FBS0EsQ0FBRUEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBRUEsUUFBUUEsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsYUFBYUEsQ0FBRUEsQ0FBQ0E7WUFDbEhBLENBQUNBO1lBQ0RBLElBQUlBLENBQ0pBLENBQUNBO2dCQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxPQUFPQSxDQUFDQSxTQUFTQSxDQUFDQTtnQkFDbENBLE9BQU9BLFNBQVNBLElBQUlBLENBQUNBLEVBQ3JCQSxDQUFDQTtvQkFDQ0EsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBRUEsR0FBR0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQzFDQSxNQUFNQSxDQUFBQSxDQUFFQSxTQUFTQSxHQUFHQSxJQUFLQSxDQUFDQSxDQUMxQkEsQ0FBQ0E7d0JBQ0NBLEtBQUtBLElBQUlBLEVBQUVBLEtBQUtBLENBQUNBO3dCQUNqQkEsS0FBS0EsSUFBSUE7NEJBQUVBLFFBQVFBLENBQUVBLFVBQVVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFFBQVFBLENBQUVBLE1BQU1BLEVBQUVBLENBQUVBLENBQUNBOzRCQUFDQSxLQUFLQSxDQUFDQTt3QkFDOUVBLEtBQUtBLElBQUlBOzRCQUFFQSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFBQ0EsS0FBS0EsQ0FBQ0E7b0JBQ2hJQSxDQUFDQTtvQkFDREEsVUFBVUEsRUFBRUEsQ0FBQ0E7b0JBQ2JBLFNBQVNBLEtBQUtBLENBQUNBLENBQUNBO2dCQUNsQkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLEdBQUdBLGFBQWFBLEdBQUdBLEtBQUtBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dCQUVyRkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBRUE7dUJBQ2xCQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBOzJCQUMzREEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQTsyQkFDN0RBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLElBQUlBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBRUE7dUJBQ2pFQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBO3VCQUM3REEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFHQSxDQUFDQSxDQUNsRUEsQ0FBQ0E7b0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUFDQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQzVFQSxJQUFJQSxPQUFPQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQUNBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBO2dCQUM5RUEsQ0FBQ0E7Z0JBRURBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLFVBQVVBLEdBQUdBLENBQUNBLEVBQUVBLFVBQVVBLEdBQUdBLFVBQVVBLEVBQUVBLEVBQUVBLFVBQVVBLEVBQzlEQSxDQUFDQTtvQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7b0JBQy9CQSxJQUFJQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtvQkFFL0JBLE1BQU1BLENBQUFBLENBQUVBLENBQUVBLENBQUNBLENBQ1hBLENBQUNBO3dCQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBOzRCQUN6Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBQ0E7Z0NBQ1ZBLEtBQUtBLENBQUVBLElBQUlBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUMzQkEsSUFBSUE7Z0NBQ0ZBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBOzRCQUNiQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQTs0QkFDM0NBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO2dDQUNWQSxLQUFLQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDM0JBLElBQUlBO2dDQUNGQSxLQUFLQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTs0QkFDYkEsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkE7NEJBQzNDQSxLQUFLQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDekJBLEtBQUtBLENBQUNBO3dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSwwQkFBMEJBOzRCQUM3Q0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ25CQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsMkJBQTJCQTs0QkFDOUNBLEtBQUtBLENBQUVBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUN4Q0EsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkE7NEJBQzVDQSxDQUFDQTtnQ0FDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0NBQzNEQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFFQSxDQUFDQTtnQ0FDekJBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO29DQUNWQSxLQUFLQSxDQUFFQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDbENBLElBQUlBO29DQUNGQSxLQUFLQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDekJBLEtBQUtBLENBQUNBOzRCQUNSQSxDQUFDQTtvQkFDSEEsQ0FBQ0E7b0JBRURBLEVBQUVBLENBQUNBLENBQUVBLFVBQVVBLEdBQUdBLFVBQVVBLEdBQUdBLENBQUVBLENBQUNBO3dCQUNoQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xCQSxDQUFDQTtnQkFDREEsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDaEJBLENBQUNBO1lBRURBLEVBQUVBLENBQUNBLENBQUVBLFlBQWFBLENBQUNBO2dCQUNqQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFDNUJBLENBQ0FBO1FBQUFBLEtBQUtBLENBQUFBLENBQUVBLENBQUVBLENBQUNBLENBQ1ZBLENBQUNBO1lBQ0NBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2JBLENBQUNBO1FBQUFBLENBQUNBO1FBR0ZBLE1BQU1BLENBQUNBLFFBQVFBLENBQUNBO0lBQ2xCQSxDQUFDQTtJQVFPSCxnQkFBZ0JBLENBQUVBLE9BQU9BLEVBQUVBLFVBQVVBO1FBRTNDSyxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVsRUEsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO1lBQ0NBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUNBO1lBQy9CQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM5QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDOUJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsR0FBR0EsWUFBWUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7WUFFMUNBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUNBO1lBQzlCQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLFVBQVVBLENBQUNBO1lBRWpDQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM5QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxNQUFNQSxHQUFHQSxZQUFZQSxDQUFDQSxVQUFVQSxDQUFDQTtRQUM1Q0EsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFT0wsa0JBQWtCQSxDQUFFQSxXQUFXQTtRQUVyQ00sRUFBRUEsQ0FBQ0EsQ0FBRUEsV0FBV0EsR0FBR0EsTUFBT0EsQ0FBQ0EsQ0FDM0JBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFdBQVdBLElBQUlBLE1BQU9BLENBQUNBLENBQzVCQSxDQUFDQTtnQkFDQ0EsTUFBTUEsQ0FBQ0E7b0JBQ0xBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO29CQUN6QkEsV0FBV0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7b0JBQ3JDQSxVQUFVQSxFQUFFQSxXQUFXQSxHQUFHQSxNQUFNQTtpQkFDakNBLENBQUNBO1lBQ0pBLENBQUNBO1lBQ0RBLElBQUlBLENBQ0pBLENBQUNBO2dCQUNDQSxNQUFNQSxDQUFDQTtvQkFDTEEsUUFBUUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0E7b0JBQzFCQSxXQUFXQSxFQUFFQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtvQkFDckNBLFVBQVVBLEVBQUVBLFdBQVdBLEdBQUdBLE1BQU1BO2lCQUNqQ0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ0xBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO2dCQUN6QkEsV0FBV0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQ3JDQSxVQUFVQSxFQUFFQSxXQUFXQSxHQUFHQSxNQUFNQTthQUNqQ0EsQ0FBQ0E7UUFDSkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFRT04sZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsTUFBTUE7UUFFOUNPLElBQUlBLFFBQVFBLENBQUNBO1FBQ2JBLElBQUlBLFVBQVVBLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3hCQSxJQUFJQSxTQUFTQSxDQUFDQTtRQUVkQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUE7Z0JBQzVCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQTtnQkFDNUJBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN6Q0EsVUFBVUEsSUFBSUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7Z0JBQzdCQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO2dCQUM1QkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3pDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO2dCQUM1QkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3pDQSxVQUFVQSxJQUFJQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQTtnQkFDN0JBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0E7Z0JBQzVCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDekNBLFVBQVVBLElBQUlBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUM5QkEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtnQkFDM0JBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN4Q0EsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtnQkFDM0JBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN4Q0EsVUFBVUEsSUFBSUEsU0FBU0EsQ0FBQ0E7Z0JBQ3hCQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUMzQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0Es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QUFXQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUU3RUEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7UUFDNUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVNBLENBQUNBO1lBQ2JBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBO1FBRTdEQSxNQUFNQSxDQUFDQSxRQUFRQSxDQUFDQTtJQUNsQkEsQ0FBQ0E7SUFFT3RCLFdBQVdBLENBQUVBLEdBQUdBO1FBRXRCdUIsTUFBTUEsQ0FBQUEsQ0FBRUEsR0FBSUEsQ0FBQ0EsQ0FDYkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ25EQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ2pHQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNB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QUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDeERBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDdkJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVdBLENBQUNBLENBQ3ZDQSxDQUFDQTt3QkFFQ0EsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7d0JBQ2pDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDdEZBLENBQUNBO29CQUNEQSxJQUFJQTt3QkFDRkEsSUFBSUEsQ0FBQ0Esb0JBQW9CQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDakVBLEtBQUtBLENBQUNBO2dCQUdSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDekJBLENBQUNBO3dCQUNDQSxJQUFJQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDeEVBLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGtCQUFrQkEsQ0FBRUEsV0FBV0EsQ0FBRUEsQ0FBQ0E7d0JBQzFEQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxZQUFZ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R0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFHNURBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLFdBQVdBLENBQUNBLEVBQUVBLENBQUVBLENBQUVBLENBQUNBO1FBR3BFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxXQUFXQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUM3RUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsR0FBR0EsRUFBRUEsRUFBRUEsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFFakVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLFdBQVdBLENBQUNBLElBQUlBLENBQUVBLENBQUNBO1FBRWxEQSxJQUFJQSxDQUFDQSxhQUFhQSxFQUFFQSxDQUFDQTtJQUN2QkEsQ0FBQ0E7SUFFRHpCLGVBQWVBO1FBRWIwQixJQUFJQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtRQUU1Q0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFL0RBLE1BQU1BLENBQUNBLElBQUlBLFlBQVlBLENBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUVBLEVBQUdBLENBQUVBLENBQUFBO0lBRXJJQSxDQUFDQTtJQUVEMUIsSUFBSUEsUUFBUUE7UUFFVjJCLE1BQU1BLENBQUNBO1lBQ0xBLFVBQVVBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO1lBQzNCQSxXQUFXQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQTtZQUM3QkEsVUFBVUEsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUE7WUFDM0JBLFVBQVVBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO1lBQzNCQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQTtZQUN6QkEsVUFBVUEsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUE7WUFDM0JBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBO1NBQzFCQSxDQUFDQTtJQUNKQSxDQUFDQTtBQUVIM0IsQ0FBQ0E7QUFBQSxPQzExQk0sRUFBRSxTQUFTLEVBQUUsTUFBTSx3QkFBd0I7T0FDM0MsRUFBRSxhQUFhLEVBQUUsUUFBUSxFQUFFLE1BQU0sa0JBQWtCO09BQ25ELEVBQUUsaUJBQWlCLEVBQUUsTUFBTSxtQkFBbUI7T0FJOUMsRUFBRSxZQUFZLEVBQUUsTUFBTSwwQkFBMEI7QUFJdkQsY0FBZ0IsR0FBRztJQUVqQkYsTUFBTUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7QUFDdENBLENBQUNBO0FBRUQ7SUFNRThCLFlBQWFBLFFBQVFBLEVBQUVBLFVBQVVBLEVBQUVBLFdBQVdBO1FBRTVDQyxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxRQUFRQSxDQUFDQTtRQUN6QkEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsVUFBVUEsQ0FBQ0E7UUFDN0JBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFdBQVdBLENBQUNBO0lBQ2pDQSxDQUFDQTtBQUNIRCxDQUFDQTtBQUVEO0lBa0JFRSxZQUFhQSxNQUFPQTtRQUVsQkMsRUFBRUEsQ0FBQ0EsQ0FBRUEsTUFBT0EsQ0FBQ0E7WUFDWEEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFDM0JBLElBQUlBO1lBQ0ZBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLGNBQWNBLENBQUNBLGFBQWFBLENBQUNBO1FBRWpEQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUUvQkEsSUFBSUEsQ0FBQ0EsT0FBT0EsR0FBR0EsRUFBRUEsQ0FBQ0E7SUFDcEJBLENBQUNBO0lBRURELGVBQWVBLENBQUVBLEdBQWNBLEVBQUVBLEdBQWNBO1FBRTdDRSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVaQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdaQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN4QkEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFFVEEsSUFBSUEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFDL0RBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUVBLENBQUVBLENBQUNBO1FBQ2pEQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFDQTtRQUdYQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN4QkEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFFVEEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsU0FBU0EsRUFB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RUFBRUEsRUFBRUEsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsRUFBRUEsRUFBRUEsRUFBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFHeEZBLENBQUNBO0lBV0RQLFlBQVlBLENBQUVBLE1BQU1BO1FBRWxCUSxJQUFJQSxDQUFDQSxhQUFhQSxHQUFHQSxJQUFJQSxhQUFhQSxFQUFFQSxDQUFDQTtRQUV6Q0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQUE7UUFDakdBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLElBQUlBLENBQUNBLGFBQWFBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLE9BQU9BLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2pGQSxJQUFJQSxDQUFDQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQTtRQUU1R0EsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsaUJBQWlCQSxFQUFFQSxDQUFDQTtRQUVuQ0EsSUFBSUEsQ0FBQ0EsT0FBT0EsRUFBRUEsQ0FBQ0E7SUFDakJBLENBQUNBO0lBRURSLE9BQU9BO1FBSUxTLElBQUlBLFNBQVNBLEdBQUdBO1lBQ2RBLFVBQVVBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO1lBQzNCQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQTtZQUMzQkEsVUFBVUEsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUE7U0FDdkNBLENBQUNBO1FBRUZBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9B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QVdBLENBQUVBLE9BQVlBO1FBRzlCSyxNQUFNQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7QUFDSEwsQ0FBQ0E7QUFFRCxXQUFXLENBQUMsSUFBSSxDQUFFLEdBQUcsRUFBRSw4QkFBOEIsQ0FBRTtLQUNwRCxLQUFLLENBQUUsTUFBTSxFQUFFLGNBQWMsRUFBRSxTQUFTLENBQUU7S0FDMUMsS0FBSyxDQUFFLE1BQU0sRUFBRSxjQUFjLEVBQUUsU0FBUyxDQUFFO0tBQzFDLEtBQUssQ0FBRSxLQUFLLEVBQUUsYUFBYSxFQUFFLFNBQVMsQ0FBRTtLQUN4QyxLQUFLLENBQUUsS0FBSyxFQUFFLGFBQWEsRUFBRSxTQUFTLENBQUUsQ0FDeEMiLCJmaWxlIjoiY3J5cHRvZ3JhcGhpeC1zZS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5cclxuZXhwb3J0IGNsYXNzIEtleVxyXG57XHJcbiAgX3R5cGU6IG51bWJlcjtcclxuICBfc2l6ZTogbnVtYmVyO1xyXG4gIF9jb21wb25lbnRBcnJheTogQnl0ZVN0cmluZ1tdO1xyXG5cclxuICBjb25zdHJ1Y3RvcigpXHJcbiAge1xyXG4gICAgdGhpcy5fdHlwZSA9IDA7XHJcbiAgICB0aGlzLl9zaXplID0gLTE7XHJcbiAgICB0aGlzLl9jb21wb25lbnRBcnJheSA9IFtdO1xyXG4gIH1cclxuXHJcbiAgc2V0VHlwZSgga2V5VHlwZTogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl90eXBlID0ga2V5VHlwZTtcclxuICB9XHJcblxyXG4gIGdldFR5cGUoKTogbnVtYmVyXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3R5cGU7XHJcbiAgfVxyXG5cclxuICBzZXRTaXplKCBzaXplOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHRoaXMuX3NpemUgPSBzaXplO1xyXG4gIH1cclxuXHJcbiAgZ2V0U2l6ZSgpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5fc2l6ZTtcclxuICB9XHJcblxyXG4gIHNldENvbXBvbmVudCggY29tcDogbnVtYmVyLCB2YWx1ZTogQnl0ZVN0cmluZyApXHJcbiAge1xyXG4gICAgdGhpcy5fY29tcG9uZW50QXJyYXlbIGNvbXAgXSA9IHZhbHVlO1xyXG4gIH1cclxuXHJcbiAgZ2V0Q29tcG9uZW50KCBjb21wOiBudW1iZXIgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLl9jb21wb25lbnRBcnJheVsgY29tcCBdO1xyXG4gIH1cclxuXHJcblxyXG4gIHN0YXRpYyBTRUNSRVQgPSAxO1xyXG4gIHN0YXRpYyBQUklWQVRFID0gMjtcclxuICBzdGF0aWMgUFVCTElDID0gMztcclxuXHJcbiAgc3RhdGljIERFUyA9IDE7XHJcbiAgc3RhdGljIEFFUyA9IDI7XHJcbiAgc3RhdGljIE1PRFVMVVMgPSAzO1xyXG4gIHN0YXRpYyBFWFBPTkVOVCA9IDQ7XHJcbiAgc3RhdGljIENSVF9QID0gNTtcclxuICBzdGF0aWMgQ1JUX1EgPSA2O1xyXG4gIHN0YXRpYyBDUlRfRFAxID0gNztcclxuICBzdGF0aWMgQ1JUX0RRMSA9IDg7XHJcbiAgc3RhdGljIENSVF9QUSA9IDk7XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5pbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XG5pbXBvcnQgeyBLZXkgfSBmcm9tICcuL2tleSc7XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9cbntcbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cblxuICBlbmNyeXB0KCBrZXk6IEtleSwgbWVjaCwgZGF0YTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXG4gIHtcbiAgICB2YXIgazogQnl0ZUFycmF5ID0ga2V5LmdldENvbXBvbmVudCggS2V5LlNFQ1JFVCApLmJ5dGVBcnJheTtcblxuICAgIGlmICggay5sZW5ndGggPT0gMTYgKSAgLy8gM0RFUyBEb3VibGUgLT4gVHJpcGxlXG4gICAge1xuICAgICAgdmFyIG9yaWcgPSBrO1xuXG4gICAgICBrID0gbmV3IEJ5dGVBcnJheSggW10gKS5zZXRMZW5ndGgoIDI0ICk7XG5cbiAgICAgIGsuc2V0Qnl0ZXNBdCggMCwgb3JpZyApO1xuICAgICAgay5zZXRCeXRlc0F0KCAxNiwgb3JpZy52aWV3QXQoIDAsIDggKSApO1xuICAgIH1cblxuICAgIHZhciBjcnlwdG9UZXh0ID0gbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGsuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDAgKSApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCBjcnlwdG9UZXh0ICk7XG4gIH1cblxuICBkZWNyeXB0KCBrZXksIG1lY2gsIGRhdGEgKVxuICB7XG4gICAgcmV0dXJuIGRhdGE7XG4gIH1cblxuICBzaWduKCBrZXk6IEtleSwgbWVjaCwgZGF0YTogQnl0ZVN0cmluZywgaXY/ICk6IEJ5dGVTdHJpbmdcbiAge1xuICAgIHZhciBrID0ga2V5LmdldENvbXBvbmVudCggS2V5LlNFQ1JFVCApLmJ5dGVBcnJheTtcblxuICAgIHZhciBrZXlEYXRhID0gaztcblxuICAgIGlmICggay5sZW5ndGggPT0gMTYgKSAgLy8gM0RFUyBEb3VibGUgLT4gVHJpcGxlXG4gICAge1xuICAgICAga2V5RGF0YSA9IG5ldyBCeXRlQXJyYXkoKTtcblxuICAgICAga2V5RGF0YVxuICAgICAgICAuc2V0TGVuZ3RoKCAyNCApXG4gICAgICAgIC5zZXRCeXRlc0F0KCAwLCBrIClcbiAgICAgICAgLnNldEJ5dGVzQXQoIDE2LCBrLmJ5dGVzQXQoIDAsIDggKSApO1xuICAgIH1cblxuICAgIGlmICggaXYgPT0gdW5kZWZpbmVkIClcbiAgICAgIGl2ID0gbmV3IFVpbnQ4QXJyYXkoIFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdICk7XG5cbiAgICAvLyBmdW5jdGlvbigga2V5LCBtZXNzYWdlLCBlbmNyeXB0LCBtb2RlLCBpdiwgcGFkZGluZyApXG4gICAgLy8gbW9kZT0xIENCQywgcGFkZGluZz00IG5vLXBhZFxuICAgIHZhciBjcnlwdG9UZXh0ID0gbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGtleURhdGEuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDEsIGl2LCA0ICkgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggY3J5cHRvVGV4dCApLmJ5dGVzKCAtOCApO1xuICB9XG5cbiAgc3RhdGljIGRlc1BDO1xuICBzdGF0aWMgZGVzU1A7XG5cbiAgcHJpdmF0ZSBkZXMoIGtleTogVWludDhBcnJheSwgbWVzc2FnZTogVWludDhBcnJheSwgZW5jcnlwdDogbnVtYmVyLCBtb2RlOiBudW1iZXIsIGl2PzogVWludDhBcnJheSwgcGFkZGluZz86IG51bWJlciApOiBVaW50OEFycmF5XG4gIHtcbiAgICAvL2Rlc19jcmVhdGVLZXlzXG4gICAgLy90aGlzIHRha2VzIGFzIGlucHV0IGEgNjQgYml0IGtleSAoZXZlbiB0aG91Z2ggb25seSA1NiBiaXRzIGFyZSB1c2VkKVxuICAgIC8vYXMgYW4gYXJyYXkgb2YgMiBpbnRlZ2VycywgYW5kIHJldHVybnMgMTYgNDggYml0IGtleXNcbiAgICBmdW5jdGlvbiBkZXNfY3JlYXRlS2V5cyAoa2V5KVxuICAgIHtcbiAgICAgIGlmICggQ3J5cHRvLmRlc1BDID09IHVuZGVmaW5lZCApXG4gICAgICB7XG4gICAgICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgICAgIENyeXB0by5kZXNQQyA9IHtcbiAgICAgICAgICBwYzJieXRlczAgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgyMDAwMDAwMCwweDIwMDAwMDA0LDB4MTAwMDAsMHgxMDAwNCwweDIwMDEwMDAwLDB4MjAwMTAwMDQsMHgyMDAsMHgyMDQsMHgyMDAwMDIwMCwweDIwMDAwMjA0LDB4MTAyMDAsMHgxMDIwNCwweDIwMDEwMjAwLDB4MjAwMTAyMDQgXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MSwweDEwMDAwMCwweDEwMDAwMSwweDQwMDAwMDAsMHg0MDAwMDAxLDB4NDEwMDAwMCwweDQxMDAwMDEsMHgxMDAsMHgxMDEsMHgxMDAxMDAsMHgxMDAxMDEsMHg0MDAwMTAwLDB4NDAwMDEwMSwweDQxMDAxMDAsMHg0MTAwMTAxXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDgsMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAwMDAwLDB4ODAwMDAwMCwweDgyMDAwMDAsMHgyMDAwLDB4MjAyMDAwLDB4ODAwMjAwMCwweDgyMDIwMDAsMHgyMDAwMCwweDIyMDAwMCwweDgwMjAwMDAsMHg4MjIwMDAwLDB4MjIwMDAsMHgyMjIwMDAsMHg4MDIyMDAwLDB4ODIyMjAwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczQgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwLDB4MjAsMHg0MjAsMCwweDQwMCwweDIwLDB4NDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjBdICksXG4gICAgICAgICAgcGMyYnl0ZXM2IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyLDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAsMHg4MDAsMHgxMDgwMCwweDIwMDAwMDAwLDB4MjAwMTAwMDAsMHgyMDAwMDgwMCwweDIwMDEwODAwLDB4MjAwMDAsMHgzMDAwMCwweDIwODAwLDB4MzA4MDAsMHgyMDAyMDAwMCwweDIwMDMwMDAwLDB4MjAwMjA4MDAsMHgyMDAzMDgwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczggOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDAsMHg0MDAwMCwweDIsMHg0MDAwMiwweDIsMHg0MDAwMiwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAyLDB4MjA0MDAwMiwweDIwMDAwMDIsMHgyMDQwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMCwwLDB4MjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgyMDAwLDB4MjAyMCwweDIwMDAsMHgyMDIwLDB4MTAyMDAwLDB4MTAyMDIwLDB4MTAyMDAwLDB4MTAyMDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTE6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMCwweDIwMCwweDEwMDAyMDAsMHgyMDAwMDAsMHgxMjAwMDAwLDB4MjAwMjAwLDB4MTIwMDIwMCwweDQwMDAwMDAsMHg1MDAwMDAwLDB4NDAwMDIwMCwweDUwMDAyMDAsMHg0MjAwMDAwLDB4NTIwMDAwMCwweDQyMDAyMDAsMHg1MjAwMjAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTI6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMCwweDgwMDAwMDAsMHg4MDAxMDAwLDB4ODAwMDAsMHg4MTAwMCwweDgwODAwMDAsMHg4MDgxMDAwLDB4MTAsMHgxMDEwLDB4ODAwMDAxMCwweDgwMDEwMTAsMHg4MDAxMCwweDgxMDEwLDB4ODA4MDAxMCwweDgwODEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMzogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MTAwLDB4MTA0LDAsMHg0LDB4MTAwLDB4MTA0LDB4MSwweDUsMHgxMDEsMHgxMDUsMHgxLDB4NSwweDEwMSwweDEwNV0gKVxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICAvL2hvdyBtYW55IGl0ZXJhdGlvbnMgKDEgZm9yIGRlcywgMyBmb3IgdHJpcGxlIGRlcylcbiAgICAgIHZhciBpdGVyYXRpb25zID0ga2V5Lmxlbmd0aCA+IDggPyAzIDogMTsgLy9jaGFuZ2VkIGJ5IFBhdWwgMTYvNi8yMDA3IHRvIHVzZSBUcmlwbGUgREVTIGZvciA5KyBieXRlIGtleXNcbiAgICAgIC8vc3RvcmVzIHRoZSByZXR1cm4ga2V5c1xuICAgICAgdmFyIGtleXMgPSBuZXcgVWludDMyQXJyYXkoMzIgKiBpdGVyYXRpb25zKTtcbiAgICAgIC8vbm93IGRlZmluZSB0aGUgbGVmdCBzaGlmdHMgd2hpY2ggbmVlZCB0byBiZSBkb25lXG4gICAgICB2YXIgc2hpZnRzID0gWyAwLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwIF07XG4gICAgICAvL290aGVyIHZhcmlhYmxlc1xuICAgICAgdmFyIGxlZnR0ZW1wLCByaWdodHRlbXAsIG09MCwgbj0wLCB0ZW1wO1xuXG4gICAgICBmb3IgKHZhciBqPTA7IGo8aXRlcmF0aW9uczsgaisrKVxuICAgICAgeyAvL2VpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuICAgICAgICBsZWZ0ID0gIChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG4gICAgICAgIHJpZ2h0ID0gKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcblxuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDIpIF4gcmlnaHQpICYgMHgzMzMzMzMzMzsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAyKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgICAvL3RoZSByaWdodCBzaWRlIG5lZWRzIHRvIGJlIHNoaWZ0ZWQgYW5kIHRvIGdldCB0aGUgbGFzdCBmb3VyIGJpdHMgb2YgdGhlIGxlZnQgc2lkZVxuICAgICAgICB0ZW1wID0gKGxlZnQgPDwgOCkgfCAoKHJpZ2h0ID4+PiAyMCkgJiAweDAwMDAwMGYwKTtcbiAgICAgICAgLy9sZWZ0IG5lZWRzIHRvIGJlIHB1dCB1cHNpZGUgZG93blxuICAgICAgICBsZWZ0ID0gKHJpZ2h0IDw8IDI0KSB8ICgocmlnaHQgPDwgOCkgJiAweGZmMDAwMCkgfCAoKHJpZ2h0ID4+PiA4KSAmIDB4ZmYwMCkgfCAoKHJpZ2h0ID4+PiAyNCkgJiAweGYwKTtcbiAgICAgICAgcmlnaHQgPSB0ZW1wO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlc2Ugc2hpZnRzIG9uIHRoZSBsZWZ0IGFuZCByaWdodCBrZXlzXG4gICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHNoaWZ0cy5sZW5ndGg7IGkrKylcbiAgICAgICAge1xuICAgICAgICAgIC8vc2hpZnQgdGhlIGtleXMgZWl0aGVyIG9uZSBvciB0d28gYml0cyB0byB0aGUgbGVmdFxuICAgICAgICAgIGlmIChzaGlmdHNbaV0pXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDIpIHwgKGxlZnQgPj4+IDI2KTsgcmlnaHQgPSAocmlnaHQgPDwgMikgfCAocmlnaHQgPj4+IDI2KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZWxzZVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAyNyk7IHJpZ2h0ID0gKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAyNyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGxlZnQgJj0gLTB4ZjsgcmlnaHQgJj0gLTB4ZjtcblxuICAgICAgICAgIC8vbm93IGFwcGx5IFBDLTIsIGluIHN1Y2ggYSB3YXkgdGhhdCBFIGlzIGVhc2llciB3aGVuIGVuY3J5cHRpbmcgb3IgZGVjcnlwdGluZ1xuICAgICAgICAgIC8vdGhpcyBjb252ZXJzaW9uIHdpbGwgbG9vayBsaWtlIFBDLTIgZXhjZXB0IG9ubHkgdGhlIGxhc3QgNiBiaXRzIG9mIGVhY2ggYnl0ZSBhcmUgdXNlZFxuICAgICAgICAgIC8vcmF0aGVyIHRoYW4gNDggY29uc2VjdXRpdmUgYml0cyBhbmQgdGhlIG9yZGVyIG9mIGxpbmVzIHdpbGwgYmUgYWNjb3JkaW5nIHRvXG4gICAgICAgICAgLy9ob3cgdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9ucyB3aWxsIGJlIGFwcGxpZWQ6IFMyLCBTNCwgUzYsIFM4LCBTMSwgUzMsIFM1LCBTN1xuICAgICAgICAgIGxlZnR0ZW1wID0gQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMFtsZWZ0ID4+PiAyOF0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMyWyhsZWZ0ID4+PiAyMCkgJiAweGZdIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzM1sobGVmdCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzNFsobGVmdCA+Pj4gMTIpICYgMHhmXSB8IENyeXB0by5kZXNQQy5wYzJieXRlczVbKGxlZnQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzNlsobGVmdCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHJpZ2h0dGVtcCA9IENyeXB0by5kZXNQQy5wYzJieXRlczdbcmlnaHQgPj4+IDI4XSB8IENyeXB0by5kZXNQQy5wYzJieXRlczhbKHJpZ2h0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzOVsocmlnaHQgPj4+IDIwKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMVsocmlnaHQgPj4+IDEyKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMlsocmlnaHQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNQQy5wYzJieXRlczEzWyhyaWdodCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjtcbiAgICAgICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICAgICAgfVxuICAgICAgfSAvL2ZvciBlYWNoIGl0ZXJhdGlvbnNcblxuICAgICAgcmV0dXJuIGtleXM7XG4gICAgfSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG4gICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICBpZiAoIENyeXB0by5kZXNTUCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIENyeXB0by5kZXNTUCA9IHtcbiAgICAgICAgc3BmdW5jdGlvbjE6IG5ldyBVaW50MzJBcnJheSggWzB4MTAxMDQwMCwwLDB4MTAwMDAsMHgxMDEwNDA0LDB4MTAxMDAwNCwweDEwNDA0LDB4NCwweDEwMDAwLDB4NDAwLDB4MTAxMDQwMCwweDEwMTA0MDQsMHg0MDAsMHgxMDAwNDA0LDB4MTAxMDAwNCwweDEwMDAwMDAsMHg0LDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMHgxMDQwMCwweDEwNDAwLDB4MTAxMDAwMCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDQsMHgxMDAwMDA0LDB4MTAwMDAwNCwweDEwMDA0LDAsMHg0MDQsMHgxMDQwNCwweDEwMDAwMDAsMHgxMDAwMCwweDEwMTA0MDQsMHg0LDB4MTAxMDAwMCwweDEwMTA0MDAsMHgxMDAwMDAwLDB4MTAwMDAwMCwweDQwMCwweDEwMTAwMDQsMHgxMDAwMCwweDEwNDAwLDB4MTAwMDAwNCwweDQwMCwweDQsMHgxMDAwNDA0LDB4MTA0MDQsMHgxMDEwNDA0LDB4MTAwMDQsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDAwMDQsMHg0MDQsMHgxMDQwNCwweDEwMTA0MDAsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwwLDB4MTAwMDQsMHgxMDQwMCwwLDB4MTAxMDAwNF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjI6IG5ldyBVaW50MzJBcnJheSggWy0weDdmZWY3ZmUwLC0weDdmZmY4MDAwLDB4ODAwMCwweDEwODAyMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLC0weDdmZWY3ZmUwLC0weDdmZWY4MDAwLC0weDgwMDAwMDAwLC0weDdmZmY4MDAwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsMHgxMDgwMDAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsMCwtMHg4MDAwMDAwMCwweDgwMDAsMHgxMDgwMjAsLTB4N2ZmMDAwMDAsMHgxMDAwMjAsLTB4N2ZmZmZmZTAsMCwweDEwODAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsLTB4N2ZmMDAwMDAsMHg4MDIwLDAsMHgxMDgwMjAsLTB4N2ZlZmZmZTAsMHgxMDAwMDAsLTB4N2ZmZjdmZTAsLTB4N2ZmMDAwMDAsLTB4N2ZlZjgwMDAsMHg4MDAwLC0weDdmZjAwMDAwLC0weDdmZmY4MDAwLDB4MjAsLTB4N2ZlZjdmZTAsMHgxMDgwMjAsMHgyMCwweDgwMDAsLTB4ODAwMDAwMDAsMHg4MDIwLC0weDdmZWY4MDAwLDB4MTAwMDAwLC0weDdmZmZmZmUwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLDB4MTAwMDIwLDB4MTA4MDAwLDAsLTB4N2ZmZjgwMDAsMHg4MDIwLC0weDgwMDAwMDAwLC0weDdmZWZmZmUwLC0weDdmZWY3ZmUwLDB4MTA4MDAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uMzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDgsMHg4MDIwMjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwMCwwLDB4MjAyMDgsMHg4MDAwMjAwLDB4MjAwMDgsMHg4MDAwMDA4LDB4ODAwMDAwOCwweDIwMDAwLDB4ODAyMDIwOCwweDIwMDA4LDB4ODAyMDAwMCwweDIwOCwweDgwMDAwMDAsMHg4LDB4ODAyMDIwMCwweDIwMCwweDIwMjAwLDB4ODAyMDAwMCwweDgwMjAwMDgsMHgyMDIwOCwweDgwMDAyMDgsMHgyMDIwMCwweDIwMDAwLDB4ODAwMDIwOCwweDgsMHg4MDIwMjA4LDB4MjAwLDB4ODAwMDAwMCwweDgwMjAyMDAsMHg4MDAwMDAwLDB4MjAwMDgsMHgyMDgsMHgyMDAwMCwweDgwMjAyMDAsMHg4MDAwMjAwLDAsMHgyMDAsMHgyMDAwOCwweDgwMjAyMDgsMHg4MDAwMjAwLDB4ODAwMDAwOCwweDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDgsMHgyMDAwMCwweDgwMDAwMDAsMHg4MDIwMjA4LDB4OCwweDIwMjA4LDB4MjAyMDAsMHg4MDAwMDA4LDB4ODAyMDAwMCwweDgwMDAyMDgsMHgyMDgsMHg4MDIwMDAwLDB4MjAyMDgsMHg4LDB4ODAyMDAwOCwweDIwMjAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNDogbmV3IFVpbnQzMkFycmF5KCBbMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgwLDB4ODAwMDgxLDB4ODAwMDAxLDB4MjAwMSwwLDB4ODAyMDAwLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwweDgwMDA4MCwweDgwMDAwMSwweDEsMHgyMDAwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAxLDB4MjA4MCwweDgwMDA4MSwweDEsMHgyMDgwLDB4ODAwMDgwLDB4MjAwMCwweDgwMjA4MCwweDgwMjA4MSwweDgxLDB4ODAwMDgwLDB4ODAwMDAxLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwwLDB4ODAyMDAwLDB4MjA4MCwweDgwMDA4MCwweDgwMDA4MSwweDEsMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgxLDB4ODEsMHgxLDB4MjAwMCwweDgwMDAwMSwweDIwMDEsMHg4MDIwODAsMHg4MDAwODEsMHgyMDAxLDB4MjA4MCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMCwweDgwMjA4MF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjU6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwLDB4MjA4MDEwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDgwMDAwLDB4MTAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDAwODAxMDAsMHg4MDAwMCwweDIwMDAxMDAsMHg0MDA4MDEwMCwweDQyMDAwMTAwLDB4NDIwODAwMDAsMHg4MDEwMCwweDQwMDAwMDAwLDB4MjAwMDAwMCwweDQwMDgwMDAwLDB4NDAwODAwMDAsMCwweDQwMDAwMTAwLDB4NDIwODAxMDAsMHg0MjA4MDEwMCwweDIwMDAxMDAsMHg0MjA4MDAwMCwweDQwMDAwMTAwLDAsMHg0MjAwMDAwMCwweDIwODAxMDAsMHgyMDAwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDgwMDAwLDB4NDIwMDAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg0MDA4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDAwMCwweDQyMDgwMDAwLDB4MjA4MDEwMCwweDQwMDgwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQyMDgwMDAwLDB4NDIwODAxMDAsMHg4MDEwMCwweDQyMDAwMDAwLDB4NDIwODAxMDAsMHgyMDgwMDAwLDAsMHg0MDA4MDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAxMDAsMHg4MDAwMCwwLDB4NDAwODAwMDAsMHgyMDgwMTAwLDB4NDAwMDAxMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb242OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMDEwLDB4MjA0MDAwMDAsMHg0MDAwLDB4MjA0MDQwMTAsMHgyMDQwMDAwMCwweDEwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDQwNDAxMCwweDQwMDAwMCwweDIwMDAwMDEwLDB4NDAwMDEwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMCwweDQwMDAxMCwweDIwMDA0MDEwLDB4NDAwMCwweDQwNDAwMCwweDIwMDA0MDEwLDB4MTAsMHgyMDQwMDAxMCwweDIwNDAwMDEwLDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwweDQwMTAsMHg0MDQwMDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4MjAwMDQwMDAsMHgxMCwweDIwNDAwMDEwLDB4NDA0MDAwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4MjA0MDQwMTAsMHg0MDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDIwNDA0MDAwLDAsMHgyMDQwMDAxMCwweDEwLDB4NDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4NDAwMCwweDQwMDAxMCwweDIwMDA0MDEwLDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4NDAwMDEwLDB4MjAwMDQwMTBdICksXG4gICAgICAgIHNwZnVuY3Rpb243OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMCwweDQyMDAwMDIsMHg0MDAwODAyLDAsMHg4MDAsMHg0MDAwODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDQyMDA4MDIsMHgyMDAwMDAsMCwweDQwMDAwMDIsMHgyLDB4NDAwMDAwMCwweDQyMDAwMDIsMHg4MDIsMHg0MDAwODAwLDB4MjAwODAyLDB4MjAwMDAyLDB4NDAwMDgwMCwweDQwMDAwMDIsMHg0MjAwMDAwLDB4NDIwMDgwMCwweDIwMDAwMiwweDQyMDAwMDAsMHg4MDAsMHg4MDIsMHg0MjAwODAyLDB4MjAwODAwLDB4MiwweDQwMDAwMDAsMHgyMDA4MDAsMHg0MDAwMDAwLDB4MjAwODAwLDB4MjAwMDAwLDB4NDAwMDgwMiwweDQwMDA4MDIsMHg0MjAwMDAyLDB4NDIwMDAwMiwweDIsMHgyMDAwMDIsMHg0MDAwMDAwLDB4NDAwMDgwMCwweDIwMDAwMCwweDQyMDA4MDAsMHg4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4ODAyLDB4NDAwMDAwMiwweDQyMDA4MDIsMHg0MjAwMDAwLDB4MjAwODAwLDAsMHgyLDB4NDIwMDgwMiwwLDB4MjAwODAyLDB4NDIwMDAwMCwweDgwMCwweDQwMDAwMDIsMHg0MDAwODAwLDB4ODAwLDB4MjAwMDAyXSApLFxuICAgICAgICBzcGZ1bmN0aW9uODogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAwMTA0MCwweDEwMDAsMHg0MDAwMCwweDEwMDQxMDQwLDB4MTAwMDAwMDAsMHgxMDAwMTA0MCwweDQwLDB4MTAwMDAwMDAsMHg0MDA0MCwweDEwMDQwMDAwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDEwMDQxMDAwLDB4NDEwNDAsMHgxMDAwLDB4NDAsMHgxMDA0MDAwMCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHgxMDQwLDB4NDEwMDAsMHg0MDA0MCwweDEwMDQwMDQwLDB4MTAwNDEwMDAsMHgxMDQwLDAsMCwweDEwMDQwMDQwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDQxMDQwLDB4NDAwMDAsMHg0MTA0MCwweDQwMDAwLDB4MTAwNDEwMDAsMHgxMDAwLDB4NDAsMHgxMDA0MDA0MCwweDEwMDAsMHg0MTA0MCwweDEwMDAxMDAwLDB4NDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwNDAwNDAsMHgxMDAwMDAwMCwweDQwMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDAwNDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwMDEwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDQxMDAwLDB4MTA0MCwweDEwNDAsMHg0MDA0MCwweDEwMDAwMDAwLDB4MTAwNDEwMDBdICksXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vY3JlYXRlIHRoZSAxNiBvciA0OCBzdWJrZXlzIHdlIHdpbGwgbmVlZFxuICAgIHZhciBrZXlzID0gZGVzX2NyZWF0ZUtleXMoIGtleSApO1xuXG4gICAgdmFyIG09MCwgaSwgaiwgdGVtcCwgbGVmdCwgcmlnaHQsIGxvb3Bpbmc7XG4gICAgdmFyIGNiY2xlZnQsIGNiY2xlZnQyLCBjYmNyaWdodCwgY2JjcmlnaHQyXG4gICAgdmFyIGxlbiA9IG1lc3NhZ2UubGVuZ3RoO1xuXG4gICAgLy9zZXQgdXAgdGhlIGxvb3BzIGZvciBzaW5nbGUgYW5kIHRyaXBsZSBkZXNcbiAgICB2YXIgaXRlcmF0aW9ucyA9IGtleXMubGVuZ3RoID09IDMyID8gMyA6IDk7IC8vc2luZ2xlIG9yIHRyaXBsZSBkZXNcblxuICAgIGlmIChpdGVyYXRpb25zID09IDMpXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyIF0gOiBbIDMwLCAtMiwgLTIgXTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiwgNjIsIDMwLCAtMiwgNjQsIDk2LCAyIF0gOiBbIDk0LCA2MiwgLTIsIDMyLCA2NCwgMiwgMzAsIC0yLCAtMiBdO1xuICAgIH1cblxuICAgIC8vIHBhZCB0aGUgbWVzc2FnZSBkZXBlbmRpbmcgb24gdGhlIHBhZGRpbmcgcGFyYW1ldGVyXG4gICAgaWYgKCAoIHBhZGRpbmcgIT0gdW5kZWZpbmVkICkgJiYgKCBwYWRkaW5nICE9IDQgKSApXG4gICAge1xuICAgICAgdmFyIHVucGFkZGVkTWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICB2YXIgcGFkID0gOC0obGVuJTgpO1xuXG4gICAgICBtZXNzYWdlID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiArIDggKTtcbiAgICAgIG1lc3NhZ2Uuc2V0KCB1bnBhZGRlZE1lc3NhZ2UsIDAgKTtcblxuICAgICAgc3dpdGNoKCBwYWRkaW5nIClcbiAgICAgIHtcbiAgICAgICAgY2FzZSAwOiAvLyB6ZXJvLXBhZFxuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwIF0gKSwgbGVuICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgY2FzZSAxOiAvLyBQS0NTNyBwYWRkaW5nXG4gICAgICAgIHtcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWRdICksIDggKTtcblxuICAgICAgICAgIGlmICggcGFkPT04IClcbiAgICAgICAgICAgIGxlbis9ODtcblxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG5cbiAgICAgICAgY2FzZSAyOiAgLy8gcGFkIHRoZSBtZXNzYWdlIHdpdGggc3BhY2VzXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAgXSApLCA4ICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgIH1cblxuICAgICAgbGVuICs9IDgtKGxlbiU4KVxuICAgIH1cblxuICAgIC8vIHN0b3JlIHRoZSByZXN1bHQgaGVyZVxuICAgIHZhciByZXN1bHQgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG5cbiAgICBpZiAobW9kZSA9PSAxKVxuICAgIHsgLy9DQkMgbW9kZVxuICAgICAgdmFyIG0gPSAwO1xuXG4gICAgICBjYmNsZWZ0ID0gIChpdlttKytdIDw8IDI0KSB8IChpdlttKytdIDw8IDE2KSB8IChpdlttKytdIDw8IDgpIHwgaXZbbSsrXTtcbiAgICAgIGNiY3JpZ2h0ID0gKGl2W20rK10gPDwgMjQpIHwgKGl2W20rK10gPDwgMTYpIHwgKGl2W20rK10gPDwgOCkgfCBpdlttKytdO1xuICAgIH1cblxuICAgIHZhciBybSA9IDA7XG5cbiAgICAvL2xvb3AgdGhyb3VnaCBlYWNoIDY0IGJpdCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgIHdoaWxlIChtIDwgbGVuKVxuICAgIHtcbiAgICAgIGxlZnQgPSAgKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG4gICAgICByaWdodCA9IChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBsZWZ0IF49IGNiY2xlZnQ7IHJpZ2h0IF49IGNiY3JpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGNiY2xlZnQyID0gY2JjbGVmdDtcbiAgICAgICAgICBjYmNyaWdodDIgPSBjYmNyaWdodDtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vZmlyc3QgZWFjaCA2NCBidXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2UgbXVzdCBiZSBwZXJtdXRlZCBhY2NvcmRpbmcgdG8gSVBcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICBsZWZ0ID0gKChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDMxKSk7XG4gICAgICByaWdodCA9ICgocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDMxKSk7XG5cbiAgICAgIC8vZG8gdGhpcyBlaXRoZXIgMSBvciAzIHRpbWVzIGZvciBlYWNoIGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgICBmb3IgKGo9MDsgajxpdGVyYXRpb25zOyBqKz0zKVxuICAgICAge1xuICAgICAgICB2YXIgZW5kbG9vcCA9IGxvb3BpbmdbaisxXTtcbiAgICAgICAgdmFyIGxvb3BpbmMgPSBsb29waW5nW2orMl07XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uXG4gICAgICAgIGZvciAoaT1sb29waW5nW2pdOyBpIT1lbmRsb29wOyBpKz1sb29waW5jKVxuICAgICAgICB7IC8vZm9yIGVmZmljaWVuY3lcbiAgICAgICAgICB2YXIgcmlnaHQxID0gcmlnaHQgXiBrZXlzW2ldO1xuICAgICAgICAgIHZhciByaWdodDIgPSAoKHJpZ2h0ID4+PiA0KSB8IChyaWdodCA8PCAyOCkpIF4ga2V5c1tpKzFdO1xuXG4gICAgICAgICAgLy90aGUgcmVzdWx0IGlzIGF0dGFpbmVkIGJ5IHBhc3NpbmcgdGhlc2UgYnl0ZXMgdGhyb3VnaCB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zXG4gICAgICAgICAgdGVtcCA9IGxlZnQ7XG4gICAgICAgICAgbGVmdCA9IHJpZ2h0O1xuICAgICAgICAgIHJpZ2h0ID0gdGVtcCBeIChDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjJbKHJpZ2h0MSA+Pj4gMjQpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjRbKHJpZ2h0MSA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb242WyhyaWdodDEgPj4+ICA4KSAmIDB4M2ZdIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb244W3JpZ2h0MSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uM1socmlnaHQyID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjVbKHJpZ2h0MiA+Pj4gIDgpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjdbcmlnaHQyICYgMHgzZl0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdGVtcCA9IGxlZnQ7IGxlZnQgPSByaWdodDsgcmlnaHQgPSB0ZW1wOyAvL3VucmV2ZXJzZSBsZWZ0IGFuZCByaWdodFxuICAgICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgICAgbGVmdCA9ICgobGVmdCA+Pj4gMSkgfCAobGVmdCA8PCAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpO1xuXG4gICAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDI7XG4gICAgICAgICAgcmlnaHQgXj0gY2JjcmlnaHQyO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc3VsdC5zZXQoIG5ldyBVaW50OEFycmF5ICggWyAobGVmdD4+PjI0KSAmIDB4ZmYsIChsZWZ0Pj4+MTYpICYgMHhmZiwgKGxlZnQ+Pj44KSAmIDB4ZmYsIChsZWZ0KSAmIDB4ZmYsIChyaWdodD4+PjI0KSAmIDB4ZmYsIChyaWdodD4+PjE2KSAmIDB4ZmYsIChyaWdodD4+PjgpICYgMHhmZiwgKHJpZ2h0KSAmIDB4ZmYgXSApLCBybSApO1xuXG4gICAgICBybSArPSA4O1xuICAgIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9IC8vZW5kIG9mIGRlc1xuXG4gIHZlcmlmeSgga2V5LCBtZWNoLCBkYXRhLCBzaWduYXR1cmUsIGl2IClcbiAge1xuICAgIHJldHVybiBkYXRhO1xuICB9XG5cbiAgZGlnZXN0KCBtZWNoLCBkYXRhIClcbiAge1xuICAgIHJldHVybiBkYXRhO1xuICB9XG5cbiAgc3RhdGljIERFU19DQkM6IE51bWJlciA9IDI7XG4gIHN0YXRpYyBERVNfRUNCID0gNTtcbiAgc3RhdGljIERFU19NQUMgPSA4O1xuICBzdGF0aWMgREVTX01BQ19FTVYgPSA5O1xuICBzdGF0aWMgSVNPOTc5N19NRVRIT0RfMSA9IDExO1xuICBzdGF0aWMgSVNPOTc5N19NRVRIT0RfMiA9IDEyO1xuXG4gIHN0YXRpYyBNRDUgPSAxMztcbiAgc3RhdGljIFJTQSA9IDE0O1xuICBzdGF0aWMgU0hBXzEgPSAxNTtcbiAgc3RhdGljIFNIQV81MTIgPSAyNTtcbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSwgQnl0ZUVuY29kaW5nIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcblxyXG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XHJcbmltcG9ydCB7IENyeXB0byB9IGZyb20gJy4vY3J5cHRvJztcclxuXHJcbmV4cG9ydCBjbGFzcyBCeXRlU3RyaW5nXHJcbntcclxuICBwdWJsaWMgYnl0ZUFycmF5OiBCeXRlQXJyYXk7XHJcblxyXG4gIHB1YmxpYyBzdGF0aWMgSEVYID0gQnl0ZUVuY29kaW5nLkhFWDtcclxuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCB2YWx1ZTogc3RyaW5nIHwgQnl0ZVN0cmluZyB8IEJ5dGVBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIgKVxyXG4gIHtcclxuICAgIGlmICggIWVuY29kaW5nIClcclxuICAgIHtcclxuICAgICAgaWYgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVTdHJpbmcgKVxyXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICAgIGVsc2UgaWYgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVBcnJheSApXHJcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5jbG9uZSgpO1xyXG4vLyAgICAgIGVsc2VcclxuLy8gICAgICAgIHN1cGVyKCBVaW50OEFycmF5KCB2YWx1ZSApICk7XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICB7XHJcbiAgICAgIHN3aXRjaCggZW5jb2RpbmcgKVxyXG4gICAgICB7XHJcbiAgICAgICAgY2FzZSBCeXRlU3RyaW5nLkhFWDpcclxuICAgICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggPHN0cmluZz52YWx1ZSwgQnl0ZUFycmF5LkhFWCApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICB0aHJvdyBcIkJ5dGVTdHJpbmcgdW5zdXBwb3J0ZWQgZW5jb2RpbmdcIjtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xyXG4gIH1cclxuXHJcbiAgYnl0ZXMoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS52aWV3QXQoIG9mZnNldCwgY291bnQgKSApO1xyXG4gIH1cclxuXHJcbiAgYnl0ZUF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQgKTtcclxuICB9XHJcblxyXG4gIGVxdWFscyggb3RoZXJCeXRlU3RyaW5nOiBCeXRlU3RyaW5nIClcclxuICB7XHJcbi8vICAgIHJldHVybiAhKCB0aGlzLl9ieXRlcyA8IG90aGVyQnl0ZVN0cmluZy5fYnl0ZXMgKSAmJiAhKCB0aGlzLl9ieXRlcyA+IG90aGVyQnl0ZVN0cmluZy5fYnl0ZXMgKTtcclxuICB9XHJcblxyXG4gIGNvbmNhdCggdmFsdWU6IEJ5dGVTdHJpbmcgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHRoaXMuYnl0ZUFycmF5LmNvbmNhdCggdmFsdWUuYnl0ZUFycmF5ICk7XHJcblxyXG4gICAgcmV0dXJuIHRoaXM7XHJcbiAgfVxyXG5cclxuICBsZWZ0KCBjb3VudDogbnVtYmVyIClcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LnZpZXdBdCggMCApICk7XHJcbiAgfVxyXG5cclxuICByaWdodCggY291bnQ6IG51bWJlciApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS52aWV3QXQoIC1jb3VudCApICk7XHJcbiAgfVxyXG5cclxuICBub3QoICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LmNsb25lKCkubm90KCkgKTtcclxuICB9XHJcblxyXG4gIGFuZCggdmFsdWU6IEJ5dGVTdHJpbmcgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkuY2xvbmUoKS5hbmQoIHZhbHVlLmJ5dGVBcnJheSkgKTtcclxuICB9XHJcblxyXG4gIG9yKCB2YWx1ZTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS5jbG9uZSgpLm9yKCB2YWx1ZS5ieXRlQXJyYXkpICk7XHJcbiAgfVxyXG5cclxuICBwYWQoIG1ldGhvZDogbnVtYmVyLCBvcHRpb25hbD86IGJvb2xlYW4gKVxyXG4gIHtcclxuICAgIHZhciBicyA9IG5ldyBCeXRlQnVmZmVyKCB0aGlzLmJ5dGVBcnJheSApO1xyXG5cclxuICAgIGlmICggb3B0aW9uYWwgPT0gdW5kZWZpbmVkIClcclxuICAgICAgb3B0aW9uYWwgPSBmYWxzZTtcclxuXHJcbiAgICBpZiAoICggKCBicy5sZW5ndGggJiA3ICkgIT0gMCApIHx8ICggIW9wdGlvbmFsICkgKVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV3bGVuID0gKCAoIGJzLmxlbmd0aCArIDggKSAmIH43ICk7XHJcbiAgICAgIGlmICggbWV0aG9kID09IENyeXB0by5JU085Nzk3X01FVEhPRF8xIClcclxuICAgICAgICBicy5hcHBlbmQoIDB4ODAgKTtcclxuXHJcbiAgICAgIHdoaWxlKCBicy5sZW5ndGggPCBuZXdsZW4gKVxyXG4gICAgICAgIGJzLmFwcGVuZCggMHgwMCApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBicy50b0J5dGVTdHJpbmcoKTtcclxuICB9XHJcblxyXG4gIHRvU3RyaW5nKCBlbmNvZGluZz86IG51bWJlciApOiBzdHJpbmdcclxuICB7XHJcbiAgICAvL1RPRE86IGVuY29kaW5nIC4uLlxyXG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5LnRvU3RyaW5nKCBCeXRlQXJyYXkuSEVYICk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY29uc3QgSEVYID0gQnl0ZVN0cmluZy5IRVg7XHJcbi8vZXhwb3J0IGNvbnN0IEFTQ0lJID0gQnl0ZVN0cmluZy5BU0NJSTtcclxuZXhwb3J0IGNvbnN0IEJBU0U2NCA9IEJ5dGVTdHJpbmcuQkFTRTY0O1xyXG4vL2V4cG9ydCBjb25zdCBVVEY4ID0gQnl0ZVN0cmluZy5VVEY4O1xyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5cclxuZXhwb3J0IGNsYXNzIEJ5dGVCdWZmZXJcclxue1xyXG4gIGJ5dGVBcnJheTogQnl0ZUFycmF5O1xyXG5cclxuICBjb25zdHJ1Y3RvciAoIHZhbHVlPzogQnl0ZUFycmF5IHwgQnl0ZVN0cmluZyB8IHN0cmluZywgZW5jb2Rpbmc/IClcclxuICB7XHJcbiAgICBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5jbG9uZSgpO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZVN0cmluZyApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggZW5jb2RpbmcgIT0gdW5kZWZpbmVkIClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgQnl0ZVN0cmluZyggdmFsdWUsIGVuY29kaW5nICkuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggW10gKTtcclxuICB9XHJcblxyXG4gIGdldCBsZW5ndGgoKVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XHJcbiAgfVxyXG5cclxuICB0b0J5dGVTdHJpbmcoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkgKTtcclxuICB9XHJcblxyXG4gIGNsZWFyKClcclxuICB7XHJcbiAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcbiAgfVxyXG5cclxuICBhcHBlbmQoIHZhbHVlOiBCeXRlU3RyaW5nIHwgQnl0ZUJ1ZmZlciB8IG51bWJlciApOiBCeXRlQnVmZmVyXHJcbiAge1xyXG4gICAgbGV0IHZhbHVlQXJyYXk6IEJ5dGVBcnJheTtcclxuXHJcbiAgICBpZiAoICggdmFsdWUgaW5zdGFuY2VvZiBCeXRlU3RyaW5nICkgfHwgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVCdWZmZXIgKSApXHJcbiAgICB7XHJcbiAgICAgIHZhbHVlQXJyYXkgPSB2YWx1ZS5ieXRlQXJyYXk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggdHlwZW9mIHZhbHVlID09IFwibnVtYmVyXCIgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggWyAoIDxudW1iZXI+dmFsdWUgJiAweGZmICkgXSApO1xyXG4gICAgfVxyXG4vKiAgICBlbHNlIGlmICggdHlwZW9mIHZhbHVlID09IFwic3RyaW5nXCIgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIHZhbHVlLmxlbmd0aCApO1xyXG4gICAgICBmb3IoIHZhciBpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgKytpIClcclxuICAgICAgICB2YWx1ZUFycmF5W2ldID0gdmFsdWUuY2hhckF0KCBpICk7XHJcbiAgICB9Ki9cclxuLy8gICAgZWxzZVxyXG4vLyAgICAgIHZhbHVlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCB2YWx1ZSApO1xyXG5cclxuICAgIHRoaXMuYnl0ZUFycmF5LmNvbmNhdCggdmFsdWVBcnJheSApO1xyXG5cclxuICAgIHJldHVybiB0aGlzO1xyXG4gIH1cclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuZXhwb3J0IGNsYXNzIEJhc2VUTFZcbntcbiAgcHVibGljIHN0YXRpYyBFbmNvZGluZ3MgPSB7XG4gICAgRU1WOiAxLFxuICAgIERHSTogMlxuICB9O1xuXG4gIHN0YXRpYyBwYXJzZVRMViggYnVmZmVyOiBCeXRlQXJyYXksIGVuY29kaW5nOiBudW1iZXIgKTogeyB0YWc6IG51bWJlciwgbGVuOiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXksIGxlbk9mZnNldDogbnVtYmVyLCB2YWx1ZU9mZnNldDogbnVtYmVyIH1cbiAge1xuICAgIHZhciByZXMgPSB7IHRhZzogMCwgbGVuOiAwLCB2YWx1ZTogdW5kZWZpbmVkLCBsZW5PZmZzZXQ6IDAsIHZhbHVlT2Zmc2V0OiAwIH07XG4gICAgdmFyIG9mZiA9IDA7XG4gICAgdmFyIGJ5dGVzID0gYnVmZmVyLmJhY2tpbmdBcnJheTsgIC8vIFRPRE86IFVzZSBieXRlQXQoIC4uIClcblxuICAgIHN3aXRjaCggZW5jb2RpbmcgKVxuICAgIHtcbiAgICAgIGNhc2UgQmFzZVRMVi5FbmNvZGluZ3MuRU1WOlxuICAgICAge1xuICAgICAgICB3aGlsZSggKCBvZmYgPCBieXRlcy5sZW5ndGggKSAmJiAoICggYnl0ZXNbIG9mZiBdID09IDB4MDAgKSB8fCAoIGJ5dGVzWyBvZmYgXSA9PSAweEZGICkgKSApXG4gICAgICAgICAgKytvZmY7XG5cbiAgICAgICAgaWYgKCBvZmYgPj0gYnl0ZXMubGVuZ3RoIClcbiAgICAgICAgICByZXR1cm4gcmVzO1xuXG4gICAgICAgIGlmICggKCBieXRlc1sgb2ZmIF0gJiAweDFGICkgPT0gMHgxRiApXG4gICAgICAgIHtcbiAgICAgICAgICByZXMudGFnID0gYnl0ZXNbIG9mZisrIF0gPDwgODtcbiAgICAgICAgICBpZiAoIG9mZiA+PSBieXRlcy5sZW5ndGggKVxuICAgICAgICAgIHsgLypsb2coXCIxXCIpOyovICByZXR1cm4gbnVsbDsgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmVzLnRhZyB8PSBieXRlc1sgb2ZmKysgXTtcblxuICAgICAgICByZXMubGVuT2Zmc2V0ID0gb2ZmO1xuXG4gICAgICAgIGlmICggb2ZmID49IGJ5dGVzLmxlbmd0aCApXG4gICAgICAgIHsgLypsb2coXCIyXCIpOyovICByZXR1cm4gbnVsbDsgfVxuXG4gICAgICAgIHZhciBsbCA9ICggYnl0ZXNbIG9mZiBdICYgMHg4MCApID8gKCBieXRlc1sgb2ZmKysgXSAmIDB4N0YgKSA6IDE7XG4gICAgICAgIHdoaWxlKCBsbC0tID4gMCApXG4gICAgICAgIHtcbiAgICAgICAgICBpZiAoIG9mZiA+PSBieXRlcy5sZW5ndGggKVxuICAgICAgICAgIHsgLypsb2coXCIzOlwiICsgb2ZmICsgXCI6XCIgKyBieXRlcy5sZW5ndGgpOyAgKi9yZXR1cm4gbnVsbDsgfVxuXG4gICAgICAgICAgcmVzLmxlbiA9ICggcmVzLmxlbiA8PCA4ICkgfCBieXRlc1sgb2ZmKysgXTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJlcy52YWx1ZU9mZnNldCA9IG9mZjtcbiAgICAgICAgaWYgKCBvZmYgKyByZXMubGVuID4gYnl0ZXMubGVuZ3RoIClcbiAgICAgIHsgLypsb2coXCI0XCIpOyovICByZXR1cm4gbnVsbDsgfVxuICAgICAgICByZXMudmFsdWUgPSBieXRlcy5zbGljZSggcmVzLnZhbHVlT2Zmc2V0LCByZXMudmFsdWVPZmZzZXQgKyByZXMubGVuICk7XG5cbiAgLy8gICAgICBsb2coIHJlcy52YWx1ZU9mZnNldCArIFwiK1wiICsgcmVzLmxlbiArIFwiPVwiICsgYnl0ZXMgKTtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcztcbiAgfVxuXG4gIHB1YmxpYyBieXRlQXJyYXk6IEJ5dGVBcnJheTtcbiAgZW5jb2Rpbmc6IG51bWJlcjtcblxuICBjb25zdHJ1Y3RvciAoIHRhZzogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5LCBlbmNvZGluZz86IG51bWJlciApXG4gIHtcbiAgICB0aGlzLmVuY29kaW5nID0gZW5jb2RpbmcgfHwgQmFzZVRMVi5FbmNvZGluZ3MuRU1WO1xuXG4gICAgc3dpdGNoKCB0aGlzLmVuY29kaW5nIClcbiAgICB7XG4gICAgICBjYXNlIEJhc2VUTFYuRW5jb2RpbmdzLkVNVjpcbiAgICAgIHtcbiAgICAgICAgdmFyIHRsdkJ1ZmZlciA9IG5ldyBCeXRlQXJyYXkoW10pO1xuXG4gICAgICAgIGlmICggdGFnID49ICAweDEwMCApXG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoICggdGFnID4+IDggKSAmIDB4RkYgKTtcbiAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoIHRhZyAmIDB4RkYgKTtcblxuICAgICAgICB2YXIgbGVuID0gdmFsdWUubGVuZ3RoO1xuICAgICAgICBpZiAoIGxlbiA+IDB4RkYgKVxuICAgICAgICB7XG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoIDB4ODIgKTtcbiAgICAgICAgICB0bHZCdWZmZXIuYWRkQnl0ZSggKCBsZW4gPj4gOCApICYgMHhGRiApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCBsZW4gPiAweDdGIClcbiAgICAgICAgICB0bHZCdWZmZXIuYWRkQnl0ZSggMHg4MSApO1xuXG4gICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCBsZW4gJiAweEZGICk7XG5cbiAgICAgICAgdGx2QnVmZmVyLmNvbmNhdCggdmFsdWUgKTtcblxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IHRsdkJ1ZmZlcjtcblxuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBnZXQgdGFnKCk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIEJhc2VUTFYucGFyc2VUTFYoIHRoaXMuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICkudGFnO1xuICB9XG5cbiAgZ2V0IHZhbHVlKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIEJhc2VUTFYucGFyc2VUTFYoIHRoaXMuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICkudmFsdWU7XG4gIH1cblxuICBnZXQgbGVuKCk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIEJhc2VUTFYucGFyc2VUTFYoIHRoaXMuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICkubGVuO1xuICB9XG59XG5cbkJhc2VUTFYuRW5jb2RpbmdzWyBcIkNUVlwiIF0gPSA0Oy8vIHsgcGFyc2U6IDAsIGJ1aWxkOiAxIH07XG4iLCJpbXBvcnQgeyBCYXNlVExWIGFzIEJhc2VUTFYgfSBmcm9tICcuLi9pc283ODE2L2Jhc2UtdGx2JztcclxuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XHJcblxyXG5leHBvcnQgY2xhc3MgVExWXHJcbntcclxuICB0bHY6IEJhc2VUTFY7XHJcbiAgZW5jb2Rpbmc6IG51bWJlcjtcclxuXHJcbiAgY29uc3RydWN0b3IgKCB0YWc6IG51bWJlciwgdmFsdWU6IEJ5dGVTdHJpbmcsIGVuY29kaW5nOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHRoaXMudGx2ID0gbmV3IEJhc2VUTFYoIHRhZywgdmFsdWUuYnl0ZUFycmF5LCBlbmNvZGluZyApO1xyXG5cclxuICAgIHRoaXMuZW5jb2RpbmcgPSBlbmNvZGluZztcclxuICB9XHJcblxyXG4gIGdldFRMVigpOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkgKTtcclxuICB9XHJcblxyXG4gIGdldFRhZygpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy50bHYudGFnO1xyXG4gIH1cclxuXHJcbiAgZ2V0VmFsdWUoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy50bHYudmFsdWUgKTtcclxuICB9XHJcblxyXG4gIGdldEwoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHZhciBpbmZvID0gQmFzZVRMVi5wYXJzZVRMViggdGhpcy50bHYuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkudmlld0F0KCBpbmZvLmxlbk9mZnNldCwgaW5mby52YWx1ZU9mZnNldCApICk7XHJcbiAgfVxyXG5cclxuICBnZXRMVigpXHJcbiAge1xyXG4gICAgdmFyIGluZm8gPSBCYXNlVExWLnBhcnNlVExWKCB0aGlzLnRsdi5ieXRlQXJyYXksIHRoaXMuZW5jb2RpbmcgKTtcclxuXHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMudGx2LmJ5dGVBcnJheS52aWV3QXQoIGluZm8ubGVuT2Zmc2V0LCBpbmZvLnZhbHVlT2Zmc2V0ICsgaW5mby5sZW4gKSApO1xyXG4gIH1cclxuXHJcbiAgc3RhdGljIHBhcnNlVExWKCBidWZmZXI6IEJ5dGVTdHJpbmcsIGVuY29kaW5nOiBudW1iZXIgKTogeyB0YWc6IG51bWJlciwgbGVuOiBudW1iZXIsIHZhbHVlOiBCeXRlU3RyaW5nLCBsZW5PZmZzZXQ6IG51bWJlciwgdmFsdWVPZmZzZXQ6IG51bWJlciB9XHJcbiAge1xyXG4gICAgbGV0IGluZm8gPSBCYXNlVExWLnBhcnNlVExWKCBidWZmZXIuYnl0ZUFycmF5LCBlbmNvZGluZyApO1xyXG5cclxuICAgIHJldHVybiB7XHJcbiAgICAgIHRhZzogaW5mby50YWcsXHJcbiAgICAgIGxlbjogaW5mby5sZW4sXHJcbiAgICAgIHZhbHVlOiBuZXcgQnl0ZVN0cmluZyggaW5mby52YWx1ZSApLFxyXG4gICAgICBsZW5PZmZzZXQ6IGluZm8ubGVuT2Zmc2V0LFxyXG4gICAgICB2YWx1ZU9mZnNldDogaW5mby52YWx1ZU9mZnNldFxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIHN0YXRpYyBFTVYgPSBCYXNlVExWLkVuY29kaW5ncy5FTVY7XHJcbiAgc3RhdGljIERHSSA9IEJhc2VUTFYuRW5jb2RpbmdzLkRHSTtcclxuLy8gIHN0YXRpYyBMMTYgPSBCYXNlVExWLkwxNjtcclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XHJcbmltcG9ydCB7IFRMViB9IGZyb20gJy4vdGx2JztcclxuXHJcbmV4cG9ydCBjbGFzcyBUTFZMaXN0XHJcbntcclxuICBfdGx2czogVExWW107XHJcblxyXG4gIGNvbnN0cnVjdG9yKCB0bHZTdHJlYW06IEJ5dGVTdHJpbmcsIGVuY29kaW5nPzogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl90bHZzID0gW107XHJcblxyXG4gICAgdmFyIG9mZiA9IDA7XHJcblxyXG4gICAgd2hpbGUoIG9mZiA8IHRsdlN0cmVhbS5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB2YXIgdGx2SW5mbyA9IFRMVi5wYXJzZVRMViggdGx2U3RyZWFtLmJ5dGVzKCBvZmYgKSwgZW5jb2RpbmcgKVxyXG5cclxuICAgICAgaWYgKCB0bHZJbmZvID09IG51bGwgKVxyXG4gICAgICB7XHJcbiAgICAgICAgLy8gZXJyb3IgLi4uXHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgLy8gbm8gbW9yZSAuLi4gP1xyXG4gICAgICAgIGlmICggdGx2SW5mby52YWx1ZU9mZnNldCA9PSAwIClcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICB0aGlzLl90bHZzLnB1c2goIG5ldyBUTFYoIHRsdkluZm8udGFnLCB0bHZJbmZvLnZhbHVlLCBlbmNvZGluZyApICk7XHJcbiAgICAgICAgb2ZmICs9IHRsdkluZm8udmFsdWVPZmZzZXQgKyB0bHZJbmZvLmxlbjtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgaW5kZXgoIGluZGV4OiBudW1iZXIgKTogVExWXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3RsdnNbIGluZGV4IF07XHJcbiAgfVxyXG59XHJcbiIsbnVsbCxudWxsLG51bGwsbnVsbCxudWxsLCJpbXBvcnQgeyAgQnl0ZUFycmF5LCBLaW5kLCBLaW5kQnVpbGRlciwgS2luZEluZm8gfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuLyoqXG4gKiBFbmNvZGVyL0RlY29kb3IgS2luZCBmb3IgYSBBUERVIENvbW1hbmRcbiAqL1xuZXhwb3J0IGNsYXNzIENvbW1hbmRBUERVIGltcGxlbWVudHMgS2luZFxue1xuICBDTEE6IG51bWJlcjsgLy8gPSAwO1xuICBJTlM6IG51bWJlciA9IDA7XG4gIFAxOiBudW1iZXIgPSAwO1xuICBQMjogbnVtYmVyID0gMDtcbiAgZGF0YTogQnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSgpO1xuICBMZTogbnVtYmVyID0gMDtcblxuLy8gIHN0YXRpYyBraW5kSW5mbzogS2luZEluZm87XG5cbiAgLyoqXG4gICAqIEBjb25zdHJ1Y3RvclxuICAgKlxuICAgKiBEZXNlcmlhbGl6ZSBmcm9tIGEgSlNPTiBvYmplY3RcbiAgICovXG4gIGNvbnN0cnVjdG9yKCBhdHRyaWJ1dGVzPzoge30gKVxuICB7XG4gICAgS2luZC5pbml0RmllbGRzKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IExjKCk6bnVtYmVyICAgICAgICAgIHsgcmV0dXJuIHRoaXMuZGF0YS5sZW5ndGg7IH1cbiAgcHVibGljIGdldCBoZWFkZXIoKTogQnl0ZUFycmF5ICB7IHJldHVybiBuZXcgQnl0ZUFycmF5KCBbIHRoaXMuQ0xBLCB0aGlzLklOUywgdGhpcy5QMSwgdGhpcy5QMiBdICk7IH1cblxuICAvKipcbiAgICogRmx1ZW50IEJ1aWxkZXJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgaW5pdCggQ0xBPzogbnVtYmVyLCBJTlM/OiBudW1iZXIsIFAxPzogbnVtYmVyLCBQMj86IG51bWJlciwgZGF0YT86IEJ5dGVBcnJheSwgZXhwZWN0ZWRMZW4/OiBudW1iZXIgKTogQ29tbWFuZEFQRFVcbiAge1xuICAgIHJldHVybiAoIG5ldyBDb21tYW5kQVBEVSgpICkuc2V0KCBDTEEsIElOUywgUDEsIFAyLCBkYXRhLCBleHBlY3RlZExlbiApO1xuICB9XG5cbiAgcHVibGljIHNldCggQ0xBOiBudW1iZXIsIElOUzogbnVtYmVyLCBQMTogbnVtYmVyLCBQMjogbnVtYmVyLCBkYXRhPzogQnl0ZUFycmF5LCBleHBlY3RlZExlbj86IG51bWJlciApOiBDb21tYW5kQVBEVVxuICB7XG4gICAgdGhpcy5DTEEgPSBDTEE7XG4gICAgdGhpcy5JTlMgPSBJTlM7XG4gICAgdGhpcy5QMSA9IFAxO1xuICAgIHRoaXMuUDIgPSBQMjtcbiAgICB0aGlzLmRhdGEgPSBkYXRhIHx8IG5ldyBCeXRlQXJyYXkoKTtcbiAgICB0aGlzLkxlID0gZXhwZWN0ZWRMZW4gfHwgMDtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgcHVibGljIHNldENMQSggQ0xBOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICB7IHRoaXMuQ0xBID0gQ0xBOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0SU5TKCBJTlM6IG51bWJlciApOiBDb21tYW5kQVBEVSAgICAgIHsgdGhpcy5JTlMgPSBJTlM7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXRQMSggUDE6IG51bWJlciApOiBDb21tYW5kQVBEVSAgICAgICAgeyB0aGlzLlAxID0gUDE7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXRQMiggUDI6IG51bWJlciApOiBDb21tYW5kQVBEVSAgICAgICAgeyB0aGlzLlAyID0gUDI7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXREYXRhKCBkYXRhOiBCeXRlQXJyYXkgKTogQ29tbWFuZEFQRFUgeyB0aGlzLmRhdGEgPSBkYXRhOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0TGUoIExlOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICAgIHsgdGhpcy5MZSA9IExlOyByZXR1cm4gdGhpczsgfVxuXG4gIC8qKlxuICAgKiBTZXJpYWxpemF0aW9uLCByZXR1cm5zIGEgSlNPTiBvYmplY3RcbiAgICovXG4gIHB1YmxpYyB0b0pTT04oKToge31cbiAge1xuICAgIHJldHVybiB7XG4gICAgICBDTEE6IHRoaXMuQ0xBLFxuICAgICAgSU5TOiB0aGlzLklOUyxcbiAgICAgIFAxOiB0aGlzLlAxLFxuICAgICAgUDI6IHRoaXMuUDIsXG4gICAgICBkYXRhOiB0aGlzLmRhdGEsXG4gICAgICBMZTogdGhpcy5MZVxuICAgIH07XG4gIH1cblxuICAvKipcbiAgICogRW5jb2RlclxuICAgKi9cbiAgcHVibGljIGVuY29kZUJ5dGVzKCBvcHRpb25zPzoge30gKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgZGxlbiA9ICggKCB0aGlzLkxjID4gMCApID8gMSArIHRoaXMuTGMgOiAwICk7XG4gICAgbGV0IGxlbiA9IDQgKyBkbGVuICsgKCAoIHRoaXMuTGUgPiAwICkgPyAxIDogMCApO1xuICAgIGxldCBiYSA9IG5ldyBCeXRlQXJyYXkoKS5zZXRMZW5ndGgoIGxlbiApO1xuXG4gICAgLy8gcmVidWlsZCBiaW5hcnkgQVBEVUNvbW1hbmRcbiAgICBiYS5zZXRCeXRlc0F0KCAwLCB0aGlzLmhlYWRlciApO1xuICAgIGlmICggdGhpcy5MYyApIHtcbiAgICAgIGJhLnNldEJ5dGVBdCggNCwgdGhpcy5MYyApO1xuICAgICAgYmEuc2V0Qnl0ZXNBdCggNSwgdGhpcy5kYXRhICk7XG4gICAgfVxuXG4gICAgaWYgKCB0aGlzLkxlID4gMCApIHtcbiAgICAgIGJhLnNldEJ5dGVBdCggNCArIGRsZW4sIHRoaXMuTGUgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYmE7XG4gIH1cblxuICAvKipcbiAgKiBEZWNvZGVyXG4gICovXG4gIHB1YmxpYyBkZWNvZGVCeXRlcyggYnl0ZUFycmF5OiBCeXRlQXJyYXksIG9wdGlvbnM/OiB7fSApOiB0aGlzXG4gIHtcbiAgICBpZiAoIGJ5dGVBcnJheS5sZW5ndGggPCA0IClcbiAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbW1hbmRBUERVOiBJbnZhbGlkIGJ1ZmZlcicgKTtcblxuICAgIGxldCBvZmZzZXQgPSAwO1xuXG4gICAgdGhpcy5DTEEgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuICAgIHRoaXMuSU5TID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcbiAgICB0aGlzLlAxID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcbiAgICB0aGlzLlAyID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcblxuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA+IG9mZnNldCArIDEgKVxuICAgIHtcbiAgICAgIHZhciBMYyA9IGJ5dGVBcnJheS5ieXRlQXQoIG9mZnNldCsrICk7XG4gICAgICB0aGlzLmRhdGEgPSBieXRlQXJyYXkuYnl0ZXNBdCggb2Zmc2V0LCBMYyApO1xuICAgICAgb2Zmc2V0ICs9IExjO1xuICAgIH1cblxuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA+IG9mZnNldCApXG4gICAgICB0aGlzLkxlID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcblxuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCAhPSBvZmZzZXQgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tbWFuZEFQRFU6IEludmFsaWQgYnVmZmVyJyApO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbn1cblxuS2luZEJ1aWxkZXIuaW5pdCggQ29tbWFuZEFQRFUsICdJU083ODE2IENvbW1hbmQgQVBEVScgKVxuICAuYnl0ZUZpZWxkKCAnQ0xBJywgJ0NsYXNzJyApXG4gIC5ieXRlRmllbGQoICdJTlMnLCAnSW5zdHJ1Y3Rpb24nIClcbiAgLmJ5dGVGaWVsZCggJ1AxJywgJ1AxIFBhcmFtJyApXG4gIC5ieXRlRmllbGQoICdQMicsICdQMiBQYXJhbScgKVxuICAuaW50ZWdlckZpZWxkKCAnTGMnLCAnQ29tbWFuZCBMZW5ndGgnLCB7IGNhbGN1bGF0ZWQ6IHRydWUgfSApXG4gIC5maWVsZCggJ2RhdGEnLCAnQ29tbWFuZCBEYXRhJywgQnl0ZUFycmF5IClcbiAgLmludGVnZXJGaWVsZCggJ0xlJywgJ0V4cGVjdGVkIExlbmd0aCcgKVxuICA7XG4iLCJleHBvcnQgZW51bSBJU083ODE2XHJcbntcclxuICAvLyBJU08gY2xhc3MgY29kZVxyXG4gIENMQV9JU08gPSAweDAwLFxyXG5cclxuICAvLyBFeHRlcm5hbCBleHRlcm5hbCBhdXRoZW50aWNhdGUgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19FWFRFUk5BTF9BVVRIRU5USUNBVEUgPSAweDgyLFxyXG5cclxuICAvLyBHZXQgY2hhbGxlbmdlIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfR0VUX0NIQUxMRU5HRSA9IDB4ODQsXHJcblxyXG4gIC8vIEludGVybmFsIGF1dGhlbnRpY2F0ZSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0lOVEVSTkFMX0FVVEhFTlRJQ0FURSA9IDB4ODgsXHJcblxyXG4gIC8vIFNlbGVjdCBmaWxlIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfU0VMRUNUX0ZJTEUgPSAweEE0LFxyXG5cclxuICAvLyBSZWFkIHJlY29yZCBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1JFQURfUkVDT1JEID0gMHhCMixcclxuXHJcbiAgLy8gVXBkYXRlIHJlY29yZCBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1VQREFURV9SRUNPUkQgPSAweERDLFxyXG5cclxuICAvLyBWZXJpZnkgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19WRVJJRlkgPSAweDIwLFxyXG5cclxuICAvLyBCbG9jayBBcHBsaWNhdGlvbiBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0JMT0NLX0FQUExJQ0FUSU9OID0gMHgxRSxcclxuXHJcbiAgLy8gVW5ibG9jayBhcHBsaWNhdGlvbiBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1VOQkxPQ0tfQVBQTElDQVRJT04gPSAweDE4LFxyXG5cclxuICAvLyBVbmJsb2NrIGNoYW5nZSBQSU4gaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19VTkJMT0NLX0NIQU5HRV9QSU4gPSAweDI0LFxyXG5cclxuICAvLyBHZXQgZGF0YSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0dFVF9EQVRBID0gMHhDQSxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gVGVtcGxhdGVcclxuICBUQUdfQVBQTElDQVRJT05fVEVNUExBVEUgPSAweDYxLFxyXG5cclxuICAvLyBGQ0kgUHJvcHJpZXRhcnkgVGVtcGxhdGVcclxuICBUQUdfRkNJX1BST1BSSUVUQVJZX1RFTVBMQVRFID0gMHhBNSxcclxuXHJcbiAgLy8gRkNJIFRlbXBsYXRlXHJcbiAgVEFHX0ZDSV9URU1QTEFURSA9IDB4NkYsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIElkZW50aWZpZXIgKEFJRCkgLSBjYXJkXHJcbiAgVEFHX0FJRCA9IDB4NEYsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIExhYmVsXHJcbiAgVEFHX0FQUExJQ0FUSU9OX0xBQkVMID0gMHg1MCxcclxuXHJcbiAgLy8gTGFuZ3VhZ2UgUHJlZmVyZW5jZVxyXG4gIFRBR19MQU5HVUFHRV9QUkVGRVJFTkNFUyA9IDB4NUYyRCxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gRWZmZWN0aXZlIERhdGFcclxuICBUQUdfQVBQTElDQVRJT05fRUZGRUNUSVZFX0RBVEUgPSAweDVGMjUsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIEV4cGlyYXRpb24gRGF0ZVxyXG4gIFRBR19BUFBMSUNBVElPTl9FWFBJUllfREFURSA9IDB4NUYyNCxcclxuXHJcbiAgLy8gQ2FyZCBIb2xkZXIgTmFtZVxyXG4gIFRBR19DQVJESE9MREVSX05BTUUgPSAweDVGMjAsXHJcblxyXG4gIC8vIElzc3VlciBDb3VudHJ5IENvZGVcclxuICBUQUdfSVNTVUVSX0NPVU5UUllfQ09ERSA9IDB4NUYyOCxcclxuXHJcbiAgLy8gSXNzdWVyIFVSTFxyXG4gIFRBR19JU1NVRVJfVVJMID0gMHg1RjUwLFxyXG5cclxuICAvLyBBcHBsaWNhdGlvbiBQcmltYXJ5IEFjY291bnQgTnVtYmVyIChQQU4pXHJcbiAgVEFHX1BBTiA9IDB4NWEsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIFByaW1hcnkgQWNjb3VudCBOdW1iZXIgKFBBTikgU2VxdWVuY2UgTnVtYmVyXHJcbiAgVEFHX1BBTl9TRVFVRU5DRV9OVU1CRVIgPSAweDVGMzQsXHJcblxyXG4gIC8vIFNlcnZpY2UgQ29kZVxyXG4gIFRBR19TRVJWSUNFX0NPREUgPSAweDVGMzAsXHJcblxyXG4gIElTT19QSU5CTE9DS19TSVpFID0gOCwgICAvLzwgU2l6ZSBvZiBhbiBJU08gUElOIGJsb2NrXHJcblxyXG4gIEFQRFVfTEVOX0xFX01BWCA9IDI1NiwgICAvLzwgTWF4aW11bSBzaXplIGZvciBMZVxyXG5cclxuICBTV19TVUNDRVNTID0gMHg5MDAwLFxyXG4gIC8vICBTV19CWVRFU19SRU1BSU5JTkcoU1cyKSA9IDB4NjEjI1NXMixcclxuICBTV19XQVJOSU5HX05WX01FTU9SWV9VTkNIQU5HRUQgPSAweDYyMDAgLFxyXG4gIFNXX1BBUlRfT0ZfUkVUVVJOX0RBVEFfQ09SUlVQVEVEID0gMHg2MjgxLFxyXG4gIFNXX0VORF9GSUxFX1JFQUNIRURfQkVGT1JFX0xFX0JZVEUgPSAweDYyODIsXHJcbiAgU1dfU0VMRUNURURfRklMRV9JTlZBTElEID0gMHg2MjgzLFxyXG4gIFNXX0ZDSV9OT1RfRk9STUFUVEVEX1RPX0lTTyA9IDB4NjI4NCxcclxuICBTV19XQVJOSU5HX05WX01FTU9SWV9DSEFOR0VEID0gMHg2MzAwLFxyXG4gIFNXX0ZJTEVfRklMTEVEX0JZX0xBU1RfV1JJVEUgPSAweDYzODEsXHJcbiAgLy8gIFNXX0NPVU5URVJfUFJPVklERURfQllfWChYKSA9IDB4NjNDIyNYLFxyXG4gIC8vICBTV19FUlJPUl9OVl9NRU1PUllfVU5DSEFOR0VEKFNXMikgPSAweDY0IyNTVzIsXHJcbiAgLy8gIFNXX0VSUk9SX05WX01FTU9SWV9DSEFOR0VEKFNXMikgPSAweDY1IyNTVzIgLFxyXG4gIC8vICBTV19SRVNFUlZFRChTVzIpID0gMHg2NiMjU1cyLFxyXG4gIFNXX1dST05HX0xFTkdUSCA9IDB4NjcwMCAsXHJcbiAgU1dfRlVOQ1RJT05TX0lOX0NMQV9OT1RfU1VQUE9SVEVEID0gMHg2ODAwLFxyXG4gIFNXX0xPR0lDQUxfQ0hBTk5FTF9OT1RfU1VQUE9SVEVEID0gMHg2ODgxLFxyXG4gIFNXX1NFQ1VSRV9NRVNTQUdJTkdfTk9UX1NVUFBPUlRFRCA9IDB4Njg4MixcclxuICBTV19DT01NQU5EX05PVF9BTExPV0VEID0gMHg2OTAwLFxyXG4gIFNXX0NPTU1BTkRfSU5DT01QQVRJQkxFX1dJVEhfRklMRV9TVFJVQ1RVUkUgPSAweDY5ODEsXHJcbiAgU1dfU0VDVVJJVFlfU1RBVFVTX05PVF9TQVRJU0ZJRUQgPSAweDY5ODIsXHJcbiAgU1dfRklMRV9JTlZBTElEID0gMHg2OTgzLFxyXG4gIFNXX0RBVEFfSU5WQUxJRCA9IDB4Njk4NCxcclxuICBTV19DT05ESVRJT05TX05PVF9TQVRJU0ZJRUQgPSAweDY5ODUsXHJcbiAgU1dfQ09NTUFORF9OT1RfQUxMT1dFRF9BR0FJTiA9IDB4Njk4NixcclxuICBTV19FWFBFQ1RFRF9TTV9EQVRBX09CSkVDVFNfTUlTU0lORyA9IDB4Njk4NyAsXHJcbiAgU1dfU01fREFUQV9PQkpFQ1RTX0lOQ09SUkVDVCA9IDB4Njk4OCxcclxuICBTV19XUk9OR19QQVJBTVMgPSAweDZBMDAgICAsXHJcbiAgU1dfV1JPTkdfREFUQSA9IDB4NkE4MCxcclxuICBTV19GVU5DX05PVF9TVVBQT1JURUQgPSAweDZBODEsXHJcbiAgU1dfRklMRV9OT1RfRk9VTkQgPSAweDZBODIsXHJcbiAgU1dfUkVDT1JEX05PVF9GT1VORCA9IDB4NkE4MyxcclxuICBTV19OT1RfRU5PVUdIX1NQQUNFX0lOX0ZJTEUgPSAweDZBODQsXHJcbiAgU1dfTENfSU5DT05TSVNURU5UX1dJVEhfVExWID0gMHg2QTg1LFxyXG4gIFNXX0lOQ09SUkVDVF9QMVAyID0gMHg2QTg2LFxyXG4gIFNXX0xDX0lOQ09OU0lTVEVOVF9XSVRIX1AxUDIgPSAweDZBODcsXHJcbiAgU1dfUkVGRVJFTkNFRF9EQVRBX05PVF9GT1VORCA9IDB4NkE4OCxcclxuICBTV19XUk9OR19QMVAyID0gMHg2QjAwLFxyXG4gIC8vU1dfQ09SUkVDVF9MRU5HVEgoU1cyKSA9IDB4NkMjI1NXMixcclxuICBTV19JTlNfTk9UX1NVUFBPUlRFRCA9IDB4NkQwMCxcclxuICBTV19DTEFfTk9UX1NVUFBPUlRFRCA9IDB4NkUwMCxcclxuICBTV19VTktOT1dOID0gMHg2RjAwLFxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSwgS2luZCwgS2luZEluZm8sIEtpbmRCdWlsZGVyIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5pbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi9pc283ODE2JztcblxuLyoqXG4gKiBFbmNvZGVyL0RlY29kb3IgZm9yIGEgQVBEVSBSZXNwb25zZVxuICovXG5leHBvcnQgY2xhc3MgUmVzcG9uc2VBUERVIGltcGxlbWVudHMgS2luZFxue1xuICBTVzogbnVtYmVyID0gSVNPNzgxNi5TV19TVUNDRVNTO1xuICBkYXRhOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XG5cbi8vICBzdGF0aWMga2luZEluZm86IEtpbmRJbmZvO1xuXG4gIC8qKlxuICAgKiBAY29uc3RydWN0b3JcbiAgICpcbiAgICogRGVzZXJpYWxpemUgZnJvbSBhIEpTT04gb2JqZWN0XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYXR0cmlidXRlcz86IHt9IClcbiAge1xuICAgIEtpbmQuaW5pdEZpZWxkcyggdGhpcywgYXR0cmlidXRlcyApO1xuICB9XG5cbiAgcHVibGljIGdldCBMYSgpIHsgcmV0dXJuIHRoaXMuZGF0YS5sZW5ndGg7IH1cblxuICBwdWJsaWMgc3RhdGljIGluaXQoIHN3OiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXkgKTogUmVzcG9uc2VBUERVXG4gIHtcbiAgICByZXR1cm4gKCBuZXcgUmVzcG9uc2VBUERVKCkgKS5zZXQoIHN3LCBkYXRhICk7XG4gIH1cblxuICBwdWJsaWMgc2V0KCBzdzogbnVtYmVyLCBkYXRhPzogQnl0ZUFycmF5ICk6IFJlc3BvbnNlQVBEVVxuICB7XG4gICAgdGhpcy5TVyA9IHN3O1xuICAgIHRoaXMuZGF0YSA9IGRhdGEgfHwgbmV3IEJ5dGVBcnJheSgpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgc2V0U1coIFNXOiBudW1iZXIgKTogUmVzcG9uc2VBUERVICAgICAgICB7IHRoaXMuU1cgPSBTVzsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldFNXMSggU1cxOiBudW1iZXIgKTogUmVzcG9uc2VBUERVICAgICAgeyB0aGlzLlNXID0gKCB0aGlzLlNXICYgMHhGRiApIHwgKCBTVzEgPDwgOCApOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0U1cyKCBTVzI6IG51bWJlciApOiBSZXNwb25zZUFQRFUgICAgICB7IHRoaXMuU1cgPSAoIHRoaXMuU1cgJiAweEZGMDAgKSB8IFNXMjsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldERhdGEoIGRhdGE6IEJ5dGVBcnJheSApOiBSZXNwb25zZUFQRFUgeyB0aGlzLmRhdGEgPSBkYXRhOyByZXR1cm4gdGhpczsgfVxuXG4gIC8qKlxuICAgKiBFbmNvZGVyIGZ1bmN0aW9uLCByZXR1cm5zIGEgYmxvYiBmcm9tIGFuIEFQRFVSZXNwb25zZSBvYmplY3RcbiAgICovXG4gIHB1YmxpYyBlbmNvZGVCeXRlcyggb3B0aW9ucz86IHt9ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gbmV3IEJ5dGVBcnJheSgpLnNldExlbmd0aCggdGhpcy5MYSArIDIgKTtcblxuICAgIGJhLnNldEJ5dGVzQXQoIDAsIHRoaXMuZGF0YSApO1xuICAgIGJhLnNldEJ5dGVBdCggdGhpcy5MYSAgICAsICggdGhpcy5TVyA+PiA4ICkgJiAweGZmICk7XG4gICAgYmEuc2V0Qnl0ZUF0KCB0aGlzLkxhICsgMSwgKCB0aGlzLlNXID4+IDAgKSAmIDB4ZmYgKTtcblxuICAgIHJldHVybiBiYTtcbiAgfVxuXG4gIHB1YmxpYyBkZWNvZGVCeXRlcyggYnl0ZUFycmF5OiBCeXRlQXJyYXksIG9wdGlvbnM/OiB7fSApOiB0aGlzXG4gIHtcbiAgICBpZiAoIGJ5dGVBcnJheS5sZW5ndGggPCAyIClcbiAgICAgIHRocm93IG5ldyBFcnJvciggJ1Jlc3BvbnNlQVBEVSBCdWZmZXIgaW52YWxpZCcgKTtcblxuICAgIGxldCBsYSA9IGJ5dGVBcnJheS5sZW5ndGggLSAyO1xuXG4gICAgdGhpcy5TVyA9IGJ5dGVBcnJheS53b3JkQXQoIGxhICk7XG4gICAgdGhpcy5kYXRhID0gKCBsYSApID8gYnl0ZUFycmF5LmJ5dGVzQXQoIDAsIGxhICkgOiBuZXcgQnl0ZUFycmF5KCk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG5LaW5kQnVpbGRlci5pbml0KCBSZXNwb25zZUFQRFUsICdJU083ODE2IFJlc3BvbnNlIEFQRFUnIClcbiAgLmludGVnZXJGaWVsZCggJ1NXJywgJ1N0YXR1cyBXb3JkJywgeyBtYXhpbXVtOiAweEZGRkYgfSApXG4gIC5pbnRlZ2VyRmllbGQoICdMYScsICdBY3R1YWwgTGVuZ3RoJywgIHsgY2FsY3VsYXRlZDogdHJ1ZSB9IClcbiAgLmZpZWxkKCAnRGF0YScsICdSZXNwb25zZSBEYXRhJywgQnl0ZUFycmF5IClcbiAgO1xuIixudWxsLCJpbXBvcnQgeyBCeXRlQXJyYXksIEVuZFBvaW50LCBNZXNzYWdlLCBNZXNzYWdlSGVhZGVyLCBEaXJlY3Rpb24sIENoYW5uZWwsIFByb3RvY29sIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmltcG9ydCB7IFNsb3QgfSBmcm9tICcuLi9pc283ODE2L3Nsb3QnO1xuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9pc283ODE2L2NvbW1hbmQtYXBkdSc7XG5pbXBvcnQgeyBSZXNwb25zZUFQRFUgfSBmcm9tICcuLi9pc283ODE2L3Jlc3BvbnNlLWFwZHUnO1xuXG5leHBvcnQgY2xhc3MgU2xvdFByb3RvY29sIGltcGxlbWVudHMgUHJvdG9jb2w8U2xvdD4ge1xuICBzdGF0aWMgZ2V0SGFuZGxlcigpOiBTbG90UHJvdG9jb2xIYW5kbGVyIHtcbiAgICByZXR1cm4gbmV3IFNsb3RQcm90b2NvbEhhbmRsZXIoKTtcbiAgfVxuXG4gIHN0YXRpYyBnZXRQcm94eSggZW5kUG9pbnQ6IEVuZFBvaW50ICk6IFNsb3RQcm90b2NvbFByb3h5IHtcbiAgICByZXR1cm4gbmV3IFNsb3RQcm90b2NvbFByb3h5KCBlbmRQb2ludCApO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTbG90UHJvdG9jb2xQcm94eSBpbXBsZW1lbnRzIFNsb3Qge1xuICBlbmRQb2ludDogRW5kUG9pbnQ7XG4gIHBlbmRpbmc6IGFueTtcblxuICBwcml2YXRlIHBvd2VyQ29tbWFuZCggbWV0aG9kOiBzdHJpbmcgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBtZS5wZW5kaW5nID0ge1xuICAgICAgICBtZXRob2Q6IG1ldGhvZCxcbiAgICAgICAgcmVzb2x2ZTogcmVzb2x2ZSxcbiAgICAgICAgcmVqZWN0OiByZWplY3RcbiAgICAgIH07XG5cbiAgICAgIG1lLmVuZFBvaW50LnNlbmRNZXNzYWdlKCBuZXcgTWVzc2FnZTx2b2lkPiggeyBtZXRob2Q6IG1ldGhvZCB9LCBudWxsICkgKTtcbiAgICB9KTtcbiAgfVxuXG4gIGNvbnN0cnVjdG9yKCBlbmRQb2ludDogRW5kUG9pbnQgKSB7XG4gICAgdGhpcy5lbmRQb2ludCA9IGVuZFBvaW50O1xuXG4gICAgLy8gTmFzdHkgcGx1bWJpbmcgLi4gZWFjaCBwcm94eS1jb21tYW5kIHdpbGwgc2V0IHBlbmRpbmcgdG8gY29udGFpbmVyXG4gICAgLy8gICAtIG1ldGhvZCBjYWxsZWQgKHBvd2VyT24sIHBvd2VyT2ZmLCByZXNldCwgZXhlY3V0ZUFQRFUgKVxuICAgIC8vICAgLSByZXNvbHZlIGNhbGxiYWNrIChmcm9tIHByb21pc2UpIC0gcmVjZWl2ZXMgdGhlIHBheWxvYWRcbiAgICAvLyAgIC0gcmVqZWN0IGNhbGxiYWNrIChmcm9tIHByb21pc2UpXG4gICAgLy8gV2hlbiB0aGUgZW5kLXBvaW50IHJlY2VpdmVzIGEgbWVzc2FnZSAocmVzcG9uc2UpLCBjaGVjayBtZXRob2RcbiAgICAvLyBhbmQgaWYgaXQgbWF0Y2hlcyB0aGUgcGVuZGluZy1vcCwgcmVzb2x2ZSB0aGUgcHJvbWlzZVxuICAgIC8vIG90aGVyd2lzZSByZWplY3QgaXRcbiAgICBsZXQgbWUgPSB0aGlzO1xuICAgIGVuZFBvaW50Lm9uTWVzc2FnZSggKCBtc2cgKSA9PiB7XG4gICAgICBsZXQgcGVuZGluZ09wID0gbWUucGVuZGluZztcblxuICAgICAgaWYgKCBwZW5kaW5nT3AgKSB7XG4gICAgICAgIGlmICggbXNnLmhlYWRlci5pc1Jlc3BvbnNlICYmICggbXNnLmhlYWRlci5tZXRob2QgPT0gcGVuZGluZ09wLm1ldGhvZCApICkge1xuICAgICAgICAgIHBlbmRpbmdPcC5yZXNvbHZlKCBtc2cucGF5bG9hZCApO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICBwZW5kaW5nT3AucmVqZWN0KCBtc2cucGF5bG9hZCApO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIHRoaXMucG93ZXJDb21tYW5kKCAncG93ZXJPbicgKTtcbiAgfVxuICByZXNldCgpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiB0aGlzLnBvd2VyQ29tbWFuZCggJ3Jlc2V0JyApO1xuICB9XG4gIHBvd2VyT2ZmKCk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIHRoaXMucG93ZXJDb21tYW5kKCAncG93ZXJPZmYnICk7XG4gIH1cbiAgZ2V0IGlzUHJlc2VudCgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgZ2V0IGlzUG93ZXJlZCgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBleGVjdXRlQVBEVSggY21kOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT4ge1xuICAgIGxldCBtZSA9IHRoaXM7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPFJlc3BvbnNlQVBEVT4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIG1lLnBlbmRpbmcgPSB7XG4gICAgICAgIG1ldGhvZDogJ2V4ZWN1dGVBUERVJyxcbiAgICAgICAgcmVzb2x2ZTogcmVzb2x2ZSxcbiAgICAgICAgcmVqZWN0OiByZWplY3RcbiAgICAgIH07XG5cbiAgICAgIG1lLmVuZFBvaW50LnNlbmRNZXNzYWdlKCBuZXcgTWVzc2FnZTxDb21tYW5kQVBEVT4oIHsgbWV0aG9kOiAnZXhlY3V0ZUFQRFUnIH0sIGNtZCApICk7XG4gICAgfSk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFNsb3RQcm90b2NvbEhhbmRsZXIge1xuXG4gIGVuZFBvaW50OiBFbmRQb2ludDtcbiAgc2xvdDogU2xvdDtcblxuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgfVxuXG4gIGxpbmtTbG90KCBzbG90OiBTbG90LCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMuZW5kUG9pbnQgPSBlbmRQb2ludDtcbiAgICB0aGlzLnNsb3QgPSBzbG90O1xuXG4gICAgZW5kUG9pbnQub25NZXNzYWdlKCAoIG1zZywgZXAgKSA9PiB7XG4gICAgICBtZS5vbk1lc3NhZ2UoIG1zZyxlcCApO1xuICAgIH0gKTtcbiAgfVxuXG4gIHVubGlua1Nsb3QoKVxuICB7XG4gICAgdGhpcy5lbmRQb2ludC5vbk1lc3NhZ2UoIG51bGwgKTtcbiAgICB0aGlzLmVuZFBvaW50ID0gbnVsbDtcbiAgICB0aGlzLnNsb3QgPSBudWxsO1xuICB9XG5cbiAgb25NZXNzYWdlKCBwYWNrZXQ6IE1lc3NhZ2U8YW55PiwgcmVjZWl2aW5nRW5kUG9pbnQ6IEVuZFBvaW50IClcbiAge1xuICAgIGxldCBoZHI6IGFueSA9IHBhY2tldC5oZWFkZXI7XG4gICAgbGV0IHBheWxvYWQgPSBwYWNrZXQucGF5bG9hZDtcblxuICAgIGxldCByZXNwb25zZTogUHJvbWlzZTxhbnk+O1xuICAgIGxldCByZXBseUhlYWRlciA9IHsgbWV0aG9kOiBoZHIubWV0aG9kLCBpc1Jlc3BvbnNlOiB0cnVlIH07XG5cbiAgICBzd2l0Y2goIGhkci5tZXRob2QgKVxuICAgIHtcbiAgICAgIGNhc2UgXCJleGVjdXRlQVBEVVwiOlxuICAgICAgICBpZiAoICEoIHBheWxvYWQgaW5zdGFuY2VvZiBDb21tYW5kQVBEVSApIClcbiAgICAgICAgICBicmVhaztcblxuICAgICAgICByZXNwb25zZSA9IHRoaXMuc2xvdC5leGVjdXRlQVBEVSggPENvbW1hbmRBUERVPnBheWxvYWQgKTtcblxuICAgICAgICByZXNwb25zZS50aGVuKCAoIHJlc3BvbnNlQVBEVTogUmVzcG9uc2VBUERVICkgPT4ge1xuICAgICAgICAgIGxldCByZXBseVBhY2tldCA9IG5ldyBNZXNzYWdlPFJlc3BvbnNlQVBEVT4oIHJlcGx5SGVhZGVyLCByZXNwb25zZUFQRFUgKTtcblxuICAgICAgICAgIHJlY2VpdmluZ0VuZFBvaW50LnNlbmRNZXNzYWdlKCByZXBseVBhY2tldCApO1xuICAgICAgICB9KTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgXCJwb3dlck9mZlwiOlxuICAgICAgICByZXNwb25zZSA9IHRoaXMuc2xvdC5wb3dlck9mZigpXG4gICAgICAgICAgLnRoZW4oICggcmVzcERhdGE6IEJ5dGVBcnJheSApPT4ge1xuICAgICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIG5ldyBNZXNzYWdlPEJ5dGVBcnJheT4oIHJlcGx5SGVhZGVyLCBuZXcgQnl0ZUFycmF5KCkgKSApO1xuICAgICAgICAgIH0pO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBcInBvd2VyT25cIjpcbiAgICAgICAgcmVzcG9uc2UgPSB0aGlzLnNsb3QucG93ZXJPbigpXG4gICAgICAgICAgLnRoZW4oICggcmVzcERhdGE6IEJ5dGVBcnJheSApPT4ge1xuICAgICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIG5ldyBNZXNzYWdlPEJ5dGVBcnJheT4oIHJlcGx5SGVhZGVyLCByZXNwRGF0YSApICk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFwicmVzZXRcIjpcbiAgICAgICAgcmVzcG9uc2UgPSB0aGlzLnNsb3QucmVzZXQoKVxuICAgICAgICAgIC50aGVuKCAoIHJlc3BEYXRhOiBCeXRlQXJyYXkgKT0+IHtcbiAgICAgICAgICAgIHJlY2VpdmluZ0VuZFBvaW50LnNlbmRNZXNzYWdlKCBuZXcgTWVzc2FnZTxCeXRlQXJyYXk+KCByZXBseUhlYWRlciwgcmVzcERhdGEgKSApO1xuICAgICAgICAgIH0pO1xuICAgICAgICBicmVhaztcblxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmVzcG9uc2UgPSBQcm9taXNlLnJlamVjdDxFcnJvcj4oIG5ldyBFcnJvciggXCJJbnZhbGlkIG1ldGhvZFwiICsgaGRyLm1ldGhvZCApICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH0gLy8gc3dpdGNoXG5cbiAgICAvLyB0cmFwIGFuZCByZXR1cm4gYW55IGVycm9yc1xuICAgIHJlc3BvbnNlLmNhdGNoKCAoIGU6IGFueSApID0+IHtcbiAgICAgIGxldCBlcnJvclBhY2tldCA9IG5ldyBNZXNzYWdlPEVycm9yPiggeyBtZXRob2Q6IFwiZXJyb3JcIiB9LCBlICk7XG5cbiAgICAgIHJlY2VpdmluZ0VuZFBvaW50LnNlbmRNZXNzYWdlKCBlcnJvclBhY2tldCApO1xuICAgIH0pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbmNsYXNzIEpTU2ltdWxhdGVkU2xvdFxyXG57XHJcbiAgY2FyZFdvcmtlcjtcclxuICBvbkFQRFVSZXNwb25zZTtcclxuICBzdG9wO1xyXG5cclxuICBPbk1lc3NhZ2UoZSlcclxuICB7XHJcbiAgICBpZiAodGhpcy5zdG9wKSByZXR1cm47XHJcblxyXG4gICAgaWYgKGUuZGF0YS5jb21tYW5kID09IFwiZGVidWdcIilcclxuICAgIHtcclxuICAgICAgY29uc29sZS5sb2coZS5kYXRhLmRhdGEpO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoZS5kYXRhLmNvbW1hbmQgPT0gXCJleGVjdXRlQVBEVVwiKVxyXG4gICAge1xyXG4gICAgICAvLyBjb25zb2xlLmxvZyggbmV3IEJ5dGVTdHJpbmcoIGUuZGF0YS5kYXRhICkudG9TdHJpbmcoKSApO1xyXG5cclxuICAgICAgaWYgKCB0aGlzLm9uQVBEVVJlc3BvbnNlIClcclxuICAgICAge1xyXG4gICAgICAgIHZhciBicyA9IDxVaW50OEFycmF5PmUuZGF0YS5kYXRhLCBsZW4gPSBicy5sZW5ndGg7XHJcblxyXG4gICAgICAgIHRoaXMub25BUERVUmVzcG9uc2UoICggYnNbIGxlbiAtIDIgXSA8PCA4ICkgfCBic1sgbGVuIC0gMSBdLCAoIGxlbiA+IDIgKSA/IG5ldyBCeXRlQXJyYXkoIGJzLnN1YmFycmF5KCAwLCBsZW4tMiApICkgOiBudWxsICk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIGVsc2VcclxuICAgIHtcclxuICAgICAgY29uc29sZS5sb2coIFwiY21kOiBcIiArIGUuZGF0YS5jb21tYW5kICsgXCIgZGF0YTogXCIgKyBlLmRhdGEuZGF0YSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgaW5pdCgpXHJcbiAge1xyXG4gICAgdGhpcy5jYXJkV29ya2VyID0gbmV3IFdvcmtlciggXCJqcy9TbWFydENhcmRTbG90U2ltdWxhdG9yL1NtYXJ0Q2FyZFNsb3RXb3JrZXIuanNcIiApO1xyXG4gICAgdGhpcy5jYXJkV29ya2VyLm9ubWVzc2FnZSA9IHRoaXMuT25NZXNzYWdlLmJpbmQoIHRoaXMgKTtcclxuXHJcbiAgICB0aGlzLmNhcmRXb3JrZXIub25lcnJvciA9IGZ1bmN0aW9uKGU6IEV2ZW50KVxyXG4gICAge1xyXG4gICAgICAvL2FsZXJ0KCBcIkVycm9yIGF0IFwiICsgZS5maWxlbmFtZSArIFwiOlwiICsgZS5saW5lbm8gKyBcIjogXCIgKyBlLm1lc3NhZ2UgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHNlbmRUb1dvcmtlciggY29tbWFuZCwgZGF0YSApXHJcbiAge1xyXG4gICAgdGhpcy5jYXJkV29ya2VyLnBvc3RNZXNzYWdlKFxyXG4gICAgICB7XHJcbiAgICAgICAgXCJjb21tYW5kXCI6IGNvbW1hbmQsXHJcbiAgICAgICAgXCJkYXRhXCI6IGRhdGFcclxuICAgICAgfVxyXG4gICAgKTtcclxuICB9XHJcblxyXG4gIGV4ZWN1dGVBUERVQ29tbWFuZCggYkNMQSwgYklOUywgYlAxLCBiUDIsIGNvbW1hbmREYXRhLCB3TGUsIG9uQVBEVVJlc3BvbnNlIClcclxuICB7XHJcbiAgICB2YXIgY21kID0gWyBiQ0xBLCBiSU5TLCBiUDEsIGJQMiBdO1xyXG4gICAgdmFyIGxlbiA9IDQ7XHJcbiAgICB2YXIgYnNDb21tYW5kRGF0YSA9ICggY29tbWFuZERhdGEgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKSA/IGNvbW1hbmREYXRhIDogbmV3IEJ5dGVBcnJheSggY29tbWFuZERhdGEsIEJ5dGVBcnJheS5IRVggKTtcclxuICAgIGlmICggYnNDb21tYW5kRGF0YS5sZW5ndGggPiAwIClcclxuICAgIHtcclxuICAgICAgY21kW2xlbisrXSA9IGJzQ29tbWFuZERhdGEubGVuZ3RoO1xyXG4gICAgICBmb3IoIHZhciBpID0gMDsgaSA8IGJzQ29tbWFuZERhdGEubGVuZ3RoOyArK2kgKVxyXG4gICAgICAgIGNtZFtsZW4rK10gPSBic0NvbW1hbmREYXRhLmJ5dGVBdCggaSApO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHdMZSAhPSB1bmRlZmluZWQgKVxyXG4gICAgICAgIGNtZFtsZW4rK10gPSB3TGUgJiAweEZGO1xyXG5cclxuICAgIHRoaXMuc2VuZFRvV29ya2VyKCBcImV4ZWN1dGVBUERVXCIsIGNtZCApO1xyXG5cclxuICAgIHRoaXMub25BUERVUmVzcG9uc2UgPSBvbkFQRFVSZXNwb25zZTtcclxuXHJcbiAgICAvLyBvbiBzdWNjZXNzL2ZhaWx1cmUsIHdpbGwgY2FsbGJhY2tcclxuICAgIC8vIGlmICggcmVzcCA9PSBudWxsIClcclxuICAgIHJldHVybjtcclxuICB9XHJcbn1cclxuIixudWxsLCJpbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi4vaXNvNzgxNi9JU083ODE2JztcclxuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9pc283ODE2L2NvbW1hbmQtYXBkdSc7XHJcbmltcG9ydCB7IFJlc3BvbnNlQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvcmVzcG9uc2UtYXBkdSc7XHJcblxyXG5leHBvcnQgY2xhc3MgSlNJTVNjcmlwdEFwcGxldFxyXG57XHJcbiAgc2VsZWN0QXBwbGljYXRpb24oIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cclxuICB7XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4OTAwMCB9ICkgKTtcclxuICB9XHJcblxyXG4gIGRlc2VsZWN0QXBwbGljYXRpb24oKVxyXG4gIHtcclxuICB9XHJcblxyXG4gIGV4ZWN1dGVBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XHJcbiAge1xyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxSZXNwb25zZUFQRFU+KCBuZXcgUmVzcG9uc2VBUERVKCB7IHN3OiAweDZEMDAgfSApICk7XHJcbiAgfVxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi4vaXNvNzgxNi9JU083ODE2JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9yZXNwb25zZS1hcGR1JztcblxuaW1wb3J0IHsgSlNJTUNhcmQgfSBmcm9tICcuL2pzaW0tY2FyZCc7XG5pbXBvcnQgeyBKU0lNU2NyaXB0QXBwbGV0IH0gZnJvbSAnLi9qc2ltLXNjcmlwdC1hcHBsZXQnO1xuXG5leHBvcnQgY2xhc3MgSlNJTVNjcmlwdENhcmQgaW1wbGVtZW50cyBKU0lNQ2FyZFxue1xuICBwcml2YXRlIF9wb3dlcklzT246IGJvb2xlYW47XG4gIHByaXZhdGUgX2F0cjogQnl0ZUFycmF5O1xuXG4gIGFwcGxldHM6IHsgYWlkOiBCeXRlQXJyYXksIGFwcGxldDogSlNJTVNjcmlwdEFwcGxldCB9W10gPSBbXTtcblxuICBzZWxlY3RlZEFwcGxldDogSlNJTVNjcmlwdEFwcGxldDtcblxuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgICB0aGlzLl9hdHIgPSBuZXcgQnl0ZUFycmF5KCBbXSApO1xuICB9XG5cbiAgbG9hZEFwcGxpY2F0aW9uKCBhaWQ6IEJ5dGVBcnJheSwgYXBwbGV0OiBKU0lNU2NyaXB0QXBwbGV0IClcbiAge1xuICAgIHRoaXMuYXBwbGV0cy5wdXNoKCB7IGFpZDogYWlkLCBhcHBsZXQ6IGFwcGxldCB9ICk7XG4gIH1cblxuICBnZXQgaXNQb3dlcmVkKCk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3dlcklzT247XG4gIH1cblxuICBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgdGhpcy5fcG93ZXJJc09uID0gdHJ1ZTtcblxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmU8Qnl0ZUFycmF5PiggdGhpcy5fYXRyICk7XG4gIH1cblxuICBwb3dlck9mZigpOiBQcm9taXNlPGFueT5cbiAge1xuICAgIHRoaXMuX3Bvd2VySXNPbiA9IGZhbHNlO1xuXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcblxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgfVxuXG4gIHJlc2V0KCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgdGhpcy5fcG93ZXJJc09uID0gdHJ1ZTtcblxuICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XG5cbiAgICAvLyBUT0RPOiBSZXNldFxuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxCeXRlQXJyYXk+KCB0aGlzLl9hdHIgKTtcbiAgfVxuXG4gIGV4Y2hhbmdlQVBEVSggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVICk6IFByb21pc2U8UmVzcG9uc2VBUERVPlxuICB7XG4gICAgaWYgKCBjb21tYW5kQVBEVS5JTlMgPT0gMHhBNCApXG4gICAge1xuICAgICAgaWYgKCB0aGlzLnNlbGVjdGVkQXBwbGV0IClcbiAgICAgIHtcbiAgICAgICAgdGhpcy5zZWxlY3RlZEFwcGxldC5kZXNlbGVjdEFwcGxpY2F0aW9uKCk7XG5cbiAgICAgICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcbiAgICAgIH1cblxuICAgICAgLy9UT0RPOiBMb29rdXAgQXBwbGljYXRpb25cbiAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB0aGlzLmFwcGxldHNbIDAgXS5hcHBsZXQ7XG5cbiAgICAgIHJldHVybiB0aGlzLnNlbGVjdGVkQXBwbGV0LnNlbGVjdEFwcGxpY2F0aW9uKCBjb21tYW5kQVBEVSApO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnNlbGVjdGVkQXBwbGV0LmV4ZWN1dGVBUERVKCBjb21tYW5kQVBEVSApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuaW1wb3J0IHsgU2xvdCB9IGZyb20gJy4uL2lzbzc4MTYvc2xvdCc7XG5pbXBvcnQgeyBDb21tYW5kQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvY29tbWFuZC1hcGR1JztcbmltcG9ydCB7IFJlc3BvbnNlQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvcmVzcG9uc2UtYXBkdSc7XG5pbXBvcnQgeyBKU0lNQ2FyZCB9IGZyb20gJy4vanNpbS1jYXJkJztcblxuZXhwb3J0IGNsYXNzIEpTSU1TbG90IGltcGxlbWVudHMgU2xvdFxue1xuICBwdWJsaWMgY2FyZDogSlNJTUNhcmQ7XG5cbiAgY29uc3RydWN0b3IoIGNhcmQ/OiBKU0lNQ2FyZCApXG4gIHtcbiAgICB0aGlzLmNhcmQgPSBjYXJkO1xuICB9XG5cbiAgZ2V0IGlzUHJlc2VudCgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gISF0aGlzLmNhcmQ7XG4gIH1cblxuICBnZXQgaXNQb3dlcmVkKCk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLmlzUHJlc2VudCAmJiB0aGlzLmNhcmQuaXNQb3dlcmVkO1xuICB9XG5cbiAgcG93ZXJPbigpOiBQcm9taXNlPEJ5dGVBcnJheT5cbiAge1xuICAgIGlmICggIXRoaXMuaXNQcmVzZW50IClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBuZXcgRXJyb3IoIFwiSlNJTTogQ2FyZCBub3QgcHJlc2VudFwiICkgKTtcblxuICAgIHJldHVybiB0aGlzLmNhcmQucG93ZXJPbigpO1xuICB9XG5cbiAgcG93ZXJPZmYoKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICBpZiAoICF0aGlzLmlzUHJlc2VudCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgbm90IHByZXNlbnRcIiApICk7XG5cbiAgICByZXR1cm4gdGhpcy5jYXJkLnBvd2VyT2ZmKCk7XG4gIH1cblxuICByZXNldCgpOiBQcm9taXNlPEJ5dGVBcnJheT5cbiAge1xuICAgIGlmICggIXRoaXMuaXNQcmVzZW50IClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBuZXcgRXJyb3IoIFwiSlNJTTogQ2FyZCBub3QgcHJlc2VudFwiICkgKTtcblxuICAgIHJldHVybiB0aGlzLmNhcmQucmVzZXQoKTtcbiAgfVxuXG4gIGV4ZWN1dGVBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XG4gIHtcbiAgICBpZiAoICF0aGlzLmlzUHJlc2VudCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8UmVzcG9uc2VBUERVPiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgbm90IHByZXNlbnRcIiApICk7XG5cbiAgICBpZiAoICF0aGlzLmlzUG93ZXJlZCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8UmVzcG9uc2VBUERVPiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgdW5wb3dlcmVkXCIgKSApO1xuXG4gICAgcmV0dXJuIHRoaXMuY2FyZC5leGNoYW5nZUFQRFUoIGNvbW1hbmRBUERVICk7XG4gIH1cblxuICBpbnNlcnRDYXJkKCBjYXJkOiBKU0lNQ2FyZCApXG4gIHtcbiAgICBpZiAoIHRoaXMuY2FyZCApXG4gICAgICB0aGlzLmVqZWN0Q2FyZCgpO1xuXG4gICAgdGhpcy5jYXJkID0gY2FyZDtcbiAgfVxuXG4gIGVqZWN0Q2FyZCgpXG4gIHtcbiAgICBpZiAoIHRoaXMuY2FyZCApXG4gICAge1xuICAgICAgaWYgKCB0aGlzLmNhcmQuaXNQb3dlcmVkIClcbiAgICAgICAgdGhpcy5jYXJkLnBvd2VyT2ZmKCk7XG5cbiAgICAgIHRoaXMuY2FyZCA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGhleDIoIHZhbCApIHsgcmV0dXJuICggXCIwMFwiICsgdmFsLnRvU3RyaW5nKCAxNiApLnRvVXBwZXJDYXNlKCkgKS5zdWJzdHIoIC0yICk7IH1cclxuZXhwb3J0IGZ1bmN0aW9uIGhleDQoIHZhbCApIHsgcmV0dXJuICggXCIwMDAwXCIgKyB2YWwudG9TdHJpbmcoIDE2ICkudG9VcHBlckNhc2UoKSApLnN1YnN0ciggLTQgKTsgfVxyXG5cclxuZXhwb3J0IGVudW0gTUVNRkxBR1Mge1xyXG4gIFJFQURfT05MWSA9IDEgPDwgMCxcclxuICBUUkFOU0FDVElPTkFCTEUgPSAxIDw8IDEsXHJcbiAgVFJBQ0UgPSAxIDw8IDJcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIFNlZ21lbnRcclxue1xyXG4gIHByaXZhdGUgbWVtRGF0YTogQnl0ZUFycmF5O1xyXG4gIHByaXZhdGUgbWVtVHlwZTtcclxuICBwcml2YXRlIHJlYWRPbmx5O1xyXG4gIHByaXZhdGUgZmxhZ3M7XHJcbiAgcHJpdmF0ZSBpblRyYW5zYWN0aW9uID0gZmFsc2U7XHJcbiAgcHJpdmF0ZSB0cmFuc0Jsb2NrcyA9IFtdO1xyXG4gIG1lbVRyYWNlcztcclxuXHJcbiAgY29uc3RydWN0b3IoIHNlZ1R5cGUsIHNpemUsIGZsYWdzPywgYmFzZT86IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgdGhpcy5tZW1UeXBlID0gc2VnVHlwZTtcclxuICAgIHRoaXMucmVhZE9ubHkgPSAoIGZsYWdzICYgTUVNRkxBR1MuUkVBRF9PTkxZICkgPyB0cnVlIDogZmFsc2U7XHJcblxyXG4gICAgaWYgKCBiYXNlIClcclxuICAgIHtcclxuICAgICAgdGhpcy5tZW1EYXRhID0gbmV3IEJ5dGVBcnJheSggYmFzZSApXHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICB7XHJcbiAgICAgIHRoaXMubWVtRGF0YSA9IG5ldyBCeXRlQXJyYXkoIFtdICkuc2V0TGVuZ3RoKCBzaXplICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBnZXRUeXBlKCkgeyByZXR1cm4gdGhpcy5tZW1UeXBlOyB9XHJcbiAgZ2V0TGVuZ3RoKCkgeyByZXR1cm4gdGhpcy5tZW1EYXRhLmxlbmd0aDsgfVxyXG4gIGdldEZsYWdzKCkgeyByZXR1cm4gdGhpcy5mbGFnczsgfVxyXG4gIGdldERlYnVnKCkgeyByZXR1cm4geyBtZW1EYXRhOiB0aGlzLm1lbURhdGEsIG1lbVR5cGU6IHRoaXMubWVtVHlwZSwgcmVhZE9ubHk6IHRoaXMucmVhZE9ubHksIGluVHJhbnNhY3Rpb246IHRoaXMuaW5UcmFuc2FjdGlvbiwgdHJhbnNCbG9ja3M6IHRoaXMudHJhbnNCbG9ja3MgfTsgfVxyXG5cclxuICBiZWdpblRyYW5zYWN0aW9uKClcclxuICB7XHJcbiAgICB0aGlzLmluVHJhbnNhY3Rpb24gPSB0cnVlO1xyXG4gICAgdGhpcy50cmFuc0Jsb2NrcyA9IFtdO1xyXG4gIH1cclxuXHJcbiAgZW5kVHJhbnNhY3Rpb24oIGNvbW1pdCApXHJcbiAge1xyXG4gICAgaWYgKCAhY29tbWl0ICYmIHRoaXMuaW5UcmFuc2FjdGlvbiApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMuaW5UcmFuc2FjdGlvbiA9IGZhbHNlO1xyXG5cclxuICAgICAgLy8gcm9sbGJhY2sgdHJhbnNhY3Rpb25zXHJcbiAgICAgIGZvciggdmFyIGk9MDsgaSA8IHRoaXMudHJhbnNCbG9ja3MubGVuZ3RoOyBpKysgKVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIGJsb2NrID0gdGhpcy50cmFuc0Jsb2Nrc1sgaSBdO1xyXG5cclxuICAgICAgICB0aGlzLndyaXRlQnl0ZXMoIGJsb2NrLmFkZHIsIGJsb2NrLmRhdGEgKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhbnNCbG9ja3MgPSBbXTtcclxuICB9XHJcblxyXG4gIHJlYWRCeXRlKCBhZGRyIClcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5tZW1EYXRhWyBhZGRyIF07XHJcbiAgfVxyXG5cclxuICB6ZXJvQnl0ZXMoIGFkZHIsIGxlbiApXHJcbiAge1xyXG4gICAgZm9yKCB2YXIgaSA9IDA7IGkgPCBsZW47ICsraSApXHJcbiAgICAgIHRoaXMubWVtRGF0YVsgYWRkciArIGkgXSA9IDA7XHJcbiAgfVxyXG5cclxuICByZWFkQnl0ZXMoIGFkZHIsIGxlbiApOiBCeXRlQXJyYXlcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5tZW1EYXRhLnZpZXdBdCggYWRkciwgbGVuICk7XHJcbiAgfVxyXG5cclxuICBjb3B5Qnl0ZXMoIGZyb21BZGRyLCB0b0FkZHIsIGxlbiApXHJcbiAge1xyXG4gICAgdGhpcy53cml0ZUJ5dGVzKCB0b0FkZHIsIHRoaXMucmVhZEJ5dGVzKCBmcm9tQWRkciwgbGVuICkgKTtcclxuICB9XHJcblxyXG4gIHdyaXRlQnl0ZXMoIGFkZHI6IG51bWJlciwgdmFsOiBCeXRlQXJyYXkgKVxyXG4gIHtcclxuICAgIGlmICggdGhpcy5pblRyYW5zYWN0aW9uICYmICggdGhpcy5mbGFncyAmIE1FTUZMQUdTLlRSQU5TQUNUSU9OQUJMRSApIClcclxuICAgIHtcclxuICAgICAgLy8gc2F2ZSBwcmV2aW91cyBFRVBST00gY29udGVudHNcclxuICAgICAgdGhpcy50cmFuc0Jsb2Nrcy5wdXNoKCB7IGFkZHI6IGFkZHIsIGRhdGE6IHRoaXMucmVhZEJ5dGVzKCBhZGRyLCB2YWwubGVuZ3RoICkgfSApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMubWVtRGF0YS5zZXRCeXRlc0F0KCBhZGRyLCB2YWwgKTtcclxuICB9XHJcblxyXG4gIG5ld0FjY2Vzc29yKCBhZGRyLCBsZW4sIG5hbWUgKTogQWNjZXNzb3JcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEFjY2Vzc29yKCB0aGlzLCBhZGRyLCBsZW4sIG5hbWUgKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBBY2Nlc3NvclxyXG57XHJcbiAgb2Zmc2V0OiBudW1iZXI7XHJcbiAgbGVuZ3RoOiBudW1iZXI7XHJcbiAgaWQ6IHN0cmluZztcclxuICBzZWc6IFNlZ21lbnQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCBzZWcsIGFkZHIsIGxlbiwgbmFtZSApXHJcbiAge1xyXG4gICAgdGhpcy5zZWcgPSBzZWc7XHJcblxyXG4gICAgdGhpcy5vZmZzZXQgPSBhZGRyO1xyXG4gICAgdGhpcy5sZW5ndGggPSBsZW47XHJcbiAgICB0aGlzLmlkID0gbmFtZTtcclxuICB9XHJcblxyXG4gIHRyYWNlTWVtb3J5T3AoIG9wLCBhZGRyLCBsZW4sIGFkZHIyPyApXHJcbiAge1xyXG4gICAgaWYgKCB0aGlzLmlkICE9IFwiY29kZVwiIClcclxuICAgICAgdGhpcy5zZWcubWVtVHJhY2VzLnB1c2goIHsgb3A6IG9wLCBuYW1lOiB0aGlzLmlkLCBhZGRyOiBhZGRyLCBsZW46IGxlbiwgYWRkcjI6IGFkZHIyIH0gKTtcclxuICB9XHJcblxyXG4gIHRyYWNlTWVtb3J5VmFsdWUoIHZhbCApXHJcbiAge1xyXG4gICAgaWYgKCB0aGlzLmlkICE9IFwiY29kZVwiIClcclxuICAgIHtcclxuICAgICAgdmFyIG1lbVRyYWNlID0gdGhpcy5zZWcubWVtVHJhY2VzWyB0aGlzLnNlZy5tZW1UcmFjZXMubGVuZ3RoIC0gMSBdO1xyXG5cclxuICAgICAgbWVtVHJhY2UudmFsID0gdmFsO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgemVyb0J5dGVzKCBhZGRyOiBudW1iZXIsIGxlbjogbnVtYmVyIClcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyBsZW4gPiB0aGlzLmxlbmd0aCApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJaUi1lcnJvclwiLCBhZGRyLCB0aGlzLmxlbmd0aCApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgWmVyb1wiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlpSXCIsIGFkZHIsIGxlbiApO1xyXG4gICAgdGhpcy5zZWcuemVyb0J5dGVzKCB0aGlzLm9mZnNldCArIGFkZHIsIGxlbiApO1xyXG4gICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCBbIDAgXSApO1xyXG4gIH1cclxuXHJcbiAgcmVhZEJ5dGUoIGFkZHI6IG51bWJlciApOiBudW1iZXJcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyAxID4gdGhpcy5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiUkQtZXJyb3JcIiwgYWRkciwgMSApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgUmVhZFwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJEXCIsIGFkZHIsIDEgKTtcclxuXHJcbiAgICB2YXIgdmFsID0gdGhpcy5zZWcucmVhZEJ5dGUoIHRoaXMub2Zmc2V0ICsgYWRkciApO1xyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggWyB2YWwgXSk7XHJcblxyXG4gICAgcmV0dXJuIHZhbDtcclxuICB9XHJcblxyXG4gIHJlYWRCeXRlcyggYWRkciwgbGVuICk6IEJ5dGVBcnJheVxyXG4gIHtcclxuICAgIGlmICggYWRkciArIGxlbiA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJELWVycm9yXCIsIGFkZHIsIGxlbiApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgUmVhZFwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJEXCIsIGFkZHIsIGxlbiApO1xyXG4gICAgdmFyIHZhbCA9IHRoaXMuc2VnLnJlYWRCeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCBsZW4gKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggdmFsICk7XHJcblxyXG4gICAgcmV0dXJuIHZhbDtcclxuICB9XHJcblxyXG4gIGNvcHlCeXRlcyggZnJvbUFkZHI6IG51bWJlciwgdG9BZGRyOiBudW1iZXIsIGxlbjogbnVtYmVyICk6IEJ5dGVBcnJheVxyXG4gIHtcclxuICAgIGlmICggKCBmcm9tQWRkciArIGxlbiA+IHRoaXMubGVuZ3RoICkgfHwgKCB0b0FkZHIgKyBsZW4gPiB0aGlzLmxlbmd0aCApIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIkNQLWVycm9yXCIsIGZyb21BZGRyLCBsZW4sIHRvQWRkciApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgUmVhZFwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgLy9pZiAoIG1lbVRyYWNpbmcgKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiQ1BcIiwgZnJvbUFkZHIsIGxlbiwgdG9BZGRyICk7XHJcbiAgICAgIHZhciB2YWwgPSB0aGlzLnNlZy5yZWFkQnl0ZXMoIHRoaXMub2Zmc2V0ICsgZnJvbUFkZHIsIGxlbiApO1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIHZhbCApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc2VnLmNvcHlCeXRlcyggdGhpcy5vZmZzZXQgKyBmcm9tQWRkciwgdGhpcy5vZmZzZXQgKyB0b0FkZHIsIGxlbiApO1xyXG4gICAgcmV0dXJuIHZhbDtcclxuICB9XHJcblxyXG4gIHdyaXRlQnl0ZSggYWRkcjogbnVtYmVyLCB2YWw6IG51bWJlciApXHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgMSA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIldSLWVycm9yXCIsIGFkZHIsIDEgKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFdyaXRlXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiV1JcIiwgYWRkciwgMSApO1xyXG4gICAgdGhpcy5zZWcud3JpdGVCeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCBuZXcgQnl0ZUFycmF5KCBbIHZhbCBdICkgKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggWyB2YWwgXSApO1xyXG4gIH1cclxuXHJcbiAgd3JpdGVCeXRlcyggYWRkcjogbnVtYmVyLCB2YWw6IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgdmFsLmxlbmd0aCA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIldSLWVycm9yXCIsIGFkZHIsIHZhbC5sZW5ndGggKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFdyaXRlXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiV1JcIiwgYWRkciwgdmFsLmxlbmd0aCApO1xyXG4gICAgdGhpcy5zZWcud3JpdGVCeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCB2YWwgKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggdmFsICk7XHJcbiAgfVxyXG5cclxuICBnZXRUeXBlKCkgeyByZXR1cm4gdGhpcy5zZWcuZ2V0VHlwZSgpOyB9XHJcbiAgZ2V0TGVuZ3RoKCkgeyByZXR1cm4gdGhpcy5sZW5ndGg7IH1cclxuICBnZXRJRCgpIHsgcmV0dXJuIHRoaXMuaWQ7IH1cclxuLy8gICAgICAgIGJlZ2luVHJhbnNhY3Rpb246IGJlZ2luVHJhbnNhY3Rpb24sXHJcbi8vICAgICAgICBpblRyYW5zYWN0aW9uOiBmdW5jdGlvbigpIHsgcmV0dXJuIGluVHJhbnNhY3Rpb247IH0sXHJcbi8vICAgICAgICBlbmRUcmFuc2FjdGlvbjogZW5kVHJhbnNhY3Rpb24sXHJcbiAgZ2V0RGVidWcoKSB7IHJldHVybiB7IG9mZnNldDogdGhpcy5vZmZzZXQsIGxlbmd0aDogdGhpcy5sZW5ndGgsIHNlZzogdGhpcy5zZWcgfTsgfVxyXG59XHJcblxyXG5mdW5jdGlvbiBzbGljZURhdGEoIGJhc2UsIG9mZnNldCwgc2l6ZSApOiBVaW50OEFycmF5XHJcbntcclxuICByZXR1cm4gYmFzZS5zdWJhcnJheSggb2Zmc2V0LCBvZmZzZXQgKyBzaXplICk7XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBNZW1vcnlNYW5hZ2VyXHJcbntcclxuICBwcml2YXRlIG1lbW9yeVNlZ21lbnRzID0gW107XHJcblxyXG4gIHByaXZhdGUgbWVtVHJhY2VzID0gW107XHJcblxyXG4gIG5ld1NlZ21lbnQoIG1lbVR5cGUsIHNpemUsIGZsYWdzPyAgKTogU2VnbWVudFxyXG4gIHtcclxuICAgIGxldCBuZXdTZWcgPSBuZXcgU2VnbWVudCggbWVtVHlwZSwgc2l6ZSwgZmxhZ3MgKTtcclxuXHJcbiAgICB0aGlzLm1lbW9yeVNlZ21lbnRzWyBtZW1UeXBlIF0gPSBuZXdTZWc7XHJcblxyXG4gICAgbmV3U2VnLm1lbVRyYWNlcyA9IHRoaXMubWVtVHJhY2VzO1xyXG5cclxuICAgIHJldHVybiBuZXdTZWc7XHJcbiAgfVxyXG5cclxuICBnZXRNZW1UcmFjZSgpIHsgcmV0dXJuIHRoaXMubWVtVHJhY2VzOyB9XHJcblxyXG4gIGluaXRNZW1UcmFjZSgpIHsgdGhpcy5tZW1UcmFjZXMgPSBbXTsgfVxyXG5cclxuICBnZXRTZWdtZW50KCB0eXBlICkgeyByZXR1cm4gdGhpcy5tZW1vcnlTZWdtZW50c1sgdHlwZSBdOyB9XHJcbn1cclxuIiwiZXhwb3J0IGVudW0gTUVMSU5TVCB7XHJcbiAgbWVsU1lTVEVNID0gIDB4MDAsXHJcbiAgbWVsQlJBTkNIID0gIDB4MDEsXHJcbiAgbWVsSlVNUCA9ICAgIDB4MDIsXHJcbiAgbWVsQ0FMTCA9ICAgIDB4MDMsXHJcbiAgbWVsU1RBQ0sgPSAgIDB4MDQsXHJcbiAgbWVsUFJJTVJFVCA9IDB4MDUsXHJcbiAgbWVsSU5WQUxJRCA9IDB4MDYsXHJcbiAgbWVsTE9BRCA9ICAgIDB4MDcsXHJcbiAgbWVsU1RPUkUgPSAgIDB4MDgsXHJcbiAgbWVsTE9BREkgPSAgIDB4MDksXHJcbiAgbWVsU1RPUkVJID0gIDB4MEEsXHJcbiAgbWVsTE9BREEgPSAgIDB4MEIsXHJcbiAgbWVsSU5ERVggPSAgIDB4MEMsXHJcbiAgbWVsU0VUQiA9ICAgIDB4MEQsXHJcbiAgbWVsQ01QQiA9ICAgIDB4MEUsXHJcbiAgbWVsQUREQiA9ICAgIDB4MEYsXHJcbiAgbWVsU1VCQiA9ICAgIDB4MTAsXHJcbiAgbWVsU0VUVyA9ICAgIDB4MTEsXHJcbiAgbWVsQ01QVyA9ICAgIDB4MTIsXHJcbiAgbWVsQUREVyA9ICAgIDB4MTMsXHJcbiAgbWVsU1VCVyA9ICAgIDB4MTQsXHJcbiAgbWVsQ0xFQVJOID0gIDB4MTUsXHJcbiAgbWVsVEVTVE4gPSAgIDB4MTYsXHJcbiAgbWVsSU5DTiA9ICAgIDB4MTcsXHJcbiAgbWVsREVDTiA9ICAgIDB4MTgsXHJcbiAgbWVsTk9UTiA9ICAgIDB4MTksXHJcbiAgbWVsQ01QTiA9ICAgIDB4MUEsXHJcbiAgbWVsQURETiA9ICAgIDB4MUIsXHJcbiAgbWVsU1VCTiA9ICAgIDB4MUMsXHJcbiAgbWVsQU5ETiA9ICAgIDB4MUQsXHJcbiAgbWVsT1JOID0gICAgIDB4MUUsXHJcbiAgbWVsWE9STiA9ICAgIDB4MUZcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFRBR0FERFIge1xyXG4gIG1lbEFkZHJUT1MgPSAweDAwLFxyXG4gIG1lbEFkZHJTQiA9ICAweDAxLFxyXG4gIG1lbEFkZHJTVCA9ICAweDAyLFxyXG4gIG1lbEFkZHJEQiA9ICAweDAzLFxyXG4gIG1lbEFkZHJMQiA9ICAweDA0LFxyXG4gIG1lbEFkZHJEVCA9ICAweDA1LFxyXG4gIG1lbEFkZHJQQiA9ICAweDA2LFxyXG4gIG1lbEFkZHJQVCA9ICAweDA3XHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxUQUdDT05EIHtcclxuICBtZWxDb25kU1BFQyA9ICAweDAwLCAvLyBTcGVjaWFsXHJcbiAgbWVsQ29uZEVRID0gICAgMHgwMSwgLy8gRXF1YWxcclxuICBtZWxDb25kTFQgPSAgICAweDAyLCAvLyBMZXNzIHRoYW5cclxuICBtZWxDb25kTEUgPSAgICAweDAzLCAvLyBMZXNzIHRoYW4sIGVxdWFsIHRvXHJcbiAgbWVsQ29uZEdUID0gICAgMHgwNCwgLy8gR3JlYXRlciB0aGFuXHJcbiAgbWVsQ29uZEdFID0gICAgMHgwNSwgLy8gR3JlYXRlciB0aGFuLCBlcXVhbCB0b1xyXG4gIG1lbENvbmRORSA9ICAgIDB4MDYsIC8vIE5vdCBlcXVhbCB0b1xyXG4gIG1lbENvbmRBTEwgPSAgIDB4MDcgIC8vIEFsd2F5c1xyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHU1lTVEVNIHtcclxuICBtZWxTeXN0ZW1OT1AgPSAgICAgICAweDAwLCAvLyBOT1BcclxuICBtZWxTeXN0ZW1TZXRTVyA9ICAgICAweDAxLCAvLyBTRVRTV1xyXG4gIG1lbFN5c3RlbVNldExhID0gICAgIDB4MDIsIC8vIFNFVExBXHJcbiAgbWVsU3lzdGVtU2V0U1dMYSA9ICAgMHgwMywgLy8gU0VUU1dMQVxyXG4gIG1lbFN5c3RlbUV4aXQgPSAgICAgIDB4MDQsIC8vIEVYSVRcclxuICBtZWxTeXN0ZW1FeGl0U1cgPSAgICAweDA1LCAvLyBFWElUU1dcclxuICBtZWxTeXN0ZW1FeGl0TGEgPSAgICAweDA2LCAvLyBFWElUTEFcclxuICBtZWxTeXN0ZW1FeGl0U1dMYSA9ICAweDA3ICAvLyBFWElUU1dMQVxyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHU1RBQ0sge1xyXG4gIG1lbFN0YWNrUFVTSFogPSAgMHgwMCwgLy8gUFVTSFpcclxuICBtZWxTdGFja1BVU0hCID0gIDB4MDEsIC8vIFBVU0hCXHJcbiAgbWVsU3RhY2tQVVNIVyA9ICAweDAyLCAvLyBQVVNIV1xyXG4gIG1lbFN0YWNrWFg0ID0gICAgMHgwMywgLy8gSWxsZWdhbFxyXG4gIG1lbFN0YWNrUE9QTiA9ICAgMHgwNCwgLy8gUE9QTlxyXG4gIG1lbFN0YWNrUE9QQiA9ICAgMHgwNSwgLy8gUE9QQlxyXG4gIG1lbFN0YWNrUE9QVyA9ICAgMHgwNiwgLy8gUE9QV1xyXG4gIG1lbFN0YWNrWFg3ID0gICAgMHgwNyAgLy8gSWxsZWdhbFxyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHUFJJTVJFVCB7XHJcbiAgbWVsUHJpbVJldFBSSU0wID0gIDB4MDAsIC8vIFBSSU0gMFxyXG4gIG1lbFByaW1SZXRQUklNMSA9ICAweDAxLCAvLyBQUklNIDFcclxuICBtZWxQcmltUmV0UFJJTTIgPSAgMHgwMiwgLy8gUFJJTSAyXHJcbiAgbWVsUHJpbVJldFBSSU0zID0gIDB4MDMsIC8vIFBSSU0gM1xyXG4gIG1lbFByaW1SZXRSRVQgPSAgICAweDA0LCAvLyBSRVRcclxuICBtZWxQcmltUmV0UkVUSSA9ICAgMHgwNSwgLy8gUkVUIEluXHJcbiAgbWVsUHJpbVJldFJFVE8gPSAgIDB4MDYsIC8vIFJFVCBPdXRcclxuICBtZWxQcmltUmV0UkVUSU8gPSAgMHgwNyAgLy8gUkVUIEluT3V0XHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxQQVJBTURFRiB7XHJcbiAgbWVsUGFyYW1EZWZOb25lID0gICAgICAgICAgICAgIDB4MDAsXHJcbiAgbWVsUGFyYW1EZWZUb3BPZlN0YWNrID0gICAgICAgIDB4MDEsXHJcbiAgbWVsUGFyYW1EZWZCeXRlT3BlckxlbiA9ICAgICAgIDB4MTEsXHJcbiAgbWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlID0gICAgIDB4MTIsXHJcbiAgbWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlID0gIDB4MTgsXHJcbiAgbWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlID0gICAgIDB4MjAsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0U0IgPSAgICAgIDB4MjEsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1QgPSAgICAgIDB4MjIsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0REIgPSAgICAgIDB4MjMsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0TEIgPSAgICAgIDB4MjQsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQgPSAgICAgIDB4MjUsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0UEIgPSAgICAgIDB4MjYsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0UFQgPSAgICAgIDB4MjcsXHJcbiAgbWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgPSAgIDB4MjhcclxufTtcclxuXHJcbmZ1bmN0aW9uIE1FTFBBUkFNNCggYSwgYiwgYywgZCApICAgICAgICB7IHJldHVybiAoIChkPDwyNCkgfCAoYzw8MTYpIHwgKGI8PDgpIHwgKGE8PDApICk7IH1cclxuZnVuY3Rpb24gT1BUQUcyTUVMSU5TVCggb3BDb2RlLCB0YWcgKSAgIHsgcmV0dXJuICggKCAoIG9wQ29kZSAmIDB4MWYgKSA8PCAzICkgfCB0YWcgKTsgfVxyXG5leHBvcnQgZnVuY3Rpb24gTUVMMk9QQ09ERSggYnl0ZUNvZGUgKSAgICAgICAgIHsgcmV0dXJuICggKCBieXRlQ29kZSA+PiAzICkgJiAweDFmICk7IH1cclxuZXhwb3J0IGZ1bmN0aW9uIE1FTDJJTlNUKCBieXRlQ29kZSApICAgICAgICAgICB7IHJldHVybiBNRUwyT1BDT0RFKCBieXRlQ29kZSApOyB9XHJcbmV4cG9ydCBmdW5jdGlvbiBNRUwyVEFHKCBieXRlQ29kZSApICAgICAgICAgICAgeyByZXR1cm4gKCAoYnl0ZUNvZGUpICYgNyApIH07XHJcblxyXG5mdW5jdGlvbiBNRUxQQVJBTVNJWkUoIHBhcmFtVHlwZSApXHJcbntcclxuICByZXR1cm4gKCBwYXJhbVR5cGUgPT0gTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lIClcclxuICAgICAgICAgPyAwXHJcbiAgICAgICAgIDogKCBwYXJhbVR5cGUgPCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUpID8gMSA6IDI7XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBNRUxcclxue1xyXG4gIHB1YmxpYyBzdGF0aWMgbWVsRGVjb2RlID0gW107XHJcblxyXG4gIHB1YmxpYyBzdGF0aWMgTUVMSU5TVDogTUVMSU5TVDtcclxuICBwdWJsaWMgc3RhdGljIE1FTFRBR1NUQUNLOiBNRUxUQUdTVEFDSztcclxuICBwdWJsaWMgc3RhdGljIE1FTFBBUkFNREVGOiBNRUxQQVJBTURFRjtcclxuICBwdWJsaWMgc3RhdGljIE1FTFRBR0FERFI6IE1FTFRBR0FERFI7XHJcblxyXG59XHJcblxyXG5mdW5jdGlvbiBzZXRNZWxEZWNvZGUoIGJ5dGVDb2RlOiBudW1iZXIsIGluc3ROYW1lOiBzdHJpbmcsIHBhcmFtMT8sIHBhcmFtMj8sIHBhcmFtMz8sIHBhcmFtND8gKVxyXG57XHJcbiAgcGFyYW0xID0gcGFyYW0xIHx8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZTtcclxuICBwYXJhbTIgPSBwYXJhbTIgfHwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lO1xyXG4gIHBhcmFtMyA9IHBhcmFtMyB8fCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmU7XHJcbiAgcGFyYW00ID0gcGFyYW00IHx8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZTtcclxuXHJcbiAgTUVMLm1lbERlY29kZVsgYnl0ZUNvZGUgXSA9IHtcclxuICAgIGJ5dGVDb2RlOiBieXRlQ29kZSxcclxuICAgIGluc3RMZW46IDEgKyBNRUxQQVJBTVNJWkUoIHBhcmFtMSApICsgTUVMUEFSQU1TSVpFKCBwYXJhbTIgKSArIE1FTFBBUkFNU0laRSggcGFyYW0zICkgKyBNRUxQQVJBTVNJWkUoIHBhcmFtNCApLFxyXG4gICAgaW5zdE5hbWU6IGluc3ROYW1lLFxyXG4gICAgcGFyYW1EZWZzOiBNRUxQQVJBTTQoIHBhcmFtMSwgcGFyYW0yLCBwYXJhbTMsIHBhcmFtNCApXHJcbiAgfTtcclxufVxyXG5cclxuZnVuY3Rpb24gc2V0TWVsRGVjb2RlU3RkTW9kZXMoIG1lbEluc3Q6IE1FTElOU1QsIGluc3ROYW1lOiBzdHJpbmcsIHBhcmFtMURlZjogTUVMUEFSQU1ERUYgKVxyXG57XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJTQiApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyU1QgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1QgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkckRCICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJMQiApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRMQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyRFQgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclBCICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJQVCApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQVCApO1xyXG59XHJcblxyXG5mdW5jdGlvbiBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggbWVsSW5zdDogTUVMSU5TVCwgaW5zdE5hbWU6IHN0cmluZywgcGFyYW0xRGVmOiBNRUxQQVJBTURFRiApXHJcbntcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclRPUyApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZlRvcE9mU3RhY2sgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2RlcyggbWVsSW5zdCwgaW5zdE5hbWUsIHBhcmFtMURlZiApO1xyXG59XHJcblxyXG5mdW5jdGlvbiBmaWxsTWVsRGVjb2RlKClcclxue1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbExPQUQsICAgXCJMT0FEXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNUT1JFLCAgXCJTVE9SRVwiLCAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbExPQURJLCAgXCJMT0FESVwiLCAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNUT1JFSSwgXCJTVE9SRUlcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclNCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U0IgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclNUICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1QgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkckRCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0REIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkckxCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0TEIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkckRUICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclBCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UEIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclBUICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UFQgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXMoIE1FTElOU1QubWVsSU5ERVgsICBcIklOREVYXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG5cclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTRVRCLCAgIFwiU0VUQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxDTVBCLCAgIFwiQ01QQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxBRERCLCAgIFwiQUREQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVUJCLCAgIFwiU1VCQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTRVRXLCAgIFwiU0VUV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxDTVBXLCAgIFwiQ01QV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxBRERXLCAgIFwiQUREV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVUJXLCAgIFwiU1VCV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQ0xFQVJOLCBcIkNMRUFSTlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsVEVTVE4sICBcIlRFU1ROXCIsICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsSU5DTiwgICBcIklOQ05cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsREVDTiwgICBcIkRFQ05cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsTk9UTiwgICBcIk5PVE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQ01QTiwgICBcIkNNUE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQURETiwgICBcIkFERE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU1VCTiwgICBcIlNVQk5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQU5ETiwgICBcIkFORE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsT1JOLCAgICBcIk9STlwiLCAgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsWE9STiwgICBcIlhPUk5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1OT1AgKSwgXCJOT1BcIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1TZXRTVyApLCBcIlNFVFNXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1TZXRMYSApLCBcIlNFVExBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1TZXRTV0xhICksIFwiU0VUU1dMQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1FeGl0ICksIFwiRVhJVFwiICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbUV4aXRTVyApLCBcIkVYSVRTV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtRXhpdExhICksIFwiRVhJVEFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbUV4aXRTV0xhICksIFwiRVhJVFNXTEFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuXHJcbiAgLy8gc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxCUkFOQ0gsIG1lbENvbmRTUEVDICksIFwiLS0tXCIsIDAsIG1lbEFkZHJUT1MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRFUSApLCBcIkJFUVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRMVCApLCBcIkJMVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRMRSApLCBcIkJMRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRHVCApLCBcIkJHVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRHRSApLCBcIkJHRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRORSApLCBcIkJORVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRBTEwgKSwgXCJCQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZFNQRUMgKSwgXCJKQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kRVEgKSwgXCJKRVFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kTFQgKSwgXCJKTFRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kTEUgKSwgXCJKTEVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kR1QgKSwgXCJKR1RcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kR0UgKSwgXCJKR0VcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kTkUgKSwgXCJKTkVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kQUxMICksIFwiSkFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZFNQRUMgKSwgXCJDQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kRVEgKSwgXCJDRVFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kTFQgKSwgXCJDTFRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kTEUgKSwgXCJDTEVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kR1QgKSwgXCJDR1RcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kR0UgKSwgXCJDR0VcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kTkUgKSwgXCJDTkVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kQUxMICksIFwiQ0FcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BVU0haICksIFwiUFVTSFpcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIQiApLCBcIlBVU0hCXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIVyApLCBcIlBVU0hXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIC8vIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsU1RBQ0ssIG1lbFN0YWNrWFg0ICksIFwiLS1cIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BOICksIFwiUE9QTlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BPUEIgKSwgXCJQT1BCXCIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QVyApLCBcIlBPUFdcIiApO1xyXG4gIC8vIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsU1RBQ0ssIG1lbFN0YWNrWFg3ICksIFwiLS1cIiApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTAgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMSApLCBcIlBSSU1cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTIgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTMgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVQgKSwgXCJSRVRcIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJICksIFwiUkVUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUTyApLCBcIlJFVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVElPICksIFwiUkVUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4sIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxufVxyXG5cclxuXHJcbmZpbGxNZWxEZWNvZGUoKTtcclxuXHJcbmV4cG9ydCB2YXIgTUVMRGVjb2RlID0gTUVMLm1lbERlY29kZTtcclxuZXhwb3J0IGNvbnN0IE1FTF9DQ1JfWiA9IDB4MDE7XHJcbmV4cG9ydCBjb25zdCBNRUxfQ0NSX0MgPSAweDAyO1xyXG4iLCJpbXBvcnQgKiBhcyBNRUwgZnJvbSAnLi9tZWwtZGVmaW5lcyc7XHJcbmltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9pc283ODE2L2NvbW1hbmQtYXBkdSc7XHJcbmltcG9ydCB7IFJlc3BvbnNlQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvcmVzcG9uc2UtYXBkdSc7XHJcblxyXG5mdW5jdGlvbiBoZXgoIHZhbCApIHsgcmV0dXJuIHZhbC50b1N0cmluZyggMTYgKTsgfVxyXG5mdW5jdGlvbiBoZXgyKCB2YWwgKSB7IHJldHVybiAoIFwiMDBcIiArIHZhbC50b1N0cmluZyggMTYgKSApLnN1YnN0ciggLTIgKTsgfVxyXG5mdW5jdGlvbiBoZXg0KCB2YWwgKSB7IHJldHVybiAoIFwiMDAwMFwiICsgdmFsLnRvU3RyaW5nKCAxNiApICkuc3Vic3RyKCAtNCApOyB9XHJcbmZ1bmN0aW9uIGxqdXN0KCBzdHIsIHcgKSB7IHJldHVybiAoIHN0ciArIEFycmF5KCB3ICsgMSApLmpvaW4oIFwiIFwiICkgKS5zdWJzdHIoIDAsIHcgKTsgfVxyXG5mdW5jdGlvbiByanVzdCggc3RyLCB3ICkgeyByZXR1cm4gKCBBcnJheSggdyArIDEgKS5qb2luKCBcIiBcIiApICsgc3RyICkuc3Vic3RyKCAtdyApOyB9XHJcblxyXG5mdW5jdGlvbiAgIEJBMlcoIHZhbCApXHJcbntcclxuICByZXR1cm4gKCB2YWxbIDAgXSA8PCA4ICkgfCB2YWxbIDEgXTtcclxufVxyXG5cclxuZnVuY3Rpb24gICBXMkJBKCB2YWwgKVxyXG57XHJcblxyXG4gIHJldHVybiBuZXcgQnl0ZUFycmF5KCBbIHZhbCA+PiA4LCB2YWwgJiAweEZGIF0gKTtcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE1FTFZpcnR1YWxNYWNoaW5lIHtcclxuICAvLyBjYXJkXHJcbiAgcmFtU2VnbWVudDtcclxuICByb21TZWdtZW50O1xyXG5cclxuICAvLyBhcHBsaWNhdGlvblxyXG4gIGNvZGVBcmVhO1xyXG4gIHN0YXRpY0FyZWE7XHJcbiAgcHVibGljQXJlYTtcclxuICBkeW5hbWljQXJlYTtcclxuICBzZXNzaW9uU2l6ZTtcclxuXHJcbiAgLy8gZXhlY3V0aW9uXHJcbiAgaXNFeGVjdXRpbmc7XHJcbiAgY3VycmVudElQO1xyXG4gIGxvY2FsQmFzZTtcclxuICBkeW5hbWljVG9wO1xyXG4gIGNvbmRpdGlvbkNvZGVSZWc7XHJcblxyXG4gIGluaXRNVk0oIHBhcmFtcyApXHJcbiAge1xyXG4gICAgdGhpcy5yb21TZWdtZW50ID0gcGFyYW1zLnJvbVNlZ21lbnQ7XHJcbiAgICB0aGlzLnJhbVNlZ21lbnQgPSBwYXJhbXMucmFtU2VnbWVudDtcclxuXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEgPSB0aGlzLnJhbVNlZ21lbnQubmV3QWNjZXNzb3IoIDAsIDUxMiwgXCJQXCIgKTtcclxuICB9XHJcblxyXG4gIGRpc2Fzc2VtYmxlQ29kZSggcmVzZXRJUCwgc3RlcFRvTmV4dElQIClcclxuICB7XHJcbiAgICB2YXIgZGlzbVRleHQgPSBcIlwiO1xyXG4gICAgZnVuY3Rpb24gcHJpbnQoIHN0ciApIHsgZGlzbVRleHQgKz0gc3RyOyB9XHJcblxyXG4gICAgaWYgKCByZXNldElQIClcclxuICAgICAgdGhpcy5jdXJyZW50SVAgPSAwO1xyXG5cclxuICAgIGlmICggdGhpcy5jdXJyZW50SVAgPj0gdGhpcy5jb2RlQXJlYS5nZXRMZW5ndGgoKSApXHJcbiAgICAgIHJldHVybiBudWxsO1xyXG5cclxuICAgIHRyeVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV4dElQID0gdGhpcy5jdXJyZW50SVA7XHJcbiAgICAgIHZhciBpbnN0Qnl0ZSA9IHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICk7XHJcbiAgICAgIHZhciBwYXJhbUNvdW50ID0gMDtcclxuICAgICAgdmFyIHBhcmFtVmFsID0gW107XHJcbiAgICAgIHZhciBwYXJhbURlZiA9IFtdO1xyXG5cclxuICAgICAgdmFyIG1lbEluc3QgPSBNRUwuTUVMRGVjb2RlWyBpbnN0Qnl0ZSBdO1xyXG5cclxuICAgICAgaWYgKCBtZWxJbnN0ID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHtcclxuICAgICAgICBwcmludCggXCJbXCIgKyBoZXg0KCB0aGlzLmN1cnJlbnRJUCApICsgXCJdICAgICAgICAgIFwiICsgbGp1c3QoIFwiRVJST1I6XCIgKyBoZXgyKCBpbnN0Qnl0ZSApLCA4ICkgKyBcIiAqKioqKioqKlxcblwiICk7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIHBhcmFtRGVmcyA9IG1lbEluc3QucGFyYW1EZWZzO1xyXG4gICAgICAgIHdoaWxlKCBwYXJhbURlZnMgIT0gMCApXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcGFyYW1EZWZbIHBhcmFtQ291bnQgXSA9IHBhcmFtRGVmcyAmIDB4RkY7XHJcbiAgICAgICAgICBzd2l0Y2goIHBhcmFtRGVmcyAmIDB4RjAgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIDB4MDA6IGJyZWFrO1xyXG4gICAgICAgICAgICBjYXNlIDB4MTA6IHBhcmFtVmFsWyBwYXJhbUNvdW50IF0gPSB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApOyBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAweDIwOiBwYXJhbVZhbFsgcGFyYW1Db3VudCBdID0gQkEyVyggWyB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApLCB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApIF0gKTsgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBwYXJhbUNvdW50Kys7XHJcbiAgICAgICAgICBwYXJhbURlZnMgPj49IDg7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwcmludCggXCJbXCIgKyBoZXg0KCB0aGlzLmN1cnJlbnRJUCApICsgXCJdICAgICAgICAgIFwiICsgbGp1c3QoIG1lbEluc3QuaW5zdE5hbWUsIDggKSApO1xyXG5cclxuICAgICAgICBpZiAoICggcGFyYW1Db3VudCA+IDEgKVxyXG4gICAgICAgICAgJiYgKCAoIHBhcmFtRGVmWyAwIF0gPT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKVxyXG4gICAgICAgICAgICB8fCAoIHBhcmFtRGVmWyAwIF0gPT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApXHJcbiAgICAgICAgICAgIHx8ICggcGFyYW1EZWZbIDAgXSA9PSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICkgKVxyXG4gICAgICAgICAgJiYgKCBwYXJhbURlZlsgMSBdICE9IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKVxyXG4gICAgICAgICAgJiYgKCBwYXJhbURlZlsgMSBdICE9IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICkgKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciB0ZW1wVmFsID0gcGFyYW1WYWxbMV07IHBhcmFtVmFsWzFdID0gcGFyYW1WYWxbMF07IHBhcmFtVmFsWzBdID0gdGVtcFZhbDtcclxuICAgICAgICAgIHZhciB0ZW1wRGVmID0gcGFyYW1EZWZbMV07IHBhcmFtRGVmWzFdID0gcGFyYW1EZWZbMF07IHBhcmFtRGVmWzBdID0gdGVtcERlZjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGZvciggdmFyIHBhcmFtSW5kZXggPSAwOyBwYXJhbUluZGV4IDwgcGFyYW1Db3VudDsgKytwYXJhbUluZGV4IClcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgdiA9IHBhcmFtVmFsWyBwYXJhbUluZGV4IF07XHJcbiAgICAgICAgICB2YXIgZCA9IHBhcmFtRGVmWyBwYXJhbUluZGV4IF07XHJcblxyXG4gICAgICAgICAgc3dpdGNoKCBkIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbjpcclxuICAgICAgICAgICAgICBpZiAoIHYgPiAwIClcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIjB4XCIgKyBoZXgoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHByaW50KCB2ICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGU6XHJcbiAgICAgICAgICAgICAgaWYgKCB2ID4gMCApXHJcbiAgICAgICAgICAgICAgICBwcmludCggXCIweFwiICsgaGV4KCB2ICkgKTtcclxuICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICBwcmludCggdiApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlOlxyXG4gICAgICAgICAgICAgIHByaW50KCBcIjB4XCIgKyBoZXgoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3M6XHJcbiAgICAgICAgICAgICAgcHJpbnQoIGhleDQoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlOlxyXG4gICAgICAgICAgICAgIHByaW50KCBoZXg0KCB0aGlzLmN1cnJlbnRJUCArIDIgKyB2ICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNCOiAgLy8gMDFcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1Q6ICAvLyAwMlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREQjogIC8vIDAzXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldExCOiAgLy8gMDRcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQ6ICAvLyAwNVxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQQjogIC8vIDA2XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBUOiAgLy8gMDdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgIHZhciBzZWcgPSBbIFwiXCIsIFwiU0JcIiwgXCJTVFwiLCBcIkRCXCIsIFwiTEJcIiwgXCJEVFwiLCBcIlBCXCIsIFwiUFRcIiBdO1xyXG4gICAgICAgICAgICAgIHByaW50KCBzZWdbIGQgJiAweDA3IF0gKTtcclxuICAgICAgICAgICAgICBpZiAoIHYgPiAwIClcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIlsweFwiICsgaGV4KCB2ICkgKyBcIl1cIiApO1xyXG4gICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIltcIiArIHYgKyBcIl1cIiApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgaWYgKCBwYXJhbUluZGV4IDwgcGFyYW1Db3VudCAtIDEgKVxyXG4gICAgICAgICAgICBwcmludCggXCIsIFwiICk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHByaW50KCBcIlxcblwiICk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICggc3RlcFRvTmV4dElQIClcclxuICAgICAgICB0aGlzLmN1cnJlbnRJUCA9IG5leHRJUDtcclxuICAgIH1cclxuICAgIGNhdGNoKCBlIClcclxuICAgIHtcclxuICAgICAgcHJpbnQoIGUgKTtcclxuICAgIH07XHJcblxyXG5cclxuICAgIHJldHVybiBkaXNtVGV4dDtcclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gTVVMVE9TIGFkZHJlc3NlcyBhcmUgMTYtYml0IGxpbmVhciB2YWx1ZXMsIHdoZW4gcHVzaGVkIG9udG8gc3RhY2tcclxuICAvLyBhbmQgdXNlZCBmb3IgaW5kaXJlY3Rpb24uIFdlIG1hcCBhZGRyZXNzLXRhZyBhbmQgb2Zmc2V0IHBhaXJzIHRvIGxpbmVhclxyXG4gIC8vIGFkZHJlc3NlcywgYW5kIGJhY2sgYWdhaW4sIGJ5IGJhc2luZyBzdGF0aWMgYXQgMHgwMDAwLCBkeW5hbWljIGF0IDB4ODAwMFxyXG4gIC8vIGFuZCBwdWJsaWMgYXQgMHhGMDAwLlxyXG4gIC8vXHJcbiAgcHJpdmF0ZSBtYXBUb1NlZ21lbnRBZGRyKCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDAgKTtcclxuXHJcbiAgICBzd2l0Y2goIGFkZHJUYWcgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1M6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRCOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJMQjpcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQ6XHJcbiAgICAgICAgcmV0dXJuIDB4ODAwMCArIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0O1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU0I6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclNUOlxyXG4gICAgICAgIHJldHVybiB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldDtcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclBCOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJQVDpcclxuICAgICAgICByZXR1cm4gMHhGMDAwICsgdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQ7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIG1hcEZyb21TZWdtZW50QWRkciggc2VnbWVudEFkZHIgKVxyXG4gIHtcclxuICAgIGlmICggc2VnbWVudEFkZHIgJiAweDgwMDAgKVxyXG4gICAge1xyXG4gICAgICBpZiAoIHNlZ21lbnRBZGRyID49IDB4RjAwMCApXHJcbiAgICAgIHtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YUFyZWE6IHRoaXMucHVibGljQXJlYSxcclxuICAgICAgICAgIGRhdGFBZGRyVGFnOiBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUEIsXHJcbiAgICAgICAgICBkYXRhT2Zmc2V0OiBzZWdtZW50QWRkciAmIDB4MEZGRlxyXG4gICAgICAgIH07XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGFBcmVhOiB0aGlzLmR5bmFtaWNBcmVhLFxyXG4gICAgICAgICAgZGF0YUFkZHJUYWc6IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEQixcclxuICAgICAgICAgIGRhdGFPZmZzZXQ6IHNlZ21lbnRBZGRyICYgMHgzRkZGXHJcbiAgICAgICAgfTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgZWxzZVxyXG4gICAge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGFBcmVhOiB0aGlzLnN0YXRpY0FyZWEsXHJcbiAgICAgICAgZGF0YUFkZHJUYWc6IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJTQixcclxuICAgICAgICBkYXRhT2Zmc2V0OiBzZWdtZW50QWRkciAmIDB4N0ZGRlxyXG4gICAgICB9O1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLy9cclxuICAvLyB2YWxpZGF0ZSBhIG11bHRpLWJ5dGUgbWVtb3J5IGFjY2Vzcywgc3BlY2lmaWVkIGJ5IGFkZHJlc3MtdGFnL29mZnNldCBwYWlyXHJcbiAgLy8gYW5kIGxlbmd0aCB2YWx1ZXMuIElmIG9rLCBtYXAgdG8gYW4gYXJlYSBhbmQgb2Zmc2V0IHdpdGhpbiB0aGF0IGFyZWEuXHJcbiAgLy8gQ2FuIGFjY2VwdCBwb3NpdGl2ZS9uZWdhdGl2ZSBvZmZzZXRzLCBzaW5jZSB0aGV5IGFyZWEgcmVsYXRpdmUgdG8gdGhlXHJcbiAgLy8gdGhlIHRvcCBvciB0aGUgYm90dG9tIG9mIHRoZSBzcGVjaWZpZWQgYXJlYSwgYXMgaW5kaWNhdGVkIGJ5IHRoZSB0YWcuXHJcbiAgLy9cclxuICBwcml2YXRlIGNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgb2Zmc2V0LCBsZW5ndGggKVxyXG4gIHtcclxuICAgIHZhciBkYXRhQXJlYTtcclxuICAgIHZhciBkYXRhT2Zmc2V0ID0gb2Zmc2V0O1xyXG4gICAgdmFyIGFyZWFMaW1pdDtcclxuXHJcbiAgICBzd2l0Y2goIGFkZHJUYWcgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1M6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLmR5bmFtaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuZHluYW1pY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSB0aGlzLmxvY2FsQmFzZTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRCOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5keW5hbWljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLmR5bmFtaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyTEI6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLmR5bmFtaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuZHluYW1pY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSB0aGlzLmxvY2FsQmFzZTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRUOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5keW5hbWljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLmR5bmFtaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gdGhpcy5keW5hbWljVG9wO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU0I6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnN0YXRpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5zdGF0aWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU1Q6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnN0YXRpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5zdGF0aWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gYXJlYUxpbWl0O1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUEI6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnB1YmxpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUFQ6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnB1YmxpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gYXJlYUxpbWl0O1xyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgfVxyXG5cclxuICAgIGRhdGFPZmZzZXQgJj0gMHhmZmZmOyAvLyAxNiBiaXRzIGFkZHJlc3Nlc1xyXG4gICAgaWYgKCAoIGRhdGFPZmZzZXQgPCBhcmVhTGltaXQgKSAmJiAoIGRhdGFPZmZzZXQgKyBsZW5ndGggPCBhcmVhTGltaXQgKSApXHJcbiAgICB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YUFyZWE6IGRhdGFBcmVhLFxyXG4gICAgICAgIGRhdGFPZmZzZXQ6IGRhdGFPZmZzZXRcclxuICAgICAgfTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gcGVyZm9ybSBhIHZhbGlkYXRlZCBtdWx0aS1ieXRlIHJlYWQsIHNwZWNpZmllZCBieSBhZGRyZXNzLXRhZy9vZmZzZXQgcGFpciBhbmRcclxuICAvLyBsZW5ndGggdmFsdWVzLiBSZXR1cm4gZGF0YS1hcnJheSwgb3IgdW5kZWZpbmVkXHJcbiAgLy9cclxuICBwcml2YXRlIHJlYWRTZWdtZW50RGF0YSggYWRkclRhZywgb2Zmc2V0LCBsZW5ndGggKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgb2Zmc2V0LCAxICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgcmV0dXJuIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS5yZWFkQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBsZW5ndGggKTtcclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gcGVyZm9ybSBhIHZhbGlkYXRlZCBtdWx0aS1ieXRlIHdyaXRlLCBzcGVjaWZpZWQgYnkgYWRkcmVzcy10YWcvb2Zmc2V0IHBhaXIgYW5kXHJcbiAgLy8gZGF0YS1hcnJheSB0byBiZSB3cml0dGVuLlxyXG4gIC8vXHJcbiAgcHJpdmF0ZSB3cml0ZVNlZ21lbnREYXRhKCBhZGRyVGFnLCBvZmZzZXQsIHZhbCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBvZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEud3JpdGVCeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIHZhbCApO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwdXNoWmVyb3NUb1N0YWNrKCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY0FyZWEuemVyb0J5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIGNudCApO1xyXG5cclxuICAgIHRoaXMuZHluYW1pY1RvcCArPSBjbnQ7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHB1c2hDb25zdFRvU3RhY2soIGNudCwgdmFsIClcclxuICB7XHJcbiAgICBpZiAoIGNudCA9PSAxIClcclxuICAgICAgdGhpcy5keW5hbWljQXJlYS53cml0ZUJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIFsgdmFsIF0gKTtcclxuICAgIGVsc2VcclxuICAgICAgdGhpcy5keW5hbWljQXJlYS53cml0ZUJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIFcyQkEoIHZhbCApICk7XHJcblxyXG4gICAgdGhpcy5keW5hbWljVG9wICs9IGNudDtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgY29weU9uU3RhY2soIGZyb21PZmZzZXQsIHRvT2Zmc2V0LCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY0FyZWEuY29weUJ5dGVzKCBmcm9tT2Zmc2V0LCB0b09mZnNldCwgY250ICk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHB1c2hUb1N0YWNrKCBhZGRyVGFnLCBvZmZzZXQsIGNudCApXHJcbiAge1xyXG4gICAgdGhpcy5keW5hbWljVG9wICs9IGNudDtcclxuICAgIHRoaXMuZHluYW1pY0FyZWEud3JpdGVCeXRlcyggdGhpcy5keW5hbWljVG9wLCB0aGlzLnJlYWRTZWdtZW50RGF0YSggYWRkclRhZywgb2Zmc2V0LCBjbnQgKSApO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwb3BGcm9tU3RhY2tBbmRTdG9yZSggYWRkclRhZywgb2Zmc2V0LCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY1RvcCAtPSBjbnQ7XHJcblxyXG4gICAgdGhpcy53cml0ZVNlZ21lbnREYXRhKCBhZGRyVGFnLCBvZmZzZXQsIHRoaXMuZHluYW1pY0FyZWEucmVhZEJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIGNudCApICk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBvcEZyb21TdGFjayggY250IClcclxuICB7XHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgLT0gY250O1xyXG5cclxuICAgIHJldHVybiB0aGlzLmR5bmFtaWNBcmVhLnJlYWRCeXRlcyggdGhpcy5keW5hbWljVG9wLCBjbnQgKTtcclxuICB9XHJcblxyXG4gIC8vIHNldHVwIGFwcGxpY2F0aW9uIGZvciBleGVjdXRpb25cclxuICBzZXR1cEFwcGxpY2F0aW9uKCBleGVjUGFyYW1zIClcclxuICB7XHJcbiAgICB0aGlzLmNvZGVBcmVhID0gZXhlY1BhcmFtcy5jb2RlQXJlYTtcclxuICAgIHRoaXMuc3RhdGljQXJlYSA9IGV4ZWNQYXJhbXMuc3RhdGljQXJlYTtcclxuICAgIHRoaXMuc2Vzc2lvblNpemUgPSBleGVjUGFyYW1zLnNlc3Npb25TaXplO1xyXG5cclxuICAgIHRoaXMuZHluYW1pY0FyZWEgPSB0aGlzLnJhbVNlZ21lbnQubmV3QWNjZXNzb3IoIDAsIDUxMiwgXCJEXCIgKTsgLy9UT0RPOiBleGVjUGFyYW1zLnNlc3Npb25TaXplXHJcblxyXG4gICAgdGhpcy5pbml0RXhlY3V0aW9uKCk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGluaXRFeGVjdXRpb24oKVxyXG4gIHtcclxuICAgIHRoaXMuY3VycmVudElQID0gMDtcclxuICAgIHRoaXMuaXNFeGVjdXRpbmcgPSB0cnVlO1xyXG5cclxuICAgIC8vIFRPRE86IFNlcGFyYXRlIHN0YWNrIGFuZCBzZXNzaW9uXHJcbiAgICB0aGlzLmxvY2FsQmFzZSA9IHRoaXMuc2Vzc2lvblNpemU7XHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgPSB0aGlzLmxvY2FsQmFzZTtcclxuXHJcbiAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgPSAwO1xyXG4gIH1cclxuXHJcbiAgc2VncyA9IFsgXCJcIiwgXCJTQlwiLCBcIlNUXCIsIFwiREJcIiwgXCJMQlwiLCBcIkRUXCIsIFwiUEJcIiwgXCJQVFwiIF07XHJcblxyXG4gIHByaXZhdGUgY29uc3RCeXRlQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIGNvbnN0VmFsLCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICB2YXIgdGVtcFZhbCA9IHRhcmdldEFjY2Vzcy5kYXRhQXJlYS5yZWFkQnl0ZSggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQgKTtcclxuXHJcbiAgICBzd2l0Y2goIG9wQ29kZSApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsICsgY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPCBjb25zdFZhbCApICAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQkI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCAtIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsID4gY29uc3RWYWwgKSAgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgLSBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA+IGNvbnN0VmFsICkgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTRVRCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSBjb25zdFZhbDtcclxuICAgICAgICBicmVhaztcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIHRlbXBWYWwgPT0gMCApXHJcbiAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9aO1xyXG5cclxuICAgIGlmICggb3BDb2RlICE9IE1FTC5NRUxJTlNULm1lbENNUEIgKVxyXG4gICAge1xyXG4gICAgICB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEud3JpdGVCeXRlKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgdGVtcFZhbCApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBjb25zdFdvcmRCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgY29uc3RWYWwsIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMiApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHZhciB0ZW1wVmFsID0gQkEyVyggdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLnJlYWRCeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIDIgKSApO1xyXG5cclxuICAgIHN3aXRjaCggb3BDb2RlIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBRERCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgKyBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA8IGNvbnN0VmFsICkgIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1VCQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsIC0gY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPiBjb25zdFZhbCApICAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENNUEI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCAtIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsID4gY29uc3RWYWwgKSAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVEI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9IGNvbnN0VmFsO1xyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICggdGVtcFZhbCA9PSAwIClcclxuICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX1o7XHJcblxyXG4gICAgaWYgKCBvcENvZGUgIT0gTUVMLk1FTElOU1QubWVsQ01QVyApXHJcbiAgICB7XHJcbiAgICAgIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS53cml0ZUJ5dGVzKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgVzJCQSggdGVtcFZhbCApICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBvcFNpemUsIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMSApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHRoaXMuY2hlY2tEYXRhQWNjZXNzKCAtb3BTaXplIC0gMSwgb3BTaXplLCBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TICk7IC8vIEZpcnN0XHJcblxyXG4gICAgLy8gdG9kbzpcclxuICB9XHJcblxyXG4gIHByaXZhdGUgdW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgb3BTaXplLCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICBzd2l0Y2goIG9wQ29kZSApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ0xFQVJOOlxyXG4gICAgICAgIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS56ZXJvQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBvcFNpemUgKTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsVEVTVE46ICAgICAgICAgLy8gMTZcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxJTkNOOiAgICAgICAgICAvLyAxN1xyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbERFQ046ICAgICAgICAgIC8vIDE4XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTk9UTjogICAgICAgICAgLy8gMTlcclxuICAgICAgICA7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGhhbmRsZVJldHVybiggaW5CeXRlcywgb3V0Qnl0ZXMgKVxyXG4gIHtcclxuICAgIHZhciByZXRWYWxPZmZzZXQgPSB0aGlzLmR5bmFtaWNUb3AgLSBvdXRCeXRlcztcclxuXHJcbiAgICB2YXIgcmV0dXJuSVAgPSBCQTJXKCB0aGlzLmR5bmFtaWNBcmVhLnJlYWRCeXRlcyggdGhpcy5sb2NhbEJhc2UgLSAyLCAyICkgKTtcclxuICAgIHRoaXMubG9jYWxCYXNlID0gQkEyVyggdGhpcy5keW5hbWljQXJlYS5yZWFkQnl0ZXMoIHRoaXMubG9jYWxCYXNlIC0gNCwgMiApICk7XHJcblxyXG4gICAgdGhpcy5keW5hbWljVG9wID0gdGhpcy5sb2NhbEJhc2UgKyBvdXRCeXRlcztcclxuICAgIGlmICggb3V0Qnl0ZXMgKVxyXG4gICAgICB0aGlzLmNvcHlPblN0YWNrKCByZXRWYWxPZmZzZXQsIHRoaXMubG9jYWxCYXNlLCBvdXRCeXRlcyApO1xyXG5cclxuICAgIHJldHVybiByZXR1cm5JUDtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgaXNDb25kaXRpb24oIHRhZyApXHJcbiAge1xyXG4gICAgc3dpdGNoKCB0YWcgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRFUTpcclxuICAgICAgICByZXR1cm4gKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZExUOlxyXG4gICAgICAgIHJldHVybiAhKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9DICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZExFOlxyXG4gICAgICAgIHJldHVybiAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX1ogKSB8fCAhKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9DICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZEdUOlxyXG4gICAgICAgIHJldHVybiAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX0MgKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kR0U6XHJcbiAgICAgICAgcmV0dXJuICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfWiApIHx8ICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfQyApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRORTpcclxuICAgICAgICByZXR1cm4gISggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRBTEw6XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgIGRlZmF1bHQ6IC8vIG1lbENvbmRTUEVDXHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGZhbHNlO1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZVN0ZXAoKVxyXG4gIHtcclxuICAgIHRyeVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV4dElQID0gdGhpcy5jdXJyZW50SVA7XHJcbiAgICAgIHZhciBpbnN0Qnl0ZSA9IHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICk7XHJcbiAgICAgIHZhciBwYXJhbUNvdW50ID0gMDtcclxuICAgICAgdmFyIHBhcmFtVmFsID0gW107XHJcbiAgICAgIHZhciBwYXJhbURlZiA9IFtdO1xyXG5cclxuICAgICAgdmFyIG1lbEluc3QgPSBNRUwuTUVMRGVjb2RlWyBpbnN0Qnl0ZSBdO1xyXG5cclxuICAgICAgaWYgKCBtZWxJbnN0ID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHtcclxuICAgICAgICByZXR1cm4gbnVsbDtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICB2YXIgcGFyYW1EZWZzID0gbWVsSW5zdC5wYXJhbURlZnM7XHJcblxyXG4gICAgICAgIHdoaWxlKCBwYXJhbURlZnMgIT0gMCApXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcGFyYW1EZWZbIHBhcmFtQ291bnQgXSA9IHBhcmFtRGVmcyAmIDB4RkY7XHJcbiAgICAgICAgICBzd2l0Y2goIHBhcmFtRGVmcyAmIDB4RjAgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIDB4MDA6IGJyZWFrO1xyXG4gICAgICAgICAgICBjYXNlIDB4MTA6IHBhcmFtVmFsWyBwYXJhbUNvdW50IF0gPSB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApOyBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAweDIwOiBwYXJhbVZhbFsgcGFyYW1Db3VudCBdID0gQkEyVyggWyB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApLCB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApIF0gKTsgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBwYXJhbUNvdW50Kys7XHJcbiAgICAgICAgICBwYXJhbURlZnMgPj49IDg7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICB2YXIgb3BDb2RlID0gTUVMLk1FTDJPUENPREUoIGluc3RCeXRlICk7XHJcbiAgICAgIHZhciB0YWcgPSBNRUwuTUVMMlRBRyggaW5zdEJ5dGUgKTtcclxuXHJcbiAgICAgIHN3aXRjaCggb3BDb2RlIClcclxuICAgICAge1xyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1lTVEVNOiAgICAgICAgLy8gMDBcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgcHVibGljVG9wID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG5cclxuICAgICAgICAgIHN3aXRjaCggdGFnIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1FeGl0OlxyXG4gICAgICAgICAgICAgIHRoaXMuaXNFeGVjdXRpbmcgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAvL25vIGJyZWFrXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtTk9QOlxyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1FeGl0U1c6XHJcbiAgICAgICAgICAgICAgdGhpcy5pc0V4ZWN1dGluZyA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgIC8vbm8gYnJlYWtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1TZXRTVzpcclxuICAgICAgICAgICAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gMiwgVzJCQSggcGFyYW1WYWxbIDAgXSApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbUV4aXRMYTpcclxuICAgICAgICAgICAgICB0aGlzLmlzRXhlY3V0aW5nID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgLy9ubyBicmVha1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbVNldExhOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSA0LCBXMkJBKCBwYXJhbVZhbFsgMCBdICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtRXhpdFNXTGE6XHJcbiAgICAgICAgICAgICAgdGhpcy5pc0V4ZWN1dGluZyA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgIC8vbm8gYnJlYWtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1TZXRTV0xhOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSAyLCBXMkJBKCBwYXJhbVZhbFsgMCBdICkgKTtcclxuICAgICAgICAgICAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gNCwgVzJCQSggcGFyYW1WYWxbIDEgXSApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQlJBTkNIOiAgICAgICAgLy8gMDFcclxuICAgICAgICAgIGlmICggdGhpcy5pc0NvbmRpdGlvbiggdGFnICkgKVxyXG4gICAgICAgICAgICBuZXh0SVAgPSBuZXh0SVAgKyBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSlVNUDogICAgICAgICAgLy8gMDJcclxuICAgICAgICAgIGlmICggdGhpcy5pc0NvbmRpdGlvbiggdGFnICkgKVxyXG4gICAgICAgICAgICBuZXh0SVAgPSBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ0FMTDogICAgICAgICAgLy8gMDNcclxuICAgICAgICAgIGlmICggdGhpcy5pc0NvbmRpdGlvbiggdGFnICkgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDIsIHRoaXMubG9jYWxCYXNlICk7XHJcbiAgICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMiwgbmV4dElQICk7XHJcblxyXG4gICAgICAgICAgICBuZXh0SVAgPSBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgICB0aGlzLmxvY2FsQmFzZSA9IHRoaXMuZHluYW1pY1RvcDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNUQUNLOiAgICAgICAgIC8vIDA0XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgc3dpdGNoKCB0YWcgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BVU0haOlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgdGhpcy5wdXNoWmVyb3NUb1N0YWNrKCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIQjpcclxuICAgICAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDEsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSFc6XHJcbiAgICAgICAgICAgICAgdGhpcy5wdXNoQ29uc3RUb1N0YWNrKCAyLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BPUE46XHJcbiAgICAgICAgICAgICAgdGhpcy5wb3BGcm9tU3RhY2soIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QQjpcclxuICAgICAgICAgICAgICB0aGlzLnBvcEZyb21TdGFjayggMSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BXOlxyXG4gICAgICAgICAgICAgIHRoaXMucG9wRnJvbVN0YWNrKCAyICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsUFJJTVJFVDogICAgICAgLy8gMDVcclxuICAgICAgICB7XHJcbiAgICAgICAgICBzd2l0Y2goIHRhZyApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0wOlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMTpcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTI6XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0zOlxyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCAwLCAwICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCBwYXJhbVZhbFsgMCBdLCAwICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRPOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCAwLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJTzpcclxuICAgICAgICAgICAgICBuZXh0SVAgPSB0aGlzLmhhbmRsZVJldHVybiggcGFyYW1WYWxbIDAgXSwgcGFyYW1WYWxbIDEgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbExPQUQ6ICAgICAgICAgIC8vIDA3XHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgLy8gRFVQIFRPU1xyXG4gICAgICAgICAgICB0aGlzLmNvcHlPblN0YWNrKCB0aGlzLmR5bmFtaWNUb3AgLSBwYXJhbVZhbFsgMCBdLCB0aGlzLmR5bmFtaWNUb3AsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgdGhpcy5keW5hbWljVG9wICs9IHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMucHVzaFRvU3RhY2soIHRhZywgcGFyYW1WYWxbIDEgXSwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1RPUkU6ICAgICAgICAgLy8gMDhcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICAvLyBTSElGVCBUT1NcclxuICAgICAgICAgICAgdGhpcy5keW5hbWljVG9wIC09IHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICAgIHRoaXMuY29weU9uU3RhY2soIHRoaXMuZHluYW1pY1RvcCwgdGhpcy5keW5hbWljVG9wIC0gcGFyYW1WYWxbIDAgXSwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLnBvcEZyb21TdGFja0FuZFN0b3JlKCB0YWcsIHBhcmFtVmFsWyAxIF0sIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxMT0FESTogICAgICAgICAvLyAwOVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciBzZWdtZW50QWRkciA9IEJBMlcoIHRoaXMucmVhZFNlZ21lbnREYXRhKCB0YWcsIHBhcmFtVmFsWyAxIF0sIDIgKSApO1xyXG4gICAgICAgICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMubWFwRnJvbVNlZ21lbnRBZGRyKCBzZWdtZW50QWRkciApO1xyXG4gICAgICAgICAgdGhpcy5wdXNoVG9TdGFjayggdGFyZ2V0QWNjZXNzLmRhdGFBZGRyVGFnLCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNUT1JFSTogICAgICAgIC8vIDBBXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIHNlZ21lbnRBZGRyID0gQkEyVyggdGhpcy5yZWFkU2VnbWVudERhdGEoIHRhZywgcGFyYW1WYWxbIDEgXSwgMiApICk7XHJcbiAgICAgICAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5tYXBGcm9tU2VnbWVudEFkZHIoIHNlZ21lbnRBZGRyICk7XHJcbiAgICAgICAgICB0aGlzLnBvcEZyb21TdGFja0FuZFN0b3JlKCB0YXJnZXRBY2Nlc3MuZGF0YUFkZHJUYWcsIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTE9BREE6ICAgICAgICAgLy8gMEJcclxuICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMiwgdGhpcy5tYXBUb1NlZ21lbnRBZGRyKCB0YWcsIHBhcmFtVmFsWyAwIF0gKSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSU5ERVg6ICAgICAgICAgLy8gMENcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVEI6ICAgICAgICAgIC8vIDBEXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBCOiAgICAgICAgICAvLyAwRVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREQjogICAgICAgICAgLy8gMEZcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQkI6ICAgICAgICAgIC8vIDEwXHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy5jb25zdEJ5dGVCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTEgKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5jb25zdEJ5dGVCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIHRhZywgcGFyYW1WYWxbMV0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVFc6ICAgICAgICAgIC8vIDExXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBXOiAgICAgICAgICAvLyAxMlxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREVzogICAgICAgICAgLy8gMTNcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQlc6ICAgICAgICAgIC8vIDE0XHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy5jb25zdFdvcmRCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTIgKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5jb25zdFdvcmRCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIHRhZywgcGFyYW1WYWxbMV0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENMRUFSTjogICAgICAgIC8vIDE1XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxURVNUTjogICAgICAgICAvLyAxNlxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSU5DTjogICAgICAgICAgLy8gMTdcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbERFQ046ICAgICAgICAgIC8vIDE4XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxOT1ROOiAgICAgICAgICAvLyAxOVxyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICAgIHRoaXMudW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTEgKiBwYXJhbVZhbFswXSApO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLnVuYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCB0YWcsIHBhcmFtVmFsWzFdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBOOiAgICAgICAgICAvLyAxQVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQURETjogICAgICAgICAgLy8gMUJcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQk46ICAgICAgICAgIC8vIDFDXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBTkROOiAgICAgICAgICAvLyAxRFxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsT1JOOiAgICAgICAgICAgLy8gMUVcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFhPUk46ICAgICAgICAgIC8vIDFGXHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy5iaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTIgKiBwYXJhbVZhbFswXSApO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLmJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgdGFnLCBwYXJhbVZhbFsxXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuY3VycmVudElQID0gbmV4dElQO1xyXG4gICAgfVxyXG4gICAgY2F0Y2goIGUgKVxyXG4gICAge1xyXG4gICAgICAvL3ByaW50KCBlICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBzZXRDb21tYW5kQVBEVSggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVIClcclxuICB7XHJcbiAgICB2YXIgcHVibGljVG9wID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG5cclxuICAgIC8vIC0yLC0xID0gU1cxMlxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDIsIFcyQkEoIDB4OTAwMCApICk7XHJcblxyXG4gICAgLy8gLTQsLTMgPSBMYVxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDQsIFcyQkEoIDB4MDAwMCApICk7XHJcblxyXG4gICAgLy8gLTYsLTUgPSBMZVxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDYsIFcyQkEoIGNvbW1hbmRBUERVLkxlICkgKTtcclxuXHJcbiAgICAvLyAtOCwtNyA9IExjXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gOCwgVzJCQSggY29tbWFuZEFQRFUuZGF0YS5sZW5ndGggKSApO1xyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDEzLCBjb21tYW5kQVBEVS5oZWFkZXIgKTtcclxuXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggMCwgY29tbWFuZEFQRFUuZGF0YSApO1xyXG5cclxuICAgIHRoaXMuaW5pdEV4ZWN1dGlvbigpO1xyXG4gIH1cclxuXHJcbiAgZ2V0UmVzcG9uc2VBUERVKCk6IFJlc3BvbnNlQVBEVVxyXG4gIHtcclxuICAgIHZhciBwdWJsaWNUb3AgPSB0aGlzLnB1YmxpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcblxyXG4gICAgdmFyIGxhID0gQkEyVyggdGhpcy5wdWJsaWNBcmVhLnJlYWRCeXRlcyggcHVibGljVG9wIC0gNCwgMiApICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IEJBMlcoIHRoaXMucHVibGljQXJlYS5yZWFkQnl0ZXMoIHB1YmxpY1RvcCAtIDIsIDIgKSApLCBkYXRhOiB0aGlzLnB1YmxpY0FyZWEucmVhZEJ5dGVzKCAwLCBsYSApICB9IClcclxuXHJcbiAgfVxyXG5cclxuICBnZXQgZ2V0RGVidWcoKToge31cclxuICB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICByYW1TZWdtZW50OiB0aGlzLnJhbVNlZ21lbnQsXHJcbiAgICAgIGR5bmFtaWNBcmVhOiB0aGlzLmR5bmFtaWNBcmVhLFxyXG4gICAgICBwdWJsaWNBcmVhOiB0aGlzLnB1YmxpY0FyZWEsXHJcbiAgICAgIHN0YXRpY0FyZWE6IHRoaXMuc3RhdGljQXJlYSxcclxuICAgICAgY3VycmVudElQOiB0aGlzLmN1cnJlbnRJUCxcclxuICAgICAgZHluYW1pY1RvcDogdGhpcy5keW5hbWljVG9wLFxyXG4gICAgICBsb2NhbEJhc2U6IHRoaXMubG9jYWxCYXNlXHJcbiAgICB9O1xyXG4gIH1cclxuLy8gIGlzRXhlY3V0aW5nOiBmdW5jdGlvbigpIHsgcmV0dXJuIGlzRXhlY3V0aW5nOyB9LFxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5pbXBvcnQgeyBNZW1vcnlNYW5hZ2VyLCBNRU1GTEFHUyB9IGZyb20gJy4vbWVtb3J5LW1hbmFnZXInO1xyXG5pbXBvcnQgeyBNRUxWaXJ0dWFsTWFjaGluZSB9IGZyb20gJy4vdmlydHVhbC1tYWNoaW5lJztcclxuXHJcbmltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuLi9pc283ODE2L0lTTzc4MTYnO1xyXG5pbXBvcnQgeyBDb21tYW5kQVBEVSB9IGZyb20gJy4uL2lzbzc4MTYvY29tbWFuZC1hcGR1JztcclxuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vaXNvNzgxNi9yZXNwb25zZS1hcGR1JztcclxuXHJcbmltcG9ydCB7IEpTSU1DYXJkIH0gZnJvbSAnLi4vanNpbS1jYXJkL2pzaW0tY2FyZCc7XHJcblxyXG5mdW5jdGlvbiAgQkEyVyggdmFsIClcclxue1xyXG4gIHJldHVybiAoIHZhbFsgMCBdIDw8IDggKSB8IHZhbFsgMSBdO1xyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgSlNJTU11bHRvc0FwcGxldFxyXG57XHJcbiAgc2Vzc2lvblNpemU7XHJcbiAgY29kZUFyZWE7XHJcbiAgc3RhdGljQXJlYTtcclxuXHJcbiAgY29uc3RydWN0b3IoIGNvZGVBcmVhLCBzdGF0aWNBcmVhLCBzZXNzaW9uU2l6ZSApXHJcbiAge1xyXG4gICAgdGhpcy5jb2RlQXJlYSA9IGNvZGVBcmVhO1xyXG4gICAgdGhpcy5zdGF0aWNBcmVhID0gc3RhdGljQXJlYTtcclxuICAgIHRoaXMuc2Vzc2lvblNpemUgPSBzZXNzaW9uU2l6ZTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBKU0lNTXVsdG9zQ2FyZCBpbXBsZW1lbnRzIEpTSU1DYXJkXHJcbntcclxuICBwcml2YXRlIGNhcmRDb25maWc7XHJcblxyXG4gIHN0YXRpYyBkZWZhdWx0Q29uZmlnID0ge1xyXG4gICAgcm9tU2l6ZTogMCxcclxuICAgIHJhbVNpemU6IDEwMjQsXHJcbiAgICBwdWJsaWNTaXplOiA1MTIsXHJcbiAgICBudnJhbVNpemU6IDMyNzY4XHJcbiAgfTtcclxuXHJcbiAgcHJpdmF0ZSBwb3dlcklzT246IGJvb2xlYW47XHJcbiAgcHJpdmF0ZSBhdHI6IEJ5dGVBcnJheTtcclxuXHJcbiAgYXBwbGV0czogeyBhaWQ6IEJ5dGVBcnJheSwgYXBwbGV0OiBKU0lNTXVsdG9zQXBwbGV0IH1bXTtcclxuXHJcbiAgc2VsZWN0ZWRBcHBsZXQ6IEpTSU1NdWx0b3NBcHBsZXQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCBjb25maWc/IClcclxuICB7XHJcbiAgICBpZiAoIGNvbmZpZyApXHJcbiAgICAgIHRoaXMuY2FyZENvbmZpZyA9IGNvbmZpZztcclxuICAgIGVsc2VcclxuICAgICAgdGhpcy5jYXJkQ29uZmlnID0gSlNJTU11bHRvc0NhcmQuZGVmYXVsdENvbmZpZztcclxuXHJcbiAgICB0aGlzLmF0ciA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcblxyXG4gICAgdGhpcy5hcHBsZXRzID0gW107XHJcbiAgfVxyXG5cclxuICBsb2FkQXBwbGljYXRpb24oIGFpZDogQnl0ZUFycmF5LCBhbHU6IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgdmFyIGxlbiA9IDA7XHJcblxyXG4gICAgdmFyIG9mZiA9IDg7XHJcblxyXG4gICAgLy8gTEVOOjpDT0RFXHJcbiAgICBsZW4gPSBhbHUud29yZEF0KCBvZmYgKTtcclxuICAgIG9mZiArPSAyO1xyXG5cclxuICAgIGxldCBjb2RlQXJlYSA9IHRoaXMubnZyYW1TZWdtZW50Lm5ld0FjY2Vzc29yKCAwLCBsZW4sIFwiY29kZVwiICk7XHJcbiAgICBjb2RlQXJlYS53cml0ZUJ5dGVzKCAwLCBhbHUudmlld0F0KCBvZmYsIGxlbiApICk7XHJcbiAgICBvZmYgKz0gbGVuO1xyXG5cclxuICAgIC8vIExFTjo6REFUQVxyXG4gICAgbGVuID0gYWx1LndvcmRBdCggb2ZmICk7XHJcbiAgICBvZmYgKz0gMjtcclxuXHJcbiAgICBsZXQgc3RhdGljQXJlYSA9IHRoaXMubnZyYW1TZWdtZW50Lm5ld0FjY2Vzc29yKCBjb2RlQXJlYS5nZXRMZW5ndGgoKSwgbGVuLCBcIlNcIiApO1xyXG4gICAgc3RhdGljQXJlYS53cml0ZUJ5dGVzKCAwLCBhbHUudmlld0F0KCBvZmYsIGxlbiApICk7XHJcbiAgICBvZmYgKz0gbGVuO1xyXG5cclxuICAgIGxldCBhcHBsZXQgPSBuZXcgSlNJTU11bHRvc0FwcGxldCggY29kZUFyZWEsIHN0YXRpY0FyZWEsIDAgKTtcclxuXHJcbiAgICB0aGlzLmFwcGxldHMucHVzaCggeyBhaWQ6IGFpZCwgYXBwbGV0OiBhcHBsZXQgfSApO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIGdldCBpc1Bvd2VyZWQoKTogYm9vbGVhblxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLnBvd2VySXNPbjtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PlxyXG4gIHtcclxuICAgIHRoaXMucG93ZXJJc09uID0gdHJ1ZTtcclxuXHJcbiAgICB0aGlzLmluaXRpYWxpemVWTSggdGhpcy5jYXJkQ29uZmlnICk7XHJcblxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSggdGhpcy5hdHIgKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBwb3dlck9mZigpOiBQcm9taXNlPGFueT5cclxuICB7XHJcbiAgICB0aGlzLnBvd2VySXNPbiA9IGZhbHNlO1xyXG5cclxuICAgIHRoaXMucmVzZXRWTSgpO1xyXG5cclxuICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XHJcblxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSggICk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcmVzZXQoKTogUHJvbWlzZTxCeXRlQXJyYXk+XHJcbiAge1xyXG4gICAgdGhpcy5wb3dlcklzT24gPSB0cnVlO1xyXG5cclxuICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XHJcblxyXG4gICAgdGhpcy5zaHV0ZG93blZNKCk7XHJcblxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSggdGhpcy5hdHIgKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBleGNoYW5nZUFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cclxuICB7XHJcbiAgICBpZiAoIGNvbW1hbmRBUERVLklOUyA9PSAweEE0IClcclxuICAgIHtcclxuICAgICAgaWYgKCB0aGlzLnNlbGVjdGVkQXBwbGV0IClcclxuICAgICAge1xyXG4gICAgICAgIC8vdGhpcy5zZWxlY3RlZEFwcGxldC5kZXNlbGVjdEFwcGxpY2F0aW9uKCk7XHJcblxyXG4gICAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIC8vVE9ETzogTG9va3VwIEFwcGxpY2F0aW9uXHJcbiAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB0aGlzLmFwcGxldHNbIDAgXS5hcHBsZXQ7XHJcblxyXG4gICAgICBsZXQgZmNpID0gbmV3IEJ5dGVBcnJheSggWyAweDZGLCAweDAwIF0gKTtcclxuXHJcbiAgICAgIHRoaXMubXZtLnNldHVwQXBwbGljYXRpb24oIHRoaXMuc2VsZWN0ZWRBcHBsZXQgKTtcclxuXHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmU8UmVzcG9uc2VBUERVPiggbmV3IFJlc3BvbnNlQVBEVSggeyBzdzogMHg5MDAwLCBkYXRhOiBmY2kgIH0gKSApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMubXZtLnNldENvbW1hbmRBUERVKCBjb21tYW5kQVBEVSk7XHJcblxyXG4vLyAgICBnZXRSZXNwb25zZUFQRFUoKVxyXG4vLyAgICB7XHJcbi8vICAgICAgcmV0dXJuIHRoaXMubXZtLmdldFJlc3BvbnNlQVBEVSgpO1xyXG4vLyAgICB9XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4OTAwMCwgZGF0YTogW10gIH0gKSApO1xyXG5cclxuICAgIC8vcmV0dXJuIHRoaXMuZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVICk7XHJcbiAgfVxyXG5cclxuICBtZW1vcnlNYW5hZ2VyOiBNZW1vcnlNYW5hZ2VyO1xyXG5cclxuICAvLyBDYXJkIE1lbW9yeSBTZWdtZW50c1xyXG4gIHJvbVNlZ21lbnQ7ICAgICAgLy8gUk9NOiBjb2RlbGV0c1xyXG4gIG52cmFtU2VnbWVudDsgICAgLy8gTlZSQU06IGFwcGxldHMgY29kZSArIGRhdGFcclxuICByYW1TZWdtZW50OyAgICAgIC8vIFJBTTogd29ya3NwYWNlXHJcblxyXG4gIG12bTtcclxuXHJcbiAgaW5pdGlhbGl6ZVZNKCBjb25maWcgKVxyXG4gIHtcclxuICAgIHRoaXMubWVtb3J5TWFuYWdlciA9IG5ldyBNZW1vcnlNYW5hZ2VyKCk7XHJcblxyXG4gICAgdGhpcy5yb21TZWdtZW50ID0gdGhpcy5tZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQoIDAsIHRoaXMuY2FyZENvbmZpZy5yb21TaXplLCBNRU1GTEFHUy5SRUFEX09OTFkgKVxyXG4gICAgdGhpcy5yYW1TZWdtZW50ID0gdGhpcy5tZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQoIDEsIHRoaXMuY2FyZENvbmZpZy5yYW1TaXplLCAwICk7XHJcbiAgICB0aGlzLm52cmFtU2VnbWVudCA9IHRoaXMubWVtb3J5TWFuYWdlci5uZXdTZWdtZW50KCAyLCB0aGlzLmNhcmRDb25maWcubnZyYW1TaXplLCBNRU1GTEFHUy5UUkFOU0FDVElPTkFCTEUgKTtcclxuXHJcbiAgICB0aGlzLm12bSA9IG5ldyBNRUxWaXJ0dWFsTWFjaGluZSgpO1xyXG5cclxuICAgIHRoaXMucmVzZXRWTSgpO1xyXG4gIH1cclxuXHJcbiAgcmVzZXRWTSgpXHJcbiAge1xyXG4gICAgLy8gZmlyc3QgdGltZSAuLi5cclxuICAgIC8vIGluaXQgVmlydHVhbE1hY2hpbmVcclxuICAgIHZhciBtdm1QYXJhbXMgPSB7XHJcbiAgICAgIHJhbVNlZ21lbnQ6IHRoaXMucmFtU2VnbWVudCxcclxuICAgICAgcm9tU2VnbWVudDogdGhpcy5yb21TZWdtZW50LFxyXG4gICAgICBwdWJsaWNTaXplOiB0aGlzLmNhcmRDb25maWcucHVibGljU2l6ZVxyXG4gICAgfTtcclxuXHJcbiAgICB0aGlzLm12bS5pbml0TVZNKCBtdm1QYXJhbXMgKTtcclxuICB9XHJcblxyXG4gIHNodXRkb3duVk0oKVxyXG4gIHtcclxuICAgIHRoaXMucmVzZXRWTSgpO1xyXG4gICAgdGhpcy5tdm0gPSBudWxsO1xyXG4gIH1cclxuXHJcbiAgc2VsZWN0QXBwbGljYXRpb24oIGFwcGxldDogSlNJTU11bHRvc0FwcGxldCwgc2Vzc2lvblNpemUgKVxyXG4gIHtcclxuICAgIHZhciBleGVjUGFyYW1zID0ge1xyXG4gICAgICBjb2RlQXJlYTogYXBwbGV0LmNvZGVBcmVhLFxyXG4gICAgICBzdGF0aWNBcmVhOiBhcHBsZXQuc3RhdGljQXJlYSxcclxuICAgICAgc2Vzc2lvblNpemU6IHNlc3Npb25TaXplXHJcbiAgICB9O1xyXG5cclxuICAgIHRoaXMubXZtLmV4ZWNBcHBsaWNhdGlvbiggZXhlY1BhcmFtcyApO1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZVN0ZXAoKVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLm12bS5leGVjdXRlU3RlcCgpO1xyXG4gIH1cclxufVxyXG4iLCJ2YXIgc2V0WmVyb1ByaW1pdGl2ZXMgPVxyXG57XHJcbiAgMHgwMToge1xyXG4gICAgbmFtZTogXCJDSEVDS19DQVNFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICBcdCAgdmFyIGV4cGVjdGVkSVNPPSBwb3BCeXRlKCk7XHJcblxyXG4gIFx0ICBpZiAoZXhwZWN0ZWRJU088IDEgfHwgZXhwZWN0ZWRJU08+IDQpXHJcbiAgXHQgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG4gIFx0ICBlbHNlXHJcbiAgXHQgICAgU2V0Q0NSRmxhZyhaZmxhZywgQ2hlY2tJU09DYXNlKGV4cGVjdGVkSVNPQ2FzZSkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAyOiB7XHJcbiAgICBuYW1lOiBcIlJFU0VUX1dXVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHNlbmRXYWl0UmVxdWVzdCgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA1OiB7XHJcbiAgICBuYW1lOiBcIkxPQURfQ0NSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgcHVzaEJ5dGUoQ0NSKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA2OiB7XHJcbiAgICBuYW1lOiBcIlNUT1JFX0NDUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIENDUigpID0gcG9wQnl0ZSgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA3OiB7XHJcbiAgICBuYW1lOiBcIlNFVF9BVFJfRklMRV9SRUNPUkRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIGxlbiA9IGdldEJ5dGUoYWRkcik7XHJcblxyXG4gICAgICBNRUxBcHBsaWNhdGlvbiAqYSA9IHN0YXRlLmFwcGxpY2F0aW9uO1xyXG4gICAgICBpZiAoYS5BVFJGaWxlUmVjb3JkU2l6ZSlcclxuICAgICAgICBkZWxldGUgW11hLkFUUkZpbGVSZWNvcmQ7XHJcblxyXG4gICAgICBhLkFUUkZpbGVSZWNvcmRTaXplID0gbGVuO1xyXG5cclxuICAgICAgaWYgKGxlbilcclxuICAgICAge1xyXG4gICAgICAgIGEuQVRSRmlsZVJlY29yZCA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgICByZWFkKGFkZHIsIGxlbiwgYS5BVFJGaWxlUmVjb3JkKTtcclxuICAgICAgfVxyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIHB1c2hCeXRlKGxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDg6IHtcclxuICAgIG5hbWU6IFwiU0VUX0FUUl9ISVNUT1JJQ0FMX0NIQVJBQ1RFUlNcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIGxlbiA9IGdldEJ5dGUoYWRkcik7XHJcbiAgICAgIHZhciB3cml0dGVuO1xyXG4gICAgICB2YXIgb2theSA9IHNldEFUUkhpc3RvcmljYWxDaGFyYWN0ZXJzKGxlbiwgYWRkcisxLCB3cml0dGVuKTtcclxuXHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgcHVzaEJ5dGUod3JpdHRlbik7XHJcbiAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIHdyaXR0ZW4gPCBsZW4pO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCAhb2theSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDk6IHtcclxuICAgIG5hbWU6IFwiR0VUX01FTU9SWV9SRUxJQUJJTElUWVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGZhbHNlKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGE6IHtcclxuICAgIG5hbWU6IFwiTE9PS1VQXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIHZhbHVlID0gZ2V0Qnl0ZShkeW5hbWljVG9wLTMpO1xyXG4gICAgICB2YXIgYXJyQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG5cclxuICAgICAgdmFyIGFycmxlbiA9IGdldEJ5dGUoYXJyQWRkcik7XHJcbiAgICAgIGZvciAodmFyIGk9MDtpPGFycmxlbjtpKyspXHJcbiAgICAgICAgaWYgKGdldEJ5dGUoYXJyQWRkcitpKzEpID09IHZhbHVlKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWkpO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgdHJ1ZSk7XHJcbiAgICAgICAgICBpID0gYXJybGVuO1xyXG4gICAgICAgIH1cclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhiOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT01QQVJFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgdmFyIG9wMSA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIG9wMiA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIGJsb2NrQ29tcGFyZShvcDEsIG9wMiwgbGVuKTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM6IHtcclxuICAgIG5hbWU6IFwiTUVNT1JZX0NPUFlcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbnVtID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICB2YXIgZHN0ID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgc3JjID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgY29weShkc3QsIHNyYywgbnVtKTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGQ6IHtcclxuICAgIG5hbWU6IFwiUVVFUllfSU5URVJGQUNFX1RZUEVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBmYWxzZSk7IC8vIGNvbnRhY3RcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgxMDoge1xyXG4gICAgbmFtZTogXCJDT05UUk9MX0FVVE9fUkVTRVRfV1dUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgLy8gRG9lc24ndCBkbyBhbnl0aGluZ1xyXG4gICAgICBEVCgtMik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MTE6IHtcclxuICAgIG5hbWU6IFwiU0VUX0ZDSV9GSUxFX1JFQ09SRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0Qnl0ZShhZGRyKTtcclxuXHJcbiAgICAgIE1FTEFwcGxpY2F0aW9uICphID0gc3RhdGUuYXBwbGljYXRpb247XHJcblxyXG4gICAgICBpZiAoYS5GQ0lSZWNvcmRTaXplKVxyXG4gICAgICAgIGRlbGV0ZSBbXWEuRkNJUmVjb3JkO1xyXG5cclxuICAgICAgYS5GQ0lSZWNvcmRTaXplID0gbGVuO1xyXG4gICAgICBhLkZDSVJlY29yZCA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgcmVhZChhZGRyICsgMSwgbGVuLCBhLkZDSVJlY29yZCk7XHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgcHVzaEJ5dGUobGVuKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MDoge1xyXG4gICAgbmFtZTogXCJERUxFR0FURVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIC8vIHJvbGxiYWNrIGFuZCB0dXJuIG9mZiB0cmFuc2FjdGlvbiBwcm90ZWN0aW9uXHJcbiAgICAgIHZhciBtID0gc3RhdGUuYXBwbGljYXRpb24uc3RhdGljRGF0YTtcclxuICAgICAgaWYgKG0ub24pXHJcbiAgICAgIHtcclxuICAgICAgICBtLmRpc2NhcmQoKTtcclxuICAgICAgICBtLm9uID0gZmFsc2U7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHZhciBBSURBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBEVCgtMik7XHJcblxyXG4gICAgICB2YXIgQUlEbGVuID0gZ2V0Qnl0ZShBSURBZGRyKTtcclxuICAgICAgaWYgKEFJRGxlbiA8IDEgfHwgQUlEbGVuID4gMTYpXHJcbiAgICAgICAgc2V0V29yZChQVCgpK1NXMSwgMHg2YTgzKTtcclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIEFJRCA9IG5ldyB2YXJbQUlEbGVuXTtcclxuXHJcbiAgICAgICAgcmVhZChBSURBZGRyKzEsIEFJRGxlbiwgQUlEKTtcclxuICAgICAgICBpZiAoIWRlbGVnYXRlQXBwbGljYXRpb24oQUlEbGVuLCBBSUQpKVxyXG4gICAgICAgICAgc2V0V29yZChQVCgpK1NXMSwgMHg2YTgzKTtcclxuICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgxOiB7XHJcbiAgICBuYW1lOiBcIlJFU0VUX1NFU1NJT05fREFUQVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGlmIChzdGF0ZS5hcHBsaWNhdGlvbi5pc1NoZWxsQXBwKVxyXG4gICAgICAgIFJlc2V0U2Vzc2lvbkRhdGEoKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4Mjoge1xyXG4gICAgbmFtZTogXCJDSEVDS1NVTVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW5ndGggPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgY2hlY2tzdW1bNF0gPSB7IDB4NWEsIDB4YTUsIDB4NWEsIDB4YTUgfTtcclxuXHJcbiAgICAgIHZhciBtID0gc3RhdGUuYXBwbGljYXRpb24uc3RhdGljRGF0YTtcclxuICAgICAgdmFyIGFjY291bnRGb3JUcmFuc2FjdGlvblByb3RlY3Rpb24gPSAoYWRkciA+PSBtLnN0YXJ0KCkgJiYgYWRkciA8PSBtLnN0YXJ0KCkgKyBtLnNpemUoKSAmJiBtLm9uKTtcclxuXHJcbiAgICAgIGZvciAodmFyIGo9MDsgaiA8IGxlbmd0aDsgaisrKVxyXG4gICAgICB7XHJcbiAgICAgICAgaWYgKGFjY291bnRGb3JUcmFuc2FjdGlvblByb3RlY3Rpb24pXHJcbiAgICAgICAgICBjaGVja3N1bVswXSArPSAodmFyKW0ucmVhZFBlbmRpbmdCeXRlTWVtb3J5KGFkZHIraik7XHJcbiAgICAgICAgZWxzZVxyXG4gICAgICAgICAgY2hlY2tzdW1bMF0gKz0gKHZhcilnZXRCeXRlKGFkZHIgKyBqKTtcclxuXHJcbiAgICAgICAgY2hlY2tzdW1bMV0gKz0gY2hlY2tzdW1bMF07XHJcbiAgICAgICAgY2hlY2tzdW1bMl0gKz0gY2hlY2tzdW1bMV07XHJcbiAgICAgICAgY2hlY2tzdW1bM10gKz0gY2hlY2tzdW1bMl07XHJcbiAgICAgIH1cclxuICAgICAgd3JpdGUoZHluYW1pY1RvcC00LCA0LCBjaGVja3N1bSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODM6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9DT0RFTEVUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGNvZGVsZXRJZCA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIGNvZGVhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgRFQoLTQpO1xyXG4gICAgICBjYWxsQ29kZWxldChjb2RlbGV0SWQsIGNvZGVhZGRyKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4NDoge1xyXG4gICAgbmFtZTogXCJRVUVSWV9DT0RFTEVUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGNvZGVsZXRJZCA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIHF1ZXJ5Q29kZWxldChjb2RlbGV0SWQpKTtcclxuICAgICAgRFQoLTIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGMxOiB7XHJcbiAgICBuYW1lOiBcIkRFU19FQ0JfRU5DSVBIRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksOCk7XHJcbiAgICAgIHZhciBwbGFpbnRleHRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIHZhciAqY2lwaGVydGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksOCk7XHJcbiAgICAgIHZhciBwbGFpbnRleHRbOF07XHJcblxyXG4gICAgICBtdGhfZGVzKERFU19ERUNSWVBULCBrZXksIGNpcGhlcnRleHQsIHBsYWludGV4dCk7XHJcbiAgICAgIHdyaXRlKHBsYWludGV4dEFkZHIsIDgsIHBsYWludGV4dCk7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjMjoge1xyXG4gICAgbmFtZTogXCJNT0RVTEFSX01VTFRJUExJQ0FUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG1vZGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgY29uc3QgdmFyICpsaHMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgbW9kbGVuKTtcclxuICAgICAgY29uc3QgdmFyICpyaHMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgbW9kbGVuKTtcclxuICAgICAgY29uc3QgdmFyICptb2QgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgbW9kbGVuKTtcclxuICAgICAgdmFyICpyZXMgPSBuZXcgdmFyW21vZGxlbl07XHJcbiAgICAgIG10aF9tb2RfbXVsdChsaHMsIG1vZGxlbiwgcmhzLCBtb2RsZW4sIG1vZCwgbW9kbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShnZXRXb3JkKGR5bmFtaWNUb3AtNiksIG1vZGxlbiwgcmVzKTtcclxuICAgICAgRFQoLTgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGMzOiB7XHJcbiAgICBuYW1lOiBcIk1PRFVMQVJfUkVEVUNUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG9wbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICB2YXIgbW9kbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICBjb25zdCB2YXIgKm9wID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG9wbGVuKTtcclxuICAgICAgY29uc3QgdmFyICptb2QgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgb3BsZW4pO1xyXG4gICAgICB2YXIgKnJlcyA9IG5ldyB2YXJbb3BsZW5dO1xyXG4gICAgICBtdGhfbW9kX3JlZChvcCwgb3BsZW4sIG1vZCwgbW9kbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG9wbGVuLCByZXMpO1xyXG4gICAgICBEVCgtOCk7XHJcbiAgICAgIGRlbGV0ZSBbXXJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNDoge1xyXG4gICAgbmFtZTogXCJHRVRfUkFORE9NX05VTUJFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciByYW5kWzhdO1xyXG4gICAgICByYW5kZGF0YShyYW5kLCA4KTtcclxuICAgICAgRFQoOCk7XHJcbiAgICAgIHdyaXRlKGR5bmFtaWNUb3AtOCwgOCwgcmFuZCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzU6IHtcclxuICAgIG5hbWU6IFwiREVTX0VDQl9ERUNJUEhFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSw4KTtcclxuICAgICAgdmFyIGNpcGhlckFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgdmFyICpwbGFpbnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDIpLDgpO1xyXG4gICAgICB2YXIgY2lwaGVydGV4dFs4XTtcclxuXHJcbiAgICAgIG10aF9kZXMoREVTX0VOQ1JZUFQsIGtleSwgcGxhaW50ZXh0LCBjaXBoZXJ0ZXh0KTtcclxuICAgICAgd3JpdGUoY2lwaGVyQWRkciwgOCwgY2lwaGVydGV4dCk7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNjoge1xyXG4gICAgbmFtZTogXCJHRU5FUkFURV9ERVNfQ0JDX1NJR05BVFVSRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBwbGFpblRleHRMZW5ndGggPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHhhKTtcclxuICAgICAgdmFyIElWYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDgpO1xyXG4gICAgICB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksIDgpO1xyXG4gICAgICB2YXIgc2lnbmF0dXJlQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgKnBsYWluVGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksIHBsYWluVGV4dExlbmd0aCk7XHJcbiAgICAgIHZhciBzaWduYXR1cmVbOF07XHJcblxyXG4gICAgICByZWFkKElWYWRkciwgOCwgc2lnbmF0dXJlKTtcclxuICAgICAgd2hpbGUgKHBsYWluVGV4dExlbmd0aCA+PSA4KVxyXG4gICAgICB7XHJcbiAgICAgICAgZm9yICh2YXIgaT0wO2k8ODtpKyspXHJcbiAgICAgICAgICBzaWduYXR1cmVbaV0gXj0gcGxhaW5UZXh0W2ldO1xyXG5cclxuICAgICAgICB2YXIgZW5jcnlwdGVkU2lnbmF0dXJlWzhdO1xyXG5cclxuICAgICAgICBtdGhfZGVzKERFU19FTkNSWVBULCBrZXksIHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlKTtcclxuICAgICAgICBtZW1jcHkoc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUsIDgpO1xyXG4gICAgICAgIHBsYWluVGV4dExlbmd0aCAtPSA4O1xyXG4gICAgICAgIHBsYWluVGV4dCArPSA4O1xyXG4gICAgICB9XHJcbiAgICAgIHdyaXRlKHNpZ25hdHVyZUFkZHIsIDgsIHNpZ25hdHVyZSk7XHJcbiAgICAgIERUKC0xMCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Yzc6IHtcclxuICAgIG5hbWU6IFwiR0VORVJBVEVfVFJJUExFX0RFU19DQkNfU0lHTkFUVVJFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaW50IHBsYWluVGV4dExlbmd0aCA9IGdldFdvcmQoZHluYW1pY1RvcC0weGEpO1xyXG4gICAgICB2YXIgSVZhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4OCk7XHJcbiAgICAgIHZhciBrZXkxID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSwgMTYpO1xyXG4gICAgICB2YXIga2V5MiA9IGtleTEgKyA4O1xyXG4gICAgICB2YXIgc2lnbmF0dXJlQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgcGxhaW5UZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSwgcGxhaW5UZXh0TGVuZ3RoKTtcclxuICAgICAgdmFyIHNpZ25hdHVyZVs4XTtcclxuXHJcbiAgICAgIHJlYWQoSVZhZGRyLCA4LCBzaWduYXR1cmUpO1xyXG4gICAgICB3aGlsZSAocGxhaW5UZXh0TGVuZ3RoID4gMClcclxuICAgICAge1xyXG4gICAgICAgIGZvciAodmFyIGk9MDtpPDg7aSsrKVxyXG4gICAgICAgICAgc2lnbmF0dXJlW2ldIF49IHBsYWluVGV4dFtpXTtcclxuXHJcbiAgICAgICAgdmFyIGVuY3J5cHRlZFNpZ25hdHVyZVs4XTtcclxuXHJcbiAgICAgICAgbXRoX2RlcyhERVNfRU5DUllQVCwga2V5MSwgc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUpO1xyXG4gICAgICAgIG10aF9kZXMoREVTX0RFQ1JZUFQsIGtleTIsIGVuY3J5cHRlZFNpZ25hdHVyZSwgc2lnbmF0dXJlKTtcclxuICAgICAgICBtdGhfZGVzKERFU19FTkNSWVBULCBrZXkxLCBzaWduYXR1cmUsIGVuY3J5cHRlZFNpZ25hdHVyZSk7XHJcbiAgICAgICAgbWVtY3B5KHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlLCA4KTtcclxuICAgICAgICBwbGFpblRleHRMZW5ndGggLT0gODtcclxuICAgICAgICBwbGFpblRleHQgKz0gODtcclxuICAgICAgfVxyXG4gICAgICB3cml0ZShzaWduYXR1cmVBZGRyLCA4LCBzaWduYXR1cmUpO1xyXG4gICAgICBEVCgtMTApO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM4OiB7XHJcbiAgICBuYW1lOiBcIk1PRFVMQVJfRVhQT05FTlRJQVRJT05cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgZXhwbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Yyk7XHJcbiAgICAgIHZhciBtb2RsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHhhKTtcclxuICAgICAgdmFyIGV4cG9uZW50ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg4KSwgZXhwbGVuKTtcclxuICAgICAgdmFyIG1vZCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksIG1vZGxlbik7XHJcbiAgICAgIHZhciBiYXNlID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KSwgbW9kbGVuKTtcclxuICAgICAgdmFyIHJlc0FkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKTtcclxuICAgICAgdmFyIHJlcyA9IG5ldyB2YXJbbW9kbGVuXTtcclxuXHJcbiAgICAgIG10aF9tb2RfZXhwKGJhc2UsIG1vZGxlbiwgZXhwb25lbnQsIGV4cGxlbiwgbW9kLCBtb2RsZW4sIHJlcyk7XHJcbiAgICAgIHdyaXRlKHJlc0FkZHIsIG1vZGxlbiwgcmVzKTtcclxuICAgICAgRFQoLTEyKTtcclxuXHJcbiAgICAgIGRlbGV0ZSBbXXJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjOToge1xyXG4gICAgbmFtZTogXCJNT0RVTEFSX0VYUE9ORU5USUFUSU9OX0NSVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgIHZhciBkcGRxID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtOCksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgdmFyIHBxdSAgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgbW9kdWx1c19sZW4gKiAzIC8gMik7XHJcbiAgICAgIHZhciBiYXNlID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgdmFyIG91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIHZhciByZXMgPSBuZXcgdmFyW21vZHVsdXNfbGVuXTtcclxuXHJcbiAgICAgIG10aF9tb2RfZXhwX2NydChtb2R1bHVzX2xlbiwgZHBkcSwgcHF1LCBiYXNlLCByZXMpO1xyXG4gICAgICB3cml0ZShvdXRBZGRyLCBtb2R1bHVzX2xlbiwgcmVzKTtcclxuICAgICAgRFQoLTEwKTtcclxuICAgICAgZGVsZXRlW10gcmVzO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGNhOiB7XHJcbiAgICBuYW1lOiBcIlNIQTFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgcGxhaW50ZXh0TGVuZ3RoID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Nik7XHJcbiAgICAgIHZhciBoYXNoRGlnZXN0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgcGxhaW50ZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSwgcGxhaW50ZXh0TGVuZ3RoKTtcclxuICAgICAgdmFyIGxvbmcgaGFzaERpZ2VzdFs1XTsgLy8gMjAgYnl0ZSBoYXNoXHJcblxyXG4gICAgICBtdGhfc2hhX2luaXQoaGFzaERpZ2VzdCk7XHJcblxyXG4gICAgICB3aGlsZSAocGxhaW50ZXh0TGVuZ3RoID4gNjQpXHJcbiAgICAgIHtcclxuICAgICAgICBtdGhfc2hhX3VwZGF0ZShoYXNoRGlnZXN0LCAodmFyICopcGxhaW50ZXh0KTtcclxuICAgICAgICBwbGFpbnRleHQgKz0gNjQ7XHJcbiAgICAgICAgcGxhaW50ZXh0TGVuZ3RoIC09IDY0O1xyXG4gICAgICB9XHJcblxyXG4gICAgICBtdGhfc2hhX2ZpbmFsKGhhc2hEaWdlc3QsICh2YXIgKilwbGFpbnRleHQsIHBsYWludGV4dExlbmd0aCk7XHJcblxyXG4gICAgICBmb3IgKGludCBpPTA7aTw1O2krKylcclxuICAgICAgICB3cml0ZU51bWJlcihoYXNoRGlnZXN0QWRkcisoaSo0KSwgNCwgaGFzaERpZ2VzdFtpXSk7XHJcblxyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Y2M6IHtcclxuICAgIG5hbWU6IFwiR0VORVJBVEVfUkFORE9NX1BSSU1FXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGdjZEZsYWcgPSBnZXRCeXRlKGR5bmFtaWNUb3AtMTMpO1xyXG4gICAgICB2YXIgY29uZiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMik7XHJcbiAgICAgIHZhciB0aW1lb3V0ID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgdmFyIHJnRXhwID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICBjb25zdCB2YXIgKm1pbkxvYyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCA0KTtcclxuICAgICAgY29uc3QgdmFyICptYXhMb2MgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgNCk7XHJcbiAgICAgIHZhciByZXNBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Mik7XHJcbiAgICAgIGlmICgocmdFeHAgPCA1KSB8fCAocmdFeHAgPiAyNTYpKVxyXG4gICAgICB7XHJcbiAgICAgICAgQWJlbmQoXCJyZ0V4cCBwYXJhbWV0ZXIgb3V0IG9mIHJhbmdlXCIpO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIHN0YXRpYyBjb25zdCB2bG9uZyBvbmUoMSk7XHJcbiAgICAgICAgc3RhdGljIGNvbnN0IHZsb25nIHRocmVlKDMpO1xyXG4gICAgICAgIHN0ZDo6dmVjdG9yPHZhcj4gY2FuZGlkYXRlKHJnRXhwKTtcclxuICAgICAgICBmb3IgKDs7KVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHN0ZDo6Z2VuZXJhdGUoY2FuZGlkYXRlLmJlZ2luKCksIGNhbmRpZGF0ZS5lbmQoKSwgcmFuZCk7XHJcbiAgICAgICAgICBpZiAoc3RkOjpsZXhpY29ncmFwaGljYWxfY29tcGFyZShcclxuICAgICAgICAgICAgICAgIGNhbmRpZGF0ZS5iZWdpbigpLCBjYW5kaWRhdGUuZW5kKCksXHJcbiAgICAgICAgICAgICAgICBtaW5Mb2MsIG1pbkxvYyArIDQpKVxyXG4gICAgICAgICAgICBjb250aW51ZTtcclxuICAgICAgICAgIGlmIChzdGQ6OmxleGljb2dyYXBoaWNhbF9jb21wYXJlKFxyXG4gICAgICAgICAgICAgICAgbWF4TG9jLCBtYXhMb2MgKyA0LFxyXG4gICAgICAgICAgICAgICAgY2FuZGlkYXRlLmJlZ2luKCksIGNhbmRpZGF0ZS5lbmQoKSkpXHJcbiAgICAgICAgICAgIGNvbnRpbnVlO1xyXG4gICAgICAgICAgdmxvbmcgdmxvbmdfY2FuZGlkYXRlKGNhbmRpZGF0ZS5zaXplKCksICZjYW5kaWRhdGVbMF0pO1xyXG4gICAgICAgICAgaWYgKDB4ODAgPT0gZ2NkRmxhZylcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgaWYgKG9uZSAhPSBnY2QodGhyZWUsIHZsb25nX2NhbmRpZGF0ZSkpXHJcbiAgICAgICAgICAgICAgY29udGludWU7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBpZiAoIWlzX3Byb2JhYmxlX3ByaW1lKHZsb25nX2NhbmRpZGF0ZSkpXHJcbiAgICAgICAgICAgIGNvbnRpbnVlO1xyXG5cclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuICAgICAgICB3cml0ZShyZXNBZGRyLCByZ0V4cCwgJmNhbmRpZGF0ZVswXSk7XHJcbiAgICAgICAgRFQoLTEzKTtcclxuICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGNkOiB7XHJcbiAgICBuYW1lOiBcIlNFRURfRUNCX0RFQ0lQSEVSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgc3RhdGljIGNvbnN0IHZhciBibG9ja19zaXplID0gMTY7XHJcblxyXG4gICAgICBjb25zdCB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBibG9ja19zaXplKTtcclxuICAgICAgdmFyIHJlc0FkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgY29uc3QgdmFyICpwbGFpbnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgYmxvY2tfc2l6ZSk7XHJcblxyXG4gICAgICB2YXIgYnVmZmVyW2Jsb2NrX3NpemVdO1xyXG4gICAgICBtZW1jcHkoYnVmZmVyLCBrZXksIGJsb2NrX3NpemUpO1xyXG4gICAgICBEV09SRCByb3VuZF9rZXlbMiAqIGJsb2NrX3NpemVdO1xyXG4gICAgICBTZWVkRW5jUm91bmRLZXkocm91bmRfa2V5LCBidWZmZXIpO1xyXG4gICAgICBtZW1jcHkoYnVmZmVyLCBwbGFpbnRleHQsIGJsb2NrX3NpemUpO1xyXG4gICAgICBTZWVkRGVjcnlwdChidWZmZXIsIHJvdW5kX2tleSk7XHJcblxyXG4gICAgICB3cml0ZShyZXNBZGRyLCBibG9ja19zaXplLCBidWZmZXIpO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Y2U6IHtcclxuICAgIG5hbWU6IFwiU0VFRF9FQ0JfRU5DSVBIRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBzdGF0aWMgY29uc3QgdmFyIGJsb2NrX3NpemUgPSAxNjtcclxuXHJcbiAgICAgIGNvbnN0IHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIGJsb2NrX3NpemUpO1xyXG4gICAgICB2YXIgcmVzQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICBjb25zdCB2YXIgKnBsYWludGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBibG9ja19zaXplKTtcclxuXHJcbiAgICAgIHZhciBidWZmZXJbYmxvY2tfc2l6ZV07XHJcbiAgICAgIG1lbWNweShidWZmZXIsIGtleSwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIERXT1JEIHJvdW5kX2tleVsyICogYmxvY2tfc2l6ZV07XHJcbiAgICAgIFNlZWRFbmNSb3VuZEtleShyb3VuZF9rZXksIGJ1ZmZlcik7XHJcbiAgICAgIG1lbWNweShidWZmZXIsIHBsYWludGV4dCwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIFNlZWRFbmNyeXB0KGJ1ZmZlciwgcm91bmRfa2V5KTtcclxuXHJcbiAgICAgIHdyaXRlKHJlc0FkZHIsIGJsb2NrX3NpemUsIGJ1ZmZlcik7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH1cclxufTtcclxuXHJcbnZhciBzZXRPbmVQcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDA6IHtcclxuICAgIG5hbWU6IFwiUVVFUlkwXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaSA9IHByaW0wLmZpbmQoYXJnMSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGkgIT0gcHJpbTAuZW5kKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAxOiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZMVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGkgPSBwcmltMS5maW5kKGFyZzEpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBpICE9IHByaW0xLmVuZCgpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMjoge1xyXG4gICAgbmFtZTogXCJRVUVSWTJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpID0gcHJpbTIuZmluZChhcmcxKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgaSAhPSBwcmltMi5lbmQoKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDM6IHtcclxuICAgIG5hbWU6IFwiUVVFUlkzXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaSA9IHByaW0zLmZpbmQoYXJnMSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGkgIT0gcHJpbTMuZW5kKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA4OiB7XHJcbiAgICBuYW1lOiBcIkRJVklERU5cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gYXJnMTtcclxuICAgICAgdmFyICpkZW5vbWluYXRvciA9IGR1bXAoZHluYW1pY1RvcC1sZW4sIGxlbik7XHJcbiAgICAgIGlmIChibG9ja0lzWmVybyhkZW5vbWluYXRvciwgbGVuKSlcclxuICAgICAge1xyXG4gICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIHRydWUpO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIGNvbnN0IHZhciAqbnVtZXJhdG9yID0gZHVtcChkeW5hbWljVG9wLTIqbGVuLCBsZW4pO1xyXG4gICAgICAgIHZhciAqcXVvdGllbnQgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgICAgdmFyICpyZW1haW5kZXIgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgICAgbXRoX2RpdihudW1lcmF0b3IsIGRlbm9taW5hdG9yLCBsZW4sIHF1b3RpZW50LCByZW1haW5kZXIpO1xyXG4gICAgICAgIHdyaXRlKGR5bmFtaWNUb3AtMipsZW4sIGxlbiwgcXVvdGllbnQpO1xyXG4gICAgICAgIHdyaXRlKGR5bmFtaWNUb3AtbGVuLCBsZW4sIHJlbWFpbmRlcik7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgZmFsc2UpO1xyXG4gICAgICAgIFNldENDUkZsYWcoWmZsYWcsIGJsb2NrSXNaZXJvKHF1b3RpZW50LGxlbikpO1xyXG4gICAgICAgIGRlbGV0ZSBbXXF1b3RpZW50O1xyXG4gICAgICAgIGRlbGV0ZSBbXXJlbWFpbmRlcjtcclxuICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA5OiB7XHJcbiAgICBuYW1lOiBcIkdFVF9ESVJfRklMRV9SRUNPUkRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICAvLyBTYW1lIGFzIGJlbG93XHJcbiAgICAgIE1VTFRPUy5QcmltaXRpdmVzLnNldE9uZVByaW1pdGl2ZXNbIDB4MGEgXS5wcm9jKCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGE6IHtcclxuICAgIG5hbWU6IFwiR0VUX0ZJTEVfQ09OVFJPTF9JTkZPUk1BVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW4gPSBhcmcxO1xyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0zKTtcclxuICAgICAgdmFyIHJlY29yZE51bWJlciA9IGdldEJ5dGUoZHluYW1pY1RvcC0xKTtcclxuICAgICAgdmFyIG9rYXk7XHJcbiAgICAgIHZhciAqZGF0YTtcclxuICAgICAgdmFyIGRhdGFsZW47XHJcbiAgICAgIGlmIChwcmltID09IEdFVF9ESVJfRklMRV9SRUNPUkQpXHJcbiAgICAgICAgb2theSA9IGdldERpckZpbGVSZWNvcmQocmVjb3JkTnVtYmVyLTEsICZkYXRhbGVuLCAmZGF0YSk7XHJcbiAgICAgIGVsc2VcclxuICAgICAgICBva2F5ID0gZ2V0RkNJKHJlY29yZE51bWJlci0xLCAmZGF0YWxlbiwgJmRhdGEpO1xyXG4gICAgICBpZiAob2theSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgY29waWVkID0gbGVuIDwgZGF0YWxlbiA/IGxlbiA6IGRhdGFsZW47XHJcbiAgICAgICAgICBpZiAoY29waWVkKVxyXG4gICAgICAgICAgICB3cml0ZShhZGRyLCBjb3BpZWQsIGRhdGEpO1xyXG4gICAgICAgICAgcHVzaEJ5dGUoY29waWVkKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIChjb3BpZWQgPCBsZW4pKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoWmZsYWcsIDApO1xyXG4gICAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHB1c2hCeXRlKDApO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgMSk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCAxKTtcclxuICAgICAgICB9XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGI6IHtcclxuICAgIG5hbWU6IFwiR0VUX01BTlVGQUNUVVJFUl9EQVRBXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIERUKC0xKTtcclxuICAgICAgdmFyIG1hbnVmYWN0dXJlclsyNTZdO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0TWFudWZhY3R1cmVyRGF0YShtYW51ZmFjdHVyZXIpO1xyXG4gICAgICBsZW4gPSBhcmcxIDwgbGVuID8gYXJnMSA6IGxlbjtcclxuICAgICAgaWYgKGxlbilcclxuICAgICAgICB3cml0ZShhZGRyLCBsZW4sIG1hbnVmYWN0dXJlcik7XHJcbiAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGM6IHtcclxuICAgIG5hbWU6IFwiR0VUX01VTFRPU19EQVRBXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIERUKC0xKTtcclxuICAgICAgdmFyIE1VTFRPU0RhdGFbMjU2XTtcclxuICAgICAgdmFyIGxlbiA9IGdldE1VTFRPU0RhdGEoTVVMVE9TRGF0YSk7XHJcbiAgICAgIGlmIChsZW4pXHJcbiAgICAgICAgbGVuID0gYXJnMSA8IGxlbiA/IGFyZzEgOiBsZW47XHJcbiAgICAgIHdyaXRlKGFkZHIsIGxlbiwgTVVMVE9TRGF0YSk7XHJcbiAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGQ6IHtcclxuICAgIG5hbWU6IFwiR0VUX1BVUlNFX1RZUEVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBlOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT1BZX0ZJWEVEX0xFTkdUSFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBkc3QgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBzcmMgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBjb3B5KGRzdCwgc3JjLCBhcmcxKTtcclxuICAgICAgRFQoLTQpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBmOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT01QQVJFX0ZJWEVEX0xFTkdUSFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBvcDEgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBvcDIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIGJsb2NrQ29tcGFyZShvcDEsIG9wMiwgYXJnMSk7XHJcbiAgICAgIERUKC00KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgxMDoge1xyXG4gICAgbmFtZTogXCJNVUxUSVBMWU5cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gYXJnMTtcclxuICAgICAgY29uc3QgdmFyICpvcDEgPSBkdW1wKGR5bmFtaWNUb3AtMipsZW4sIGxlbik7XHJcbiAgICAgIGNvbnN0IHZhciAqb3AyID0gZHVtcChkeW5hbWljVG9wLWxlbiwgbGVuKTtcclxuICAgICAgdmFyICpyZXMgPSBuZXcgdmFyW2xlbioyXTtcclxuICAgICAgbXRoX211bChvcDEsIG9wMiwgbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShkeW5hbWljVG9wLTIqbGVuLCBsZW4qMiwgcmVzKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgYmxvY2tJc1plcm8ocmVzLGxlbioyKSk7XHJcbiAgICAgIGRlbGV0ZSBbXXJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MDoge1xyXG4gICAgbmFtZTogXCJTRVRfVFJBTlNBQ1RJT05fUFJPVEVDVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBtID0gc3RhdGUuYXBwbGljYXRpb24uc3RhdGljRGF0YTtcclxuICAgICAgaWYgKG0ub24pXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgaWYgKGFyZzEgJiAxKVxyXG4gICAgICAgICAgICBtLmNvbW1pdCgpO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICBtLmRpc2NhcmQoKTtcclxuICAgICAgICB9XHJcbiAgICAgIGlmIChhcmcxICYgMilcclxuICAgICAgICBtLm9uID0gdHJ1ZTtcclxuICAgICAgZWxzZVxyXG4gICAgICAgIG0ub24gPSBmYWxzZTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MToge1xyXG4gICAgbmFtZTogXCJHRVRfREVMRUdBVE9SX0FJRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBBSURBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIE1FTEV4ZWN1dGlvblN0YXRlICplID0gZ2V0RGVsZWdhdG9yU3RhdGUoKTtcclxuICAgICAgaWYgKGUpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIGxlbjtcclxuICAgICAgICAgIGlmICggYXJnMSA8IGUuYXBwbGljYXRpb24uQUlEbGVuZ3RoKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgbGVuID0gYXJnMTtcclxuICAgICAgICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCB0cnVlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgbGVuID0gIGUuYXBwbGljYXRpb24uQUlEbGVuZ3RoO1xyXG4gICAgICAgICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGZhbHNlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgc2V0Qnl0ZShBSURBZGRyLCAodmFyKWxlbik7XHJcbiAgICAgICAgICBBSURBZGRyKys7XHJcbiAgICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCBsZW47IGkrKylcclxuICAgICAgICAgICAgc2V0Qnl0ZShBSURBZGRyK2ksIGUuYXBwbGljYXRpb24uQUlEW2ldKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoWmZsYWcsIGZhbHNlKTtcclxuICAgICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCB0cnVlKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNDoge1xyXG4gICAgbmFtZTogXCJHRU5FUkFURV9BU1lNTUVUUklDX0hBU0hcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBjb25zdCB2YXIgKml2O1xyXG4gICAgICB2YXIgcGxhaW5fbGVuO1xyXG4gICAgICB2YXIgZGlnZXN0T3V0QWRkcjtcclxuICAgICAgY29uc3QgdmFyICpwbGFpbjtcclxuICAgICAgTUVMS2V5KiBhaGFzaEtleTtcclxuICAgICAgaW50IGR0dmFsO1xyXG4gICAgICBzdGQ6OmF1dG9fcHRyPFNpbXBsZU1FTEtleVdyYXBwZXI+IHNta3c7XHJcbiAgICAgIHZhciBoY2wgPSAxNjtcclxuXHJcbiAgICAgIHN3aXRjaCAoYXJnMSlcclxuICAgICAge1xyXG4gICAgICAgIGNhc2UgMDpcclxuICAgICAgICAgIGl2ID0gMDtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBnZXRBSGFzaEtleSgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtNjtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIDE6XHJcbiAgICAgICAgICBpdiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTgpLCAxNik7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gZ2V0QUhhc2hLZXkoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTY7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSAyOlxyXG4gICAgICAgICAgaXYgPSAwO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtOCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXNfbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTEwO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgMzpcclxuICAgICAgICAgIGl2ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMTIpLCAxNik7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgICAgICBjb25zdCB2YXIqIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTEyO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgNDpcclxuICAgICAgICAgIGl2ID0gMDtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMik7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtOCksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgICAgICBjb25zdCB2YXIqIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGhjbCA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgICAgIGR0dmFsID0gLTEyO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgNTpcclxuICAgICAgICAgIGhjbCA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgICAgIGl2ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMTQpLCBoY2wpO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEyKTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC04KSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgICAgIGNvbnN0IHZhciogbW9kdWx1cyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgICAgICBzbWt3ID0gc3RkOjphdXRvX3B0cjxTaW1wbGVNRUxLZXlXcmFwcGVyPihuZXcgU2ltcGxlTUVMS2V5V3JhcHBlcihtb2R1bHVzX2xlbiwgbW9kdWx1cykpO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBzbWt3LmdldCgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtMTQ7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgIEFiZW5kKFwiYmFkIGIyIHZhbHVlIGZvciBHZW5lcmF0ZUFzeW1tZXRyaWNIYXNoIHByaW1pdGl2ZVwiKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBzdGQ6OnZlY3Rvcjx2YXI+IGhhc2goaGNsKTtcclxuICAgICAgQUhhc2goYWhhc2hLZXksIHBsYWluX2xlbiwgcGxhaW4sICZoYXNoWzBdLCBpdiwgaGNsKTtcclxuICAgICAgd3JpdGUoZGlnZXN0T3V0QWRkciwgaGNsLCAmaGFzaFswXSk7XHJcbiAgICAgIERUKGR0dmFsKTtcclxuICAgICovfVxyXG4gIH1cclxufTtcclxuXHJcbmZ1bmN0aW9uIGJpdE1hbmlwdWxhdGUoYml0bWFwLCBsaXRlcmFsLCBkYXRhKVxyXG57XHJcbiAgdmFyIG1vZGlmeSA9ICgoYml0bWFwICYgKDE8PDcpKSA9PSAoMTw8NykpO1xyXG4gIGlmIChiaXRtYXAgJiAweDdjKSAvLyBiaXRzIDYtMiBzaG91bGQgYmUgemVyb1xyXG4gICAgdGhyb3cgbmV3IEVycm9yKCBcIlVuZGVmaW5lZCBhcmd1bWVudHNcIik7XHJcblxyXG4gIHN3aXRjaCAoYml0bWFwICYgMylcclxuICB7XHJcbiAgICBjYXNlIDM6XHJcbiAgICAgIGRhdGEgJj0gbGl0ZXJhbDtcclxuICAgICAgYnJlYWs7XHJcbiAgICBjYXNlIDI6XHJcbiAgICAgIGRhdGEgfD0gbGl0ZXJhbDtcclxuICAgICAgYnJlYWs7XHJcbiAgICBjYXNlIDE6XHJcbiAgICAgIGRhdGEgPSB+KGRhdGEgXiBsaXRlcmFsKTtcclxuICAgICAgYnJlYWs7XHJcbiAgICBjYXNlIDA6XHJcbiAgICAgIGRhdGEgXj0gbGl0ZXJhbDtcclxuICAgICAgYnJlYWs7XHJcbiAgfVxyXG5cclxuICAvL1NldENDUkZsYWcoWmZsYWcsIGRhdGE9PTApO1xyXG5cclxuICByZXR1cm4gbW9kaWZ5OyAvL1RPRE86IHJldHVybiBkYXRhXHJcbn1cclxuXHJcbnZhciBzZXRUd29QcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDE6IHtcclxuICAgIG5hbWU6IFwiQklUX01BTklQVUxBVEVfQllURVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qLypcclxuICAgICAgdmFyIGIgPSBnZXRCeXRlKGR5bmFtaWNUb3AtMSk7XHJcblxyXG4gICAgICBpZiAoYml0TWFuaXB1bGF0ZShhcmcxLCBhcmcyLCBiKSlcclxuICAgICAgICBzZXRCeXRlKGR5bmFtaWNUb3AtMSwgKHZhciliKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMjoge1xyXG4gICAgbmFtZTogXCJTSElGVF9MRUZUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgLy8gc2FtZSBhcyBTSElGVF9SSUdIVFxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAzOiB7XHJcbiAgICBuYW1lOiBcIlNISUZUX1JJR0hUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGFyZzE7XHJcbiAgICAgIHZhciBudW1TaGlmdEJpdHMgPSBhcmcyO1xyXG4gICAgICBpZiAoIWxlbiB8fCAhbnVtU2hpZnRCaXRzIHx8IG51bVNoaWZ0Qml0cz49OCpsZW4pXHJcbiAgICAgICAgQWJlbmQoXCJ1bmRlZmluZWQgc2hpZnQgYXJndW1lbnRzXCIpO1xyXG5cclxuICAgICAgdmFyICpkYXRhID0gbmV3IHZhcltsZW5dO1xyXG4gICAgICByZWFkKGR5bmFtaWNUb3AtbGVuLCBsZW4sIGRhdGEpO1xyXG5cclxuICAgICAgaWYgKHByaW0gPT0gU0hJRlRfTEVGVClcclxuICAgICAge1xyXG4gICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGJsb2NrQml0U2V0KGxlbiwgZGF0YSwgbGVuKjgtbnVtU2hpZnRCaXRzKSk7XHJcbiAgICAgICAgbXRoX3NobChkYXRhLCBsZW4sIG51bVNoaWZ0Qml0cyk7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgYmxvY2tCaXRTZXQobGVuLCBkYXRhLCBudW1TaGlmdEJpdHMtMSkpO1xyXG4gICAgICAgIG10aF9zaHIoZGF0YSwgbGVuLCBudW1TaGlmdEJpdHMpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB3cml0ZShkeW5hbWljVG9wLWxlbiwgbGVuLCBkYXRhKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgYmxvY2tJc1plcm8oZGF0YSxsZW4pKTtcclxuICAgICAgZGVsZXRlIFtdZGF0YTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwNDoge1xyXG4gICAgbmFtZTogXCJTRVRfU0VMRUNUX1NXXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgc2V0U2VsZWN0U1coYXJnMSwgYXJnMik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDU6IHtcclxuICAgIG5hbWU6IFwiQ0FSRF9CTE9DS1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODA6IHtcclxuICAgIG5hbWU6IFwiUkVUVVJOX0ZST01fQ09ERUxFVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHJldHVybkZyb21Db2RlbGV0KGFyZzEsIGFyZzIpO1xyXG4gICAgKi99XHJcbiAgfVxyXG59XHJcblxyXG52YXIgc2V0VGhyZWVQcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDE6IHtcclxuICAgIG5hbWU6IFwiQklUX01BTklQVUxBVEVfV09SRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciB3ID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgaWYgKGJpdE1hbmlwdWxhdGUoYXJnMSwgbWtXb3JkKGFyZzIsIGFyZzMpLCB3KSlcclxuICAgICAgICBzZXRXb3JkKGR5bmFtaWNUb3AtMiwgdyk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODA6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFMFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODE6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFMVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODI6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFMlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODM6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFM1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODQ6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFNFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODU6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFNVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODY6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFNlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9XHJcbn07XHJcblxyXG52YXIgcHJpbWl0aXZlU2V0cyA9IFtcclxuICBzZXRaZXJvUHJpbWl0aXZlcyxcclxuICBzZXRPbmVQcmltaXRpdmVzLFxyXG4gIHNldFR3b1ByaW1pdGl2ZXMsXHJcbiAgc2V0VGhyZWVQcmltaXRpdmVzXHJcbl07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gY2FsbFByaW1pdGl2ZSggY3R4LCBwcmltLCBzZXQsIGFyZzEsIGFyZzIsIGFyZzMgKVxyXG57XHJcbiAgdmFyIHByaW1JbmZvID0gcHJpbWl0aXZlU2V0c1sgc2V0IF1bIHByaW0gXTtcclxuXHJcbiAgaWYgKCBwcmltSW5mbyApXHJcbiAge1xyXG4gICAgc3dpdGNoKCBzZXQgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIDA6IHByaW1JbmZvLnByb2MoKTsgYnJlYWs7XHJcbiAgICAgIGNhc2UgMTogcHJpbUluZm8ucHJvYyggYXJnMSApOyBicmVhaztcclxuICAgICAgY2FzZSAyOiBwcmltSW5mby5wcm9jKCBhcmcxLCBhcmcyICk7IGJyZWFrO1xyXG4gICAgICBjYXNlIDM6IHByaW1JbmZvLnByb2MoIGFyZzEsIGFyZzIsIGFyZzMgKTsgYnJlYWs7XHJcbiAgICB9XHJcbiAgfVxyXG4gIGVsc2VcclxuICB7XHJcbiAgICAvLyBubyBwcmltXHJcbiAgICB0aHJvdyBuZXcgRXJyb3IoIFwiUHJpbWl0aXZlIG5vdCBJbXBsZW1lbnRlZFwiICk7XHJcbiAgfVxyXG59XHJcbiIsImV4cG9ydCBjbGFzcyBTZWN1cml0eU1hbmFnZXJcclxue1xyXG4gIGluaXRTZWN1cml0eSgpXHJcbiAge1xyXG4gIH1cclxuXHJcbiAgcHJvY2Vzc0FQRFUoIGFwZHUgKVxyXG4gIHtcclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LEtpbmQsS2luZEluZm8gfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuZXhwb3J0IGNsYXNzIEFEQ1xue1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LEtpbmQsS2luZEluZm8gfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuZXhwb3J0IGNsYXNzIEFMQ1xue1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LCBLaW5kLCBLaW5kSW5mbywgS2luZEJ1aWxkZXIgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbi8qKlxyXG4gKiBFbmNvZGVyL0RlY29kb3IgZm9yIGEgTVVMVE9TIEFwcGxpY2F0aW9uIExvYWQgVW5pdFxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIEFMVSBpbXBsZW1lbnRzIEtpbmRcclxue1xyXG4gIHN0YXRpYyBraW5kSW5mbzogS2luZEluZm87XHJcblxyXG4gIGNvZGU6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcclxuICBkYXRhOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcbiAgZmNpOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcbiAgZGlyOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcblxyXG4gIC8qKlxyXG4gICAqIEBjb25zdHJ1Y3RvclxyXG4gICAqL1xyXG4gIGNvbnN0cnVjdG9yKCBhdHRyaWJ1dGVzPzoge30gKVxyXG4gIHtcclxuICAgIGlmICggYXR0cmlidXRlcyApXHJcbiAgICB7XHJcbiAgICAgIGZvciggbGV0IGZpZWxkIGluIEFMVS5raW5kSW5mby5maWVsZHMgKVxyXG4gICAgICAgIGlmICggYXR0cmlidXRlc1sgZmllbGQuaWQgXSApXHJcbiAgICAgICAgICB0aGlzWyBmaWVsZC5pZCBdID0gYXR0cmlidXRlc1sgZmllbGQuaWQgXTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFNlcmlhbGl6YXRpb24sIHJldHVybnMgYSBKU09OIG9iamVjdFxyXG4gICAqL1xyXG4gIHB1YmxpYyB0b0pTT04oKToge31cclxuICB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBjb2RlOiB0aGlzLmNvZGUsXHJcbiAgICAgIGRhdGE6IHRoaXMuZGF0YSxcclxuICAgICAgZmNpOiB0aGlzLmZjaSxcclxuICAgICAgZGlyOiB0aGlzLmRpclxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgZ2V0QUxVU2VnbWVudCggYnl0ZXM6IEJ5dGVBcnJheSwgc2VnbWVudElEOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHZhciBvZmZzZXQgPSA4O1xyXG5cclxuICAgIHdoaWxlKCAoIHNlZ21lbnRJRCA+IDEgKSAmJiAoIG9mZnNldCA8IGJ5dGVzLmxlbmd0aCApIClcclxuICAgIHtcclxuICAgICAgb2Zmc2V0ICs9IDIgKyBieXRlcy53b3JkQXQoIG9mZnNldCApO1xyXG4gICAgICAtLXNlZ21lbnRJRDtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gYnl0ZXMudmlld0F0KCBvZmZzZXQgKyAyLCBieXRlcy53b3JkQXQoIG9mZnNldCApICk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBEZWNvZGVyIGZhY3RvcnkgZnVuY3Rpb24sIGRlY29kZXMgYSBibG9iIGludG8gYSBNdWx0b3NBTFUgb2JqZWN0XHJcbiAgICovXHJcbiAgcHVibGljIGRlY29kZUJ5dGVzKCBieXRlczogQnl0ZUFycmF5LCBvcHRpb25zPzogT2JqZWN0ICk6IHRoaXNcclxuICB7XHJcbiAgICB0aGlzLmNvZGUgPSB0aGlzLmdldEFMVVNlZ21lbnQoIGJ5dGVzLCAxICk7XHJcbiAgICB0aGlzLmRhdGEgPSB0aGlzLmdldEFMVVNlZ21lbnQoIGJ5dGVzLCAyICk7XHJcbiAgICB0aGlzLmRpciA9IHRoaXMuZ2V0QUxVU2VnbWVudCggYnl0ZXMsIDMgKTtcclxuICAgIHRoaXMuZmNpID0gdGhpcy5nZXRBTFVTZWdtZW50KCBieXRlcywgNCApO1xyXG5cclxuICAgIHJldHVybiB0aGlzO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogRW5jb2RlciBmdW5jdGlvbiwgcmV0dXJucyBhIGJsb2IgZnJvbSBhIE11bHRvc0FMVSBvYmplY3RcclxuICAgKi9cclxuICBwdWJsaWMgZW5jb2RlQnl0ZXMoIG9wdGlvbnM/OiB7fSApOiBCeXRlQXJyYXlcclxuICB7XHJcbiAgICAvL0AgVE9ETzogcmVidWlsZCBiaW5hcnkgQUxVXHJcbiAgICByZXR1cm4gbmV3IEJ5dGVBcnJheSggW10gKTtcclxuICB9XHJcbn1cclxuXHJcbktpbmRCdWlsZGVyLmluaXQoIEFMVSwgXCJNVUxUT1MgQXBwbGljYXRpb24gTG9hZCBVbml0XCIgKVxyXG4gIC5maWVsZCggXCJjb2RlXCIsIFwiQ29kZSBTZWdtZW50XCIsIEJ5dGVBcnJheSApXHJcbiAgLmZpZWxkKCBcImRhdGFcIiwgXCJEYXRhIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICAuZmllbGQoIFwiZmNpXCIsIFwiRkNJIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICAuZmllbGQoIFwiZGlyXCIsIFwiRElSIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICA7XHJcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
