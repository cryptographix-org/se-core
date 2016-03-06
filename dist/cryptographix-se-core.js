  import { ByteArray, Kind, KindBuilder, Message } from 'cryptographix-sim-core';











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
        this.endPoint = endPoint;
        this.slot = slot;
        endPoint.onMessage(this.onMessage);
    }
    unlinkSlot() {
        this.endPoint.onMessage(undefined);
        this.endPoint = undefined;
        this.slot = undefined;
    }
    onMessage(packet, receivingEndPoint) {
        let hdr = packet.header;
        let payload = packet.payload;
        switch (hdr.command) {
            case "executeAPDU":
                {
                    if (!(hdr.kind instanceof CommandAPDU))
                        break;
                    let commandAPDU = payload;
                    var resp = this.slot.executeAPDU(commandAPDU);
                    let x = null;
                    resp.then((responseAPDU) => {
                        let replyPacket = new Message({ method: "executeAPDU" }, responseAPDU);
                        receivingEndPoint.sendMessage(replyPacket);
                    })
                        .catch(() => {
                        let errorPacket = new Message({ method: "error" }, undefined);
                        receivingEndPoint.sendMessage(errorPacket);
                    });
                    break;
                }
        }
    }
}

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
        var cryptoText = new ByteBuffer(this.des(k.backingArray, data.byteArray.backingArray, 1, 0));
        return cryptoText.toByteString();
    }
    decrypt(key, mech, data) {
        return data;
    }
    sign(key, mech, data, iv) {
        var k = key.getComponent(Key.SECRET)._bytes;
        var keyData = k;
        if (k.length == 16) {
            keyData = new Uint8Array(24);
            keyData.set(k, 0);
            keyData.set(k.subarray(0, 8), 16);
        }
        if (iv == undefined)
            iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        var cryptoText = new ByteBuffer(this.des(keyData, data._bytes, 1, 1, iv, 4));
        return cryptoText.toByteString().bytes(-8);
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
ByteString.HEX = ByteArray.HEX;
ByteString.BASE64 = ByteArray.HEX;
export const HEX = ByteString.HEX;
export const BASE64 = ByteString.BASE64;


export class ByteBuffer {
    constructor(value, encoding) {
        if (value instanceof ByteArray) {
            this.byteArray = value;
        }
        else if (value instanceof ByteString) {
            this.byteArray = value.bytes;
        }
        else if (encoding != undefined) {
            this.byteArray = new ByteString(value, encoding).byteArray;
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
        this.atr = new ByteArray([]);
    }
    loadApplication(aid, applet) {
        this.applets.push({ aid: aid, applet: applet });
    }
    get isPowered() {
        return this.powerIsOn;
    }
    powerOn() {
        this.powerIsOn = true;
        return Promise.resolve(this.atr);
    }
    powerOff() {
        this.powerIsOn = false;
        this.selectedApplet = undefined;
        return Promise.resolve();
    }
    reset() {
        this.powerIsOn = true;
        this.selectedApplet = undefined;
        return Promise.resolve(this.atr);
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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImNvbXBvbmVudHMvYnl0ZS1kYXRhLWlucHV0LmpzIiwiY29tcG9uZW50cy9ieXRlLWRhdGEtb3V0cHV0LmpzIiwiY29tcG9uZW50cy9jcnlwdG9yLWJveC5qcyIsImNvbXBvbmVudHMvcnNhLWtleS1idWlsZGVyLmpzIiwiY29tcG9uZW50cy9zZWNyZXQta2V5LWJ1aWxkZXIuanMiLCJiYXNlL2Jhc2UtdGx2LnRzIiwiYmFzZS9jb21tYW5kLWFwZHUudHMiLCJiYXNlL2lzbzc4MTYudHMiLCJiYXNlL3Jlc3BvbnNlLWFwZHUudHMiLCJiYXNlL3Nsb3QuanMiLCJiYXNlL3Nsb3QtcHJvdG9jb2wtaGFuZGxlci50cyIsImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcva2V5LnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9jcnlwdG8udHMiLCJnbG9iYWwtcGxhdGZvcm0tc2NyaXB0aW5nL2J5dGUtc3RyaW5nLnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9ieXRlLWJ1ZmZlci50cyIsImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcvdGx2LnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy90bHYtbGlzdC50cyIsImpzaW0tY2FyZC9TbG90cy50cyIsImpzaW0tY2FyZC9qc2ltLWNhcmQuanMiLCJqc2ltLWNhcmQvanNpbS1zY3JpcHQtYXBwbGV0LnRzIiwianNpbS1jYXJkL2pzaW0tc2NyaXB0LWNhcmQudHMiLCJqc2ltLWNhcmQvanNpbS1zbG90LnRzIiwianNpbS1tdWx0b3MvbWVtb3J5LW1hbmFnZXIudHMiLCJqc2ltLW11bHRvcy9tZWwtZGVmaW5lcy50cyIsImpzaW0tbXVsdG9zL3ZpcnR1YWwtbWFjaGluZS50cyIsImpzaW0tbXVsdG9zL2pzaW0tbXVsdG9zLWNhcmQudHMiLCJqc2ltLW11bHRvcy9wcmltaXRpdmVzLnRzIiwianNpbS1tdWx0b3Mvc2VjdXJpdHktbWFuYWdlci50cyIsIm11bHRvcy9hZGMudHMiLCJtdWx0b3MvYWxjLnRzIiwibXVsdG9zL2FsdS50cyJdLCJuYW1lcyI6WyJCYXNlVExWIiwiQmFzZVRMVi5jb25zdHJ1Y3RvciIsIkJhc2VUTFYucGFyc2VUTFYiLCJCYXNlVExWLnRhZyIsIkJhc2VUTFYudmFsdWUiLCJCYXNlVExWLmxlbiIsIkNvbW1hbmRBUERVIiwiQ29tbWFuZEFQRFUuY29uc3RydWN0b3IiLCJDb21tYW5kQVBEVS5MYyIsIkNvbW1hbmRBUERVLmhlYWRlciIsIkNvbW1hbmRBUERVLmluaXQiLCJDb21tYW5kQVBEVS5zZXQiLCJDb21tYW5kQVBEVS5zZXRDTEEiLCJDb21tYW5kQVBEVS5zZXRJTlMiLCJDb21tYW5kQVBEVS5zZXRQMSIsIkNvbW1hbmRBUERVLnNldFAyIiwiQ29tbWFuZEFQRFUuc2V0RGF0YSIsIkNvbW1hbmRBUERVLnNldExlIiwiQ29tbWFuZEFQRFUudG9KU09OIiwiQ29tbWFuZEFQRFUuZW5jb2RlQnl0ZXMiLCJDb21tYW5kQVBEVS5kZWNvZGVCeXRlcyIsIklTTzc4MTYiLCJSZXNwb25zZUFQRFUiLCJSZXNwb25zZUFQRFUuY29uc3RydWN0b3IiLCJSZXNwb25zZUFQRFUuTGEiLCJSZXNwb25zZUFQRFUuaW5pdCIsIlJlc3BvbnNlQVBEVS5zZXQiLCJSZXNwb25zZUFQRFUuc2V0U1ciLCJSZXNwb25zZUFQRFUuc2V0U1cxIiwiUmVzcG9uc2VBUERVLnNldFNXMiIsIlJlc3BvbnNlQVBEVS5zZXREYXRhIiwiUmVzcG9uc2VBUERVLmVuY29kZUJ5dGVzIiwiUmVzcG9uc2VBUERVLmRlY29kZUJ5dGVzIiwiU2xvdFByb3RvY29sSGFuZGxlciIsIlNsb3RQcm90b2NvbEhhbmRsZXIuY29uc3RydWN0b3IiLCJTbG90UHJvdG9jb2xIYW5kbGVyLmxpbmtTbG90IiwiU2xvdFByb3RvY29sSGFuZGxlci51bmxpbmtTbG90IiwiU2xvdFByb3RvY29sSGFuZGxlci5vbk1lc3NhZ2UiLCJLZXkiLCJLZXkuY29uc3RydWN0b3IiLCJLZXkuc2V0VHlwZSIsIktleS5nZXRUeXBlIiwiS2V5LnNldFNpemUiLCJLZXkuZ2V0U2l6ZSIsIktleS5zZXRDb21wb25lbnQiLCJLZXkuZ2V0Q29tcG9uZW50IiwiQ3J5cHRvIiwiQ3J5cHRvLmNvbnN0cnVjdG9yIiwiQ3J5cHRvLmVuY3J5cHQiLCJDcnlwdG8uZGVjcnlwdCIsIkNyeXB0by5zaWduIiwiQ3J5cHRvLmRlcyIsIkNyeXB0by5kZXMuZGVzX2NyZWF0ZUtleXMiLCJDcnlwdG8udmVyaWZ5IiwiQ3J5cHRvLmRpZ2VzdCIsIkJ5dGVTdHJpbmciLCJCeXRlU3RyaW5nLmNvbnN0cnVjdG9yIiwiQnl0ZVN0cmluZy5sZW5ndGgiLCJCeXRlU3RyaW5nLmJ5dGVzIiwiQnl0ZVN0cmluZy5ieXRlQXQiLCJCeXRlU3RyaW5nLmVxdWFscyIsIkJ5dGVTdHJpbmcuY29uY2F0IiwiQnl0ZVN0cmluZy5sZWZ0IiwiQnl0ZVN0cmluZy5yaWdodCIsIkJ5dGVTdHJpbmcubm90IiwiQnl0ZVN0cmluZy5hbmQiLCJCeXRlU3RyaW5nLm9yIiwiQnl0ZVN0cmluZy5wYWQiLCJCeXRlU3RyaW5nLnRvU3RyaW5nIiwiQnl0ZUJ1ZmZlciIsIkJ5dGVCdWZmZXIuY29uc3RydWN0b3IiLCJCeXRlQnVmZmVyLmxlbmd0aCIsIkJ5dGVCdWZmZXIudG9CeXRlU3RyaW5nIiwiQnl0ZUJ1ZmZlci5jbGVhciIsIkJ5dGVCdWZmZXIuYXBwZW5kIiwiVExWIiwiVExWLmNvbnN0cnVjdG9yIiwiVExWLmdldFRMViIsIlRMVi5nZXRUYWciLCJUTFYuZ2V0VmFsdWUiLCJUTFYuZ2V0TCIsIlRMVi5nZXRMViIsIlRMVi5wYXJzZVRMViIsIlRMVkxpc3QiLCJUTFZMaXN0LmNvbnN0cnVjdG9yIiwiVExWTGlzdC5pbmRleCIsIkpTU2ltdWxhdGVkU2xvdCIsIkpTU2ltdWxhdGVkU2xvdC5Pbk1lc3NhZ2UiLCJKU1NpbXVsYXRlZFNsb3QuaW5pdCIsIkpTU2ltdWxhdGVkU2xvdC5zZW5kVG9Xb3JrZXIiLCJKU1NpbXVsYXRlZFNsb3QuZXhlY3V0ZUFQRFVDb21tYW5kIiwiSlNJTVNjcmlwdEFwcGxldCIsIkpTSU1TY3JpcHRBcHBsZXQuc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNU2NyaXB0QXBwbGV0LmRlc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNU2NyaXB0QXBwbGV0LmV4ZWN1dGVBUERVIiwiSlNJTVNjcmlwdENhcmQiLCJKU0lNU2NyaXB0Q2FyZC5jb25zdHJ1Y3RvciIsIkpTSU1TY3JpcHRDYXJkLmxvYWRBcHBsaWNhdGlvbiIsIkpTSU1TY3JpcHRDYXJkLmlzUG93ZXJlZCIsIkpTSU1TY3JpcHRDYXJkLnBvd2VyT24iLCJKU0lNU2NyaXB0Q2FyZC5wb3dlck9mZiIsIkpTSU1TY3JpcHRDYXJkLnJlc2V0IiwiSlNJTVNjcmlwdENhcmQuZXhjaGFuZ2VBUERVIiwiSlNJTVNsb3QiLCJKU0lNU2xvdC5jb25zdHJ1Y3RvciIsIkpTSU1TbG90LmlzUHJlc2VudCIsIkpTSU1TbG90LmlzUG93ZXJlZCIsIkpTSU1TbG90LnBvd2VyT24iLCJKU0lNU2xvdC5wb3dlck9mZiIsIkpTSU1TbG90LnJlc2V0IiwiSlNJTVNsb3QuZXhlY3V0ZUFQRFUiLCJKU0lNU2xvdC5pbnNlcnRDYXJkIiwiSlNJTVNsb3QuZWplY3RDYXJkIiwiaGV4MiIsImhleDQiLCJNRU1GTEFHUyIsIlNlZ21lbnQiLCJTZWdtZW50LmNvbnN0cnVjdG9yIiwiU2VnbWVudC5nZXRUeXBlIiwiU2VnbWVudC5nZXRMZW5ndGgiLCJTZWdtZW50LmdldEZsYWdzIiwiU2VnbWVudC5nZXREZWJ1ZyIsIlNlZ21lbnQuYmVnaW5UcmFuc2FjdGlvbiIsIlNlZ21lbnQuZW5kVHJhbnNhY3Rpb24iLCJTZWdtZW50LnJlYWRCeXRlIiwiU2VnbWVudC56ZXJvQnl0ZXMiLCJTZWdtZW50LnJlYWRCeXRlcyIsIlNlZ21lbnQuY29weUJ5dGVzIiwiU2VnbWVudC53cml0ZUJ5dGVzIiwiU2VnbWVudC5uZXdBY2Nlc3NvciIsIkFjY2Vzc29yIiwiQWNjZXNzb3IuY29uc3RydWN0b3IiLCJBY2Nlc3Nvci50cmFjZU1lbW9yeU9wIiwiQWNjZXNzb3IudHJhY2VNZW1vcnlWYWx1ZSIsIkFjY2Vzc29yLnplcm9CeXRlcyIsIkFjY2Vzc29yLnJlYWRCeXRlIiwiQWNjZXNzb3IucmVhZEJ5dGVzIiwiQWNjZXNzb3IuY29weUJ5dGVzIiwiQWNjZXNzb3Iud3JpdGVCeXRlIiwiQWNjZXNzb3Iud3JpdGVCeXRlcyIsIkFjY2Vzc29yLmdldFR5cGUiLCJBY2Nlc3Nvci5nZXRMZW5ndGgiLCJBY2Nlc3Nvci5nZXRJRCIsIkFjY2Vzc29yLmdldERlYnVnIiwic2xpY2VEYXRhIiwiTWVtb3J5TWFuYWdlciIsIk1lbW9yeU1hbmFnZXIuY29uc3RydWN0b3IiLCJNZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQiLCJNZW1vcnlNYW5hZ2VyLmdldE1lbVRyYWNlIiwiTWVtb3J5TWFuYWdlci5pbml0TWVtVHJhY2UiLCJNZW1vcnlNYW5hZ2VyLmdldFNlZ21lbnQiLCJNRUxJTlNUIiwiTUVMVEFHQUREUiIsIk1FTFRBR0NPTkQiLCJNRUxUQUdTWVNURU0iLCJNRUxUQUdTVEFDSyIsIk1FTFRBR1BSSU1SRVQiLCJNRUxQQVJBTURFRiIsIk1FTFBBUkFNNCIsIk9QVEFHMk1FTElOU1QiLCJNRUwyT1BDT0RFIiwiTUVMMklOU1QiLCJNRUwyVEFHIiwiTUVMUEFSQU1TSVpFIiwiTUVMIiwic2V0TWVsRGVjb2RlIiwic2V0TWVsRGVjb2RlU3RkTW9kZXMiLCJzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyIsImZpbGxNZWxEZWNvZGUiLCJoZXgiLCJsanVzdCIsInJqdXN0IiwiQkEyVyIsIlcyQkEiLCJNRUxWaXJ0dWFsTWFjaGluZSIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0cnVjdG9yIiwiTUVMVmlydHVhbE1hY2hpbmUuaW5pdE1WTSIsIk1FTFZpcnR1YWxNYWNoaW5lLmRpc2Fzc2VtYmxlQ29kZSIsIk1FTFZpcnR1YWxNYWNoaW5lLmRpc2Fzc2VtYmxlQ29kZS5wcmludCIsIk1FTFZpcnR1YWxNYWNoaW5lLm1hcFRvU2VnbWVudEFkZHIiLCJNRUxWaXJ0dWFsTWFjaGluZS5tYXBGcm9tU2VnbWVudEFkZHIiLCJNRUxWaXJ0dWFsTWFjaGluZS5jaGVja0RhdGFBY2Nlc3MiLCJNRUxWaXJ0dWFsTWFjaGluZS5yZWFkU2VnbWVudERhdGEiLCJNRUxWaXJ0dWFsTWFjaGluZS53cml0ZVNlZ21lbnREYXRhIiwiTUVMVmlydHVhbE1hY2hpbmUucHVzaFplcm9zVG9TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2hDb25zdFRvU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5jb3B5T25TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2hUb1N0YWNrIiwiTUVMVmlydHVhbE1hY2hpbmUucG9wRnJvbVN0YWNrQW5kU3RvcmUiLCJNRUxWaXJ0dWFsTWFjaGluZS5wb3BGcm9tU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5zZXR1cEFwcGxpY2F0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuaW5pdEV4ZWN1dGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0Qnl0ZUJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0V29yZEJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLnVuYXJ5T3BlcmF0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuaGFuZGxlUmV0dXJuIiwiTUVMVmlydHVhbE1hY2hpbmUuaXNDb25kaXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS5leGVjdXRlU3RlcCIsIk1FTFZpcnR1YWxNYWNoaW5lLnNldENvbW1hbmRBUERVIiwiTUVMVmlydHVhbE1hY2hpbmUuZ2V0UmVzcG9uc2VBUERVIiwiTUVMVmlydHVhbE1hY2hpbmUuZ2V0RGVidWciLCJKU0lNTXVsdG9zQXBwbGV0IiwiSlNJTU11bHRvc0FwcGxldC5jb25zdHJ1Y3RvciIsIkpTSU1NdWx0b3NDYXJkIiwiSlNJTU11bHRvc0NhcmQuY29uc3RydWN0b3IiLCJKU0lNTXVsdG9zQ2FyZC5sb2FkQXBwbGljYXRpb24iLCJKU0lNTXVsdG9zQ2FyZC5pc1Bvd2VyZWQiLCJKU0lNTXVsdG9zQ2FyZC5wb3dlck9uIiwiSlNJTU11bHRvc0NhcmQucG93ZXJPZmYiLCJKU0lNTXVsdG9zQ2FyZC5yZXNldCIsIkpTSU1NdWx0b3NDYXJkLmV4Y2hhbmdlQVBEVSIsIkpTSU1NdWx0b3NDYXJkLmluaXRpYWxpemVWTSIsIkpTSU1NdWx0b3NDYXJkLnJlc2V0Vk0iLCJKU0lNTXVsdG9zQ2FyZC5zaHV0ZG93blZNIiwiSlNJTU11bHRvc0NhcmQuc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNTXVsdG9zQ2FyZC5leGVjdXRlU3RlcCIsImJpdE1hbmlwdWxhdGUiLCJjYWxsUHJpbWl0aXZlIiwiU2VjdXJpdHlNYW5hZ2VyIiwiU2VjdXJpdHlNYW5hZ2VyLmluaXRTZWN1cml0eSIsIlNlY3VyaXR5TWFuYWdlci5wcm9jZXNzQVBEVSIsIkFEQyIsIkFMQyIsIkFMVSIsIkFMVS5jb25zdHJ1Y3RvciIsIkFMVS50b0pTT04iLCJBTFUuZ2V0QUxVU2VnbWVudCIsIkFMVS5kZWNvZGVCeXRlcyIsIkFMVS5lbmNvZGVCeXRlcyJdLCJtYXBwaW5ncyI6IkFBQUE7QUFDQTtBQ0RBO0FBQ0E7QUNEQTtBQUNBO0FDREE7QUFDQTtBQ0RBO0FBQ0E7T0NETyxFQUFFLFNBQVMsRUFBRSxNQUFNLHdCQUF3QjtBQUVsRDtJQThERUEsWUFBY0EsR0FBV0EsRUFBRUEsS0FBZ0JBLEVBQUVBLFFBQWlCQTtRQUU1REMsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsUUFBUUEsSUFBSUEsT0FBT0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0E7UUFFbERBLE1BQU1BLENBQUFBLENBQUVBLElBQUlBLENBQUNBLFFBQVNBLENBQUNBLENBQ3ZCQSxDQUFDQTtZQUNDQSxLQUFLQSxPQUFPQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQTtnQkFDMUJBLENBQUNBO29CQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFFbENBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUtBLEtBQU1BLENBQUNBO3dCQUNsQkEsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7b0JBQzNDQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFDQTtvQkFFaENBLElBQUlBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLENBQUNBO29CQUN2QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBS0EsQ0FBQ0EsQ0FDakJBLENBQUNBO3dCQUNDQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTt3QkFDMUJBLFNBQVNBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO29CQUMzQ0EsQ0FBQ0E7b0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLEdBQUdBLElBQUtBLENBQUNBO3dCQUNwQkEsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7b0JBRTVCQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFDQTtvQkFFaENBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLEtBQUtBLENBQUVBLENBQUNBO29CQUUxQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsU0FBU0EsQ0FBQ0E7b0JBRTNCQSxLQUFLQSxDQUFDQTtnQkFDUkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUF2RkRELE9BQU9BLFFBQVFBLENBQUVBLE1BQWlCQSxFQUFFQSxRQUFnQkE7UUFFbERFLElBQUlBLEdBQUdBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEtBQUtBLEVBQUVBLFNBQVNBLEVBQUVBLFNBQVNBLEVBQUVBLENBQUNBLEVBQUVBLFdBQVdBLEVBQUVBLENBQUNBLEVBQUVBLENBQUNBO1FBQzdFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNaQSxJQUFJQSxLQUFLQSxHQUFHQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQTtRQUVoQ0EsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FDbEJBLENBQUNBO1lBQ0NBLEtBQUtBLE9BQU9BLENBQUNBLFNBQVNBLENBQUNBLEdBQUdBO2dCQUMxQkEsQ0FBQ0E7b0JBQ0NBLE9BQU9BLENBQUVBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUVBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLElBQUlBLElBQUlBLENBQUVBLElBQUlBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLElBQUlBLElBQUlBLENBQUVBLENBQUVBO3dCQUN2RkEsRUFBRUEsR0FBR0EsQ0FBQ0E7b0JBRVJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBO3dCQUN4QkEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBRWJBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLElBQUtBLENBQUNBLENBQ3RDQSxDQUFDQTt3QkFDQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBQ0E7d0JBQzlCQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxLQUFLQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUMxQkEsQ0FBQ0E7NEJBQWdCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTt3QkFBQ0EsQ0FBQ0E7b0JBQ2pDQSxDQUFDQTtvQkFFREEsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsS0FBS0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBRUEsQ0FBQ0E7b0JBRTFCQSxHQUFHQSxDQUFDQSxTQUFTQSxHQUFHQSxHQUFHQSxDQUFDQTtvQkFFcEJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBLENBQzFCQSxDQUFDQTt3QkFBZ0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO29CQUFDQSxDQUFDQTtvQkFFL0JBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLEdBQUdBLENBQUVBLEtBQUtBLENBQUVBLEdBQUdBLEVBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBO29CQUNqRUEsT0FBT0EsRUFBRUEsRUFBRUEsR0FBR0EsQ0FBQ0EsRUFDZkEsQ0FBQ0E7d0JBQ0NBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBLENBQzFCQSxDQUFDQTs0QkFBNENBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO3dCQUFDQSxDQUFDQTt3QkFFM0RBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUVBLEdBQUdBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLEtBQUtBLENBQUVBLEdBQUdBLEVBQUVBLENBQUVBLENBQUNBO29CQUM5Q0EsQ0FBQ0E7b0JBRURBLEdBQUdBLENBQUNBLFdBQVdBLEdBQUdBLEdBQUdBLENBQUNBO29CQUN0QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDckNBLENBQUNBO3dCQUFnQkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7b0JBQUNBLENBQUNBO29CQUM3QkEsR0FBR0EsQ0FBQ0EsS0FBS0EsR0FBR0EsS0FBS0EsQ0FBQ0EsS0FBS0Es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WUFDYkEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7WUFDYkEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUE7WUFDWEEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUE7WUFDWEEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUE7WUFDZkEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUE7U0FDWkEsQ0FBQ0E7SUFDSkEsQ0FBQ0E7SUFLTVosV0FBV0EsQ0FBRUEsT0FBWUE7UUFFOUJhLElBQUlBLElBQUlBLEdBQUdBLENBQUVBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLEdBQUdBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO1FBQ2pEQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNqREEsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsU0FBU0EsRUFBRUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFHMUNBLEVBQUVBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBO1FBQ2hDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNkQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUMzQkEsRUFBRUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFDaENBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBQ2xCQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNwQ0EsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7SUFDWkEsQ0FBQ0E7SUFLTWIsV0FBV0EsQ0FBRUEsU0FBb0JBLEVBQUVBLE9BQVlBO1FBRXBEYyxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQTtZQUN6QkEsTUFBTUEsSUFBSUEsS0FBS0EsQ0FBRUEsNkJBQTZCQSxDQUFFQSxDQUFDQTtRQUVuREEsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFZkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsU0FBU0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsTUFBTUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDeENBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLE1BQU1BLEVBQUVBLENBQUVBLENBQUNBO1FBQ3hDQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUN2Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsU0FBU0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsTUFBTUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFdkNBLEVBQUVBLENBQUNBLENBQUVBLFNBQVNBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLEdBQUdBLENBQUVBLENBQUNBLENBQ3BDQSxDQUFDQTtZQUNDQSxJQUFJQSxFQUFFQSxHQUFHQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUN0Q0EsSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFDNUNBLE1BQU1BLElBQUlBLEVBQUVBLENBQUNBO1FBQ2ZBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUVBLFNBQVNBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU9BLENBQUNBO1lBQzlCQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV6Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsQ0FBQ0EsTUFBTUEsSUFBSUEsTUFBT0EsQ0FBQ0E7WUFDL0JBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLDZCQUE2QkEsQ0FBRUEsQ0FBQ0E7UUFFbkRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0FBQ0hkLENBQUNBO0FBRUQsV0FBVyxDQUFDLElBQUksQ0FBRSxXQUFXLEVBQUUsc0JBQXNCLENBQUU7S0FDcEQsU0FBUyxDQUFFLEtBQUssRUFBRSxPQUFPLENBQUU7S0FDM0IsU0FBUyxDQUFFLEtBQUssRUFBRSxhQUFhLENBQUU7S0FDakMsU0FBUyxDQUFFLElBQUksRUFBRSxVQUFVLENBQUU7S0FDN0IsU0FBUyxDQUFFLElBQUksRUFBRSxVQUFVLENBQUU7S0FDN0IsWUFBWSxDQUFFLElBQUksRUFBRSxnQkFBZ0IsRUFBRSxFQUFFLFVBQVUsRUFBRSxJQUFJLEVBQUUsQ0FBRTtLQUM1RCxLQUFLLENBQUUsTUFBTSxFQUFFLGNBQWMsRUFBRSxTQUFTLENBQUU7S0FDMUMsWUFBWSxDQUFFLElBQUksRUFBRSxpQkFBaUIsQ0FBRSxDQUN2QztBQ3RJSCxXQUFZLE9BNkhYO0FBN0hELFdBQVksT0FBTztJQUdqQmUsMkNBQWNBLENBQUFBO0lBR2RBLGlGQUFnQ0EsQ0FBQUE7SUFHaENBLGlFQUF3QkEsQ0FBQUE7SUFHeEJBLGlGQUFnQ0EsQ0FBQUE7SUFHaENBLDZEQUFzQkEsQ0FBQUE7SUFHdEJBLDZEQUFzQkEsQ0FBQUE7SUFHdEJBLGlFQUF3QkEsQ0FBQUE7SUFHeEJBLGtEQUFpQkEsQ0FBQUE7SUFHakJBLHdFQUE0QkEsQ0FBQUE7SUFHNUJBLDRFQUE4QkEsQ0FBQUE7SUFHOUJBLDBFQUE2QkEsQ0FBQUE7SUFHN0JBLHVEQUFtQkEsQ0FBQUE7SUFHbkJBLDhFQUErQkEsQ0FBQUE7SUFHL0JBLHVGQUFtQ0EsQ0FBQUE7SUFHbkNBLCtEQUF1QkEsQ0FBQUE7SUFHdkJBLDRDQUFjQSxDQUFBQTtJQUdkQSx3RUFBNEJBLENBQUFBO0lBRzVCQSxpRkFBaUNBLENBQUFBO0lBR2pDQSw2RkFBdUNBLENBQUFBO0lBR3ZDQSx1RkFBb0NBLENBQUFBO0lBR3BDQSx1RUFBNEJBLENBQUFBO0lBRzVCQSwrRUFBZ0NBLENBQUFBO0lBR2hDQSw2REFBdUJBLENBQUFBO0lBR3ZCQSw0Q0FBY0EsQ0FBQUE7SUFHZEEsK0VBQWdDQSxDQUFBQTtJQUdoQ0EsaUVBQXlCQSxDQUFBQTtJQUV6QkEsK0RBQXFCQSxDQUFBQTtJQUVyQkEsNkRBQXFCQSxDQUFBQTtJQUVyQkEscURBQW1CQSxDQUFBQTtJQUVuQkEsNkZBQXVDQSxDQUFBQTtJQUN2Q0EsaUdBQXlDQSxDQUFBQTtJQUN6Q0EscUdBQTJDQSxDQUFBQTtJQUMzQ0EsaUZBQWlDQSxDQUFBQTtJQUNqQ0EsdUZBQW9DQSxDQUFBQTtJQUNwQ0EseUZBQXFDQSxDQUFBQTtJQUNyQ0EseUZBQXFDQSxDQUFBQTtJQUtyQ0EsK0RBQXdCQSxDQUFBQTtJQUN4QkEsbUdBQTBDQSxDQUFBQTtJQUMxQ0EsaUdBQXlDQSxDQUFBQTtJQUN6Q0EsbUdBQTBDQSxDQUFBQTtJQUMxQ0EsNkVBQStCQSxDQUFBQTtJQUMvQkEsdUhBQW9EQSxDQUFBQTtJQUNwREEsaUdBQXlDQSxDQUFBQTtJQUN6Q0EsK0RBQXdCQSxDQUFBQTtJQUN4QkEsK0RBQXdCQSxDQUFBQTtJQUN4QkEsdUZBQW9DQSxDQUFBQTtJQUNwQ0EseUZBQXFDQSxDQUFBQTtJQUNyQ0EsdUdBQTRDQSxDQUFBQTtJQUM1Q0EseUZBQXFDQSxDQUFBQTtJQUNyQ0EsK0RBQXdCQSxDQUFBQTtJQUN4QkEsMkRBQXNCQSxDQUFBQTtJQUN0QkEsMkVBQThCQSxDQUFBQTtJQUM5QkEsbUVBQTBCQSxDQUFBQTtJQUMxQkEsdUVBQTRCQSxDQUFBQTtJQUM1QkEsdUZBQW9DQSxDQUFBQTtJQUNwQ0EsdUZBQW9DQSxDQUFBQTtJQUNwQ0EsbUVBQTBCQSxDQUFBQTtJQUMxQkEseUZBQXFDQSxDQUFBQTtJQUNyQ0EseUZBQXFDQSxDQUFBQTtJQUNyQ0EsMkRBQXNCQSxDQUFBQTtJQUV0QkEseUVBQTZCQSxDQUFBQTtJQUM3QkEseUVBQTZCQSxDQUFBQTtJQUM3QkEscURBQW1CQSxDQUFBQTtBQUNyQkEsQ0FBQ0EsRUE3SFcsT0FBTyxLQUFQLE9BQU8sUUE2SGxCOztPQzdITSxFQUFFLFNBQVMsRUFBRSxJQUFJLEVBQVksV0FBVyxFQUFFLE1BQU0sd0JBQXdCO09BQ3hFLEVBQUUsT0FBTyxFQUFFLE1BQU0sV0FBVztBQUtuQztJQVlFQyxZQUFhQSxVQUFlQTtRQVY1QkMsT0FBRUEsR0FBV0EsT0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBQ0E7UUFDaENBLFNBQUlBLEdBQWNBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBO1FBV2hDQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFREQsSUFBV0EsRUFBRUEsS0FBS0UsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFFNUNGLE9BQWNBLElBQUlBLENBQUVBLEVBQVVBLEVBQUVBLElBQWdCQTtRQUU5Q0csTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsWUFBWUEsRUFBRUEsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDaERBLENBQUNBO0lBRU1ILEdBQUdBLENBQUVBLEVBQVVBLEVBQUVBLElBQWdCQTtRQUV0Q0ksSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFDYkEsSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsSUFBSUEsSUFBSUEsSUFBSUEsU0FBU0EsRUFBRUEsQ0FBQ0E7UUFFcENBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRU1KLEtBQUtBLENBQUVBLEVBQVVBLElBQTBCSyxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN2RUwsTUFBTUEsQ0FBRUEsR0FBV0EsSUFBd0JNLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLElBQUlBLENBQUVBLEdBQUdBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLENBQUVBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQ3RHTixNQUFNQSxDQUFFQSxHQUFXQSxJQUF3Qk8sSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsTUFBTUEsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDL0ZQLE9BQU9BLENBQUVBLElBQWVBLElBQW1CUSxJQUFJQSxDQUFDQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUszRVIsV0FBV0EsQ0FBRUEsT0FBWUE7UUFFOUJTLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO1FBRWxEQSxFQUFFQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUM5QkEsRUFBRUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsRUFBTUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFDckRBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLEVBQUVBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxFQUFFQSxDQUFDQTtJQUNaQSxDQUFDQTtJQUVNVCxXQUFXQSxDQUFFQSxTQUFvQkEsRUFBRUEsT0FBWUE7UUFFcERVLEVBQUVBLENBQUNBLENBQUVBLFNBQVNBLENBQUNBLE1BQU1BLEdBQUdBLENBQUVBLENBQUNBO1lBQ3pCQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSw2QkFBNkJBLENBQUVBLENBQUNBO1FBRW5EQSxJQUFJQSxFQUFFQSxHQUFHQSxTQUFTQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUU5QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsU0FBU0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDakNBLElBQUlBLENBQUNBLElBQUlBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLEdBQUdBLFNBQVNBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUVBLEdBQUdBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBO1FBRWxFQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtBQUNIVixDQUFDQTtBQUVELFdBQVcsQ0FBQyxJQUFJLENBQUUsWUFBWSxFQUFFLHVCQUF1QixDQUFFO0tBQ3RELFlBQVksQ0FBRSxJQUFJLEVBQUUsYUFBYSxFQUFFLEVBQUUsT0FBTyxFQUFFLE1BQU0sRUFBRSxDQUFFO0tBQ3hELFlBQVksQ0FBRSxJQUFJLEVBQUUsZUFBZSxFQUFHLEVBQUUsVUFBVSxFQUFFLElBQUksRUFBRSxDQUFFO0tBQzVELEtBQUssQ0FBRSxNQUFNLEVBQUUsZUFBZSxFQUFFLFNBQVMsQ0FBRSxDQUMzQztBQzNFSDtBQUNBO09DRE8sRUFBdUIsT0FBTyxFQUFpQixNQUFNLHdCQUF3QjtPQUc3RSxFQUFFLFdBQVcsRUFBRSxNQUFNLHNCQUFzQjtBQUdsRDtJQUtFVztJQUVBQyxDQUFDQTtJQUVERCxRQUFRQSxDQUFFQSxJQUFVQSxFQUFFQSxRQUFrQkE7UUFFdENFLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFFBQVFBLENBQUNBO1FBQ3pCQSxJQUFJQSxDQUFDQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUVqQkEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7SUFDdkNBLENBQUNBO0lBRURGLFVBQVVBO1FBRVJHLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBQ3JDQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxTQUFTQSxDQUFDQTtRQUMxQkEsSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURILFNBQVNBLENBQUVBLE1BQW9CQSxFQUFFQSxpQkFBMkJBO1FBRTFESSxJQUFJQSxHQUFHQSxHQUFRQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUM3QkEsSUFBSUEsT0FBT0EsR0FBR0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBQ0E7UUFFN0JBLE1BQU1BLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLE9BQVFBLENBQUNBLENBQ3JCQSxDQUFDQTtZQUNDQSxLQUFLQSxhQUFhQTtnQkFDbEJBLENBQUNBO29CQUNDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxJQUFJQSxZQUFZQSxXQUFXQSxDQUFHQSxDQUFDQTt3QkFDekNBLEtBQUtBLENBQUNBO29CQUVSQSxJQUFJQSxXQUFXQSxHQUE2QkEsT0FBT0EsQ0FBQ0E7b0JBRXBEQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxXQUFXQSxDQUFFQSxDQUFDQTtvQkFDaERBLElBQUlBLENBQUNBLEdBQWtCQSxJQUFJQSxDQUFDQTtvQkFFNUJBLElBQUlBLENBQUNBLElBQUlBLENBQUVBLENBQUVBLFlBQVlBO3dCQUN2QkEsSUFBSUEsV0FBV0EsR0FBR0EsSUFBSUEsT0FBT0EsQ0FBZ0JBLEVBQUVBLE1BQU1BLEVBQUVBLGFBQWFBLEVBQUVBLEVBQUVBLFlBQVlBLENBQUVBLENBQUNBO3dCQUV2RkEsaUJBQWlCQSxDQUFDQSxXQUFXQSxDQUFFQSxXQUFXQSxDQUFFQSxDQUFDQTtvQkFDL0NBLENBQUNBLENBQUNBO3lCQUNEQSxLQUFLQSxDQUFFQTt3QkFDTkEsSUFBSUEsV0FBV0EsR0FBR0EsSUFBSUEsT0FBT0EsQ0FBU0EsRUFBRUEsTUFBTUEsRUFBRUEsT0FBT0EsRUFBRUEsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7d0JBRXZFQSxpQkFBaUJBLENBQUNBLFdBQVdBLENBQUVBLFdBQVdBLENBQUVBLENBQUNBO29CQUMvQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRUhBLEtBQUtBLENBQUNBO2dCQUNSQSxDQUFDQTtRQXFCQ0EsQ0FBQ0E7SUFDUEEsQ0FBQ0E7QUFDSEosQ0FBQ0E7QUFBQSxBQ2hGRDtJQU1FSztRQUVFQyxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNmQSxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUNoQkEsSUFBSUEsQ0FBQ0EsZUFBZUEsR0FBR0EsRUFBRUEsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBRURELE9BQU9BLENBQUVBLE9BQWVBO1FBRXRCRSxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQSxPQUFPQSxDQUFDQTtJQUN2QkEsQ0FBQ0E7SUFFREYsT0FBT0E7UUFFTEcsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7SUFDcEJBLENBQUNBO0lBRURILE9BQU9BLENBQUVBLElBQVlBO1FBRW5CSSxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtJQUNwQkEsQ0FBQ0E7SUFFREosT0FBT0E7UUFFTEssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7SUFDcEJBLENBQUNBO0lBRURMLFlBQVlBLENBQUVBLElBQVlBLEVBQUVBLEtBQWlCQTtRQUUzQ00sSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsSUFBSUEsQ0FBRUEsR0FBR0EsS0FBS0EsQ0FBQ0E7SUFDdkNBLENBQUNBO0lBRUROLFlBQVlBLENBQUVBLElBQVlBO1FBRXhCTyxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7QUFnQkhQLENBQUNBO0FBYlEsVUFBTSxHQUFHLENBQUMsQ0FBQztBQUNYLFdBQU8sR0FBRyxDQUFDLENBQUM7QUFDWixVQUFNLEdBQUcsQ0FBQyxDQUFDO0FBRVgsT0FBRyxHQUFHLENBQUMsQ0FBQztBQUNSLE9BQUcsR0FBRyxDQUFDLENBQUM7QUFDUixXQUFPLEdBQUcsQ0FBQyxDQUFDO0FBQ1osWUFBUSxHQUFHLENBQUMsQ0FBQztBQUNiLFNBQUssR0FBRyxDQUFDLENBQUM7QUFDVixTQUFLLEdBQUcsQ0FBQyxDQUFDO0FBQ1YsV0FBTyxHQUFHLENBQUMsQ0FBQztBQUNaLFdBQU8sR0FBRyxDQUFDLENBQUM7QUFDWixVQUFNLEdBQUcsQ0FBQyxDQUNsQjs7T0MzRE0sRUFBRSxTQUFTLEVBQUUsTUFBTSx3QkFBd0I7T0FFM0MsRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlO09BQ25DLEVBQUUsR0FBRyxFQUFFLE1BQU0sT0FBTztBQUUzQjtJQUVFUTtJQUVBQyxDQUFDQTtJQUVERCxPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFnQkE7UUFFbENFLElBQUlBLENBQUNBLEdBQWNBLEdBQUdBLENBQUNBLFlBQVlBLENBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLFNBQVNBLENBQUNBO1FBRTVEQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFHQSxDQUFDQSxDQUNyQkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFYkEsQ0FBQ0EsR0FBR0EsSUFBSUEsU0FBU0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFFeENBLENBQUNBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO1lBQ3hCQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUMxQ0EsQ0FBQ0E7UUFFREEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFakdBLE1BQU1BLENBQUNBLFVBQVVBLENBQUNBLFlBQVlBLEVBQUVBLENBQUNBO0lBQ25DQSxDQUFDQTtJQUVERixPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQTtRQUV0QkcsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFREgsSUFBSUEsQ0FBRUEsR0FBR0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsRUFBR0E7UUFFeEJJLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLFlBQVlBLENBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLE1BQU1BLENBQUNBO1FBRTlDQSxJQUFJQSxPQUFPQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVoQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBR0EsQ0FBQ0EsQ0FDckJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1lBRS9CQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUNwQkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDeENBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLFNBQVVBLENBQUNBO1lBQ3BCQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUk1RUEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFakZBLE1BQU1BLENBQUNBLFVBQVVBLENBQUNBLFlBQVlBLEVBQUVBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO0lBQy9DQSxDQUFDQTtJQUtPSixHQUFHQSxDQUFFQSxHQUFlQSxFQUFFQSxPQUFtQkEsRUFBRUEsT0FBZUEsRUFBRUEsSUFBWUEsRUFBRUEsRUFBZUEsRUFBRUEsT0FBZ0JBO1FBS2pISyx3QkFBeUJBLEdBQUdBO1lBRTFCQyxFQUFFQSxDQUFDQSxDQUFFQSxNQUFNQSxDQUFDQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUNoQ0EsQ0FBQ0E7Z0JBRUNBLE1BQU1BLENBQUNBLEtBQUtBLEdBQUdBO29CQUNiQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFFQSxDQUFFQTtvQkFDNUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3JKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDOUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO29CQUMzSUEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3ZKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDcktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUNqTEEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDN0pBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO29CQUNuSkEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ25MQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdEtBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLENBQUNBLENBQUVBO2lCQUM5R0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7WUFHREEsSUFBSUEsVUFBVUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFeENBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFdBQVdBLENBQUNBLEVBQUVBLEdBQUdBLFVBQVVBLENBQUNBLENBQUNBO1lBRTVDQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVoRUEsSUFBSUEsUUFBUUEsRUFBRUEsU0FBU0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0E7WUFFeENBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQy9CQSxDQUFDQTtnQkFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3pFQSxLQUFLQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFFekVBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ25GQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtnQkFFbkRBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUN0R0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBR2JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLE1BQU1BLEVBQUVBLENBQUNBLEVBQUVBLEVBQ3BDQSxDQUFDQTtvQkFFQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTt3QkFDQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBQUNBLEtBQUtBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO29CQUM1RUEsQ0FBQ0E7b0JBQ0RBLElBQUlBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFNNUJBLFFBQVFBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNqRkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ3pGQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDeEZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUN0REEsU0FBU0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ25GQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDNUZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUM1RkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ3pEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxTQUFTQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtvQkFDcERBLElBQUlBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBO29CQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxTQUFTQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDcEVBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBQ2RBLENBQUNBO1FBR0RELEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLENBQUNBLEtBQUtBLElBQUlBLFNBQVVBLENBQUNBLENBQ2hDQSxDQUFDQTtZQUNDQSxNQUFNQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDYkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pmQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDam9CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDcm1CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDempCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTthQUN0bEJBLENBQUNBO1FBQ0pBLENBQUNBO1FBR0RBLElBQUlBLElBQUlBLEdBQUdBLGNBQWNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxPQUFPQSxDQUFDQTtRQUMxQ0EsSUFBSUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBQUE7UUFDMUNBLElBQUlBLEdBQUdBLEdBQUdBLE9BQU9BLENBQUNBLE1BQU1BLENBQUNBO1FBR3pCQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUUzQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLE9BQU9BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO1FBQ3BEQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNsR0EsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsT0FBT0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FDbkRBLENBQUNBO1lBQ0NBLElBQUlBLGVBQWVBLEdBQUdBLE9BQU9BLENBQUNBO1lBQzlCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUVwQkEsT0FBT0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDcENBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLGVBQWVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBRWxDQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7Z0JBQ0NBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtvQkFDekZBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxDQUFDQTtvQkFDTkEsQ0FBQ0E7d0JBQ0NBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUU5RUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ1hBLEdBQUdBLElBQUVBLENBQUNBLENBQUNBO3dCQUVUQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDdkZBLEtBQUtBLENBQUNBO1lBRVZBLENBQUNBO1lBRURBLEdBQUdBLElBQUlBLENBQUNBLEdBQUNBLENBQUNBLEdBQUdBLEdBQUNBLENBQUNBLENBQUNBLENBQUFBO1FBQ2xCQSxDQUFDQTtRQUdEQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVuQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFVkEsT0FBT0EsR0FBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDeEVBLFFBQVFBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1FBQzFFQSxDQUFDQTtRQUVEQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdYQSxPQUFPQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUNkQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUN6RkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFHekZBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsT0FBT0EsQ0FBQ0E7b0JBQUNBLEtBQUtBLElBQUlBLFFBQVFBLENBQUNBO2dCQUNyQ0EsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtvQkFDbkJBLFNBQVNBLEdBQUdBLFFBQVFBLENBQUNBO29CQUNyQkEsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQ2pGQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRS9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNyQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHeENBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLElBQUVBLENBQUNBLEVBQzVCQSxDQUFDQTtnQkFDQ0EsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzNCQSxJQUFJQSxPQUFPQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFHM0JBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLE9BQU9BLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQ3pDQSxDQUFDQTtvQkFDQ0EsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzdCQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFHekRBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO29CQUNaQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtvQkFDYkEsS0FBS0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQ25HQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDMUZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNuR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzlHQSxDQUFDQTtnQkFFREEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUFDQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtZQUMxQ0EsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHL0VBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxJQUFJQSxJQUFJQSxRQUFRQSxDQUFDQTtvQkFDakJBLEtBQUtBLElBQUlBLFNBQVNBLENBQUNBO2dCQUNyQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFFREEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBR0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsS0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsQ0FBQ0Es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QUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLEVBQUVBLENBQUNBLEVBQUVBLEVBQzlDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBRWxDQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFDQSxJQUFJQSxFQUFFQSxLQUFLQSxDQUFDQSxJQUFJQSxDQUFFQSxDQUFDQTtZQUM1Q0EsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFFREEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsRUFBRUEsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURQLFFBQVFBLENBQUVBLElBQUlBO1FBRVpRLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLElBQUlBLENBQUVBLENBQUNBO0lBQzlCQSxDQUFDQTtJQUVEUixTQUFTQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQTtRQUVsQlMsR0FBR0EsQ0FBQUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsRUFBRUEsRUFBRUEsQ0FBQ0E7WUFDMUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLElBQUlBLEdBQUdBLENBQUNBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBO0lBQ2pDQSxDQUFDQTtJQUVEVCxTQUFTQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQTtRQUVsQlUsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7SUFDMUNBLENBQUNBO0lBRURWLFNBQVNBLENBQUVBLFFBQVFBLEVBQUVBLE1BQU1BLEVBQUVBLEdBQUdBO1FBRTlCVyxJQUFJQSxDQUFDQSxVQUFVQSxDQUFFQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxD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Q0FBRUEsVUFBVUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7WUFDNUNBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGtCQUFrQkEsQ0FBRUEsQ0FBQ0E7UUFDeENBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBQ3RDQSxJQUFJQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN4REEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUU3QkEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDYkEsQ0FBQ0E7SUFFRE4sU0FBU0EsQ0FBRUEsUUFBZ0JBLEVBQUVBLE1BQWNBLEVBQUVBLEdBQVdBO1FBRXRETyxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxRQUFRQSxHQUFHQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFFQSxNQUFNQSxHQUFHQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFHQSxDQUFDQSxDQUN6RUEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsVUFBVUEsRUFBRUEsUUFBUUEsRUFBRUEsR0FBR0EsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7WUFDeERBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGtCQUFrQkEsQ0FBRUEsQ0FBQ0E7UUFDeENBLENBQUNBO1FBR0RBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO1lBQ2xEQSxJQUFJQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxRQUFRQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtZQUM1REEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0E7UUFFREEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsUUFBUUEsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsTUFBTUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDeEVBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRURQLFNBQVNBLENBQUVBLElBQVlBLEVBQUVBLEdBQVdBO1FBRWxDUSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUM3QkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsVUFBVUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDMUNBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLG1CQUFtQkEsQ0FBRUEsQ0FBQ0E7UUFDekNBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3BDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxFQUFFQSxJQUFJQSxTQUFTQSxDQUFFQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUNwRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFFQSxDQUFDQTtJQUNuQ0EsQ0FBQ0E7SUFFRFIsVUFBVUEsQ0FBRUEsSUFBWUEsRUFBRUEsR0FBY0E7UUFFdENTLEVBQUVBLENBQUNBLENBQUVBLElB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RUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBRUEsQ0FBQ0E7SUFFdEhBLG9CQUFvQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBR0EsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUV6RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFFOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFHQSxPQUFPQSxFQUFHQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsTUFBTUEsRUFBS0EsS0FBS0EsRUFBS0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBRTlGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxZQUFZQSxDQUFFQSxFQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtJQUNyRkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUMvSEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUMvSEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDektBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGFBQWFBLENBQUVBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO0lBQ3ZGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ2pJQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ2hJQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxpQkFBaUJBLENBQUVBLEVBQUVBLFVBQVVBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUczS0EsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUN6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUN6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUN6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUN6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUN6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUN6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsV0FBV0EsQ0FBQ0EsMkJBQTJCQSxDQUFFQSxDQUFDQTtJQUV6SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBRUEsQ0FBQ0E7SUFDNUdBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFDdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLDBCQUEwQkEsQ0FBRUEsQ0FBQ0E7SUFFdEhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFdBQVdBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLGVBQWVBLENBQUVBLENBQUNBO0lBQzVHQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBRXRIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzFIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzVIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBRTVIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxZQUFZQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQ3hIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxZQUFZQSxDQUFFQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUNwRkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFHcEZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFVBQVVBLEVBQUVBLGFBQWFBLENBQUNBLGVBQWVBLENBQUVBLEVBQUVBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDaklBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFVBQVVBLEVBQUVBLGFBQWFBLENBQUNBLGVBQWVBLENBQUVBLEVBQUVBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUN2S0EsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsVUFBVUEsRUFBRUEsYUFBYUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDN01BLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFVBQVVBLEVBQUVBLGFBQWFBLENBQUNBLGVBQWVBLENBQUVBLEVBQUVBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDblBBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFVBQVVBLEVBQUVBLGFBQWFBLENBQUNBLGFBQWFBLENBQUVBLEVBQUVBLEtBQUtBLENBQUVBLENBQUNBO0lBQ3hGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxjQUFjQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzdIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxjQUFjQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzdIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLEVBQUVBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7QUFDcEtBLENBQUNBO0FBR0QsYUFBYSxFQUFFLENBQUM7QUFFaEIsV0FBVyxTQUFTLEdBQUcsR0FBRyxDQUFDLFNBQVMsQ0FBQztBQUNyQyxhQUFhLFNBQVMsR0FBRyxJQUFJLENBQUM7QUFDOUIsYUFBYSxTQUFTLEdBQUcsSUFBSSxDQUFDOztPQ3JRdkIsS0FBSyxHQUFHLE1BQU0sZUFBZTtPQUM3QixFQUFFLFNBQVMsRUFBRSxNQUFNLHdCQUF3QjtPQUczQyxFQUFFLFlBQVksRUFBRSxNQUFNLHVCQUF1QjtBQUVwRCxhQUFjLEdBQUcsSUFBS0MsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDbEQsY0FBZSxHQUFHLElBQUt4RCxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxRQUFRQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtBQUMzRSxjQUFlLEdBQUcsSUFBS0MsTUFBTUEsQ0FBQ0EsQ0FBRUEsTUFBTUEsR0FBR0EsR0FBR0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDN0UsZUFBZ0IsR0FBRyxFQUFFLENBQUMsSUFBS3dELE1BQU1BLENBQUNBLENBQUVBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBLElBQUlBLENBQUVBLEdBQUdBLENBQUVBLENBQUVBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLENBQUNBLENBQUNBO0FBQ3hGLGVBQWdCLEdBQUcsRUFBRSxDQUFDLElBQUtDLE1BQU1BLENBQUNBLENBQUVBLEtBQUtBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBLElBQUlBLENBQUVBLEdBQUdBLENBQUVBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBLENBQUNBLENBQUNBO0FBRXRGLGNBQWlCLEdBQUc7SUFFbEJDLE1BQU1BLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO0FBQ3RDQSxDQUFDQTtBQUVELGNBQWlCLEdBQUc7SUFHbEJDLE1BQU1BLENBQUNBLElBQUlBLFNBQVNBLENBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUVBLENBQUVBLENBQUNBO0FBQ25EQSxDQUFDQTtBQUVEO0lBQUFDO1FBbVhFQyxTQUFJQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQWdkMURBLENBQUNBO0lBaHpCQ0QsT0FBT0EsQ0FBRUEsTUFBTUE7UUFFYkUsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsTUFBTUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7UUFDcENBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLE1BQU1BLENBQUNBLFVBQVVBLENBQUNBO1FBRXBDQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxXQUFXQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtJQUMvREEsQ0FBQ0E7SUFFREYsZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsWUFBWUE7UUFFcENHLElBQUlBLFFBQVFBLEdBQUdBLEVBQUVBLENBQUNBO1FBQ2xCQSxlQUFnQkEsR0FBR0EsSUFBS0MsUUFBUUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFFMUNELEVBQUVBLENBQUNBLENBQUVBLE9BQVFBLENBQUNBO1lBQ1pBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLENBQUNBO1FBRXJCQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxJQUFJQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxTQUFTQSxFQUFHQSxDQUFDQTtZQUNoREEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFFZEEsSUFDQUEsQ0FBQ0E7WUFDQ0EsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDNUJBLElBQUlBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFFBQVFBLENBQUVBLE1BQU1BLEVBQUVBLENBQUVBLENBQUNBO1lBQ2xEQSxJQUFJQSxVQUFVQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUNuQkEsSUFBSUEsUUFBUUEsR0FBR0EsRUFBRUEsQ0FBQ0E7WUFDbEJBLElBQUlBLFFBQVFBLEdBQUdBLEVBQUVBLENBQUNBO1lBRWxCQSxJQUFJQSxPQUFPQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQTtZQUV4Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsSUFBSUEsU0FBVUEsQ0FBQ0EsQ0FDM0JBLENBQUNBO2dCQUNDQSxLQUFLQSxDQUFFQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxHQUFHQSxhQUFhQSxHQUFHQSxLQUFLQSxDQUFFQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFFQSxRQUFRQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxhQUFhQSxDQUFFQSxDQUFDQTtZQUNsSEEsQ0FBQ0E7WUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLFNBQVNBLEdBQUdBLE9BQU9BLENBQUNBLFNBQVNBLENBQUNBO2dCQUNsQ0EsT0FBT0EsU0FBU0EsSUFBSUEsQ0FBQ0EsRUFDckJBLENBQUNBO29CQUNDQSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxHQUFHQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDMUNBLE1BQU1BLENBQUFBLENBQUVBLFNBQVNBLEdBQUdBLElBQUtBLENBQUNBLENBQzFCQSxDQUFDQTt3QkFDQ0EsS0FBS0EsSUFBSUEsRUFBRUEsS0FBS0EsQ0FBQ0E7d0JBQ2pCQSxLQUFLQSxJQUFJQTs0QkFBRUEsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsTUFBTUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7NEJBQUNBLEtBQUtBLENBQUNBO3dCQUM5RUEsS0FBS0EsSUFBSUE7NEJBQUVBLFFBQVFBLENBQUVBLFVBQVVBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUVBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFFBQVFBLENBQUVBLE1BQU1BLEVBQUVBLENBQUVBLEVBQUVBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFFBQVFBLENBQUVBLE1BQU1BLEVBQUVBLENBQUVBLENBQUVBLENBQUVBLENBQUNBOzRCQUFDQSxLQUFLQSxDQUFDQTtvQkFDaElBLENBQUNBO29CQUNEQSxVQUFVQSxFQUFFQSxDQUFDQTtvQkFDYkEsU0FBU0EsS0FBS0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2xCQSxDQUFDQTtnQkFFREEsS0FBS0EsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsR0FBR0EsYUFBYUEsR0FBR0EsS0FBS0EsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0JBRXJGQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxVQUFVQSxHQUFHQSxDQUFDQSxDQUFFQTt1QkFDbEJBLENBQUVBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLElBQUlBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUE7MkJBQzNEQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBOzJCQUM3REEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFFQTt1QkFDakVBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLElBQUlBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUE7dUJBQzdEQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUdBLENBQUNBLENBQ2xFQSxDQUFDQTtvQkFDQ0EsSUFBSUEsT0FBT0EsR0FBR0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQUNBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUFDQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQTtvQkFDNUVBLElBQUlBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUFDQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0E7Z0JBQzlFQSxDQUFDQTtnQkFFREEsR0FBR0EsQ0FBQUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsR0FBR0EsQ0FBQ0EsRUFBRUEsVUFBVUEsR0FBR0EsVUFBVUEsRUFBRUEsRUFBRUEsVUFBVUEsRUFDOURBLENBQUNBO29CQUNDQSxJQUFJQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtvQkFDL0JBLElBQUlBLENBQUNBLEdBQUdBLFFBQVFBLENBQUVBLFVBQVVBLENBQUVBLENBQUNBO29CQUUvQkEsTUFBTUEsQ0FBQUEsQ0FBRUEsQ0FBRUEsQ0FBQ0EsQ0FDWEEsQ0FBQ0E7d0JBQ0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHNCQUFzQkE7NEJBQ3pDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDVkEsS0FBS0EsQ0FBRUEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7NEJBQzNCQSxJQUFJQTtnQ0FDRkEsS0FBS0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7NEJBQ2JBLEtBQUtBLENBQUNBO3dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx3QkFBd0JBOzRCQUMzQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBQ0E7Z0NBQ1ZBLEtBQUtBLENBQUVBLElBQUlBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUMzQkEsSUFBSUE7Z0NBQ0ZBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBOzRCQUNiQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQTs0QkFDM0NBLEtBQUtBLENBQUVBLElBQUlBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUN6QkEsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLDBCQUEwQkE7NEJBQzdDQSxLQUFLQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDbkJBLEtBQUtBLENBQUNBO3dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSwyQkFBMkJBOzRCQUM5Q0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ3hDQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQTs0QkFDNUNBLENBQUNBO2dDQUNDQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxF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Q0E7Z0JBQzVCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDekNBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0E7Z0JBQzVCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDekNBLFVBQVVBLElBQUlBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO2dCQUM3QkEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQTtnQkFDNUJBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN6Q0EsVUFBVUEsSUFBSUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7Z0JBQzlCQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUMzQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3hDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUMzQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3hDQSxVQUFVQSxJQUFJQSxTQUFTQSxDQUFDQTtnQkFDeEJBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7Z0JBQzNCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDeENBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7Z0JBQzNCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDeENBLFVBQVVBLElBQUlBLFNBQVNBLENBQUNBO2dCQUN4QkEsS0FBS0EsQ0FBQ0E7UUFDVkEsQ0FBQ0E7UUFFREEsVUFBVUEsSUFBSUEsTUFBTUEsQ0FBQ0E7UUFDckJBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLFVBQVVBLEdBQUdBLFNBQVNBLENBQUVBLElBQUlBLENBQUVBLFVBQVVBLEdBQUdBLE1BQU1BLEdBQUdBLFNBQVNBLENBQUdBLENBQUNBLENBQ3hFQSxDQUFDQTtZQUNDQSxNQUFNQSxDQUFDQTtnQkFDTEEsUUFBUUEsRUFBRUEsUUFBUUE7Z0JBQ2xCQSxVQUFVQSxFQUFFQSxVQUFVQTthQUN2QkEsQ0FBQ0E7UUFDSkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFNT1AsZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsTUFBTUE7UUFFOUNRLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGVBQWVBLENBQUVBLE9BQU9BLEVBQUVBLE1BQU1BLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQzlEQSxFQUFFQSxDQUFDQSxDQUFFQSxZQUFZQSxJQUFJQSxTQUFVQSxDQUFDQTtZQUM5QkEsTUFBTUEsQ0FBQ0E7UUFFVEEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsWUFBWUEsQ0FBQ0EsVUFBVUEsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDNUVBLENBQUNBO0lBTU9SLGdCQUFnQkEsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsR0FBR0E7UUFFNUNTLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGVBQWVBLENBQUVBLE9BQU9BLEVBQUVBLE1BQU1BLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQzlEQSxFQUFFQSxDQUFDQSxDQUFFQSxZQUFZQSxJQUFJQSxTQUFVQSxDQUFDQTtZQUM5QkEsTUFBTUEsQ0FBQ0E7UUFFVEEsWUFBWUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsWUFBWUEsQ0FBQ0EsVUFBVUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7SUFDbkVBLENBQUNBO0lBRU9ULGdCQUFnQkEsQ0FBRUEsR0FBR0E7UUFFM0JVLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLFVBQVVBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRW5EQSxJQUFJQSxDQUFDQSxVQUFVQSxJQUFJQSxHQUFHQSxDQUFDQTtJQUN6QkEsQ0FBQ0E7SUFFT1YsZ0JBQWdCQSxDQUFFQSxHQUFHQSxFQUFFQSxHQUFHQTtRQUVoQ1csRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDYkEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsRUFBRUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDMURBLElBQUlBO1lBQ0ZBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFVBQVVBLENBQUVBLElBQUlBLENBQUNBLFVBQVVBLEVBQUVBLElBQUlBLENBQUVBLEdBQUdBLENBQUVBLENBQUVBLENBQUNBO1FBRTlEQSxJQUFJQSxDQUFDQSxVQUFVQSxJQUFJQSxHQUFHQSxDQUFDQTtJQUN6QkEsQ0FBQ0E7SUFFT1gsV0FBV0EsQ0FBRUEsVUFBVUEsRUFBRUEsUUFBUUEsRUFBRUEs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QUFTQSxDQUFDQTtnQkFDekNBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO2dCQUN0QkEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxTQUFTQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtnQkFDNURBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUNBO2dCQUNuQkEsS0FBS0EsQ0FBQ0E7UUFDVkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDakJBLElBQUlBLENBQUNBLGdCQUFnQkEsSUFBSUEsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFFekNBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLElBQUlBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQVFBLENBQUNBLENBQ3BDQSxDQUFDQTtZQUNDQSxZQUFZQSxDQUFDQSxRQUFRQSxDQUFDQSxTQUFTQSxDQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxPQUFPQSxDQUFFQSxDQUFDQTtRQUN0RUEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFT2xCLHdCQUF3QkEsQ0FBRUEsTUFBTUEsRUFBRUEsUUFBUUEsRUFBRUEsT0FBT0EsRUFBRUEsVUFBVUE7UUFFckVtQixJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNsRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsWUFBWUEsSUFBSUEsU0FBVUEsQ0FBQ0E7WUFDOUJBLE1BQU1BLENBQUNBO1FBRVRBLElBQUlBLE9BQU9BLEdBQUdBLElBQUlBLENBQUVBLFlBQVlBLENBQUNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBLFlBQVlBLENBQUNBLFVBQVVBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO1FBRXBGQSxNQUFNQSxDQUFBQSxD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SUEsQ0FBQ0EsU0FBU0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDM0VBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO1FBRTdFQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtRQUM1Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBU0EsQ0FBQ0E7WUFDYkEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsRUFBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0E7UUFFN0RBLE1BQU1BLENBQUNBLFFBQVFBLENBQUNBO0lBQ2xCQSxDQUFDQTtJQUVPdEIsV0FBV0EsQ0FBRUEsR0FBR0E7UUFFdEJ1QixNQUFNQSxDQUFBQSxDQUFFQSxHQUFJQSxDQUFDQSxDQUNiQSxDQUFDQTtZQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDbkRBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUNwREEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDakdBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUNuREEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDaEdBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUNwREEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUE7Z0JBQzVCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtZQUNkQSxRQUFRQTtRQUNWQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQTtJQUNmQSxDQUFDQTtJQUVEdkIsV0FBV0E7UUFFVHdCLElBQ0FBLENBQUNBO1lBQ0NBLElBQUlBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1lBQzVCQSxJQUFJQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUNsREEsSUFBSUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDbkJBLElBQUlBLFFBQVFBLEdBQUdBLEVBQUVBLENBQUNBO1lBQ2xCQSxJQUFJQSxRQUFRQSxHQUFHQSxF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QUVBLENBQUNBO3dCQUNwRkEsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ25DQSxDQUFDQTtvQkFDREEsSUFBSUE7d0JBQ0ZBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLEdBQUdBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO29CQUN4REEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBO29CQUN2QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBV0EsQ0FBQ0EsQ0FDdkNBLENBQUNBO3dCQUVDQSxJQUFJQSxDQUFDQSxVQUFVQSxJQUFJQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTt3QkFDakNBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLElBQUlBLENBQUNBLFVBQVVBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO29CQUN0RkEsQ0FBQ0E7b0JBQ0RBLElBQUlBO3dCQUNGQSxJQUFJQSxDQUFDQSxvQkFBb0JBLENBQUVBLEdBQUdBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO29CQUNqRUEsS0FBS0EsQ0FBQ0E7Z0JBR1JBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBO29CQUN6QkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLFdBQVdBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLGVBQWVBLENBQUVBLEdBQUdBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO3dCQUN4RUEsSUFBSUEsWUFBWUEsR0FBR0EsSUFBSUEsQ0FBQ0Esa0JBQWtCQSxDQUFFQSxXQUFXQSxDQUFFQSxDQUFDQTt3QkFDMURBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLFlBQVlBLENBQUNBLFdBQVdBLEVBQUVBLFlBQVlBLENBQUNBLFVBQVVBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO3dCQUNyRkEsS0FBS0EsQ0FBQ0E7b0JBQ1JBLENBQUNBO2dCQUVEQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxTQUFTQTtvQkFDMUJBLENBQUNBO3dCQUNDQSxJQUFJQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDeEVBLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGtCQUFrQkEsQ0FBRUEsV0FBV0EsQ0FBRUEsQ0FBQ0E7d0JBQzFEQSxJQUFJQSxDQUFDQSxvQkFBb0JBLENBQUVBLFlBQVlBLENBQUNBLFdBQVdBLEVBQUVBLFlBQVlBLENBQUNBLFVBQVVBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO3dCQUM5RkEsS0FBS0EsQ0FBQ0E7b0JBQ1JBLENBQUNBO2dCQUVEQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDdkJBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDeEVBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDdkJBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQTtvQkFDdEJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVdBLENBQUNBO3dCQUNyQ0EsSUFBSUEsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDckZBLElBQUlBO3dCQUNGQSxJQUFJQSxDQUFDQSx3QkFBd0JBLENBQUVBLE1BQU1BLEVBQUVBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO29CQUN6RUEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO29CQUN0QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBV0EsQ0FBQ0E7d0JBQ3JDQSxJQUFJQSxDQUFDQSx3QkFBd0JBLENBQUVBLE1BQU1BLEVBQUVBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO29CQUNyRkEsSUFBSUE7d0JBQ0ZBLElBQUlBLENBQUNBLHdCQUF3QkEsQ0FBRUEsTUFBTUEsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3pFQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsU0FBU0EsQ0FBQ0E7Z0JBQzNCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQSxDQUFDQTtnQkFDMUJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQTtvQkFDdEJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVdBLENBQUNBO3dCQUNyQ0EsSUFBSUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsTUFBTUEsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3pGQSxJQUFJQTt3QkFDRkEsSUFBSUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsTUFBTUEsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQy9EQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFDQTtnQkFDeEJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO29CQUN0QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBV0EsQ0FBQ0E7d0JBQ3JDQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDMUZBLElBQUlBO3dCQUNGQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDaEVBLEtBQUtBLENBQUNBO1lBQ1ZBLENBQUNBO1lBRURBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLE1BQU1BLENBQUNBO1FBQzFCQSxDQUNBQTtRQUFBQSxLQUFLQSxDQUFBQSxDQUFFQSxDQUFFQSxDQUFDQSxDQUNWQSxDQUFDQTtRQUVEQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVEeEIsY0FBY0EsQ0FBRUEsV0FBd0JBO1FBRXRDeUIsSUFBSUEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7UUFHNUNBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLE1BQU1BLENBQUVBLENBQUVBLENBQUNBO1FBRzVEQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUc1REEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBRUEsV0FBV0EsQ0FBQ0EsRUFBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFHcEVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLFdBQVdBLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUVBLENBQUVBLENBQUNBO1FBQzdFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxFQUFFQSxFQUFFQSxXQUFXQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUVqRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsV0FBV0EsQ0FBQ0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFbERBLElBQUlBLENBQUNBLGFBQWFBLEVBQUVBLENBQUNBO0lBQ3ZCQSxDQUFDQTtJQUVEekIsZUFBZUE7UUFFYjBCLElBQUlBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO1FBRTVDQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUUvREEsTUFBTUEsQ0FBQ0EsSUFBSUEsWUFBWUEsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsSUFBSUEs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QSxHQUFHQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUUxQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFLTUosV0FBV0EsQ0FBRUEsT0FBWUE7UUFHOUJLLE1BQU1BLENBQUNBLElBQUlBLFNBQVNBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQzdCQSxDQUFDQTtBQUNITCxDQUFDQTtBQUVELFdBQVcsQ0FBQyxJQUFJLENBQUUsR0FBRyxFQUFFLDhCQUE4QixDQUFFO0tBQ3BELEtBQUssQ0FBRSxNQUFNLEVBQUUsY0FBYyxFQUFFLFNBQVMsQ0FBRTtLQUMxQyxLQUFLLENBQUUsTUFBTSxFQUFFLGNBQWMsRUFBRSxTQUFTLENBQUU7S0FDMUMsS0FBSyxDQUFFLEtBQUssRUFBRSxhQUFhLEVBQUUsU0FBUyxDQUFFO0tBQ3hDLEtBQUssQ0FBRSxLQUFLLEVBQUUsYUFBYSxFQUFFLFNBQVMsQ0FBRSxDQUN4QyIsImZpbGUiOiJjcnlwdG9ncmFwaGl4LXNlLWNvcmUuanMiLCJzb3VyY2VzQ29udGVudCI6W251bGwsbnVsbCxudWxsLG51bGwsbnVsbCwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmV4cG9ydCBjbGFzcyBCYXNlVExWXG57XG4gIHB1YmxpYyBzdGF0aWMgRW5jb2RpbmdzID0ge1xuICAgIEVNVjogMSxcbiAgICBER0k6IDJcbiAgfTtcblxuICBzdGF0aWMgcGFyc2VUTFYoIGJ1ZmZlcjogQnl0ZUFycmF5LCBlbmNvZGluZzogbnVtYmVyICk6IHsgdGFnOiBudW1iZXIsIGxlbjogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5LCBsZW5PZmZzZXQ6IG51bWJlciwgdmFsdWVPZmZzZXQ6IG51bWJlciB9XG4gIHtcbiAgICB2YXIgcmVzID0geyB0YWc6IDAsIGxlbjogMCwgdmFsdWU6IHVuZGVmaW5lZCwgbGVuT2Zmc2V0OiAwLCB2YWx1ZU9mZnNldDogMCB9O1xuICAgIHZhciBvZmYgPSAwO1xuICAgIHZhciBieXRlcyA9IGJ1ZmZlci5iYWNraW5nQXJyYXk7ICAvLyBUT0RPOiBVc2UgYnl0ZUF0KCAuLiApXG5cbiAgICBzd2l0Y2goIGVuY29kaW5nIClcbiAgICB7XG4gICAgICBjYXNlIEJhc2VUTFYuRW5jb2RpbmdzLkVNVjpcbiAgICAgIHtcbiAgICAgICAgd2hpbGUoICggb2ZmIDwgYnl0ZXMubGVuZ3RoICkgJiYgKCAoIGJ5dGVzWyBvZmYgXSA9PSAweDAwICkgfHwgKCBieXRlc1sgb2ZmIF0gPT0gMHhGRiApICkgKVxuICAgICAgICAgICsrb2ZmO1xuXG4gICAgICAgIGlmICggb2ZmID49IGJ5dGVzLmxlbmd0aCApXG4gICAgICAgICAgcmV0dXJuIHJlcztcblxuICAgICAgICBpZiAoICggYnl0ZXNbIG9mZiBdICYgMHgxRiApID09IDB4MUYgKVxuICAgICAgICB7XG4gICAgICAgICAgcmVzLnRhZyA9IGJ5dGVzWyBvZmYrKyBdIDw8IDg7XG4gICAgICAgICAgaWYgKCBvZmYgPj0gYnl0ZXMubGVuZ3RoIClcbiAgICAgICAgICB7IC8qbG9nKFwiMVwiKTsqLyAgcmV0dXJuIG51bGw7IH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJlcy50YWcgfD0gYnl0ZXNbIG9mZisrIF07XG5cbiAgICAgICAgcmVzLmxlbk9mZnNldCA9IG9mZjtcblxuICAgICAgICBpZiAoIG9mZiA+PSBieXRlcy5sZW5ndGggKVxuICAgICAgICB7IC8qbG9nKFwiMlwiKTsqLyAgcmV0dXJuIG51bGw7IH1cblxuICAgICAgICB2YXIgbGwgPSAoIGJ5dGVzWyBvZmYgXSAmIDB4ODAgKSA/ICggYnl0ZXNbIG9mZisrIF0gJiAweDdGICkgOiAxO1xuICAgICAgICB3aGlsZSggbGwtLSA+IDAgKVxuICAgICAgICB7XG4gICAgICAgICAgaWYgKCBvZmYgPj0gYnl0ZXMubGVuZ3RoIClcbiAgICAgICAgICB7IC8qbG9nKFwiMzpcIiArIG9mZiArIFwiOlwiICsgYnl0ZXMubGVuZ3RoKTsgICovcmV0dXJuIG51bGw7IH1cblxuICAgICAgICAgIHJlcy5sZW4gPSAoIHJlcy5sZW4gPDwgOCApIHwgYnl0ZXNbIG9mZisrIF07XG4gICAgICAgIH1cblxuICAgICAgICByZXMudmFsdWVPZmZzZXQgPSBvZmY7XG4gICAgICAgIGlmICggb2ZmICsgcmVzLmxlbiA+IGJ5dGVzLmxlbmd0aCApXG4gICAgICB7IC8qbG9nKFwiNFwiKTsqLyAgcmV0dXJuIG51bGw7IH1cbiAgICAgICAgcmVzLnZhbHVlID0gYnl0ZXMuc2xpY2UoIHJlcy52YWx1ZU9mZnNldCwgcmVzLnZhbHVlT2Zmc2V0ICsgcmVzLmxlbiApO1xuXG4gIC8vICAgICAgbG9nKCByZXMudmFsdWVPZmZzZXQgKyBcIitcIiArIHJlcy5sZW4gKyBcIj1cIiArIGJ5dGVzICk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiByZXM7XG4gIH1cblxuICBwdWJsaWMgYnl0ZUFycmF5OiBCeXRlQXJyYXk7XG4gIGVuY29kaW5nOiBudW1iZXI7XG5cbiAgY29uc3RydWN0b3IgKCB0YWc6IG51bWJlciwgdmFsdWU6IEJ5dGVBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIgKVxuICB7XG4gICAgdGhpcy5lbmNvZGluZyA9IGVuY29kaW5nIHx8IEJhc2VUTFYuRW5jb2RpbmdzLkVNVjtcblxuICAgIHN3aXRjaCggdGhpcy5lbmNvZGluZyApXG4gICAge1xuICAgICAgY2FzZSBCYXNlVExWLkVuY29kaW5ncy5FTVY6XG4gICAgICB7XG4gICAgICAgIHZhciB0bHZCdWZmZXIgPSBuZXcgQnl0ZUFycmF5KFtdKTtcblxuICAgICAgICBpZiAoIHRhZyA+PSAgMHgxMDAgKVxuICAgICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCAoIHRhZyA+PiA4ICkgJiAweEZGICk7XG4gICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCB0YWcgJiAweEZGICk7XG5cbiAgICAgICAgdmFyIGxlbiA9IHZhbHVlLmxlbmd0aDtcbiAgICAgICAgaWYgKCBsZW4gPiAweEZGIClcbiAgICAgICAge1xuICAgICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCAweDgyICk7XG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoICggbGVuID4+IDggKSAmIDB4RkYgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggbGVuID4gMHg3RiApXG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoIDB4ODEgKTtcblxuICAgICAgICB0bHZCdWZmZXIuYWRkQnl0ZSggbGVuICYgMHhGRiApO1xuXG4gICAgICAgIHRsdkJ1ZmZlci5jb25jYXQoIHZhbHVlICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSB0bHZCdWZmZXI7XG5cbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgZ2V0IHRhZygpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiBCYXNlVExWLnBhcnNlVExWKCB0aGlzLmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApLnRhZztcbiAgfVxuXG4gIGdldCB2YWx1ZSgpOiBCeXRlQXJyYXlcbiAge1xuICAgIHJldHVybiBCYXNlVExWLnBhcnNlVExWKCB0aGlzLmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApLnZhbHVlO1xuICB9XG5cbiAgZ2V0IGxlbigpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiBCYXNlVExWLnBhcnNlVExWKCB0aGlzLmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApLmxlbjtcbiAgfVxufVxuXG5CYXNlVExWLkVuY29kaW5nc1sgXCJDVFZcIiBdID0gNDsvLyB7IHBhcnNlOiAwLCBidWlsZDogMSB9O1xuIiwiaW1wb3J0IHsgIEJ5dGVBcnJheSwgS2luZCwgS2luZEJ1aWxkZXIsIEtpbmRJbmZvIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbi8qKlxuICogRW5jb2Rlci9EZWNvZG9yIEtpbmQgZm9yIGEgQVBEVSBDb21tYW5kXG4gKi9cbmV4cG9ydCBjbGFzcyBDb21tYW5kQVBEVSBpbXBsZW1lbnRzIEtpbmRcbntcbiAgQ0xBOiBudW1iZXI7IC8vID0gMDtcbiAgSU5TOiBudW1iZXIgPSAwO1xuICBQMTogbnVtYmVyID0gMDtcbiAgUDI6IG51bWJlciA9IDA7XG4gIGRhdGE6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcbiAgTGU6IG51bWJlciA9IDA7XG5cbi8vICBzdGF0aWMga2luZEluZm86IEtpbmRJbmZvO1xuXG4gIC8qKlxuICAgKiBAY29uc3RydWN0b3JcbiAgICpcbiAgICogRGVzZXJpYWxpemUgZnJvbSBhIEpTT04gb2JqZWN0XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYXR0cmlidXRlcz86IHt9IClcbiAge1xuICAgIEtpbmQuaW5pdEZpZWxkcyggdGhpcywgYXR0cmlidXRlcyApO1xuICB9XG5cbiAgcHVibGljIGdldCBMYygpOm51bWJlciAgICAgICAgICB7IHJldHVybiB0aGlzLmRhdGEubGVuZ3RoOyB9XG4gIHB1YmxpYyBnZXQgaGVhZGVyKCk6IEJ5dGVBcnJheSAgeyByZXR1cm4gbmV3IEJ5dGVBcnJheSggWyB0aGlzLkNMQSwgdGhpcy5JTlMsIHRoaXMuUDEsIHRoaXMuUDIgXSApOyB9XG5cbiAgLyoqXG4gICAqIEZsdWVudCBCdWlsZGVyXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIGluaXQoIENMQT86IG51bWJlciwgSU5TPzogbnVtYmVyLCBQMT86IG51bWJlciwgUDI/OiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXksIGV4cGVjdGVkTGVuPzogbnVtYmVyICk6IENvbW1hbmRBUERVXG4gIHtcbiAgICByZXR1cm4gKCBuZXcgQ29tbWFuZEFQRFUoKSApLnNldCggQ0xBLCBJTlMsIFAxLCBQMiwgZGF0YSwgZXhwZWN0ZWRMZW4gKTtcbiAgfVxuXG4gIHB1YmxpYyBzZXQoIENMQTogbnVtYmVyLCBJTlM6IG51bWJlciwgUDE6IG51bWJlciwgUDI6IG51bWJlciwgZGF0YT86IEJ5dGVBcnJheSwgZXhwZWN0ZWRMZW4/OiBudW1iZXIgKTogQ29tbWFuZEFQRFVcbiAge1xuICAgIHRoaXMuQ0xBID0gQ0xBO1xuICAgIHRoaXMuSU5TID0gSU5TO1xuICAgIHRoaXMuUDEgPSBQMTtcbiAgICB0aGlzLlAyID0gUDI7XG4gICAgdGhpcy5kYXRhID0gZGF0YSB8fCBuZXcgQnl0ZUFycmF5KCk7XG4gICAgdGhpcy5MZSA9IGV4cGVjdGVkTGVuIHx8IDA7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBzZXRDTEEoIENMQTogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgeyB0aGlzLkNMQSA9IENMQTsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldElOUyggSU5TOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICB7IHRoaXMuSU5TID0gSU5TOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0UDEoIFAxOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICAgIHsgdGhpcy5QMSA9IFAxOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0UDIoIFAyOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICAgIHsgdGhpcy5QMiA9IFAyOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0RGF0YSggZGF0YTogQnl0ZUFycmF5ICk6IENvbW1hbmRBUERVIHsgdGhpcy5kYXRhID0gZGF0YTsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldExlKCBMZTogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgICB7IHRoaXMuTGUgPSBMZTsgcmV0dXJuIHRoaXM7IH1cblxuICAvKipcbiAgICogU2VyaWFsaXphdGlvbiwgcmV0dXJucyBhIEpTT04gb2JqZWN0XG4gICAqL1xuICBwdWJsaWMgdG9KU09OKCk6IHt9XG4gIHtcbiAgICByZXR1cm4ge1xuICAgICAgQ0xBOiB0aGlzLkNMQSxcbiAgICAgIElOUzogdGhpcy5JTlMsXG4gICAgICBQMTogdGhpcy5QMSxcbiAgICAgIFAyOiB0aGlzLlAyLFxuICAgICAgZGF0YTogdGhpcy5kYXRhLFxuICAgICAgTGU6IHRoaXMuTGVcbiAgICB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEVuY29kZXJcbiAgICovXG4gIHB1YmxpYyBlbmNvZGVCeXRlcyggb3B0aW9ucz86IHt9ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGRsZW4gPSAoICggdGhpcy5MYyA+IDAgKSA/IDEgKyB0aGlzLkxjIDogMCApO1xuICAgIGxldCBsZW4gPSA0ICsgZGxlbiArICggKCB0aGlzLkxlID4gMCApID8gMSA6IDAgKTtcbiAgICBsZXQgYmEgPSBuZXcgQnl0ZUFycmF5KCkuc2V0TGVuZ3RoKCBsZW4gKTtcblxuICAgIC8vIHJlYnVpbGQgYmluYXJ5IEFQRFVDb21tYW5kXG4gICAgYmEuc2V0Qnl0ZXNBdCggMCwgdGhpcy5oZWFkZXIgKTtcbiAgICBpZiAoIHRoaXMuTGMgKSB7XG4gICAgICBiYS5zZXRCeXRlQXQoIDQsIHRoaXMuTGMgKTtcbiAgICAgIGJhLnNldEJ5dGVzQXQoIDUsIHRoaXMuZGF0YSApO1xuICAgIH1cblxuICAgIGlmICggdGhpcy5MZSA+IDAgKSB7XG4gICAgICBiYS5zZXRCeXRlQXQoIDQgKyBkbGVuLCB0aGlzLkxlICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGJhO1xuICB9XG5cbiAgLyoqXG4gICogRGVjb2RlclxuICAqL1xuICBwdWJsaWMgZGVjb2RlQnl0ZXMoIGJ5dGVBcnJheTogQnl0ZUFycmF5LCBvcHRpb25zPzoge30gKTogQ29tbWFuZEFQRFVcbiAge1xuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA8IDQgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tbWFuZEFQRFU6IEludmFsaWQgYnVmZmVyJyApO1xuXG4gICAgbGV0IG9mZnNldCA9IDA7XG5cbiAgICB0aGlzLkNMQSA9IGJ5dGVBcnJheS5ieXRlQXQoIG9mZnNldCsrICk7XG4gICAgdGhpcy5JTlMgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuICAgIHRoaXMuUDEgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuICAgIHRoaXMuUDIgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuXG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoID4gb2Zmc2V0ICsgMSApXG4gICAge1xuICAgICAgdmFyIExjID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcbiAgICAgIHRoaXMuZGF0YSA9IGJ5dGVBcnJheS5ieXRlc0F0KCBvZmZzZXQsIExjICk7XG4gICAgICBvZmZzZXQgKz0gTGM7XG4gICAgfVxuXG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoID4gb2Zmc2V0IClcbiAgICAgIHRoaXMuTGUgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuXG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoICE9IG9mZnNldCApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21tYW5kQVBEVTogSW52YWxpZCBidWZmZXInICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG5LaW5kQnVpbGRlci5pbml0KCBDb21tYW5kQVBEVSwgJ0lTTzc4MTYgQ29tbWFuZCBBUERVJyApXG4gIC5ieXRlRmllbGQoICdDTEEnLCAnQ2xhc3MnIClcbiAgLmJ5dGVGaWVsZCggJ0lOUycsICdJbnN0cnVjdGlvbicgKVxuICAuYnl0ZUZpZWxkKCAnUDEnLCAnUDEgUGFyYW0nIClcbiAgLmJ5dGVGaWVsZCggJ1AyJywgJ1AyIFBhcmFtJyApXG4gIC5pbnRlZ2VyRmllbGQoICdMYycsICdDb21tYW5kIExlbmd0aCcsIHsgY2FsY3VsYXRlZDogdHJ1ZSB9IClcbiAgLmZpZWxkKCAnZGF0YScsICdDb21tYW5kIERhdGEnLCBCeXRlQXJyYXkgKVxuICAuaW50ZWdlckZpZWxkKCAnTGUnLCAnRXhwZWN0ZWQgTGVuZ3RoJyApXG4gIDtcbiIsImV4cG9ydCBlbnVtIElTTzc4MTZcclxue1xyXG4gIC8vIElTTyBjbGFzcyBjb2RlXHJcbiAgQ0xBX0lTTyA9IDB4MDAsXHJcblxyXG4gIC8vIEV4dGVybmFsIGV4dGVybmFsIGF1dGhlbnRpY2F0ZSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0VYVEVSTkFMX0FVVEhFTlRJQ0FURSA9IDB4ODIsXHJcblxyXG4gIC8vIEdldCBjaGFsbGVuZ2UgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19HRVRfQ0hBTExFTkdFID0gMHg4NCxcclxuXHJcbiAgLy8gSW50ZXJuYWwgYXV0aGVudGljYXRlIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfSU5URVJOQUxfQVVUSEVOVElDQVRFID0gMHg4OCxcclxuXHJcbiAgLy8gU2VsZWN0IGZpbGUgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19TRUxFQ1RfRklMRSA9IDB4QTQsXHJcblxyXG4gIC8vIFJlYWQgcmVjb3JkIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfUkVBRF9SRUNPUkQgPSAweEIyLFxyXG5cclxuICAvLyBVcGRhdGUgcmVjb3JkIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfVVBEQVRFX1JFQ09SRCA9IDB4REMsXHJcblxyXG4gIC8vIFZlcmlmeSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1ZFUklGWSA9IDB4MjAsXHJcblxyXG4gIC8vIEJsb2NrIEFwcGxpY2F0aW9uIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfQkxPQ0tfQVBQTElDQVRJT04gPSAweDFFLFxyXG5cclxuICAvLyBVbmJsb2NrIGFwcGxpY2F0aW9uIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfVU5CTE9DS19BUFBMSUNBVElPTiA9IDB4MTgsXHJcblxyXG4gIC8vIFVuYmxvY2sgY2hhbmdlIFBJTiBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1VOQkxPQ0tfQ0hBTkdFX1BJTiA9IDB4MjQsXHJcblxyXG4gIC8vIEdldCBkYXRhIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfR0VUX0RBVEEgPSAweENBLFxyXG5cclxuICAvLyBBcHBsaWNhdGlvbiBUZW1wbGF0ZVxyXG4gIFRBR19BUFBMSUNBVElPTl9URU1QTEFURSA9IDB4NjEsXHJcblxyXG4gIC8vIEZDSSBQcm9wcmlldGFyeSBUZW1wbGF0ZVxyXG4gIFRBR19GQ0lfUFJPUFJJRVRBUllfVEVNUExBVEUgPSAweEE1LFxyXG5cclxuICAvLyBGQ0kgVGVtcGxhdGVcclxuICBUQUdfRkNJX1RFTVBMQVRFID0gMHg2RixcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gSWRlbnRpZmllciAoQUlEKSAtIGNhcmRcclxuICBUQUdfQUlEID0gMHg0RixcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gTGFiZWxcclxuICBUQUdfQVBQTElDQVRJT05fTEFCRUwgPSAweDUwLFxyXG5cclxuICAvLyBMYW5ndWFnZSBQcmVmZXJlbmNlXHJcbiAgVEFHX0xBTkdVQUdFX1BSRUZFUkVOQ0VTID0gMHg1RjJELFxyXG5cclxuICAvLyBBcHBsaWNhdGlvbiBFZmZlY3RpdmUgRGF0YVxyXG4gIFRBR19BUFBMSUNBVElPTl9FRkZFQ1RJVkVfREFURSA9IDB4NUYyNSxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gRXhwaXJhdGlvbiBEYXRlXHJcbiAgVEFHX0FQUExJQ0FUSU9OX0VYUElSWV9EQVRFID0gMHg1RjI0LFxyXG5cclxuICAvLyBDYXJkIEhvbGRlciBOYW1lXHJcbiAgVEFHX0NBUkRIT0xERVJfTkFNRSA9IDB4NUYyMCxcclxuXHJcbiAgLy8gSXNzdWVyIENvdW50cnkgQ29kZVxyXG4gIFRBR19JU1NVRVJfQ09VTlRSWV9DT0RFID0gMHg1RjI4LFxyXG5cclxuICAvLyBJc3N1ZXIgVVJMXHJcbiAgVEFHX0lTU1VFUl9VUkwgPSAweDVGNTAsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIFByaW1hcnkgQWNjb3VudCBOdW1iZXIgKFBBTilcclxuICBUQUdfUEFOID0gMHg1YSxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gUHJpbWFyeSBBY2NvdW50IE51bWJlciAoUEFOKSBTZXF1ZW5jZSBOdW1iZXJcclxuICBUQUdfUEFOX1NFUVVFTkNFX05VTUJFUiA9IDB4NUYzNCxcclxuXHJcbiAgLy8gU2VydmljZSBDb2RlXHJcbiAgVEFHX1NFUlZJQ0VfQ09ERSA9IDB4NUYzMCxcclxuXHJcbiAgSVNPX1BJTkJMT0NLX1NJWkUgPSA4LCAgIC8vPCBTaXplIG9mIGFuIElTTyBQSU4gYmxvY2tcclxuXHJcbiAgQVBEVV9MRU5fTEVfTUFYID0gMjU2LCAgIC8vPCBNYXhpbXVtIHNpemUgZm9yIExlXHJcblxyXG4gIFNXX1NVQ0NFU1MgPSAweDkwMDAsXHJcbiAgLy8gIFNXX0JZVEVTX1JFTUFJTklORyhTVzIpID0gMHg2MSMjU1cyLFxyXG4gIFNXX1dBUk5JTkdfTlZfTUVNT1JZX1VOQ0hBTkdFRCA9IDB4NjIwMCAsXHJcbiAgU1dfUEFSVF9PRl9SRVRVUk5fREFUQV9DT1JSVVBURUQgPSAweDYyODEsXHJcbiAgU1dfRU5EX0ZJTEVfUkVBQ0hFRF9CRUZPUkVfTEVfQllURSA9IDB4NjI4MixcclxuICBTV19TRUxFQ1RFRF9GSUxFX0lOVkFMSUQgPSAweDYyODMsXHJcbiAgU1dfRkNJX05PVF9GT1JNQVRURURfVE9fSVNPID0gMHg2Mjg0LFxyXG4gIFNXX1dBUk5JTkdfTlZfTUVNT1JZX0NIQU5HRUQgPSAweDYzMDAsXHJcbiAgU1dfRklMRV9GSUxMRURfQllfTEFTVF9XUklURSA9IDB4NjM4MSxcclxuICAvLyAgU1dfQ09VTlRFUl9QUk9WSURFRF9CWV9YKFgpID0gMHg2M0MjI1gsXHJcbiAgLy8gIFNXX0VSUk9SX05WX01FTU9SWV9VTkNIQU5HRUQoU1cyKSA9IDB4NjQjI1NXMixcclxuICAvLyAgU1dfRVJST1JfTlZfTUVNT1JZX0NIQU5HRUQoU1cyKSA9IDB4NjUjI1NXMiAsXHJcbiAgLy8gIFNXX1JFU0VSVkVEKFNXMikgPSAweDY2IyNTVzIsXHJcbiAgU1dfV1JPTkdfTEVOR1RIID0gMHg2NzAwICxcclxuICBTV19GVU5DVElPTlNfSU5fQ0xBX05PVF9TVVBQT1JURUQgPSAweDY4MDAsXHJcbiAgU1dfTE9HSUNBTF9DSEFOTkVMX05PVF9TVVBQT1JURUQgPSAweDY4ODEsXHJcbiAgU1dfU0VDVVJFX01FU1NBR0lOR19OT1RfU1VQUE9SVEVEID0gMHg2ODgyLFxyXG4gIFNXX0NPTU1BTkRfTk9UX0FMTE9XRUQgPSAweDY5MDAsXHJcbiAgU1dfQ09NTUFORF9JTkNPTVBBVElCTEVfV0lUSF9GSUxFX1NUUlVDVFVSRSA9IDB4Njk4MSxcclxuICBTV19TRUNVUklUWV9TVEFUVVNfTk9UX1NBVElTRklFRCA9IDB4Njk4MixcclxuICBTV19GSUxFX0lOVkFMSUQgPSAweDY5ODMsXHJcbiAgU1dfREFUQV9JTlZBTElEID0gMHg2OTg0LFxyXG4gIFNXX0NPTkRJVElPTlNfTk9UX1NBVElTRklFRCA9IDB4Njk4NSxcclxuICBTV19DT01NQU5EX05PVF9BTExPV0VEX0FHQUlOID0gMHg2OTg2LFxyXG4gIFNXX0VYUEVDVEVEX1NNX0RBVEFfT0JKRUNUU19NSVNTSU5HID0gMHg2OTg3ICxcclxuICBTV19TTV9EQVRBX09CSkVDVFNfSU5DT1JSRUNUID0gMHg2OTg4LFxyXG4gIFNXX1dST05HX1BBUkFNUyA9IDB4NkEwMCAgICxcclxuICBTV19XUk9OR19EQVRBID0gMHg2QTgwLFxyXG4gIFNXX0ZVTkNfTk9UX1NVUFBPUlRFRCA9IDB4NkE4MSxcclxuICBTV19GSUxFX05PVF9GT1VORCA9IDB4NkE4MixcclxuICBTV19SRUNPUkRfTk9UX0ZPVU5EID0gMHg2QTgzLFxyXG4gIFNXX05PVF9FTk9VR0hfU1BBQ0VfSU5fRklMRSA9IDB4NkE4NCxcclxuICBTV19MQ19JTkNPTlNJU1RFTlRfV0lUSF9UTFYgPSAweDZBODUsXHJcbiAgU1dfSU5DT1JSRUNUX1AxUDIgPSAweDZBODYsXHJcbiAgU1dfTENfSU5DT05TSVNURU5UX1dJVEhfUDFQMiA9IDB4NkE4NyxcclxuICBTV19SRUZFUkVOQ0VEX0RBVEFfTk9UX0ZPVU5EID0gMHg2QTg4LFxyXG4gIFNXX1dST05HX1AxUDIgPSAweDZCMDAsXHJcbiAgLy9TV19DT1JSRUNUX0xFTkdUSChTVzIpID0gMHg2QyMjU1cyLFxyXG4gIFNXX0lOU19OT1RfU1VQUE9SVEVEID0gMHg2RDAwLFxyXG4gIFNXX0NMQV9OT1RfU1VQUE9SVEVEID0gMHg2RTAwLFxyXG4gIFNXX1VOS05PV04gPSAweDZGMDAsXHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LCBLaW5kLCBLaW5kSW5mbywgS2luZEJ1aWxkZXIgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcbmltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuL2lzbzc4MTYnO1xuXG4vKipcbiAqIEVuY29kZXIvRGVjb2RvciBmb3IgYSBBUERVIFJlc3BvbnNlXG4gKi9cbmV4cG9ydCBjbGFzcyBSZXNwb25zZUFQRFUgaW1wbGVtZW50cyBLaW5kXG57XG4gIFNXOiBudW1iZXIgPSBJU083ODE2LlNXX1NVQ0NFU1M7XG4gIGRhdGE6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcblxuLy8gIHN0YXRpYyBraW5kSW5mbzogS2luZEluZm87XG5cbiAgLyoqXG4gICAqIEBjb25zdHJ1Y3RvclxuICAgKlxuICAgKiBEZXNlcmlhbGl6ZSBmcm9tIGEgSlNPTiBvYmplY3RcbiAgICovXG4gIGNvbnN0cnVjdG9yKCBhdHRyaWJ1dGVzPzoge30gKVxuICB7XG4gICAgS2luZC5pbml0RmllbGRzKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IExhKCkgeyByZXR1cm4gdGhpcy5kYXRhLmxlbmd0aDsgfVxuXG4gIHB1YmxpYyBzdGF0aWMgaW5pdCggc3c6IG51bWJlciwgZGF0YT86IEJ5dGVBcnJheSApOiBSZXNwb25zZUFQRFVcbiAge1xuICAgIHJldHVybiAoIG5ldyBSZXNwb25zZUFQRFUoKSApLnNldCggc3csIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzZXQoIHN3OiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXkgKTogUmVzcG9uc2VBUERVXG4gIHtcbiAgICB0aGlzLlNXID0gc3c7XG4gICAgdGhpcy5kYXRhID0gZGF0YSB8fCBuZXcgQnl0ZUFycmF5KCk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBzZXRTVyggU1c6IG51bWJlciApOiBSZXNwb25zZUFQRFUgICAgICAgIHsgdGhpcy5TVyA9IFNXOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0U1cxKCBTVzE6IG51bWJlciApOiBSZXNwb25zZUFQRFUgICAgICB7IHRoaXMuU1cgPSAoIHRoaXMuU1cgJiAweEZGICkgfCAoIFNXMSA8PCA4ICk7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXRTVzIoIFNXMjogbnVtYmVyICk6IFJlc3BvbnNlQVBEVSAgICAgIHsgdGhpcy5TVyA9ICggdGhpcy5TVyAmIDB4RkYwMCApIHwgU1cyOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0RGF0YSggZGF0YTogQnl0ZUFycmF5ICk6IFJlc3BvbnNlQVBEVSB7IHRoaXMuZGF0YSA9IGRhdGE7IHJldHVybiB0aGlzOyB9XG5cbiAgLyoqXG4gICAqIEVuY29kZXIgZnVuY3Rpb24sIHJldHVybnMgYSBibG9iIGZyb20gYW4gQVBEVVJlc3BvbnNlIG9iamVjdFxuICAgKi9cbiAgcHVibGljIGVuY29kZUJ5dGVzKCBvcHRpb25zPzoge30gKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSBuZXcgQnl0ZUFycmF5KCkuc2V0TGVuZ3RoKCB0aGlzLkxhICsgMiApO1xuXG4gICAgYmEuc2V0Qnl0ZXNBdCggMCwgdGhpcy5kYXRhICk7XG4gICAgYmEuc2V0Qnl0ZUF0KCB0aGlzLkxhICAgICwgKCB0aGlzLlNXID4+IDggKSAmIDB4ZmYgKTtcbiAgICBiYS5zZXRCeXRlQXQoIHRoaXMuTGEgKyAxLCAoIHRoaXMuU1cgPj4gMCApICYgMHhmZiApO1xuXG4gICAgcmV0dXJuIGJhO1xuICB9XG5cbiAgcHVibGljIGRlY29kZUJ5dGVzKCBieXRlQXJyYXk6IEJ5dGVBcnJheSwgb3B0aW9ucz86IHt9ICk6IFJlc3BvbnNlQVBEVVxuICB7XG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoIDwgMiApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdSZXNwb25zZUFQRFUgQnVmZmVyIGludmFsaWQnICk7XG5cbiAgICBsZXQgbGEgPSBieXRlQXJyYXkubGVuZ3RoIC0gMjtcblxuICAgIHRoaXMuU1cgPSBieXRlQXJyYXkud29yZEF0KCBsYSApO1xuICAgIHRoaXMuZGF0YSA9ICggbGEgKSA/IGJ5dGVBcnJheS5ieXRlc0F0KCAwLCBsYSApIDogbmV3IEJ5dGVBcnJheSgpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbn1cblxuS2luZEJ1aWxkZXIuaW5pdCggUmVzcG9uc2VBUERVLCAnSVNPNzgxNiBSZXNwb25zZSBBUERVJyApXG4gIC5pbnRlZ2VyRmllbGQoICdTVycsICdTdGF0dXMgV29yZCcsIHsgbWF4aW11bTogMHhGRkZGIH0gKVxuICAuaW50ZWdlckZpZWxkKCAnTGEnLCAnQWN0dWFsIExlbmd0aCcsICB7IGNhbGN1bGF0ZWQ6IHRydWUgfSApXG4gIC5maWVsZCggJ0RhdGEnLCAnUmVzcG9uc2UgRGF0YScsIEJ5dGVBcnJheSApXG4gIDtcbiIsbnVsbCwiaW1wb3J0IHsgQnl0ZUFycmF5LCBFbmRQb2ludCwgTWVzc2FnZSwgTWVzc2FnZUhlYWRlciB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBTbG90IH0gZnJvbSAnLi4vYmFzZS9zbG90JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vYmFzZS9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vYmFzZS9yZXNwb25zZS1hcGR1JztcblxuZXhwb3J0IGNsYXNzIFNsb3RQcm90b2NvbEhhbmRsZXJcbntcbiAgZW5kUG9pbnQ6IEVuZFBvaW50O1xuICBzbG90OiBTbG90O1xuXG4gIGNvbnN0cnVjdG9yKCAgKVxuICB7XG4gIH1cblxuICBsaW5rU2xvdCggc2xvdDogU2xvdCwgZW5kUG9pbnQ6IEVuZFBvaW50IClcbiAge1xuICAgIHRoaXMuZW5kUG9pbnQgPSBlbmRQb2ludDtcbiAgICB0aGlzLnNsb3QgPSBzbG90O1xuXG4gICAgZW5kUG9pbnQub25NZXNzYWdlKCB0aGlzLm9uTWVzc2FnZSApO1xuICB9XG5cbiAgdW5saW5rU2xvdCgpXG4gIHtcbiAgICB0aGlzLmVuZFBvaW50Lm9uTWVzc2FnZSggdW5kZWZpbmVkICk7XG4gICAgdGhpcy5lbmRQb2ludCA9IHVuZGVmaW5lZDtcbiAgICB0aGlzLnNsb3QgPSB1bmRlZmluZWQ7XG4gIH1cblxuICBvbk1lc3NhZ2UoIHBhY2tldDogTWVzc2FnZTxhbnk+LCByZWNlaXZpbmdFbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgbGV0IGhkcjogYW55ID0gcGFja2V0LmhlYWRlcjtcbiAgICBsZXQgcGF5bG9hZCA9IHBhY2tldC5wYXlsb2FkO1xuXG4gICAgc3dpdGNoKCBoZHIuY29tbWFuZCApXG4gICAge1xuICAgICAgY2FzZSBcImV4ZWN1dGVBUERVXCI6XG4gICAgICB7XG4gICAgICAgIGlmICggISggaGRyLmtpbmQgaW5zdGFuY2VvZiBDb21tYW5kQVBEVSApIClcbiAgICAgICAgICBicmVhaztcblxuICAgICAgICBsZXQgY29tbWFuZEFQRFU6IENvbW1hbmRBUERVID0gPENvbW1hbmRBUERVPnBheWxvYWQ7XG5cbiAgICAgICAgdmFyIHJlc3AgPSB0aGlzLnNsb3QuZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVICk7XG4gICAgICAgIGxldCB4OiBNZXNzYWdlSGVhZGVyID0gbnVsbDtcblxuICAgICAgICByZXNwLnRoZW4oICggcmVzcG9uc2VBUERVICkgPT4ge1xuICAgICAgICAgIGxldCByZXBseVBhY2tldCA9IG5ldyBNZXNzYWdlPFJlc3BvbnNlQVBEVT4oIHsgbWV0aG9kOiBcImV4ZWN1dGVBUERVXCIgfSwgcmVzcG9uc2VBUERVICk7XG5cbiAgICAgICAgICByZWNlaXZpbmdFbmRQb2ludC5zZW5kTWVzc2FnZSggcmVwbHlQYWNrZXQgKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoKSA9PiB7XG4gICAgICAgICAgbGV0IGVycm9yUGFja2V0ID0gbmV3IE1lc3NhZ2U8RXJyb3I+KCB7IG1ldGhvZDogXCJlcnJvclwiIH0sIHVuZGVmaW5lZCApO1xuXG4gICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIGVycm9yUGFja2V0ICk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuXG4vKiAgICAgICAgICBjYXNlIFwiY3RybFBvd2VyUmVzZXRcIjpcbiAgICAgICAgICB7XG4gICAgICAgICAgICB2YXIgYXRyID0gbnVsbDtcblxuICAgICAgICAgICAgaWYgKCBjbWQuZGF0YSA9PSBcInBvd2VyT2ZmXCIgKVxuICAgICAgICAgICAgICBhdHIgPSBzbG90LmN0cmxQb3dlclJlc2V0KCAwICk7XG4gICAgICAgICAgICBlbHNlIGlmICggY21kLmRhdGEgPT0gXCJwb3dlck9uXCIgKVxuICAgICAgICAgICAgICBhdHIgPSBzbG90LmN0cmxQb3dlclJlc2V0KCAxICk7XG4gICAgICAgICAgICBlbHNlIGlmICggY21kLmRhdGEgPT0gXCJyZXNldFwiIClcbiAgICAgICAgICAgICAgYXRyID0gc2xvdC5jdHJsUG93ZXJSZXNldCggMiApO1xuXG4gICAgICAgICAgICByZXR1cm4gc2VuZFJlc3BvbnNlUGFja2V0KFxuICAgICAgICAgICAgICBwb3J0LFxuICAgICAgICAgICAgICBwYWNrZXQuaGVhZGVyLFxuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgY29tbWFuZDogXCJjdHJsUG93ZXJSZXNldFwiLFxuICAgICAgICAgICAgICAgIGRhdGE6IG5ldyBVaW50OEFycmF5KCBhdHIgKVxuICAgICAgICAgICAgICB9ICk7XG4gICAgICAgICAgfSovXG4gICAgICAgIH0gLy8gc3dpdGNoXG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVTdHJpbmcgfSBmcm9tICcuL2J5dGUtc3RyaW5nJztcclxuXHJcbmV4cG9ydCBjbGFzcyBLZXlcclxue1xyXG4gIF90eXBlOiBudW1iZXI7XHJcbiAgX3NpemU6IG51bWJlcjtcclxuICBfY29tcG9uZW50QXJyYXk6IEJ5dGVTdHJpbmdbXTtcclxuXHJcbiAgY29uc3RydWN0b3IoKVxyXG4gIHtcclxuICAgIHRoaXMuX3R5cGUgPSAwO1xyXG4gICAgdGhpcy5fc2l6ZSA9IC0xO1xyXG4gICAgdGhpcy5fY29tcG9uZW50QXJyYXkgPSBbXTtcclxuICB9XHJcblxyXG4gIHNldFR5cGUoIGtleVR5cGU6IG51bWJlciApXHJcbiAge1xyXG4gICAgdGhpcy5fdHlwZSA9IGtleVR5cGU7XHJcbiAgfVxyXG5cclxuICBnZXRUeXBlKCk6IG51bWJlclxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLl90eXBlO1xyXG4gIH1cclxuXHJcbiAgc2V0U2l6ZSggc2l6ZTogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl9zaXplID0gc2l6ZTtcclxuICB9XHJcblxyXG4gIGdldFNpemUoKTogbnVtYmVyXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3NpemU7XHJcbiAgfVxyXG5cclxuICBzZXRDb21wb25lbnQoIGNvbXA6IG51bWJlciwgdmFsdWU6IEJ5dGVTdHJpbmcgKVxyXG4gIHtcclxuICAgIHRoaXMuX2NvbXBvbmVudEFycmF5WyBjb21wIF0gPSB2YWx1ZTtcclxuICB9XHJcblxyXG4gIGdldENvbXBvbmVudCggY29tcDogbnVtYmVyICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5fY29tcG9uZW50QXJyYXlbIGNvbXAgXTtcclxuICB9XHJcblxyXG5cclxuICBzdGF0aWMgU0VDUkVUID0gMTtcclxuICBzdGF0aWMgUFJJVkFURSA9IDI7XHJcbiAgc3RhdGljIFBVQkxJQyA9IDM7XHJcblxyXG4gIHN0YXRpYyBERVMgPSAxO1xyXG4gIHN0YXRpYyBBRVMgPSAyO1xyXG4gIHN0YXRpYyBNT0RVTFVTID0gMztcclxuICBzdGF0aWMgRVhQT05FTlQgPSA0O1xyXG4gIHN0YXRpYyBDUlRfUCA9IDU7XHJcbiAgc3RhdGljIENSVF9RID0gNjtcclxuICBzdGF0aWMgQ1JUX0RQMSA9IDc7XHJcbiAgc3RhdGljIENSVF9EUTEgPSA4O1xyXG4gIHN0YXRpYyBDUlRfUFEgPSA5O1xyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xuaW1wb3J0IHsgQnl0ZUJ1ZmZlciB9IGZyb20gJy4vYnl0ZS1idWZmZXInO1xuaW1wb3J0IHsgS2V5IH0gZnJvbSAnLi9rZXknO1xuXG5leHBvcnQgY2xhc3MgQ3J5cHRvXG57XG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICB9XG5cbiAgZW5jcnlwdCgga2V5LCBtZWNoLCBkYXRhOiBCeXRlU3RyaW5nIClcbiAge1xuICAgIHZhciBrOiBCeXRlQXJyYXkgPSBrZXkuZ2V0Q29tcG9uZW50KCBLZXkuU0VDUkVUICkuYnl0ZUFycmF5O1xuXG4gICAgaWYgKCBrLmxlbmd0aCA9PSAxNiApICAvLyAzREVTIERvdWJsZSAtPiBUcmlwbGVcbiAgICB7XG4gICAgICB2YXIgb3JpZyA9IGs7XG5cbiAgICAgIGsgPSBuZXcgQnl0ZUFycmF5KCBbXSApLnNldExlbmd0aCggMjQgKTtcblxuICAgICAgay5zZXRCeXRlc0F0KCAwLCBvcmlnICk7XG4gICAgICBrLnNldEJ5dGVzQXQoIDE2LCBvcmlnLnZpZXdBdCggMCwgOCApICk7XG4gICAgfVxuXG4gICAgdmFyIGNyeXB0b1RleHQgPSBuZXcgQnl0ZUJ1ZmZlciggdGhpcy5kZXMoIGsuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDAgKSApO1xuXG4gICAgcmV0dXJuIGNyeXB0b1RleHQudG9CeXRlU3RyaW5nKCk7XG4gIH1cblxuICBkZWNyeXB0KCBrZXksIG1lY2gsIGRhdGEgKVxuICB7XG4gICAgcmV0dXJuIGRhdGE7XG4gIH1cblxuICBzaWduKCBrZXksIG1lY2gsIGRhdGEsIGl2PyApXG4gIHtcbiAgICB2YXIgayA9IGtleS5nZXRDb21wb25lbnQoIEtleS5TRUNSRVQgKS5fYnl0ZXM7XG5cbiAgICB2YXIga2V5RGF0YSA9IGs7XG5cbiAgICBpZiAoIGsubGVuZ3RoID09IDE2ICkgIC8vIDNERVMgRG91YmxlIC0+IFRyaXBsZVxuICAgIHtcbiAgICAgIGtleURhdGEgPSBuZXcgVWludDhBcnJheSggMjQgKTtcblxuICAgICAga2V5RGF0YS5zZXQoIGssIDAgKTtcbiAgICAgIGtleURhdGEuc2V0KCBrLnN1YmFycmF5KCAwLCA4ICksIDE2ICk7XG4gICAgfVxuXG4gICAgaWYgKCBpdiA9PSB1bmRlZmluZWQgKVxuICAgICAgaXYgPSBuZXcgVWludDhBcnJheSggWyAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwIF0gKTtcblxuICAgIC8vIGZ1bmN0aW9uKCBrZXksIG1lc3NhZ2UsIGVuY3J5cHQsIG1vZGUsIGl2LCBwYWRkaW5nIClcbiAgICAvLyBtb2RlPTEgQ0JDLCBwYWRkaW5nPTQgbm8tcGFkXG4gICAgdmFyIGNyeXB0b1RleHQgPSBuZXcgQnl0ZUJ1ZmZlciggdGhpcy5kZXMoIGtleURhdGEsIGRhdGEuX2J5dGVzLCAxLCAxLCBpdiwgNCApICk7XG5cbiAgICByZXR1cm4gY3J5cHRvVGV4dC50b0J5dGVTdHJpbmcoKS5ieXRlcyggLTggKTtcbiAgfVxuXG4gIHN0YXRpYyBkZXNQQztcbiAgc3RhdGljIGRlc1NQO1xuXG4gIHByaXZhdGUgZGVzKCBrZXk6IFVpbnQ4QXJyYXksIG1lc3NhZ2U6IFVpbnQ4QXJyYXksIGVuY3J5cHQ6IG51bWJlciwgbW9kZTogbnVtYmVyLCBpdj86IFVpbnQ4QXJyYXksIHBhZGRpbmc/OiBudW1iZXIgKTogVWludDhBcnJheVxuICB7XG4gICAgLy9kZXNfY3JlYXRlS2V5c1xuICAgIC8vdGhpcyB0YWtlcyBhcyBpbnB1dCBhIDY0IGJpdCBrZXkgKGV2ZW4gdGhvdWdoIG9ubHkgNTYgYml0cyBhcmUgdXNlZClcbiAgICAvL2FzIGFuIGFycmF5IG9mIDIgaW50ZWdlcnMsIGFuZCByZXR1cm5zIDE2IDQ4IGJpdCBrZXlzXG4gICAgZnVuY3Rpb24gZGVzX2NyZWF0ZUtleXMgKGtleSlcbiAgICB7XG4gICAgICBpZiAoIENyeXB0by5kZXNQQyA9PSB1bmRlZmluZWQgKVxuICAgICAge1xuICAgICAgICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICAgICAgICBDcnlwdG8uZGVzUEMgPSB7XG4gICAgICAgICAgcGMyYnl0ZXMwIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MjAwMDAwMDAsMHgyMDAwMDAwNCwweDEwMDAwLDB4MTAwMDQsMHgyMDAxMDAwMCwweDIwMDEwMDA0LDB4MjAwLDB4MjA0LDB4MjAwMDAyMDAsMHgyMDAwMDIwNCwweDEwMjAwLDB4MTAyMDQsMHgyMDAxMDIwMCwweDIwMDEwMjA0IF0gKSxcbiAgICAgICAgICBwYzJieXRlczEgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEsMHgxMDAwMDAsMHgxMDAwMDEsMHg0MDAwMDAwLDB4NDAwMDAwMSwweDQxMDAwMDAsMHg0MTAwMDAxLDB4MTAwLDB4MTAxLDB4MTAwMTAwLDB4MTAwMTAxLDB4NDAwMDEwMCwweDQwMDAxMDEsMHg0MTAwMTAwLDB4NDEwMDEwMV0gKSxcbiAgICAgICAgICBwYzJieXRlczIgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4LDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOF0gKSxcbiAgICAgICAgICBwYzJieXRlczMgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDIwMDAwMCwweDgwMDAwMDAsMHg4MjAwMDAwLDB4MjAwMCwweDIwMjAwMCwweDgwMDIwMDAsMHg4MjAyMDAwLDB4MjAwMDAsMHgyMjAwMDAsMHg4MDIwMDAwLDB4ODIyMDAwMCwweDIyMDAwLDB4MjIyMDAwLDB4ODAyMjAwMCwweDgyMjIwMDBdICksXG4gICAgICAgICAgcGMyYnl0ZXM0IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMF0gKSxcbiAgICAgICAgICBwYzJieXRlczUgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMCwweDIwLDB4NDIwLDAsMHg0MDAsMHgyMCwweDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4MDAwMCwweDEwMDgwMDAwLDB4MiwweDEwMDAwMDAyLDB4ODAwMDIsMHgxMDA4MDAwMiwwLDB4MTAwMDAwMDAsMHg4MDAwMCwweDEwMDgwMDAwLDB4MiwweDEwMDAwMDAyLDB4ODAwMDIsMHgxMDA4MDAwMl0gKSxcbiAgICAgICAgICBwYzJieXRlczcgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwLDB4ODAwLDB4MTA4MDAsMHgyMDAwMDAwMCwweDIwMDEwMDAwLDB4MjAwMDA4MDAsMHgyMDAxMDgwMCwweDIwMDAwLDB4MzAwMDAsMHgyMDgwMCwweDMwODAwLDB4MjAwMjAwMDAsMHgyMDAzMDAwMCwweDIwMDIwODAwLDB4MjAwMzA4MDBdICksXG4gICAgICAgICAgcGMyYnl0ZXM4IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAwMCwwLDB4NDAwMDAsMHgyLDB4NDAwMDIsMHgyLDB4NDAwMDIsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMiwweDIwNDAwMDIsMHgyMDAwMDAyLDB4MjA0MDAwMl0gKSxcbiAgICAgICAgICBwYzJieXRlczkgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAsMCwweDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MjAwMCwweDIwMjAsMHgyMDAwLDB4MjAyMCwweDEwMjAwMCwweDEwMjAyMCwweDEwMjAwMCwweDEwMjAyMF0gKSxcbiAgICAgICAgICBwYzJieXRlczExOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAsMHgyMDAsMHgxMDAwMjAwLDB4MjAwMDAwLDB4MTIwMDAwMCwweDIwMDIwMCwweDEyMDAyMDAsMHg0MDAwMDAwLDB4NTAwMDAwMCwweDQwMDAyMDAsMHg1MDAwMjAwLDB4NDIwMDAwMCwweDUyMDAwMDAsMHg0MjAwMjAwLDB4NTIwMDIwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczEyOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAsMHg4MDAwMDAwLDB4ODAwMTAwMCwweDgwMDAwLDB4ODEwMDAsMHg4MDgwMDAwLDB4ODA4MTAwMCwweDEwLDB4MTAxMCwweDgwMDAwMTAsMHg4MDAxMDEwLDB4ODAwMTAsMHg4MTAxMCwweDgwODAwMTAsMHg4MDgxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTM6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NCwweDEwMCwweDEwNCwwLDB4NCwweDEwMCwweDEwNCwweDEsMHg1LDB4MTAxLDB4MTA1LDB4MSwweDUsMHgxMDEsMHgxMDVdIClcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy9ob3cgbWFueSBpdGVyYXRpb25zICgxIGZvciBkZXMsIDMgZm9yIHRyaXBsZSBkZXMpXG4gICAgICB2YXIgaXRlcmF0aW9ucyA9IGtleS5sZW5ndGggPiA4ID8gMyA6IDE7IC8vY2hhbmdlZCBieSBQYXVsIDE2LzYvMjAwNyB0byB1c2UgVHJpcGxlIERFUyBmb3IgOSsgYnl0ZSBrZXlzXG4gICAgICAvL3N0b3JlcyB0aGUgcmV0dXJuIGtleXNcbiAgICAgIHZhciBrZXlzID0gbmV3IFVpbnQzMkFycmF5KDMyICogaXRlcmF0aW9ucyk7XG4gICAgICAvL25vdyBkZWZpbmUgdGhlIGxlZnQgc2hpZnRzIHdoaWNoIG5lZWQgdG8gYmUgZG9uZVxuICAgICAgdmFyIHNoaWZ0cyA9IFsgMCwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCBdO1xuICAgICAgLy9vdGhlciB2YXJpYWJsZXNcbiAgICAgIHZhciBsZWZ0dGVtcCwgcmlnaHR0ZW1wLCBtPTAsIG49MCwgdGVtcDtcblxuICAgICAgZm9yICh2YXIgaj0wOyBqPGl0ZXJhdGlvbnM7IGorKylcbiAgICAgIHsgLy9laXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcbiAgICAgICAgbGVmdCA9ICAoa2V5W20rK10gPDwgMjQpIHwgKGtleVttKytdIDw8IDE2KSB8IChrZXlbbSsrXSA8PCA4KSB8IGtleVttKytdO1xuICAgICAgICByaWdodCA9IChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG5cbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAyKSBeIHJpZ2h0KSAmIDB4MzMzMzMzMzM7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMik7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAgICAgLy90aGUgcmlnaHQgc2lkZSBuZWVkcyB0byBiZSBzaGlmdGVkIGFuZCB0byBnZXQgdGhlIGxhc3QgZm91ciBiaXRzIG9mIHRoZSBsZWZ0IHNpZGVcbiAgICAgICAgdGVtcCA9IChsZWZ0IDw8IDgpIHwgKChyaWdodCA+Pj4gMjApICYgMHgwMDAwMDBmMCk7XG4gICAgICAgIC8vbGVmdCBuZWVkcyB0byBiZSBwdXQgdXBzaWRlIGRvd25cbiAgICAgICAgbGVmdCA9IChyaWdodCA8PCAyNCkgfCAoKHJpZ2h0IDw8IDgpICYgMHhmZjAwMDApIHwgKChyaWdodCA+Pj4gOCkgJiAweGZmMDApIHwgKChyaWdodCA+Pj4gMjQpICYgMHhmMCk7XG4gICAgICAgIHJpZ2h0ID0gdGVtcDtcblxuICAgICAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZXNlIHNoaWZ0cyBvbiB0aGUgbGVmdCBhbmQgcmlnaHQga2V5c1xuICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCBzaGlmdHMubGVuZ3RoOyBpKyspXG4gICAgICAgIHtcbiAgICAgICAgICAvL3NoaWZ0IHRoZSBrZXlzIGVpdGhlciBvbmUgb3IgdHdvIGJpdHMgdG8gdGhlIGxlZnRcbiAgICAgICAgICBpZiAoc2hpZnRzW2ldKVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAyKSB8IChsZWZ0ID4+PiAyNik7IHJpZ2h0ID0gKHJpZ2h0IDw8IDIpIHwgKHJpZ2h0ID4+PiAyNik7XG4gICAgICAgICAgfVxuICAgICAgICAgIGVsc2VcbiAgICAgICAgICB7XG4gICAgICAgICAgICBsZWZ0ID0gKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMjcpOyByaWdodCA9IChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMjcpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBsZWZ0ICY9IC0weGY7IHJpZ2h0ICY9IC0weGY7XG5cbiAgICAgICAgICAvL25vdyBhcHBseSBQQy0yLCBpbiBzdWNoIGEgd2F5IHRoYXQgRSBpcyBlYXNpZXIgd2hlbiBlbmNyeXB0aW5nIG9yIGRlY3J5cHRpbmdcbiAgICAgICAgICAvL3RoaXMgY29udmVyc2lvbiB3aWxsIGxvb2sgbGlrZSBQQy0yIGV4Y2VwdCBvbmx5IHRoZSBsYXN0IDYgYml0cyBvZiBlYWNoIGJ5dGUgYXJlIHVzZWRcbiAgICAgICAgICAvL3JhdGhlciB0aGFuIDQ4IGNvbnNlY3V0aXZlIGJpdHMgYW5kIHRoZSBvcmRlciBvZiBsaW5lcyB3aWxsIGJlIGFjY29yZGluZyB0b1xuICAgICAgICAgIC8vaG93IHRoZSBTIHNlbGVjdGlvbiBmdW5jdGlvbnMgd2lsbCBiZSBhcHBsaWVkOiBTMiwgUzQsIFM2LCBTOCwgUzEsIFMzLCBTNSwgUzdcbiAgICAgICAgICBsZWZ0dGVtcCA9IENyeXB0by5kZXNQQy5wYzJieXRlczBbbGVmdCA+Pj4gMjhdIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMVsobGVmdCA+Pj4gMjQpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMlsobGVmdCA+Pj4gMjApICYgMHhmXSB8IENyeXB0by5kZXNQQy5wYzJieXRlczNbKGxlZnQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNQQy5wYzJieXRlczRbKGxlZnQgPj4+IDEyKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXM1WyhsZWZ0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNQQy5wYzJieXRlczZbKGxlZnQgPj4+IDQpICYgMHhmXTtcbiAgICAgICAgICByaWdodHRlbXAgPSBDcnlwdG8uZGVzUEMucGMyYnl0ZXM3W3JpZ2h0ID4+PiAyOF0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXM4WyhyaWdodCA+Pj4gMjQpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNQQy5wYzJieXRlczlbKHJpZ2h0ID4+PiAyMCkgJiAweGZdIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMTBbKHJpZ2h0ID4+PiAxNikgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMTFbKHJpZ2h0ID4+PiAxMikgJiAweGZdIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMTJbKHJpZ2h0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxM1socmlnaHQgPj4+IDQpICYgMHhmXTtcbiAgICAgICAgICB0ZW1wID0gKChyaWdodHRlbXAgPj4+IDE2KSBeIGxlZnR0ZW1wKSAmIDB4MDAwMGZmZmY7XG4gICAgICAgICAga2V5c1tuKytdID0gbGVmdHRlbXAgXiB0ZW1wOyBrZXlzW24rK10gPSByaWdodHRlbXAgXiAodGVtcCA8PCAxNik7XG4gICAgICAgIH1cbiAgICAgIH0gLy9mb3IgZWFjaCBpdGVyYXRpb25zXG5cbiAgICAgIHJldHVybiBrZXlzO1xuICAgIH0gLy9lbmQgb2YgZGVzX2NyZWF0ZUtleXNcblxuICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgaWYgKCBDcnlwdG8uZGVzU1AgPT0gdW5kZWZpbmVkIClcbiAgICB7XG4gICAgICBDcnlwdG8uZGVzU1AgPSB7XG4gICAgICAgIHNwZnVuY3Rpb24xOiBuZXcgVWludDMyQXJyYXkoIFsweDEwMTA0MDAsMCwweDEwMDAwLDB4MTAxMDQwNCwweDEwMTAwMDQsMHgxMDQwNCwweDQsMHgxMDAwMCwweDQwMCwweDEwMTA0MDAsMHgxMDEwNDA0LDB4NDAwLDB4MTAwMDQwNCwweDEwMTAwMDQsMHgxMDAwMDAwLDB4NCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDB4MTA0MDAsMHgxMDQwMCwweDEwMTAwMDAsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDA0LDB4MTAwMDAwNCwweDEwMDAwMDQsMHgxMDAwNCwwLDB4NDA0LDB4MTA0MDQsMHgxMDAwMDAwLDB4MTAwMDAsMHgxMDEwNDA0LDB4NCwweDEwMTAwMDAsMHgxMDEwNDAwLDB4MTAwMDAwMCwweDEwMDAwMDAsMHg0MDAsMHgxMDEwMDA0LDB4MTAwMDAsMHgxMDQwMCwweDEwMDAwMDQsMHg0MDAsMHg0LDB4MTAwMDQwNCwweDEwNDA0LDB4MTAxMDQwNCwweDEwMDA0LDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwMDA0LDB4NDA0LDB4MTA0MDQsMHgxMDEwNDAwLDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMCwweDEwMDA0LDB4MTA0MDAsMCwweDEwMTAwMDRdICksXG4gICAgICAgIHNwZnVuY3Rpb24yOiBuZXcgVWludDMyQXJyYXkoIFstMHg3ZmVmN2ZlMCwtMHg3ZmZmODAwMCwweDgwMDAsMHgxMDgwMjAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwtMHg3ZmZmN2ZlMCwtMHg3ZmZmZmZlMCwtMHg3ZmVmN2ZlMCwtMHg3ZmVmODAwMCwtMHg4MDAwMDAwMCwtMHg3ZmZmODAwMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLDB4MTA4MDAwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLDAsLTB4ODAwMDAwMDAsMHg4MDAwLDB4MTA4MDIwLC0weDdmZjAwMDAwLDB4MTAwMDIwLC0weDdmZmZmZmUwLDAsMHgxMDgwMDAsMHg4MDIwLC0weDdmZWY4MDAwLC0weDdmZjAwMDAwLDB4ODAyMCwwLDB4MTA4MDIwLC0weDdmZWZmZmUwLDB4MTAwMDAwLC0weDdmZmY3ZmUwLC0weDdmZjAwMDAwLC0weDdmZWY4MDAwLDB4ODAwMCwtMHg3ZmYwMDAwMCwtMHg3ZmZmODAwMCwweDIwLC0weDdmZWY3ZmUwLDB4MTA4MDIwLDB4MjAsMHg4MDAwLC0weDgwMDAwMDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwweDEwMDAwMCwtMHg3ZmZmZmZlMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwtMHg3ZmZmZmZlMCwweDEwMDAyMCwweDEwODAwMCwwLC0weDdmZmY4MDAwLDB4ODAyMCwtMHg4MDAwMDAwMCwtMHg3ZmVmZmZlMCwtMHg3ZmVmN2ZlMCwweDEwODAwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjM6IG5ldyBVaW50MzJBcnJheSggWzB4MjA4LDB4ODAyMDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDAsMCwweDIwMjA4LDB4ODAwMDIwMCwweDIwMDA4LDB4ODAwMDAwOCwweDgwMDAwMDgsMHgyMDAwMCwweDgwMjAyMDgsMHgyMDAwOCwweDgwMjAwMDAsMHgyMDgsMHg4MDAwMDAwLDB4OCwweDgwMjAyMDAsMHgyMDAsMHgyMDIwMCwweDgwMjAwMDAsMHg4MDIwMDA4LDB4MjAyMDgsMHg4MDAwMjA4LDB4MjAyMDAsMHgyMDAwMCwweDgwMDAyMDgsMHg4LDB4ODAyMDIwOCwweDIwMCwweDgwMDAwMDAsMHg4MDIwMjAwLDB4ODAwMDAwMCwweDIwMDA4LDB4MjA4LDB4MjAwMDAsMHg4MDIwMjAwLDB4ODAwMDIwMCwwLDB4MjAwLDB4MjAwMDgsMHg4MDIwMjA4LDB4ODAwMDIwMCwweDgwMDAwMDgsMHgyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjA4LDB4MjAwMDAsMHg4MDAwMDAwLDB4ODAyMDIwOCwweDgsMHgyMDIwOCwweDIwMjAwLDB4ODAwMDAwOCwweDgwMjAwMDAsMHg4MDAwMjA4LDB4MjA4LDB4ODAyMDAwMCwweDIwMjA4LDB4OCwweDgwMjAwMDgsMHgyMDIwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjQ6IG5ldyBVaW50MzJBcnJheSggWzB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MCwweDgwMDA4MSwweDgwMDAwMSwweDIwMDEsMCwweDgwMjAwMCwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMHg4MDAwODAsMHg4MDAwMDEsMHgxLDB4MjAwMCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMSwweDIwODAsMHg4MDAwODEsMHgxLDB4MjA4MCwweDgwMDA4MCwweDIwMDAsMHg4MDIwODAsMHg4MDIwODEsMHg4MSwweDgwMDA4MCwweDgwMDAwMSwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMCwweDgwMjAwMCwweDIwODAsMHg4MDAwODAsMHg4MDAwODEsMHgxLDB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MSwweDgxLDB4MSwweDIwMDAsMHg4MDAwMDEsMHgyMDAxLDB4ODAyMDgwLDB4ODAwMDgxLDB4MjAwMSwweDIwODAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDAsMHg4MDIwODBdICksXG4gICAgICAgIHNwZnVuY3Rpb241OiBuZXcgVWludDMyQXJyYXkoIFsweDEwMCwweDIwODAxMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg4MDAwMCwweDEwMCwweDQwMDAwMDAwLDB4MjA4MDAwMCwweDQwMDgwMTAwLDB4ODAwMDAsMHgyMDAwMTAwLDB4NDAwODAxMDAsMHg0MjAwMDEwMCwweDQyMDgwMDAwLDB4ODAxMDAsMHg0MDAwMDAwMCwweDIwMDAwMDAsMHg0MDA4MDAwMCwweDQwMDgwMDAwLDAsMHg0MDAwMDEwMCwweDQyMDgwMTAwLDB4NDIwODAxMDAsMHgyMDAwMTAwLDB4NDIwODAwMDAsMHg0MDAwMDEwMCwwLDB4NDIwMDAwMDAsMHgyMDgwMTAwLDB4MjAwMDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHg4MDAwMCwweDQyMDAwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQwMDAwMDAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4NDAwODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAwMDAsMHg0MjA4MDAwMCwweDIwODAxMDAsMHg0MDA4MDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MjA4MDAwMCwweDQyMDgwMTAwLDB4ODAxMDAsMHg0MjAwMDAwMCwweDQyMDgwMTAwLDB4MjA4MDAwMCwwLDB4NDAwODAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMTAwLDB4ODAwMDAsMCwweDQwMDgwMDAwLDB4MjA4MDEwMCwweDQwMDAwMTAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNjogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDAwMDAxMCwweDIwNDAwMDAwLDB4NDAwMCwweDIwNDA0MDEwLDB4MjA0MDAwMDAsMHgxMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHg0MDQwMTAsMHg0MDAwMDAsMHgyMDAwMDAxMCwweDQwMDAxMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwweDQwMDAsMHg0MDQwMDAsMHgyMDAwNDAxMCwweDEwLDB4MjA0MDAwMTAsMHgyMDQwMDAxMCwwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMHg0MDEwLDB4NDA0MDAwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDIwMDA0MDAwLDB4MTAsMHgyMDQwMDAxMCwweDQwNDAwMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDIwNDA0MDEwLDB4NDA0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwwLDB4MjA0MDAwMTAsMHgxMCwweDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDQwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDQwMDAxMCwweDIwMDA0MDEwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDAwMDAsMHg0MjAwMDAyLDB4NDAwMDgwMiwwLDB4ODAwLDB4NDAwMDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg0MjAwODAyLDB4MjAwMDAwLDAsMHg0MDAwMDAyLDB4MiwweDQwMDAwMDAsMHg0MjAwMDAyLDB4ODAyLDB4NDAwMDgwMCwweDIwMDgwMiwweDIwMDAwMiwweDQwMDA4MDAsMHg0MDAwMDAyLDB4NDIwMDAwMCwweDQyMDA4MDAsMHgyMDAwMDIsMHg0MjAwMDAwLDB4ODAwLDB4ODAyLDB4NDIwMDgwMiwweDIwMDgwMCwweDIsMHg0MDAwMDAwLDB4MjAwODAwLDB4NDAwMDAwMCwweDIwMDgwMCwweDIwMDAwMCwweDQwMDA4MDIsMHg0MDAwODAyLDB4NDIwMDAwMiwweDQyMDAwMDIsMHgyLDB4MjAwMDAyLDB4NDAwMDAwMCwweDQwMDA4MDAsMHgyMDAwMDAsMHg0MjAwODAwLDB4ODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDgwMiwweDQwMDAwMDIsMHg0MjAwODAyLDB4NDIwMDAwMCwweDIwMDgwMCwwLDB4MiwweDQyMDA4MDIsMCwweDIwMDgwMiwweDQyMDAwMDAsMHg4MDAsMHg0MDAwMDAyLDB4NDAwMDgwMCwweDgwMCwweDIwMDAwMl0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjg6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwMDEwNDAsMHgxMDAwLDB4NDAwMDAsMHgxMDA0MTA0MCwweDEwMDAwMDAwLDB4MTAwMDEwNDAsMHg0MCwweDEwMDAwMDAwLDB4NDAwNDAsMHgxMDA0MDAwMCwweDEwMDQxMDQwLDB4NDEwMDAsMHgxMDA0MTAwMCwweDQxMDQwLDB4MTAwMCwweDQwLDB4MTAwNDAwMDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4MTA0MCwweDQxMDAwLDB4NDAwNDAsMHgxMDA0MDA0MCwweDEwMDQxMDAwLDB4MTA0MCwwLDAsMHgxMDA0MDA0MCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHg0MTA0MCwweDQwMDAwLDB4NDEwNDAsMHg0MDAwMCwweDEwMDQxMDAwLDB4MTAwMCwweDQwLDB4MTAwNDAwNDAsMHgxMDAwLDB4NDEwNDAsMHgxMDAwMTAwMCwweDQwLDB4MTAwMDAwNDAsMHgxMDA0MDAwMCwweDEwMDQwMDQwLDB4MTAwMDAwMDAsMHg0MDAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQwMDQwLDB4MTAwMDAwNDAsMHgxMDA0MDAwMCwweDEwMDAxMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDEwMDAsMHg0MTAwMCwweDEwNDAsMHgxMDQwLDB4NDAwNDAsMHgxMDAwMDAwMCwweDEwMDQxMDAwXSApLFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvL2NyZWF0ZSB0aGUgMTYgb3IgNDggc3Via2V5cyB3ZSB3aWxsIG5lZWRcbiAgICB2YXIga2V5cyA9IGRlc19jcmVhdGVLZXlzKCBrZXkgKTtcblxuICAgIHZhciBtPTAsIGksIGosIHRlbXAsIGxlZnQsIHJpZ2h0LCBsb29waW5nO1xuICAgIHZhciBjYmNsZWZ0LCBjYmNsZWZ0MiwgY2JjcmlnaHQsIGNiY3JpZ2h0MlxuICAgIHZhciBsZW4gPSBtZXNzYWdlLmxlbmd0aDtcblxuICAgIC8vc2V0IHVwIHRoZSBsb29wcyBmb3Igc2luZ2xlIGFuZCB0cmlwbGUgZGVzXG4gICAgdmFyIGl0ZXJhdGlvbnMgPSBrZXlzLmxlbmd0aCA9PSAzMiA/IDMgOiA5OyAvL3NpbmdsZSBvciB0cmlwbGUgZGVzXG5cbiAgICBpZiAoaXRlcmF0aW9ucyA9PSAzKVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiBdIDogWyAzMCwgLTIsIC0yIF07XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICBsb29waW5nID0gZW5jcnlwdCA/IFsgMCwgMzIsIDIsIDYyLCAzMCwgLTIsIDY0LCA5NiwgMiBdIDogWyA5NCwgNjIsIC0yLCAzMiwgNjQsIDIsIDMwLCAtMiwgLTIgXTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIG1lc3NhZ2UgZGVwZW5kaW5nIG9uIHRoZSBwYWRkaW5nIHBhcmFtZXRlclxuICAgIGlmICggKCBwYWRkaW5nICE9IHVuZGVmaW5lZCApICYmICggcGFkZGluZyAhPSA0ICkgKVxuICAgIHtcbiAgICAgIHZhciB1bnBhZGRlZE1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgdmFyIHBhZCA9IDgtKGxlbiU4KTtcblxuICAgICAgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KCBsZW4gKyA4ICk7XG4gICAgICBtZXNzYWdlLnNldCggdW5wYWRkZWRNZXNzYWdlLCAwICk7XG5cbiAgICAgIHN3aXRjaCggcGFkZGluZyApXG4gICAgICB7XG4gICAgICAgIGNhc2UgMDogLy8gemVyby1wYWRcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdICksIGxlbiApO1xuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgIGNhc2UgMTogLy8gUEtDUzcgcGFkZGluZ1xuICAgICAgICB7XG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkXSApLCA4ICk7XG5cbiAgICAgICAgICBpZiAoIHBhZD09OCApXG4gICAgICAgICAgICBsZW4rPTg7XG5cbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuXG4gICAgICAgIGNhc2UgMjogIC8vIHBhZCB0aGUgbWVzc2FnZSB3aXRoIHNwYWNlc1xuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwIF0gKSwgOCApO1xuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICB9XG5cbiAgICAgIGxlbiArPSA4LShsZW4lOClcbiAgICB9XG5cbiAgICAvLyBzdG9yZSB0aGUgcmVzdWx0IGhlcmVcbiAgICB2YXIgcmVzdWx0ID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiApO1xuXG4gICAgaWYgKG1vZGUgPT0gMSlcbiAgICB7IC8vQ0JDIG1vZGVcbiAgICAgIHZhciBtID0gMDtcblxuICAgICAgY2JjbGVmdCA9ICAoaXZbbSsrXSA8PCAyNCkgfCAoaXZbbSsrXSA8PCAxNikgfCAoaXZbbSsrXSA8PCA4KSB8IGl2W20rK107XG4gICAgICBjYmNyaWdodCA9IChpdlttKytdIDw8IDI0KSB8IChpdlttKytdIDw8IDE2KSB8IChpdlttKytdIDw8IDgpIHwgaXZbbSsrXTtcbiAgICB9XG5cbiAgICB2YXIgcm0gPSAwO1xuXG4gICAgLy9sb29wIHRocm91Z2ggZWFjaCA2NCBiaXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICB3aGlsZSAobSA8IGxlbilcbiAgICB7XG4gICAgICBsZWZ0ID0gIChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuICAgICAgcmlnaHQgPSAobWVzc2FnZVttKytdIDw8IDI0KSB8IChtZXNzYWdlW20rK10gPDwgMTYpIHwgKG1lc3NhZ2VbbSsrXSA8PCA4KSB8IG1lc3NhZ2VbbSsrXTtcblxuICAgICAgLy9mb3IgQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUsIHhvciB0aGUgbWVzc2FnZSB3aXRoIHRoZSBwcmV2aW91cyByZXN1bHRcbiAgICAgIGlmIChtb2RlID09IDEpXG4gICAgICB7XG4gICAgICAgIGlmIChlbmNyeXB0KVxuICAgICAgICB7XG4gICAgICAgICAgbGVmdCBePSBjYmNsZWZ0OyByaWdodCBePSBjYmNyaWdodDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0MiA9IGNiY2xlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQyID0gY2JjcmlnaHQ7XG4gICAgICAgICAgY2JjbGVmdCA9IGxlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQgPSByaWdodDtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvL2ZpcnN0IGVhY2ggNjQgYnV0IGNodW5rIG9mIHRoZSBtZXNzYWdlIG11c3QgYmUgcGVybXV0ZWQgYWNjb3JkaW5nIHRvIElQXG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxNikgXiByaWdodCkgJiAweDAwMDBmZmZmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDE2KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgbGVmdCA9ICgobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAzMSkpO1xuXG4gICAgICAvL2RvIHRoaXMgZWl0aGVyIDEgb3IgMyB0aW1lcyBmb3IgZWFjaCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgICAgZm9yIChqPTA7IGo8aXRlcmF0aW9uczsgais9MylcbiAgICAgIHtcbiAgICAgICAgdmFyIGVuZGxvb3AgPSBsb29waW5nW2orMV07XG4gICAgICAgIHZhciBsb29waW5jID0gbG9vcGluZ1tqKzJdO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlIGVuY3J5cHRpb24gb3IgZGVjcnlwdGlvblxuICAgICAgICBmb3IgKGk9bG9vcGluZ1tqXTsgaSE9ZW5kbG9vcDsgaSs9bG9vcGluYylcbiAgICAgICAgeyAvL2ZvciBlZmZpY2llbmN5XG4gICAgICAgICAgdmFyIHJpZ2h0MSA9IHJpZ2h0IF4ga2V5c1tpXTtcbiAgICAgICAgICB2YXIgcmlnaHQyID0gKChyaWdodCA+Pj4gNCkgfCAocmlnaHQgPDwgMjgpKSBeIGtleXNbaSsxXTtcblxuICAgICAgICAgIC8vdGhlIHJlc3VsdCBpcyBhdHRhaW5lZCBieSBwYXNzaW5nIHRoZXNlIGJ5dGVzIHRocm91Z2ggdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9uc1xuICAgICAgICAgIHRlbXAgPSBsZWZ0O1xuICAgICAgICAgIGxlZnQgPSByaWdodDtcbiAgICAgICAgICByaWdodCA9IHRlbXAgXiAoQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb24yWyhyaWdodDEgPj4+IDI0KSAmIDB4M2ZdIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb240WyhyaWdodDEgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uNlsocmlnaHQxID4+PiAgOCkgJiAweDNmXSB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uOFtyaWdodDEgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjFbKHJpZ2h0MiA+Pj4gMjQpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjNbKHJpZ2h0MiA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb241WyhyaWdodDIgPj4+ICA4KSAmIDB4M2ZdIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb243W3JpZ2h0MiAmIDB4M2ZdKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRlbXAgPSBsZWZ0OyBsZWZ0ID0gcmlnaHQ7IHJpZ2h0ID0gdGVtcDsgLy91bnJldmVyc2UgbGVmdCBhbmQgcmlnaHRcbiAgICAgIH0gLy9mb3IgZWl0aGVyIDEgb3IgMyBpdGVyYXRpb25zXG5cbiAgICAgIC8vbW92ZSB0aGVuIGVhY2ggb25lIGJpdCB0byB0aGUgcmlnaHRcbiAgICAgIGxlZnQgPSAoKGxlZnQgPj4+IDEpIHwgKGxlZnQgPDwgMzEpKTtcbiAgICAgIHJpZ2h0ID0gKChyaWdodCA+Pj4gMSkgfCAocmlnaHQgPDwgMzEpKTtcblxuICAgICAgLy9ub3cgcGVyZm9ybSBJUC0xLCB3aGljaCBpcyBJUCBpbiB0aGUgb3Bwb3NpdGUgZGlyZWN0aW9uXG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gMikgXiBsZWZ0KSAmIDB4MzMzMzMzMzM7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgMik7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxNikgXiByaWdodCkgJiAweDAwMDBmZmZmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDE2KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcblxuICAgICAgLy9mb3IgQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUsIHhvciB0aGUgbWVzc2FnZSB3aXRoIHRoZSBwcmV2aW91cyByZXN1bHRcbiAgICAgIGlmIChtb2RlID09IDEpXG4gICAgICB7XG4gICAgICAgIGlmIChlbmNyeXB0KVxuICAgICAgICB7XG4gICAgICAgICAgY2JjbGVmdCA9IGxlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQgPSByaWdodDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgIHtcbiAgICAgICAgICBsZWZ0IF49IGNiY2xlZnQyO1xuICAgICAgICAgIHJpZ2h0IF49IGNiY3JpZ2h0MjtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICByZXN1bHQuc2V0KCBuZXcgVWludDhBcnJheSAoIFsgKGxlZnQ+Pj4yNCkgJiAweGZmLCAobGVmdD4+PjE2KSAmIDB4ZmYsIChsZWZ0Pj4+OCkgJiAweGZmLCAobGVmdCkgJiAweGZmLCAocmlnaHQ+Pj4yNCkgJiAweGZmLCAocmlnaHQ+Pj4xNikgJiAweGZmLCAocmlnaHQ+Pj44KSAmIDB4ZmYsIChyaWdodCkgJiAweGZmIF0gKSwgcm0gKTtcblxuICAgICAgcm0gKz0gODtcbiAgICB9IC8vZm9yIGV2ZXJ5IDggY2hhcmFjdGVycywgb3IgNjQgYml0cyBpbiB0aGUgbWVzc2FnZVxuXG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSAvL2VuZCBvZiBkZXNcblxuICB2ZXJpZnkoIGtleSwgbWVjaCwgZGF0YSwgc2lnbmF0dXJlLCBpdiApXG4gIHtcbiAgICByZXR1cm4gZGF0YTtcbiAgfVxuXG4gIGRpZ2VzdCggbWVjaCwgZGF0YSApXG4gIHtcbiAgICByZXR1cm4gZGF0YTtcbiAgfVxuXG4gIHN0YXRpYyBERVNfQ0JDOiBOdW1iZXIgPSAyO1xuICBzdGF0aWMgREVTX0VDQiA9IDU7XG4gIHN0YXRpYyBERVNfTUFDID0gODtcbiAgc3RhdGljIERFU19NQUNfRU1WID0gOTtcbiAgc3RhdGljIElTTzk3OTdfTUVUSE9EXzEgPSAxMTtcbiAgc3RhdGljIElTTzk3OTdfTUVUSE9EXzIgPSAxMjtcblxuICBzdGF0aWMgTUQ1ID0gMTM7XG4gIHN0YXRpYyBSU0EgPSAxNDtcbiAgc3RhdGljIFNIQV8xID0gMTU7XG4gIHN0YXRpYyBTSEFfNTEyID0gMjU7XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbmltcG9ydCB7IEJ5dGVCdWZmZXIgfSBmcm9tICcuL2J5dGUtYnVmZmVyJztcclxuaW1wb3J0IHsgQ3J5cHRvIH0gZnJvbSAnLi9jcnlwdG8nO1xyXG5cclxuZXhwb3J0IGNsYXNzIEJ5dGVTdHJpbmdcclxue1xyXG4gIHB1YmxpYyBieXRlQXJyYXk6IEJ5dGVBcnJheTtcclxuXHJcbiAgcHVibGljIHN0YXRpYyBIRVggPSBCeXRlQXJyYXkuSEVYO1xyXG4gIHB1YmxpYyBzdGF0aWMgQkFTRTY0ID0gQnl0ZUFycmF5LkhFWDtcclxuXHJcbiAgY29uc3RydWN0b3IoIHZhbHVlOiBzdHJpbmcgfCBCeXRlU3RyaW5nIHwgQnl0ZUFycmF5LCBlbmNvZGluZz86IG51bWJlciApXHJcbiAge1xyXG4gICAgaWYgKCAhZW5jb2RpbmcgKVxyXG4gICAge1xyXG4gICAgICBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZVN0cmluZyApXHJcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5ieXRlQXJyYXkuY2xvbmUoKTtcclxuICAgICAgZWxzZSBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcclxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IHZhbHVlLmNsb25lKCk7XHJcbi8vICAgICAgZWxzZVxyXG4vLyAgICAgICAgc3VwZXIoIFVpbnQ4QXJyYXkoIHZhbHVlICkgKTtcclxuICAgIH1cclxuICAgIGVsc2VcclxuICAgIHtcclxuICAgICAgc3dpdGNoKCBlbmNvZGluZyApXHJcbiAgICAgIHtcclxuICAgICAgICBjYXNlIEJ5dGVTdHJpbmcuSEVYOlxyXG4gICAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCA8c3RyaW5nPnZhbHVlLCBCeXRlQXJyYXkuSEVYICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgIHRocm93IFwiQnl0ZVN0cmluZyB1bnN1cHBvcnRlZCBlbmNvZGluZ1wiO1xyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBnZXQgbGVuZ3RoKCk6IG51bWJlclxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XHJcbiAgfVxyXG5cclxuICBieXRlcyggb2Zmc2V0OiBudW1iZXIsIGNvdW50PzogbnVtYmVyICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LnZpZXdBdCggb2Zmc2V0LCBjb3VudCApICk7XHJcbiAgfVxyXG5cclxuICBieXRlQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5ieXRlQXQoIG9mZnNldCApO1xyXG4gIH1cclxuXHJcbiAgZXF1YWxzKCBvdGhlckJ5dGVTdHJpbmc6IEJ5dGVTdHJpbmcgKVxyXG4gIHtcclxuLy8gICAgcmV0dXJuICEoIHRoaXMuX2J5dGVzIDwgb3RoZXJCeXRlU3RyaW5nLl9ieXRlcyApICYmICEoIHRoaXMuX2J5dGVzID4gb3RoZXJCeXRlU3RyaW5nLl9ieXRlcyApO1xyXG4gIH1cclxuXHJcbiAgY29uY2F0KCB2YWx1ZTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgdGhpcy5ieXRlQXJyYXkuY29uY2F0KCB2YWx1ZS5ieXRlQXJyYXkgKTtcclxuXHJcbiAgICByZXR1cm4gdGhpcztcclxuICB9XHJcblxyXG4gIGxlZnQoIGNvdW50OiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkudmlld0F0KCAwICkgKTtcclxuICB9XHJcblxyXG4gIHJpZ2h0KCBjb3VudDogbnVtYmVyICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LnZpZXdBdCggLWNvdW50ICkgKTtcclxuICB9XHJcblxyXG4gIG5vdCggKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkuY2xvbmUoKS5ub3QoKSApO1xyXG4gIH1cclxuXHJcbiAgYW5kKCB2YWx1ZTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS5jbG9uZSgpLmFuZCggdmFsdWUuYnl0ZUFycmF5KSApO1xyXG4gIH1cclxuXHJcbiAgb3IoIHZhbHVlOiBCeXRlU3RyaW5nICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LmNsb25lKCkub3IoIHZhbHVlLmJ5dGVBcnJheSkgKTtcclxuICB9XHJcblxyXG4gIHBhZCggbWV0aG9kOiBudW1iZXIsIG9wdGlvbmFsPzogYm9vbGVhbiApXHJcbiAge1xyXG4gICAgdmFyIGJzID0gbmV3IEJ5dGVCdWZmZXIoIHRoaXMuYnl0ZUFycmF5ICk7XHJcblxyXG4gICAgaWYgKCBvcHRpb25hbCA9PSB1bmRlZmluZWQgKVxyXG4gICAgICBvcHRpb25hbCA9IGZhbHNlO1xyXG5cclxuICAgIGlmICggKCAoIGJzLmxlbmd0aCAmIDcgKSAhPSAwICkgfHwgKCAhb3B0aW9uYWwgKSApXHJcbiAgICB7XHJcbiAgICAgIHZhciBuZXdsZW4gPSAoICggYnMubGVuZ3RoICsgOCApICYgfjcgKTtcclxuICAgICAgaWYgKCBtZXRob2QgPT0gQ3J5cHRvLklTTzk3OTdfTUVUSE9EXzEgKVxyXG4gICAgICAgIGJzLmFwcGVuZCggMHg4MCApO1xyXG5cclxuICAgICAgd2hpbGUoIGJzLmxlbmd0aCA8IG5ld2xlbiApXHJcbiAgICAgICAgYnMuYXBwZW5kKCAweDAwICk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGJzLnRvQnl0ZVN0cmluZygpO1xyXG4gIH1cclxuXHJcbiAgdG9TdHJpbmcoIGVuY29kaW5nPzogbnVtYmVyICk6IHN0cmluZ1xyXG4gIHtcclxuICAgIC8vVE9ETzogZW5jb2RpbmcgLi4uXHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkudG9TdHJpbmcoIEJ5dGVBcnJheS5IRVggKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBIRVggPSBCeXRlU3RyaW5nLkhFWDtcclxuLy9leHBvcnQgY29uc3QgQVNDSUkgPSBCeXRlU3RyaW5nLkFTQ0lJO1xyXG5leHBvcnQgY29uc3QgQkFTRTY0ID0gQnl0ZVN0cmluZy5CQVNFNjQ7XHJcbi8vZXhwb3J0IGNvbnN0IFVURjggPSBCeXRlU3RyaW5nLlVURjg7XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5pbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XHJcblxyXG5leHBvcnQgY2xhc3MgQnl0ZUJ1ZmZlclxyXG57XHJcbiAgYnl0ZUFycmF5OiBCeXRlQXJyYXk7XHJcblxyXG4gIGNvbnN0cnVjdG9yICggdmFsdWU/LCBlbmNvZGluZz8gKVxyXG4gIHtcclxuICAgIGlmICggdmFsdWUgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKVxyXG4gICAge1xyXG4gICAgICB0aGlzLmJ5dGVBcnJheSA9IHZhbHVlO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZVN0cmluZyApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZXM7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggZW5jb2RpbmcgIT0gdW5kZWZpbmVkIClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgQnl0ZVN0cmluZyggdmFsdWUsIGVuY29kaW5nICkuYnl0ZUFycmF5O1xyXG4gICAgfVxyXG4gICAgZWxzZVxyXG4gICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcbiAgfVxyXG5cclxuICBnZXQgbGVuZ3RoKClcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xyXG4gIH1cclxuXHJcbiAgdG9CeXRlU3RyaW5nKCk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5ICk7XHJcbiAgfVxyXG5cclxuICBjbGVhcigpXHJcbiAge1xyXG4gICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCBbXSApO1xyXG4gIH1cclxuXHJcbiAgYXBwZW5kKCB2YWx1ZTogQnl0ZVN0cmluZyB8IEJ5dGVCdWZmZXIgfCBudW1iZXIgKTogQnl0ZUJ1ZmZlclxyXG4gIHtcclxuICAgIGxldCB2YWx1ZUFycmF5OiBCeXRlQXJyYXk7XHJcblxyXG4gICAgaWYgKCAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZVN0cmluZyApIHx8ICggdmFsdWUgaW5zdGFuY2VvZiBCeXRlQnVmZmVyICkgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5O1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHR5cGVvZiB2YWx1ZSA9PSBcIm51bWJlclwiIClcclxuICAgIHtcclxuICAgICAgdmFsdWVBcnJheSA9IG5ldyBCeXRlQXJyYXkoIFsgKCA8bnVtYmVyPnZhbHVlICYgMHhmZiApIF0gKTtcclxuICAgIH1cclxuLyogICAgZWxzZSBpZiAoIHR5cGVvZiB2YWx1ZSA9PSBcInN0cmluZ1wiIClcclxuICAgIHtcclxuICAgICAgdmFsdWVBcnJheSA9IG5ldyBVaW50OEFycmF5KCB2YWx1ZS5sZW5ndGggKTtcclxuICAgICAgZm9yKCB2YXIgaSA9IDA7IGkgPCB2YWx1ZS5sZW5ndGg7ICsraSApXHJcbiAgICAgICAgdmFsdWVBcnJheVtpXSA9IHZhbHVlLmNoYXJBdCggaSApO1xyXG4gICAgfSovXHJcbi8vICAgIGVsc2VcclxuLy8gICAgICB2YWx1ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggdmFsdWUgKTtcclxuXHJcbiAgICB0aGlzLmJ5dGVBcnJheS5jb25jYXQoIHZhbHVlQXJyYXkgKTtcclxuXHJcbiAgICByZXR1cm4gdGhpcztcclxuICB9XHJcbn1cclxuIiwiaW1wb3J0IHsgQmFzZVRMViBhcyBCYXNlVExWIH0gZnJvbSAnLi4vYmFzZS9iYXNlLXRsdic7XHJcbmltcG9ydCB7IEJ5dGVTdHJpbmcgfSBmcm9tICcuL2J5dGUtc3RyaW5nJztcclxuaW1wb3J0IHsgQnl0ZUJ1ZmZlciB9IGZyb20gJy4vYnl0ZS1idWZmZXInO1xyXG5cclxuZXhwb3J0IGNsYXNzIFRMVlxyXG57XHJcbiAgdGx2OiBCYXNlVExWO1xyXG4gIGVuY29kaW5nOiBudW1iZXI7XHJcblxyXG4gIGNvbnN0cnVjdG9yICggdGFnOiBudW1iZXIsIHZhbHVlOiBCeXRlU3RyaW5nLCBlbmNvZGluZzogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLnRsdiA9IG5ldyBCYXNlVExWKCB0YWcsIHZhbHVlLmJ5dGVBcnJheSwgZW5jb2RpbmcgKTtcclxuXHJcbiAgICB0aGlzLmVuY29kaW5nID0gZW5jb2Rpbmc7XHJcbiAgfVxyXG5cclxuICBnZXRUTFYoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy50bHYuYnl0ZUFycmF5ICk7XHJcbiAgfVxyXG5cclxuICBnZXRUYWcoKTogbnVtYmVyXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMudGx2LnRhZztcclxuICB9XHJcblxyXG4gIGdldFZhbHVlKCk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMudGx2LnZhbHVlICk7XHJcbiAgfVxyXG5cclxuICBnZXRMKCk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICB2YXIgaW5mbyA9IEJhc2VUTFYucGFyc2VUTFYoIHRoaXMudGx2LmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApO1xyXG5cclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy50bHYuYnl0ZUFycmF5LnZpZXdBdCggaW5mby5sZW5PZmZzZXQsIGluZm8udmFsdWVPZmZzZXQgKSApO1xyXG4gIH1cclxuXHJcbiAgZ2V0TFYoKVxyXG4gIHtcclxuICAgIHZhciBpbmZvID0gQmFzZVRMVi5wYXJzZVRMViggdGhpcy50bHYuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkudmlld0F0KCBpbmZvLmxlbk9mZnNldCwgaW5mby52YWx1ZU9mZnNldCArIGluZm8ubGVuICkgKTtcclxuICB9XHJcblxyXG4gIHN0YXRpYyBwYXJzZVRMViggYnVmZmVyOiBCeXRlU3RyaW5nLCBlbmNvZGluZzogbnVtYmVyICk6IHsgdGFnOiBudW1iZXIsIGxlbjogbnVtYmVyLCB2YWx1ZTogQnl0ZVN0cmluZywgbGVuT2Zmc2V0OiBudW1iZXIsIHZhbHVlT2Zmc2V0OiBudW1iZXIgfVxyXG4gIHtcclxuICAgIGxldCBpbmZvID0gQmFzZVRMVi5wYXJzZVRMViggYnVmZmVyLmJ5dGVBcnJheSwgZW5jb2RpbmcgKTtcclxuXHJcbiAgICByZXR1cm4ge1xyXG4gICAgICB0YWc6IGluZm8udGFnLFxyXG4gICAgICBsZW46IGluZm8ubGVuLFxyXG4gICAgICB2YWx1ZTogbmV3IEJ5dGVTdHJpbmcoIGluZm8udmFsdWUgKSxcclxuICAgICAgbGVuT2Zmc2V0OiBpbmZvLmxlbk9mZnNldCxcclxuICAgICAgdmFsdWVPZmZzZXQ6IGluZm8udmFsdWVPZmZzZXRcclxuICAgIH07XHJcbiAgfVxyXG5cclxuICBzdGF0aWMgRU1WID0gQmFzZVRMVi5FbmNvZGluZ3MuRU1WO1xyXG4gIHN0YXRpYyBER0kgPSBCYXNlVExWLkVuY29kaW5ncy5ER0k7XHJcbi8vICBzdGF0aWMgTDE2ID0gQmFzZVRMVi5MMTY7XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5pbXBvcnQgeyBUTFYgfSBmcm9tICcuL3Rsdic7XHJcblxyXG5leHBvcnQgY2xhc3MgVExWTGlzdFxyXG57XHJcbiAgX3RsdnM6IFRMVltdO1xyXG5cclxuICBjb25zdHJ1Y3RvciggdGx2U3RyZWFtOiBCeXRlU3RyaW5nLCBlbmNvZGluZz86IG51bWJlciApXHJcbiAge1xyXG4gICAgdGhpcy5fdGx2cyA9IFtdO1xyXG5cclxuICAgIHZhciBvZmYgPSAwO1xyXG5cclxuICAgIHdoaWxlKCBvZmYgPCB0bHZTdHJlYW0ubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdmFyIHRsdkluZm8gPSBUTFYucGFyc2VUTFYoIHRsdlN0cmVhbS5ieXRlcyggb2ZmICksIGVuY29kaW5nIClcclxuXHJcbiAgICAgIGlmICggdGx2SW5mbyA9PSBudWxsIClcclxuICAgICAge1xyXG4gICAgICAgIC8vIGVycm9yIC4uLlxyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIC8vIG5vIG1vcmUgLi4uID9cclxuICAgICAgICBpZiAoIHRsdkluZm8udmFsdWVPZmZzZXQgPT0gMCApXHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgdGhpcy5fdGx2cy5wdXNoKCBuZXcgVExWKCB0bHZJbmZvLnRhZywgdGx2SW5mby52YWx1ZSwgZW5jb2RpbmcgKSApO1xyXG4gICAgICAgIG9mZiArPSB0bHZJbmZvLnZhbHVlT2Zmc2V0ICsgdGx2SW5mby5sZW47XHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGluZGV4KCBpbmRleDogbnVtYmVyICk6IFRMVlxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLl90bHZzWyBpbmRleCBdO1xyXG4gIH1cclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbmNsYXNzIEpTU2ltdWxhdGVkU2xvdFxyXG57XHJcbiAgY2FyZFdvcmtlcjtcclxuICBvbkFQRFVSZXNwb25zZTtcclxuICBzdG9wO1xyXG5cclxuICBPbk1lc3NhZ2UoZSlcclxuICB7XHJcbiAgICBpZiAodGhpcy5zdG9wKSByZXR1cm47XHJcblxyXG4gICAgaWYgKGUuZGF0YS5jb21tYW5kID09IFwiZGVidWdcIilcclxuICAgIHtcclxuICAgICAgY29uc29sZS5sb2coZS5kYXRhLmRhdGEpO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoZS5kYXRhLmNvbW1hbmQgPT0gXCJleGVjdXRlQVBEVVwiKVxyXG4gICAge1xyXG4gICAgICAvLyBjb25zb2xlLmxvZyggbmV3IEJ5dGVTdHJpbmcoIGUuZGF0YS5kYXRhICkudG9TdHJpbmcoKSApO1xyXG5cclxuICAgICAgaWYgKCB0aGlzLm9uQVBEVVJlc3BvbnNlIClcclxuICAgICAge1xyXG4gICAgICAgIHZhciBicyA9IDxVaW50OEFycmF5PmUuZGF0YS5kYXRhLCBsZW4gPSBicy5sZW5ndGg7XHJcblxyXG4gICAgICAgIHRoaXMub25BUERVUmVzcG9uc2UoICggYnNbIGxlbiAtIDIgXSA8PCA4ICkgfCBic1sgbGVuIC0gMSBdLCAoIGxlbiA+IDIgKSA/IG5ldyBCeXRlQXJyYXkoIGJzLnN1YmFycmF5KCAwLCBsZW4tMiApICkgOiBudWxsICk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIGVsc2VcclxuICAgIHtcclxuICAgICAgY29uc29sZS5sb2coIFwiY21kOiBcIiArIGUuZGF0YS5jb21tYW5kICsgXCIgZGF0YTogXCIgKyBlLmRhdGEuZGF0YSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgaW5pdCgpXHJcbiAge1xyXG4gICAgdGhpcy5jYXJkV29ya2VyID0gbmV3IFdvcmtlciggXCJqcy9TbWFydENhcmRTbG90U2ltdWxhdG9yL1NtYXJ0Q2FyZFNsb3RXb3JrZXIuanNcIiApO1xyXG4gICAgdGhpcy5jYXJkV29ya2VyLm9ubWVzc2FnZSA9IHRoaXMuT25NZXNzYWdlLmJpbmQoIHRoaXMgKTtcclxuXHJcbiAgICB0aGlzLmNhcmRXb3JrZXIub25lcnJvciA9IGZ1bmN0aW9uKGU6IEV2ZW50KVxyXG4gICAge1xyXG4gICAgICAvL2FsZXJ0KCBcIkVycm9yIGF0IFwiICsgZS5maWxlbmFtZSArIFwiOlwiICsgZS5saW5lbm8gKyBcIjogXCIgKyBlLm1lc3NhZ2UgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHNlbmRUb1dvcmtlciggY29tbWFuZCwgZGF0YSApXHJcbiAge1xyXG4gICAgdGhpcy5jYXJkV29ya2VyLnBvc3RNZXNzYWdlKFxyXG4gICAgICB7XHJcbiAgICAgICAgXCJjb21tYW5kXCI6IGNvbW1hbmQsXHJcbiAgICAgICAgXCJkYXRhXCI6IGRhdGFcclxuICAgICAgfVxyXG4gICAgKTtcclxuICB9XHJcblxyXG4gIGV4ZWN1dGVBUERVQ29tbWFuZCggYkNMQSwgYklOUywgYlAxLCBiUDIsIGNvbW1hbmREYXRhLCB3TGUsIG9uQVBEVVJlc3BvbnNlIClcclxuICB7XHJcbiAgICB2YXIgY21kID0gWyBiQ0xBLCBiSU5TLCBiUDEsIGJQMiBdO1xyXG4gICAgdmFyIGxlbiA9IDQ7XHJcbiAgICB2YXIgYnNDb21tYW5kRGF0YSA9ICggY29tbWFuZERhdGEgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKSA/IGNvbW1hbmREYXRhIDogbmV3IEJ5dGVBcnJheSggY29tbWFuZERhdGEsIEJ5dGVBcnJheS5IRVggKTtcclxuICAgIGlmICggYnNDb21tYW5kRGF0YS5sZW5ndGggPiAwIClcclxuICAgIHtcclxuICAgICAgY21kW2xlbisrXSA9IGJzQ29tbWFuZERhdGEubGVuZ3RoO1xyXG4gICAgICBmb3IoIHZhciBpID0gMDsgaSA8IGJzQ29tbWFuZERhdGEubGVuZ3RoOyArK2kgKVxyXG4gICAgICAgIGNtZFtsZW4rK10gPSBic0NvbW1hbmREYXRhLmJ5dGVBdCggaSApO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHdMZSAhPSB1bmRlZmluZWQgKVxyXG4gICAgICAgIGNtZFtsZW4rK10gPSB3TGUgJiAweEZGO1xyXG5cclxuICAgIHRoaXMuc2VuZFRvV29ya2VyKCBcImV4ZWN1dGVBUERVXCIsIGNtZCApO1xyXG5cclxuICAgIHRoaXMub25BUERVUmVzcG9uc2UgPSBvbkFQRFVSZXNwb25zZTtcclxuXHJcbiAgICAvLyBvbiBzdWNjZXNzL2ZhaWx1cmUsIHdpbGwgY2FsbGJhY2tcclxuICAgIC8vIGlmICggcmVzcCA9PSBudWxsIClcclxuICAgIHJldHVybjtcclxuICB9XHJcbn1cclxuIixudWxsLCJpbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi4vYmFzZS9JU083ODE2JztcclxuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9iYXNlL2NvbW1hbmQtYXBkdSc7XHJcbmltcG9ydCB7IFJlc3BvbnNlQVBEVSB9IGZyb20gJy4uL2Jhc2UvcmVzcG9uc2UtYXBkdSc7XHJcblxyXG5leHBvcnQgY2xhc3MgSlNJTVNjcmlwdEFwcGxldFxyXG57XHJcbiAgc2VsZWN0QXBwbGljYXRpb24oIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cclxuICB7XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4OTAwMCB9ICkgKTtcclxuICB9XHJcblxyXG4gIGRlc2VsZWN0QXBwbGljYXRpb24oKVxyXG4gIHtcclxuICB9XHJcblxyXG4gIGV4ZWN1dGVBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XHJcbiAge1xyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxSZXNwb25zZUFQRFU+KCBuZXcgUmVzcG9uc2VBUERVKCB7IHN3OiAweDZEMDAgfSApICk7XHJcbiAgfVxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi4vYmFzZS9JU083ODE2JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vYmFzZS9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vYmFzZS9yZXNwb25zZS1hcGR1JztcblxuaW1wb3J0IHsgSlNJTUNhcmQgfSBmcm9tICcuL2pzaW0tY2FyZCc7XG5pbXBvcnQgeyBKU0lNU2NyaXB0QXBwbGV0IH0gZnJvbSAnLi9qc2ltLXNjcmlwdC1hcHBsZXQnO1xuXG5leHBvcnQgY2xhc3MgSlNJTVNjcmlwdENhcmQgaW1wbGVtZW50cyBKU0lNQ2FyZFxue1xuICBwcml2YXRlIHBvd2VySXNPbjogYm9vbGVhbjtcbiAgcHJpdmF0ZSBhdHI6IEJ5dGVBcnJheTtcblxuICBhcHBsZXRzOiB7IGFpZDogQnl0ZUFycmF5LCBhcHBsZXQ6IEpTSU1TY3JpcHRBcHBsZXQgfVtdO1xuXG4gIHNlbGVjdGVkQXBwbGV0OiBKU0lNU2NyaXB0QXBwbGV0O1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMuYXRyID0gbmV3IEJ5dGVBcnJheSggW10gKTtcbiAgfVxuXG4gIGxvYWRBcHBsaWNhdGlvbiggYWlkOiBCeXRlQXJyYXksIGFwcGxldDogSlNJTVNjcmlwdEFwcGxldCApXG4gIHtcbiAgICB0aGlzLmFwcGxldHMucHVzaCggeyBhaWQ6IGFpZCwgYXBwbGV0OiBhcHBsZXQgfSApO1xuICB9XG5cbiAgZ2V0IGlzUG93ZXJlZCgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5wb3dlcklzT247XG4gIH1cblxuICBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgdGhpcy5wb3dlcklzT24gPSB0cnVlO1xuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxCeXRlQXJyYXk+KCB0aGlzLmF0ciApO1xuICB9XG5cbiAgcG93ZXJPZmYoKTogUHJvbWlzZTxhbnk+XG4gIHtcbiAgICB0aGlzLnBvd2VySXNPbiA9IGZhbHNlO1xuXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcblxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgfVxuXG4gIHJlc2V0KCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgdGhpcy5wb3dlcklzT24gPSB0cnVlO1xuXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcblxuICAgIC8vIFRPRE86IFJlc2V0XG5cbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPEJ5dGVBcnJheT4oIHRoaXMuYXRyICk7XG4gIH1cblxuICBleGNoYW5nZUFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cbiAge1xuICAgIGlmICggY29tbWFuZEFQRFUuSU5TID09IDB4QTQgKVxuICAgIHtcbiAgICAgIGlmICggdGhpcy5zZWxlY3RlZEFwcGxldCApXG4gICAgICB7XG4gICAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQuZGVzZWxlY3RBcHBsaWNhdGlvbigpO1xuXG4gICAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XG4gICAgICB9XG5cbiAgICAgIC8vVE9ETzogTG9va3VwIEFwcGxpY2F0aW9uXG4gICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdGhpcy5hcHBsZXRzWyAwIF0uYXBwbGV0O1xuXG4gICAgICByZXR1cm4gdGhpcy5zZWxlY3RlZEFwcGxldC5zZWxlY3RBcHBsaWNhdGlvbiggY29tbWFuZEFQRFUgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zZWxlY3RlZEFwcGxldC5leGVjdXRlQVBEVSggY29tbWFuZEFQRFUgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmltcG9ydCB7IFNsb3QgfSBmcm9tICcuLi9iYXNlL3Nsb3QnO1xuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9iYXNlL2NvbW1hbmQtYXBkdSc7XG5pbXBvcnQgeyBSZXNwb25zZUFQRFUgfSBmcm9tICcuLi9iYXNlL3Jlc3BvbnNlLWFwZHUnO1xuaW1wb3J0IHsgSlNJTUNhcmQgfSBmcm9tICcuL2pzaW0tY2FyZCc7XG5cbmV4cG9ydCBjbGFzcyBKU0lNU2xvdCBpbXBsZW1lbnRzIFNsb3RcbntcbiAgcHVibGljIGNhcmQ6IEpTSU1DYXJkO1xuXG4gIGNvbnN0cnVjdG9yKCBjYXJkPzogSlNJTUNhcmQgKVxuICB7XG4gICAgdGhpcy5jYXJkID0gY2FyZDtcbiAgfVxuXG4gIGdldCBpc1ByZXNlbnQoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuICEhdGhpcy5jYXJkO1xuICB9XG5cbiAgZ2V0IGlzUG93ZXJlZCgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5pc1ByZXNlbnQgJiYgdGhpcy5jYXJkLmlzUG93ZXJlZDtcbiAgfVxuXG4gIHBvd2VyT24oKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICBpZiAoICF0aGlzLmlzUHJlc2VudCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgbm90IHByZXNlbnRcIiApICk7XG5cbiAgICByZXR1cm4gdGhpcy5jYXJkLnBvd2VyT24oKTtcbiAgfVxuXG4gIHBvd2VyT2ZmKCk6IFByb21pc2U8Ym9vbGVhbj5cbiAge1xuICAgIGlmICggIXRoaXMuaXNQcmVzZW50IClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxib29sZWFuPiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgbm90IHByZXNlbnRcIiApICk7XG5cbiAgICByZXR1cm4gdGhpcy5jYXJkLnBvd2VyT2ZmKCk7XG4gIH1cblxuICByZXNldCgpOiBQcm9taXNlPEJ5dGVBcnJheT5cbiAge1xuICAgIGlmICggIXRoaXMuaXNQcmVzZW50IClcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBuZXcgRXJyb3IoIFwiSlNJTTogQ2FyZCBub3QgcHJlc2VudFwiICkgKTtcblxuICAgIHJldHVybiB0aGlzLmNhcmQucmVzZXQoKTtcbiAgfVxuXG4gIGV4ZWN1dGVBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XG4gIHtcbiAgICBpZiAoICF0aGlzLmlzUHJlc2VudCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8UmVzcG9uc2VBUERVPiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgbm90IHByZXNlbnRcIiApICk7XG5cbiAgICBpZiAoICF0aGlzLmlzUG93ZXJlZCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8UmVzcG9uc2VBUERVPiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgdW5wb3dlcmVkXCIgKSApO1xuXG4gICAgcmV0dXJuIHRoaXMuY2FyZC5leGNoYW5nZUFQRFUoIGNvbW1hbmRBUERVICk7XG4gIH1cblxuICBpbnNlcnRDYXJkKCBjYXJkOiBKU0lNQ2FyZCApXG4gIHtcbiAgICBpZiAoIHRoaXMuY2FyZCApXG4gICAgICB0aGlzLmVqZWN0Q2FyZCgpO1xuXG4gICAgdGhpcy5jYXJkID0gY2FyZDtcbiAgfVxuXG4gIGVqZWN0Q2FyZCgpXG4gIHtcbiAgICBpZiAoIHRoaXMuY2FyZCApXG4gICAge1xuICAgICAgaWYgKCB0aGlzLmNhcmQuaXNQb3dlcmVkIClcbiAgICAgICAgdGhpcy5jYXJkLnBvd2VyT2ZmKCk7XG5cbiAgICAgIHRoaXMuY2FyZCA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGhleDIoIHZhbCApIHsgcmV0dXJuICggXCIwMFwiICsgdmFsLnRvU3RyaW5nKCAxNiApLnRvVXBwZXJDYXNlKCkgKS5zdWJzdHIoIC0yICk7IH1cclxuZXhwb3J0IGZ1bmN0aW9uIGhleDQoIHZhbCApIHsgcmV0dXJuICggXCIwMDAwXCIgKyB2YWwudG9TdHJpbmcoIDE2ICkudG9VcHBlckNhc2UoKSApLnN1YnN0ciggLTQgKTsgfVxyXG5cclxuZXhwb3J0IGVudW0gTUVNRkxBR1Mge1xyXG4gIFJFQURfT05MWSA9IDEgPDwgMCxcclxuICBUUkFOU0FDVElPTkFCTEUgPSAxIDw8IDEsXHJcbiAgVFJBQ0UgPSAxIDw8IDJcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIFNlZ21lbnRcclxue1xyXG4gIHByaXZhdGUgbWVtRGF0YTogQnl0ZUFycmF5O1xyXG4gIHByaXZhdGUgbWVtVHlwZTtcclxuICBwcml2YXRlIHJlYWRPbmx5O1xyXG4gIHByaXZhdGUgZmxhZ3M7XHJcbiAgcHJpdmF0ZSBpblRyYW5zYWN0aW9uID0gZmFsc2U7XHJcbiAgcHJpdmF0ZSB0cmFuc0Jsb2NrcyA9IFtdO1xyXG4gIG1lbVRyYWNlcztcclxuXHJcbiAgY29uc3RydWN0b3IoIHNlZ1R5cGUsIHNpemUsIGZsYWdzPywgYmFzZT86IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgdGhpcy5tZW1UeXBlID0gc2VnVHlwZTtcclxuICAgIHRoaXMucmVhZE9ubHkgPSAoIGZsYWdzICYgTUVNRkxBR1MuUkVBRF9PTkxZICkgPyB0cnVlIDogZmFsc2U7XHJcblxyXG4gICAgaWYgKCBiYXNlIClcclxuICAgIHtcclxuICAgICAgdGhpcy5tZW1EYXRhID0gbmV3IEJ5dGVBcnJheSggYmFzZSApXHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICB7XHJcbiAgICAgIHRoaXMubWVtRGF0YSA9IG5ldyBCeXRlQXJyYXkoIFtdICkuc2V0TGVuZ3RoKCBzaXplICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBnZXRUeXBlKCkgeyByZXR1cm4gdGhpcy5tZW1UeXBlOyB9XHJcbiAgZ2V0TGVuZ3RoKCkgeyByZXR1cm4gdGhpcy5tZW1EYXRhLmxlbmd0aDsgfVxyXG4gIGdldEZsYWdzKCkgeyByZXR1cm4gdGhpcy5mbGFnczsgfVxyXG4gIGdldERlYnVnKCkgeyByZXR1cm4geyBtZW1EYXRhOiB0aGlzLm1lbURhdGEsIG1lbVR5cGU6IHRoaXMubWVtVHlwZSwgcmVhZE9ubHk6IHRoaXMucmVhZE9ubHksIGluVHJhbnNhY3Rpb246IHRoaXMuaW5UcmFuc2FjdGlvbiwgdHJhbnNCbG9ja3M6IHRoaXMudHJhbnNCbG9ja3MgfTsgfVxyXG5cclxuICBiZWdpblRyYW5zYWN0aW9uKClcclxuICB7XHJcbiAgICB0aGlzLmluVHJhbnNhY3Rpb24gPSB0cnVlO1xyXG4gICAgdGhpcy50cmFuc0Jsb2NrcyA9IFtdO1xyXG4gIH1cclxuXHJcbiAgZW5kVHJhbnNhY3Rpb24oIGNvbW1pdCApXHJcbiAge1xyXG4gICAgaWYgKCAhY29tbWl0ICYmIHRoaXMuaW5UcmFuc2FjdGlvbiApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMuaW5UcmFuc2FjdGlvbiA9IGZhbHNlO1xyXG5cclxuICAgICAgLy8gcm9sbGJhY2sgdHJhbnNhY3Rpb25zXHJcbiAgICAgIGZvciggdmFyIGk9MDsgaSA8IHRoaXMudHJhbnNCbG9ja3MubGVuZ3RoOyBpKysgKVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIGJsb2NrID0gdGhpcy50cmFuc0Jsb2Nrc1sgaSBdO1xyXG5cclxuICAgICAgICB0aGlzLndyaXRlQnl0ZXMoIGJsb2NrLmFkZHIsIGJsb2NrLmRhdGEgKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhbnNCbG9ja3MgPSBbXTtcclxuICB9XHJcblxyXG4gIHJlYWRCeXRlKCBhZGRyIClcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5tZW1EYXRhWyBhZGRyIF07XHJcbiAgfVxyXG5cclxuICB6ZXJvQnl0ZXMoIGFkZHIsIGxlbiApXHJcbiAge1xyXG4gICAgZm9yKCB2YXIgaSA9IDA7IGkgPCBsZW47ICsraSApXHJcbiAgICAgIHRoaXMubWVtRGF0YVsgYWRkciArIGkgXSA9IDA7XHJcbiAgfVxyXG5cclxuICByZWFkQnl0ZXMoIGFkZHIsIGxlbiApOiBCeXRlQXJyYXlcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5tZW1EYXRhLnZpZXdBdCggYWRkciwgbGVuICk7XHJcbiAgfVxyXG5cclxuICBjb3B5Qnl0ZXMoIGZyb21BZGRyLCB0b0FkZHIsIGxlbiApXHJcbiAge1xyXG4gICAgdGhpcy53cml0ZUJ5dGVzKCB0b0FkZHIsIHRoaXMucmVhZEJ5dGVzKCBmcm9tQWRkciwgbGVuICkgKTtcclxuICB9XHJcblxyXG4gIHdyaXRlQnl0ZXMoIGFkZHI6IG51bWJlciwgdmFsOiBCeXRlQXJyYXkgKVxyXG4gIHtcclxuICAgIGlmICggdGhpcy5pblRyYW5zYWN0aW9uICYmICggdGhpcy5mbGFncyAmIE1FTUZMQUdTLlRSQU5TQUNUSU9OQUJMRSApIClcclxuICAgIHtcclxuICAgICAgLy8gc2F2ZSBwcmV2aW91cyBFRVBST00gY29udGVudHNcclxuICAgICAgdGhpcy50cmFuc0Jsb2Nrcy5wdXNoKCB7IGFkZHI6IGFkZHIsIGRhdGE6IHRoaXMucmVhZEJ5dGVzKCBhZGRyLCB2YWwubGVuZ3RoICkgfSApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMubWVtRGF0YS5zZXRCeXRlc0F0KCBhZGRyLCB2YWwgKTtcclxuICB9XHJcblxyXG4gIG5ld0FjY2Vzc29yKCBhZGRyLCBsZW4sIG5hbWUgKTogQWNjZXNzb3JcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEFjY2Vzc29yKCB0aGlzLCBhZGRyLCBsZW4sIG5hbWUgKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBBY2Nlc3NvclxyXG57XHJcbiAgb2Zmc2V0OiBudW1iZXI7XHJcbiAgbGVuZ3RoOiBudW1iZXI7XHJcbiAgaWQ6IHN0cmluZztcclxuICBzZWc6IFNlZ21lbnQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCBzZWcsIGFkZHIsIGxlbiwgbmFtZSApXHJcbiAge1xyXG4gICAgdGhpcy5zZWcgPSBzZWc7XHJcblxyXG4gICAgdGhpcy5vZmZzZXQgPSBhZGRyO1xyXG4gICAgdGhpcy5sZW5ndGggPSBsZW47XHJcbiAgICB0aGlzLmlkID0gbmFtZTtcclxuICB9XHJcblxyXG4gIHRyYWNlTWVtb3J5T3AoIG9wLCBhZGRyLCBsZW4sIGFkZHIyPyApXHJcbiAge1xyXG4gICAgaWYgKCB0aGlzLmlkICE9IFwiY29kZVwiIClcclxuICAgICAgdGhpcy5zZWcubWVtVHJhY2VzLnB1c2goIHsgb3A6IG9wLCBuYW1lOiB0aGlzLmlkLCBhZGRyOiBhZGRyLCBsZW46IGxlbiwgYWRkcjI6IGFkZHIyIH0gKTtcclxuICB9XHJcblxyXG4gIHRyYWNlTWVtb3J5VmFsdWUoIHZhbCApXHJcbiAge1xyXG4gICAgaWYgKCB0aGlzLmlkICE9IFwiY29kZVwiIClcclxuICAgIHtcclxuICAgICAgdmFyIG1lbVRyYWNlID0gdGhpcy5zZWcubWVtVHJhY2VzWyB0aGlzLnNlZy5tZW1UcmFjZXMubGVuZ3RoIC0gMSBdO1xyXG5cclxuICAgICAgbWVtVHJhY2UudmFsID0gdmFsO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgemVyb0J5dGVzKCBhZGRyOiBudW1iZXIsIGxlbjogbnVtYmVyIClcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyBsZW4gPiB0aGlzLmxlbmd0aCApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJaUi1lcnJvclwiLCBhZGRyLCB0aGlzLmxlbmd0aCApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgWmVyb1wiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlpSXCIsIGFkZHIsIGxlbiApO1xyXG4gICAgdGhpcy5zZWcuemVyb0J5dGVzKCB0aGlzLm9mZnNldCArIGFkZHIsIGxlbiApO1xyXG4gICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCBbIDAgXSApO1xyXG4gIH1cclxuXHJcbiAgcmVhZEJ5dGUoIGFkZHI6IG51bWJlciApOiBudW1iZXJcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyAxID4gdGhpcy5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiUkQtZXJyb3JcIiwgYWRkciwgMSApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgUmVhZFwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJEXCIsIGFkZHIsIDEgKTtcclxuXHJcbiAgICB2YXIgdmFsID0gdGhpcy5zZWcucmVhZEJ5dGUoIHRoaXMub2Zmc2V0ICsgYWRkciApO1xyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggWyB2YWwgXSk7XHJcblxyXG4gICAgcmV0dXJuIHZhbDtcclxuICB9XHJcblxyXG4gIHJlYWRCeXRlcyggYWRkciwgbGVuICk6IEJ5dGVBcnJheVxyXG4gIHtcclxuICAgIGlmICggYWRkciArIGxlbiA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJELWVycm9yXCIsIGFkZHIsIGxlbiApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgUmVhZFwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJEXCIsIGFkZHIsIGxlbiApO1xyXG4gICAgdmFyIHZhbCA9IHRoaXMuc2VnLnJlYWRCeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCBsZW4gKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggdmFsICk7XHJcblxyXG4gICAgcmV0dXJuIHZhbDtcclxuICB9XHJcblxyXG4gIGNvcHlCeXRlcyggZnJvbUFkZHI6IG51bWJlciwgdG9BZGRyOiBudW1iZXIsIGxlbjogbnVtYmVyICk6IEJ5dGVBcnJheVxyXG4gIHtcclxuICAgIGlmICggKCBmcm9tQWRkciArIGxlbiA+IHRoaXMubGVuZ3RoICkgfHwgKCB0b0FkZHIgKyBsZW4gPiB0aGlzLmxlbmd0aCApIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIkNQLWVycm9yXCIsIGZyb21BZGRyLCBsZW4sIHRvQWRkciApO1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiTU06IEludmFsaWQgUmVhZFwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgLy9pZiAoIG1lbVRyYWNpbmcgKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiQ1BcIiwgZnJvbUFkZHIsIGxlbiwgdG9BZGRyICk7XHJcbiAgICAgIHZhciB2YWwgPSB0aGlzLnNlZy5yZWFkQnl0ZXMoIHRoaXMub2Zmc2V0ICsgZnJvbUFkZHIsIGxlbiApO1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIHZhbCApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc2VnLmNvcHlCeXRlcyggdGhpcy5vZmZzZXQgKyBmcm9tQWRkciwgdGhpcy5vZmZzZXQgKyB0b0FkZHIsIGxlbiApO1xyXG4gICAgcmV0dXJuIHZhbDtcclxuICB9XHJcblxyXG4gIHdyaXRlQnl0ZSggYWRkcjogbnVtYmVyLCB2YWw6IG51bWJlciApXHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgMSA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIldSLWVycm9yXCIsIGFkZHIsIDEgKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFdyaXRlXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiV1JcIiwgYWRkciwgMSApO1xyXG4gICAgdGhpcy5zZWcud3JpdGVCeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCBuZXcgQnl0ZUFycmF5KCBbIHZhbCBdICkgKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggWyB2YWwgXSApO1xyXG4gIH1cclxuXHJcbiAgd3JpdGVCeXRlcyggYWRkcjogbnVtYmVyLCB2YWw6IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgdmFsLmxlbmd0aCA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIldSLWVycm9yXCIsIGFkZHIsIHZhbC5sZW5ndGggKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFdyaXRlXCIgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiV1JcIiwgYWRkciwgdmFsLmxlbmd0aCApO1xyXG4gICAgdGhpcy5zZWcud3JpdGVCeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCB2YWwgKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggdmFsICk7XHJcbiAgfVxyXG5cclxuICBnZXRUeXBlKCkgeyByZXR1cm4gdGhpcy5zZWcuZ2V0VHlwZSgpOyB9XHJcbiAgZ2V0TGVuZ3RoKCkgeyByZXR1cm4gdGhpcy5sZW5ndGg7IH1cclxuICBnZXRJRCgpIHsgcmV0dXJuIHRoaXMuaWQ7IH1cclxuLy8gICAgICAgIGJlZ2luVHJhbnNhY3Rpb246IGJlZ2luVHJhbnNhY3Rpb24sXHJcbi8vICAgICAgICBpblRyYW5zYWN0aW9uOiBmdW5jdGlvbigpIHsgcmV0dXJuIGluVHJhbnNhY3Rpb247IH0sXHJcbi8vICAgICAgICBlbmRUcmFuc2FjdGlvbjogZW5kVHJhbnNhY3Rpb24sXHJcbiAgZ2V0RGVidWcoKSB7IHJldHVybiB7IG9mZnNldDogdGhpcy5vZmZzZXQsIGxlbmd0aDogdGhpcy5sZW5ndGgsIHNlZzogdGhpcy5zZWcgfTsgfVxyXG59XHJcblxyXG5mdW5jdGlvbiBzbGljZURhdGEoIGJhc2UsIG9mZnNldCwgc2l6ZSApOiBVaW50OEFycmF5XHJcbntcclxuICByZXR1cm4gYmFzZS5zdWJhcnJheSggb2Zmc2V0LCBvZmZzZXQgKyBzaXplICk7XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBNZW1vcnlNYW5hZ2VyXHJcbntcclxuICBwcml2YXRlIG1lbW9yeVNlZ21lbnRzID0gW107XHJcblxyXG4gIHByaXZhdGUgbWVtVHJhY2VzID0gW107XHJcblxyXG4gIG5ld1NlZ21lbnQoIG1lbVR5cGUsIHNpemUsIGZsYWdzPyAgKTogU2VnbWVudFxyXG4gIHtcclxuICAgIGxldCBuZXdTZWcgPSBuZXcgU2VnbWVudCggbWVtVHlwZSwgc2l6ZSwgZmxhZ3MgKTtcclxuXHJcbiAgICB0aGlzLm1lbW9yeVNlZ21lbnRzWyBtZW1UeXBlIF0gPSBuZXdTZWc7XHJcblxyXG4gICAgbmV3U2VnLm1lbVRyYWNlcyA9IHRoaXMubWVtVHJhY2VzO1xyXG5cclxuICAgIHJldHVybiBuZXdTZWc7XHJcbiAgfVxyXG5cclxuICBnZXRNZW1UcmFjZSgpIHsgcmV0dXJuIHRoaXMubWVtVHJhY2VzOyB9XHJcblxyXG4gIGluaXRNZW1UcmFjZSgpIHsgdGhpcy5tZW1UcmFjZXMgPSBbXTsgfVxyXG5cclxuICBnZXRTZWdtZW50KCB0eXBlICkgeyByZXR1cm4gdGhpcy5tZW1vcnlTZWdtZW50c1sgdHlwZSBdOyB9XHJcbn1cclxuIiwiZXhwb3J0IGVudW0gTUVMSU5TVCB7XHJcbiAgbWVsU1lTVEVNID0gIDB4MDAsXHJcbiAgbWVsQlJBTkNIID0gIDB4MDEsXHJcbiAgbWVsSlVNUCA9ICAgIDB4MDIsXHJcbiAgbWVsQ0FMTCA9ICAgIDB4MDMsXHJcbiAgbWVsU1RBQ0sgPSAgIDB4MDQsXHJcbiAgbWVsUFJJTVJFVCA9IDB4MDUsXHJcbiAgbWVsSU5WQUxJRCA9IDB4MDYsXHJcbiAgbWVsTE9BRCA9ICAgIDB4MDcsXHJcbiAgbWVsU1RPUkUgPSAgIDB4MDgsXHJcbiAgbWVsTE9BREkgPSAgIDB4MDksXHJcbiAgbWVsU1RPUkVJID0gIDB4MEEsXHJcbiAgbWVsTE9BREEgPSAgIDB4MEIsXHJcbiAgbWVsSU5ERVggPSAgIDB4MEMsXHJcbiAgbWVsU0VUQiA9ICAgIDB4MEQsXHJcbiAgbWVsQ01QQiA9ICAgIDB4MEUsXHJcbiAgbWVsQUREQiA9ICAgIDB4MEYsXHJcbiAgbWVsU1VCQiA9ICAgIDB4MTAsXHJcbiAgbWVsU0VUVyA9ICAgIDB4MTEsXHJcbiAgbWVsQ01QVyA9ICAgIDB4MTIsXHJcbiAgbWVsQUREVyA9ICAgIDB4MTMsXHJcbiAgbWVsU1VCVyA9ICAgIDB4MTQsXHJcbiAgbWVsQ0xFQVJOID0gIDB4MTUsXHJcbiAgbWVsVEVTVE4gPSAgIDB4MTYsXHJcbiAgbWVsSU5DTiA9ICAgIDB4MTcsXHJcbiAgbWVsREVDTiA9ICAgIDB4MTgsXHJcbiAgbWVsTk9UTiA9ICAgIDB4MTksXHJcbiAgbWVsQ01QTiA9ICAgIDB4MUEsXHJcbiAgbWVsQURETiA9ICAgIDB4MUIsXHJcbiAgbWVsU1VCTiA9ICAgIDB4MUMsXHJcbiAgbWVsQU5ETiA9ICAgIDB4MUQsXHJcbiAgbWVsT1JOID0gICAgIDB4MUUsXHJcbiAgbWVsWE9STiA9ICAgIDB4MUZcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFRBR0FERFIge1xyXG4gIG1lbEFkZHJUT1MgPSAweDAwLFxyXG4gIG1lbEFkZHJTQiA9ICAweDAxLFxyXG4gIG1lbEFkZHJTVCA9ICAweDAyLFxyXG4gIG1lbEFkZHJEQiA9ICAweDAzLFxyXG4gIG1lbEFkZHJMQiA9ICAweDA0LFxyXG4gIG1lbEFkZHJEVCA9ICAweDA1LFxyXG4gIG1lbEFkZHJQQiA9ICAweDA2LFxyXG4gIG1lbEFkZHJQVCA9ICAweDA3XHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxUQUdDT05EIHtcclxuICBtZWxDb25kU1BFQyA9ICAweDAwLCAvLyBTcGVjaWFsXHJcbiAgbWVsQ29uZEVRID0gICAgMHgwMSwgLy8gRXF1YWxcclxuICBtZWxDb25kTFQgPSAgICAweDAyLCAvLyBMZXNzIHRoYW5cclxuICBtZWxDb25kTEUgPSAgICAweDAzLCAvLyBMZXNzIHRoYW4sIGVxdWFsIHRvXHJcbiAgbWVsQ29uZEdUID0gICAgMHgwNCwgLy8gR3JlYXRlciB0aGFuXHJcbiAgbWVsQ29uZEdFID0gICAgMHgwNSwgLy8gR3JlYXRlciB0aGFuLCBlcXVhbCB0b1xyXG4gIG1lbENvbmRORSA9ICAgIDB4MDYsIC8vIE5vdCBlcXVhbCB0b1xyXG4gIG1lbENvbmRBTEwgPSAgIDB4MDcgIC8vIEFsd2F5c1xyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHU1lTVEVNIHtcclxuICBtZWxTeXN0ZW1OT1AgPSAgICAgICAweDAwLCAvLyBOT1BcclxuICBtZWxTeXN0ZW1TZXRTVyA9ICAgICAweDAxLCAvLyBTRVRTV1xyXG4gIG1lbFN5c3RlbVNldExhID0gICAgIDB4MDIsIC8vIFNFVExBXHJcbiAgbWVsU3lzdGVtU2V0U1dMYSA9ICAgMHgwMywgLy8gU0VUU1dMQVxyXG4gIG1lbFN5c3RlbUV4aXQgPSAgICAgIDB4MDQsIC8vIEVYSVRcclxuICBtZWxTeXN0ZW1FeGl0U1cgPSAgICAweDA1LCAvLyBFWElUU1dcclxuICBtZWxTeXN0ZW1FeGl0TGEgPSAgICAweDA2LCAvLyBFWElUTEFcclxuICBtZWxTeXN0ZW1FeGl0U1dMYSA9ICAweDA3ICAvLyBFWElUU1dMQVxyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHU1RBQ0sge1xyXG4gIG1lbFN0YWNrUFVTSFogPSAgMHgwMCwgLy8gUFVTSFpcclxuICBtZWxTdGFja1BVU0hCID0gIDB4MDEsIC8vIFBVU0hCXHJcbiAgbWVsU3RhY2tQVVNIVyA9ICAweDAyLCAvLyBQVVNIV1xyXG4gIG1lbFN0YWNrWFg0ID0gICAgMHgwMywgLy8gSWxsZWdhbFxyXG4gIG1lbFN0YWNrUE9QTiA9ICAgMHgwNCwgLy8gUE9QTlxyXG4gIG1lbFN0YWNrUE9QQiA9ICAgMHgwNSwgLy8gUE9QQlxyXG4gIG1lbFN0YWNrUE9QVyA9ICAgMHgwNiwgLy8gUE9QV1xyXG4gIG1lbFN0YWNrWFg3ID0gICAgMHgwNyAgLy8gSWxsZWdhbFxyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHUFJJTVJFVCB7XHJcbiAgbWVsUHJpbVJldFBSSU0wID0gIDB4MDAsIC8vIFBSSU0gMFxyXG4gIG1lbFByaW1SZXRQUklNMSA9ICAweDAxLCAvLyBQUklNIDFcclxuICBtZWxQcmltUmV0UFJJTTIgPSAgMHgwMiwgLy8gUFJJTSAyXHJcbiAgbWVsUHJpbVJldFBSSU0zID0gIDB4MDMsIC8vIFBSSU0gM1xyXG4gIG1lbFByaW1SZXRSRVQgPSAgICAweDA0LCAvLyBSRVRcclxuICBtZWxQcmltUmV0UkVUSSA9ICAgMHgwNSwgLy8gUkVUIEluXHJcbiAgbWVsUHJpbVJldFJFVE8gPSAgIDB4MDYsIC8vIFJFVCBPdXRcclxuICBtZWxQcmltUmV0UkVUSU8gPSAgMHgwNyAgLy8gUkVUIEluT3V0XHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxQQVJBTURFRiB7XHJcbiAgbWVsUGFyYW1EZWZOb25lID0gICAgICAgICAgICAgIDB4MDAsXHJcbiAgbWVsUGFyYW1EZWZUb3BPZlN0YWNrID0gICAgICAgIDB4MDEsXHJcbiAgbWVsUGFyYW1EZWZCeXRlT3BlckxlbiA9ICAgICAgIDB4MTEsXHJcbiAgbWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlID0gICAgIDB4MTIsXHJcbiAgbWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlID0gIDB4MTgsXHJcbiAgbWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlID0gICAgIDB4MjAsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0U0IgPSAgICAgIDB4MjEsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1QgPSAgICAgIDB4MjIsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0REIgPSAgICAgIDB4MjMsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0TEIgPSAgICAgIDB4MjQsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQgPSAgICAgIDB4MjUsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0UEIgPSAgICAgIDB4MjYsXHJcbiAgbWVsUGFyYW1EZWZXb3JkT2Zmc2V0UFQgPSAgICAgIDB4MjcsXHJcbiAgbWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgPSAgIDB4MjhcclxufTtcclxuXHJcbmZ1bmN0aW9uIE1FTFBBUkFNNCggYSwgYiwgYywgZCApICAgICAgICB7IHJldHVybiAoIChkPDwyNCkgfCAoYzw8MTYpIHwgKGI8PDgpIHwgKGE8PDApICk7IH1cclxuZnVuY3Rpb24gT1BUQUcyTUVMSU5TVCggb3BDb2RlLCB0YWcgKSAgIHsgcmV0dXJuICggKCAoIG9wQ29kZSAmIDB4MWYgKSA8PCAzICkgfCB0YWcgKTsgfVxyXG5leHBvcnQgZnVuY3Rpb24gTUVMMk9QQ09ERSggYnl0ZUNvZGUgKSAgICAgICAgIHsgcmV0dXJuICggKCBieXRlQ29kZSA+PiAzICkgJiAweDFmICk7IH1cclxuZXhwb3J0IGZ1bmN0aW9uIE1FTDJJTlNUKCBieXRlQ29kZSApICAgICAgICAgICB7IHJldHVybiBNRUwyT1BDT0RFKCBieXRlQ29kZSApOyB9XHJcbmV4cG9ydCBmdW5jdGlvbiBNRUwyVEFHKCBieXRlQ29kZSApICAgICAgICAgICAgeyByZXR1cm4gKCAoYnl0ZUNvZGUpICYgNyApIH07XHJcblxyXG5mdW5jdGlvbiBNRUxQQVJBTVNJWkUoIHBhcmFtVHlwZSApXHJcbntcclxuICByZXR1cm4gKCBwYXJhbVR5cGUgPT0gTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lIClcclxuICAgICAgICAgPyAwXHJcbiAgICAgICAgIDogKCBwYXJhbVR5cGUgPCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUpID8gMSA6IDI7XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBNRUxcclxue1xyXG4gIHB1YmxpYyBzdGF0aWMgbWVsRGVjb2RlID0gW107XHJcblxyXG4gIHB1YmxpYyBzdGF0aWMgTUVMSU5TVDogTUVMSU5TVDtcclxuICBwdWJsaWMgc3RhdGljIE1FTFRBR1NUQUNLOiBNRUxUQUdTVEFDSztcclxuICBwdWJsaWMgc3RhdGljIE1FTFBBUkFNREVGOiBNRUxQQVJBTURFRjtcclxuICBwdWJsaWMgc3RhdGljIE1FTFRBR0FERFI6IE1FTFRBR0FERFI7XHJcblxyXG59XHJcblxyXG5mdW5jdGlvbiBzZXRNZWxEZWNvZGUoIGJ5dGVDb2RlOiBudW1iZXIsIGluc3ROYW1lOiBzdHJpbmcsIHBhcmFtMT8sIHBhcmFtMj8sIHBhcmFtMz8sIHBhcmFtND8gKVxyXG57XHJcbiAgcGFyYW0xID0gcGFyYW0xIHx8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZTtcclxuICBwYXJhbTIgPSBwYXJhbTIgfHwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lO1xyXG4gIHBhcmFtMyA9IHBhcmFtMyB8fCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmU7XHJcbiAgcGFyYW00ID0gcGFyYW00IHx8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZTtcclxuXHJcbiAgTUVMLm1lbERlY29kZVsgYnl0ZUNvZGUgXSA9IHtcclxuICAgIGJ5dGVDb2RlOiBieXRlQ29kZSxcclxuICAgIGluc3RMZW46IDEgKyBNRUxQQVJBTVNJWkUoIHBhcmFtMSApICsgTUVMUEFSQU1TSVpFKCBwYXJhbTIgKSArIE1FTFBBUkFNU0laRSggcGFyYW0zICkgKyBNRUxQQVJBTVNJWkUoIHBhcmFtNCApLFxyXG4gICAgaW5zdE5hbWU6IGluc3ROYW1lLFxyXG4gICAgcGFyYW1EZWZzOiBNRUxQQVJBTTQoIHBhcmFtMSwgcGFyYW0yLCBwYXJhbTMsIHBhcmFtNCApXHJcbiAgfTtcclxufVxyXG5cclxuZnVuY3Rpb24gc2V0TWVsRGVjb2RlU3RkTW9kZXMoIG1lbEluc3Q6IE1FTElOU1QsIGluc3ROYW1lOiBzdHJpbmcsIHBhcmFtMURlZjogTUVMUEFSQU1ERUYgKVxyXG57XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJTQiApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyU1QgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1QgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkckRCICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJMQiApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRMQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyRFQgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclBCICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJQVCApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQVCApO1xyXG59XHJcblxyXG5mdW5jdGlvbiBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggbWVsSW5zdDogTUVMSU5TVCwgaW5zdE5hbWU6IHN0cmluZywgcGFyYW0xRGVmOiBNRUxQQVJBTURFRiApXHJcbntcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclRPUyApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZlRvcE9mU3RhY2sgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2RlcyggbWVsSW5zdCwgaW5zdE5hbWUsIHBhcmFtMURlZiApO1xyXG59XHJcblxyXG5mdW5jdGlvbiBmaWxsTWVsRGVjb2RlKClcclxue1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbExPQUQsICAgXCJMT0FEXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNUT1JFLCAgXCJTVE9SRVwiLCAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbExPQURJLCAgXCJMT0FESVwiLCAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNUT1JFSSwgXCJTVE9SRUlcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclNCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U0IgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclNUICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1QgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkckRCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0REIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkckxCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0TEIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkckRUICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclBCICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UEIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsTE9BREEsIE1FTFRBR0FERFIubWVsQWRkclBUICksIFwiTE9BREFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UFQgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXMoIE1FTElOU1QubWVsSU5ERVgsICBcIklOREVYXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG5cclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTRVRCLCAgIFwiU0VUQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxDTVBCLCAgIFwiQ01QQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxBRERCLCAgIFwiQUREQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVUJCLCAgIFwiU1VCQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTRVRXLCAgIFwiU0VUV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxDTVBXLCAgIFwiQ01QV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxBRERXLCAgIFwiQUREV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVUJXLCAgIFwiU1VCV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQ0xFQVJOLCBcIkNMRUFSTlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsVEVTVE4sICBcIlRFU1ROXCIsICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsSU5DTiwgICBcIklOQ05cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsREVDTiwgICBcIkRFQ05cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsTk9UTiwgICBcIk5PVE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQ01QTiwgICBcIkNNUE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQURETiwgICBcIkFERE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU1VCTiwgICBcIlNVQk5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQU5ETiwgICBcIkFORE5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsT1JOLCAgICBcIk9STlwiLCAgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsWE9STiwgICBcIlhPUk5cIiwgICBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1OT1AgKSwgXCJOT1BcIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1TZXRTVyApLCBcIlNFVFNXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1TZXRMYSApLCBcIlNFVExBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1TZXRTV0xhICksIFwiU0VUU1dMQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1FeGl0ICksIFwiRVhJVFwiICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbUV4aXRTVyApLCBcIkVYSVRTV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtRXhpdExhICksIFwiRVhJVEFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbUV4aXRTV0xhICksIFwiRVhJVFNXTEFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuXHJcbiAgLy8gc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxCUkFOQ0gsIG1lbENvbmRTUEVDICksIFwiLS0tXCIsIDAsIG1lbEFkZHJUT1MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRFUSApLCBcIkJFUVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRMVCApLCBcIkJMVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRMRSApLCBcIkJMRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRHVCApLCBcIkJHVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRHRSApLCBcIkJHRVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRORSApLCBcIkJORVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQlJBTkNILCBNRUxUQUdDT05ELm1lbENvbmRBTEwgKSwgXCJCQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVDb2RlUmVsYXRpdmUgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZFNQRUMgKSwgXCJKQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kRVEgKSwgXCJKRVFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kTFQgKSwgXCJKTFRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kTEUgKSwgXCJKTEVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kR1QgKSwgXCJKR1RcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kR0UgKSwgXCJKR0VcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kTkUgKSwgXCJKTkVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsSlVNUCwgTUVMVEFHQ09ORC5tZWxDb25kQUxMICksIFwiSkFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZFNQRUMgKSwgXCJDQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kRVEgKSwgXCJDRVFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kTFQgKSwgXCJDTFRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kTEUgKSwgXCJDTEVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kR1QgKSwgXCJDR1RcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kR0UgKSwgXCJDR0VcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kTkUgKSwgXCJDTkVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsQ0FMTCwgTUVMVEFHQ09ORC5tZWxDb25kQUxMICksIFwiQ0FcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3MgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BVU0haICksIFwiUFVTSFpcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIQiApLCBcIlBVU0hCXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIVyApLCBcIlBVU0hXXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIC8vIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsU1RBQ0ssIG1lbFN0YWNrWFg0ICksIFwiLS1cIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BOICksIFwiUE9QTlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BPUEIgKSwgXCJQT1BCXCIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QVyApLCBcIlBPUFdcIiApO1xyXG4gIC8vIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsU1RBQ0ssIG1lbFN0YWNrWFg3ICksIFwiLS1cIiApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTAgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMSApLCBcIlBSSU1cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTIgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTMgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVQgKSwgXCJSRVRcIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJICksIFwiUkVUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUTyApLCBcIlJFVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVElPICksIFwiUkVUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4sIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxufVxyXG5cclxuXHJcbmZpbGxNZWxEZWNvZGUoKTtcclxuXHJcbmV4cG9ydCB2YXIgTUVMRGVjb2RlID0gTUVMLm1lbERlY29kZTtcclxuZXhwb3J0IGNvbnN0IE1FTF9DQ1JfWiA9IDB4MDE7XHJcbmV4cG9ydCBjb25zdCBNRUxfQ0NSX0MgPSAweDAyO1xyXG4iLCJpbXBvcnQgKiBhcyBNRUwgZnJvbSAnLi9tZWwtZGVmaW5lcyc7XHJcbmltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9iYXNlL2NvbW1hbmQtYXBkdSc7XHJcbmltcG9ydCB7IFJlc3BvbnNlQVBEVSB9IGZyb20gJy4uL2Jhc2UvcmVzcG9uc2UtYXBkdSc7XHJcblxyXG5mdW5jdGlvbiBoZXgoIHZhbCApIHsgcmV0dXJuIHZhbC50b1N0cmluZyggMTYgKTsgfVxyXG5mdW5jdGlvbiBoZXgyKCB2YWwgKSB7IHJldHVybiAoIFwiMDBcIiArIHZhbC50b1N0cmluZyggMTYgKSApLnN1YnN0ciggLTIgKTsgfVxyXG5mdW5jdGlvbiBoZXg0KCB2YWwgKSB7IHJldHVybiAoIFwiMDAwMFwiICsgdmFsLnRvU3RyaW5nKCAxNiApICkuc3Vic3RyKCAtNCApOyB9XHJcbmZ1bmN0aW9uIGxqdXN0KCBzdHIsIHcgKSB7IHJldHVybiAoIHN0ciArIEFycmF5KCB3ICsgMSApLmpvaW4oIFwiIFwiICkgKS5zdWJzdHIoIDAsIHcgKTsgfVxyXG5mdW5jdGlvbiByanVzdCggc3RyLCB3ICkgeyByZXR1cm4gKCBBcnJheSggdyArIDEgKS5qb2luKCBcIiBcIiApICsgc3RyICkuc3Vic3RyKCAtdyApOyB9XHJcblxyXG5mdW5jdGlvbiAgIEJBMlcoIHZhbCApXHJcbntcclxuICByZXR1cm4gKCB2YWxbIDAgXSA8PCA4ICkgfCB2YWxbIDEgXTtcclxufVxyXG5cclxuZnVuY3Rpb24gICBXMkJBKCB2YWwgKVxyXG57XHJcblxyXG4gIHJldHVybiBuZXcgQnl0ZUFycmF5KCBbIHZhbCA+PiA4LCB2YWwgJiAweEZGIF0gKTtcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIE1FTFZpcnR1YWxNYWNoaW5lIHtcclxuICAvLyBjYXJkXHJcbiAgcmFtU2VnbWVudDtcclxuICByb21TZWdtZW50O1xyXG5cclxuICAvLyBhcHBsaWNhdGlvblxyXG4gIGNvZGVBcmVhO1xyXG4gIHN0YXRpY0FyZWE7XHJcbiAgcHVibGljQXJlYTtcclxuICBkeW5hbWljQXJlYTtcclxuICBzZXNzaW9uU2l6ZTtcclxuXHJcbiAgLy8gZXhlY3V0aW9uXHJcbiAgaXNFeGVjdXRpbmc7XHJcbiAgY3VycmVudElQO1xyXG4gIGxvY2FsQmFzZTtcclxuICBkeW5hbWljVG9wO1xyXG4gIGNvbmRpdGlvbkNvZGVSZWc7XHJcblxyXG4gIGluaXRNVk0oIHBhcmFtcyApXHJcbiAge1xyXG4gICAgdGhpcy5yb21TZWdtZW50ID0gcGFyYW1zLnJvbVNlZ21lbnQ7XHJcbiAgICB0aGlzLnJhbVNlZ21lbnQgPSBwYXJhbXMucmFtU2VnbWVudDtcclxuXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEgPSB0aGlzLnJhbVNlZ21lbnQubmV3QWNjZXNzb3IoIDAsIDUxMiwgXCJQXCIgKTtcclxuICB9XHJcblxyXG4gIGRpc2Fzc2VtYmxlQ29kZSggcmVzZXRJUCwgc3RlcFRvTmV4dElQIClcclxuICB7XHJcbiAgICB2YXIgZGlzbVRleHQgPSBcIlwiO1xyXG4gICAgZnVuY3Rpb24gcHJpbnQoIHN0ciApIHsgZGlzbVRleHQgKz0gc3RyOyB9XHJcblxyXG4gICAgaWYgKCByZXNldElQIClcclxuICAgICAgdGhpcy5jdXJyZW50SVAgPSAwO1xyXG5cclxuICAgIGlmICggdGhpcy5jdXJyZW50SVAgPj0gdGhpcy5jb2RlQXJlYS5nZXRMZW5ndGgoKSApXHJcbiAgICAgIHJldHVybiBudWxsO1xyXG5cclxuICAgIHRyeVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV4dElQID0gdGhpcy5jdXJyZW50SVA7XHJcbiAgICAgIHZhciBpbnN0Qnl0ZSA9IHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICk7XHJcbiAgICAgIHZhciBwYXJhbUNvdW50ID0gMDtcclxuICAgICAgdmFyIHBhcmFtVmFsID0gW107XHJcbiAgICAgIHZhciBwYXJhbURlZiA9IFtdO1xyXG5cclxuICAgICAgdmFyIG1lbEluc3QgPSBNRUwuTUVMRGVjb2RlWyBpbnN0Qnl0ZSBdO1xyXG5cclxuICAgICAgaWYgKCBtZWxJbnN0ID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHtcclxuICAgICAgICBwcmludCggXCJbXCIgKyBoZXg0KCB0aGlzLmN1cnJlbnRJUCApICsgXCJdICAgICAgICAgIFwiICsgbGp1c3QoIFwiRVJST1I6XCIgKyBoZXgyKCBpbnN0Qnl0ZSApLCA4ICkgKyBcIiAqKioqKioqKlxcblwiICk7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIHBhcmFtRGVmcyA9IG1lbEluc3QucGFyYW1EZWZzO1xyXG4gICAgICAgIHdoaWxlKCBwYXJhbURlZnMgIT0gMCApXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcGFyYW1EZWZbIHBhcmFtQ291bnQgXSA9IHBhcmFtRGVmcyAmIDB4RkY7XHJcbiAgICAgICAgICBzd2l0Y2goIHBhcmFtRGVmcyAmIDB4RjAgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIDB4MDA6IGJyZWFrO1xyXG4gICAgICAgICAgICBjYXNlIDB4MTA6IHBhcmFtVmFsWyBwYXJhbUNvdW50IF0gPSB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApOyBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAweDIwOiBwYXJhbVZhbFsgcGFyYW1Db3VudCBdID0gQkEyVyggWyB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApLCB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApIF0gKTsgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBwYXJhbUNvdW50Kys7XHJcbiAgICAgICAgICBwYXJhbURlZnMgPj49IDg7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwcmludCggXCJbXCIgKyBoZXg0KCB0aGlzLmN1cnJlbnRJUCApICsgXCJdICAgICAgICAgIFwiICsgbGp1c3QoIG1lbEluc3QuaW5zdE5hbWUsIDggKSApO1xyXG5cclxuICAgICAgICBpZiAoICggcGFyYW1Db3VudCA+IDEgKVxyXG4gICAgICAgICAgJiYgKCAoIHBhcmFtRGVmWyAwIF0gPT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKVxyXG4gICAgICAgICAgICB8fCAoIHBhcmFtRGVmWyAwIF0gPT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSApXHJcbiAgICAgICAgICAgIHx8ICggcGFyYW1EZWZbIDAgXSA9PSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICkgKVxyXG4gICAgICAgICAgJiYgKCBwYXJhbURlZlsgMSBdICE9IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKVxyXG4gICAgICAgICAgJiYgKCBwYXJhbURlZlsgMSBdICE9IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICkgKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciB0ZW1wVmFsID0gcGFyYW1WYWxbMV07IHBhcmFtVmFsWzFdID0gcGFyYW1WYWxbMF07IHBhcmFtVmFsWzBdID0gdGVtcFZhbDtcclxuICAgICAgICAgIHZhciB0ZW1wRGVmID0gcGFyYW1EZWZbMV07IHBhcmFtRGVmWzFdID0gcGFyYW1EZWZbMF07IHBhcmFtRGVmWzBdID0gdGVtcERlZjtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGZvciggdmFyIHBhcmFtSW5kZXggPSAwOyBwYXJhbUluZGV4IDwgcGFyYW1Db3VudDsgKytwYXJhbUluZGV4IClcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgdiA9IHBhcmFtVmFsWyBwYXJhbUluZGV4IF07XHJcbiAgICAgICAgICB2YXIgZCA9IHBhcmFtRGVmWyBwYXJhbUluZGV4IF07XHJcblxyXG4gICAgICAgICAgc3dpdGNoKCBkIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbjpcclxuICAgICAgICAgICAgICBpZiAoIHYgPiAwIClcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIjB4XCIgKyBoZXgoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHByaW50KCB2ICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGU6XHJcbiAgICAgICAgICAgICAgaWYgKCB2ID4gMCApXHJcbiAgICAgICAgICAgICAgICBwcmludCggXCIweFwiICsgaGV4KCB2ICkgKTtcclxuICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICBwcmludCggdiApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlOlxyXG4gICAgICAgICAgICAgIHByaW50KCBcIjB4XCIgKyBoZXgoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkQ29kZUFkZHJlc3M6XHJcbiAgICAgICAgICAgICAgcHJpbnQoIGhleDQoIHYgKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlOlxyXG4gICAgICAgICAgICAgIHByaW50KCBoZXg0KCB0aGlzLmN1cnJlbnRJUCArIDIgKyB2ICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNCOiAgLy8gMDFcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U1Q6ICAvLyAwMlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREQjogIC8vIDAzXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldExCOiAgLy8gMDRcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0RFQ6ICAvLyAwNVxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQQjogIC8vIDA2XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBUOiAgLy8gMDdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgIHZhciBzZWcgPSBbIFwiXCIsIFwiU0JcIiwgXCJTVFwiLCBcIkRCXCIsIFwiTEJcIiwgXCJEVFwiLCBcIlBCXCIsIFwiUFRcIiBdO1xyXG4gICAgICAgICAgICAgIHByaW50KCBzZWdbIGQgJiAweDA3IF0gKTtcclxuICAgICAgICAgICAgICBpZiAoIHYgPiAwIClcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIlsweFwiICsgaGV4KCB2ICkgKyBcIl1cIiApO1xyXG4gICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHByaW50KCBcIltcIiArIHYgKyBcIl1cIiApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgaWYgKCBwYXJhbUluZGV4IDwgcGFyYW1Db3VudCAtIDEgKVxyXG4gICAgICAgICAgICBwcmludCggXCIsIFwiICk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHByaW50KCBcIlxcblwiICk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICggc3RlcFRvTmV4dElQIClcclxuICAgICAgICB0aGlzLmN1cnJlbnRJUCA9IG5leHRJUDtcclxuICAgIH1cclxuICAgIGNhdGNoKCBlIClcclxuICAgIHtcclxuICAgICAgcHJpbnQoIGUgKTtcclxuICAgIH07XHJcblxyXG5cclxuICAgIHJldHVybiBkaXNtVGV4dDtcclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gTVVMVE9TIGFkZHJlc3NlcyBhcmUgMTYtYml0IGxpbmVhciB2YWx1ZXMsIHdoZW4gcHVzaGVkIG9udG8gc3RhY2tcclxuICAvLyBhbmQgdXNlZCBmb3IgaW5kaXJlY3Rpb24uIFdlIG1hcCBhZGRyZXNzLXRhZyBhbmQgb2Zmc2V0IHBhaXJzIHRvIGxpbmVhclxyXG4gIC8vIGFkZHJlc3NlcywgYW5kIGJhY2sgYWdhaW4sIGJ5IGJhc2luZyBzdGF0aWMgYXQgMHgwMDAwLCBkeW5hbWljIGF0IDB4ODAwMFxyXG4gIC8vIGFuZCBwdWJsaWMgYXQgMHhGMDAwLlxyXG4gIC8vXHJcbiAgcHJpdmF0ZSBtYXBUb1NlZ21lbnRBZGRyKCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDAgKTtcclxuXHJcbiAgICBzd2l0Y2goIGFkZHJUYWcgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1M6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRCOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJMQjpcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQ6XHJcbiAgICAgICAgcmV0dXJuIDB4ODAwMCArIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0O1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU0I6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclNUOlxyXG4gICAgICAgIHJldHVybiB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldDtcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclBCOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJQVDpcclxuICAgICAgICByZXR1cm4gMHhGMDAwICsgdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQ7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIG1hcEZyb21TZWdtZW50QWRkciggc2VnbWVudEFkZHIgKVxyXG4gIHtcclxuICAgIGlmICggc2VnbWVudEFkZHIgJiAweDgwMDAgKVxyXG4gICAge1xyXG4gICAgICBpZiAoIHNlZ21lbnRBZGRyID49IDB4RjAwMCApXHJcbiAgICAgIHtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YUFyZWE6IHRoaXMucHVibGljQXJlYSxcclxuICAgICAgICAgIGRhdGFBZGRyVGFnOiBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUEIsXHJcbiAgICAgICAgICBkYXRhT2Zmc2V0OiBzZWdtZW50QWRkciAmIDB4MEZGRlxyXG4gICAgICAgIH07XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGFBcmVhOiB0aGlzLmR5bmFtaWNBcmVhLFxyXG4gICAgICAgICAgZGF0YUFkZHJUYWc6IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEQixcclxuICAgICAgICAgIGRhdGFPZmZzZXQ6IHNlZ21lbnRBZGRyICYgMHgzRkZGXHJcbiAgICAgICAgfTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgZWxzZVxyXG4gICAge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGFBcmVhOiB0aGlzLnN0YXRpY0FyZWEsXHJcbiAgICAgICAgZGF0YUFkZHJUYWc6IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJTQixcclxuICAgICAgICBkYXRhT2Zmc2V0OiBzZWdtZW50QWRkciAmIDB4N0ZGRlxyXG4gICAgICB9O1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLy9cclxuICAvLyB2YWxpZGF0ZSBhIG11bHRpLWJ5dGUgbWVtb3J5IGFjY2Vzcywgc3BlY2lmaWVkIGJ5IGFkZHJlc3MtdGFnL29mZnNldCBwYWlyXHJcbiAgLy8gYW5kIGxlbmd0aCB2YWx1ZXMuIElmIG9rLCBtYXAgdG8gYW4gYXJlYSBhbmQgb2Zmc2V0IHdpdGhpbiB0aGF0IGFyZWEuXHJcbiAgLy8gQ2FuIGFjY2VwdCBwb3NpdGl2ZS9uZWdhdGl2ZSBvZmZzZXRzLCBzaW5jZSB0aGV5IGFyZWEgcmVsYXRpdmUgdG8gdGhlXHJcbiAgLy8gdGhlIHRvcCBvciB0aGUgYm90dG9tIG9mIHRoZSBzcGVjaWZpZWQgYXJlYSwgYXMgaW5kaWNhdGVkIGJ5IHRoZSB0YWcuXHJcbiAgLy9cclxuICBwcml2YXRlIGNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgb2Zmc2V0LCBsZW5ndGggKVxyXG4gIHtcclxuICAgIHZhciBkYXRhQXJlYTtcclxuICAgIHZhciBkYXRhT2Zmc2V0ID0gb2Zmc2V0O1xyXG4gICAgdmFyIGFyZWFMaW1pdDtcclxuXHJcbiAgICBzd2l0Y2goIGFkZHJUYWcgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1M6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLmR5bmFtaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuZHluYW1pY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSB0aGlzLmxvY2FsQmFzZTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRCOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5keW5hbWljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLmR5bmFtaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyTEI6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLmR5bmFtaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuZHluYW1pY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcbiAgICAgICAgZGF0YU9mZnNldCArPSB0aGlzLmxvY2FsQmFzZTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRUOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5keW5hbWljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLmR5bmFtaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gdGhpcy5keW5hbWljVG9wO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU0I6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnN0YXRpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5zdGF0aWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU1Q6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnN0YXRpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5zdGF0aWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gYXJlYUxpbWl0O1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUEI6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnB1YmxpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUFQ6XHJcbiAgICAgICAgZGF0YUFyZWEgPSB0aGlzLnB1YmxpY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gYXJlYUxpbWl0O1xyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgfVxyXG5cclxuICAgIGRhdGFPZmZzZXQgJj0gMHhmZmZmOyAvLyAxNiBiaXRzIGFkZHJlc3Nlc1xyXG4gICAgaWYgKCAoIGRhdGFPZmZzZXQgPCBhcmVhTGltaXQgKSAmJiAoIGRhdGFPZmZzZXQgKyBsZW5ndGggPCBhcmVhTGltaXQgKSApXHJcbiAgICB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YUFyZWE6IGRhdGFBcmVhLFxyXG4gICAgICAgIGRhdGFPZmZzZXQ6IGRhdGFPZmZzZXRcclxuICAgICAgfTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gcGVyZm9ybSBhIHZhbGlkYXRlZCBtdWx0aS1ieXRlIHJlYWQsIHNwZWNpZmllZCBieSBhZGRyZXNzLXRhZy9vZmZzZXQgcGFpciBhbmRcclxuICAvLyBsZW5ndGggdmFsdWVzLiBSZXR1cm4gZGF0YS1hcnJheSwgb3IgdW5kZWZpbmVkXHJcbiAgLy9cclxuICBwcml2YXRlIHJlYWRTZWdtZW50RGF0YSggYWRkclRhZywgb2Zmc2V0LCBsZW5ndGggKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgb2Zmc2V0LCAxICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgcmV0dXJuIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS5yZWFkQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBsZW5ndGggKTtcclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gcGVyZm9ybSBhIHZhbGlkYXRlZCBtdWx0aS1ieXRlIHdyaXRlLCBzcGVjaWZpZWQgYnkgYWRkcmVzcy10YWcvb2Zmc2V0IHBhaXIgYW5kXHJcbiAgLy8gZGF0YS1hcnJheSB0byBiZSB3cml0dGVuLlxyXG4gIC8vXHJcbiAgcHJpdmF0ZSB3cml0ZVNlZ21lbnREYXRhKCBhZGRyVGFnLCBvZmZzZXQsIHZhbCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBvZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEud3JpdGVCeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIHZhbCApO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwdXNoWmVyb3NUb1N0YWNrKCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY0FyZWEuemVyb0J5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIGNudCApO1xyXG5cclxuICAgIHRoaXMuZHluYW1pY1RvcCArPSBjbnQ7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHB1c2hDb25zdFRvU3RhY2soIGNudCwgdmFsIClcclxuICB7XHJcbiAgICBpZiAoIGNudCA9PSAxIClcclxuICAgICAgdGhpcy5keW5hbWljQXJlYS53cml0ZUJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIFsgdmFsIF0gKTtcclxuICAgIGVsc2VcclxuICAgICAgdGhpcy5keW5hbWljQXJlYS53cml0ZUJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIFcyQkEoIHZhbCApICk7XHJcblxyXG4gICAgdGhpcy5keW5hbWljVG9wICs9IGNudDtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgY29weU9uU3RhY2soIGZyb21PZmZzZXQsIHRvT2Zmc2V0LCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY0FyZWEuY29weUJ5dGVzKCBmcm9tT2Zmc2V0LCB0b09mZnNldCwgY250ICk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHB1c2hUb1N0YWNrKCBhZGRyVGFnLCBvZmZzZXQsIGNudCApXHJcbiAge1xyXG4gICAgdGhpcy5keW5hbWljVG9wICs9IGNudDtcclxuICAgIHRoaXMuZHluYW1pY0FyZWEud3JpdGVCeXRlcyggdGhpcy5keW5hbWljVG9wLCB0aGlzLnJlYWRTZWdtZW50RGF0YSggYWRkclRhZywgb2Zmc2V0LCBjbnQgKSApO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwb3BGcm9tU3RhY2tBbmRTdG9yZSggYWRkclRhZywgb2Zmc2V0LCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY1RvcCAtPSBjbnQ7XHJcblxyXG4gICAgdGhpcy53cml0ZVNlZ21lbnREYXRhKCBhZGRyVGFnLCBvZmZzZXQsIHRoaXMuZHluYW1pY0FyZWEucmVhZEJ5dGVzKCB0aGlzLmR5bmFtaWNUb3AsIGNudCApICk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBvcEZyb21TdGFjayggY250IClcclxuICB7XHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgLT0gY250O1xyXG5cclxuICAgIHJldHVybiB0aGlzLmR5bmFtaWNBcmVhLnJlYWRCeXRlcyggdGhpcy5keW5hbWljVG9wLCBjbnQgKTtcclxuICB9XHJcblxyXG4gIC8vIHNldHVwIGFwcGxpY2F0aW9uIGZvciBleGVjdXRpb25cclxuICBzZXR1cEFwcGxpY2F0aW9uKCBleGVjUGFyYW1zIClcclxuICB7XHJcbiAgICB0aGlzLmNvZGVBcmVhID0gZXhlY1BhcmFtcy5jb2RlQXJlYTtcclxuICAgIHRoaXMuc3RhdGljQXJlYSA9IGV4ZWNQYXJhbXMuc3RhdGljQXJlYTtcclxuICAgIHRoaXMuc2Vzc2lvblNpemUgPSBleGVjUGFyYW1zLnNlc3Npb25TaXplO1xyXG5cclxuICAgIHRoaXMuZHluYW1pY0FyZWEgPSB0aGlzLnJhbVNlZ21lbnQubmV3QWNjZXNzb3IoIDAsIDUxMiwgXCJEXCIgKTsgLy9UT0RPOiBleGVjUGFyYW1zLnNlc3Npb25TaXplXHJcblxyXG4gICAgdGhpcy5pbml0RXhlY3V0aW9uKCk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGluaXRFeGVjdXRpb24oKVxyXG4gIHtcclxuICAgIHRoaXMuY3VycmVudElQID0gMDtcclxuICAgIHRoaXMuaXNFeGVjdXRpbmcgPSB0cnVlO1xyXG5cclxuICAgIC8vIFRPRE86IFNlcGFyYXRlIHN0YWNrIGFuZCBzZXNzaW9uXHJcbiAgICB0aGlzLmxvY2FsQmFzZSA9IHRoaXMuc2Vzc2lvblNpemU7XHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgPSB0aGlzLmxvY2FsQmFzZTtcclxuXHJcbiAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgPSAwO1xyXG4gIH1cclxuXHJcbiAgc2VncyA9IFsgXCJcIiwgXCJTQlwiLCBcIlNUXCIsIFwiREJcIiwgXCJMQlwiLCBcIkRUXCIsIFwiUEJcIiwgXCJQVFwiIF07XHJcblxyXG4gIHByaXZhdGUgY29uc3RCeXRlQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIGNvbnN0VmFsLCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICB2YXIgdGVtcFZhbCA9IHRhcmdldEFjY2Vzcy5kYXRhQXJlYS5yZWFkQnl0ZSggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQgKTtcclxuXHJcbiAgICBzd2l0Y2goIG9wQ29kZSApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsICsgY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPCBjb25zdFZhbCApICAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQkI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCAtIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsID4gY29uc3RWYWwgKSAgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgLSBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA+IGNvbnN0VmFsICkgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTRVRCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSBjb25zdFZhbDtcclxuICAgICAgICBicmVhaztcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIHRlbXBWYWwgPT0gMCApXHJcbiAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9aO1xyXG5cclxuICAgIGlmICggb3BDb2RlICE9IE1FTC5NRUxJTlNULm1lbENNUEIgKVxyXG4gICAge1xyXG4gICAgICB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEud3JpdGVCeXRlKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgdGVtcFZhbCApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBjb25zdFdvcmRCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgY29uc3RWYWwsIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMiApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHZhciB0ZW1wVmFsID0gQkEyVyggdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLnJlYWRCeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIDIgKSApO1xyXG5cclxuICAgIHN3aXRjaCggb3BDb2RlIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBRERCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgKyBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA8IGNvbnN0VmFsICkgIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1VCQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsIC0gY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPiBjb25zdFZhbCApICAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENNUEI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCAtIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsID4gY29uc3RWYWwgKSAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVEI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9IGNvbnN0VmFsO1xyXG4gICAgICAgIGJyZWFrO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICggdGVtcFZhbCA9PSAwIClcclxuICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX1o7XHJcblxyXG4gICAgaWYgKCBvcENvZGUgIT0gTUVMLk1FTElOU1QubWVsQ01QVyApXHJcbiAgICB7XHJcbiAgICAgIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS53cml0ZUJ5dGVzKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgVzJCQSggdGVtcFZhbCApICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBvcFNpemUsIGFkZHJUYWcsIGFkZHJPZmZzZXQgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgYWRkck9mZnNldCwgMSApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHRoaXMuY2hlY2tEYXRhQWNjZXNzKCAtb3BTaXplIC0gMSwgb3BTaXplLCBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TICk7IC8vIEZpcnN0XHJcblxyXG4gICAgLy8gdG9kbzpcclxuICB9XHJcblxyXG4gIHByaXZhdGUgdW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgb3BTaXplLCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICBzd2l0Y2goIG9wQ29kZSApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ0xFQVJOOlxyXG4gICAgICAgIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS56ZXJvQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBvcFNpemUgKTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsVEVTVE46ICAgICAgICAgLy8gMTZcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxJTkNOOiAgICAgICAgICAvLyAxN1xyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbERFQ046ICAgICAgICAgIC8vIDE4XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTk9UTjogICAgICAgICAgLy8gMTlcclxuICAgICAgICA7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGhhbmRsZVJldHVybiggaW5CeXRlcywgb3V0Qnl0ZXMgKVxyXG4gIHtcclxuICAgIHZhciByZXRWYWxPZmZzZXQgPSB0aGlzLmR5bmFtaWNUb3AgLSBvdXRCeXRlcztcclxuXHJcbiAgICB2YXIgcmV0dXJuSVAgPSBCQTJXKCB0aGlzLmR5bmFtaWNBcmVhLnJlYWRCeXRlcyggdGhpcy5sb2NhbEJhc2UgLSAyLCAyICkgKTtcclxuICAgIHRoaXMubG9jYWxCYXNlID0gQkEyVyggdGhpcy5keW5hbWljQXJlYS5yZWFkQnl0ZXMoIHRoaXMubG9jYWxCYXNlIC0gNCwgMiApICk7XHJcblxyXG4gICAgdGhpcy5keW5hbWljVG9wID0gdGhpcy5sb2NhbEJhc2UgKyBvdXRCeXRlcztcclxuICAgIGlmICggb3V0Qnl0ZXMgKVxyXG4gICAgICB0aGlzLmNvcHlPblN0YWNrKCByZXRWYWxPZmZzZXQsIHRoaXMubG9jYWxCYXNlLCBvdXRCeXRlcyApO1xyXG5cclxuICAgIHJldHVybiByZXR1cm5JUDtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgaXNDb25kaXRpb24oIHRhZyApXHJcbiAge1xyXG4gICAgc3dpdGNoKCB0YWcgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRFUTpcclxuICAgICAgICByZXR1cm4gKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZExUOlxyXG4gICAgICAgIHJldHVybiAhKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9DICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZExFOlxyXG4gICAgICAgIHJldHVybiAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX1ogKSB8fCAhKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9DICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZEdUOlxyXG4gICAgICAgIHJldHVybiAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX0MgKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kR0U6XHJcbiAgICAgICAgcmV0dXJuICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfWiApIHx8ICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfQyApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRORTpcclxuICAgICAgICByZXR1cm4gISggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRBTEw6XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgIGRlZmF1bHQ6IC8vIG1lbENvbmRTUEVDXHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGZhbHNlO1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZVN0ZXAoKVxyXG4gIHtcclxuICAgIHRyeVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV4dElQID0gdGhpcy5jdXJyZW50SVA7XHJcbiAgICAgIHZhciBpbnN0Qnl0ZSA9IHRoaXMuY29kZUFyZWEucmVhZEJ5dGUoIG5leHRJUCsrICk7XHJcbiAgICAgIHZhciBwYXJhbUNvdW50ID0gMDtcclxuICAgICAgdmFyIHBhcmFtVmFsID0gW107XHJcbiAgICAgIHZhciBwYXJhbURlZiA9IFtdO1xyXG5cclxuICAgICAgdmFyIG1lbEluc3QgPSBNRUwuTUVMRGVjb2RlWyBpbnN0Qnl0ZSBdO1xyXG5cclxuICAgICAgaWYgKCBtZWxJbnN0ID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHtcclxuICAgICAgICByZXR1cm4gbnVsbDtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICB2YXIgcGFyYW1EZWZzID0gbWVsSW5zdC5wYXJhbURlZnM7XHJcblxyXG4gICAgICAgIHdoaWxlKCBwYXJhbURlZnMgIT0gMCApXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcGFyYW1EZWZbIHBhcmFtQ291bnQgXSA9IHBhcmFtRGVmcyAmIDB4RkY7XHJcbiAgICAgICAgICBzd2l0Y2goIHBhcmFtRGVmcyAmIDB4RjAgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIDB4MDA6IGJyZWFrO1xyXG4gICAgICAgICAgICBjYXNlIDB4MTA6IHBhcmFtVmFsWyBwYXJhbUNvdW50IF0gPSB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApOyBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAweDIwOiBwYXJhbVZhbFsgcGFyYW1Db3VudCBdID0gQkEyVyggWyB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApLCB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApIF0gKTsgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBwYXJhbUNvdW50Kys7XHJcbiAgICAgICAgICBwYXJhbURlZnMgPj49IDg7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICB2YXIgb3BDb2RlID0gTUVMLk1FTDJPUENPREUoIGluc3RCeXRlICk7XHJcbiAgICAgIHZhciB0YWcgPSBNRUwuTUVMMlRBRyggaW5zdEJ5dGUgKTtcclxuXHJcbiAgICAgIHN3aXRjaCggb3BDb2RlIClcclxuICAgICAge1xyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1lTVEVNOiAgICAgICAgLy8gMDBcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgcHVibGljVG9wID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG5cclxuICAgICAgICAgIHN3aXRjaCggdGFnIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1FeGl0OlxyXG4gICAgICAgICAgICAgIHRoaXMuaXNFeGVjdXRpbmcgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAvL25vIGJyZWFrXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtTk9QOlxyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1FeGl0U1c6XHJcbiAgICAgICAgICAgICAgdGhpcy5pc0V4ZWN1dGluZyA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgIC8vbm8gYnJlYWtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1TZXRTVzpcclxuICAgICAgICAgICAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gMiwgVzJCQSggcGFyYW1WYWxbIDAgXSApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbUV4aXRMYTpcclxuICAgICAgICAgICAgICB0aGlzLmlzRXhlY3V0aW5nID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgLy9ubyBicmVha1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbVNldExhOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSA0LCBXMkJBKCBwYXJhbVZhbFsgMCBdICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtRXhpdFNXTGE6XHJcbiAgICAgICAgICAgICAgdGhpcy5pc0V4ZWN1dGluZyA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgIC8vbm8gYnJlYWtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1TZXRTV0xhOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSAyLCBXMkJBKCBwYXJhbVZhbFsgMCBdICkgKTtcclxuICAgICAgICAgICAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gNCwgVzJCQSggcGFyYW1WYWxbIDEgXSApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQlJBTkNIOiAgICAgICAgLy8gMDFcclxuICAgICAgICAgIGlmICggdGhpcy5pc0NvbmRpdGlvbiggdGFnICkgKVxyXG4gICAgICAgICAgICBuZXh0SVAgPSBuZXh0SVAgKyBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSlVNUDogICAgICAgICAgLy8gMDJcclxuICAgICAgICAgIGlmICggdGhpcy5pc0NvbmRpdGlvbiggdGFnICkgKVxyXG4gICAgICAgICAgICBuZXh0SVAgPSBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ0FMTDogICAgICAgICAgLy8gMDNcclxuICAgICAgICAgIGlmICggdGhpcy5pc0NvbmRpdGlvbiggdGFnICkgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDIsIHRoaXMubG9jYWxCYXNlICk7XHJcbiAgICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMiwgbmV4dElQICk7XHJcblxyXG4gICAgICAgICAgICBuZXh0SVAgPSBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgICB0aGlzLmxvY2FsQmFzZSA9IHRoaXMuZHluYW1pY1RvcDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNUQUNLOiAgICAgICAgIC8vIDA0XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgc3dpdGNoKCB0YWcgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BVU0haOlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgdGhpcy5wdXNoWmVyb3NUb1N0YWNrKCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIQjpcclxuICAgICAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDEsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSFc6XHJcbiAgICAgICAgICAgICAgdGhpcy5wdXNoQ29uc3RUb1N0YWNrKCAyLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BPUE46XHJcbiAgICAgICAgICAgICAgdGhpcy5wb3BGcm9tU3RhY2soIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QQjpcclxuICAgICAgICAgICAgICB0aGlzLnBvcEZyb21TdGFjayggMSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BXOlxyXG4gICAgICAgICAgICAgIHRoaXMucG9wRnJvbVN0YWNrKCAyICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsUFJJTVJFVDogICAgICAgLy8gMDVcclxuICAgICAgICB7XHJcbiAgICAgICAgICBzd2l0Y2goIHRhZyApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0wOlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMTpcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTI6XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0zOlxyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCAwLCAwICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCBwYXJhbVZhbFsgMCBdLCAwICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRPOlxyXG4gICAgICAgICAgICAgIG5leHRJUCA9IHRoaXMuaGFuZGxlUmV0dXJuKCAwLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJTzpcclxuICAgICAgICAgICAgICBuZXh0SVAgPSB0aGlzLmhhbmRsZVJldHVybiggcGFyYW1WYWxbIDAgXSwgcGFyYW1WYWxbIDEgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbExPQUQ6ICAgICAgICAgIC8vIDA3XHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgLy8gRFVQIFRPU1xyXG4gICAgICAgICAgICB0aGlzLmNvcHlPblN0YWNrKCB0aGlzLmR5bmFtaWNUb3AgLSBwYXJhbVZhbFsgMCBdLCB0aGlzLmR5bmFtaWNUb3AsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgICAgdGhpcy5keW5hbWljVG9wICs9IHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMucHVzaFRvU3RhY2soIHRhZywgcGFyYW1WYWxbIDEgXSwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU1RPUkU6ICAgICAgICAgLy8gMDhcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICAvLyBTSElGVCBUT1NcclxuICAgICAgICAgICAgdGhpcy5keW5hbWljVG9wIC09IHBhcmFtVmFsWyAwIF07XHJcbiAgICAgICAgICAgIHRoaXMuY29weU9uU3RhY2soIHRoaXMuZHluYW1pY1RvcCwgdGhpcy5keW5hbWljVG9wIC0gcGFyYW1WYWxbIDAgXSwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLnBvcEZyb21TdGFja0FuZFN0b3JlKCB0YWcsIHBhcmFtVmFsWyAxIF0sIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxMT0FESTogICAgICAgICAvLyAwOVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciBzZWdtZW50QWRkciA9IEJBMlcoIHRoaXMucmVhZFNlZ21lbnREYXRhKCB0YWcsIHBhcmFtVmFsWyAxIF0sIDIgKSApO1xyXG4gICAgICAgICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMubWFwRnJvbVNlZ21lbnRBZGRyKCBzZWdtZW50QWRkciApO1xyXG4gICAgICAgICAgdGhpcy5wdXNoVG9TdGFjayggdGFyZ2V0QWNjZXNzLmRhdGFBZGRyVGFnLCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNUT1JFSTogICAgICAgIC8vIDBBXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIHNlZ21lbnRBZGRyID0gQkEyVyggdGhpcy5yZWFkU2VnbWVudERhdGEoIHRhZywgcGFyYW1WYWxbIDEgXSwgMiApICk7XHJcbiAgICAgICAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5tYXBGcm9tU2VnbWVudEFkZHIoIHNlZ21lbnRBZGRyICk7XHJcbiAgICAgICAgICB0aGlzLnBvcEZyb21TdGFja0FuZFN0b3JlKCB0YXJnZXRBY2Nlc3MuZGF0YUFkZHJUYWcsIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTE9BREE6ICAgICAgICAgLy8gMEJcclxuICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMiwgdGhpcy5tYXBUb1NlZ21lbnRBZGRyKCB0YWcsIHBhcmFtVmFsWyAwIF0gKSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSU5ERVg6ICAgICAgICAgLy8gMENcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVEI6ICAgICAgICAgIC8vIDBEXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBCOiAgICAgICAgICAvLyAwRVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREQjogICAgICAgICAgLy8gMEZcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQkI6ICAgICAgICAgIC8vIDEwXHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy5jb25zdEJ5dGVCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTEgKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5jb25zdEJ5dGVCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIHRhZywgcGFyYW1WYWxbMV0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNFVFc6ICAgICAgICAgIC8vIDExXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBXOiAgICAgICAgICAvLyAxMlxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREVzogICAgICAgICAgLy8gMTNcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQlc6ICAgICAgICAgIC8vIDE0XHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy5jb25zdFdvcmRCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTIgKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5jb25zdFdvcmRCaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIHRhZywgcGFyYW1WYWxbMV0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENMRUFSTjogICAgICAgIC8vIDE1XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxURVNUTjogICAgICAgICAvLyAxNlxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSU5DTjogICAgICAgICAgLy8gMTdcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbERFQ046ICAgICAgICAgIC8vIDE4XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxOT1ROOiAgICAgICAgICAvLyAxOVxyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICAgIHRoaXMudW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTEgKiBwYXJhbVZhbFswXSApO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLnVuYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCB0YWcsIHBhcmFtVmFsWzFdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBOOiAgICAgICAgICAvLyAxQVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQURETjogICAgICAgICAgLy8gMUJcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQk46ICAgICAgICAgIC8vIDFDXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxBTkROOiAgICAgICAgICAvLyAxRFxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsT1JOOiAgICAgICAgICAgLy8gMUVcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFhPUk46ICAgICAgICAgIC8vIDFGXHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgICAgdGhpcy5iaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVCwgLTIgKiBwYXJhbVZhbFswXSApO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLmJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgdGFnLCBwYXJhbVZhbFsxXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuY3VycmVudElQID0gbmV4dElQO1xyXG4gICAgfVxyXG4gICAgY2F0Y2goIGUgKVxyXG4gICAge1xyXG4gICAgICAvL3ByaW50KCBlICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBzZXRDb21tYW5kQVBEVSggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVIClcclxuICB7XHJcbiAgICB2YXIgcHVibGljVG9wID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG5cclxuICAgIC8vIC0yLC0xID0gU1cxMlxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDIsIFcyQkEoIDB4OTAwMCApICk7XHJcblxyXG4gICAgLy8gLTQsLTMgPSBMYVxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDQsIFcyQkEoIDB4MDAwMCApICk7XHJcblxyXG4gICAgLy8gLTYsLTUgPSBMZVxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDYsIFcyQkEoIGNvbW1hbmRBUERVLkxlICkgKTtcclxuXHJcbiAgICAvLyAtOCwtNyA9IExjXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gOCwgVzJCQSggY29tbWFuZEFQRFUuZGF0YS5sZW5ndGggKSApO1xyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDEzLCBjb21tYW5kQVBEVS5oZWFkZXIgKTtcclxuXHJcbiAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggMCwgY29tbWFuZEFQRFUuZGF0YSApO1xyXG5cclxuICAgIHRoaXMuaW5pdEV4ZWN1dGlvbigpO1xyXG4gIH1cclxuXHJcbiAgZ2V0UmVzcG9uc2VBUERVKCk6IFJlc3BvbnNlQVBEVVxyXG4gIHtcclxuICAgIHZhciBwdWJsaWNUb3AgPSB0aGlzLnB1YmxpY0FyZWEuZ2V0TGVuZ3RoKCk7XHJcblxyXG4gICAgdmFyIGxhID0gQkEyVyggdGhpcy5wdWJsaWNBcmVhLnJlYWRCeXRlcyggcHVibGljVG9wIC0gNCwgMiApICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IEJBMlcoIHRoaXMucHVibGljQXJlYS5yZWFkQnl0ZXMoIHB1YmxpY1RvcCAtIDIsIDIgKSApLCBkYXRhOiB0aGlzLnB1YmxpY0FyZWEucmVhZEJ5dGVzKCAwLCBsYSApICB9IClcclxuXHJcbiAgfVxyXG5cclxuICBnZXQgZ2V0RGVidWcoKToge31cclxuICB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICByYW1TZWdtZW50OiB0aGlzLnJhbVNlZ21lbnQsXHJcbiAgICAgIGR5bmFtaWNBcmVhOiB0aGlzLmR5bmFtaWNBcmVhLFxyXG4gICAgICBwdWJsaWNBcmVhOiB0aGlzLnB1YmxpY0FyZWEsXHJcbiAgICAgIHN0YXRpY0FyZWE6IHRoaXMuc3RhdGljQXJlYSxcclxuICAgICAgY3VycmVudElQOiB0aGlzLmN1cnJlbnRJUCxcclxuICAgICAgZHluYW1pY1RvcDogdGhpcy5keW5hbWljVG9wLFxyXG4gICAgICBsb2NhbEJhc2U6IHRoaXMubG9jYWxCYXNlXHJcbiAgICB9O1xyXG4gIH1cclxuLy8gIGlzRXhlY3V0aW5nOiBmdW5jdGlvbigpIHsgcmV0dXJuIGlzRXhlY3V0aW5nOyB9LFxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5pbXBvcnQgeyBNZW1vcnlNYW5hZ2VyLCBNRU1GTEFHUyB9IGZyb20gJy4vbWVtb3J5LW1hbmFnZXInO1xyXG5pbXBvcnQgeyBNRUxWaXJ0dWFsTWFjaGluZSB9IGZyb20gJy4vdmlydHVhbC1tYWNoaW5lJztcclxuXHJcbmltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuLi9iYXNlL0lTTzc4MTYnO1xyXG5pbXBvcnQgeyBDb21tYW5kQVBEVSB9IGZyb20gJy4uL2Jhc2UvY29tbWFuZC1hcGR1JztcclxuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vYmFzZS9yZXNwb25zZS1hcGR1JztcclxuXHJcbmltcG9ydCB7IEpTSU1DYXJkIH0gZnJvbSAnLi4vanNpbS1jYXJkL2pzaW0tY2FyZCc7XHJcblxyXG5mdW5jdGlvbiAgQkEyVyggdmFsIClcclxue1xyXG4gIHJldHVybiAoIHZhbFsgMCBdIDw8IDggKSB8IHZhbFsgMSBdO1xyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgSlNJTU11bHRvc0FwcGxldFxyXG57XHJcbiAgc2Vzc2lvblNpemU7XHJcbiAgY29kZUFyZWE7XHJcbiAgc3RhdGljQXJlYTtcclxuXHJcbiAgY29uc3RydWN0b3IoIGNvZGVBcmVhLCBzdGF0aWNBcmVhLCBzZXNzaW9uU2l6ZSApXHJcbiAge1xyXG4gICAgdGhpcy5jb2RlQXJlYSA9IGNvZGVBcmVhO1xyXG4gICAgdGhpcy5zdGF0aWNBcmVhID0gc3RhdGljQXJlYTtcclxuICAgIHRoaXMuc2Vzc2lvblNpemUgPSBzZXNzaW9uU2l6ZTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBKU0lNTXVsdG9zQ2FyZCBpbXBsZW1lbnRzIEpTSU1DYXJkXHJcbntcclxuICBwcml2YXRlIGNhcmRDb25maWc7XHJcblxyXG4gIHN0YXRpYyBkZWZhdWx0Q29uZmlnID0ge1xyXG4gICAgcm9tU2l6ZTogMCxcclxuICAgIHJhbVNpemU6IDEwMjQsXHJcbiAgICBwdWJsaWNTaXplOiA1MTIsXHJcbiAgICBudnJhbVNpemU6IDMyNzY4XHJcbiAgfTtcclxuXHJcbiAgcHJpdmF0ZSBwb3dlcklzT246IGJvb2xlYW47XHJcbiAgcHJpdmF0ZSBhdHI6IEJ5dGVBcnJheTtcclxuXHJcbiAgYXBwbGV0czogeyBhaWQ6IEJ5dGVBcnJheSwgYXBwbGV0OiBKU0lNTXVsdG9zQXBwbGV0IH1bXTtcclxuXHJcbiAgc2VsZWN0ZWRBcHBsZXQ6IEpTSU1NdWx0b3NBcHBsZXQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCBjb25maWc/IClcclxuICB7XHJcbiAgICBpZiAoIGNvbmZpZyApXHJcbiAgICAgIHRoaXMuY2FyZENvbmZpZyA9IGNvbmZpZztcclxuICAgIGVsc2VcclxuICAgICAgdGhpcy5jYXJkQ29uZmlnID0gSlNJTU11bHRvc0NhcmQuZGVmYXVsdENvbmZpZztcclxuXHJcbiAgICB0aGlzLmF0ciA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcblxyXG4gICAgdGhpcy5hcHBsZXRzID0gW107XHJcbiAgfVxyXG5cclxuICBsb2FkQXBwbGljYXRpb24oIGFpZDogQnl0ZUFycmF5LCBhbHU6IEJ5dGVBcnJheSApXHJcbiAge1xyXG4gICAgdmFyIGxlbiA9IDA7XHJcblxyXG4gICAgdmFyIG9mZiA9IDg7XHJcblxyXG4gICAgLy8gTEVOOjpDT0RFXHJcbiAgICBsZW4gPSBhbHUud29yZEF0KCBvZmYgKTtcclxuICAgIG9mZiArPSAyO1xyXG5cclxuICAgIGxldCBjb2RlQXJlYSA9IHRoaXMubnZyYW1TZWdtZW50Lm5ld0FjY2Vzc29yKCAwLCBsZW4sIFwiY29kZVwiICk7XHJcbiAgICBjb2RlQXJlYS53cml0ZUJ5dGVzKCAwLCBhbHUudmlld0F0KCBvZmYsIGxlbiApICk7XHJcbiAgICBvZmYgKz0gbGVuO1xyXG5cclxuICAgIC8vIExFTjo6REFUQVxyXG4gICAgbGVuID0gYWx1LndvcmRBdCggb2ZmICk7XHJcbiAgICBvZmYgKz0gMjtcclxuXHJcbiAgICBsZXQgc3RhdGljQXJlYSA9IHRoaXMubnZyYW1TZWdtZW50Lm5ld0FjY2Vzc29yKCBjb2RlQXJlYS5nZXRMZW5ndGgoKSwgbGVuLCBcIlNcIiApO1xyXG4gICAgc3RhdGljQXJlYS53cml0ZUJ5dGVzKCAwLCBhbHUudmlld0F0KCBvZmYsIGxlbiApICk7XHJcbiAgICBvZmYgKz0gbGVuO1xyXG5cclxuICAgIGxldCBhcHBsZXQgPSBuZXcgSlNJTU11bHRvc0FwcGxldCggY29kZUFyZWEsIHN0YXRpY0FyZWEsIDAgKTtcclxuXHJcbiAgICB0aGlzLmFwcGxldHMucHVzaCggeyBhaWQ6IGFpZCwgYXBwbGV0OiBhcHBsZXQgfSApO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIGdldCBpc1Bvd2VyZWQoKTogYm9vbGVhblxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLnBvd2VySXNPbjtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PlxyXG4gIHtcclxuICAgIHRoaXMucG93ZXJJc09uID0gdHJ1ZTtcclxuXHJcbiAgICB0aGlzLmluaXRpYWxpemVWTSggdGhpcy5jYXJkQ29uZmlnICk7XHJcblxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSggdGhpcy5hdHIgKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBwb3dlck9mZigpOiBQcm9taXNlPGFueT5cclxuICB7XHJcbiAgICB0aGlzLnBvd2VySXNPbiA9IGZhbHNlO1xyXG5cclxuICAgIHRoaXMucmVzZXRWTSgpO1xyXG5cclxuICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XHJcblxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSggICk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcmVzZXQoKTogUHJvbWlzZTxCeXRlQXJyYXk+XHJcbiAge1xyXG4gICAgdGhpcy5wb3dlcklzT24gPSB0cnVlO1xyXG5cclxuICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XHJcblxyXG4gICAgdGhpcy5zaHV0ZG93blZNKCk7XHJcblxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSggdGhpcy5hdHIgKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBleGNoYW5nZUFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cclxuICB7XHJcbiAgICBpZiAoIGNvbW1hbmRBUERVLklOUyA9PSAweEE0IClcclxuICAgIHtcclxuICAgICAgaWYgKCB0aGlzLnNlbGVjdGVkQXBwbGV0IClcclxuICAgICAge1xyXG4gICAgICAgIC8vdGhpcy5zZWxlY3RlZEFwcGxldC5kZXNlbGVjdEFwcGxpY2F0aW9uKCk7XHJcblxyXG4gICAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB1bmRlZmluZWQ7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIC8vVE9ETzogTG9va3VwIEFwcGxpY2F0aW9uXHJcbiAgICAgIHRoaXMuc2VsZWN0ZWRBcHBsZXQgPSB0aGlzLmFwcGxldHNbIDAgXS5hcHBsZXQ7XHJcblxyXG4gICAgICBsZXQgZmNpID0gbmV3IEJ5dGVBcnJheSggWyAweDZGLCAweDAwIF0gKTtcclxuXHJcbiAgICAgIHRoaXMubXZtLnNldHVwQXBwbGljYXRpb24oIHRoaXMuc2VsZWN0ZWRBcHBsZXQgKTtcclxuXHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmU8UmVzcG9uc2VBUERVPiggbmV3IFJlc3BvbnNlQVBEVSggeyBzdzogMHg5MDAwLCBkYXRhOiBmY2kgIH0gKSApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMubXZtLnNldENvbW1hbmRBUERVKCBjb21tYW5kQVBEVSk7XHJcblxyXG4vLyAgICBnZXRSZXNwb25zZUFQRFUoKVxyXG4vLyAgICB7XHJcbi8vICAgICAgcmV0dXJuIHRoaXMubXZtLmdldFJlc3BvbnNlQVBEVSgpO1xyXG4vLyAgICB9XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4OTAwMCwgZGF0YTogW10gIH0gKSApO1xyXG5cclxuICAgIC8vcmV0dXJuIHRoaXMuZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVICk7XHJcbiAgfVxyXG5cclxuICBtZW1vcnlNYW5hZ2VyOiBNZW1vcnlNYW5hZ2VyO1xyXG5cclxuICAvLyBDYXJkIE1lbW9yeSBTZWdtZW50c1xyXG4gIHJvbVNlZ21lbnQ7ICAgICAgLy8gUk9NOiBjb2RlbGV0c1xyXG4gIG52cmFtU2VnbWVudDsgICAgLy8gTlZSQU06IGFwcGxldHMgY29kZSArIGRhdGFcclxuICByYW1TZWdtZW50OyAgICAgIC8vIFJBTTogd29ya3NwYWNlXHJcblxyXG4gIG12bTtcclxuXHJcbiAgaW5pdGlhbGl6ZVZNKCBjb25maWcgKVxyXG4gIHtcclxuICAgIHRoaXMubWVtb3J5TWFuYWdlciA9IG5ldyBNZW1vcnlNYW5hZ2VyKCk7XHJcblxyXG4gICAgdGhpcy5yb21TZWdtZW50ID0gdGhpcy5tZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQoIDAsIHRoaXMuY2FyZENvbmZpZy5yb21TaXplLCBNRU1GTEFHUy5SRUFEX09OTFkgKVxyXG4gICAgdGhpcy5yYW1TZWdtZW50ID0gdGhpcy5tZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQoIDEsIHRoaXMuY2FyZENvbmZpZy5yYW1TaXplLCAwICk7XHJcbiAgICB0aGlzLm52cmFtU2VnbWVudCA9IHRoaXMubWVtb3J5TWFuYWdlci5uZXdTZWdtZW50KCAyLCB0aGlzLmNhcmRDb25maWcubnZyYW1TaXplLCBNRU1GTEFHUy5UUkFOU0FDVElPTkFCTEUgKTtcclxuXHJcbiAgICB0aGlzLm12bSA9IG5ldyBNRUxWaXJ0dWFsTWFjaGluZSgpO1xyXG5cclxuICAgIHRoaXMucmVzZXRWTSgpO1xyXG4gIH1cclxuXHJcbiAgcmVzZXRWTSgpXHJcbiAge1xyXG4gICAgLy8gZmlyc3QgdGltZSAuLi5cclxuICAgIC8vIGluaXQgVmlydHVhbE1hY2hpbmVcclxuICAgIHZhciBtdm1QYXJhbXMgPSB7XHJcbiAgICAgIHJhbVNlZ21lbnQ6IHRoaXMucmFtU2VnbWVudCxcclxuICAgICAgcm9tU2VnbWVudDogdGhpcy5yb21TZWdtZW50LFxyXG4gICAgICBwdWJsaWNTaXplOiB0aGlzLmNhcmRDb25maWcucHVibGljU2l6ZVxyXG4gICAgfTtcclxuXHJcbiAgICB0aGlzLm12bS5pbml0TVZNKCBtdm1QYXJhbXMgKTtcclxuICB9XHJcblxyXG4gIHNodXRkb3duVk0oKVxyXG4gIHtcclxuICAgIHRoaXMucmVzZXRWTSgpO1xyXG4gICAgdGhpcy5tdm0gPSBudWxsO1xyXG4gIH1cclxuXHJcbiAgc2VsZWN0QXBwbGljYXRpb24oIGFwcGxldDogSlNJTU11bHRvc0FwcGxldCwgc2Vzc2lvblNpemUgKVxyXG4gIHtcclxuICAgIHZhciBleGVjUGFyYW1zID0ge1xyXG4gICAgICBjb2RlQXJlYTogYXBwbGV0LmNvZGVBcmVhLFxyXG4gICAgICBzdGF0aWNBcmVhOiBhcHBsZXQuc3RhdGljQXJlYSxcclxuICAgICAgc2Vzc2lvblNpemU6IHNlc3Npb25TaXplXHJcbiAgICB9O1xyXG5cclxuICAgIHRoaXMubXZtLmV4ZWNBcHBsaWNhdGlvbiggZXhlY1BhcmFtcyApO1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZVN0ZXAoKVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLm12bS5leGVjdXRlU3RlcCgpO1xyXG4gIH1cclxufVxyXG4iLCJ2YXIgc2V0WmVyb1ByaW1pdGl2ZXMgPVxyXG57XHJcbiAgMHgwMToge1xyXG4gICAgbmFtZTogXCJDSEVDS19DQVNFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICBcdCAgdmFyIGV4cGVjdGVkSVNPPSBwb3BCeXRlKCk7XHJcblxyXG4gIFx0ICBpZiAoZXhwZWN0ZWRJU088IDEgfHwgZXhwZWN0ZWRJU08+IDQpXHJcbiAgXHQgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG4gIFx0ICBlbHNlXHJcbiAgXHQgICAgU2V0Q0NSRmxhZyhaZmxhZywgQ2hlY2tJU09DYXNlKGV4cGVjdGVkSVNPQ2FzZSkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAyOiB7XHJcbiAgICBuYW1lOiBcIlJFU0VUX1dXVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHNlbmRXYWl0UmVxdWVzdCgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA1OiB7XHJcbiAgICBuYW1lOiBcIkxPQURfQ0NSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgcHVzaEJ5dGUoQ0NSKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA2OiB7XHJcbiAgICBuYW1lOiBcIlNUT1JFX0NDUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIENDUigpID0gcG9wQnl0ZSgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA3OiB7XHJcbiAgICBuYW1lOiBcIlNFVF9BVFJfRklMRV9SRUNPUkRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIGxlbiA9IGdldEJ5dGUoYWRkcik7XHJcblxyXG4gICAgICBNRUxBcHBsaWNhdGlvbiAqYSA9IHN0YXRlLmFwcGxpY2F0aW9uO1xyXG4gICAgICBpZiAoYS5BVFJGaWxlUmVjb3JkU2l6ZSlcclxuICAgICAgICBkZWxldGUgW11hLkFUUkZpbGVSZWNvcmQ7XHJcblxyXG4gICAgICBhLkFUUkZpbGVSZWNvcmRTaXplID0gbGVuO1xyXG5cclxuICAgICAgaWYgKGxlbilcclxuICAgICAge1xyXG4gICAgICAgIGEuQVRSRmlsZVJlY29yZCA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgICByZWFkKGFkZHIsIGxlbiwgYS5BVFJGaWxlUmVjb3JkKTtcclxuICAgICAgfVxyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIHB1c2hCeXRlKGxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDg6IHtcclxuICAgIG5hbWU6IFwiU0VUX0FUUl9ISVNUT1JJQ0FMX0NIQVJBQ1RFUlNcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIGxlbiA9IGdldEJ5dGUoYWRkcik7XHJcbiAgICAgIHZhciB3cml0dGVuO1xyXG4gICAgICB2YXIgb2theSA9IHNldEFUUkhpc3RvcmljYWxDaGFyYWN0ZXJzKGxlbiwgYWRkcisxLCB3cml0dGVuKTtcclxuXHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgcHVzaEJ5dGUod3JpdHRlbik7XHJcbiAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIHdyaXR0ZW4gPCBsZW4pO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCAhb2theSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDk6IHtcclxuICAgIG5hbWU6IFwiR0VUX01FTU9SWV9SRUxJQUJJTElUWVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGZhbHNlKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGE6IHtcclxuICAgIG5hbWU6IFwiTE9PS1VQXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIHZhbHVlID0gZ2V0Qnl0ZShkeW5hbWljVG9wLTMpO1xyXG4gICAgICB2YXIgYXJyQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpO1xyXG5cclxuICAgICAgdmFyIGFycmxlbiA9IGdldEJ5dGUoYXJyQWRkcik7XHJcbiAgICAgIGZvciAodmFyIGk9MDtpPGFycmxlbjtpKyspXHJcbiAgICAgICAgaWYgKGdldEJ5dGUoYXJyQWRkcitpKzEpID09IHZhbHVlKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWkpO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgdHJ1ZSk7XHJcbiAgICAgICAgICBpID0gYXJybGVuO1xyXG4gICAgICAgIH1cclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhiOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT01QQVJFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgdmFyIG9wMSA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIG9wMiA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIGJsb2NrQ29tcGFyZShvcDEsIG9wMiwgbGVuKTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM6IHtcclxuICAgIG5hbWU6IFwiTUVNT1JZX0NPUFlcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbnVtID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICB2YXIgZHN0ID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgc3JjID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgY29weShkc3QsIHNyYywgbnVtKTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGQ6IHtcclxuICAgIG5hbWU6IFwiUVVFUllfSU5URVJGQUNFX1RZUEVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBmYWxzZSk7IC8vIGNvbnRhY3RcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgxMDoge1xyXG4gICAgbmFtZTogXCJDT05UUk9MX0FVVE9fUkVTRVRfV1dUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgLy8gRG9lc24ndCBkbyBhbnl0aGluZ1xyXG4gICAgICBEVCgtMik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MTE6IHtcclxuICAgIG5hbWU6IFwiU0VUX0ZDSV9GSUxFX1JFQ09SRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0Qnl0ZShhZGRyKTtcclxuXHJcbiAgICAgIE1FTEFwcGxpY2F0aW9uICphID0gc3RhdGUuYXBwbGljYXRpb247XHJcblxyXG4gICAgICBpZiAoYS5GQ0lSZWNvcmRTaXplKVxyXG4gICAgICAgIGRlbGV0ZSBbXWEuRkNJUmVjb3JkO1xyXG5cclxuICAgICAgYS5GQ0lSZWNvcmRTaXplID0gbGVuO1xyXG4gICAgICBhLkZDSVJlY29yZCA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgcmVhZChhZGRyICsgMSwgbGVuLCBhLkZDSVJlY29yZCk7XHJcbiAgICAgIERUKC0yKTtcclxuICAgICAgcHVzaEJ5dGUobGVuKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MDoge1xyXG4gICAgbmFtZTogXCJERUxFR0FURVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIC8vIHJvbGxiYWNrIGFuZCB0dXJuIG9mZiB0cmFuc2FjdGlvbiBwcm90ZWN0aW9uXHJcbiAgICAgIHZhciBtID0gc3RhdGUuYXBwbGljYXRpb24uc3RhdGljRGF0YTtcclxuICAgICAgaWYgKG0ub24pXHJcbiAgICAgIHtcclxuICAgICAgICBtLmRpc2NhcmQoKTtcclxuICAgICAgICBtLm9uID0gZmFsc2U7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHZhciBBSURBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBEVCgtMik7XHJcblxyXG4gICAgICB2YXIgQUlEbGVuID0gZ2V0Qnl0ZShBSURBZGRyKTtcclxuICAgICAgaWYgKEFJRGxlbiA8IDEgfHwgQUlEbGVuID4gMTYpXHJcbiAgICAgICAgc2V0V29yZChQVCgpK1NXMSwgMHg2YTgzKTtcclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIEFJRCA9IG5ldyB2YXJbQUlEbGVuXTtcclxuXHJcbiAgICAgICAgcmVhZChBSURBZGRyKzEsIEFJRGxlbiwgQUlEKTtcclxuICAgICAgICBpZiAoIWRlbGVnYXRlQXBwbGljYXRpb24oQUlEbGVuLCBBSUQpKVxyXG4gICAgICAgICAgc2V0V29yZChQVCgpK1NXMSwgMHg2YTgzKTtcclxuICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgxOiB7XHJcbiAgICBuYW1lOiBcIlJFU0VUX1NFU1NJT05fREFUQVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGlmIChzdGF0ZS5hcHBsaWNhdGlvbi5pc1NoZWxsQXBwKVxyXG4gICAgICAgIFJlc2V0U2Vzc2lvbkRhdGEoKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4Mjoge1xyXG4gICAgbmFtZTogXCJDSEVDS1NVTVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW5ndGggPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgY2hlY2tzdW1bNF0gPSB7IDB4NWEsIDB4YTUsIDB4NWEsIDB4YTUgfTtcclxuXHJcbiAgICAgIHZhciBtID0gc3RhdGUuYXBwbGljYXRpb24uc3RhdGljRGF0YTtcclxuICAgICAgdmFyIGFjY291bnRGb3JUcmFuc2FjdGlvblByb3RlY3Rpb24gPSAoYWRkciA+PSBtLnN0YXJ0KCkgJiYgYWRkciA8PSBtLnN0YXJ0KCkgKyBtLnNpemUoKSAmJiBtLm9uKTtcclxuXHJcbiAgICAgIGZvciAodmFyIGo9MDsgaiA8IGxlbmd0aDsgaisrKVxyXG4gICAgICB7XHJcbiAgICAgICAgaWYgKGFjY291bnRGb3JUcmFuc2FjdGlvblByb3RlY3Rpb24pXHJcbiAgICAgICAgICBjaGVja3N1bVswXSArPSAodmFyKW0ucmVhZFBlbmRpbmdCeXRlTWVtb3J5KGFkZHIraik7XHJcbiAgICAgICAgZWxzZVxyXG4gICAgICAgICAgY2hlY2tzdW1bMF0gKz0gKHZhcilnZXRCeXRlKGFkZHIgKyBqKTtcclxuXHJcbiAgICAgICAgY2hlY2tzdW1bMV0gKz0gY2hlY2tzdW1bMF07XHJcbiAgICAgICAgY2hlY2tzdW1bMl0gKz0gY2hlY2tzdW1bMV07XHJcbiAgICAgICAgY2hlY2tzdW1bM10gKz0gY2hlY2tzdW1bMl07XHJcbiAgICAgIH1cclxuICAgICAgd3JpdGUoZHluYW1pY1RvcC00LCA0LCBjaGVja3N1bSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODM6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9DT0RFTEVUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGNvZGVsZXRJZCA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIGNvZGVhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgRFQoLTQpO1xyXG4gICAgICBjYWxsQ29kZWxldChjb2RlbGV0SWQsIGNvZGVhZGRyKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4NDoge1xyXG4gICAgbmFtZTogXCJRVUVSWV9DT0RFTEVUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGNvZGVsZXRJZCA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIHF1ZXJ5Q29kZWxldChjb2RlbGV0SWQpKTtcclxuICAgICAgRFQoLTIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGMxOiB7XHJcbiAgICBuYW1lOiBcIkRFU19FQ0JfRU5DSVBIRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksOCk7XHJcbiAgICAgIHZhciBwbGFpbnRleHRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIHZhciAqY2lwaGVydGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksOCk7XHJcbiAgICAgIHZhciBwbGFpbnRleHRbOF07XHJcblxyXG4gICAgICBtdGhfZGVzKERFU19ERUNSWVBULCBrZXksIGNpcGhlcnRleHQsIHBsYWludGV4dCk7XHJcbiAgICAgIHdyaXRlKHBsYWludGV4dEFkZHIsIDgsIHBsYWludGV4dCk7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjMjoge1xyXG4gICAgbmFtZTogXCJNT0RVTEFSX01VTFRJUExJQ0FUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG1vZGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgY29uc3QgdmFyICpsaHMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgbW9kbGVuKTtcclxuICAgICAgY29uc3QgdmFyICpyaHMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgbW9kbGVuKTtcclxuICAgICAgY29uc3QgdmFyICptb2QgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgbW9kbGVuKTtcclxuICAgICAgdmFyICpyZXMgPSBuZXcgdmFyW21vZGxlbl07XHJcbiAgICAgIG10aF9tb2RfbXVsdChsaHMsIG1vZGxlbiwgcmhzLCBtb2RsZW4sIG1vZCwgbW9kbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShnZXRXb3JkKGR5bmFtaWNUb3AtNiksIG1vZGxlbiwgcmVzKTtcclxuICAgICAgRFQoLTgpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGMzOiB7XHJcbiAgICBuYW1lOiBcIk1PRFVMQVJfUkVEVUNUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG9wbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICB2YXIgbW9kbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICBjb25zdCB2YXIgKm9wID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG9wbGVuKTtcclxuICAgICAgY29uc3QgdmFyICptb2QgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgb3BsZW4pO1xyXG4gICAgICB2YXIgKnJlcyA9IG5ldyB2YXJbb3BsZW5dO1xyXG4gICAgICBtdGhfbW9kX3JlZChvcCwgb3BsZW4sIG1vZCwgbW9kbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG9wbGVuLCByZXMpO1xyXG4gICAgICBEVCgtOCk7XHJcbiAgICAgIGRlbGV0ZSBbXXJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNDoge1xyXG4gICAgbmFtZTogXCJHRVRfUkFORE9NX05VTUJFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciByYW5kWzhdO1xyXG4gICAgICByYW5kZGF0YShyYW5kLCA4KTtcclxuICAgICAgRFQoOCk7XHJcbiAgICAgIHdyaXRlKGR5bmFtaWNUb3AtOCwgOCwgcmFuZCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzU6IHtcclxuICAgIG5hbWU6IFwiREVTX0VDQl9ERUNJUEhFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSw4KTtcclxuICAgICAgdmFyIGNpcGhlckFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgdmFyICpwbGFpbnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDIpLDgpO1xyXG4gICAgICB2YXIgY2lwaGVydGV4dFs4XTtcclxuXHJcbiAgICAgIG10aF9kZXMoREVTX0VOQ1JZUFQsIGtleSwgcGxhaW50ZXh0LCBjaXBoZXJ0ZXh0KTtcclxuICAgICAgd3JpdGUoY2lwaGVyQWRkciwgOCwgY2lwaGVydGV4dCk7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNjoge1xyXG4gICAgbmFtZTogXCJHRU5FUkFURV9ERVNfQ0JDX1NJR05BVFVSRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBwbGFpblRleHRMZW5ndGggPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHhhKTtcclxuICAgICAgdmFyIElWYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDgpO1xyXG4gICAgICB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksIDgpO1xyXG4gICAgICB2YXIgc2lnbmF0dXJlQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgKnBsYWluVGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksIHBsYWluVGV4dExlbmd0aCk7XHJcbiAgICAgIHZhciBzaWduYXR1cmVbOF07XHJcblxyXG4gICAgICByZWFkKElWYWRkciwgOCwgc2lnbmF0dXJlKTtcclxuICAgICAgd2hpbGUgKHBsYWluVGV4dExlbmd0aCA+PSA4KVxyXG4gICAgICB7XHJcbiAgICAgICAgZm9yICh2YXIgaT0wO2k8ODtpKyspXHJcbiAgICAgICAgICBzaWduYXR1cmVbaV0gXj0gcGxhaW5UZXh0W2ldO1xyXG5cclxuICAgICAgICB2YXIgZW5jcnlwdGVkU2lnbmF0dXJlWzhdO1xyXG5cclxuICAgICAgICBtdGhfZGVzKERFU19FTkNSWVBULCBrZXksIHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlKTtcclxuICAgICAgICBtZW1jcHkoc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUsIDgpO1xyXG4gICAgICAgIHBsYWluVGV4dExlbmd0aCAtPSA4O1xyXG4gICAgICAgIHBsYWluVGV4dCArPSA4O1xyXG4gICAgICB9XHJcbiAgICAgIHdyaXRlKHNpZ25hdHVyZUFkZHIsIDgsIHNpZ25hdHVyZSk7XHJcbiAgICAgIERUKC0xMCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Yzc6IHtcclxuICAgIG5hbWU6IFwiR0VORVJBVEVfVFJJUExFX0RFU19DQkNfU0lHTkFUVVJFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaW50IHBsYWluVGV4dExlbmd0aCA9IGdldFdvcmQoZHluYW1pY1RvcC0weGEpO1xyXG4gICAgICB2YXIgSVZhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4OCk7XHJcbiAgICAgIHZhciBrZXkxID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg2KSwgMTYpO1xyXG4gICAgICB2YXIga2V5MiA9IGtleTEgKyA4O1xyXG4gICAgICB2YXIgc2lnbmF0dXJlQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgcGxhaW5UZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSwgcGxhaW5UZXh0TGVuZ3RoKTtcclxuICAgICAgdmFyIHNpZ25hdHVyZVs4XTtcclxuXHJcbiAgICAgIHJlYWQoSVZhZGRyLCA4LCBzaWduYXR1cmUpO1xyXG4gICAgICB3aGlsZSAocGxhaW5UZXh0TGVuZ3RoID4gMClcclxuICAgICAge1xyXG4gICAgICAgIGZvciAodmFyIGk9MDtpPDg7aSsrKVxyXG4gICAgICAgICAgc2lnbmF0dXJlW2ldIF49IHBsYWluVGV4dFtpXTtcclxuXHJcbiAgICAgICAgdmFyIGVuY3J5cHRlZFNpZ25hdHVyZVs4XTtcclxuXHJcbiAgICAgICAgbXRoX2RlcyhERVNfRU5DUllQVCwga2V5MSwgc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUpO1xyXG4gICAgICAgIG10aF9kZXMoREVTX0RFQ1JZUFQsIGtleTIsIGVuY3J5cHRlZFNpZ25hdHVyZSwgc2lnbmF0dXJlKTtcclxuICAgICAgICBtdGhfZGVzKERFU19FTkNSWVBULCBrZXkxLCBzaWduYXR1cmUsIGVuY3J5cHRlZFNpZ25hdHVyZSk7XHJcbiAgICAgICAgbWVtY3B5KHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlLCA4KTtcclxuICAgICAgICBwbGFpblRleHRMZW5ndGggLT0gODtcclxuICAgICAgICBwbGFpblRleHQgKz0gODtcclxuICAgICAgfVxyXG4gICAgICB3cml0ZShzaWduYXR1cmVBZGRyLCA4LCBzaWduYXR1cmUpO1xyXG4gICAgICBEVCgtMTApO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM4OiB7XHJcbiAgICBuYW1lOiBcIk1PRFVMQVJfRVhQT05FTlRJQVRJT05cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgZXhwbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Yyk7XHJcbiAgICAgIHZhciBtb2RsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHhhKTtcclxuICAgICAgdmFyIGV4cG9uZW50ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg4KSwgZXhwbGVuKTtcclxuICAgICAgdmFyIG1vZCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksIG1vZGxlbik7XHJcbiAgICAgIHZhciBiYXNlID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KSwgbW9kbGVuKTtcclxuICAgICAgdmFyIHJlc0FkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKTtcclxuICAgICAgdmFyIHJlcyA9IG5ldyB2YXJbbW9kbGVuXTtcclxuXHJcbiAgICAgIG10aF9tb2RfZXhwKGJhc2UsIG1vZGxlbiwgZXhwb25lbnQsIGV4cGxlbiwgbW9kLCBtb2RsZW4sIHJlcyk7XHJcbiAgICAgIHdyaXRlKHJlc0FkZHIsIG1vZGxlbiwgcmVzKTtcclxuICAgICAgRFQoLTEyKTtcclxuXHJcbiAgICAgIGRlbGV0ZSBbXXJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjOToge1xyXG4gICAgbmFtZTogXCJNT0RVTEFSX0VYUE9ORU5USUFUSU9OX0NSVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgIHZhciBkcGRxID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtOCksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgdmFyIHBxdSAgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgbW9kdWx1c19sZW4gKiAzIC8gMik7XHJcbiAgICAgIHZhciBiYXNlID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgdmFyIG91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIHZhciByZXMgPSBuZXcgdmFyW21vZHVsdXNfbGVuXTtcclxuXHJcbiAgICAgIG10aF9tb2RfZXhwX2NydChtb2R1bHVzX2xlbiwgZHBkcSwgcHF1LCBiYXNlLCByZXMpO1xyXG4gICAgICB3cml0ZShvdXRBZGRyLCBtb2R1bHVzX2xlbiwgcmVzKTtcclxuICAgICAgRFQoLTEwKTtcclxuICAgICAgZGVsZXRlW10gcmVzO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGNhOiB7XHJcbiAgICBuYW1lOiBcIlNIQTFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgcGxhaW50ZXh0TGVuZ3RoID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Nik7XHJcbiAgICAgIHZhciBoYXNoRGlnZXN0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgcGxhaW50ZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSwgcGxhaW50ZXh0TGVuZ3RoKTtcclxuICAgICAgdmFyIGxvbmcgaGFzaERpZ2VzdFs1XTsgLy8gMjAgYnl0ZSBoYXNoXHJcblxyXG4gICAgICBtdGhfc2hhX2luaXQoaGFzaERpZ2VzdCk7XHJcblxyXG4gICAgICB3aGlsZSAocGxhaW50ZXh0TGVuZ3RoID4gNjQpXHJcbiAgICAgIHtcclxuICAgICAgICBtdGhfc2hhX3VwZGF0ZShoYXNoRGlnZXN0LCAodmFyICopcGxhaW50ZXh0KTtcclxuICAgICAgICBwbGFpbnRleHQgKz0gNjQ7XHJcbiAgICAgICAgcGxhaW50ZXh0TGVuZ3RoIC09IDY0O1xyXG4gICAgICB9XHJcblxyXG4gICAgICBtdGhfc2hhX2ZpbmFsKGhhc2hEaWdlc3QsICh2YXIgKilwbGFpbnRleHQsIHBsYWludGV4dExlbmd0aCk7XHJcblxyXG4gICAgICBmb3IgKGludCBpPTA7aTw1O2krKylcclxuICAgICAgICB3cml0ZU51bWJlcihoYXNoRGlnZXN0QWRkcisoaSo0KSwgNCwgaGFzaERpZ2VzdFtpXSk7XHJcblxyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Y2M6IHtcclxuICAgIG5hbWU6IFwiR0VORVJBVEVfUkFORE9NX1BSSU1FXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGdjZEZsYWcgPSBnZXRCeXRlKGR5bmFtaWNUb3AtMTMpO1xyXG4gICAgICB2YXIgY29uZiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMik7XHJcbiAgICAgIHZhciB0aW1lb3V0ID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgdmFyIHJnRXhwID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICBjb25zdCB2YXIgKm1pbkxvYyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCA0KTtcclxuICAgICAgY29uc3QgdmFyICptYXhMb2MgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgNCk7XHJcbiAgICAgIHZhciByZXNBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Mik7XHJcbiAgICAgIGlmICgocmdFeHAgPCA1KSB8fCAocmdFeHAgPiAyNTYpKVxyXG4gICAgICB7XHJcbiAgICAgICAgQWJlbmQoXCJyZ0V4cCBwYXJhbWV0ZXIgb3V0IG9mIHJhbmdlXCIpO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIHN0YXRpYyBjb25zdCB2bG9uZyBvbmUoMSk7XHJcbiAgICAgICAgc3RhdGljIGNvbnN0IHZsb25nIHRocmVlKDMpO1xyXG4gICAgICAgIHN0ZDo6dmVjdG9yPHZhcj4gY2FuZGlkYXRlKHJnRXhwKTtcclxuICAgICAgICBmb3IgKDs7KVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHN0ZDo6Z2VuZXJhdGUoY2FuZGlkYXRlLmJlZ2luKCksIGNhbmRpZGF0ZS5lbmQoKSwgcmFuZCk7XHJcbiAgICAgICAgICBpZiAoc3RkOjpsZXhpY29ncmFwaGljYWxfY29tcGFyZShcclxuICAgICAgICAgICAgICAgIGNhbmRpZGF0ZS5iZWdpbigpLCBjYW5kaWRhdGUuZW5kKCksXHJcbiAgICAgICAgICAgICAgICBtaW5Mb2MsIG1pbkxvYyArIDQpKVxyXG4gICAgICAgICAgICBjb250aW51ZTtcclxuICAgICAgICAgIGlmIChzdGQ6OmxleGljb2dyYXBoaWNhbF9jb21wYXJlKFxyXG4gICAgICAgICAgICAgICAgbWF4TG9jLCBtYXhMb2MgKyA0LFxyXG4gICAgICAgICAgICAgICAgY2FuZGlkYXRlLmJlZ2luKCksIGNhbmRpZGF0ZS5lbmQoKSkpXHJcbiAgICAgICAgICAgIGNvbnRpbnVlO1xyXG4gICAgICAgICAgdmxvbmcgdmxvbmdfY2FuZGlkYXRlKGNhbmRpZGF0ZS5zaXplKCksICZjYW5kaWRhdGVbMF0pO1xyXG4gICAgICAgICAgaWYgKDB4ODAgPT0gZ2NkRmxhZylcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgaWYgKG9uZSAhPSBnY2QodGhyZWUsIHZsb25nX2NhbmRpZGF0ZSkpXHJcbiAgICAgICAgICAgICAgY29udGludWU7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBpZiAoIWlzX3Byb2JhYmxlX3ByaW1lKHZsb25nX2NhbmRpZGF0ZSkpXHJcbiAgICAgICAgICAgIGNvbnRpbnVlO1xyXG5cclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuICAgICAgICB3cml0ZShyZXNBZGRyLCByZ0V4cCwgJmNhbmRpZGF0ZVswXSk7XHJcbiAgICAgICAgRFQoLTEzKTtcclxuICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGNkOiB7XHJcbiAgICBuYW1lOiBcIlNFRURfRUNCX0RFQ0lQSEVSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgc3RhdGljIGNvbnN0IHZhciBibG9ja19zaXplID0gMTY7XHJcblxyXG4gICAgICBjb25zdCB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBibG9ja19zaXplKTtcclxuICAgICAgdmFyIHJlc0FkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgY29uc3QgdmFyICpwbGFpbnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgYmxvY2tfc2l6ZSk7XHJcblxyXG4gICAgICB2YXIgYnVmZmVyW2Jsb2NrX3NpemVdO1xyXG4gICAgICBtZW1jcHkoYnVmZmVyLCBrZXksIGJsb2NrX3NpemUpO1xyXG4gICAgICBEV09SRCByb3VuZF9rZXlbMiAqIGJsb2NrX3NpemVdO1xyXG4gICAgICBTZWVkRW5jUm91bmRLZXkocm91bmRfa2V5LCBidWZmZXIpO1xyXG4gICAgICBtZW1jcHkoYnVmZmVyLCBwbGFpbnRleHQsIGJsb2NrX3NpemUpO1xyXG4gICAgICBTZWVkRGVjcnlwdChidWZmZXIsIHJvdW5kX2tleSk7XHJcblxyXG4gICAgICB3cml0ZShyZXNBZGRyLCBibG9ja19zaXplLCBidWZmZXIpO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Y2U6IHtcclxuICAgIG5hbWU6IFwiU0VFRF9FQ0JfRU5DSVBIRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBzdGF0aWMgY29uc3QgdmFyIGJsb2NrX3NpemUgPSAxNjtcclxuXHJcbiAgICAgIGNvbnN0IHZhciAqa2V5ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIGJsb2NrX3NpemUpO1xyXG4gICAgICB2YXIgcmVzQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICBjb25zdCB2YXIgKnBsYWludGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBibG9ja19zaXplKTtcclxuXHJcbiAgICAgIHZhciBidWZmZXJbYmxvY2tfc2l6ZV07XHJcbiAgICAgIG1lbWNweShidWZmZXIsIGtleSwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIERXT1JEIHJvdW5kX2tleVsyICogYmxvY2tfc2l6ZV07XHJcbiAgICAgIFNlZWRFbmNSb3VuZEtleShyb3VuZF9rZXksIGJ1ZmZlcik7XHJcbiAgICAgIG1lbWNweShidWZmZXIsIHBsYWludGV4dCwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIFNlZWRFbmNyeXB0KGJ1ZmZlciwgcm91bmRfa2V5KTtcclxuXHJcbiAgICAgIHdyaXRlKHJlc0FkZHIsIGJsb2NrX3NpemUsIGJ1ZmZlcik7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH1cclxufTtcclxuXHJcbnZhciBzZXRPbmVQcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDA6IHtcclxuICAgIG5hbWU6IFwiUVVFUlkwXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaSA9IHByaW0wLmZpbmQoYXJnMSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGkgIT0gcHJpbTAuZW5kKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAxOiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZMVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGkgPSBwcmltMS5maW5kKGFyZzEpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBpICE9IHByaW0xLmVuZCgpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMjoge1xyXG4gICAgbmFtZTogXCJRVUVSWTJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpID0gcHJpbTIuZmluZChhcmcxKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgaSAhPSBwcmltMi5lbmQoKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDM6IHtcclxuICAgIG5hbWU6IFwiUVVFUlkzXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaSA9IHByaW0zLmZpbmQoYXJnMSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGkgIT0gcHJpbTMuZW5kKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA4OiB7XHJcbiAgICBuYW1lOiBcIkRJVklERU5cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gYXJnMTtcclxuICAgICAgdmFyICpkZW5vbWluYXRvciA9IGR1bXAoZHluYW1pY1RvcC1sZW4sIGxlbik7XHJcbiAgICAgIGlmIChibG9ja0lzWmVybyhkZW5vbWluYXRvciwgbGVuKSlcclxuICAgICAge1xyXG4gICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIHRydWUpO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIGNvbnN0IHZhciAqbnVtZXJhdG9yID0gZHVtcChkeW5hbWljVG9wLTIqbGVuLCBsZW4pO1xyXG4gICAgICAgIHZhciAqcXVvdGllbnQgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgICAgdmFyICpyZW1haW5kZXIgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgICAgbXRoX2RpdihudW1lcmF0b3IsIGRlbm9taW5hdG9yLCBsZW4sIHF1b3RpZW50LCByZW1haW5kZXIpO1xyXG4gICAgICAgIHdyaXRlKGR5bmFtaWNUb3AtMipsZW4sIGxlbiwgcXVvdGllbnQpO1xyXG4gICAgICAgIHdyaXRlKGR5bmFtaWNUb3AtbGVuLCBsZW4sIHJlbWFpbmRlcik7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgZmFsc2UpO1xyXG4gICAgICAgIFNldENDUkZsYWcoWmZsYWcsIGJsb2NrSXNaZXJvKHF1b3RpZW50LGxlbikpO1xyXG4gICAgICAgIGRlbGV0ZSBbXXF1b3RpZW50O1xyXG4gICAgICAgIGRlbGV0ZSBbXXJlbWFpbmRlcjtcclxuICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA5OiB7XHJcbiAgICBuYW1lOiBcIkdFVF9ESVJfRklMRV9SRUNPUkRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICAvLyBTYW1lIGFzIGJlbG93XHJcbiAgICAgIE1VTFRPUy5QcmltaXRpdmVzLnNldE9uZVByaW1pdGl2ZXNbIDB4MGEgXS5wcm9jKCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGE6IHtcclxuICAgIG5hbWU6IFwiR0VUX0ZJTEVfQ09OVFJPTF9JTkZPUk1BVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW4gPSBhcmcxO1xyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0zKTtcclxuICAgICAgdmFyIHJlY29yZE51bWJlciA9IGdldEJ5dGUoZHluYW1pY1RvcC0xKTtcclxuICAgICAgdmFyIG9rYXk7XHJcbiAgICAgIHZhciAqZGF0YTtcclxuICAgICAgdmFyIGRhdGFsZW47XHJcbiAgICAgIGlmIChwcmltID09IEdFVF9ESVJfRklMRV9SRUNPUkQpXHJcbiAgICAgICAgb2theSA9IGdldERpckZpbGVSZWNvcmQocmVjb3JkTnVtYmVyLTEsICZkYXRhbGVuLCAmZGF0YSk7XHJcbiAgICAgIGVsc2VcclxuICAgICAgICBva2F5ID0gZ2V0RkNJKHJlY29yZE51bWJlci0xLCAmZGF0YWxlbiwgJmRhdGEpO1xyXG4gICAgICBpZiAob2theSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgY29waWVkID0gbGVuIDwgZGF0YWxlbiA/IGxlbiA6IGRhdGFsZW47XHJcbiAgICAgICAgICBpZiAoY29waWVkKVxyXG4gICAgICAgICAgICB3cml0ZShhZGRyLCBjb3BpZWQsIGRhdGEpO1xyXG4gICAgICAgICAgcHVzaEJ5dGUoY29waWVkKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIChjb3BpZWQgPCBsZW4pKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoWmZsYWcsIDApO1xyXG4gICAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHB1c2hCeXRlKDApO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgMSk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCAxKTtcclxuICAgICAgICB9XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGI6IHtcclxuICAgIG5hbWU6IFwiR0VUX01BTlVGQUNUVVJFUl9EQVRBXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIERUKC0xKTtcclxuICAgICAgdmFyIG1hbnVmYWN0dXJlclsyNTZdO1xyXG4gICAgICB2YXIgbGVuID0gZ2V0TWFudWZhY3R1cmVyRGF0YShtYW51ZmFjdHVyZXIpO1xyXG4gICAgICBsZW4gPSBhcmcxIDwgbGVuID8gYXJnMSA6IGxlbjtcclxuICAgICAgaWYgKGxlbilcclxuICAgICAgICB3cml0ZShhZGRyLCBsZW4sIG1hbnVmYWN0dXJlcik7XHJcbiAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGM6IHtcclxuICAgIG5hbWU6IFwiR0VUX01VTFRPU19EQVRBXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIERUKC0xKTtcclxuICAgICAgdmFyIE1VTFRPU0RhdGFbMjU2XTtcclxuICAgICAgdmFyIGxlbiA9IGdldE1VTFRPU0RhdGEoTVVMVE9TRGF0YSk7XHJcbiAgICAgIGlmIChsZW4pXHJcbiAgICAgICAgbGVuID0gYXJnMSA8IGxlbiA/IGFyZzEgOiBsZW47XHJcbiAgICAgIHdyaXRlKGFkZHIsIGxlbiwgTVVMVE9TRGF0YSk7XHJcbiAgICAgIHNldEJ5dGUoZHluYW1pY1RvcC0xLCAodmFyKWxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MGQ6IHtcclxuICAgIG5hbWU6IFwiR0VUX1BVUlNFX1RZUEVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBlOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT1BZX0ZJWEVEX0xFTkdUSFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBkc3QgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBzcmMgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBjb3B5KGRzdCwgc3JjLCBhcmcxKTtcclxuICAgICAgRFQoLTQpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBmOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT01QQVJFX0ZJWEVEX0xFTkdUSFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBvcDEgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBvcDIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIGJsb2NrQ29tcGFyZShvcDEsIG9wMiwgYXJnMSk7XHJcbiAgICAgIERUKC00KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgxMDoge1xyXG4gICAgbmFtZTogXCJNVUxUSVBMWU5cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gYXJnMTtcclxuICAgICAgY29uc3QgdmFyICpvcDEgPSBkdW1wKGR5bmFtaWNUb3AtMipsZW4sIGxlbik7XHJcbiAgICAgIGNvbnN0IHZhciAqb3AyID0gZHVtcChkeW5hbWljVG9wLWxlbiwgbGVuKTtcclxuICAgICAgdmFyICpyZXMgPSBuZXcgdmFyW2xlbioyXTtcclxuICAgICAgbXRoX211bChvcDEsIG9wMiwgbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShkeW5hbWljVG9wLTIqbGVuLCBsZW4qMiwgcmVzKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgYmxvY2tJc1plcm8ocmVzLGxlbioyKSk7XHJcbiAgICAgIGRlbGV0ZSBbXXJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MDoge1xyXG4gICAgbmFtZTogXCJTRVRfVFJBTlNBQ1RJT05fUFJPVEVDVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBtID0gc3RhdGUuYXBwbGljYXRpb24uc3RhdGljRGF0YTtcclxuICAgICAgaWYgKG0ub24pXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgaWYgKGFyZzEgJiAxKVxyXG4gICAgICAgICAgICBtLmNvbW1pdCgpO1xyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICBtLmRpc2NhcmQoKTtcclxuICAgICAgICB9XHJcbiAgICAgIGlmIChhcmcxICYgMilcclxuICAgICAgICBtLm9uID0gdHJ1ZTtcclxuICAgICAgZWxzZVxyXG4gICAgICAgIG0ub24gPSBmYWxzZTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MToge1xyXG4gICAgbmFtZTogXCJHRVRfREVMRUdBVE9SX0FJRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBBSURBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIE1FTEV4ZWN1dGlvblN0YXRlICplID0gZ2V0RGVsZWdhdG9yU3RhdGUoKTtcclxuICAgICAgaWYgKGUpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIGxlbjtcclxuICAgICAgICAgIGlmICggYXJnMSA8IGUuYXBwbGljYXRpb24uQUlEbGVuZ3RoKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgbGVuID0gYXJnMTtcclxuICAgICAgICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCB0cnVlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgbGVuID0gIGUuYXBwbGljYXRpb24uQUlEbGVuZ3RoO1xyXG4gICAgICAgICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGZhbHNlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgc2V0Qnl0ZShBSURBZGRyLCAodmFyKWxlbik7XHJcbiAgICAgICAgICBBSURBZGRyKys7XHJcbiAgICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCBsZW47IGkrKylcclxuICAgICAgICAgICAgc2V0Qnl0ZShBSURBZGRyK2ksIGUuYXBwbGljYXRpb24uQUlEW2ldKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoWmZsYWcsIGZhbHNlKTtcclxuICAgICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCB0cnVlKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjNDoge1xyXG4gICAgbmFtZTogXCJHRU5FUkFURV9BU1lNTUVUUklDX0hBU0hcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBjb25zdCB2YXIgKml2O1xyXG4gICAgICB2YXIgcGxhaW5fbGVuO1xyXG4gICAgICB2YXIgZGlnZXN0T3V0QWRkcjtcclxuICAgICAgY29uc3QgdmFyICpwbGFpbjtcclxuICAgICAgTUVMS2V5KiBhaGFzaEtleTtcclxuICAgICAgaW50IGR0dmFsO1xyXG4gICAgICBzdGQ6OmF1dG9fcHRyPFNpbXBsZU1FTEtleVdyYXBwZXI+IHNta3c7XHJcbiAgICAgIHZhciBoY2wgPSAxNjtcclxuXHJcbiAgICAgIHN3aXRjaCAoYXJnMSlcclxuICAgICAge1xyXG4gICAgICAgIGNhc2UgMDpcclxuICAgICAgICAgIGl2ID0gMDtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTIpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBnZXRBSGFzaEtleSgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtNjtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIDE6XHJcbiAgICAgICAgICBpdiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTgpLCAxNik7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gZ2V0QUhhc2hLZXkoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTY7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSAyOlxyXG4gICAgICAgICAgaXYgPSAwO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtOCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXNfbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTEwO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgMzpcclxuICAgICAgICAgIGl2ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMTIpLCAxNik7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgICAgICBjb25zdCB2YXIqIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTEyO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgNDpcclxuICAgICAgICAgIGl2ID0gMDtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMik7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtOCksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgICAgICBjb25zdCB2YXIqIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGhjbCA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgICAgIGR0dmFsID0gLTEyO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgNTpcclxuICAgICAgICAgIGhjbCA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgICAgIGl2ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMTQpLCBoY2wpO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEyKTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC04KSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgICAgIGNvbnN0IHZhciogbW9kdWx1cyA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgICAgICBzbWt3ID0gc3RkOjphdXRvX3B0cjxTaW1wbGVNRUxLZXlXcmFwcGVyPihuZXcgU2ltcGxlTUVMS2V5V3JhcHBlcihtb2R1bHVzX2xlbiwgbW9kdWx1cykpO1xyXG4gICAgICAgICAgYWhhc2hLZXkgPSBzbWt3LmdldCgpO1xyXG4gICAgICAgICAgZHR2YWwgPSAtMTQ7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgIEFiZW5kKFwiYmFkIGIyIHZhbHVlIGZvciBHZW5lcmF0ZUFzeW1tZXRyaWNIYXNoIHByaW1pdGl2ZVwiKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBzdGQ6OnZlY3Rvcjx2YXI+IGhhc2goaGNsKTtcclxuICAgICAgQUhhc2goYWhhc2hLZXksIHBsYWluX2xlbiwgcGxhaW4sICZoYXNoWzBdLCBpdiwgaGNsKTtcclxuICAgICAgd3JpdGUoZGlnZXN0T3V0QWRkciwgaGNsLCAmaGFzaFswXSk7XHJcbiAgICAgIERUKGR0dmFsKTtcclxuICAgICovfVxyXG4gIH1cclxufTtcclxuXHJcbmZ1bmN0aW9uIGJpdE1hbmlwdWxhdGUoYml0bWFwLCBsaXRlcmFsLCBkYXRhKVxyXG57XHJcbiAgdmFyIG1vZGlmeSA9ICgoYml0bWFwICYgKDE8PDcpKSA9PSAoMTw8NykpO1xyXG4gIGlmIChiaXRtYXAgJiAweDdjKSAvLyBiaXRzIDYtMiBzaG91bGQgYmUgemVyb1xyXG4gICAgdGhyb3cgbmV3IEVycm9yKCBcIlVuZGVmaW5lZCBhcmd1bWVudHNcIik7XHJcblxyXG4gIHN3aXRjaCAoYml0bWFwICYgMylcclxuICB7XHJcbiAgICBjYXNlIDM6XHJcbiAgICAgIGRhdGEgJj0gbGl0ZXJhbDtcclxuICAgICAgYnJlYWs7XHJcbiAgICBjYXNlIDI6XHJcbiAgICAgIGRhdGEgfD0gbGl0ZXJhbDtcclxuICAgICAgYnJlYWs7XHJcbiAgICBjYXNlIDE6XHJcbiAgICAgIGRhdGEgPSB+KGRhdGEgXiBsaXRlcmFsKTtcclxuICAgICAgYnJlYWs7XHJcbiAgICBjYXNlIDA6XHJcbiAgICAgIGRhdGEgXj0gbGl0ZXJhbDtcclxuICAgICAgYnJlYWs7XHJcbiAgfVxyXG5cclxuICAvL1NldENDUkZsYWcoWmZsYWcsIGRhdGE9PTApO1xyXG5cclxuICByZXR1cm4gbW9kaWZ5OyAvL1RPRE86IHJldHVybiBkYXRhXHJcbn1cclxuXHJcbnZhciBzZXRUd29QcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDE6IHtcclxuICAgIG5hbWU6IFwiQklUX01BTklQVUxBVEVfQllURVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qLypcclxuICAgICAgdmFyIGIgPSBnZXRCeXRlKGR5bmFtaWNUb3AtMSk7XHJcblxyXG4gICAgICBpZiAoYml0TWFuaXB1bGF0ZShhcmcxLCBhcmcyLCBiKSlcclxuICAgICAgICBzZXRCeXRlKGR5bmFtaWNUb3AtMSwgKHZhciliKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMjoge1xyXG4gICAgbmFtZTogXCJTSElGVF9MRUZUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgLy8gc2FtZSBhcyBTSElGVF9SSUdIVFxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAzOiB7XHJcbiAgICBuYW1lOiBcIlNISUZUX1JJR0hUXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGFyZzE7XHJcbiAgICAgIHZhciBudW1TaGlmdEJpdHMgPSBhcmcyO1xyXG4gICAgICBpZiAoIWxlbiB8fCAhbnVtU2hpZnRCaXRzIHx8IG51bVNoaWZ0Qml0cz49OCpsZW4pXHJcbiAgICAgICAgQWJlbmQoXCJ1bmRlZmluZWQgc2hpZnQgYXJndW1lbnRzXCIpO1xyXG5cclxuICAgICAgdmFyICpkYXRhID0gbmV3IHZhcltsZW5dO1xyXG4gICAgICByZWFkKGR5bmFtaWNUb3AtbGVuLCBsZW4sIGRhdGEpO1xyXG5cclxuICAgICAgaWYgKHByaW0gPT0gU0hJRlRfTEVGVClcclxuICAgICAge1xyXG4gICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGJsb2NrQml0U2V0KGxlbiwgZGF0YSwgbGVuKjgtbnVtU2hpZnRCaXRzKSk7XHJcbiAgICAgICAgbXRoX3NobChkYXRhLCBsZW4sIG51bVNoaWZ0Qml0cyk7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgYmxvY2tCaXRTZXQobGVuLCBkYXRhLCBudW1TaGlmdEJpdHMtMSkpO1xyXG4gICAgICAgIG10aF9zaHIoZGF0YSwgbGVuLCBudW1TaGlmdEJpdHMpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB3cml0ZShkeW5hbWljVG9wLWxlbiwgbGVuLCBkYXRhKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgYmxvY2tJc1plcm8oZGF0YSxsZW4pKTtcclxuICAgICAgZGVsZXRlIFtdZGF0YTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwNDoge1xyXG4gICAgbmFtZTogXCJTRVRfU0VMRUNUX1NXXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgc2V0U2VsZWN0U1coYXJnMSwgYXJnMik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDU6IHtcclxuICAgIG5hbWU6IFwiQ0FSRF9CTE9DS1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODA6IHtcclxuICAgIG5hbWU6IFwiUkVUVVJOX0ZST01fQ09ERUxFVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHJldHVybkZyb21Db2RlbGV0KGFyZzEsIGFyZzIpO1xyXG4gICAgKi99XHJcbiAgfVxyXG59XHJcblxyXG52YXIgc2V0VGhyZWVQcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDE6IHtcclxuICAgIG5hbWU6IFwiQklUX01BTklQVUxBVEVfV09SRFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciB3ID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgaWYgKGJpdE1hbmlwdWxhdGUoYXJnMSwgbWtXb3JkKGFyZzIsIGFyZzMpLCB3KSlcclxuICAgICAgICBzZXRXb3JkKGR5bmFtaWNUb3AtMiwgdyk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODA6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFMFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODE6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFMVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODI6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFMlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODM6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFM1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODQ6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFNFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODU6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFNVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODY6IHtcclxuICAgIG5hbWU6IFwiQ0FMTF9FWFRFTlNJT05fUFJJTUlUSVZFNlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIEFiZW5kKFwicHJpbWl0aXZlIG5vdCBzdXBwb3J0ZWRcIik7XHJcbiAgICAqL31cclxuICB9XHJcbn07XHJcblxyXG52YXIgcHJpbWl0aXZlU2V0cyA9IFtcclxuICBzZXRaZXJvUHJpbWl0aXZlcyxcclxuICBzZXRPbmVQcmltaXRpdmVzLFxyXG4gIHNldFR3b1ByaW1pdGl2ZXMsXHJcbiAgc2V0VGhyZWVQcmltaXRpdmVzXHJcbl07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gY2FsbFByaW1pdGl2ZSggY3R4LCBwcmltLCBzZXQsIGFyZzEsIGFyZzIsIGFyZzMgKVxyXG57XHJcbiAgdmFyIHByaW1JbmZvID0gcHJpbWl0aXZlU2V0c1sgc2V0IF1bIHByaW0gXTtcclxuXHJcbiAgaWYgKCBwcmltSW5mbyApXHJcbiAge1xyXG4gICAgc3dpdGNoKCBzZXQgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIDA6IHByaW1JbmZvLnByb2MoKTsgYnJlYWs7XHJcbiAgICAgIGNhc2UgMTogcHJpbUluZm8ucHJvYyggYXJnMSApOyBicmVhaztcclxuICAgICAgY2FzZSAyOiBwcmltSW5mby5wcm9jKCBhcmcxLCBhcmcyICk7IGJyZWFrO1xyXG4gICAgICBjYXNlIDM6IHByaW1JbmZvLnByb2MoIGFyZzEsIGFyZzIsIGFyZzMgKTsgYnJlYWs7XHJcbiAgICB9XHJcbiAgfVxyXG4gIGVsc2VcclxuICB7XHJcbiAgICAvLyBubyBwcmltXHJcbiAgICB0aHJvdyBuZXcgRXJyb3IoIFwiUHJpbWl0aXZlIG5vdCBJbXBsZW1lbnRlZFwiICk7XHJcbiAgfVxyXG59XHJcbiIsImV4cG9ydCBjbGFzcyBTZWN1cml0eU1hbmFnZXJcclxue1xyXG4gIGluaXRTZWN1cml0eSgpXHJcbiAge1xyXG4gIH1cclxuXHJcbiAgcHJvY2Vzc0FQRFUoIGFwZHUgKVxyXG4gIHtcclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LEtpbmQsS2luZEluZm8gfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuZXhwb3J0IGNsYXNzIEFEQ1xue1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LEtpbmQsS2luZEluZm8gfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcblxuZXhwb3J0IGNsYXNzIEFMQ1xue1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LCBLaW5kLCBLaW5kSW5mbywgS2luZEJ1aWxkZXIgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbi8qKlxyXG4gKiBFbmNvZGVyL0RlY29kb3IgZm9yIGEgTVVMVE9TIEFwcGxpY2F0aW9uIExvYWQgVW5pdFxyXG4gKi9cclxuZXhwb3J0IGNsYXNzIEFMVSBpbXBsZW1lbnRzIEtpbmRcclxue1xyXG4gIHN0YXRpYyBraW5kSW5mbzogS2luZEluZm87XHJcblxyXG4gIGNvZGU6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcclxuICBkYXRhOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcbiAgZmNpOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcbiAgZGlyOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcblxyXG4gIC8qKlxyXG4gICAqIEBjb25zdHJ1Y3RvclxyXG4gICAqL1xyXG4gIGNvbnN0cnVjdG9yKCBhdHRyaWJ1dGVzPzoge30gKVxyXG4gIHtcclxuICAgIGlmICggYXR0cmlidXRlcyApXHJcbiAgICB7XHJcbiAgICAgIGZvciggbGV0IGZpZWxkIGluIEFMVS5raW5kSW5mby5maWVsZHMgKVxyXG4gICAgICAgIGlmICggYXR0cmlidXRlc1sgZmllbGQuaWQgXSApXHJcbiAgICAgICAgICB0aGlzWyBmaWVsZC5pZCBdID0gYXR0cmlidXRlc1sgZmllbGQuaWQgXTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFNlcmlhbGl6YXRpb24sIHJldHVybnMgYSBKU09OIG9iamVjdFxyXG4gICAqL1xyXG4gIHB1YmxpYyB0b0pTT04oKToge31cclxuICB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBjb2RlOiB0aGlzLmNvZGUsXHJcbiAgICAgIGRhdGE6IHRoaXMuZGF0YSxcclxuICAgICAgZmNpOiB0aGlzLmZjaSxcclxuICAgICAgZGlyOiB0aGlzLmRpclxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgZ2V0QUxVU2VnbWVudCggYnl0ZXM6IEJ5dGVBcnJheSwgc2VnbWVudElEOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHZhciBvZmZzZXQgPSA4O1xyXG5cclxuICAgIHdoaWxlKCAoIHNlZ21lbnRJRCA+IDEgKSAmJiAoIG9mZnNldCA8IGJ5dGVzLmxlbmd0aCApIClcclxuICAgIHtcclxuICAgICAgb2Zmc2V0ICs9IDIgKyBieXRlcy53b3JkQXQoIG9mZnNldCApO1xyXG4gICAgICAtLXNlZ21lbnRJRDtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gYnl0ZXMudmlld0F0KCBvZmZzZXQgKyAyLCBieXRlcy53b3JkQXQoIG9mZnNldCApICk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBEZWNvZGVyIGZhY3RvcnkgZnVuY3Rpb24sIGRlY29kZXMgYSBibG9iIGludG8gYSBNdWx0b3NBTFUgb2JqZWN0XHJcbiAgICovXHJcbiAgcHVibGljIGRlY29kZUJ5dGVzKCBieXRlczogQnl0ZUFycmF5LCBvcHRpb25zPzogT2JqZWN0ICk6IEFMVVxyXG4gIHtcclxuICAgIHRoaXMuY29kZSA9IHRoaXMuZ2V0QUxVU2VnbWVudCggYnl0ZXMsIDEgKTtcclxuICAgIHRoaXMuZGF0YSA9IHRoaXMuZ2V0QUxVU2VnbWVudCggYnl0ZXMsIDIgKTtcclxuICAgIHRoaXMuZGlyID0gdGhpcy5nZXRBTFVTZWdtZW50KCBieXRlcywgMyApO1xyXG4gICAgdGhpcy5mY2kgPSB0aGlzLmdldEFMVVNlZ21lbnQoIGJ5dGVzLCA0ICk7XHJcblxyXG4gICAgcmV0dXJuIHRoaXM7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBFbmNvZGVyIGZ1bmN0aW9uLCByZXR1cm5zIGEgYmxvYiBmcm9tIGEgTXVsdG9zQUxVIG9iamVjdFxyXG4gICAqL1xyXG4gIHB1YmxpYyBlbmNvZGVCeXRlcyggb3B0aW9ucz86IHt9ICk6IEJ5dGVBcnJheVxyXG4gIHtcclxuICAgIC8vQCBUT0RPOiByZWJ1aWxkIGJpbmFyeSBBTFVcclxuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCBbXSApO1xyXG4gIH1cclxufVxyXG5cclxuS2luZEJ1aWxkZXIuaW5pdCggQUxVLCBcIk1VTFRPUyBBcHBsaWNhdGlvbiBMb2FkIFVuaXRcIiApXHJcbiAgLmZpZWxkKCBcImNvZGVcIiwgXCJDb2RlIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICAuZmllbGQoIFwiZGF0YVwiLCBcIkRhdGEgU2VnbWVudFwiLCBCeXRlQXJyYXkgKVxyXG4gIC5maWVsZCggXCJmY2lcIiwgXCJGQ0kgU2VnbWVudFwiLCBCeXRlQXJyYXkgKVxyXG4gIC5maWVsZCggXCJkaXJcIiwgXCJESVIgU2VnbWVudFwiLCBCeXRlQXJyYXkgKVxyXG4gIDtcclxuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
