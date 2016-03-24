  import { ByteArray, Kind, KindBuilder, Message, ByteEncoding } from 'cryptographix-sim-core';

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
        this.endPoint.onMessage(null);
        this.endPoint = null;
        this.slot = null;
    }
    onMessage(packet, receivingEndPoint) {
        let hdr = packet.header;
        let payload = packet.payload;
        let response;
        switch (hdr.method) {
            case "executeAPDU":
                if (!(payload instanceof CommandAPDU))
                    break;
                response = this.slot.executeAPDU(payload);
                response.then((responseAPDU) => {
                    let replyPacket = new Message({ method: "executeAPDU" }, responseAPDU);
                    receivingEndPoint.sendMessage(replyPacket);
                });
                break;
            case "powerOff":
                response = this.slot.powerOff()
                    .then((respData) => {
                    receivingEndPoint.sendMessage(new Message({ method: hdr.method }, new ByteArray()));
                });
                break;
            case "powerOn":
                response = this.slot.powerOn()
                    .then((respData) => {
                    receivingEndPoint.sendMessage(new Message({ method: hdr.method }, respData));
                });
                break;
            case "reset":
                response = this.slot.reset()
                    .then((respData) => {
                    receivingEndPoint.sendMessage(new Message({ method: hdr.method }, respData));
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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImJhc2UvYmFzZS10bHYudHMiLCJiYXNlL2NvbW1hbmQtYXBkdS50cyIsImJhc2UvaXNvNzgxNi50cyIsImJhc2UvcmVzcG9uc2UtYXBkdS50cyIsImJhc2Uvc2xvdC5qcyIsImJhc2Uvc2xvdC1wcm90b2NvbC1oYW5kbGVyLnRzIiwiY29tcG9uZW50cy9ieXRlLWRhdGEtaW5wdXQuanMiLCJjb21wb25lbnRzL2J5dGUtZGF0YS1vdXRwdXQuanMiLCJjb21wb25lbnRzL2NyeXB0b3ItYm94LmpzIiwiY29tcG9uZW50cy9yc2Eta2V5LWJ1aWxkZXIuanMiLCJjb21wb25lbnRzL3NlY3JldC1rZXktYnVpbGRlci5qcyIsImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcva2V5LnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9jcnlwdG8udHMiLCJnbG9iYWwtcGxhdGZvcm0tc2NyaXB0aW5nL2J5dGUtc3RyaW5nLnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy9ieXRlLWJ1ZmZlci50cyIsImdsb2JhbC1wbGF0Zm9ybS1zY3JpcHRpbmcvdGx2LnRzIiwiZ2xvYmFsLXBsYXRmb3JtLXNjcmlwdGluZy90bHYtbGlzdC50cyIsImpzaW0tY2FyZC9TbG90cy50cyIsImpzaW0tY2FyZC9qc2ltLWNhcmQuanMiLCJqc2ltLWNhcmQvanNpbS1zY3JpcHQtYXBwbGV0LnRzIiwianNpbS1jYXJkL2pzaW0tc2NyaXB0LWNhcmQudHMiLCJqc2ltLWNhcmQvanNpbS1zbG90LnRzIiwianNpbS1tdWx0b3MvbWVtb3J5LW1hbmFnZXIudHMiLCJqc2ltLW11bHRvcy9tZWwtZGVmaW5lcy50cyIsImpzaW0tbXVsdG9zL3ZpcnR1YWwtbWFjaGluZS50cyIsImpzaW0tbXVsdG9zL2pzaW0tbXVsdG9zLWNhcmQudHMiLCJqc2ltLW11bHRvcy9wcmltaXRpdmVzLnRzIiwianNpbS1tdWx0b3Mvc2VjdXJpdHktbWFuYWdlci50cyIsIm11bHRvcy9hZGMudHMiLCJtdWx0b3MvYWxjLnRzIiwibXVsdG9zL2FsdS50cyJdLCJuYW1lcyI6WyJCYXNlVExWIiwiQmFzZVRMVi5jb25zdHJ1Y3RvciIsIkJhc2VUTFYucGFyc2VUTFYiLCJCYXNlVExWLnRhZyIsIkJhc2VUTFYudmFsdWUiLCJCYXNlVExWLmxlbiIsIkNvbW1hbmRBUERVIiwiQ29tbWFuZEFQRFUuY29uc3RydWN0b3IiLCJDb21tYW5kQVBEVS5MYyIsIkNvbW1hbmRBUERVLmhlYWRlciIsIkNvbW1hbmRBUERVLmluaXQiLCJDb21tYW5kQVBEVS5zZXQiLCJDb21tYW5kQVBEVS5zZXRDTEEiLCJDb21tYW5kQVBEVS5zZXRJTlMiLCJDb21tYW5kQVBEVS5zZXRQMSIsIkNvbW1hbmRBUERVLnNldFAyIiwiQ29tbWFuZEFQRFUuc2V0RGF0YSIsIkNvbW1hbmRBUERVLnNldExlIiwiQ29tbWFuZEFQRFUudG9KU09OIiwiQ29tbWFuZEFQRFUuZW5jb2RlQnl0ZXMiLCJDb21tYW5kQVBEVS5kZWNvZGVCeXRlcyIsIklTTzc4MTYiLCJSZXNwb25zZUFQRFUiLCJSZXNwb25zZUFQRFUuY29uc3RydWN0b3IiLCJSZXNwb25zZUFQRFUuTGEiLCJSZXNwb25zZUFQRFUuaW5pdCIsIlJlc3BvbnNlQVBEVS5zZXQiLCJSZXNwb25zZUFQRFUuc2V0U1ciLCJSZXNwb25zZUFQRFUuc2V0U1cxIiwiUmVzcG9uc2VBUERVLnNldFNXMiIsIlJlc3BvbnNlQVBEVS5zZXREYXRhIiwiUmVzcG9uc2VBUERVLmVuY29kZUJ5dGVzIiwiUmVzcG9uc2VBUERVLmRlY29kZUJ5dGVzIiwiU2xvdFByb3RvY29sSGFuZGxlciIsIlNsb3RQcm90b2NvbEhhbmRsZXIuY29uc3RydWN0b3IiLCJTbG90UHJvdG9jb2xIYW5kbGVyLmxpbmtTbG90IiwiU2xvdFByb3RvY29sSGFuZGxlci51bmxpbmtTbG90IiwiU2xvdFByb3RvY29sSGFuZGxlci5vbk1lc3NhZ2UiLCJLZXkiLCJLZXkuY29uc3RydWN0b3IiLCJLZXkuc2V0VHlwZSIsIktleS5nZXRUeXBlIiwiS2V5LnNldFNpemUiLCJLZXkuZ2V0U2l6ZSIsIktleS5zZXRDb21wb25lbnQiLCJLZXkuZ2V0Q29tcG9uZW50IiwiQ3J5cHRvIiwiQ3J5cHRvLmNvbnN0cnVjdG9yIiwiQ3J5cHRvLmVuY3J5cHQiLCJDcnlwdG8uZGVjcnlwdCIsIkNyeXB0by5zaWduIiwiQ3J5cHRvLmRlcyIsIkNyeXB0by5kZXMuZGVzX2NyZWF0ZUtleXMiLCJDcnlwdG8udmVyaWZ5IiwiQ3J5cHRvLmRpZ2VzdCIsIkJ5dGVTdHJpbmciLCJCeXRlU3RyaW5nLmNvbnN0cnVjdG9yIiwiQnl0ZVN0cmluZy5sZW5ndGgiLCJCeXRlU3RyaW5nLmJ5dGVzIiwiQnl0ZVN0cmluZy5ieXRlQXQiLCJCeXRlU3RyaW5nLmVxdWFscyIsIkJ5dGVTdHJpbmcuY29uY2F0IiwiQnl0ZVN0cmluZy5sZWZ0IiwiQnl0ZVN0cmluZy5yaWdodCIsIkJ5dGVTdHJpbmcubm90IiwiQnl0ZVN0cmluZy5hbmQiLCJCeXRlU3RyaW5nLm9yIiwiQnl0ZVN0cmluZy5wYWQiLCJCeXRlU3RyaW5nLnRvU3RyaW5nIiwiQnl0ZUJ1ZmZlciIsIkJ5dGVCdWZmZXIuY29uc3RydWN0b3IiLCJCeXRlQnVmZmVyLmxlbmd0aCIsIkJ5dGVCdWZmZXIudG9CeXRlU3RyaW5nIiwiQnl0ZUJ1ZmZlci5jbGVhciIsIkJ5dGVCdWZmZXIuYXBwZW5kIiwiVExWIiwiVExWLmNvbnN0cnVjdG9yIiwiVExWLmdldFRMViIsIlRMVi5nZXRUYWciLCJUTFYuZ2V0VmFsdWUiLCJUTFYuZ2V0TCIsIlRMVi5nZXRMViIsIlRMVi5wYXJzZVRMViIsIlRMVkxpc3QiLCJUTFZMaXN0LmNvbnN0cnVjdG9yIiwiVExWTGlzdC5pbmRleCIsIkpTU2ltdWxhdGVkU2xvdCIsIkpTU2ltdWxhdGVkU2xvdC5Pbk1lc3NhZ2UiLCJKU1NpbXVsYXRlZFNsb3QuaW5pdCIsIkpTU2ltdWxhdGVkU2xvdC5zZW5kVG9Xb3JrZXIiLCJKU1NpbXVsYXRlZFNsb3QuZXhlY3V0ZUFQRFVDb21tYW5kIiwiSlNJTVNjcmlwdEFwcGxldCIsIkpTSU1TY3JpcHRBcHBsZXQuc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNU2NyaXB0QXBwbGV0LmRlc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNU2NyaXB0QXBwbGV0LmV4ZWN1dGVBUERVIiwiSlNJTVNjcmlwdENhcmQiLCJKU0lNU2NyaXB0Q2FyZC5jb25zdHJ1Y3RvciIsIkpTSU1TY3JpcHRDYXJkLmxvYWRBcHBsaWNhdGlvbiIsIkpTSU1TY3JpcHRDYXJkLmlzUG93ZXJlZCIsIkpTSU1TY3JpcHRDYXJkLnBvd2VyT24iLCJKU0lNU2NyaXB0Q2FyZC5wb3dlck9mZiIsIkpTSU1TY3JpcHRDYXJkLnJlc2V0IiwiSlNJTVNjcmlwdENhcmQuZXhjaGFuZ2VBUERVIiwiSlNJTVNsb3QiLCJKU0lNU2xvdC5jb25zdHJ1Y3RvciIsIkpTSU1TbG90LmlzUHJlc2VudCIsIkpTSU1TbG90LmlzUG93ZXJlZCIsIkpTSU1TbG90LnBvd2VyT24iLCJKU0lNU2xvdC5wb3dlck9mZiIsIkpTSU1TbG90LnJlc2V0IiwiSlNJTVNsb3QuZXhlY3V0ZUFQRFUiLCJKU0lNU2xvdC5pbnNlcnRDYXJkIiwiSlNJTVNsb3QuZWplY3RDYXJkIiwiaGV4MiIsImhleDQiLCJNRU1GTEFHUyIsIlNlZ21lbnQiLCJTZWdtZW50LmNvbnN0cnVjdG9yIiwiU2VnbWVudC5nZXRUeXBlIiwiU2VnbWVudC5nZXRMZW5ndGgiLCJTZWdtZW50LmdldEZsYWdzIiwiU2VnbWVudC5nZXREZWJ1ZyIsIlNlZ21lbnQuYmVnaW5UcmFuc2FjdGlvbiIsIlNlZ21lbnQuZW5kVHJhbnNhY3Rpb24iLCJTZWdtZW50LnJlYWRCeXRlIiwiU2VnbWVudC56ZXJvQnl0ZXMiLCJTZWdtZW50LnJlYWRCeXRlcyIsIlNlZ21lbnQuY29weUJ5dGVzIiwiU2VnbWVudC53cml0ZUJ5dGVzIiwiU2VnbWVudC5uZXdBY2Nlc3NvciIsIkFjY2Vzc29yIiwiQWNjZXNzb3IuY29uc3RydWN0b3IiLCJBY2Nlc3Nvci50cmFjZU1lbW9yeU9wIiwiQWNjZXNzb3IudHJhY2VNZW1vcnlWYWx1ZSIsIkFjY2Vzc29yLnplcm9CeXRlcyIsIkFjY2Vzc29yLnJlYWRCeXRlIiwiQWNjZXNzb3IucmVhZEJ5dGVzIiwiQWNjZXNzb3IuY29weUJ5dGVzIiwiQWNjZXNzb3Iud3JpdGVCeXRlIiwiQWNjZXNzb3Iud3JpdGVCeXRlcyIsIkFjY2Vzc29yLmdldFR5cGUiLCJBY2Nlc3Nvci5nZXRMZW5ndGgiLCJBY2Nlc3Nvci5nZXRJRCIsIkFjY2Vzc29yLmdldERlYnVnIiwic2xpY2VEYXRhIiwiTWVtb3J5TWFuYWdlciIsIk1lbW9yeU1hbmFnZXIuY29uc3RydWN0b3IiLCJNZW1vcnlNYW5hZ2VyLm5ld1NlZ21lbnQiLCJNZW1vcnlNYW5hZ2VyLmdldE1lbVRyYWNlIiwiTWVtb3J5TWFuYWdlci5pbml0TWVtVHJhY2UiLCJNZW1vcnlNYW5hZ2VyLmdldFNlZ21lbnQiLCJNRUxJTlNUIiwiTUVMVEFHQUREUiIsIk1FTFRBR0NPTkQiLCJNRUxUQUdTWVNURU0iLCJNRUxUQUdTVEFDSyIsIk1FTFRBR1BSSU1SRVQiLCJNRUxQQVJBTURFRiIsIk1FTFBBUkFNNCIsIk9QVEFHMk1FTElOU1QiLCJNRUwyT1BDT0RFIiwiTUVMMklOU1QiLCJNRUwyVEFHIiwiTUVMUEFSQU1TSVpFIiwiTUVMIiwic2V0TWVsRGVjb2RlIiwic2V0TWVsRGVjb2RlU3RkTW9kZXMiLCJzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyIsImZpbGxNZWxEZWNvZGUiLCJoZXgiLCJsanVzdCIsInJqdXN0IiwiQkEyVyIsIlcyQkEiLCJNRUxWaXJ0dWFsTWFjaGluZSIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0cnVjdG9yIiwiTUVMVmlydHVhbE1hY2hpbmUuaW5pdE1WTSIsIk1FTFZpcnR1YWxNYWNoaW5lLmRpc2Fzc2VtYmxlQ29kZSIsIk1FTFZpcnR1YWxNYWNoaW5lLmRpc2Fzc2VtYmxlQ29kZS5wcmludCIsIk1FTFZpcnR1YWxNYWNoaW5lLm1hcFRvU2VnbWVudEFkZHIiLCJNRUxWaXJ0dWFsTWFjaGluZS5tYXBGcm9tU2VnbWVudEFkZHIiLCJNRUxWaXJ0dWFsTWFjaGluZS5jaGVja0RhdGFBY2Nlc3MiLCJNRUxWaXJ0dWFsTWFjaGluZS5yZWFkU2VnbWVudERhdGEiLCJNRUxWaXJ0dWFsTWFjaGluZS53cml0ZVNlZ21lbnREYXRhIiwiTUVMVmlydHVhbE1hY2hpbmUucHVzaFplcm9zVG9TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2hDb25zdFRvU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5jb3B5T25TdGFjayIsIk1FTFZpcnR1YWxNYWNoaW5lLnB1c2hUb1N0YWNrIiwiTUVMVmlydHVhbE1hY2hpbmUucG9wRnJvbVN0YWNrQW5kU3RvcmUiLCJNRUxWaXJ0dWFsTWFjaGluZS5wb3BGcm9tU3RhY2siLCJNRUxWaXJ0dWFsTWFjaGluZS5zZXR1cEFwcGxpY2F0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuaW5pdEV4ZWN1dGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0Qnl0ZUJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmNvbnN0V29yZEJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLmJpbmFyeU9wZXJhdGlvbiIsIk1FTFZpcnR1YWxNYWNoaW5lLnVuYXJ5T3BlcmF0aW9uIiwiTUVMVmlydHVhbE1hY2hpbmUuaGFuZGxlUmV0dXJuIiwiTUVMVmlydHVhbE1hY2hpbmUuaXNDb25kaXRpb24iLCJNRUxWaXJ0dWFsTWFjaGluZS5leGVjdXRlU3RlcCIsIk1FTFZpcnR1YWxNYWNoaW5lLnNldENvbW1hbmRBUERVIiwiTUVMVmlydHVhbE1hY2hpbmUuZ2V0UmVzcG9uc2VBUERVIiwiTUVMVmlydHVhbE1hY2hpbmUuZ2V0RGVidWciLCJKU0lNTXVsdG9zQXBwbGV0IiwiSlNJTU11bHRvc0FwcGxldC5jb25zdHJ1Y3RvciIsIkpTSU1NdWx0b3NDYXJkIiwiSlNJTU11bHRvc0NhcmQuY29uc3RydWN0b3IiLCJKU0lNTXVsdG9zQ2FyZC5sb2FkQXBwbGljYXRpb24iLCJKU0lNTXVsdG9zQ2FyZC5pc1Bvd2VyZWQiLCJKU0lNTXVsdG9zQ2FyZC5wb3dlck9uIiwiSlNJTU11bHRvc0NhcmQucG93ZXJPZmYiLCJKU0lNTXVsdG9zQ2FyZC5yZXNldCIsIkpTSU1NdWx0b3NDYXJkLmV4Y2hhbmdlQVBEVSIsIkpTSU1NdWx0b3NDYXJkLmluaXRpYWxpemVWTSIsIkpTSU1NdWx0b3NDYXJkLnJlc2V0Vk0iLCJKU0lNTXVsdG9zQ2FyZC5zaHV0ZG93blZNIiwiSlNJTU11bHRvc0NhcmQuc2VsZWN0QXBwbGljYXRpb24iLCJKU0lNTXVsdG9zQ2FyZC5leGVjdXRlU3RlcCIsImJpdE1hbmlwdWxhdGUiLCJjYWxsUHJpbWl0aXZlIiwiU2VjdXJpdHlNYW5hZ2VyIiwiU2VjdXJpdHlNYW5hZ2VyLmluaXRTZWN1cml0eSIsIlNlY3VyaXR5TWFuYWdlci5wcm9jZXNzQVBEVSIsIkFEQyIsIkFMQyIsIkFMVSIsIkFMVS5jb25zdHJ1Y3RvciIsIkFMVS50b0pTT04iLCJBTFUuZ2V0QUxVU2VnbWVudCIsIkFMVS5kZWNvZGVCeXRlcyIsIkFMVS5lbmNvZGVCeXRlcyJdLCJtYXBwaW5ncyI6Ik9BQU8sRUFBRSxTQUFTLEVBQUUsTUFBTSx3QkFBd0I7QUFFbEQ7SUE4REVBLFlBQWNBLEdBQVdBLEVBQUVBLEtBQWdCQSxFQUFFQSxRQUFpQkE7UUFFNURDLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFFBQVFBLElBQUlBLE9BQU9BLENBQUNBLFNBQVNBLENBQUNBLEdBQUdBLENBQUNBO1FBRWxEQSxNQUFNQSxDQUFBQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFTQSxDQUFDQSxDQUN2QkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsT0FBT0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsR0FBR0E7Z0JBQzFCQSxDQUFDQTtvQkFDQ0EsSUFBSUEsU0FBU0EsR0FBR0EsSUFBSUEsU0FBU0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7b0JBRWxDQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFLQSxLQUFNQSxDQUFDQTt3QkFDbEJBLFNBQVNBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLENBQUVBLENBQUNBO29CQUMzQ0EsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7b0JBRWhDQSxJQUFJQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFDQTtvQkFDdkJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLEdBQUdBLElBQUtBLENBQUNBLENBQ2pCQSxDQUFDQTt3QkFDQ0EsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7d0JBQzFCQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFDQTtvQkFDM0NBLENBQUNBO29CQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxHQUFHQSxJQUFLQSxDQUFDQTt3QkFDcEJBLFNBQVNBLENBQUNBLE9BQU9BLENBQUVBLElBQUlBLENBQUVBLENBQUNBO29CQUU1QkEsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7b0JBRWhDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtvQkFFMUJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLFNBQVNBLENBQUNBO29CQUUzQkEsS0FBS0EsQ0FBQ0E7Z0JBQ1JBLENBQUNBO1FBQ0hBLENBQUNBO0lBQ0hBLENBQUNBO0lBdkZERCxPQUFPQSxRQUFRQSxDQUFFQSxNQUFpQkEsRUFBRUEsUUFBZ0JBO1FBRWxERSxJQUFJQSxHQUFHQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxFQUFFQSxLQUFLQSxFQUFFQSxTQUFTQSxFQUFFQSxTQUFTQSxFQUFFQSxDQUFDQSxFQUFFQSxXQUFXQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQTtRQUM3RUEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDWkEsSUFBSUEsS0FBS0EsR0FBR0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0E7UUFFaENBLE1BQU1BLENBQUFBLENBQUVBLFFBQVNBLENBQUNBLENBQ2xCQSxDQUFDQTtZQUNDQSxLQUFLQSxPQUFPQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQTtnQkFDMUJBLENBQUNBO29CQUNDQSxPQUFPQSxDQUFFQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFFQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxJQUFJQSxJQUFJQSxDQUFFQSxDQUFFQTt3QkFDdkZBLEVBQUVBLEdBQUdBLENBQUNBO29CQUVSQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxLQUFLQSxDQUFDQSxNQUFPQSxDQUFDQTt3QkFDeEJBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO29CQUViQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxJQUFLQSxDQUFDQSxDQUN0Q0EsQ0FBQ0E7d0JBQ0NBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUVBLEdBQUdBLEVBQUVBLENBQUVBLElBQUlBLENBQUNBLENBQUNBO3dCQUM5QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsS0FBS0EsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDMUJBLENBQUNBOzRCQUFnQkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7d0JBQUNBLENBQUNBO29CQUNqQ0EsQ0FBQ0E7b0JBRURBLEdBQUdBLENBQUNBLEdBQUdBLElBQUlBLEtBQUtBLENBQUVBLEdBQUdBLEVBQUVBLENBQUVBLENBQUNBO29CQUUxQkEsR0FBR0EsQ0FBQ0EsU0FBU0EsR0FBR0EsR0FBR0EsQ0FBQ0E7b0JBRXBCQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxLQUFLQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUMxQkEsQ0FBQ0E7d0JBQWdCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtvQkFBQ0EsQ0FBQ0E7b0JBRS9CQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxLQUFLQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFDQSxDQUFDQTtvQkFDakVBLE9BQU9BLEVBQUVBLEVBQUVBLEdBQUdBLENBQUNBLEVBQ2ZBLENBQUNBO3dCQUNDQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxLQUFLQSxDQUFDQSxNQUFPQSxDQUFDQSxDQUMxQkEsQ0FBQ0E7NEJBQTRDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTt3QkFBQ0EsQ0FBQ0E7d0JBRTNEQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFFQSxHQUFHQSxLQUFLQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFFQSxDQUFDQTtvQkFDOUNBLENBQUNBO29CQUVEQSxHQUFHQSxDQUFDQSxXQUFXQSxHQUFHQSxHQUFHQSxDQUFDQTtvQkFDdEJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU9BLENBQUNBLENBQ3JDQSxDQUFDQTt3QkFBZ0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO29CQUFDQSxDQUFDQTtvQkFDN0JBLEdBQUdBLENBQUNBLEtBQUtBLEdBQUdBLEtBQUtBLENBQUNBLEtBQUtBLENBQUVBLEdBQUdBLENBQUNBLFdBQVdBLEVBQUVBLEdBQUdBLENBQUNBLFdBQVdBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO29CQUd0RUEsS0FBS0EsQ0FBQ0E7Z0JBQ1JBLENBQUNBO1FBQ0hBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBdUNERixJQUFJQSxHQUFHQTtRQUVMRyxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUMvREEsQ0FBQ0E7SUFFREgsSUFBSUEsS0FBS0E7UUFFUEksTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7SUFDakVBLENBQUNBO0lBRURKLElBQUlBLEdBQUdBO1FBRUxLLE1BQU1BLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFFBQVFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBO0lBQy9EQSxDQUFDQTtBQUNITCxDQUFDQTtBQTVHZSxpQkFBUyxHQUFHO0lBQ3hCLEdBQUcsRUFBRSxDQUFDO0lBQ04sR0FBRyxFQUFFLENBQUM7Q0FDUCxDQXlHRjtBQUVELE9BQU8sQ0FBQyxTQUFTLENBQUUsS0FBSyxDQUFFLEdBQUcsQ0FBQyxDQUFDO09DbEh4QixFQUFHLFNBQVMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFZLE1BQU0sd0JBQXdCO0FBS2hGO0lBZ0JFTSxZQUFhQSxVQUFlQTtRQWI1QkMsUUFBR0EsR0FBV0EsQ0FBQ0EsQ0FBQ0E7UUFDaEJBLE9BQUVBLEdBQVdBLENBQUNBLENBQUNBO1FBQ2ZBLE9BQUVBLEdBQVdBLENBQUNBLENBQUNBO1FBQ2ZBLFNBQUlBLEdBQWNBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBO1FBQ2xDQSxPQUFFQSxHQUFXQSxDQUFDQSxDQUFDQTtRQVdiQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFREQsSUFBV0EsRUFBRUEsS0FBcUJFLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBO0lBQzVERixJQUFXQSxNQUFNQSxLQUFpQkcsTUFBTUEsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBRUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLckdILE9BQWNBLElBQUlBLENBQUVBLEdBQVlBLEVBQUVBLEdBQVlBLEVBQUVBLEVBQVdBLEVBQUVBLEVBQVdBLEVBQUVBLElBQWdCQSxFQUFFQSxXQUFvQkE7UUFFOUdJLE1BQU1BLENBQUNBLENBQUVBLElBQUlBLFdBQVdBLEVBQUVBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUVBLENBQUNBO0lBQzFFQSxDQUFDQTtJQUVNSixHQUFHQSxDQUFFQSxHQUFXQSxFQUFFQSxHQUFXQSxFQUFFQSxFQUFVQSxFQUFFQSxFQUFVQSxFQUFFQSxJQUFnQkEsRUFBRUEsV0FBb0JBO1FBRWxHSyxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQTtRQUNmQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQTtRQUNmQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNiQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNiQSxJQUFJQSxDQUFDQSxJQUFJQSxHQUFHQSxJQUFJQSxJQUFJQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQTtRQUNwQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsV0FBV0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFFM0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRU1MLE1BQU1BLENBQUVBLEdBQVdBLElBQXVCTSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN4RU4sTUFBTUEsQ0FBRUEsR0FBV0EsSUFBdUJPLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQ3hFUCxLQUFLQSxDQUFFQSxFQUFVQSxJQUF5QlEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDdEVSLEtBQUtBLENBQUVBLEVBQVVBLElBQXlCUyxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN0RVQsT0FBT0EsQ0FBRUEsSUFBZUEsSUFBa0JVLElBQUlBLENBQUNBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQzFFVixLQUFLQSxDQUFFQSxFQUFVQSxJQUF5QlcsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLdEVYLE1BQU1BO1FBRVhZLE1BQU1BLENBQUNBO1lBQ0xBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ2JBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ2JBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1lBQ1hBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1lBQ1hBLElBQUlBLEVBQUVBLElBQUlBLENBQUNBLElBQUlBO1lBQ2ZBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ1pBLENBQUNBO0lBQ0pBLENBQUNBO0lBS01aLFdBQVdBLENBQUVBLE9BQVlBO1FBRTlCYSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNqREEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBRUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDakRBLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRzFDQSxFQUFFQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUNoQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsRUFBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDZEEsRUFBRUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFDM0JBLEVBQUVBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLElBQUlBLENBQUVBLENBQUNBO1FBQ2hDQSxDQUFDQTtRQUVEQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNsQkEsRUFBRUEs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LEVBQUVBLENBQUNBO1FBRXBDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNSixLQUFLQSxDQUFFQSxFQUFVQSxJQUEwQkssSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDdkVMLE1BQU1BLENBQUVBLEdBQVdBLElBQXdCTSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUN0R04sTUFBTUEsQ0FBRUEsR0FBV0EsSUFBd0JPLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLE1BQU1BLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO0lBQy9GUCxPQUFPQSxDQUFFQSxJQUFlQSxJQUFtQlEsSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFLM0VSLFdBQVdBLENBQUVBLE9BQVlBO1FBRTlCUyxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVsREEsRUFBRUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFDOUJBLEVBQUVBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLEVBQU1BLENBQUVBLElBQUlBLENBQUNBLEVBQUVBLElBQUlB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WUFBWUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFFNURBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLENBQUNBLE1BQU1BLElBQUlBLEVBQUdBLENBQUNBLENBQ3JCQSxDQUFDQTtZQUNDQSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUViQSxDQUFDQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUV4Q0EsQ0FBQ0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDeEJBLENBQUNBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO1FBQzFDQSxDQUFDQTtRQUVEQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFDQSxZQUFZQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxZQUFZQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUVoR0EsTUFBTUEsQ0FBQ0EsSUFBSUEsVUFBVUEsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lBRURGLE9BQU9BLENBQUVBLEdBQUdBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBO1FBRXRCRyxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVESCxJQUFJQSxDQUFFQSxHQUFRQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFnQkEsRUFBRUEsRUFBR0E7UUFFekNJLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLFlBQVlBLENBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLFNBQVNBLENBQUNBO1FBRWpEQSxJQUFJQSxPQUFPQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVoQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBR0EsQ0FBQ0EsQ0FDckJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLElBQUlBLFNBQVNBLEVBQUVBLENBQUNBO1lBRTFCQSxPQUFPQTtpQkFDSkEsU0FBU0EsQ0FBRUEsRUFBRUEsQ0FBRUE7aUJBQ2ZBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBO2lCQUNsQkEsVUFBVUEsQ0FBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDekNBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLFNBQVVBLENBQUNBO1lBQ3BCQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUk1RUEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsT0FBT0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFN0dBLE1BQU1BLENBQUNBLElBQUlBLFVBQVVBLENBQUVBLFVBQVVBLENBQUVBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO0lBQ2xEQSxDQUFDQTtJQUtPSixHQUFHQSxDQUFFQSxHQUFlQSxFQUFFQSxPQUFtQkEsRUFBRUEsT0FBZUEsRUFBRUEsSUFBWUEsRUFBRUEsRUFBZUEsRUFBRUEsT0FBZ0JBO1FBS2pISyx3QkFBeUJBLEdBQUdBO1lBRTFCQyxFQUFFQSxDQUFDQSxDQUFFQSxNQUFNQSxDQUFDQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUNoQ0EsQ0FBQ0E7Z0JBRUNBLE1BQU1BLENBQUNBLEtBQUtBLEdBQUdBO29CQUNiQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFFQSxDQUFFQTtvQkFDNUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3JKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDOUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO29CQUMzSUEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3ZKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDcktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUNqTEEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDN0pBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO29CQUNuSkEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ25MQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdEtBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLENBQUNBLENBQUVBO2lCQUM5R0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7WUFHREEsSUFBSUEsVUFBVUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFeENBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFdBQVdBLENBQUNBLEVBQUVBLEdBQUdBLFVBQVVBLENBQUNBLENBQUNBO1lBRTVDQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVoRUEsSUFBSUEsUUFBUUEsRUFBRUEsU0FBU0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0E7WUFFeENBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQy9CQSxDQUFDQTtnQkFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3pFQSxLQUFLQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFFekVBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ25GQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtnQkFFbkRBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUN0R0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBR2JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLE1BQU1BLEVBQUVBLENBQUNBLEVBQUVBLEVBQ3BDQSxDQUFDQTtvQkFFQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTt3QkFDQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBQUNBLEtBQUtBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO29CQUM1RUEsQ0FBQ0E7b0JBQ0RBLElBQUlBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFNNUJBLFFBQVFBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNqRkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ3pGQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDeEZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUN0REEsU0FBU0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ25GQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDNUZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUM1RkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ3pEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxTQUFTQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtvQkFDcERBLElBQUlBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBO29CQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxTQUFTQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDcEVBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBQ2RBLENBQUNBO1FBR0RELEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLENBQUNBLEtBQUtBLElBQUlBLFNBQVVBLENBQUNBLENBQ2hDQSxDQUFDQTtZQUNDQSxNQUFNQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDYkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pmQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDam9CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDcm1CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDempCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTthQUN0bEJBLENBQUNBO1FBQ0pBLENBQUNBO1FBR0RBLElBQUlBLElBQUlBLEdBQUdBLGNBQWNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxPQUFPQSxDQUFDQTtRQUMxQ0EsSUFBSUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBQUE7UUFDMUNBLElBQUlBLEdBQUdBLEdBQUdBLE9BQU9BLENBQUNBLE1BQU1BLENBQUNBO1FBR3pCQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUUzQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLE9BQU9BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO1FBQ3BEQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNsR0EsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsT0FBT0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FDbkRBLENBQUNBO1lBQ0NBLElBQUlBLGVBQWVBLEdBQUdBLE9BQU9BLENBQUNBO1lBQzlCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUVwQkEsT0FBT0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDcENBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLGVBQWVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBRWxDQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7Z0JBQ0NBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtvQkFDekZBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxDQUFDQTtvQkFDTkEsQ0FBQ0E7d0JBQ0NBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUU5RUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ1hBLEdBQUdBLElBQUVBLENBQUNBLENBQUNBO3dCQUVUQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDdkZBLEtBQUtBLENBQUNBO1lBRVZBLENBQUNBO1lBRURBLEdBQUdBLElBQUlBLENBQUNBLEdBQUNBLENBQUNBLEdBQUdBLEdBQUNBLENBQUNBLENBQUNBLENBQUFBO1FBQ2xCQSxDQUFDQTtRQUdEQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVuQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFVkEsT0FBT0EsR0FBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDeEVBLFFBQVFBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1FBQzFFQSxDQUFDQTtRQUVEQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdYQSxPQUFPQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUNkQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUN6RkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFHekZBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsT0FBT0EsQ0FBQ0E7b0JBQUNBLEtBQUtBLElBQUlBLFFBQVFBLENBQUNBO2dCQUNyQ0EsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtvQkFDbkJBLFNBQVNBLEdBQUdBLFFBQVFBLENBQUNBO29CQUNyQkEsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQ2pGQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRS9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNyQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHeENBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLElBQUVBLENBQUNBLEVBQzVCQSxDQUFDQTtnQkFDQ0EsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzNCQSxJQUFJQSxPQUFPQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFHM0JBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLE9BQU9BLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQ3pDQSxDQUFDQTtvQkFDQ0EsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzdCQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFHekRBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO29CQUNaQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtvQkFDYkEsS0FBS0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQ25HQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDMUZBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNuR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzlHQSxDQUFDQTtnQkFFREEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUFDQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtZQUMxQ0EsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHL0VBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxJQUFJQSxJQUFJQSxRQUFRQSxDQUFDQTtvQkFDakJBLEtBQUtBLElBQUlBLFNBQVNBLENBQUNBO2dCQUNyQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFFREEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBR0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0Es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LENBQUVBLEtBQWlCQTtRQUV2Qk0sSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFekNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRUROLElBQUlBLENBQUVBLEtBQWFBO1FBRWpCTyxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtJQUN0REEsQ0FBQ0E7SUFFRFAsS0FBS0EsQ0FBRUEsS0FBYUE7UUFFbEJRLE1BQU1BLENBQUNBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBLEtBQUtBLENBQUVBLENBQUVBLENBQUNBO0lBQzNEQSxDQUFDQTtJQUVEUixHQUFHQTtRQUVEUyxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN4REEsQ0FBQ0E7SUFFRFQsR0FBR0EsQ0FBRUEsS0FBaUJBO1FBRXBCVSxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFFQSxDQUFDQTtJQUN4RUEsQ0FBQ0E7SUFFRFYsRUFBRUEsQ0FBRUEsS0FBaUJBO1FBRW5CVyxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFFQSxDQUFDQTtJQUN2RUEsQ0FBQ0E7SUFFRFgsR0FBR0EsQ0FBRUEsTUFBY0EsRUFBRUEsUUFBa0JBO1FB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QUMzQkEsQ0FBQ0E7SUFFREQsTUFBTUE7UUFFSkUsTUFBTUEsQ0FBQ0EsSUFBSUEsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7SUFDOUNBLENBQUNBO0lBRURGLE1BQU1BO1FBRUpHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBO0lBQ3RCQSxDQUFDQTtJQUVESCxRQUFRQTtRQUVOSSxNQUFNQSxDQUFDQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQTtJQUMxQ0EsQ0FBQ0E7SUFFREosSUFBSUE7UUFFRkssSUFBSUEsSUFBSUEsR0FBR0EsT0FBT0EsQ0FBQ0EsUUFBUUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0E7UUFFakVBLE1BQU1BLENBQUNBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBO0lBQ3pGQSxDQUFDQTtJQUVETCxLQUFLQTtRQUVITSxJQUFJQSxJQUFJQSxHQUFHQSxPQUFPQSxDQUFDQSxRQUFRQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFFQSxDQUFDQTtRQUVqRUEsTUFBTUEsQ0FBQ0EsSUFBSUEsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDcEdBLENBQUNBO0lBRUROLE9BQU9B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QUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO0lBQzFDQSxDQUFDQTtJQUVEVixTQUFTQSxDQUFFQSxRQUFRQSxFQUFFQSxNQUFNQSxFQUFFQSxHQUFHQTtRQUU5QlcsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsUUFBUUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDN0RBLENBQUNBO0lBRURYLFVBQVVBLENBQUVBLElBQVlBLEVBQUVBLEdBQWNBO1FBRXRDWSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxhQUFhQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQSxRQUFRQSxDQUFDQSxlQUFlQSxDQUFHQSxDQUFDQSxDQUN0RUEsQ0FBQ0E7WUFFQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsSUFBSUEsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDcEZBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLE9BQU9BLENBQUNBLFVBQVVBLENBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO0lBQ3ZDQSxDQUFDQTtJQUVEWixXQUFXQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQTtRQUUxQmEsTUFBTUEsQ0FBQ0EsSUFBSUEsUUFBUUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDL0NBLENBQUNBO0FBQ0hiLENBQUNBO0FBRUQ7SUFPRWMsWUFBYUEsR0FBR0EsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUE7UUFFL0JDLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBO1FBRWZBLElBQUlB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QUFDQTtJQUVETCxTQUFTQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQTtRQUVsQk0sRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDL0JBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLElBQUlBLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQzVDQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxrQkFBa0JBLENBQUVBLENBQUNBO1FBQ3hDQSxDQUFDQTtRQUVEQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN0Q0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDeERBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFN0JBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRUROLFNBQVNBLENBQUVBLFFBQWdCQSxFQUFFQSxNQUFjQSxFQUFFQSxHQUFXQTtRQUV0RE8sRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsUUFBUUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsR0FBR0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBR0EsQ0FBQ0EsQ0FDekVBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO1lBQ3hEQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxrQkFBa0JBLENBQUVBLENBQUNBO1FBQ3hDQSxDQUFDQTtRQUdEQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtZQUNsREEsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsUUFBUUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7WUFDNURBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDL0JBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLEVBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBQ3hFQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUNiQSxDQUFDQTtJQUVEUCxTQUFTQSxDQUFFQSxJQUFZQSxFQUFFQSxHQUFXQTtRQUVsQ1EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0EsQ0FDN0JBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLFVBQVVBLEVBQUVBLElBQUlBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBQzFDQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSxtQkFBbUJBLENBQUVBLENBQUNBO1FBQ3pDQSxDQUFDQTtRQUVEQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsRUFBRUEsSUFBSUEsU0FBU0EsQ0FBRUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBRUEs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LE9BQU87SUFDakJNLCtDQUFpQkEsQ0FBQUE7SUFDakJBLCtDQUFpQkEsQ0FBQUE7SUFDakJBLDJDQUFpQkEsQ0FBQUE7SUFDakJBLDJDQUFpQkEsQ0FBQUE7SUFDakJBLDZDQUFpQkEsQ0FBQUE7SUFDakJBLGlEQUFpQkEsQ0FBQUE7SUFDakJBLGlEQUFpQkEsQ0FBQUE7SUFDakJBLDJDQUFpQkEsQ0FBQUE7SUFDakJBLDZDQUFpQkEsQ0FBQUE7SUFDakJBLDZDQUFpQkEsQ0FBQUE7SUFDakJBLGdEQUFpQkEsQ0FBQUE7SUFDakJBLDhDQUFpQkEsQ0FBQUE7SUFDakJBLDhDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLGdEQUFpQkEsQ0FBQUE7SUFDakJBLDhDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7SUFDakJBLDBDQUFpQkEsQ0FBQUE7SUFDakJBLDRDQUFpQkEsQ0FBQUE7QUFDbkJBLENBQUNBLEVBakNXLE9BQU8sS0FBUCxPQUFPLFFBaUNsQjtBQUFBLENBQUM7QUFFRixXQUFZLFVBU1g7QUFURCxXQUFZLFVBQVU7SUFDcEJDLHVEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7SUFDakJBLHFEQUFpQkEsQ0FBQUE7QUFDbkJBLENBQUNBLEVBVFcsVUFBVSxLQUFWLFVBQVUsUUFTckI7QUFBQSxDQUFDO0FBRUYsV0FBWSxVQVNYO0FBVEQsV0FBWSxVQUFVO0lBQ3BCQyx5REFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSxxREFBbUJBLENBQUFBO0lBQ25CQSx1REFBbUJBLENBQUFBO0FBQ3JCQSxDQUFDQSxFQVRXLFVBQVUsS0FBVixVQUFVLFFBU3JCO0FBQUEsQ0FBQztBQUVGLFdBQVksWUFTWDtBQVRELFdBQVksWUFBWTtJQUN0QkMsK0RBQXlCQSxDQUFBQTtJQUN6QkEsbUVBQXlCQSxDQUFBQTtJQUN6QkEsbUVBQXlCQSxDQUFBQTtJQUN6QkEsdUVBQXlCQSxDQUFBQTtJQUN6QkEsaUVBQXlCQSxDQUFBQTtJQUN6QkEscUVBQXlCQSxDQUFBQTtJQUN6QkEscUVBQXlCQSxDQUFBQTtJQUN6QkEseUVBQXlCQSxDQUFBQTtBQUMzQkEsQ0FBQ0EsRUFUVyxZQUFZLEtBQVosWUFBWSxRQVN2QjtBQUFBLENBQUM7QUFFRixXQUFZLFdBU1g7QUFURCxXQUFZLFdBQVc7SUFDckJDLCtEQUFxQkEsQ0FBQUE7SUFDckJBLCtEQUFxQkEsQ0FBQUE7SUFDckJBLCtEQUFxQkEsQ0FBQUE7SUFDckJBLDJEQUFxQkEsQ0FBQUE7SUFDckJBLDZEQUFxQkEsQ0FBQUE7SUFDckJBLDZEQUFxQkEsQ0FBQUE7SUFDckJBLDZEQUFxQkEsQ0FBQUE7SUFDckJBLDJEQUFxQkEsQ0FBQUE7QUFDdkJBLENBQUNBLEVBVFcsV0FBVyxLQUFYLFdBQVcsUUFTdEI7QUFBQSxDQUFDO0FBRUYsV0FBWSxhQVNYO0FBVEQsV0FBWSxhQUFhO0lBQ3ZCQyx1RUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0lBQ3ZCQSxtRUFBdUJBLENBQUFBO0lBQ3ZCQSxxRUFBdUJBLENBQUFBO0lBQ3ZCQSxxRUFBdUJBLENBQUFBO0lBQ3ZCQSx1RUFBdUJBLENBQUFBO0FBQ3pCQSxDQUFDQSxFQVRXLGFBQWEsS0FBYixhQUFhLFFBU3hCO0FBQUEsQ0FBQztBQUVGLFdBQVksV0FlWDtBQWZELFdBQVksV0FBVztJQUNyQkMsbUVBQW1DQSxDQUFBQTtJQUNuQ0EsK0VBQW1DQSxDQUFBQTtJQUNuQ0Esa0ZBQW1DQSxDQUFBQTtJQUNuQ0Esc0ZBQW1DQSxDQUFBQTtJQUNuQ0EsNEZBQW1DQSxDQUFBQTtJQUNuQ0Esc0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0Esb0ZBQW1DQSxDQUFBQTtJQUNuQ0EsMEZBQW1DQSxDQUFBQTtBQUNyQ0EsQ0FBQ0EsRUFmVyxXQUFXLEtBQVgsV0FBVyxRQWV0QjtBQUFBLENBQUM7QUFFRixtQkFBb0IsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxJQUFZQyxNQUFNQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxJQUFFQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFFQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtBQUMzRix1QkFBd0IsTUFBTSxFQUFFLEdBQUcsSUFBT0MsTUFBTUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDeEYsMkJBQTRCLFFBQVEsSUFBYUMsTUFBTUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsUUFBUUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDdkYseUJBQTBCLFFBQVEsSUFBZUMsTUFBTUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7QUFDakYsd0JBQXlCLFFBQVEsSUFBZ0JDLE1BQU1BLENBQUNBLENBQUVBLENBQUNBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUFBLENBQUNBLENBQUNBO0FBQUEsQ0FBQztBQUU3RSxzQkFBdUIsU0FBUztJQUU5QkMsTUFBTUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsSUFBSUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBRUE7VUFDMUNBLENBQUNBO1VBQ0RBLENBQUVBLFNBQVNBLEdBQUdBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7QUFDdkVBLENBQUNBO0FBRUQ7QUFTQUMsQ0FBQ0E7QUFQZSxhQUFTLEdBQUcsRUFBRSxDQU83QjtBQUVELHNCQUF1QixRQUFnQixFQUFFLFFBQWdCLEVBQUUsTUFBTyxFQUFFLE1BQU8sRUFBRSxNQUFPLEVBQUUsTUFBTztJQUUzRkMsTUFBTUEsR0FBR0EsTUFBTUEsSUFBSUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBQ0E7SUFDL0NBLE1BQU1BLEdBQUdBLE1BQU1BLElBQUlBLFdBQVdBLENBQUNBLGVBQWVBLENBQUNBO0lBQy9DQSxNQUFNQSxHQUFHQSxNQUFNQSxJQUFJQSxXQUFXQSxDQUFDQSxlQUFlQSxDQUFDQTtJQUMvQ0EsTUFBTUEsR0FBR0EsTUFBTUEsSUFBSUEsV0FBV0EsQ0FBQ0EsZUFBZUEsQ0FBQ0E7SUFFL0NBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLFFBQVFBLENBQUVBLEdBQUdBO1FBQzFCQSxRQUFRQSxFQUFFQSxRQUFRQTtRQUNsQkEsT0FBT0EsRUFBRUEsQ0FBQ0EsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUEsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUEsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUEsR0FBR0EsWUFBWUEsQ0FBRUEsTUFBTUEsQ0FBRUE7UUFDOUdBLFFBQVFBLEVBQUVBLFFBQVFBO1FBQ2xCQSxTQUFTQSxFQUFFQSxTQUFTQSxDQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxDQUFFQTtLQUN2REEsQ0FBQ0E7QUFDSkEsQ0FBQ0E7QUFFRCw4QkFBK0IsT0FBZ0IsRUFBRSxRQUFnQixFQUFFLFNBQXNCO0lBRXZGQyxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3pIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxRQUFRQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0FBQzNIQSxDQUFDQTtBQUVELG9DQUFxQyxPQUFnQixFQUFFLFFBQWdCLEVBQUUsU0FBc0I7SUFFN0ZDLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLFFBQVFBLEVBQUVBLFNBQVNBLEVBQUVBLFdBQVdBLENBQUNBLHFCQUFxQkEsQ0FBRUEsQ0FBQ0E7SUFDeEhBLG9CQUFvQkEsQ0FBRUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7QUFDdkRBLENBQUNBO0FBRUQ7SUFFRUMsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUdBLE9BQU9BLEVBQUdBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBR0EsT0FBT0EsRUFBR0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxFQUFFQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBRTlGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxPQUFPQSxFQUFFQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUVBLENBQUNBO0lBRXRIQSxvQkFBb0JBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUdBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFFekZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBRTlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFFBQVFBLEVBQUVBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBR0EsT0FBT0EsRUFBR0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLE1BQU1BLEVBQUlBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUM5RkEsMEJBQTBCQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFJQSxNQUFNQSxFQUFJQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBLENBQUNBO0lBQzlGQSwwQkFBMEJBLENBQUVBLE9BQU9BLENBQUNBLE1BQU1BLEVBQUtBLEtBQUtBLEVBQUtBLFdBQVdBLENBQUNBLHNCQUFzQkEsQ0FBRUEsQ0FBQ0E7SUFDOUZBLDBCQUEwQkEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBSUEsTUFBTUEsRUFBSUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUU5RkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7SUFDckZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGNBQWNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDL0hBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGNBQWNBLENBQUVBLEVBQUVBLE9BQU9BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDL0hBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFlBQVlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsRUFBRUEsU0FBU0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ3pLQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxZQUFZQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUN2RkEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUNqSUEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUNoSUEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsU0FBU0EsRUFBRUEsWUFBWUEsQ0FBQ0EsaUJBQWlCQSxDQUFFQSxFQUFFQSxVQUFVQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFHM0tBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLEVBQUVBLEtBQUtBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFDekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLDJCQUEyQkEsQ0FBRUEsQ0FBQ0E7SUFFekhBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUVBLFVBQVVBLENBQUNBLFdBQVdBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLENBQUNBLGVBQWVBLENBQUVBLENBQUNBO0lBQzVHQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBQ3RIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSwwQkFBMEJBLENBQUVBLENBQUNBO0lBRXRIQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxFQUFFQSxVQUFVQSxDQUFDQSxXQUFXQSxDQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQTtJQUM1R0EsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsRUFBRUEsS0FBS0EsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUN0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsRUFBRUEsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsRUFBRUEsSUFBSUEsRUFBRUEsV0FBV0EsQ0FBQ0EsMEJBQTBCQSxDQUFFQSxDQUFDQTtJQUV0SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUMxSEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUM1SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsRUFBRUEsT0FBT0EsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxDQUFDQTtJQUU1SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsRUFBRUEsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFFQSxDQUFDQTtJQUN4SEEsWUFBWUEsQ0FBRUEsYUFBYUEsQ0FBRUEsT0FBT0EsQ0FBQ0EsUUFBUUEsRUFBRUEsV0FBV0EsQ0FBQ0EsWUFBWUEsQ0FBRUEsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDcEZBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLFdBQVdBLENBQUNBLFlBQVlBLENBQUVBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO0lBR3BGQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQ2pJQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBQ0E7SUFDdktBLFlBQVlBLENBQUVBLGFBQWFBLENBQUVBLE9BQU9BLENBQUNBLFVBQVVBLEVBQUVBLGFBQWFBLENBQUNBLGVBQWVBLENBQUVBLEVBQUVBLE1BQU1BLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBLENBQUNBO0lBQzdNQSxZQUFZQSxDQUFFQSxhQUFhQSxDQUFFQSxPQUFPQSxDQUFDQSxVQUFVQSxFQUFFQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFFQSxFQUFFQSxNQUFNQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLEVBQUVBLFdBQVdBLENBQUNBLHdCQUF3QkEsRUFBRUEsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxFQUFFQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVB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QSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFBQ0EsS0FBS0EsQ0FBQ0E7b0JBQ2hJQSxDQUFDQTtvQkFDREEsVUFBVUEsRUFBRUEsQ0FBQ0E7b0JBQ2JBLFNBQVNBLEtBQUtBLENBQUNBLENBQUNBO2dCQUNsQkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLEdBQUdBLGFBQWFBLEdBQUdBLEtBQUtBLENBQUVBLE9BQU9BLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dCQUVyRkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBRUE7dUJBQ2xCQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBLENBQUVBOzJCQUMzREEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQSxDQUFFQTsyQkFDN0RBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLElBQUlBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkEsQ0FBRUEsQ0FBRUE7dUJBQ2pFQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx3QkFBd0JBLENBQUVBO3VCQUM3REEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esc0JBQXNCQSxDQUFHQSxDQUFDQSxDQUNsRUEsQ0FBQ0E7b0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUFDQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQzVFQSxJQUFJQSxPQUFPQSxHQUFHQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQUNBLFFBQVFBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBO2dCQUM5RUEsQ0FBQ0E7Z0JBRURBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLFVBQVVBLEdBQUdBLENBQUNBLEVBQUVBLFVBQVVBLEdBQUdBLFVBQVVBLEVBQUVBLEVBQUVBLFVBQVVBLEVBQzlEQSxDQUFDQTtvQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7b0JBQy9CQSxJQUFJQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtvQkFFL0JBLE1BQU1BLENBQUFBLENBQUVBLENBQUVBLENBQUNBLENBQ1hBLENBQUNBO3dCQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxzQkFBc0JBOzRCQUN6Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsQ0FBQ0E7Z0NBQ1ZBLEtBQUtBLENBQUVBLElBQUlBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUMzQkEsSUFBSUE7Z0NBQ0ZBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBOzRCQUNiQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0Esd0JBQXdCQTs0QkFDM0NBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO2dDQUNWQSxLQUFLQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDM0JBLElBQUlBO2dDQUNGQSxLQUFLQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTs0QkFDYkEsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHdCQUF3QkE7NEJBQzNDQSxLQUFLQSxDQUFFQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTs0QkFDekJBLEtBQUtBLENBQUNBO3dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSwwQkFBMEJBOzRCQUM3Q0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ25CQSxLQUFLQSxDQUFDQTt3QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsMkJBQTJCQTs0QkFDOUNBLEtBQUtBLENBQUVBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUVBLENBQUVBLENBQUNBOzRCQUN4Q0EsS0FBS0EsQ0FBQ0E7d0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkEsQ0FBQ0E7d0JBQzdDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSx1QkFBdUJBLENBQUNBO3dCQUM3Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsdUJBQXVCQSxDQUFDQTt3QkFDN0NBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLHVCQUF1QkE7NEJBQzVDQSxDQUFDQTtnQ0FDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0NBQzNEQSxLQUFLQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFFQSxDQUFFQSxDQUFDQTtnQ0FDekJBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO29DQUNWQSxLQUFLQSxDQUFFQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDbENBLElBQUlBO29DQUNGQSxLQUFLQSxDQUFFQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQTtnQ0FDekJBLEtBQUtBLENBQUNBOzRCQUNSQSxDQUFDQTtvQkFDSEEsQ0FBQ0E7b0JBRURBLEVBQUVBLENBQUNBLENBQUVBLFVBQVVBLEdBQUdBLFVBQVVBLEdBQUdBLENBQUVBLENBQUNBO3dCQUNoQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xCQSxDQUFDQTtnQkFDREEsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFDaEJBLENBQUNBO1lBRURBLEVBQUVBLENBQUNBLENBQUVBLFlBQWFBLENBQUNBO2dCQUNqQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFDNUJBLENBQ0FBO1FBQUFBLEtBQUtBLENBQUFBLENBQUVBLENBQUVBLENBQUNBLENBQ1ZBLENBQUNBO1lBQ0NBLEtBQUtBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2JBLENBQUNBO1FBQUFBLENBQUNBO1FBR0ZBLE1BQU1BLENBQUNBLFFBQVFBLENBQUNBO0lBQ2xCQSxDQUFDQTtJQVFPSCxnQkFBZ0JBLENBQUVBLE9BQU9BLEVBQUVBLFVBQVVBO1FBRTNDSyxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxPQUFPQSxFQUFFQSxVQUFVQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVsRUEsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO1lBQ0NBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUNBO1lBQy9CQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM5QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDOUJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsR0FBR0EsWUFBWUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7WUFFMUNBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUNBO1lBQzlCQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLFVBQVVBLENBQUNBO1lBRWpDQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM5QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxNQUFNQSxHQUFHQSxZQUFZQSxDQUFDQSxVQUFVQSxDQUFDQTtRQUM1Q0EsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFT0wsa0JBQWtCQSxDQUFFQSxXQUFXQTtRQUVyQ00sRUFBRUEsQ0FBQ0EsQ0FBRUEsV0FBV0EsR0FBR0EsTUFBT0EsQ0FBQ0EsQ0FDM0JBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFdBQVdBLElBQUlBLE1BQU9BLENBQUNBLENBQzVCQSxDQUFDQTtnQkFDQ0EsTUFBTUEsQ0FBQ0E7b0JBQ0xBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO29CQUN6QkEsV0FBV0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7b0JBQ3JDQSxVQUFVQSxFQUFFQSxXQUFXQSxHQUFHQSxNQUFNQTtpQkFDakNBLENBQUNBO1lBQ0pBLENBQUNBO1lBQ0RBLElBQUlBLENBQ0pBLENBQUNBO2dCQUNDQSxNQUFNQSxDQUFDQTtvQkFDTEEsUUFBUUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0E7b0JBQzFCQSxXQUFXQSxFQUFFQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtvQkFDckNBLFVBQVVBLEVBQUVBLFdBQVdBLEdBQUdBLE1BQU1BO2lCQUNqQ0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ0xBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO2dCQUN6QkEsV0FBV0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQ3JDQSxVQUFVQSxFQUFFQSxXQUFXQSxHQUFHQSxNQUFNQTthQUNqQ0EsQ0FBQ0E7UUFDSkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFRT04sZUFBZUEsQ0FBRUEsT0FBT0EsRUFBRUEsTUFBTUEsRUFBRUEsTUFBTUE7UUFFOUNPLElBQUlBLFFBQVFBLENBQUNBO1FBQ2JBLElBQUlBLFVBQVVBLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3hCQSxJQUFJQSxTQUFTQSxDQUFDQTtRQUVkQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUE7Z0JBQzVCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQTtnQkFDNUJBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN6Q0EsVUFBVUEsSUFBSUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7Z0JBQzdCQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO2dCQUM1QkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3pDQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO2dCQUM1QkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0E7Z0JBQ3pDQSxVQUFVQSxJQUFJQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQTtnQkFDN0JBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0E7Z0JBQzVCQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDekNBLFVBQVVBLElBQUlBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO2dCQUM5QkEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtnQkFDM0JBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO2dCQUN4Q0EsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFD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LEVBQUVBLFFBQVFBO1FBRXJDc0IsSUFBSUEsWUFBWUEsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsUUFBUUEsQ0FBQ0E7UUFFOUNBLElBQUlBLFFBQVFBLEdBQUdBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO1FBQzNFQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUU3RUEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7UUFDNUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVNBLENBQUNBO1lBQ2JBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBO1FBRTdEQSxNQUFNQSxDQUFDQSxRQUFRQSxDQUFDQTtJQUNsQkEsQ0FBQ0E7SUFFT3RCLFdBQVdBLENBQUVBLEdBQUdBO1FBRXRCdUIsTUFBTUEsQ0FBQUEsQ0FBRUEsR0FBSUEsQ0FBQ0EsQ0FDYkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0E7Z0JBQzNCQSxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ25EQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ2pHQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDbkRBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBO2dCQUMzQkEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBQ2hHQSxLQUFLQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQTtnQkFDM0JBLE1BQU1BLENBQUNBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLEtBQUtBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBO2dCQUM1QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7WUFDZEEsUUFBUUE7UUFDVkEsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7SUFDZkEsQ0FBQ0E7SUFFRHZCLFdBQVdBO1FBRVR3QixJQUNBQSxDQUFDQTtZQUNDQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUM1QkEsSUFBSUEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FB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TUFBTUEsR0FBR0EsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ2xDQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0E7b0JBQ3RCQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxDQUFHQSxDQUFDQTt3QkFDNUJBLE1BQU1BLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO29CQUN6QkEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO29CQUN0QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsR0FBR0EsQ0FBR0EsQ0FBQ0EsQ0FDOUJBLENBQUNBO3dCQUNDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO3dCQUMzQ0EsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFFQSxDQUFDQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTt3QkFFbkNBLE1BQU1BLEdBQUdBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUN2QkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7b0JBQ25DQSxDQUFDQTtvQkFDREEsS0FBS0EsQ0FBQ0E7Z0JBRVJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLFFBQVFBO29CQUN6QkEsQ0FBQ0E7d0JBQ0NBLE1BQU1BLENBQUFBLENBQUVBLEdBQUlBLENBQUNBLENBQ2JBLENBQUNBOzRCQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxhQUFhQTtnQ0FDbENBLENBQUNBO29DQUNDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO29DQUN2Q0EsS0FBS0EsQ0FBQ0E7Z0NBQ1JBLENBQUNBOzRCQUNEQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxhQUFhQTtnQ0FDaENBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsQ0FBQ0EsRUFBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0NBQzFDQSxLQUFLQSxDQUFDQTs0QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsYUFBYUE7Z0NBQ2hDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLENBQUNBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dDQUMxQ0EsS0FBS0EsQ0FBQ0E7NEJBRVJBLEtBQUtBLEdBQUdBLENBQUNBLFdBQVdBLENBQUNBLFlBQVlBO2dDQUMvQkEsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0NBQ25DQSxLQUFLQSxDQUFDQTs0QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsWUFBWUE7Z0NBQy9CQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtnQ0FDdkJBLEtBQUtBLENBQUNBOzRCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFDQSxZQUFZQTtnQ0FDL0JBLElBQUlBLENBQUNBLFlBQVlBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO2dDQUN2QkEsS0FBS0EsQ0FBQ0E7d0JBQ1ZBLENBQUNBO3dCQUNEQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLFVBQVVBO29CQUMzQkEsQ0FBQ0E7d0JBQ0NBLE1BQU1BLENBQUFBLENBQUVBLEdBQUlBLENBQUNBLENBQ2JBLENBQUNBOzRCQUNDQSxLQUFLQSxHQUFHQSxDQUFDQSxhQUFhQSxDQUFDQSxlQUFlQSxDQUFDQTs0QkFDdkNBLEtBQUtBLEdBQUdBLENBQUNBLGFBQWFBLENBQUNBLGVBQWVBLENBQUNBOzRCQUN2Q0EsS0FBS0EsR0FBR0EsQ0FBQ0EsYUFBYUEsQ0FBQ0EsZUFBZUEsQ0FBQ0E7NEJBQ3ZDQSxLQUFLQSxHQUFHQSxDQUFDQSxhQUFhQSxDQUFDQSxlQUFlQTtnQ0FDcENBLEtBQUtBLENBQUNBOzRCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxhQUFhQSxDQUFDQSxhQUFhQTtnQ0FDbENBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLFlBQVlBLENBQUVBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO2dDQUNuQ0EsS0FBS0EsQ0FBQ0E7NEJBRVJBLEtBQUtBLEdBQUdBLENBQUNBLGFBQWFBLENBQUNBLGNBQWNBO2dDQUNuQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0NBQy9DQSxLQUFLQSxDQUFDQTs0QkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsYUFBYUEsQ0FBQ0EsY0FBY0E7Z0NBQ25DQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFFQSxDQUFDQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtnQ0FDL0NBLEtBQUtBLENBQUNBOzRCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxhQUFhQSxDQUFDQSxlQUFlQTtnQ0FDcENBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLFlBQVlBLENBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLEVBQUVBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dDQUMzREEsS0FBS0EsQ0FBQ0E7d0JBQ1ZBLENBQUNBO3dCQUNEQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BO29CQUN0QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBV0EsQ0FBQ0EsQ0FDdkNBLENBQUNBO3dCQUVDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDcEZBLElBQUlBLENBQUNBLFVBQVVBLElBQUlBLFFBQVFBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO29CQUNuQ0EsQ0FBQ0E7b0JBQ0RBLElBQUlBO3dCQUNGQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDeERBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDdkJBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLFVBQVdBLENBQUNBLENBQ3ZDQSxDQUFDQTt3QkFFQ0EsSUFBSUEsQ0FBQ0EsVUFBVUEsSUFBSUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7d0JBQ2pDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDdEZBLENBQUNBO29CQUNEQSxJQUFJQTt3QkFDRkEsSUFBSUEsQ0FBQ0Esb0JBQW9CQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtvQkFDakVBLEtBQUtBLENBQUNBO2dCQUdSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQTtvQkFDekJBLENBQUNBO3dCQUNDQSxJQUFJQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFDQSxlQUFlQSxDQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDeEVBLElBQUlBLFlBQVlBLEdBQUdBLElBQUlBLENBQUNBLGtCQUFrQkEsQ0FBRUEsV0FBV0EsQ0FBRUEsQ0FBQ0E7d0JBQzFEQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxZQUFZQSxDQUFDQSxXQUFXQSxFQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDckZBLEtBQUtBLENBQUNBO29CQUNSQSxDQUFDQTtnQkFFREEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsU0FBU0E7b0JBQzFCQSxDQUFDQTt3QkFDQ0EsSUFBSUEsV0FBV0EsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsZUFBZUEsQ0FBRUEsR0FBR0EsRUFBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7d0JBQ3hFQSxJQUFJQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxrQkFBa0JBLENBQUVBLFdBQVdBLENBQUVBLENBQUNBO3dCQUMxREEsSUFBSUEsQ0FBQ0Esb0JBQW9CQSxDQUFFQSxZQUFZQSxDQUFDQSxXQUFXQSxFQUFFQSxZQUFZQSxDQUFDQSxVQUFVQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTt3QkFDOUZBLEtBQUtBLENBQUNBO29CQUNSQSxDQUFDQTtnQkFFREEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUE7b0JBQ3ZCQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBRUEsR0FBR0EsRUFBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7b0JBQ3hFQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUE7b0JBQ3ZCQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0E7b0JBQ3RCQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFXQSxDQUFDQTt3QkFDckNBLElBQUlBLENBQUNBLHdCQUF3QkEsQ0FBRUEsTUFBTUEsRUFBRUEsUUFBUUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3JGQSxJQUFJQTt3QkFDRkEsSUFBSUEsQ0FBQ0Esd0JBQXdCQSxDQUFFQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDekVBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQTtnQkFDekJBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUNBO2dCQUN6QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3pCQSxLQUFLQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQTtvQkFDdEJBLEVBQUVB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Q0E7SUFDSEEsQ0FBQ0E7SUFFRHhCLGNBQWNBLENBQUVBLFdBQXdCQTtRQUV0Q3lCLElBQUlBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLEVBQUVBLENBQUNBO1FBRzVDQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUc1REEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFHNURBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLFdBQVdBLENBQUNBLEVBQUVBLENBQUVBLENBQUVBLENBQUNBO1FBR3BFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFFQSxXQUFXQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUM3RUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsR0FBR0EsRUFBRUEsRUFBRUEsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFFakVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLFdBQVdBLENBQUNBLElBQUlBLENBQUVBLENBQUNBO1FBRWxEQSxJQUFJQSxDQUFDQSxhQUFhQSxFQUFFQSxDQUFDQTtJQUN2QkEsQ0FBQ0E7SUFFRHpCLGVBQWVBO1FBRWIwQixJQUFJQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxDQUFDQTtRQUU1Q0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFL0RBLE1BQU1BLENBQUNBLElBQUlBLFlBQVlBLENBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLFNBQVNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUVBLEVBQUdBLENBQUVBLENBQUFBO0lBRXJJQSxDQUFDQTtJQUVEMUIsSUFBSUEsUUFBUUE7UUFFVjJCLE1BQU1BLENBQUNBO1lBQ0xBLFVBQVVBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO1lBQzNCQSxXQUFXQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQTtZQUM3QkEsVUFBVUEsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUE7WUFDM0JBLFVBQVVBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBO1lBQzNCQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQTtZQUN6QkEsVUFBVUEsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUE7WUFDM0JBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLFNBQVNBO1NBQzFCQSxDQUFDQTtJQUNKQSxDQUFDQTtBQUVIM0IsQ0FBQ0E7QUFBQSxPQzExQk0sRUFBRSxTQUFTLEVBQUUsTUFBTSx3QkFBd0I7T0FDM0MsRUFBRSxhQUFhLEVBQUUsUUFBUSxFQUFFLE1BQU0sa0JBQWtCO09BQ25ELEVBQUUsaUJBQWlCLEVBQUUsTUFBTSxtQkFBbUI7T0FJOUMsRUFBRSxZQUFZLEVBQUUsTUFBTSx1QkFBdUI7QUFJcEQsY0FBZ0IsR0FBRztJQUVqQkYsTUFBTUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7QUFDdENBLENBQUNBO0FBRUQ7SUFNRThCLFlBQWFBLFFBQVFBLEVBQUVBLFVBQVVBLEVBQUVBLFdBQVdBO1FBRTVDQyxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxRQUFRQSxDQUFDQTtRQUN6QkEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsVUFBVUEsQ0FBQ0E7UUFDN0JBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFdBQVdBLENBQUNBO0lBQ2pDQSxDQUFDQTtBQUNIRCxDQUFDQTtBQUVEO0lBa0JFRSxZQUFhQSxNQUFPQTtRQUVsQkMsRUFBRUEsQ0FBQ0EsQ0FBRUEsTUFBT0EsQ0FBQ0E7WUFDWEEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFDM0JBLElBQUlBO1lBQ0ZBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLGNBQWNBLENBQUNBLGFBQWFBLENBQUNBO1FBRWpEQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUUvQkEsSUFBSUEsQ0FBQ0EsT0FBT0EsR0FBR0EsRUFBRUEsQ0FBQ0E7SUFDcEJBLENBQUNBO0lBRURELGVBQWVBLENBQUVBLEdBQWNBLEVBQUVBLEdBQWNBO1FBRTdDRSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVaQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdaQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN4QkEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFFVEEsSUFBSUEsUUFBUUEsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFDL0RBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUVBLENBQUVBLENBQUNBO1FBQ2pEQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFDQTtRQUdYQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUN4QkEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFFVEEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsU0FBU0EsRUFBRUEsRUFBRUEsR0FBR0EsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDakZBLFVBQVVBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUVBLENBQUVBLENBQUNBO1FBQ25EQSxHQUFHQSxJQUFJQSxHQUFHQSxDQUFDQTtRQUVYQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxnQkFBZ0JBLENBQUVBLFFBQVFBLEVBQUVBLFVBQVVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBRTdEQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxJQUFJQSxDQUFFQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxNQUFNQSxFQUFFQSxNQUFNQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUNwREEsQ0FBQ0E7SUFFREYsSUFBV0EsU0FBU0E7UUFFbEJHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO0lBQ3hCQSxDQUFDQTtJQUVNSCxPQUFPQTtRQUVaSSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUV0QkEsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0E7UUFFckNBLE1BQU1BLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUVBLENBQUNBO0lBQ3JDQSxDQUFDQTtJQUVNSixRQUFRQTtRQUViSyxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtRQUV2QkEsSUFBSUEsQ0FBQ0EsT0FBT0EsRUFBRUEsQ0FBQ0E7UUFFZkEsSUFBSUEsQ0FBQ0EsY0FBY0EsR0FBR0EsU0FBU0EsQ0FBQ0E7UUFFaENBLE1BQU1BLENBQUNBLE9BQU9BLENBQUNBLE9BQU9BLEVBQUlBLENBQUNBO0lBQzdCQSxDQUFDQTtJQUVNTCxLQUFLQTtRQUVWTSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUV0QkEsSUFBSUEsQ0FBQ0EsY0FBY0EsR0FBR0EsU0FBU0EsQ0FBQ0E7UUFFaENBLElBQUlBLENBQUNBLFVBQVVBLEVBQUVBLENBQUNBO1FBRWxCQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFFQSxDQUFDQTtJQUNyQ0EsQ0FBQ0E7SUFFTU4sWUFBWUEsQ0FBRUEsV0FBd0JBO1FBRTNDTyxFQUFFQSxDQUFDQSxDQUFFQSxXQUFXQSxDQUFDQSxHQUFHQSxJQUFJQSxJQUFLQSxDQUFDQSxDQUM5QkEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsY0FBZUEsQ0FBQ0EsQ0FDMUJBLENBQUNBO2dCQUdDQSxJQUFJQSxDQUFDQSxjQUFjQSxHQUFHQSxTQUFTQSxDQUFDQTtZQUNsQ0EsQ0FBQ0E7WUFHREEsSUFBSUEsQ0FBQ0EsY0FBY0EsR0FBR0EsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7WUFFL0NBLElBQUlBLEdBQUdBLEdBQUdBLElBQUlBLFNBQVNBLENBQUVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUVBLENBQUVBLENBQUNBO1lBRTFDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxnQkFBZ0JBLENBQUVBLElBQUlBLENBQUNBLGNBQWNBLENBQUVBLENBQUNBO1lBRWpEQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFnQkEsSUFBSUEsWUFBWUEsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDekZBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLGNBQWNBLENBQUVBLFdBQVdBLENBQUNBLENBQUNBO1FBTXRDQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFnQkEsSUFBSUEsWUFBWUEsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsTUFBTUEsRUFBRUEsSUFBSUEsRUFBRUEsRUFBRUEsRUFBR0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFHeEZBLENBQUNBO0lBV0RQLFlBQVlBLENBQUVBLE1BQU1BO1FBRWxCUSxJQUFJQSxDQUFDQSxhQUFhQSxHQUFHQSxJQUFJQSxhQUFhQSxFQUFFQSxDQUFDQTtRQUV6Q0EsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQUE7UUFDakdBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLElBQUlBLENBQUNBLGFBQWFBLENBQUNBLFVBQVVBLENBQUVBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLE9BQU9BLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ2pGQSxJQUFJQSxDQUFDQSxZQUFZQSxHQUFHQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFDQSxVQUFVQSxDQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxTQUFTQSxFQUFFQSxRQUFRQSxDQUFDQSxlQUFlQSxDQUFFQSxDQUFDQTtRQUU1R0EsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsaUJBQWlCQSxFQUFF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Q0FBQ0E7b0JBQzNCQSxJQUFJQSxDQUFFQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFFQSxHQUFHQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNoREEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFLTUQsTUFBTUE7UUFFWEUsTUFBTUEsQ0FBQ0E7WUFDTEEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUE7WUFDZkEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsSUFBSUE7WUFDZkEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7WUFDYkEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7U0FDZEEsQ0FBQ0E7SUFDSkEsQ0FBQ0E7SUFFT0YsYUFBYUEsQ0FBRUEsS0FBZ0JBLEVBQUVBLFNBQWlCQTtRQUV4REcsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFZkEsT0FBT0EsQ0FBRUEsU0FBU0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBRUEsTUFBTUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFDckRBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLENBQUVBLE1BQU1BLENBQUVBLENBQUNBO1lBQ3JDQSxFQUFFQSxTQUFTQSxDQUFDQTtRQUNkQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxHQUFHQSxDQUFDQSxFQUFFQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxNQUFNQSxDQUFFQSxDQUFFQSxDQUFDQTtJQUM1REEsQ0FBQ0E7SUFLTUgsV0FBV0EsQ0FBRUEsS0FBZ0JBLEVBQUVBLE9BQWdCQTtRQUVwREksSUFBSUEsQ0FBQ0EsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDM0NBLElBQUlBLENBQUNBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLGFBQWFBLENBQUVBLEtBQUtBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQzNDQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMxQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFFMUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBS01KLFdBQVdBLENBQUVBLE9BQVlBO1FBRzlCSyxNQUFNQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7QUFDSEwsQ0FBQ0E7QUFFRCxXQUFXLENBQUMsSUFBSSxDQUFFLEdBQUcsRUFBRSw4QkFBOEIsQ0FBRTtLQUNwRCxLQUFLLENBQUUsTUFBTSxFQUFFLGNBQWMsRUFBRSxTQUFTLENBQUU7S0FDMUMsS0FBSyxDQUFFLE1BQU0sRUFBRSxjQUFjLEVBQUUsU0FBUyxDQUFFO0tBQzFDLEtBQUssQ0FBRSxLQUFLLEVBQUUsYUFBYSxFQUFFLFNBQVMsQ0FBRTtLQUN4QyxLQUFLLENBQUUsS0FBSyxFQUFFLGFBQWEsRUFBRSxTQUFTLENBQUUsQ0FDeEMiLCJmaWxlIjoiY3J5cHRvZ3JhcGhpeC1zZS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmV4cG9ydCBjbGFzcyBCYXNlVExWXG57XG4gIHB1YmxpYyBzdGF0aWMgRW5jb2RpbmdzID0ge1xuICAgIEVNVjogMSxcbiAgICBER0k6IDJcbiAgfTtcblxuICBzdGF0aWMgcGFyc2VUTFYoIGJ1ZmZlcjogQnl0ZUFycmF5LCBlbmNvZGluZzogbnVtYmVyICk6IHsgdGFnOiBudW1iZXIsIGxlbjogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5LCBsZW5PZmZzZXQ6IG51bWJlciwgdmFsdWVPZmZzZXQ6IG51bWJlciB9XG4gIHtcbiAgICB2YXIgcmVzID0geyB0YWc6IDAsIGxlbjogMCwgdmFsdWU6IHVuZGVmaW5lZCwgbGVuT2Zmc2V0OiAwLCB2YWx1ZU9mZnNldDogMCB9O1xuICAgIHZhciBvZmYgPSAwO1xuICAgIHZhciBieXRlcyA9IGJ1ZmZlci5iYWNraW5nQXJyYXk7ICAvLyBUT0RPOiBVc2UgYnl0ZUF0KCAuLiApXG5cbiAgICBzd2l0Y2goIGVuY29kaW5nIClcbiAgICB7XG4gICAgICBjYXNlIEJhc2VUTFYuRW5jb2RpbmdzLkVNVjpcbiAgICAgIHtcbiAgICAgICAgd2hpbGUoICggb2ZmIDwgYnl0ZXMubGVuZ3RoICkgJiYgKCAoIGJ5dGVzWyBvZmYgXSA9PSAweDAwICkgfHwgKCBieXRlc1sgb2ZmIF0gPT0gMHhGRiApICkgKVxuICAgICAgICAgICsrb2ZmO1xuXG4gICAgICAgIGlmICggb2ZmID49IGJ5dGVzLmxlbmd0aCApXG4gICAgICAgICAgcmV0dXJuIHJlcztcblxuICAgICAgICBpZiAoICggYnl0ZXNbIG9mZiBdICYgMHgxRiApID09IDB4MUYgKVxuICAgICAgICB7XG4gICAgICAgICAgcmVzLnRhZyA9IGJ5dGVzWyBvZmYrKyBdIDw8IDg7XG4gICAgICAgICAgaWYgKCBvZmYgPj0gYnl0ZXMubGVuZ3RoIClcbiAgICAgICAgICB7IC8qbG9nKFwiMVwiKTsqLyAgcmV0dXJuIG51bGw7IH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJlcy50YWcgfD0gYnl0ZXNbIG9mZisrIF07XG5cbiAgICAgICAgcmVzLmxlbk9mZnNldCA9IG9mZjtcblxuICAgICAgICBpZiAoIG9mZiA+PSBieXRlcy5sZW5ndGggKVxuICAgICAgICB7IC8qbG9nKFwiMlwiKTsqLyAgcmV0dXJuIG51bGw7IH1cblxuICAgICAgICB2YXIgbGwgPSAoIGJ5dGVzWyBvZmYgXSAmIDB4ODAgKSA/ICggYnl0ZXNbIG9mZisrIF0gJiAweDdGICkgOiAxO1xuICAgICAgICB3aGlsZSggbGwtLSA+IDAgKVxuICAgICAgICB7XG4gICAgICAgICAgaWYgKCBvZmYgPj0gYnl0ZXMubGVuZ3RoIClcbiAgICAgICAgICB7IC8qbG9nKFwiMzpcIiArIG9mZiArIFwiOlwiICsgYnl0ZXMubGVuZ3RoKTsgICovcmV0dXJuIG51bGw7IH1cblxuICAgICAgICAgIHJlcy5sZW4gPSAoIHJlcy5sZW4gPDwgOCApIHwgYnl0ZXNbIG9mZisrIF07XG4gICAgICAgIH1cblxuICAgICAgICByZXMudmFsdWVPZmZzZXQgPSBvZmY7XG4gICAgICAgIGlmICggb2ZmICsgcmVzLmxlbiA+IGJ5dGVzLmxlbmd0aCApXG4gICAgICB7IC8qbG9nKFwiNFwiKTsqLyAgcmV0dXJuIG51bGw7IH1cbiAgICAgICAgcmVzLnZhbHVlID0gYnl0ZXMuc2xpY2UoIHJlcy52YWx1ZU9mZnNldCwgcmVzLnZhbHVlT2Zmc2V0ICsgcmVzLmxlbiApO1xuXG4gIC8vICAgICAgbG9nKCByZXMudmFsdWVPZmZzZXQgKyBcIitcIiArIHJlcy5sZW4gKyBcIj1cIiArIGJ5dGVzICk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiByZXM7XG4gIH1cblxuICBwdWJsaWMgYnl0ZUFycmF5OiBCeXRlQXJyYXk7XG4gIGVuY29kaW5nOiBudW1iZXI7XG5cbiAgY29uc3RydWN0b3IgKCB0YWc6IG51bWJlciwgdmFsdWU6IEJ5dGVBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIgKVxuICB7XG4gICAgdGhpcy5lbmNvZGluZyA9IGVuY29kaW5nIHx8IEJhc2VUTFYuRW5jb2RpbmdzLkVNVjtcblxuICAgIHN3aXRjaCggdGhpcy5lbmNvZGluZyApXG4gICAge1xuICAgICAgY2FzZSBCYXNlVExWLkVuY29kaW5ncy5FTVY6XG4gICAgICB7XG4gICAgICAgIHZhciB0bHZCdWZmZXIgPSBuZXcgQnl0ZUFycmF5KFtdKTtcblxuICAgICAgICBpZiAoIHRhZyA+PSAgMHgxMDAgKVxuICAgICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCAoIHRhZyA+PiA4ICkgJiAweEZGICk7XG4gICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCB0YWcgJiAweEZGICk7XG5cbiAgICAgICAgdmFyIGxlbiA9IHZhbHVlLmxlbmd0aDtcbiAgICAgICAgaWYgKCBsZW4gPiAweEZGIClcbiAgICAgICAge1xuICAgICAgICAgIHRsdkJ1ZmZlci5hZGRCeXRlKCAweDgyICk7XG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoICggbGVuID4+IDggKSAmIDB4RkYgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggbGVuID4gMHg3RiApXG4gICAgICAgICAgdGx2QnVmZmVyLmFkZEJ5dGUoIDB4ODEgKTtcblxuICAgICAgICB0bHZCdWZmZXIuYWRkQnl0ZSggbGVuICYgMHhGRiApO1xuXG4gICAgICAgIHRsdkJ1ZmZlci5jb25jYXQoIHZhbHVlICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSB0bHZCdWZmZXI7XG5cbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgZ2V0IHRhZygpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiBCYXNlVExWLnBhcnNlVExWKCB0aGlzLmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApLnRhZztcbiAgfVxuXG4gIGdldCB2YWx1ZSgpOiBCeXRlQXJyYXlcbiAge1xuICAgIHJldHVybiBCYXNlVExWLnBhcnNlVExWKCB0aGlzLmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApLnZhbHVlO1xuICB9XG5cbiAgZ2V0IGxlbigpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiBCYXNlVExWLnBhcnNlVExWKCB0aGlzLmJ5dGVBcnJheSwgdGhpcy5lbmNvZGluZyApLmxlbjtcbiAgfVxufVxuXG5CYXNlVExWLkVuY29kaW5nc1sgXCJDVFZcIiBdID0gNDsvLyB7IHBhcnNlOiAwLCBidWlsZDogMSB9O1xuIiwiaW1wb3J0IHsgIEJ5dGVBcnJheSwgS2luZCwgS2luZEJ1aWxkZXIsIEtpbmRJbmZvIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbi8qKlxuICogRW5jb2Rlci9EZWNvZG9yIEtpbmQgZm9yIGEgQVBEVSBDb21tYW5kXG4gKi9cbmV4cG9ydCBjbGFzcyBDb21tYW5kQVBEVSBpbXBsZW1lbnRzIEtpbmRcbntcbiAgQ0xBOiBudW1iZXI7IC8vID0gMDtcbiAgSU5TOiBudW1iZXIgPSAwO1xuICBQMTogbnVtYmVyID0gMDtcbiAgUDI6IG51bWJlciA9IDA7XG4gIGRhdGE6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcbiAgTGU6IG51bWJlciA9IDA7XG5cbi8vICBzdGF0aWMga2luZEluZm86IEtpbmRJbmZvO1xuXG4gIC8qKlxuICAgKiBAY29uc3RydWN0b3JcbiAgICpcbiAgICogRGVzZXJpYWxpemUgZnJvbSBhIEpTT04gb2JqZWN0XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYXR0cmlidXRlcz86IHt9IClcbiAge1xuICAgIEtpbmQuaW5pdEZpZWxkcyggdGhpcywgYXR0cmlidXRlcyApO1xuICB9XG5cbiAgcHVibGljIGdldCBMYygpOm51bWJlciAgICAgICAgICB7IHJldHVybiB0aGlzLmRhdGEubGVuZ3RoOyB9XG4gIHB1YmxpYyBnZXQgaGVhZGVyKCk6IEJ5dGVBcnJheSAgeyByZXR1cm4gbmV3IEJ5dGVBcnJheSggWyB0aGlzLkNMQSwgdGhpcy5JTlMsIHRoaXMuUDEsIHRoaXMuUDIgXSApOyB9XG5cbiAgLyoqXG4gICAqIEZsdWVudCBCdWlsZGVyXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIGluaXQoIENMQT86IG51bWJlciwgSU5TPzogbnVtYmVyLCBQMT86IG51bWJlciwgUDI/OiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXksIGV4cGVjdGVkTGVuPzogbnVtYmVyICk6IENvbW1hbmRBUERVXG4gIHtcbiAgICByZXR1cm4gKCBuZXcgQ29tbWFuZEFQRFUoKSApLnNldCggQ0xBLCBJTlMsIFAxLCBQMiwgZGF0YSwgZXhwZWN0ZWRMZW4gKTtcbiAgfVxuXG4gIHB1YmxpYyBzZXQoIENMQTogbnVtYmVyLCBJTlM6IG51bWJlciwgUDE6IG51bWJlciwgUDI6IG51bWJlciwgZGF0YT86IEJ5dGVBcnJheSwgZXhwZWN0ZWRMZW4/OiBudW1iZXIgKTogQ29tbWFuZEFQRFVcbiAge1xuICAgIHRoaXMuQ0xBID0gQ0xBO1xuICAgIHRoaXMuSU5TID0gSU5TO1xuICAgIHRoaXMuUDEgPSBQMTtcbiAgICB0aGlzLlAyID0gUDI7XG4gICAgdGhpcy5kYXRhID0gZGF0YSB8fCBuZXcgQnl0ZUFycmF5KCk7XG4gICAgdGhpcy5MZSA9IGV4cGVjdGVkTGVuIHx8IDA7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBzZXRDTEEoIENMQTogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgeyB0aGlzLkNMQSA9IENMQTsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldElOUyggSU5TOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICB7IHRoaXMuSU5TID0gSU5TOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0UDEoIFAxOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICAgIHsgdGhpcy5QMSA9IFAxOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0UDIoIFAyOiBudW1iZXIgKTogQ29tbWFuZEFQRFUgICAgICAgIHsgdGhpcy5QMiA9IFAyOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0RGF0YSggZGF0YTogQnl0ZUFycmF5ICk6IENvbW1hbmRBUERVIHsgdGhpcy5kYXRhID0gZGF0YTsgcmV0dXJuIHRoaXM7IH1cbiAgcHVibGljIHNldExlKCBMZTogbnVtYmVyICk6IENvbW1hbmRBUERVICAgICAgICB7IHRoaXMuTGUgPSBMZTsgcmV0dXJuIHRoaXM7IH1cblxuICAvKipcbiAgICogU2VyaWFsaXphdGlvbiwgcmV0dXJucyBhIEpTT04gb2JqZWN0XG4gICAqL1xuICBwdWJsaWMgdG9KU09OKCk6IHt9XG4gIHtcbiAgICByZXR1cm4ge1xuICAgICAgQ0xBOiB0aGlzLkNMQSxcbiAgICAgIElOUzogdGhpcy5JTlMsXG4gICAgICBQMTogdGhpcy5QMSxcbiAgICAgIFAyOiB0aGlzLlAyLFxuICAgICAgZGF0YTogdGhpcy5kYXRhLFxuICAgICAgTGU6IHRoaXMuTGVcbiAgICB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEVuY29kZXJcbiAgICovXG4gIHB1YmxpYyBlbmNvZGVCeXRlcyggb3B0aW9ucz86IHt9ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGRsZW4gPSAoICggdGhpcy5MYyA+IDAgKSA/IDEgKyB0aGlzLkxjIDogMCApO1xuICAgIGxldCBsZW4gPSA0ICsgZGxlbiArICggKCB0aGlzLkxlID4gMCApID8gMSA6IDAgKTtcbiAgICBsZXQgYmEgPSBuZXcgQnl0ZUFycmF5KCkuc2V0TGVuZ3RoKCBsZW4gKTtcblxuICAgIC8vIHJlYnVpbGQgYmluYXJ5IEFQRFVDb21tYW5kXG4gICAgYmEuc2V0Qnl0ZXNBdCggMCwgdGhpcy5oZWFkZXIgKTtcbiAgICBpZiAoIHRoaXMuTGMgKSB7XG4gICAgICBiYS5zZXRCeXRlQXQoIDQsIHRoaXMuTGMgKTtcbiAgICAgIGJhLnNldEJ5dGVzQXQoIDUsIHRoaXMuZGF0YSApO1xuICAgIH1cblxuICAgIGlmICggdGhpcy5MZSA+IDAgKSB7XG4gICAgICBiYS5zZXRCeXRlQXQoIDQgKyBkbGVuLCB0aGlzLkxlICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGJhO1xuICB9XG5cbiAgLyoqXG4gICogRGVjb2RlclxuICAqL1xuICBwdWJsaWMgZGVjb2RlQnl0ZXMoIGJ5dGVBcnJheTogQnl0ZUFycmF5LCBvcHRpb25zPzoge30gKTogQ29tbWFuZEFQRFVcbiAge1xuICAgIGlmICggYnl0ZUFycmF5Lmxlbmd0aCA8IDQgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tbWFuZEFQRFU6IEludmFsaWQgYnVmZmVyJyApO1xuXG4gICAgbGV0IG9mZnNldCA9IDA7XG5cbiAgICB0aGlzLkNMQSA9IGJ5dGVBcnJheS5ieXRlQXQoIG9mZnNldCsrICk7XG4gICAgdGhpcy5JTlMgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuICAgIHRoaXMuUDEgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuICAgIHRoaXMuUDIgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuXG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoID4gb2Zmc2V0ICsgMSApXG4gICAge1xuICAgICAgdmFyIExjID0gYnl0ZUFycmF5LmJ5dGVBdCggb2Zmc2V0KysgKTtcbiAgICAgIHRoaXMuZGF0YSA9IGJ5dGVBcnJheS5ieXRlc0F0KCBvZmZzZXQsIExjICk7XG4gICAgICBvZmZzZXQgKz0gTGM7XG4gICAgfVxuXG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoID4gb2Zmc2V0IClcbiAgICAgIHRoaXMuTGUgPSBieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQrKyApO1xuXG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoICE9IG9mZnNldCApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21tYW5kQVBEVTogSW52YWxpZCBidWZmZXInICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG5LaW5kQnVpbGRlci5pbml0KCBDb21tYW5kQVBEVSwgJ0lTTzc4MTYgQ29tbWFuZCBBUERVJyApXG4gIC5ieXRlRmllbGQoICdDTEEnLCAnQ2xhc3MnIClcbiAgLmJ5dGVGaWVsZCggJ0lOUycsICdJbnN0cnVjdGlvbicgKVxuICAuYnl0ZUZpZWxkKCAnUDEnLCAnUDEgUGFyYW0nIClcbiAgLmJ5dGVGaWVsZCggJ1AyJywgJ1AyIFBhcmFtJyApXG4gIC5pbnRlZ2VyRmllbGQoICdMYycsICdDb21tYW5kIExlbmd0aCcsIHsgY2FsY3VsYXRlZDogdHJ1ZSB9IClcbiAgLmZpZWxkKCAnZGF0YScsICdDb21tYW5kIERhdGEnLCBCeXRlQXJyYXkgKVxuICAuaW50ZWdlckZpZWxkKCAnTGUnLCAnRXhwZWN0ZWQgTGVuZ3RoJyApXG4gIDtcbiIsImV4cG9ydCBlbnVtIElTTzc4MTZcclxue1xyXG4gIC8vIElTTyBjbGFzcyBjb2RlXHJcbiAgQ0xBX0lTTyA9IDB4MDAsXHJcblxyXG4gIC8vIEV4dGVybmFsIGV4dGVybmFsIGF1dGhlbnRpY2F0ZSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX0VYVEVSTkFMX0FVVEhFTlRJQ0FURSA9IDB4ODIsXHJcblxyXG4gIC8vIEdldCBjaGFsbGVuZ2UgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19HRVRfQ0hBTExFTkdFID0gMHg4NCxcclxuXHJcbiAgLy8gSW50ZXJuYWwgYXV0aGVudGljYXRlIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfSU5URVJOQUxfQVVUSEVOVElDQVRFID0gMHg4OCxcclxuXHJcbiAgLy8gU2VsZWN0IGZpbGUgaW5zdHJ1Y3Rpb24gY29kZVxyXG4gIElOU19TRUxFQ1RfRklMRSA9IDB4QTQsXHJcblxyXG4gIC8vIFJlYWQgcmVjb3JkIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfUkVBRF9SRUNPUkQgPSAweEIyLFxyXG5cclxuICAvLyBVcGRhdGUgcmVjb3JkIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfVVBEQVRFX1JFQ09SRCA9IDB4REMsXHJcblxyXG4gIC8vIFZlcmlmeSBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1ZFUklGWSA9IDB4MjAsXHJcblxyXG4gIC8vIEJsb2NrIEFwcGxpY2F0aW9uIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfQkxPQ0tfQVBQTElDQVRJT04gPSAweDFFLFxyXG5cclxuICAvLyBVbmJsb2NrIGFwcGxpY2F0aW9uIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfVU5CTE9DS19BUFBMSUNBVElPTiA9IDB4MTgsXHJcblxyXG4gIC8vIFVuYmxvY2sgY2hhbmdlIFBJTiBpbnN0cnVjdGlvbiBjb2RlXHJcbiAgSU5TX1VOQkxPQ0tfQ0hBTkdFX1BJTiA9IDB4MjQsXHJcblxyXG4gIC8vIEdldCBkYXRhIGluc3RydWN0aW9uIGNvZGVcclxuICBJTlNfR0VUX0RBVEEgPSAweENBLFxyXG5cclxuICAvLyBBcHBsaWNhdGlvbiBUZW1wbGF0ZVxyXG4gIFRBR19BUFBMSUNBVElPTl9URU1QTEFURSA9IDB4NjEsXHJcblxyXG4gIC8vIEZDSSBQcm9wcmlldGFyeSBUZW1wbGF0ZVxyXG4gIFRBR19GQ0lfUFJPUFJJRVRBUllfVEVNUExBVEUgPSAweEE1LFxyXG5cclxuICAvLyBGQ0kgVGVtcGxhdGVcclxuICBUQUdfRkNJX1RFTVBMQVRFID0gMHg2RixcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gSWRlbnRpZmllciAoQUlEKSAtIGNhcmRcclxuICBUQUdfQUlEID0gMHg0RixcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gTGFiZWxcclxuICBUQUdfQVBQTElDQVRJT05fTEFCRUwgPSAweDUwLFxyXG5cclxuICAvLyBMYW5ndWFnZSBQcmVmZXJlbmNlXHJcbiAgVEFHX0xBTkdVQUdFX1BSRUZFUkVOQ0VTID0gMHg1RjJELFxyXG5cclxuICAvLyBBcHBsaWNhdGlvbiBFZmZlY3RpdmUgRGF0YVxyXG4gIFRBR19BUFBMSUNBVElPTl9FRkZFQ1RJVkVfREFURSA9IDB4NUYyNSxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gRXhwaXJhdGlvbiBEYXRlXHJcbiAgVEFHX0FQUExJQ0FUSU9OX0VYUElSWV9EQVRFID0gMHg1RjI0LFxyXG5cclxuICAvLyBDYXJkIEhvbGRlciBOYW1lXHJcbiAgVEFHX0NBUkRIT0xERVJfTkFNRSA9IDB4NUYyMCxcclxuXHJcbiAgLy8gSXNzdWVyIENvdW50cnkgQ29kZVxyXG4gIFRBR19JU1NVRVJfQ09VTlRSWV9DT0RFID0gMHg1RjI4LFxyXG5cclxuICAvLyBJc3N1ZXIgVVJMXHJcbiAgVEFHX0lTU1VFUl9VUkwgPSAweDVGNTAsXHJcblxyXG4gIC8vIEFwcGxpY2F0aW9uIFByaW1hcnkgQWNjb3VudCBOdW1iZXIgKFBBTilcclxuICBUQUdfUEFOID0gMHg1YSxcclxuXHJcbiAgLy8gQXBwbGljYXRpb24gUHJpbWFyeSBBY2NvdW50IE51bWJlciAoUEFOKSBTZXF1ZW5jZSBOdW1iZXJcclxuICBUQUdfUEFOX1NFUVVFTkNFX05VTUJFUiA9IDB4NUYzNCxcclxuXHJcbiAgLy8gU2VydmljZSBDb2RlXHJcbiAgVEFHX1NFUlZJQ0VfQ09ERSA9IDB4NUYzMCxcclxuXHJcbiAgSVNPX1BJTkJMT0NLX1NJWkUgPSA4LCAgIC8vPCBTaXplIG9mIGFuIElTTyBQSU4gYmxvY2tcclxuXHJcbiAgQVBEVV9MRU5fTEVfTUFYID0gMjU2LCAgIC8vPCBNYXhpbXVtIHNpemUgZm9yIExlXHJcblxyXG4gIFNXX1NVQ0NFU1MgPSAweDkwMDAsXHJcbiAgLy8gIFNXX0JZVEVTX1JFTUFJTklORyhTVzIpID0gMHg2MSMjU1cyLFxyXG4gIFNXX1dBUk5JTkdfTlZfTUVNT1JZX1VOQ0hBTkdFRCA9IDB4NjIwMCAsXHJcbiAgU1dfUEFSVF9PRl9SRVRVUk5fREFUQV9DT1JSVVBURUQgPSAweDYyODEsXHJcbiAgU1dfRU5EX0ZJTEVfUkVBQ0hFRF9CRUZPUkVfTEVfQllURSA9IDB4NjI4MixcclxuICBTV19TRUxFQ1RFRF9GSUxFX0lOVkFMSUQgPSAweDYyODMsXHJcbiAgU1dfRkNJX05PVF9GT1JNQVRURURfVE9fSVNPID0gMHg2Mjg0LFxyXG4gIFNXX1dBUk5JTkdfTlZfTUVNT1JZX0NIQU5HRUQgPSAweDYzMDAsXHJcbiAgU1dfRklMRV9GSUxMRURfQllfTEFTVF9XUklURSA9IDB4NjM4MSxcclxuICAvLyAgU1dfQ09VTlRFUl9QUk9WSURFRF9CWV9YKFgpID0gMHg2M0MjI1gsXHJcbiAgLy8gIFNXX0VSUk9SX05WX01FTU9SWV9VTkNIQU5HRUQoU1cyKSA9IDB4NjQjI1NXMixcclxuICAvLyAgU1dfRVJST1JfTlZfTUVNT1JZX0NIQU5HRUQoU1cyKSA9IDB4NjUjI1NXMiAsXHJcbiAgLy8gIFNXX1JFU0VSVkVEKFNXMikgPSAweDY2IyNTVzIsXHJcbiAgU1dfV1JPTkdfTEVOR1RIID0gMHg2NzAwICxcclxuICBTV19GVU5DVElPTlNfSU5fQ0xBX05PVF9TVVBQT1JURUQgPSAweDY4MDAsXHJcbiAgU1dfTE9HSUNBTF9DSEFOTkVMX05PVF9TVVBQT1JURUQgPSAweDY4ODEsXHJcbiAgU1dfU0VDVVJFX01FU1NBR0lOR19OT1RfU1VQUE9SVEVEID0gMHg2ODgyLFxyXG4gIFNXX0NPTU1BTkRfTk9UX0FMTE9XRUQgPSAweDY5MDAsXHJcbiAgU1dfQ09NTUFORF9JTkNPTVBBVElCTEVfV0lUSF9GSUxFX1NUUlVDVFVSRSA9IDB4Njk4MSxcclxuICBTV19TRUNVUklUWV9TVEFUVVNfTk9UX1NBVElTRklFRCA9IDB4Njk4MixcclxuICBTV19GSUxFX0lOVkFMSUQgPSAweDY5ODMsXHJcbiAgU1dfREFUQV9JTlZBTElEID0gMHg2OTg0LFxyXG4gIFNXX0NPTkRJVElPTlNfTk9UX1NBVElTRklFRCA9IDB4Njk4NSxcclxuICBTV19DT01NQU5EX05PVF9BTExPV0VEX0FHQUlOID0gMHg2OTg2LFxyXG4gIFNXX0VYUEVDVEVEX1NNX0RBVEFfT0JKRUNUU19NSVNTSU5HID0gMHg2OTg3ICxcclxuICBTV19TTV9EQVRBX09CSkVDVFNfSU5DT1JSRUNUID0gMHg2OTg4LFxyXG4gIFNXX1dST05HX1BBUkFNUyA9IDB4NkEwMCAgICxcclxuICBTV19XUk9OR19EQVRBID0gMHg2QTgwLFxyXG4gIFNXX0ZVTkNfTk9UX1NVUFBPUlRFRCA9IDB4NkE4MSxcclxuICBTV19GSUxFX05PVF9GT1VORCA9IDB4NkE4MixcclxuICBTV19SRUNPUkRfTk9UX0ZPVU5EID0gMHg2QTgzLFxyXG4gIFNXX05PVF9FTk9VR0hfU1BBQ0VfSU5fRklMRSA9IDB4NkE4NCxcclxuICBTV19MQ19JTkNPTlNJU1RFTlRfV0lUSF9UTFYgPSAweDZBODUsXHJcbiAgU1dfSU5DT1JSRUNUX1AxUDIgPSAweDZBODYsXHJcbiAgU1dfTENfSU5DT05TSVNURU5UX1dJVEhfUDFQMiA9IDB4NkE4NyxcclxuICBTV19SRUZFUkVOQ0VEX0RBVEFfTk9UX0ZPVU5EID0gMHg2QTg4LFxyXG4gIFNXX1dST05HX1AxUDIgPSAweDZCMDAsXHJcbiAgLy9TV19DT1JSRUNUX0xFTkdUSChTVzIpID0gMHg2QyMjU1cyLFxyXG4gIFNXX0lOU19OT1RfU1VQUE9SVEVEID0gMHg2RDAwLFxyXG4gIFNXX0NMQV9OT1RfU1VQUE9SVEVEID0gMHg2RTAwLFxyXG4gIFNXX1VOS05PV04gPSAweDZGMDAsXHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5LCBLaW5kLCBLaW5kSW5mbywgS2luZEJ1aWxkZXIgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcbmltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuL2lzbzc4MTYnO1xuXG4vKipcbiAqIEVuY29kZXIvRGVjb2RvciBmb3IgYSBBUERVIFJlc3BvbnNlXG4gKi9cbmV4cG9ydCBjbGFzcyBSZXNwb25zZUFQRFUgaW1wbGVtZW50cyBLaW5kXG57XG4gIFNXOiBudW1iZXIgPSBJU083ODE2LlNXX1NVQ0NFU1M7XG4gIGRhdGE6IEJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoKTtcblxuLy8gIHN0YXRpYyBraW5kSW5mbzogS2luZEluZm87XG5cbiAgLyoqXG4gICAqIEBjb25zdHJ1Y3RvclxuICAgKlxuICAgKiBEZXNlcmlhbGl6ZSBmcm9tIGEgSlNPTiBvYmplY3RcbiAgICovXG4gIGNvbnN0cnVjdG9yKCBhdHRyaWJ1dGVzPzoge30gKVxuICB7XG4gICAgS2luZC5pbml0RmllbGRzKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IExhKCkgeyByZXR1cm4gdGhpcy5kYXRhLmxlbmd0aDsgfVxuXG4gIHB1YmxpYyBzdGF0aWMgaW5pdCggc3c6IG51bWJlciwgZGF0YT86IEJ5dGVBcnJheSApOiBSZXNwb25zZUFQRFVcbiAge1xuICAgIHJldHVybiAoIG5ldyBSZXNwb25zZUFQRFUoKSApLnNldCggc3csIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzZXQoIHN3OiBudW1iZXIsIGRhdGE/OiBCeXRlQXJyYXkgKTogUmVzcG9uc2VBUERVXG4gIHtcbiAgICB0aGlzLlNXID0gc3c7XG4gICAgdGhpcy5kYXRhID0gZGF0YSB8fCBuZXcgQnl0ZUFycmF5KCk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBzZXRTVyggU1c6IG51bWJlciApOiBSZXNwb25zZUFQRFUgICAgICAgIHsgdGhpcy5TVyA9IFNXOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0U1cxKCBTVzE6IG51bWJlciApOiBSZXNwb25zZUFQRFUgICAgICB7IHRoaXMuU1cgPSAoIHRoaXMuU1cgJiAweEZGICkgfCAoIFNXMSA8PCA4ICk7IHJldHVybiB0aGlzOyB9XG4gIHB1YmxpYyBzZXRTVzIoIFNXMjogbnVtYmVyICk6IFJlc3BvbnNlQVBEVSAgICAgIHsgdGhpcy5TVyA9ICggdGhpcy5TVyAmIDB4RkYwMCApIHwgU1cyOyByZXR1cm4gdGhpczsgfVxuICBwdWJsaWMgc2V0RGF0YSggZGF0YTogQnl0ZUFycmF5ICk6IFJlc3BvbnNlQVBEVSB7IHRoaXMuZGF0YSA9IGRhdGE7IHJldHVybiB0aGlzOyB9XG5cbiAgLyoqXG4gICAqIEVuY29kZXIgZnVuY3Rpb24sIHJldHVybnMgYSBibG9iIGZyb20gYW4gQVBEVVJlc3BvbnNlIG9iamVjdFxuICAgKi9cbiAgcHVibGljIGVuY29kZUJ5dGVzKCBvcHRpb25zPzoge30gKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSBuZXcgQnl0ZUFycmF5KCkuc2V0TGVuZ3RoKCB0aGlzLkxhICsgMiApO1xuXG4gICAgYmEuc2V0Qnl0ZXNBdCggMCwgdGhpcy5kYXRhICk7XG4gICAgYmEuc2V0Qnl0ZUF0KCB0aGlzLkxhICAgICwgKCB0aGlzLlNXID4+IDggKSAmIDB4ZmYgKTtcbiAgICBiYS5zZXRCeXRlQXQoIHRoaXMuTGEgKyAxLCAoIHRoaXMuU1cgPj4gMCApICYgMHhmZiApO1xuXG4gICAgcmV0dXJuIGJhO1xuICB9XG5cbiAgcHVibGljIGRlY29kZUJ5dGVzKCBieXRlQXJyYXk6IEJ5dGVBcnJheSwgb3B0aW9ucz86IHt9ICk6IFJlc3BvbnNlQVBEVVxuICB7XG4gICAgaWYgKCBieXRlQXJyYXkubGVuZ3RoIDwgMiApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdSZXNwb25zZUFQRFUgQnVmZmVyIGludmFsaWQnICk7XG5cbiAgICBsZXQgbGEgPSBieXRlQXJyYXkubGVuZ3RoIC0gMjtcblxuICAgIHRoaXMuU1cgPSBieXRlQXJyYXkud29yZEF0KCBsYSApO1xuICAgIHRoaXMuZGF0YSA9ICggbGEgKSA/IGJ5dGVBcnJheS5ieXRlc0F0KCAwLCBsYSApIDogbmV3IEJ5dGVBcnJheSgpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbn1cblxuS2luZEJ1aWxkZXIuaW5pdCggUmVzcG9uc2VBUERVLCAnSVNPNzgxNiBSZXNwb25zZSBBUERVJyApXG4gIC5pbnRlZ2VyRmllbGQoICdTVycsICdTdGF0dXMgV29yZCcsIHsgbWF4aW11bTogMHhGRkZGIH0gKVxuICAuaW50ZWdlckZpZWxkKCAnTGEnLCAnQWN0dWFsIExlbmd0aCcsICB7IGNhbGN1bGF0ZWQ6IHRydWUgfSApXG4gIC5maWVsZCggJ0RhdGEnLCAnUmVzcG9uc2UgRGF0YScsIEJ5dGVBcnJheSApXG4gIDtcbiIsbnVsbCwiaW1wb3J0IHsgQnl0ZUFycmF5LCBFbmRQb2ludCwgTWVzc2FnZSwgTWVzc2FnZUhlYWRlciB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBTbG90IH0gZnJvbSAnLi4vYmFzZS9zbG90JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vYmFzZS9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vYmFzZS9yZXNwb25zZS1hcGR1JztcblxuZXhwb3J0IGNsYXNzIFNsb3RQcm90b2NvbEhhbmRsZXJcbntcbiAgZW5kUG9pbnQ6IEVuZFBvaW50O1xuICBzbG90OiBTbG90O1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICB9XG5cbiAgbGlua1Nsb3QoIHNsb3Q6IFNsb3QsIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICB0aGlzLmVuZFBvaW50ID0gZW5kUG9pbnQ7XG4gICAgdGhpcy5zbG90ID0gc2xvdDtcblxuICAgIGVuZFBvaW50Lm9uTWVzc2FnZSggdGhpcy5vbk1lc3NhZ2UgKTtcbiAgfVxuXG4gIHVubGlua1Nsb3QoKVxuICB7XG4gICAgdGhpcy5lbmRQb2ludC5vbk1lc3NhZ2UoIG51bGwgKTtcbiAgICB0aGlzLmVuZFBvaW50ID0gbnVsbDtcbiAgICB0aGlzLnNsb3QgPSBudWxsO1xuICB9XG5cbiAgb25NZXNzYWdlKCBwYWNrZXQ6IE1lc3NhZ2U8YW55PiwgcmVjZWl2aW5nRW5kUG9pbnQ6IEVuZFBvaW50IClcbiAge1xuICAgIGxldCBoZHI6IGFueSA9IHBhY2tldC5oZWFkZXI7XG4gICAgbGV0IHBheWxvYWQgPSBwYWNrZXQucGF5bG9hZDtcblxuICAgIGxldCByZXNwb25zZTogUHJvbWlzZTxhbnk+O1xuXG4gICAgc3dpdGNoKCBoZHIubWV0aG9kIClcbiAgICB7XG4gICAgICBjYXNlIFwiZXhlY3V0ZUFQRFVcIjpcbiAgICAgICAgaWYgKCAhKCBwYXlsb2FkIGluc3RhbmNlb2YgQ29tbWFuZEFQRFUgKSApXG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgcmVzcG9uc2UgPSB0aGlzLnNsb3QuZXhlY3V0ZUFQRFUoIDxDb21tYW5kQVBEVT5wYXlsb2FkICk7XG5cbiAgICAgICAgcmVzcG9uc2UudGhlbiggKCByZXNwb25zZUFQRFU6IFJlc3BvbnNlQVBEVSApID0+IHtcbiAgICAgICAgICBsZXQgcmVwbHlQYWNrZXQgPSBuZXcgTWVzc2FnZTxSZXNwb25zZUFQRFU+KCB7IG1ldGhvZDogXCJleGVjdXRlQVBEVVwiIH0sIHJlc3BvbnNlQVBEVSApO1xuXG4gICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIHJlcGx5UGFja2V0ICk7XG4gICAgICAgIH0pO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBcInBvd2VyT2ZmXCI6XG4gICAgICAgIHJlc3BvbnNlID0gdGhpcy5zbG90LnBvd2VyT2ZmKClcbiAgICAgICAgICAudGhlbiggKCByZXNwRGF0YTogYm9vbGVhbiApPT4ge1xuICAgICAgICAgICAgcmVjZWl2aW5nRW5kUG9pbnQuc2VuZE1lc3NhZ2UoIG5ldyBNZXNzYWdlPEJ5dGVBcnJheT4oIHsgbWV0aG9kOiBoZHIubWV0aG9kIH0sIG5ldyBCeXRlQXJyYXkoKSApICk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFwicG93ZXJPblwiOlxuICAgICAgICByZXNwb25zZSA9IHRoaXMuc2xvdC5wb3dlck9uKClcbiAgICAgICAgICAudGhlbiggKCByZXNwRGF0YTogQnl0ZUFycmF5ICk9PiB7XG4gICAgICAgICAgICByZWNlaXZpbmdFbmRQb2ludC5zZW5kTWVzc2FnZSggbmV3IE1lc3NhZ2U8Qnl0ZUFycmF5PiggeyBtZXRob2Q6IGhkci5tZXRob2QgfSwgcmVzcERhdGEgKSApO1xuICAgICAgICAgIH0pO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBcInJlc2V0XCI6XG4gICAgICAgIHJlc3BvbnNlID0gdGhpcy5zbG90LnJlc2V0KClcbiAgICAgICAgICAudGhlbiggKCByZXNwRGF0YTogQnl0ZUFycmF5ICk9PiB7XG4gICAgICAgICAgICByZWNlaXZpbmdFbmRQb2ludC5zZW5kTWVzc2FnZSggbmV3IE1lc3NhZ2U8Qnl0ZUFycmF5PiggeyBtZXRob2Q6IGhkci5tZXRob2QgfSwgcmVzcERhdGEgKSApO1xuICAgICAgICAgIH0pO1xuICAgICAgICBicmVhaztcblxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmVzcG9uc2UgPSBQcm9taXNlLnJlamVjdDxFcnJvcj4oIG5ldyBFcnJvciggXCJJbnZhbGlkIG1ldGhvZFwiICsgaGRyLm1ldGhvZCApICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH0gLy8gc3dpdGNoXG5cbiAgICAvLyB0cmFwIGFuZCByZXR1cm4gYW55IGVycm9yc1xuICAgIHJlc3BvbnNlLmNhdGNoKCAoIGU6IGFueSApID0+IHtcbiAgICAgIGxldCBlcnJvclBhY2tldCA9IG5ldyBNZXNzYWdlPEVycm9yPiggeyBtZXRob2Q6IFwiZXJyb3JcIiB9LCBlICk7XG5cbiAgICAgIHJlY2VpdmluZ0VuZFBvaW50LnNlbmRNZXNzYWdlKCBlcnJvclBhY2tldCApO1xuICAgIH0pO1xuICB9XG59XG4iLG51bGwsbnVsbCxudWxsLG51bGwsbnVsbCwiaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5cclxuZXhwb3J0IGNsYXNzIEtleVxyXG57XHJcbiAgX3R5cGU6IG51bWJlcjtcclxuICBfc2l6ZTogbnVtYmVyO1xyXG4gIF9jb21wb25lbnRBcnJheTogQnl0ZVN0cmluZ1tdO1xyXG5cclxuICBjb25zdHJ1Y3RvcigpXHJcbiAge1xyXG4gICAgdGhpcy5fdHlwZSA9IDA7XHJcbiAgICB0aGlzLl9zaXplID0gLTE7XHJcbiAgICB0aGlzLl9jb21wb25lbnRBcnJheSA9IFtdO1xyXG4gIH1cclxuXHJcbiAgc2V0VHlwZSgga2V5VHlwZTogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl90eXBlID0ga2V5VHlwZTtcclxuICB9XHJcblxyXG4gIGdldFR5cGUoKTogbnVtYmVyXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3R5cGU7XHJcbiAgfVxyXG5cclxuICBzZXRTaXplKCBzaXplOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHRoaXMuX3NpemUgPSBzaXplO1xyXG4gIH1cclxuXHJcbiAgZ2V0U2l6ZSgpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5fc2l6ZTtcclxuICB9XHJcblxyXG4gIHNldENvbXBvbmVudCggY29tcDogbnVtYmVyLCB2YWx1ZTogQnl0ZVN0cmluZyApXHJcbiAge1xyXG4gICAgdGhpcy5fY29tcG9uZW50QXJyYXlbIGNvbXAgXSA9IHZhbHVlO1xyXG4gIH1cclxuXHJcbiAgZ2V0Q29tcG9uZW50KCBjb21wOiBudW1iZXIgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLl9jb21wb25lbnRBcnJheVsgY29tcCBdO1xyXG4gIH1cclxuXHJcblxyXG4gIHN0YXRpYyBTRUNSRVQgPSAxO1xyXG4gIHN0YXRpYyBQUklWQVRFID0gMjtcclxuICBzdGF0aWMgUFVCTElDID0gMztcclxuXHJcbiAgc3RhdGljIERFUyA9IDE7XHJcbiAgc3RhdGljIEFFUyA9IDI7XHJcbiAgc3RhdGljIE1PRFVMVVMgPSAzO1xyXG4gIHN0YXRpYyBFWFBPTkVOVCA9IDQ7XHJcbiAgc3RhdGljIENSVF9QID0gNTtcclxuICBzdGF0aWMgQ1JUX1EgPSA2O1xyXG4gIHN0YXRpYyBDUlRfRFAxID0gNztcclxuICBzdGF0aWMgQ1JUX0RRMSA9IDg7XHJcbiAgc3RhdGljIENSVF9QUSA9IDk7XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5pbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XG5pbXBvcnQgeyBLZXkgfSBmcm9tICcuL2tleSc7XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9cbntcbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cblxuICBlbmNyeXB0KCBrZXk6IEtleSwgbWVjaCwgZGF0YTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXG4gIHtcbiAgICB2YXIgazogQnl0ZUFycmF5ID0ga2V5LmdldENvbXBvbmVudCggS2V5LlNFQ1JFVCApLmJ5dGVBcnJheTtcblxuICAgIGlmICggay5sZW5ndGggPT0gMTYgKSAgLy8gM0RFUyBEb3VibGUgLT4gVHJpcGxlXG4gICAge1xuICAgICAgdmFyIG9yaWcgPSBrO1xuXG4gICAgICBrID0gbmV3IEJ5dGVBcnJheSggW10gKS5zZXRMZW5ndGgoIDI0ICk7XG5cbiAgICAgIGsuc2V0Qnl0ZXNBdCggMCwgb3JpZyApO1xuICAgICAgay5zZXRCeXRlc0F0KCAxNiwgb3JpZy52aWV3QXQoIDAsIDggKSApO1xuICAgIH1cblxuICAgIHZhciBjcnlwdG9UZXh0ID0gbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGsuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDAgKSApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCBjcnlwdG9UZXh0ICk7XG4gIH1cblxuICBkZWNyeXB0KCBrZXksIG1lY2gsIGRhdGEgKVxuICB7XG4gICAgcmV0dXJuIGRhdGE7XG4gIH1cblxuICBzaWduKCBrZXk6IEtleSwgbWVjaCwgZGF0YTogQnl0ZVN0cmluZywgaXY/ICk6IEJ5dGVTdHJpbmdcbiAge1xuICAgIHZhciBrID0ga2V5LmdldENvbXBvbmVudCggS2V5LlNFQ1JFVCApLmJ5dGVBcnJheTtcblxuICAgIHZhciBrZXlEYXRhID0gaztcblxuICAgIGlmICggay5sZW5ndGggPT0gMTYgKSAgLy8gM0RFUyBEb3VibGUgLT4gVHJpcGxlXG4gICAge1xuICAgICAga2V5RGF0YSA9IG5ldyBCeXRlQXJyYXkoKTtcblxuICAgICAga2V5RGF0YVxuICAgICAgICAuc2V0TGVuZ3RoKCAyNCApXG4gICAgICAgIC5zZXRCeXRlc0F0KCAwLCBrIClcbiAgICAgICAgLnNldEJ5dGVzQXQoIDE2LCBrLmJ5dGVzQXQoIDAsIDggKSApO1xuICAgIH1cblxuICAgIGlmICggaXYgPT0gdW5kZWZpbmVkIClcbiAgICAgIGl2ID0gbmV3IFVpbnQ4QXJyYXkoIFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdICk7XG5cbiAgICAvLyBmdW5jdGlvbigga2V5LCBtZXNzYWdlLCBlbmNyeXB0LCBtb2RlLCBpdiwgcGFkZGluZyApXG4gICAgLy8gbW9kZT0xIENCQywgcGFkZGluZz00IG5vLXBhZFxuICAgIHZhciBjcnlwdG9UZXh0ID0gbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGtleURhdGEuYmFja2luZ0FycmF5LCBkYXRhLmJ5dGVBcnJheS5iYWNraW5nQXJyYXksIDEsIDEsIGl2LCA0ICkgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggY3J5cHRvVGV4dCApLmJ5dGVzKCAtOCApO1xuICB9XG5cbiAgc3RhdGljIGRlc1BDO1xuICBzdGF0aWMgZGVzU1A7XG5cbiAgcHJpdmF0ZSBkZXMoIGtleTogVWludDhBcnJheSwgbWVzc2FnZTogVWludDhBcnJheSwgZW5jcnlwdDogbnVtYmVyLCBtb2RlOiBudW1iZXIsIGl2PzogVWludDhBcnJheSwgcGFkZGluZz86IG51bWJlciApOiBVaW50OEFycmF5XG4gIHtcbiAgICAvL2Rlc19jcmVhdGVLZXlzXG4gICAgLy90aGlzIHRha2VzIGFzIGlucHV0IGEgNjQgYml0IGtleSAoZXZlbiB0aG91Z2ggb25seSA1NiBiaXRzIGFyZSB1c2VkKVxuICAgIC8vYXMgYW4gYXJyYXkgb2YgMiBpbnRlZ2VycywgYW5kIHJldHVybnMgMTYgNDggYml0IGtleXNcbiAgICBmdW5jdGlvbiBkZXNfY3JlYXRlS2V5cyAoa2V5KVxuICAgIHtcbiAgICAgIGlmICggQ3J5cHRvLmRlc1BDID09IHVuZGVmaW5lZCApXG4gICAgICB7XG4gICAgICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgICAgIENyeXB0by5kZXNQQyA9IHtcbiAgICAgICAgICBwYzJieXRlczAgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgyMDAwMDAwMCwweDIwMDAwMDA0LDB4MTAwMDAsMHgxMDAwNCwweDIwMDEwMDAwLDB4MjAwMTAwMDQsMHgyMDAsMHgyMDQsMHgyMDAwMDIwMCwweDIwMDAwMjA0LDB4MTAyMDAsMHgxMDIwNCwweDIwMDEwMjAwLDB4MjAwMTAyMDQgXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MSwweDEwMDAwMCwweDEwMDAwMSwweDQwMDAwMDAsMHg0MDAwMDAxLDB4NDEwMDAwMCwweDQxMDAwMDEsMHgxMDAsMHgxMDEsMHgxMDAxMDAsMHgxMDAxMDEsMHg0MDAwMTAwLDB4NDAwMDEwMSwweDQxMDAxMDAsMHg0MTAwMTAxXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDgsMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAwMDAwLDB4ODAwMDAwMCwweDgyMDAwMDAsMHgyMDAwLDB4MjAyMDAwLDB4ODAwMjAwMCwweDgyMDIwMDAsMHgyMDAwMCwweDIyMDAwMCwweDgwMjAwMDAsMHg4MjIwMDAwLDB4MjIwMDAsMHgyMjIwMDAsMHg4MDIyMDAwLDB4ODIyMjAwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczQgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwLDB4MjAsMHg0MjAsMCwweDQwMCwweDIwLDB4NDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjBdICksXG4gICAgICAgICAgcGMyYnl0ZXM2IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyLDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAsMHg4MDAsMHgxMDgwMCwweDIwMDAwMDAwLDB4MjAwMTAwMDAsMHgyMDAwMDgwMCwweDIwMDEwODAwLDB4MjAwMDAsMHgzMDAwMCwweDIwODAwLDB4MzA4MDAsMHgyMDAyMDAwMCwweDIwMDMwMDAwLDB4MjAwMjA4MDAsMHgyMDAzMDgwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczggOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDAsMHg0MDAwMCwweDIsMHg0MDAwMiwweDIsMHg0MDAwMiwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAyLDB4MjA0MDAwMiwweDIwMDAwMDIsMHgyMDQwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMCwwLDB4MjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgyMDAwLDB4MjAyMCwweDIwMDAsMHgyMDIwLDB4MTAyMDAwLDB4MTAyMDIwLDB4MTAyMDAwLDB4MTAyMDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTE6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMCwweDIwMCwweDEwMDAyMDAsMHgyMDAwMDAsMHgxMjAwMDAwLDB4MjAwMjAwLDB4MTIwMDIwMCwweDQwMDAwMDAsMHg1MDAwMDAwLDB4NDAwMDIwMCwweDUwMDAyMDAsMHg0MjAwMDAwLDB4NTIwMDAwMCwweDQyMDAyMDAsMHg1MjAwMjAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTI6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMCwweDgwMDAwMDAsMHg4MDAxMDAwLDB4ODAwMDAsMHg4MTAwMCwweDgwODAwMDAsMHg4MDgxMDAwLDB4MTAsMHgxMDEwLDB4ODAwMDAxMCwweDgwMDEwMTAsMHg4MDAxMCwweDgxMDEwLDB4ODA4MDAxMCwweDgwODEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMzogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MTAwLDB4MTA0LDAsMHg0LDB4MTAwLDB4MTA0LDB4MSwweDUsMHgxMDEsMHgxMDUsMHgxLDB4NSwweDEwMSwweDEwNV0gKVxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICAvL2hvdyBtYW55IGl0ZXJhdGlvbnMgKDEgZm9yIGRlcywgMyBmb3IgdHJpcGxlIGRlcylcbiAgICAgIHZhciBpdGVyYXRpb25zID0ga2V5Lmxlbmd0aCA+IDggPyAzIDogMTsgLy9jaGFuZ2VkIGJ5IFBhdWwgMTYvNi8yMDA3IHRvIHVzZSBUcmlwbGUgREVTIGZvciA5KyBieXRlIGtleXNcbiAgICAgIC8vc3RvcmVzIHRoZSByZXR1cm4ga2V5c1xuICAgICAgdmFyIGtleXMgPSBuZXcgVWludDMyQXJyYXkoMzIgKiBpdGVyYXRpb25zKTtcbiAgICAgIC8vbm93IGRlZmluZSB0aGUgbGVmdCBzaGlmdHMgd2hpY2ggbmVlZCB0byBiZSBkb25lXG4gICAgICB2YXIgc2hpZnRzID0gWyAwLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwIF07XG4gICAgICAvL290aGVyIHZhcmlhYmxlc1xuICAgICAgdmFyIGxlZnR0ZW1wLCByaWdodHRlbXAsIG09MCwgbj0wLCB0ZW1wO1xuXG4gICAgICBmb3IgKHZhciBqPTA7IGo8aXRlcmF0aW9uczsgaisrKVxuICAgICAgeyAvL2VpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuICAgICAgICBsZWZ0ID0gIChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG4gICAgICAgIHJpZ2h0ID0gKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcblxuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDIpIF4gcmlnaHQpICYgMHgzMzMzMzMzMzsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAyKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgICAvL3RoZSByaWdodCBzaWRlIG5lZWRzIHRvIGJlIHNoaWZ0ZWQgYW5kIHRvIGdldCB0aGUgbGFzdCBmb3VyIGJpdHMgb2YgdGhlIGxlZnQgc2lkZVxuICAgICAgICB0ZW1wID0gKGxlZnQgPDwgOCkgfCAoKHJpZ2h0ID4+PiAyMCkgJiAweDAwMDAwMGYwKTtcbiAgICAgICAgLy9sZWZ0IG5lZWRzIHRvIGJlIHB1dCB1cHNpZGUgZG93blxuICAgICAgICBsZWZ0ID0gKHJpZ2h0IDw8IDI0KSB8ICgocmlnaHQgPDwgOCkgJiAweGZmMDAwMCkgfCAoKHJpZ2h0ID4+PiA4KSAmIDB4ZmYwMCkgfCAoKHJpZ2h0ID4+PiAyNCkgJiAweGYwKTtcbiAgICAgICAgcmlnaHQgPSB0ZW1wO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlc2Ugc2hpZnRzIG9uIHRoZSBsZWZ0IGFuZCByaWdodCBrZXlzXG4gICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHNoaWZ0cy5sZW5ndGg7IGkrKylcbiAgICAgICAge1xuICAgICAgICAgIC8vc2hpZnQgdGhlIGtleXMgZWl0aGVyIG9uZSBvciB0d28gYml0cyB0byB0aGUgbGVmdFxuICAgICAgICAgIGlmIChzaGlmdHNbaV0pXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDIpIHwgKGxlZnQgPj4+IDI2KTsgcmlnaHQgPSAocmlnaHQgPDwgMikgfCAocmlnaHQgPj4+IDI2KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZWxzZVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAyNyk7IHJpZ2h0ID0gKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAyNyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGxlZnQgJj0gLTB4ZjsgcmlnaHQgJj0gLTB4ZjtcblxuICAgICAgICAgIC8vbm93IGFwcGx5IFBDLTIsIGluIHN1Y2ggYSB3YXkgdGhhdCBFIGlzIGVhc2llciB3aGVuIGVuY3J5cHRpbmcgb3IgZGVjcnlwdGluZ1xuICAgICAgICAgIC8vdGhpcyBjb252ZXJzaW9uIHdpbGwgbG9vayBsaWtlIFBDLTIgZXhjZXB0IG9ubHkgdGhlIGxhc3QgNiBiaXRzIG9mIGVhY2ggYnl0ZSBhcmUgdXNlZFxuICAgICAgICAgIC8vcmF0aGVyIHRoYW4gNDggY29uc2VjdXRpdmUgYml0cyBhbmQgdGhlIG9yZGVyIG9mIGxpbmVzIHdpbGwgYmUgYWNjb3JkaW5nIHRvXG4gICAgICAgICAgLy9ob3cgdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9ucyB3aWxsIGJlIGFwcGxpZWQ6IFMyLCBTNCwgUzYsIFM4LCBTMSwgUzMsIFM1LCBTN1xuICAgICAgICAgIGxlZnR0ZW1wID0gQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzMFtsZWZ0ID4+PiAyOF0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMyWyhsZWZ0ID4+PiAyMCkgJiAweGZdIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzM1sobGVmdCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzNFsobGVmdCA+Pj4gMTIpICYgMHhmXSB8IENyeXB0by5kZXNQQy5wYzJieXRlczVbKGxlZnQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzNlsobGVmdCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHJpZ2h0dGVtcCA9IENyeXB0by5kZXNQQy5wYzJieXRlczdbcmlnaHQgPj4+IDI4XSB8IENyeXB0by5kZXNQQy5wYzJieXRlczhbKHJpZ2h0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1BDLnBjMmJ5dGVzOVsocmlnaHQgPj4+IDIwKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMVsocmlnaHQgPj4+IDEyKSAmIDB4Zl0gfCBDcnlwdG8uZGVzUEMucGMyYnl0ZXMxMlsocmlnaHQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNQQy5wYzJieXRlczEzWyhyaWdodCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjtcbiAgICAgICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICAgICAgfVxuICAgICAgfSAvL2ZvciBlYWNoIGl0ZXJhdGlvbnNcblxuICAgICAgcmV0dXJuIGtleXM7XG4gICAgfSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG4gICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICBpZiAoIENyeXB0by5kZXNTUCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIENyeXB0by5kZXNTUCA9IHtcbiAgICAgICAgc3BmdW5jdGlvbjE6IG5ldyBVaW50MzJBcnJheSggWzB4MTAxMDQwMCwwLDB4MTAwMDAsMHgxMDEwNDA0LDB4MTAxMDAwNCwweDEwNDA0LDB4NCwweDEwMDAwLDB4NDAwLDB4MTAxMDQwMCwweDEwMTA0MDQsMHg0MDAsMHgxMDAwNDA0LDB4MTAxMDAwNCwweDEwMDAwMDAsMHg0LDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMHgxMDQwMCwweDEwNDAwLDB4MTAxMDAwMCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDQsMHgxMDAwMDA0LDB4MTAwMDAwNCwweDEwMDA0LDAsMHg0MDQsMHgxMDQwNCwweDEwMDAwMDAsMHgxMDAwMCwweDEwMTA0MDQsMHg0LDB4MTAxMDAwMCwweDEwMTA0MDAsMHgxMDAwMDAwLDB4MTAwMDAwMCwweDQwMCwweDEwMTAwMDQsMHgxMDAwMCwweDEwNDAwLDB4MTAwMDAwNCwweDQwMCwweDQsMHgxMDAwNDA0LDB4MTA0MDQsMHgxMDEwNDA0LDB4MTAwMDQsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDAwMDQsMHg0MDQsMHgxMDQwNCwweDEwMTA0MDAsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwwLDB4MTAwMDQsMHgxMDQwMCwwLDB4MTAxMDAwNF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjI6IG5ldyBVaW50MzJBcnJheSggWy0weDdmZWY3ZmUwLC0weDdmZmY4MDAwLDB4ODAwMCwweDEwODAyMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLC0weDdmZWY3ZmUwLC0weDdmZWY4MDAwLC0weDgwMDAwMDAwLC0weDdmZmY4MDAwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsMHgxMDgwMDAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsMCwtMHg4MDAwMDAwMCwweDgwMDAsMHgxMDgwMjAsLTB4N2ZmMDAwMDAsMHgxMDAwMjAsLTB4N2ZmZmZmZTAsMCwweDEwODAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsLTB4N2ZmMDAwMDAsMHg4MDIwLDAsMHgxMDgwMjAsLTB4N2ZlZmZmZTAsMHgxMDAwMDAsLTB4N2ZmZjdmZTAsLTB4N2ZmMDAwMDAsLTB4N2ZlZjgwMDAsMHg4MDAwLC0weDdmZjAwMDAwLC0weDdmZmY4MDAwLDB4MjAsLTB4N2ZlZjdmZTAsMHgxMDgwMjAsMHgyMCwweDgwMDAsLTB4ODAwMDAwMDAsMHg4MDIwLC0weDdmZWY4MDAwLDB4MTAwMDAwLC0weDdmZmZmZmUwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLDB4MTAwMDIwLDB4MTA4MDAwLDAsLTB4N2ZmZjgwMDAsMHg4MDIwLC0weDgwMDAwMDAwLC0weDdmZWZmZmUwLC0weDdmZWY3ZmUwLDB4MTA4MDAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uMzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDgsMHg4MDIwMjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwMCwwLDB4MjAyMDgsMHg4MDAwMjAwLDB4MjAwMDgsMHg4MDAwMDA4LDB4ODAwMDAwOCwweDIwMDAwLDB4ODAyMDIwOCwweDIwMDA4LDB4ODAyMDAwMCwweDIwOCwweDgwMDAwMDAsMHg4LDB4ODAyMDIwMCwweDIwMCwweDIwMjAwLDB4ODAyMDAwMCwweDgwMjAwMDgsMHgyMDIwOCwweDgwMDAyMDgsMHgyMDIwMCwweDIwMDAwLDB4ODAwMDIwOCwweDgsMHg4MDIwMjA4LDB4MjAwLDB4ODAwMDAwMCwweDgwMjAyMDAsMHg4MDAwMDAwLDB4MjAwMDgsMHgyMDgsMHgyMDAwMCwweDgwMjAyMDAsMHg4MDAwMjAwLDAsMHgyMDAsMHgyMDAwOCwweDgwMjAyMDgsMHg4MDAwMjAwLDB4ODAwMDAwOCwweDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDgsMHgyMDAwMCwweDgwMDAwMDAsMHg4MDIwMjA4LDB4OCwweDIwMjA4LDB4MjAyMDAsMHg4MDAwMDA4LDB4ODAyMDAwMCwweDgwMDAyMDgsMHgyMDgsMHg4MDIwMDAwLDB4MjAyMDgsMHg4LDB4ODAyMDAwOCwweDIwMjAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNDogbmV3IFVpbnQzMkFycmF5KCBbMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgwLDB4ODAwMDgxLDB4ODAwMDAxLDB4MjAwMSwwLDB4ODAyMDAwLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwweDgwMDA4MCwweDgwMDAwMSwweDEsMHgyMDAwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAxLDB4MjA4MCwweDgwMDA4MSwweDEsMHgyMDgwLDB4ODAwMDgwLDB4MjAwMCwweDgwMjA4MCwweDgwMjA4MSwweDgxLDB4ODAwMDgwLDB4ODAwMDAxLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwwLDB4ODAyMDAwLDB4MjA4MCwweDgwMDA4MCwweDgwMDA4MSwweDEsMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgxLDB4ODEsMHgxLDB4MjAwMCwweDgwMDAwMSwweDIwMDEsMHg4MDIwODAsMHg4MDAwODEsMHgyMDAxLDB4MjA4MCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMCwweDgwMjA4MF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjU6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwLDB4MjA4MDEwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDgwMDAwLDB4MTAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDAwODAxMDAsMHg4MDAwMCwweDIwMDAxMDAsMHg0MDA4MDEwMCwweDQyMDAwMTAwLDB4NDIwODAwMDAsMHg4MDEwMCwweDQwMDAwMDAwLDB4MjAwMDAwMCwweDQwMDgwMDAwLDB4NDAwODAwMDAsMCwweDQwMDAwMTAwLDB4NDIwODAxMDAsMHg0MjA4MDEwMCwweDIwMDAxMDAsMHg0MjA4MDAwMCwweDQwMDAwMTAwLDAsMHg0MjAwMDAwMCwweDIwODAxMDAsMHgyMDAwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDgwMDAwLDB4NDIwMDAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg0MDA4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDAwMCwweDQyMDgwMDAwLDB4MjA4MDEwMCwweDQwMDgwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQyMDgwMDAwLDB4NDIwODAxMDAsMHg4MDEwMCwweDQyMDAwMDAwLDB4NDIwODAxMDAsMHgyMDgwMDAwLDAsMHg0MDA4MDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAxMDAsMHg4MDAwMCwwLDB4NDAwODAwMDAsMHgyMDgwMTAwLDB4NDAwMDAxMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb242OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMDEwLDB4MjA0MDAwMDAsMHg0MDAwLDB4MjA0MDQwMTAsMHgyMDQwMDAwMCwweDEwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDQwNDAxMCwweDQwMDAwMCwweDIwMDAwMDEwLDB4NDAwMDEwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMCwweDQwMDAxMCwweDIwMDA0MDEwLDB4NDAwMCwweDQwNDAwMCwweDIwMDA0MDEwLDB4MTAsMHgyMDQwMDAxMCwweDIwNDAwMDEwLDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwweDQwMTAsMHg0MDQwMDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4MjAwMDQwMDAsMHgxMCwweDIwNDAwMDEwLDB4NDA0MDAwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4MjA0MDQwMTAsMHg0MDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDIwNDA0MDAwLDAsMHgyMDQwMDAxMCwweDEwLDB4NDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4NDAwMCwweDQwMDAxMCwweDIwMDA0MDEwLDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4NDAwMDEwLDB4MjAwMDQwMTBdICksXG4gICAgICAgIHNwZnVuY3Rpb243OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMCwweDQyMDAwMDIsMHg0MDAwODAyLDAsMHg4MDAsMHg0MDAwODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDQyMDA4MDIsMHgyMDAwMDAsMCwweDQwMDAwMDIsMHgyLDB4NDAwMDAwMCwweDQyMDAwMDIsMHg4MDIsMHg0MDAwODAwLDB4MjAwODAyLDB4MjAwMDAyLDB4NDAwMDgwMCwweDQwMDAwMDIsMHg0MjAwMDAwLDB4NDIwMDgwMCwweDIwMDAwMiwweDQyMDAwMDAsMHg4MDAsMHg4MDIsMHg0MjAwODAyLDB4MjAwODAwLDB4MiwweDQwMDAwMDAsMHgyMDA4MDAsMHg0MDAwMDAwLDB4MjAwODAwLDB4MjAwMDAwLDB4NDAwMDgwMiwweDQwMDA4MDIsMHg0MjAwMDAyLDB4NDIwMDAwMiwweDIsMHgyMDAwMDIsMHg0MDAwMDAwLDB4NDAwMDgwMCwweDIwMDAwMCwweDQyMDA4MDAsMHg4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4ODAyLDB4NDAwMDAwMiwweDQyMDA4MDIsMHg0MjAwMDAwLDB4MjAwODAwLDAsMHgyLDB4NDIwMDgwMiwwLDB4MjAwODAyLDB4NDIwMDAwMCwweDgwMCwweDQwMDAwMDIsMHg0MDAwODAwLDB4ODAwLDB4MjAwMDAyXSApLFxuICAgICAgICBzcGZ1bmN0aW9uODogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAwMTA0MCwweDEwMDAsMHg0MDAwMCwweDEwMDQxMDQwLDB4MTAwMDAwMDAsMHgxMDAwMTA0MCwweDQwLDB4MTAwMDAwMDAsMHg0MDA0MCwweDEwMDQwMDAwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDEwMDQxMDAwLDB4NDEwNDAsMHgxMDAwLDB4NDAsMHgxMDA0MDAwMCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHgxMDQwLDB4NDEwMDAsMHg0MDA0MCwweDEwMDQwMDQwLDB4MTAwNDEwMDAsMHgxMDQwLDAsMCwweDEwMDQwMDQwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDQxMDQwLDB4NDAwMDAsMHg0MTA0MCwweDQwMDAwLDB4MTAwNDEwMDAsMHgxMDAwLDB4NDAsMHgxMDA0MDA0MCwweDEwMDAsMHg0MTA0MCwweDEwMDAxMDAwLDB4NDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwNDAwNDAsMHgxMDAwMDAwMCwweDQwMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDAwNDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwMDEwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDQxMDAwLDB4MTA0MCwweDEwNDAsMHg0MDA0MCwweDEwMDAwMDAwLDB4MTAwNDEwMDBdICksXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vY3JlYXRlIHRoZSAxNiBvciA0OCBzdWJrZXlzIHdlIHdpbGwgbmVlZFxuICAgIHZhciBrZXlzID0gZGVzX2NyZWF0ZUtleXMoIGtleSApO1xuXG4gICAgdmFyIG09MCwgaSwgaiwgdGVtcCwgbGVmdCwgcmlnaHQsIGxvb3Bpbmc7XG4gICAgdmFyIGNiY2xlZnQsIGNiY2xlZnQyLCBjYmNyaWdodCwgY2JjcmlnaHQyXG4gICAgdmFyIGxlbiA9IG1lc3NhZ2UubGVuZ3RoO1xuXG4gICAgLy9zZXQgdXAgdGhlIGxvb3BzIGZvciBzaW5nbGUgYW5kIHRyaXBsZSBkZXNcbiAgICB2YXIgaXRlcmF0aW9ucyA9IGtleXMubGVuZ3RoID09IDMyID8gMyA6IDk7IC8vc2luZ2xlIG9yIHRyaXBsZSBkZXNcblxuICAgIGlmIChpdGVyYXRpb25zID09IDMpXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyIF0gOiBbIDMwLCAtMiwgLTIgXTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiwgNjIsIDMwLCAtMiwgNjQsIDk2LCAyIF0gOiBbIDk0LCA2MiwgLTIsIDMyLCA2NCwgMiwgMzAsIC0yLCAtMiBdO1xuICAgIH1cblxuICAgIC8vIHBhZCB0aGUgbWVzc2FnZSBkZXBlbmRpbmcgb24gdGhlIHBhZGRpbmcgcGFyYW1ldGVyXG4gICAgaWYgKCAoIHBhZGRpbmcgIT0gdW5kZWZpbmVkICkgJiYgKCBwYWRkaW5nICE9IDQgKSApXG4gICAge1xuICAgICAgdmFyIHVucGFkZGVkTWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICB2YXIgcGFkID0gOC0obGVuJTgpO1xuXG4gICAgICBtZXNzYWdlID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiArIDggKTtcbiAgICAgIG1lc3NhZ2Uuc2V0KCB1bnBhZGRlZE1lc3NhZ2UsIDAgKTtcblxuICAgICAgc3dpdGNoKCBwYWRkaW5nIClcbiAgICAgIHtcbiAgICAgICAgY2FzZSAwOiAvLyB6ZXJvLXBhZFxuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwIF0gKSwgbGVuICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgY2FzZSAxOiAvLyBQS0NTNyBwYWRkaW5nXG4gICAgICAgIHtcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWRdICksIDggKTtcblxuICAgICAgICAgIGlmICggcGFkPT04IClcbiAgICAgICAgICAgIGxlbis9ODtcblxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG5cbiAgICAgICAgY2FzZSAyOiAgLy8gcGFkIHRoZSBtZXNzYWdlIHdpdGggc3BhY2VzXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAgXSApLCA4ICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgIH1cblxuICAgICAgbGVuICs9IDgtKGxlbiU4KVxuICAgIH1cblxuICAgIC8vIHN0b3JlIHRoZSByZXN1bHQgaGVyZVxuICAgIHZhciByZXN1bHQgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG5cbiAgICBpZiAobW9kZSA9PSAxKVxuICAgIHsgLy9DQkMgbW9kZVxuICAgICAgdmFyIG0gPSAwO1xuXG4gICAgICBjYmNsZWZ0ID0gIChpdlttKytdIDw8IDI0KSB8IChpdlttKytdIDw8IDE2KSB8IChpdlttKytdIDw8IDgpIHwgaXZbbSsrXTtcbiAgICAgIGNiY3JpZ2h0ID0gKGl2W20rK10gPDwgMjQpIHwgKGl2W20rK10gPDwgMTYpIHwgKGl2W20rK10gPDwgOCkgfCBpdlttKytdO1xuICAgIH1cblxuICAgIHZhciBybSA9IDA7XG5cbiAgICAvL2xvb3AgdGhyb3VnaCBlYWNoIDY0IGJpdCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgIHdoaWxlIChtIDwgbGVuKVxuICAgIHtcbiAgICAgIGxlZnQgPSAgKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG4gICAgICByaWdodCA9IChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBsZWZ0IF49IGNiY2xlZnQ7IHJpZ2h0IF49IGNiY3JpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGNiY2xlZnQyID0gY2JjbGVmdDtcbiAgICAgICAgICBjYmNyaWdodDIgPSBjYmNyaWdodDtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vZmlyc3QgZWFjaCA2NCBidXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2UgbXVzdCBiZSBwZXJtdXRlZCBhY2NvcmRpbmcgdG8gSVBcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICBsZWZ0ID0gKChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDMxKSk7XG4gICAgICByaWdodCA9ICgocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDMxKSk7XG5cbiAgICAgIC8vZG8gdGhpcyBlaXRoZXIgMSBvciAzIHRpbWVzIGZvciBlYWNoIGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgICBmb3IgKGo9MDsgajxpdGVyYXRpb25zOyBqKz0zKVxuICAgICAge1xuICAgICAgICB2YXIgZW5kbG9vcCA9IGxvb3BpbmdbaisxXTtcbiAgICAgICAgdmFyIGxvb3BpbmMgPSBsb29waW5nW2orMl07XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uXG4gICAgICAgIGZvciAoaT1sb29waW5nW2pdOyBpIT1lbmRsb29wOyBpKz1sb29waW5jKVxuICAgICAgICB7IC8vZm9yIGVmZmljaWVuY3lcbiAgICAgICAgICB2YXIgcmlnaHQxID0gcmlnaHQgXiBrZXlzW2ldO1xuICAgICAgICAgIHZhciByaWdodDIgPSAoKHJpZ2h0ID4+PiA0KSB8IChyaWdodCA8PCAyOCkpIF4ga2V5c1tpKzFdO1xuXG4gICAgICAgICAgLy90aGUgcmVzdWx0IGlzIGF0dGFpbmVkIGJ5IHBhc3NpbmcgdGhlc2UgYnl0ZXMgdGhyb3VnaCB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zXG4gICAgICAgICAgdGVtcCA9IGxlZnQ7XG4gICAgICAgICAgbGVmdCA9IHJpZ2h0O1xuICAgICAgICAgIHJpZ2h0ID0gdGVtcCBeIChDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjJbKHJpZ2h0MSA+Pj4gMjQpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjRbKHJpZ2h0MSA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb242WyhyaWdodDEgPj4+ICA4KSAmIDB4M2ZdIHwgQ3J5cHRvLmRlc1NQLnNwZnVuY3Rpb244W3JpZ2h0MSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IENyeXB0by5kZXNTUC5zcGZ1bmN0aW9uM1socmlnaHQyID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjVbKHJpZ2h0MiA+Pj4gIDgpICYgMHgzZl0gfCBDcnlwdG8uZGVzU1Auc3BmdW5jdGlvbjdbcmlnaHQyICYgMHgzZl0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdGVtcCA9IGxlZnQ7IGxlZnQgPSByaWdodDsgcmlnaHQgPSB0ZW1wOyAvL3VucmV2ZXJzZSBsZWZ0IGFuZCByaWdodFxuICAgICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgICAgbGVmdCA9ICgobGVmdCA+Pj4gMSkgfCAobGVmdCA8PCAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpO1xuXG4gICAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDI7XG4gICAgICAgICAgcmlnaHQgXj0gY2JjcmlnaHQyO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc3VsdC5zZXQoIG5ldyBVaW50OEFycmF5ICggWyAobGVmdD4+PjI0KSAmIDB4ZmYsIChsZWZ0Pj4+MTYpICYgMHhmZiwgKGxlZnQ+Pj44KSAmIDB4ZmYsIChsZWZ0KSAmIDB4ZmYsIChyaWdodD4+PjI0KSAmIDB4ZmYsIChyaWdodD4+PjE2KSAmIDB4ZmYsIChyaWdodD4+PjgpICYgMHhmZiwgKHJpZ2h0KSAmIDB4ZmYgXSApLCBybSApO1xuXG4gICAgICBybSArPSA4O1xuICAgIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9IC8vZW5kIG9mIGRlc1xuXG4gIHZlcmlmeSgga2V5LCBtZWNoLCBkYXRhLCBzaWduYXR1cmUsIGl2IClcbiAge1xuICAgIHJldHVybiBkYXRhO1xuICB9XG5cbiAgZGlnZXN0KCBtZWNoLCBkYXRhIClcbiAge1xuICAgIHJldHVybiBkYXRhO1xuICB9XG5cbiAgc3RhdGljIERFU19DQkM6IE51bWJlciA9IDI7XG4gIHN0YXRpYyBERVNfRUNCID0gNTtcbiAgc3RhdGljIERFU19NQUMgPSA4O1xuICBzdGF0aWMgREVTX01BQ19FTVYgPSA5O1xuICBzdGF0aWMgSVNPOTc5N19NRVRIT0RfMSA9IDExO1xuICBzdGF0aWMgSVNPOTc5N19NRVRIT0RfMiA9IDEyO1xuXG4gIHN0YXRpYyBNRDUgPSAxMztcbiAgc3RhdGljIFJTQSA9IDE0O1xuICBzdGF0aWMgU0hBXzEgPSAxNTtcbiAgc3RhdGljIFNIQV81MTIgPSAyNTtcbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSwgQnl0ZUVuY29kaW5nIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcblxyXG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XHJcbmltcG9ydCB7IENyeXB0byB9IGZyb20gJy4vY3J5cHRvJztcclxuXHJcbmV4cG9ydCBjbGFzcyBCeXRlU3RyaW5nXHJcbntcclxuICBwdWJsaWMgYnl0ZUFycmF5OiBCeXRlQXJyYXk7XHJcblxyXG4gIHB1YmxpYyBzdGF0aWMgSEVYID0gQnl0ZUVuY29kaW5nLkhFWDtcclxuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCB2YWx1ZTogc3RyaW5nIHwgQnl0ZVN0cmluZyB8IEJ5dGVBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIgKVxyXG4gIHtcclxuICAgIGlmICggIWVuY29kaW5nIClcclxuICAgIHtcclxuICAgICAgaWYgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVTdHJpbmcgKVxyXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICAgIGVsc2UgaWYgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVBcnJheSApXHJcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5jbG9uZSgpO1xyXG4vLyAgICAgIGVsc2VcclxuLy8gICAgICAgIHN1cGVyKCBVaW50OEFycmF5KCB2YWx1ZSApICk7XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICB7XHJcbiAgICAgIHN3aXRjaCggZW5jb2RpbmcgKVxyXG4gICAgICB7XHJcbiAgICAgICAgY2FzZSBCeXRlU3RyaW5nLkhFWDpcclxuICAgICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggPHN0cmluZz52YWx1ZSwgQnl0ZUFycmF5LkhFWCApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICB0aHJvdyBcIkJ5dGVTdHJpbmcgdW5zdXBwb3J0ZWQgZW5jb2RpbmdcIjtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xyXG4gIH1cclxuXHJcbiAgYnl0ZXMoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS52aWV3QXQoIG9mZnNldCwgY291bnQgKSApO1xyXG4gIH1cclxuXHJcbiAgYnl0ZUF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkuYnl0ZUF0KCBvZmZzZXQgKTtcclxuICB9XHJcblxyXG4gIGVxdWFscyggb3RoZXJCeXRlU3RyaW5nOiBCeXRlU3RyaW5nIClcclxuICB7XHJcbi8vICAgIHJldHVybiAhKCB0aGlzLl9ieXRlcyA8IG90aGVyQnl0ZVN0cmluZy5fYnl0ZXMgKSAmJiAhKCB0aGlzLl9ieXRlcyA+IG90aGVyQnl0ZVN0cmluZy5fYnl0ZXMgKTtcclxuICB9XHJcblxyXG4gIGNvbmNhdCggdmFsdWU6IEJ5dGVTdHJpbmcgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHRoaXMuYnl0ZUFycmF5LmNvbmNhdCggdmFsdWUuYnl0ZUFycmF5ICk7XHJcblxyXG4gICAgcmV0dXJuIHRoaXM7XHJcbiAgfVxyXG5cclxuICBsZWZ0KCBjb3VudDogbnVtYmVyIClcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LnZpZXdBdCggMCApICk7XHJcbiAgfVxyXG5cclxuICByaWdodCggY291bnQ6IG51bWJlciApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS52aWV3QXQoIC1jb3VudCApICk7XHJcbiAgfVxyXG5cclxuICBub3QoICk6IEJ5dGVTdHJpbmdcclxuICB7XHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMuYnl0ZUFycmF5LmNsb25lKCkubm90KCkgKTtcclxuICB9XHJcblxyXG4gIGFuZCggdmFsdWU6IEJ5dGVTdHJpbmcgKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkuY2xvbmUoKS5hbmQoIHZhbHVlLmJ5dGVBcnJheSkgKTtcclxuICB9XHJcblxyXG4gIG9yKCB2YWx1ZTogQnl0ZVN0cmluZyApOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLmJ5dGVBcnJheS5jbG9uZSgpLm9yKCB2YWx1ZS5ieXRlQXJyYXkpICk7XHJcbiAgfVxyXG5cclxuICBwYWQoIG1ldGhvZDogbnVtYmVyLCBvcHRpb25hbD86IGJvb2xlYW4gKVxyXG4gIHtcclxuICAgIHZhciBicyA9IG5ldyBCeXRlQnVmZmVyKCB0aGlzLmJ5dGVBcnJheSApO1xyXG5cclxuICAgIGlmICggb3B0aW9uYWwgPT0gdW5kZWZpbmVkIClcclxuICAgICAgb3B0aW9uYWwgPSBmYWxzZTtcclxuXHJcbiAgICBpZiAoICggKCBicy5sZW5ndGggJiA3ICkgIT0gMCApIHx8ICggIW9wdGlvbmFsICkgKVxyXG4gICAge1xyXG4gICAgICB2YXIgbmV3bGVuID0gKCAoIGJzLmxlbmd0aCArIDggKSAmIH43ICk7XHJcbiAgICAgIGlmICggbWV0aG9kID09IENyeXB0by5JU085Nzk3X01FVEhPRF8xIClcclxuICAgICAgICBicy5hcHBlbmQoIDB4ODAgKTtcclxuXHJcbiAgICAgIHdoaWxlKCBicy5sZW5ndGggPCBuZXdsZW4gKVxyXG4gICAgICAgIGJzLmFwcGVuZCggMHgwMCApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBicy50b0J5dGVTdHJpbmcoKTtcclxuICB9XHJcblxyXG4gIHRvU3RyaW5nKCBlbmNvZGluZz86IG51bWJlciApOiBzdHJpbmdcclxuICB7XHJcbiAgICAvL1RPRE86IGVuY29kaW5nIC4uLlxyXG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5LnRvU3RyaW5nKCBCeXRlQXJyYXkuSEVYICk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY29uc3QgSEVYID0gQnl0ZVN0cmluZy5IRVg7XHJcbi8vZXhwb3J0IGNvbnN0IEFTQ0lJID0gQnl0ZVN0cmluZy5BU0NJSTtcclxuZXhwb3J0IGNvbnN0IEJBU0U2NCA9IEJ5dGVTdHJpbmcuQkFTRTY0O1xyXG4vL2V4cG9ydCBjb25zdCBVVEY4ID0gQnl0ZVN0cmluZy5VVEY4O1xyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5cclxuZXhwb3J0IGNsYXNzIEJ5dGVCdWZmZXJcclxue1xyXG4gIGJ5dGVBcnJheTogQnl0ZUFycmF5O1xyXG5cclxuICBjb25zdHJ1Y3RvciAoIHZhbHVlPzogQnl0ZUFycmF5IHwgQnl0ZVN0cmluZyB8IHN0cmluZywgZW5jb2Rpbmc/IClcclxuICB7XHJcbiAgICBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSB2YWx1ZS5jbG9uZSgpO1xyXG4gICAgfVxyXG4gICAgZWxzZSBpZiAoIHZhbHVlIGluc3RhbmNlb2YgQnl0ZVN0cmluZyApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdmFsdWUuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggZW5jb2RpbmcgIT0gdW5kZWZpbmVkIClcclxuICAgIHtcclxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgQnl0ZVN0cmluZyggdmFsdWUsIGVuY29kaW5nICkuYnl0ZUFycmF5LmNsb25lKCk7XHJcbiAgICB9XHJcbiAgICBlbHNlXHJcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggW10gKTtcclxuICB9XHJcblxyXG4gIGdldCBsZW5ndGgoKVxyXG4gIHtcclxuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XHJcbiAgfVxyXG5cclxuICB0b0J5dGVTdHJpbmcoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy5ieXRlQXJyYXkgKTtcclxuICB9XHJcblxyXG4gIGNsZWFyKClcclxuICB7XHJcbiAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XHJcbiAgfVxyXG5cclxuICBhcHBlbmQoIHZhbHVlOiBCeXRlU3RyaW5nIHwgQnl0ZUJ1ZmZlciB8IG51bWJlciApOiBCeXRlQnVmZmVyXHJcbiAge1xyXG4gICAgbGV0IHZhbHVlQXJyYXk6IEJ5dGVBcnJheTtcclxuXHJcbiAgICBpZiAoICggdmFsdWUgaW5zdGFuY2VvZiBCeXRlU3RyaW5nICkgfHwgKCB2YWx1ZSBpbnN0YW5jZW9mIEJ5dGVCdWZmZXIgKSApXHJcbiAgICB7XHJcbiAgICAgIHZhbHVlQXJyYXkgPSB2YWx1ZS5ieXRlQXJyYXk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggdHlwZW9mIHZhbHVlID09IFwibnVtYmVyXCIgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSggWyAoIDxudW1iZXI+dmFsdWUgJiAweGZmICkgXSApO1xyXG4gICAgfVxyXG4vKiAgICBlbHNlIGlmICggdHlwZW9mIHZhbHVlID09IFwic3RyaW5nXCIgKVxyXG4gICAge1xyXG4gICAgICB2YWx1ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIHZhbHVlLmxlbmd0aCApO1xyXG4gICAgICBmb3IoIHZhciBpID0gMDsgaSA8IHZhbHVlLmxlbmd0aDsgKytpIClcclxuICAgICAgICB2YWx1ZUFycmF5W2ldID0gdmFsdWUuY2hhckF0KCBpICk7XHJcbiAgICB9Ki9cclxuLy8gICAgZWxzZVxyXG4vLyAgICAgIHZhbHVlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCB2YWx1ZSApO1xyXG5cclxuICAgIHRoaXMuYnl0ZUFycmF5LmNvbmNhdCggdmFsdWVBcnJheSApO1xyXG5cclxuICAgIHJldHVybiB0aGlzO1xyXG4gIH1cclxufVxyXG4iLCJpbXBvcnQgeyBCYXNlVExWIGFzIEJhc2VUTFYgfSBmcm9tICcuLi9iYXNlL2Jhc2UtdGx2JztcclxuaW1wb3J0IHsgQnl0ZVN0cmluZyB9IGZyb20gJy4vYnl0ZS1zdHJpbmcnO1xyXG5pbXBvcnQgeyBCeXRlQnVmZmVyIH0gZnJvbSAnLi9ieXRlLWJ1ZmZlcic7XHJcblxyXG5leHBvcnQgY2xhc3MgVExWXHJcbntcclxuICB0bHY6IEJhc2VUTFY7XHJcbiAgZW5jb2Rpbmc6IG51bWJlcjtcclxuXHJcbiAgY29uc3RydWN0b3IgKCB0YWc6IG51bWJlciwgdmFsdWU6IEJ5dGVTdHJpbmcsIGVuY29kaW5nOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIHRoaXMudGx2ID0gbmV3IEJhc2VUTFYoIHRhZywgdmFsdWUuYnl0ZUFycmF5LCBlbmNvZGluZyApO1xyXG5cclxuICAgIHRoaXMuZW5jb2RpbmcgPSBlbmNvZGluZztcclxuICB9XHJcblxyXG4gIGdldFRMVigpOiBCeXRlU3RyaW5nXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkgKTtcclxuICB9XHJcblxyXG4gIGdldFRhZygpOiBudW1iZXJcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy50bHYudGFnO1xyXG4gIH1cclxuXHJcbiAgZ2V0VmFsdWUoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHJldHVybiBuZXcgQnl0ZVN0cmluZyggdGhpcy50bHYudmFsdWUgKTtcclxuICB9XHJcblxyXG4gIGdldEwoKTogQnl0ZVN0cmluZ1xyXG4gIHtcclxuICAgIHZhciBpbmZvID0gQmFzZVRMVi5wYXJzZVRMViggdGhpcy50bHYuYnl0ZUFycmF5LCB0aGlzLmVuY29kaW5nICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBCeXRlU3RyaW5nKCB0aGlzLnRsdi5ieXRlQXJyYXkudmlld0F0KCBpbmZvLmxlbk9mZnNldCwgaW5mby52YWx1ZU9mZnNldCApICk7XHJcbiAgfVxyXG5cclxuICBnZXRMVigpXHJcbiAge1xyXG4gICAgdmFyIGluZm8gPSBCYXNlVExWLnBhcnNlVExWKCB0aGlzLnRsdi5ieXRlQXJyYXksIHRoaXMuZW5jb2RpbmcgKTtcclxuXHJcbiAgICByZXR1cm4gbmV3IEJ5dGVTdHJpbmcoIHRoaXMudGx2LmJ5dGVBcnJheS52aWV3QXQoIGluZm8ubGVuT2Zmc2V0LCBpbmZvLnZhbHVlT2Zmc2V0ICsgaW5mby5sZW4gKSApO1xyXG4gIH1cclxuXHJcbiAgc3RhdGljIHBhcnNlVExWKCBidWZmZXI6IEJ5dGVTdHJpbmcsIGVuY29kaW5nOiBudW1iZXIgKTogeyB0YWc6IG51bWJlciwgbGVuOiBudW1iZXIsIHZhbHVlOiBCeXRlU3RyaW5nLCBsZW5PZmZzZXQ6IG51bWJlciwgdmFsdWVPZmZzZXQ6IG51bWJlciB9XHJcbiAge1xyXG4gICAgbGV0IGluZm8gPSBCYXNlVExWLnBhcnNlVExWKCBidWZmZXIuYnl0ZUFycmF5LCBlbmNvZGluZyApO1xyXG5cclxuICAgIHJldHVybiB7XHJcbiAgICAgIHRhZzogaW5mby50YWcsXHJcbiAgICAgIGxlbjogaW5mby5sZW4sXHJcbiAgICAgIHZhbHVlOiBuZXcgQnl0ZVN0cmluZyggaW5mby52YWx1ZSApLFxyXG4gICAgICBsZW5PZmZzZXQ6IGluZm8ubGVuT2Zmc2V0LFxyXG4gICAgICB2YWx1ZU9mZnNldDogaW5mby52YWx1ZU9mZnNldFxyXG4gICAgfTtcclxuICB9XHJcblxyXG4gIHN0YXRpYyBFTVYgPSBCYXNlVExWLkVuY29kaW5ncy5FTVY7XHJcbiAgc3RhdGljIERHSSA9IEJhc2VUTFYuRW5jb2RpbmdzLkRHSTtcclxuLy8gIHN0YXRpYyBMMTYgPSBCYXNlVExWLkwxNjtcclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlU3RyaW5nIH0gZnJvbSAnLi9ieXRlLXN0cmluZyc7XHJcbmltcG9ydCB7IFRMViB9IGZyb20gJy4vdGx2JztcclxuXHJcbmV4cG9ydCBjbGFzcyBUTFZMaXN0XHJcbntcclxuICBfdGx2czogVExWW107XHJcblxyXG4gIGNvbnN0cnVjdG9yKCB0bHZTdHJlYW06IEJ5dGVTdHJpbmcsIGVuY29kaW5nPzogbnVtYmVyIClcclxuICB7XHJcbiAgICB0aGlzLl90bHZzID0gW107XHJcblxyXG4gICAgdmFyIG9mZiA9IDA7XHJcblxyXG4gICAgd2hpbGUoIG9mZiA8IHRsdlN0cmVhbS5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB2YXIgdGx2SW5mbyA9IFRMVi5wYXJzZVRMViggdGx2U3RyZWFtLmJ5dGVzKCBvZmYgKSwgZW5jb2RpbmcgKVxyXG5cclxuICAgICAgaWYgKCB0bHZJbmZvID09IG51bGwgKVxyXG4gICAgICB7XHJcbiAgICAgICAgLy8gZXJyb3IgLi4uXHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgLy8gbm8gbW9yZSAuLi4gP1xyXG4gICAgICAgIGlmICggdGx2SW5mby52YWx1ZU9mZnNldCA9PSAwIClcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICB0aGlzLl90bHZzLnB1c2goIG5ldyBUTFYoIHRsdkluZm8udGFnLCB0bHZJbmZvLnZhbHVlLCBlbmNvZGluZyApICk7XHJcbiAgICAgICAgb2ZmICs9IHRsdkluZm8udmFsdWVPZmZzZXQgKyB0bHZJbmZvLmxlbjtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgaW5kZXgoIGluZGV4OiBudW1iZXIgKTogVExWXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMuX3RsdnNbIGluZGV4IF07XHJcbiAgfVxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xyXG5cclxuY2xhc3MgSlNTaW11bGF0ZWRTbG90XHJcbntcclxuICBjYXJkV29ya2VyO1xyXG4gIG9uQVBEVVJlc3BvbnNlO1xyXG4gIHN0b3A7XHJcblxyXG4gIE9uTWVzc2FnZShlKVxyXG4gIHtcclxuICAgIGlmICh0aGlzLnN0b3ApIHJldHVybjtcclxuXHJcbiAgICBpZiAoZS5kYXRhLmNvbW1hbmQgPT0gXCJkZWJ1Z1wiKVxyXG4gICAge1xyXG4gICAgICBjb25zb2xlLmxvZyhlLmRhdGEuZGF0YSk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmIChlLmRhdGEuY29tbWFuZCA9PSBcImV4ZWN1dGVBUERVXCIpXHJcbiAgICB7XHJcbiAgICAgIC8vIGNvbnNvbGUubG9nKCBuZXcgQnl0ZVN0cmluZyggZS5kYXRhLmRhdGEgKS50b1N0cmluZygpICk7XHJcblxyXG4gICAgICBpZiAoIHRoaXMub25BUERVUmVzcG9uc2UgKVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIGJzID0gPFVpbnQ4QXJyYXk+ZS5kYXRhLmRhdGEsIGxlbiA9IGJzLmxlbmd0aDtcclxuXHJcbiAgICAgICAgdGhpcy5vbkFQRFVSZXNwb25zZSggKCBic1sgbGVuIC0gMiBdIDw8IDggKSB8IGJzWyBsZW4gLSAxIF0sICggbGVuID4gMiApID8gbmV3IEJ5dGVBcnJheSggYnMuc3ViYXJyYXkoIDAsIGxlbi0yICkgKSA6IG51bGwgKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgZWxzZVxyXG4gICAge1xyXG4gICAgICBjb25zb2xlLmxvZyggXCJjbWQ6IFwiICsgZS5kYXRhLmNvbW1hbmQgKyBcIiBkYXRhOiBcIiArIGUuZGF0YS5kYXRhICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBpbml0KClcclxuICB7XHJcbiAgICB0aGlzLmNhcmRXb3JrZXIgPSBuZXcgV29ya2VyKCBcImpzL1NtYXJ0Q2FyZFNsb3RTaW11bGF0b3IvU21hcnRDYXJkU2xvdFdvcmtlci5qc1wiICk7XHJcbiAgICB0aGlzLmNhcmRXb3JrZXIub25tZXNzYWdlID0gdGhpcy5Pbk1lc3NhZ2UuYmluZCggdGhpcyApO1xyXG5cclxuICAgIHRoaXMuY2FyZFdvcmtlci5vbmVycm9yID0gZnVuY3Rpb24oZTogRXZlbnQpXHJcbiAgICB7XHJcbiAgICAgIC8vYWxlcnQoIFwiRXJyb3IgYXQgXCIgKyBlLmZpbGVuYW1lICsgXCI6XCIgKyBlLmxpbmVubyArIFwiOiBcIiArIGUubWVzc2FnZSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgc2VuZFRvV29ya2VyKCBjb21tYW5kLCBkYXRhIClcclxuICB7XHJcbiAgICB0aGlzLmNhcmRXb3JrZXIucG9zdE1lc3NhZ2UoXHJcbiAgICAgIHtcclxuICAgICAgICBcImNvbW1hbmRcIjogY29tbWFuZCxcclxuICAgICAgICBcImRhdGFcIjogZGF0YVxyXG4gICAgICB9XHJcbiAgICApO1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZUFQRFVDb21tYW5kKCBiQ0xBLCBiSU5TLCBiUDEsIGJQMiwgY29tbWFuZERhdGEsIHdMZSwgb25BUERVUmVzcG9uc2UgKVxyXG4gIHtcclxuICAgIHZhciBjbWQgPSBbIGJDTEEsIGJJTlMsIGJQMSwgYlAyIF07XHJcbiAgICB2YXIgbGVuID0gNDtcclxuICAgIHZhciBic0NvbW1hbmREYXRhID0gKCBjb21tYW5kRGF0YSBpbnN0YW5jZW9mIEJ5dGVBcnJheSApID8gY29tbWFuZERhdGEgOiBuZXcgQnl0ZUFycmF5KCBjb21tYW5kRGF0YSwgQnl0ZUFycmF5LkhFWCApO1xyXG4gICAgaWYgKCBic0NvbW1hbmREYXRhLmxlbmd0aCA+IDAgKVxyXG4gICAge1xyXG4gICAgICBjbWRbbGVuKytdID0gYnNDb21tYW5kRGF0YS5sZW5ndGg7XHJcbiAgICAgIGZvciggdmFyIGkgPSAwOyBpIDwgYnNDb21tYW5kRGF0YS5sZW5ndGg7ICsraSApXHJcbiAgICAgICAgY21kW2xlbisrXSA9IGJzQ29tbWFuZERhdGEuYnl0ZUF0KCBpICk7XHJcbiAgICB9XHJcbiAgICBlbHNlIGlmICggd0xlICE9IHVuZGVmaW5lZCApXHJcbiAgICAgICAgY21kW2xlbisrXSA9IHdMZSAmIDB4RkY7XHJcblxyXG4gICAgdGhpcy5zZW5kVG9Xb3JrZXIoIFwiZXhlY3V0ZUFQRFVcIiwgY21kICk7XHJcblxyXG4gICAgdGhpcy5vbkFQRFVSZXNwb25zZSA9IG9uQVBEVVJlc3BvbnNlO1xyXG5cclxuICAgIC8vIG9uIHN1Y2Nlc3MvZmFpbHVyZSwgd2lsbCBjYWxsYmFja1xyXG4gICAgLy8gaWYgKCByZXNwID09IG51bGwgKVxyXG4gICAgcmV0dXJuO1xyXG4gIH1cclxufVxyXG4iLG51bGwsImltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuLi9iYXNlL0lTTzc4MTYnO1xyXG5pbXBvcnQgeyBDb21tYW5kQVBEVSB9IGZyb20gJy4uL2Jhc2UvY29tbWFuZC1hcGR1JztcclxuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vYmFzZS9yZXNwb25zZS1hcGR1JztcclxuXHJcbmV4cG9ydCBjbGFzcyBKU0lNU2NyaXB0QXBwbGV0XHJcbntcclxuICBzZWxlY3RBcHBsaWNhdGlvbiggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVICk6IFByb21pc2U8UmVzcG9uc2VBUERVPlxyXG4gIHtcclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmU8UmVzcG9uc2VBUERVPiggbmV3IFJlc3BvbnNlQVBEVSggeyBzdzogMHg5MDAwIH0gKSApO1xyXG4gIH1cclxuXHJcbiAgZGVzZWxlY3RBcHBsaWNhdGlvbigpXHJcbiAge1xyXG4gIH1cclxuXHJcbiAgZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApOiBQcm9taXNlPFJlc3BvbnNlQVBEVT5cclxuICB7XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4NkQwMCB9ICkgKTtcclxuICB9XHJcbn1cclxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmltcG9ydCB7IElTTzc4MTYgfSBmcm9tICcuLi9iYXNlL0lTTzc4MTYnO1xuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9iYXNlL2NvbW1hbmQtYXBkdSc7XG5pbXBvcnQgeyBSZXNwb25zZUFQRFUgfSBmcm9tICcuLi9iYXNlL3Jlc3BvbnNlLWFwZHUnO1xuXG5pbXBvcnQgeyBKU0lNQ2FyZCB9IGZyb20gJy4vanNpbS1jYXJkJztcbmltcG9ydCB7IEpTSU1TY3JpcHRBcHBsZXQgfSBmcm9tICcuL2pzaW0tc2NyaXB0LWFwcGxldCc7XG5cbmV4cG9ydCBjbGFzcyBKU0lNU2NyaXB0Q2FyZCBpbXBsZW1lbnRzIEpTSU1DYXJkXG57XG4gIHByaXZhdGUgX3Bvd2VySXNPbjogYm9vbGVhbjtcbiAgcHJpdmF0ZSBfYXRyOiBCeXRlQXJyYXk7XG5cbiAgYXBwbGV0czogeyBhaWQ6IEJ5dGVBcnJheSwgYXBwbGV0OiBKU0lNU2NyaXB0QXBwbGV0IH1bXSA9IFtdO1xuXG4gIHNlbGVjdGVkQXBwbGV0OiBKU0lNU2NyaXB0QXBwbGV0O1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMuX2F0ciA9IG5ldyBCeXRlQXJyYXkoIFtdICk7XG4gIH1cblxuICBsb2FkQXBwbGljYXRpb24oIGFpZDogQnl0ZUFycmF5LCBhcHBsZXQ6IEpTSU1TY3JpcHRBcHBsZXQgKVxuICB7XG4gICAgdGhpcy5hcHBsZXRzLnB1c2goIHsgYWlkOiBhaWQsIGFwcGxldDogYXBwbGV0IH0gKTtcbiAgfVxuXG4gIGdldCBpc1Bvd2VyZWQoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Bvd2VySXNPbjtcbiAgfVxuXG4gIHBvd2VyT24oKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICB0aGlzLl9wb3dlcklzT24gPSB0cnVlO1xuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxCeXRlQXJyYXk+KCB0aGlzLl9hdHIgKTtcbiAgfVxuXG4gIHBvd2VyT2ZmKCk6IFByb21pc2U8YW55PlxuICB7XG4gICAgdGhpcy5fcG93ZXJJc09uID0gZmFsc2U7XG5cbiAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICB9XG5cbiAgcmVzZXQoKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICB0aGlzLl9wb3dlcklzT24gPSB0cnVlO1xuXG4gICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHVuZGVmaW5lZDtcblxuICAgIC8vIFRPRE86IFJlc2V0XG5cbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPEJ5dGVBcnJheT4oIHRoaXMuX2F0ciApO1xuICB9XG5cbiAgZXhjaGFuZ2VBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XG4gIHtcbiAgICBpZiAoIGNvbW1hbmRBUERVLklOUyA9PSAweEE0IClcbiAgICB7XG4gICAgICBpZiAoIHRoaXMuc2VsZWN0ZWRBcHBsZXQgKVxuICAgICAge1xuICAgICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0LmRlc2VsZWN0QXBwbGljYXRpb24oKTtcblxuICAgICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xuICAgICAgfVxuXG4gICAgICAvL1RPRE86IExvb2t1cCBBcHBsaWNhdGlvblxuICAgICAgdGhpcy5zZWxlY3RlZEFwcGxldCA9IHRoaXMuYXBwbGV0c1sgMCBdLmFwcGxldDtcblxuICAgICAgcmV0dXJuIHRoaXMuc2VsZWN0ZWRBcHBsZXQuc2VsZWN0QXBwbGljYXRpb24oIGNvbW1hbmRBUERVICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuc2VsZWN0ZWRBcHBsZXQuZXhlY3V0ZUFQRFUoIGNvbW1hbmRBUERVICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJ2NyeXB0b2dyYXBoaXgtc2ltLWNvcmUnO1xuXG5pbXBvcnQgeyBTbG90IH0gZnJvbSAnLi4vYmFzZS9zbG90JztcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vYmFzZS9jb21tYW5kLWFwZHUnO1xuaW1wb3J0IHsgUmVzcG9uc2VBUERVIH0gZnJvbSAnLi4vYmFzZS9yZXNwb25zZS1hcGR1JztcbmltcG9ydCB7IEpTSU1DYXJkIH0gZnJvbSAnLi9qc2ltLWNhcmQnO1xuXG5leHBvcnQgY2xhc3MgSlNJTVNsb3QgaW1wbGVtZW50cyBTbG90XG57XG4gIHB1YmxpYyBjYXJkOiBKU0lNQ2FyZDtcblxuICBjb25zdHJ1Y3RvciggY2FyZD86IEpTSU1DYXJkIClcbiAge1xuICAgIHRoaXMuY2FyZCA9IGNhcmQ7XG4gIH1cblxuICBnZXQgaXNQcmVzZW50KCk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiAhIXRoaXMuY2FyZDtcbiAgfVxuXG4gIGdldCBpc1Bvd2VyZWQoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuaXNQcmVzZW50ICYmIHRoaXMuY2FyZC5pc1Bvd2VyZWQ7XG4gIH1cblxuICBwb3dlck9uKCk6IFByb21pc2U8Qnl0ZUFycmF5PlxuICB7XG4gICAgaWYgKCAhdGhpcy5pc1ByZXNlbnQgKVxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIG5ldyBFcnJvciggXCJKU0lNOiBDYXJkIG5vdCBwcmVzZW50XCIgKSApO1xuXG4gICAgcmV0dXJuIHRoaXMuY2FyZC5wb3dlck9uKCk7XG4gIH1cblxuICBwb3dlck9mZigpOiBQcm9taXNlPGJvb2xlYW4+XG4gIHtcbiAgICBpZiAoICF0aGlzLmlzUHJlc2VudCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8Ym9vbGVhbj4oIG5ldyBFcnJvciggXCJKU0lNOiBDYXJkIG5vdCBwcmVzZW50XCIgKSApO1xuXG4gICAgcmV0dXJuIHRoaXMuY2FyZC5wb3dlck9mZigpO1xuICB9XG5cbiAgcmVzZXQoKTogUHJvbWlzZTxCeXRlQXJyYXk+XG4gIHtcbiAgICBpZiAoICF0aGlzLmlzUHJlc2VudCApXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggbmV3IEVycm9yKCBcIkpTSU06IENhcmQgbm90IHByZXNlbnRcIiApICk7XG5cbiAgICByZXR1cm4gdGhpcy5jYXJkLnJlc2V0KCk7XG4gIH1cblxuICBleGVjdXRlQVBEVSggY29tbWFuZEFQRFU6IENvbW1hbmRBUERVICk6IFByb21pc2U8UmVzcG9uc2VBUERVPlxuICB7XG4gICAgaWYgKCAhdGhpcy5pc1ByZXNlbnQgKVxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0PFJlc3BvbnNlQVBEVT4oIG5ldyBFcnJvciggXCJKU0lNOiBDYXJkIG5vdCBwcmVzZW50XCIgKSApO1xuXG4gICAgaWYgKCAhdGhpcy5pc1Bvd2VyZWQgKVxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0PFJlc3BvbnNlQVBEVT4oIG5ldyBFcnJvciggXCJKU0lNOiBDYXJkIHVucG93ZXJlZFwiICkgKTtcblxuICAgIHJldHVybiB0aGlzLmNhcmQuZXhjaGFuZ2VBUERVKCBjb21tYW5kQVBEVSApO1xuICB9XG5cbiAgaW5zZXJ0Q2FyZCggY2FyZDogSlNJTUNhcmQgKVxuICB7XG4gICAgaWYgKCB0aGlzLmNhcmQgKVxuICAgICAgdGhpcy5lamVjdENhcmQoKTtcblxuICAgIHRoaXMuY2FyZCA9IGNhcmQ7XG4gIH1cblxuICBlamVjdENhcmQoKVxuICB7XG4gICAgaWYgKCB0aGlzLmNhcmQgKVxuICAgIHtcbiAgICAgIGlmICggdGhpcy5jYXJkLmlzUG93ZXJlZCApXG4gICAgICAgIHRoaXMuY2FyZC5wb3dlck9mZigpO1xuXG4gICAgICB0aGlzLmNhcmQgPSB1bmRlZmluZWQ7XG4gICAgfVxuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBoZXgyKCB2YWwgKSB7IHJldHVybiAoIFwiMDBcIiArIHZhbC50b1N0cmluZyggMTYgKS50b1VwcGVyQ2FzZSgpICkuc3Vic3RyKCAtMiApOyB9XHJcbmV4cG9ydCBmdW5jdGlvbiBoZXg0KCB2YWwgKSB7IHJldHVybiAoIFwiMDAwMFwiICsgdmFsLnRvU3RyaW5nKCAxNiApLnRvVXBwZXJDYXNlKCkgKS5zdWJzdHIoIC00ICk7IH1cclxuXHJcbmV4cG9ydCBlbnVtIE1FTUZMQUdTIHtcclxuICBSRUFEX09OTFkgPSAxIDw8IDAsXHJcbiAgVFJBTlNBQ1RJT05BQkxFID0gMSA8PCAxLFxyXG4gIFRSQUNFID0gMSA8PCAyXHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBTZWdtZW50XHJcbntcclxuICBwcml2YXRlIG1lbURhdGE6IEJ5dGVBcnJheTtcclxuICBwcml2YXRlIG1lbVR5cGU7XHJcbiAgcHJpdmF0ZSByZWFkT25seTtcclxuICBwcml2YXRlIGZsYWdzO1xyXG4gIHByaXZhdGUgaW5UcmFuc2FjdGlvbiA9IGZhbHNlO1xyXG4gIHByaXZhdGUgdHJhbnNCbG9ja3MgPSBbXTtcclxuICBtZW1UcmFjZXM7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCBzZWdUeXBlLCBzaXplLCBmbGFncz8sIGJhc2U/OiBCeXRlQXJyYXkgKVxyXG4gIHtcclxuICAgIHRoaXMubWVtVHlwZSA9IHNlZ1R5cGU7XHJcbiAgICB0aGlzLnJlYWRPbmx5ID0gKCBmbGFncyAmIE1FTUZMQUdTLlJFQURfT05MWSApID8gdHJ1ZSA6IGZhbHNlO1xyXG5cclxuICAgIGlmICggYmFzZSApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMubWVtRGF0YSA9IG5ldyBCeXRlQXJyYXkoIGJhc2UgKVxyXG4gICAgfVxyXG4gICAgZWxzZVxyXG4gICAge1xyXG4gICAgICB0aGlzLm1lbURhdGEgPSBuZXcgQnl0ZUFycmF5KCBbXSApLnNldExlbmd0aCggc2l6ZSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0VHlwZSgpIHsgcmV0dXJuIHRoaXMubWVtVHlwZTsgfVxyXG4gIGdldExlbmd0aCgpIHsgcmV0dXJuIHRoaXMubWVtRGF0YS5sZW5ndGg7IH1cclxuICBnZXRGbGFncygpIHsgcmV0dXJuIHRoaXMuZmxhZ3M7IH1cclxuICBnZXREZWJ1ZygpIHsgcmV0dXJuIHsgbWVtRGF0YTogdGhpcy5tZW1EYXRhLCBtZW1UeXBlOiB0aGlzLm1lbVR5cGUsIHJlYWRPbmx5OiB0aGlzLnJlYWRPbmx5LCBpblRyYW5zYWN0aW9uOiB0aGlzLmluVHJhbnNhY3Rpb24sIHRyYW5zQmxvY2tzOiB0aGlzLnRyYW5zQmxvY2tzIH07IH1cclxuXHJcbiAgYmVnaW5UcmFuc2FjdGlvbigpXHJcbiAge1xyXG4gICAgdGhpcy5pblRyYW5zYWN0aW9uID0gdHJ1ZTtcclxuICAgIHRoaXMudHJhbnNCbG9ja3MgPSBbXTtcclxuICB9XHJcblxyXG4gIGVuZFRyYW5zYWN0aW9uKCBjb21taXQgKVxyXG4gIHtcclxuICAgIGlmICggIWNvbW1pdCAmJiB0aGlzLmluVHJhbnNhY3Rpb24gKVxyXG4gICAge1xyXG4gICAgICB0aGlzLmluVHJhbnNhY3Rpb24gPSBmYWxzZTtcclxuXHJcbiAgICAgIC8vIHJvbGxiYWNrIHRyYW5zYWN0aW9uc1xyXG4gICAgICBmb3IoIHZhciBpPTA7IGkgPCB0aGlzLnRyYW5zQmxvY2tzLmxlbmd0aDsgaSsrIClcclxuICAgICAge1xyXG4gICAgICAgIHZhciBibG9jayA9IHRoaXMudHJhbnNCbG9ja3NbIGkgXTtcclxuXHJcbiAgICAgICAgdGhpcy53cml0ZUJ5dGVzKCBibG9jay5hZGRyLCBibG9jay5kYXRhICk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnRyYW5zQmxvY2tzID0gW107XHJcbiAgfVxyXG5cclxuICByZWFkQnl0ZSggYWRkciApXHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMubWVtRGF0YVsgYWRkciBdO1xyXG4gIH1cclxuXHJcbiAgemVyb0J5dGVzKCBhZGRyLCBsZW4gKVxyXG4gIHtcclxuICAgIGZvciggdmFyIGkgPSAwOyBpIDwgbGVuOyArK2kgKVxyXG4gICAgICB0aGlzLm1lbURhdGFbIGFkZHIgKyBpIF0gPSAwO1xyXG4gIH1cclxuXHJcbiAgcmVhZEJ5dGVzKCBhZGRyLCBsZW4gKTogQnl0ZUFycmF5XHJcbiAge1xyXG4gICAgcmV0dXJuIHRoaXMubWVtRGF0YS52aWV3QXQoIGFkZHIsIGxlbiApO1xyXG4gIH1cclxuXHJcbiAgY29weUJ5dGVzKCBmcm9tQWRkciwgdG9BZGRyLCBsZW4gKVxyXG4gIHtcclxuICAgIHRoaXMud3JpdGVCeXRlcyggdG9BZGRyLCB0aGlzLnJlYWRCeXRlcyggZnJvbUFkZHIsIGxlbiApICk7XHJcbiAgfVxyXG5cclxuICB3cml0ZUJ5dGVzKCBhZGRyOiBudW1iZXIsIHZhbDogQnl0ZUFycmF5IClcclxuICB7XHJcbiAgICBpZiAoIHRoaXMuaW5UcmFuc2FjdGlvbiAmJiAoIHRoaXMuZmxhZ3MgJiBNRU1GTEFHUy5UUkFOU0FDVElPTkFCTEUgKSApXHJcbiAgICB7XHJcbiAgICAgIC8vIHNhdmUgcHJldmlvdXMgRUVQUk9NIGNvbnRlbnRzXHJcbiAgICAgIHRoaXMudHJhbnNCbG9ja3MucHVzaCggeyBhZGRyOiBhZGRyLCBkYXRhOiB0aGlzLnJlYWRCeXRlcyggYWRkciwgdmFsLmxlbmd0aCApIH0gKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLm1lbURhdGEuc2V0Qnl0ZXNBdCggYWRkciwgdmFsICk7XHJcbiAgfVxyXG5cclxuICBuZXdBY2Nlc3NvciggYWRkciwgbGVuLCBuYW1lICk6IEFjY2Vzc29yXHJcbiAge1xyXG4gICAgcmV0dXJuIG5ldyBBY2Nlc3NvciggdGhpcywgYWRkciwgbGVuLCBuYW1lICk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgQWNjZXNzb3Jcclxue1xyXG4gIG9mZnNldDogbnVtYmVyO1xyXG4gIGxlbmd0aDogbnVtYmVyO1xyXG4gIGlkOiBzdHJpbmc7XHJcbiAgc2VnOiBTZWdtZW50O1xyXG5cclxuICBjb25zdHJ1Y3Rvciggc2VnLCBhZGRyLCBsZW4sIG5hbWUgKVxyXG4gIHtcclxuICAgIHRoaXMuc2VnID0gc2VnO1xyXG5cclxuICAgIHRoaXMub2Zmc2V0ID0gYWRkcjtcclxuICAgIHRoaXMubGVuZ3RoID0gbGVuO1xyXG4gICAgdGhpcy5pZCA9IG5hbWU7XHJcbiAgfVxyXG5cclxuICB0cmFjZU1lbW9yeU9wKCBvcCwgYWRkciwgbGVuLCBhZGRyMj8gKVxyXG4gIHtcclxuICAgIGlmICggdGhpcy5pZCAhPSBcImNvZGVcIiApXHJcbiAgICAgIHRoaXMuc2VnLm1lbVRyYWNlcy5wdXNoKCB7IG9wOiBvcCwgbmFtZTogdGhpcy5pZCwgYWRkcjogYWRkciwgbGVuOiBsZW4sIGFkZHIyOiBhZGRyMiB9ICk7XHJcbiAgfVxyXG5cclxuICB0cmFjZU1lbW9yeVZhbHVlKCB2YWwgKVxyXG4gIHtcclxuICAgIGlmICggdGhpcy5pZCAhPSBcImNvZGVcIiApXHJcbiAgICB7XHJcbiAgICAgIHZhciBtZW1UcmFjZSA9IHRoaXMuc2VnLm1lbVRyYWNlc1sgdGhpcy5zZWcubWVtVHJhY2VzLmxlbmd0aCAtIDEgXTtcclxuXHJcbiAgICAgIG1lbVRyYWNlLnZhbCA9IHZhbDtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHplcm9CeXRlcyggYWRkcjogbnVtYmVyLCBsZW46IG51bWJlciApXHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgbGVuID4gdGhpcy5sZW5ndGggKVxyXG4gICAge1xyXG4gICAgICB0aGlzLnRyYWNlTWVtb3J5T3AoIFwiWlItZXJyb3JcIiwgYWRkciwgdGhpcy5sZW5ndGggKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFplcm9cIiApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJaUlwiLCBhZGRyLCBsZW4gKTtcclxuICAgIHRoaXMuc2VnLnplcm9CeXRlcyggdGhpcy5vZmZzZXQgKyBhZGRyLCBsZW4gKTtcclxuICAgIHRoaXMudHJhY2VNZW1vcnlWYWx1ZSggWyAwIF0gKTtcclxuICB9XHJcblxyXG4gIHJlYWRCeXRlKCBhZGRyOiBudW1iZXIgKTogbnVtYmVyXHJcbiAge1xyXG4gICAgaWYgKCBhZGRyICsgMSA+IHRoaXMubGVuZ3RoIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIlJELWVycm9yXCIsIGFkZHIsIDEgKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFJlYWRcIiApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJSRFwiLCBhZGRyLCAxICk7XHJcblxyXG4gICAgdmFyIHZhbCA9IHRoaXMuc2VnLnJlYWRCeXRlKCB0aGlzLm9mZnNldCArIGFkZHIgKTtcclxuXHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIFsgdmFsIF0pO1xyXG5cclxuICAgIHJldHVybiB2YWw7XHJcbiAgfVxyXG5cclxuICByZWFkQnl0ZXMoIGFkZHIsIGxlbiApOiBCeXRlQXJyYXlcclxuICB7XHJcbiAgICBpZiAoIGFkZHIgKyBsZW4gPiB0aGlzLmxlbmd0aCApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJSRC1lcnJvclwiLCBhZGRyLCBsZW4gKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFJlYWRcIiApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJSRFwiLCBhZGRyLCBsZW4gKTtcclxuICAgIHZhciB2YWwgPSB0aGlzLnNlZy5yZWFkQnl0ZXMoIHRoaXMub2Zmc2V0ICsgYWRkciwgbGVuICk7XHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIHZhbCApO1xyXG5cclxuICAgIHJldHVybiB2YWw7XHJcbiAgfVxyXG5cclxuICBjb3B5Qnl0ZXMoIGZyb21BZGRyOiBudW1iZXIsIHRvQWRkcjogbnVtYmVyLCBsZW46IG51bWJlciApOiBCeXRlQXJyYXlcclxuICB7XHJcbiAgICBpZiAoICggZnJvbUFkZHIgKyBsZW4gPiB0aGlzLmxlbmd0aCApIHx8ICggdG9BZGRyICsgbGVuID4gdGhpcy5sZW5ndGggKSApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJDUC1lcnJvclwiLCBmcm9tQWRkciwgbGVuLCB0b0FkZHIgKTtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIk1NOiBJbnZhbGlkIFJlYWRcIiApO1xyXG4gICAgfVxyXG5cclxuICAgIC8vaWYgKCBtZW1UcmFjaW5nIClcclxuICAgIHtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIkNQXCIsIGZyb21BZGRyLCBsZW4sIHRvQWRkciApO1xyXG4gICAgICB2YXIgdmFsID0gdGhpcy5zZWcucmVhZEJ5dGVzKCB0aGlzLm9mZnNldCArIGZyb21BZGRyLCBsZW4gKTtcclxuICAgICAgdGhpcy50cmFjZU1lbW9yeVZhbHVlKCB2YWwgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnNlZy5jb3B5Qnl0ZXMoIHRoaXMub2Zmc2V0ICsgZnJvbUFkZHIsIHRoaXMub2Zmc2V0ICsgdG9BZGRyLCBsZW4gKTtcclxuICAgIHJldHVybiB2YWw7XHJcbiAgfVxyXG5cclxuICB3cml0ZUJ5dGUoIGFkZHI6IG51bWJlciwgdmFsOiBudW1iZXIgKVxyXG4gIHtcclxuICAgIGlmICggYWRkciArIDEgPiB0aGlzLmxlbmd0aCApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJXUi1lcnJvclwiLCBhZGRyLCAxICk7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvciggXCJNTTogSW52YWxpZCBXcml0ZVwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIldSXCIsIGFkZHIsIDEgKTtcclxuICAgIHRoaXMuc2VnLndyaXRlQnl0ZXMoIHRoaXMub2Zmc2V0ICsgYWRkciwgbmV3IEJ5dGVBcnJheSggWyB2YWwgXSApICk7XHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIFsgdmFsIF0gKTtcclxuICB9XHJcblxyXG4gIHdyaXRlQnl0ZXMoIGFkZHI6IG51bWJlciwgdmFsOiBCeXRlQXJyYXkgKVxyXG4gIHtcclxuICAgIGlmICggYWRkciArIHZhbC5sZW5ndGggPiB0aGlzLmxlbmd0aCApXHJcbiAgICB7XHJcbiAgICAgIHRoaXMudHJhY2VNZW1vcnlPcCggXCJXUi1lcnJvclwiLCBhZGRyLCB2YWwubGVuZ3RoICk7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvciggXCJNTTogSW52YWxpZCBXcml0ZVwiICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy50cmFjZU1lbW9yeU9wKCBcIldSXCIsIGFkZHIsIHZhbC5sZW5ndGggKTtcclxuICAgIHRoaXMuc2VnLndyaXRlQnl0ZXMoIHRoaXMub2Zmc2V0ICsgYWRkciwgdmFsICk7XHJcbiAgICB0aGlzLnRyYWNlTWVtb3J5VmFsdWUoIHZhbCApO1xyXG4gIH1cclxuXHJcbiAgZ2V0VHlwZSgpIHsgcmV0dXJuIHRoaXMuc2VnLmdldFR5cGUoKTsgfVxyXG4gIGdldExlbmd0aCgpIHsgcmV0dXJuIHRoaXMubGVuZ3RoOyB9XHJcbiAgZ2V0SUQoKSB7IHJldHVybiB0aGlzLmlkOyB9XHJcbi8vICAgICAgICBiZWdpblRyYW5zYWN0aW9uOiBiZWdpblRyYW5zYWN0aW9uLFxyXG4vLyAgICAgICAgaW5UcmFuc2FjdGlvbjogZnVuY3Rpb24oKSB7IHJldHVybiBpblRyYW5zYWN0aW9uOyB9LFxyXG4vLyAgICAgICAgZW5kVHJhbnNhY3Rpb246IGVuZFRyYW5zYWN0aW9uLFxyXG4gIGdldERlYnVnKCkgeyByZXR1cm4geyBvZmZzZXQ6IHRoaXMub2Zmc2V0LCBsZW5ndGg6IHRoaXMubGVuZ3RoLCBzZWc6IHRoaXMuc2VnIH07IH1cclxufVxyXG5cclxuZnVuY3Rpb24gc2xpY2VEYXRhKCBiYXNlLCBvZmZzZXQsIHNpemUgKTogVWludDhBcnJheVxyXG57XHJcbiAgcmV0dXJuIGJhc2Uuc3ViYXJyYXkoIG9mZnNldCwgb2Zmc2V0ICsgc2l6ZSApO1xyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgTWVtb3J5TWFuYWdlclxyXG57XHJcbiAgcHJpdmF0ZSBtZW1vcnlTZWdtZW50cyA9IFtdO1xyXG5cclxuICBwcml2YXRlIG1lbVRyYWNlcyA9IFtdO1xyXG5cclxuICBuZXdTZWdtZW50KCBtZW1UeXBlLCBzaXplLCBmbGFncz8gICk6IFNlZ21lbnRcclxuICB7XHJcbiAgICBsZXQgbmV3U2VnID0gbmV3IFNlZ21lbnQoIG1lbVR5cGUsIHNpemUsIGZsYWdzICk7XHJcblxyXG4gICAgdGhpcy5tZW1vcnlTZWdtZW50c1sgbWVtVHlwZSBdID0gbmV3U2VnO1xyXG5cclxuICAgIG5ld1NlZy5tZW1UcmFjZXMgPSB0aGlzLm1lbVRyYWNlcztcclxuXHJcbiAgICByZXR1cm4gbmV3U2VnO1xyXG4gIH1cclxuXHJcbiAgZ2V0TWVtVHJhY2UoKSB7IHJldHVybiB0aGlzLm1lbVRyYWNlczsgfVxyXG5cclxuICBpbml0TWVtVHJhY2UoKSB7IHRoaXMubWVtVHJhY2VzID0gW107IH1cclxuXHJcbiAgZ2V0U2VnbWVudCggdHlwZSApIHsgcmV0dXJuIHRoaXMubWVtb3J5U2VnbWVudHNbIHR5cGUgXTsgfVxyXG59XHJcbiIsImV4cG9ydCBlbnVtIE1FTElOU1Qge1xyXG4gIG1lbFNZU1RFTSA9ICAweDAwLFxyXG4gIG1lbEJSQU5DSCA9ICAweDAxLFxyXG4gIG1lbEpVTVAgPSAgICAweDAyLFxyXG4gIG1lbENBTEwgPSAgICAweDAzLFxyXG4gIG1lbFNUQUNLID0gICAweDA0LFxyXG4gIG1lbFBSSU1SRVQgPSAweDA1LFxyXG4gIG1lbElOVkFMSUQgPSAweDA2LFxyXG4gIG1lbExPQUQgPSAgICAweDA3LFxyXG4gIG1lbFNUT1JFID0gICAweDA4LFxyXG4gIG1lbExPQURJID0gICAweDA5LFxyXG4gIG1lbFNUT1JFSSA9ICAweDBBLFxyXG4gIG1lbExPQURBID0gICAweDBCLFxyXG4gIG1lbElOREVYID0gICAweDBDLFxyXG4gIG1lbFNFVEIgPSAgICAweDBELFxyXG4gIG1lbENNUEIgPSAgICAweDBFLFxyXG4gIG1lbEFEREIgPSAgICAweDBGLFxyXG4gIG1lbFNVQkIgPSAgICAweDEwLFxyXG4gIG1lbFNFVFcgPSAgICAweDExLFxyXG4gIG1lbENNUFcgPSAgICAweDEyLFxyXG4gIG1lbEFERFcgPSAgICAweDEzLFxyXG4gIG1lbFNVQlcgPSAgICAweDE0LFxyXG4gIG1lbENMRUFSTiA9ICAweDE1LFxyXG4gIG1lbFRFU1ROID0gICAweDE2LFxyXG4gIG1lbElOQ04gPSAgICAweDE3LFxyXG4gIG1lbERFQ04gPSAgICAweDE4LFxyXG4gIG1lbE5PVE4gPSAgICAweDE5LFxyXG4gIG1lbENNUE4gPSAgICAweDFBLFxyXG4gIG1lbEFERE4gPSAgICAweDFCLFxyXG4gIG1lbFNVQk4gPSAgICAweDFDLFxyXG4gIG1lbEFORE4gPSAgICAweDFELFxyXG4gIG1lbE9STiA9ICAgICAweDFFLFxyXG4gIG1lbFhPUk4gPSAgICAweDFGXHJcbn07XHJcblxyXG5leHBvcnQgZW51bSBNRUxUQUdBRERSIHtcclxuICBtZWxBZGRyVE9TID0gMHgwMCxcclxuICBtZWxBZGRyU0IgPSAgMHgwMSxcclxuICBtZWxBZGRyU1QgPSAgMHgwMixcclxuICBtZWxBZGRyREIgPSAgMHgwMyxcclxuICBtZWxBZGRyTEIgPSAgMHgwNCxcclxuICBtZWxBZGRyRFQgPSAgMHgwNSxcclxuICBtZWxBZGRyUEIgPSAgMHgwNixcclxuICBtZWxBZGRyUFQgPSAgMHgwN1xyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMVEFHQ09ORCB7XHJcbiAgbWVsQ29uZFNQRUMgPSAgMHgwMCwgLy8gU3BlY2lhbFxyXG4gIG1lbENvbmRFUSA9ICAgIDB4MDEsIC8vIEVxdWFsXHJcbiAgbWVsQ29uZExUID0gICAgMHgwMiwgLy8gTGVzcyB0aGFuXHJcbiAgbWVsQ29uZExFID0gICAgMHgwMywgLy8gTGVzcyB0aGFuLCBlcXVhbCB0b1xyXG4gIG1lbENvbmRHVCA9ICAgIDB4MDQsIC8vIEdyZWF0ZXIgdGhhblxyXG4gIG1lbENvbmRHRSA9ICAgIDB4MDUsIC8vIEdyZWF0ZXIgdGhhbiwgZXF1YWwgdG9cclxuICBtZWxDb25kTkUgPSAgICAweDA2LCAvLyBOb3QgZXF1YWwgdG9cclxuICBtZWxDb25kQUxMID0gICAweDA3ICAvLyBBbHdheXNcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFRBR1NZU1RFTSB7XHJcbiAgbWVsU3lzdGVtTk9QID0gICAgICAgMHgwMCwgLy8gTk9QXHJcbiAgbWVsU3lzdGVtU2V0U1cgPSAgICAgMHgwMSwgLy8gU0VUU1dcclxuICBtZWxTeXN0ZW1TZXRMYSA9ICAgICAweDAyLCAvLyBTRVRMQVxyXG4gIG1lbFN5c3RlbVNldFNXTGEgPSAgIDB4MDMsIC8vIFNFVFNXTEFcclxuICBtZWxTeXN0ZW1FeGl0ID0gICAgICAweDA0LCAvLyBFWElUXHJcbiAgbWVsU3lzdGVtRXhpdFNXID0gICAgMHgwNSwgLy8gRVhJVFNXXHJcbiAgbWVsU3lzdGVtRXhpdExhID0gICAgMHgwNiwgLy8gRVhJVExBXHJcbiAgbWVsU3lzdGVtRXhpdFNXTGEgPSAgMHgwNyAgLy8gRVhJVFNXTEFcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFRBR1NUQUNLIHtcclxuICBtZWxTdGFja1BVU0haID0gIDB4MDAsIC8vIFBVU0haXHJcbiAgbWVsU3RhY2tQVVNIQiA9ICAweDAxLCAvLyBQVVNIQlxyXG4gIG1lbFN0YWNrUFVTSFcgPSAgMHgwMiwgLy8gUFVTSFdcclxuICBtZWxTdGFja1hYNCA9ICAgIDB4MDMsIC8vIElsbGVnYWxcclxuICBtZWxTdGFja1BPUE4gPSAgIDB4MDQsIC8vIFBPUE5cclxuICBtZWxTdGFja1BPUEIgPSAgIDB4MDUsIC8vIFBPUEJcclxuICBtZWxTdGFja1BPUFcgPSAgIDB4MDYsIC8vIFBPUFdcclxuICBtZWxTdGFja1hYNyA9ICAgIDB4MDcgIC8vIElsbGVnYWxcclxufTtcclxuXHJcbmV4cG9ydCBlbnVtIE1FTFRBR1BSSU1SRVQge1xyXG4gIG1lbFByaW1SZXRQUklNMCA9ICAweDAwLCAvLyBQUklNIDBcclxuICBtZWxQcmltUmV0UFJJTTEgPSAgMHgwMSwgLy8gUFJJTSAxXHJcbiAgbWVsUHJpbVJldFBSSU0yID0gIDB4MDIsIC8vIFBSSU0gMlxyXG4gIG1lbFByaW1SZXRQUklNMyA9ICAweDAzLCAvLyBQUklNIDNcclxuICBtZWxQcmltUmV0UkVUID0gICAgMHgwNCwgLy8gUkVUXHJcbiAgbWVsUHJpbVJldFJFVEkgPSAgIDB4MDUsIC8vIFJFVCBJblxyXG4gIG1lbFByaW1SZXRSRVRPID0gICAweDA2LCAvLyBSRVQgT3V0XHJcbiAgbWVsUHJpbVJldFJFVElPID0gIDB4MDcgIC8vIFJFVCBJbk91dFxyXG59O1xyXG5cclxuZXhwb3J0IGVudW0gTUVMUEFSQU1ERUYge1xyXG4gIG1lbFBhcmFtRGVmTm9uZSA9ICAgICAgICAgICAgICAweDAwLFxyXG4gIG1lbFBhcmFtRGVmVG9wT2ZTdGFjayA9ICAgICAgICAweDAxLFxyXG4gIG1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gPSAgICAgICAweDExLFxyXG4gIG1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSA9ICAgICAweDEyLFxyXG4gIG1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZSA9ICAweDE4LFxyXG4gIG1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSA9ICAgICAweDIwLFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldFNCID0gICAgICAweDIxLFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldFNUID0gICAgICAweDIyLFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldERCID0gICAgICAweDIzLFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldExCID0gICAgICAweDI0LFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldERUID0gICAgICAweDI1LFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldFBCID0gICAgICAweDI2LFxyXG4gIG1lbFBhcmFtRGVmV29yZE9mZnNldFBUID0gICAgICAweDI3LFxyXG4gIG1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzID0gICAweDI4XHJcbn07XHJcblxyXG5mdW5jdGlvbiBNRUxQQVJBTTQoIGEsIGIsIGMsIGQgKSAgICAgICAgeyByZXR1cm4gKCAoZDw8MjQpIHwgKGM8PDE2KSB8IChiPDw4KSB8IChhPDwwKSApOyB9XHJcbmZ1bmN0aW9uIE9QVEFHMk1FTElOU1QoIG9wQ29kZSwgdGFnICkgICB7IHJldHVybiAoICggKCBvcENvZGUgJiAweDFmICkgPDwgMyApIHwgdGFnICk7IH1cclxuZXhwb3J0IGZ1bmN0aW9uIE1FTDJPUENPREUoIGJ5dGVDb2RlICkgICAgICAgICB7IHJldHVybiAoICggYnl0ZUNvZGUgPj4gMyApICYgMHgxZiApOyB9XHJcbmV4cG9ydCBmdW5jdGlvbiBNRUwySU5TVCggYnl0ZUNvZGUgKSAgICAgICAgICAgeyByZXR1cm4gTUVMMk9QQ09ERSggYnl0ZUNvZGUgKTsgfVxyXG5leHBvcnQgZnVuY3Rpb24gTUVMMlRBRyggYnl0ZUNvZGUgKSAgICAgICAgICAgIHsgcmV0dXJuICggKGJ5dGVDb2RlKSAmIDcgKSB9O1xyXG5cclxuZnVuY3Rpb24gTUVMUEFSQU1TSVpFKCBwYXJhbVR5cGUgKVxyXG57XHJcbiAgcmV0dXJuICggcGFyYW1UeXBlID09IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZSApXHJcbiAgICAgICAgID8gMFxyXG4gICAgICAgICA6ICggcGFyYW1UeXBlIDwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlKSA/IDEgOiAyO1xyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgTUVMXHJcbntcclxuICBwdWJsaWMgc3RhdGljIG1lbERlY29kZSA9IFtdO1xyXG5cclxuICBwdWJsaWMgc3RhdGljIE1FTElOU1Q6IE1FTElOU1Q7XHJcbiAgcHVibGljIHN0YXRpYyBNRUxUQUdTVEFDSzogTUVMVEFHU1RBQ0s7XHJcbiAgcHVibGljIHN0YXRpYyBNRUxQQVJBTURFRjogTUVMUEFSQU1ERUY7XHJcbiAgcHVibGljIHN0YXRpYyBNRUxUQUdBRERSOiBNRUxUQUdBRERSO1xyXG5cclxufVxyXG5cclxuZnVuY3Rpb24gc2V0TWVsRGVjb2RlKCBieXRlQ29kZTogbnVtYmVyLCBpbnN0TmFtZTogc3RyaW5nLCBwYXJhbTE/LCBwYXJhbTI/LCBwYXJhbTM/LCBwYXJhbTQ/IClcclxue1xyXG4gIHBhcmFtMSA9IHBhcmFtMSB8fCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmU7XHJcbiAgcGFyYW0yID0gcGFyYW0yIHx8IE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmTm9uZTtcclxuICBwYXJhbTMgPSBwYXJhbTMgfHwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lO1xyXG4gIHBhcmFtNCA9IHBhcmFtNCB8fCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZk5vbmU7XHJcblxyXG4gIE1FTC5tZWxEZWNvZGVbIGJ5dGVDb2RlIF0gPSB7XHJcbiAgICBieXRlQ29kZTogYnl0ZUNvZGUsXHJcbiAgICBpbnN0TGVuOiAxICsgTUVMUEFSQU1TSVpFKCBwYXJhbTEgKSArIE1FTFBBUkFNU0laRSggcGFyYW0yICkgKyBNRUxQQVJBTVNJWkUoIHBhcmFtMyApICsgTUVMUEFSQU1TSVpFKCBwYXJhbTQgKSxcclxuICAgIGluc3ROYW1lOiBpbnN0TmFtZSxcclxuICAgIHBhcmFtRGVmczogTUVMUEFSQU00KCBwYXJhbTEsIHBhcmFtMiwgcGFyYW0zLCBwYXJhbTQgKVxyXG4gIH07XHJcbn1cclxuXHJcbmZ1bmN0aW9uIHNldE1lbERlY29kZVN0ZE1vZGVzKCBtZWxJbnN0OiBNRUxJTlNULCBpbnN0TmFtZTogc3RyaW5nLCBwYXJhbTFEZWY6IE1FTFBBUkFNREVGIClcclxue1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyU0IgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0U0IgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkclNUICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNUICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJEQiApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXREQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyTEIgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0TEIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbEluc3QsIE1FTFRBR0FERFIubWVsQWRkckRUICksIGluc3ROYW1lLCBwYXJhbTFEZWYsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERUICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJQQiApLCBpbnN0TmFtZSwgcGFyYW0xRGVmLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQQiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsSW5zdCwgTUVMVEFHQUREUi5tZWxBZGRyUFQgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UFQgKTtcclxufVxyXG5cclxuZnVuY3Rpb24gc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIG1lbEluc3Q6IE1FTElOU1QsIGluc3ROYW1lOiBzdHJpbmcsIHBhcmFtMURlZjogTUVMUEFSQU1ERUYgKVxyXG57XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBtZWxJbnN0LCBNRUxUQUdBRERSLm1lbEFkZHJUT1MgKSwgaW5zdE5hbWUsIHBhcmFtMURlZiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZUb3BPZlN0YWNrICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXMoIG1lbEluc3QsIGluc3ROYW1lLCBwYXJhbTFEZWYgKTtcclxufVxyXG5cclxuZnVuY3Rpb24gZmlsbE1lbERlY29kZSgpXHJcbntcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxMT0FELCAgIFwiTE9BRFwiLCAgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVE9SRSwgIFwiU1RPUkVcIiwgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxMT0FESSwgIFwiTE9BRElcIiwgIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGVTdGRNb2Rlc0FuZFRPUyggTUVMSU5TVC5tZWxTVE9SRUksIFwiU1RPUkVJXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJTQiApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJTVCApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNUICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJEQiApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJMQiApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldExCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJEVCApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERUICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJQQiApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBCICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbExPQURBLCBNRUxUQUdBRERSLm1lbEFkZHJQVCApLCBcIkxPQURBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFBUICk7XHJcblxyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzKCBNRUxJTlNULm1lbElOREVYLCAgXCJJTkRFWFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU0VUQiwgICBcIlNFVEJcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQ01QQiwgICBcIkNNUEJcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQUREQiwgICBcIkFEREJcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU1VCQiwgICBcIlNVQkJcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU0VUVywgICBcIlNFVFdcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQ01QVywgICBcIkNNUFdcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsQUREVywgICBcIkFERFdcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlU3RkTW9kZXNBbmRUT1MoIE1FTElOU1QubWVsU1VCVywgICBcIlNVQldcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcblxyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbENMRUFSTiwgXCJDTEVBUk5cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFRFU1ROLCAgXCJURVNUTlwiLCAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbElOQ04sICAgXCJJTkNOXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbERFQ04sICAgXCJERUNOXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbE5PVE4sICAgXCJOT1ROXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbENNUE4sICAgXCJDTVBOXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbEFERE4sICAgXCJBREROXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFNVQk4sICAgXCJTVUJOXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbEFORE4sICAgXCJBTkROXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbE9STiwgICAgXCJPUk5cIiwgICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZVN0ZE1vZGVzQW5kVE9TKCBNRUxJTlNULm1lbFhPUk4sICAgXCJYT1JOXCIsICAgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG5cclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtTk9QICksIFwiTk9QXCIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtU2V0U1cgKSwgXCJTRVRTV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtU2V0TGEgKSwgXCJTRVRMQVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtU2V0U1dMYSApLCBcIlNFVFNXTEFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1lTVEVNLCBNRUxUQUdTWVNURU0ubWVsU3lzdGVtRXhpdCApLCBcIkVYSVRcIiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1FeGl0U1cgKSwgXCJFWElUU1dcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNZU1RFTSwgTUVMVEFHU1lTVEVNLm1lbFN5c3RlbUV4aXRMYSApLCBcIkVYSVRBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTWVNURU0sIE1FTFRBR1NZU1RFTS5tZWxTeXN0ZW1FeGl0U1dMYSApLCBcIkVYSVRTV0xBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkSW1tZWRpYXRlICk7XHJcblxyXG4gIC8vIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggbWVsQlJBTkNILCBtZWxDb25kU1BFQyApLCBcIi0tLVwiLCAwLCBtZWxBZGRyVE9TICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kRVEgKSwgXCJCRVFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kTFQgKSwgXCJCTFRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kTEUgKSwgXCJCTEVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kR1QgKSwgXCJCR1RcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kR0UgKSwgXCJCR0VcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kTkUgKSwgXCJCTkVcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEJSQU5DSCwgTUVMVEFHQ09ORC5tZWxDb25kQUxMICksIFwiQkFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlQ29kZVJlbGF0aXZlICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxKVU1QLCBNRUxUQUdDT05ELm1lbENvbmRTUEVDICksIFwiSkFcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZEVRICksIFwiSkVRXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZExUICksIFwiSkxUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZExFICksIFwiSkxFXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZEdUICksIFwiSkdUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZEdFICksIFwiSkdFXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZE5FICksIFwiSk5FXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbEpVTVAsIE1FTFRBR0NPTkQubWVsQ29uZEFMTCApLCBcIkpBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxDQUxMLCBNRUxUQUdDT05ELm1lbENvbmRTUEVDICksIFwiQ0FcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZOb25lICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZEVRICksIFwiQ0VRXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZExUICksIFwiQ0xUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZExFICksIFwiQ0xFXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZEdUICksIFwiQ0dUXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZEdFICksIFwiQ0dFXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZE5FICksIFwiQ05FXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbENBTEwsIE1FTFRBR0NPTkQubWVsQ29uZEFMTCApLCBcIkNBXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzICk7XHJcblxyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIWiApLCBcIlBVU0haXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW4gKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSEIgKSwgXCJQVVNIQlwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSFcgKSwgXCJQVVNIV1wiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRJbW1lZGlhdGUgKTtcclxuICAvLyBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbFNUQUNLLCBtZWxTdGFja1hYNCApLCBcIi0tXCIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsU1RBQ0ssIE1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QTiApLCBcIlBPUE5cIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxTVEFDSywgTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BCICksIFwiUE9QQlwiICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFNUQUNLLCBNRUxUQUdTVEFDSy5tZWxTdGFja1BPUFcgKSwgXCJQT1BXXCIgKTtcclxuICAvLyBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIG1lbFNUQUNLLCBtZWxTdGFja1hYNyApLCBcIi0tXCIgKTtcclxuXHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0wICksIFwiUFJJTVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTEgKSwgXCJQUklNXCIsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0yICksIFwiUFJJTVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0zICksIFwiUFJJTVwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUsIE1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUltbWVkaWF0ZSwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUICksIFwiUkVUXCIgKTtcclxuICBzZXRNZWxEZWNvZGUoIE9QVEFHMk1FTElOU1QoIE1FTElOU1QubWVsUFJJTVJFVCwgTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUSSApLCBcIlJFVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbiAgc2V0TWVsRGVjb2RlKCBPUFRBRzJNRUxJTlNUKCBNRUxJTlNULm1lbFBSSU1SRVQsIE1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVE8gKSwgXCJSRVRcIiwgTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApO1xyXG4gIHNldE1lbERlY29kZSggT1BUQUcyTUVMSU5TVCggTUVMSU5TVC5tZWxQUklNUkVULCBNRUxUQUdQUklNUkVULm1lbFByaW1SZXRSRVRJTyApLCBcIlJFVFwiLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuLCBNRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuICk7XHJcbn1cclxuXHJcblxyXG5maWxsTWVsRGVjb2RlKCk7XHJcblxyXG5leHBvcnQgdmFyIE1FTERlY29kZSA9IE1FTC5tZWxEZWNvZGU7XHJcbmV4cG9ydCBjb25zdCBNRUxfQ0NSX1ogPSAweDAxO1xyXG5leHBvcnQgY29uc3QgTUVMX0NDUl9DID0gMHgwMjtcclxuIiwiaW1wb3J0ICogYXMgTUVMIGZyb20gJy4vbWVsLWRlZmluZXMnO1xyXG5pbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuXHJcbmltcG9ydCB7IENvbW1hbmRBUERVIH0gZnJvbSAnLi4vYmFzZS9jb21tYW5kLWFwZHUnO1xyXG5pbXBvcnQgeyBSZXNwb25zZUFQRFUgfSBmcm9tICcuLi9iYXNlL3Jlc3BvbnNlLWFwZHUnO1xyXG5cclxuZnVuY3Rpb24gaGV4KCB2YWwgKSB7IHJldHVybiB2YWwudG9TdHJpbmcoIDE2ICk7IH1cclxuZnVuY3Rpb24gaGV4MiggdmFsICkgeyByZXR1cm4gKCBcIjAwXCIgKyB2YWwudG9TdHJpbmcoIDE2ICkgKS5zdWJzdHIoIC0yICk7IH1cclxuZnVuY3Rpb24gaGV4NCggdmFsICkgeyByZXR1cm4gKCBcIjAwMDBcIiArIHZhbC50b1N0cmluZyggMTYgKSApLnN1YnN0ciggLTQgKTsgfVxyXG5mdW5jdGlvbiBsanVzdCggc3RyLCB3ICkgeyByZXR1cm4gKCBzdHIgKyBBcnJheSggdyArIDEgKS5qb2luKCBcIiBcIiApICkuc3Vic3RyKCAwLCB3ICk7IH1cclxuZnVuY3Rpb24gcmp1c3QoIHN0ciwgdyApIHsgcmV0dXJuICggQXJyYXkoIHcgKyAxICkuam9pbiggXCIgXCIgKSArIHN0ciApLnN1YnN0ciggLXcgKTsgfVxyXG5cclxuZnVuY3Rpb24gICBCQTJXKCB2YWwgKVxyXG57XHJcbiAgcmV0dXJuICggdmFsWyAwIF0gPDwgOCApIHwgdmFsWyAxIF07XHJcbn1cclxuXHJcbmZ1bmN0aW9uICAgVzJCQSggdmFsIClcclxue1xyXG5cclxuICByZXR1cm4gbmV3IEJ5dGVBcnJheSggWyB2YWwgPj4gOCwgdmFsICYgMHhGRiBdICk7XHJcbn1cclxuXHJcbmV4cG9ydCBjbGFzcyBNRUxWaXJ0dWFsTWFjaGluZSB7XHJcbiAgLy8gY2FyZFxyXG4gIHJhbVNlZ21lbnQ7XHJcbiAgcm9tU2VnbWVudDtcclxuXHJcbiAgLy8gYXBwbGljYXRpb25cclxuICBjb2RlQXJlYTtcclxuICBzdGF0aWNBcmVhO1xyXG4gIHB1YmxpY0FyZWE7XHJcbiAgZHluYW1pY0FyZWE7XHJcbiAgc2Vzc2lvblNpemU7XHJcblxyXG4gIC8vIGV4ZWN1dGlvblxyXG4gIGlzRXhlY3V0aW5nO1xyXG4gIGN1cnJlbnRJUDtcclxuICBsb2NhbEJhc2U7XHJcbiAgZHluYW1pY1RvcDtcclxuICBjb25kaXRpb25Db2RlUmVnO1xyXG5cclxuICBpbml0TVZNKCBwYXJhbXMgKVxyXG4gIHtcclxuICAgIHRoaXMucm9tU2VnbWVudCA9IHBhcmFtcy5yb21TZWdtZW50O1xyXG4gICAgdGhpcy5yYW1TZWdtZW50ID0gcGFyYW1zLnJhbVNlZ21lbnQ7XHJcblxyXG4gICAgdGhpcy5wdWJsaWNBcmVhID0gdGhpcy5yYW1TZWdtZW50Lm5ld0FjY2Vzc29yKCAwLCA1MTIsIFwiUFwiICk7XHJcbiAgfVxyXG5cclxuICBkaXNhc3NlbWJsZUNvZGUoIHJlc2V0SVAsIHN0ZXBUb05leHRJUCApXHJcbiAge1xyXG4gICAgdmFyIGRpc21UZXh0ID0gXCJcIjtcclxuICAgIGZ1bmN0aW9uIHByaW50KCBzdHIgKSB7IGRpc21UZXh0ICs9IHN0cjsgfVxyXG5cclxuICAgIGlmICggcmVzZXRJUCApXHJcbiAgICAgIHRoaXMuY3VycmVudElQID0gMDtcclxuXHJcbiAgICBpZiAoIHRoaXMuY3VycmVudElQID49IHRoaXMuY29kZUFyZWEuZ2V0TGVuZ3RoKCkgKVxyXG4gICAgICByZXR1cm4gbnVsbDtcclxuXHJcbiAgICB0cnlcclxuICAgIHtcclxuICAgICAgdmFyIG5leHRJUCA9IHRoaXMuY3VycmVudElQO1xyXG4gICAgICB2YXIgaW5zdEJ5dGUgPSB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApO1xyXG4gICAgICB2YXIgcGFyYW1Db3VudCA9IDA7XHJcbiAgICAgIHZhciBwYXJhbVZhbCA9IFtdO1xyXG4gICAgICB2YXIgcGFyYW1EZWYgPSBbXTtcclxuXHJcbiAgICAgIHZhciBtZWxJbnN0ID0gTUVMLk1FTERlY29kZVsgaW5zdEJ5dGUgXTtcclxuXHJcbiAgICAgIGlmICggbWVsSW5zdCA9PSB1bmRlZmluZWQgKVxyXG4gICAgICB7XHJcbiAgICAgICAgcHJpbnQoIFwiW1wiICsgaGV4NCggdGhpcy5jdXJyZW50SVAgKSArIFwiXSAgICAgICAgICBcIiArIGxqdXN0KCBcIkVSUk9SOlwiICsgaGV4MiggaW5zdEJ5dGUgKSwgOCApICsgXCIgKioqKioqKipcXG5cIiApO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIHZhciBwYXJhbURlZnMgPSBtZWxJbnN0LnBhcmFtRGVmcztcclxuICAgICAgICB3aGlsZSggcGFyYW1EZWZzICE9IDAgKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHBhcmFtRGVmWyBwYXJhbUNvdW50IF0gPSBwYXJhbURlZnMgJiAweEZGO1xyXG4gICAgICAgICAgc3dpdGNoKCBwYXJhbURlZnMgJiAweEYwIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSAweDAwOiBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAweDEwOiBwYXJhbVZhbFsgcGFyYW1Db3VudCBdID0gdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKTsgYnJlYWs7XHJcbiAgICAgICAgICAgIGNhc2UgMHgyMDogcGFyYW1WYWxbIHBhcmFtQ291bnQgXSA9IEJBMlcoIFsgdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKSwgdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKSBdICk7IGJyZWFrO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgcGFyYW1Db3VudCsrO1xyXG4gICAgICAgICAgcGFyYW1EZWZzID4+PSA4O1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHJpbnQoIFwiW1wiICsgaGV4NCggdGhpcy5jdXJyZW50SVAgKSArIFwiXSAgICAgICAgICBcIiArIGxqdXN0KCBtZWxJbnN0Lmluc3ROYW1lLCA4ICkgKTtcclxuXHJcbiAgICAgICAgaWYgKCAoIHBhcmFtQ291bnQgPiAxIClcclxuICAgICAgICAgICYmICggKCBwYXJhbURlZlsgMCBdID09IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVPcGVyTGVuIClcclxuICAgICAgICAgICAgfHwgKCBwYXJhbURlZlsgMCBdID09IE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZkJ5dGVJbW1lZGlhdGUgKVxyXG4gICAgICAgICAgICB8fCAoIHBhcmFtRGVmWyAwIF0gPT0gTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZSApIClcclxuICAgICAgICAgICYmICggcGFyYW1EZWZbIDEgXSAhPSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlIClcclxuICAgICAgICAgICYmICggcGFyYW1EZWZbIDEgXSAhPSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlT3BlckxlbiApIClcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgdGVtcFZhbCA9IHBhcmFtVmFsWzFdOyBwYXJhbVZhbFsxXSA9IHBhcmFtVmFsWzBdOyBwYXJhbVZhbFswXSA9IHRlbXBWYWw7XHJcbiAgICAgICAgICB2YXIgdGVtcERlZiA9IHBhcmFtRGVmWzFdOyBwYXJhbURlZlsxXSA9IHBhcmFtRGVmWzBdOyBwYXJhbURlZlswXSA9IHRlbXBEZWY7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBmb3IoIHZhciBwYXJhbUluZGV4ID0gMDsgcGFyYW1JbmRleCA8IHBhcmFtQ291bnQ7ICsrcGFyYW1JbmRleCApXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIHYgPSBwYXJhbVZhbFsgcGFyYW1JbmRleCBdO1xyXG4gICAgICAgICAgdmFyIGQgPSBwYXJhbURlZlsgcGFyYW1JbmRleCBdO1xyXG5cclxuICAgICAgICAgIHN3aXRjaCggZCApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZU9wZXJMZW46XHJcbiAgICAgICAgICAgICAgaWYgKCB2ID4gMCApXHJcbiAgICAgICAgICAgICAgICBwcmludCggXCIweFwiICsgaGV4KCB2ICkgKTtcclxuICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICBwcmludCggdiApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZCeXRlSW1tZWRpYXRlOlxyXG4gICAgICAgICAgICAgIGlmICggdiA+IDAgKVxyXG4gICAgICAgICAgICAgICAgcHJpbnQoIFwiMHhcIiArIGhleCggdiApICk7XHJcbiAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgcHJpbnQoIHYgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZEltbWVkaWF0ZTpcclxuICAgICAgICAgICAgICBwcmludCggXCIweFwiICsgaGV4KCB2ICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZENvZGVBZGRyZXNzOlxyXG4gICAgICAgICAgICAgIHByaW50KCBoZXg0KCB2ICkgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmQnl0ZUNvZGVSZWxhdGl2ZTpcclxuICAgICAgICAgICAgICBwcmludCggaGV4NCggdGhpcy5jdXJyZW50SVAgKyAyICsgdiApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRTQjogIC8vIDAxXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldFNUOiAgLy8gMDJcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0REI6ICAvLyAwM1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRMQjogIC8vIDA0XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFBBUkFNREVGLm1lbFBhcmFtRGVmV29yZE9mZnNldERUOiAgLy8gMDVcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMUEFSQU1ERUYubWVsUGFyYW1EZWZXb3JkT2Zmc2V0UEI6ICAvLyAwNlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxQQVJBTURFRi5tZWxQYXJhbURlZldvcmRPZmZzZXRQVDogIC8vIDA3XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICB2YXIgc2VnID0gWyBcIlwiLCBcIlNCXCIsIFwiU1RcIiwgXCJEQlwiLCBcIkxCXCIsIFwiRFRcIiwgXCJQQlwiLCBcIlBUXCIgXTtcclxuICAgICAgICAgICAgICBwcmludCggc2VnWyBkICYgMHgwNyBdICk7XHJcbiAgICAgICAgICAgICAgaWYgKCB2ID4gMCApXHJcbiAgICAgICAgICAgICAgICBwcmludCggXCJbMHhcIiArIGhleCggdiApICsgXCJdXCIgKTtcclxuICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICBwcmludCggXCJbXCIgKyB2ICsgXCJdXCIgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIGlmICggcGFyYW1JbmRleCA8IHBhcmFtQ291bnQgLSAxIClcclxuICAgICAgICAgICAgcHJpbnQoIFwiLCBcIiApO1xyXG4gICAgICAgIH1cclxuICAgICAgICBwcmludCggXCJcXG5cIiApO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIHN0ZXBUb05leHRJUCApXHJcbiAgICAgICAgdGhpcy5jdXJyZW50SVAgPSBuZXh0SVA7XHJcbiAgICB9XHJcbiAgICBjYXRjaCggZSApXHJcbiAgICB7XHJcbiAgICAgIHByaW50KCBlICk7XHJcbiAgICB9O1xyXG5cclxuXHJcbiAgICByZXR1cm4gZGlzbVRleHQ7XHJcbiAgfVxyXG5cclxuICAvL1xyXG4gIC8vIE1VTFRPUyBhZGRyZXNzZXMgYXJlIDE2LWJpdCBsaW5lYXIgdmFsdWVzLCB3aGVuIHB1c2hlZCBvbnRvIHN0YWNrXHJcbiAgLy8gYW5kIHVzZWQgZm9yIGluZGlyZWN0aW9uLiBXZSBtYXAgYWRkcmVzcy10YWcgYW5kIG9mZnNldCBwYWlycyB0byBsaW5lYXJcclxuICAvLyBhZGRyZXNzZXMsIGFuZCBiYWNrIGFnYWluLCBieSBiYXNpbmcgc3RhdGljIGF0IDB4MDAwMCwgZHluYW1pYyBhdCAweDgwMDBcclxuICAvLyBhbmQgcHVibGljIGF0IDB4RjAwMC5cclxuICAvL1xyXG4gIHByaXZhdGUgbWFwVG9TZWdtZW50QWRkciggYWRkclRhZywgYWRkck9mZnNldCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBhZGRyT2Zmc2V0LCAwICk7XHJcblxyXG4gICAgc3dpdGNoKCBhZGRyVGFnIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEQjpcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyTEI6XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckRUOlxyXG4gICAgICAgIHJldHVybiAweDgwMDAgKyB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldDtcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclNCOlxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJTVDpcclxuICAgICAgICByZXR1cm4gdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQ7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJQQjpcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyUFQ6XHJcbiAgICAgICAgcmV0dXJuIDB4RjAwMCArIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0O1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBtYXBGcm9tU2VnbWVudEFkZHIoIHNlZ21lbnRBZGRyIClcclxuICB7XHJcbiAgICBpZiAoIHNlZ21lbnRBZGRyICYgMHg4MDAwIClcclxuICAgIHtcclxuICAgICAgaWYgKCBzZWdtZW50QWRkciA+PSAweEYwMDAgKVxyXG4gICAgICB7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGFBcmVhOiB0aGlzLnB1YmxpY0FyZWEsXHJcbiAgICAgICAgICBkYXRhQWRkclRhZzogTUVMLk1FTFRBR0FERFIubWVsQWRkclBCLFxyXG4gICAgICAgICAgZGF0YU9mZnNldDogc2VnbWVudEFkZHIgJiAweDBGRkZcclxuICAgICAgICB9O1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhQXJlYTogdGhpcy5keW5hbWljQXJlYSxcclxuICAgICAgICAgIGRhdGFBZGRyVGFnOiBNRUwuTUVMVEFHQUREUi5tZWxBZGRyREIsXHJcbiAgICAgICAgICBkYXRhT2Zmc2V0OiBzZWdtZW50QWRkciAmIDB4M0ZGRlxyXG4gICAgICAgIH07XHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIGVsc2VcclxuICAgIHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhQXJlYTogdGhpcy5zdGF0aWNBcmVhLFxyXG4gICAgICAgIGRhdGFBZGRyVGFnOiBNRUwuTUVMVEFHQUREUi5tZWxBZGRyU0IsXHJcbiAgICAgICAgZGF0YU9mZnNldDogc2VnbWVudEFkZHIgJiAweDdGRkZcclxuICAgICAgfTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8vXHJcbiAgLy8gdmFsaWRhdGUgYSBtdWx0aS1ieXRlIG1lbW9yeSBhY2Nlc3MsIHNwZWNpZmllZCBieSBhZGRyZXNzLXRhZy9vZmZzZXQgcGFpclxyXG4gIC8vIGFuZCBsZW5ndGggdmFsdWVzLiBJZiBvaywgbWFwIHRvIGFuIGFyZWEgYW5kIG9mZnNldCB3aXRoaW4gdGhhdCBhcmVhLlxyXG4gIC8vIENhbiBhY2NlcHQgcG9zaXRpdmUvbmVnYXRpdmUgb2Zmc2V0cywgc2luY2UgdGhleSBhcmVhIHJlbGF0aXZlIHRvIHRoZVxyXG4gIC8vIHRoZSB0b3Agb3IgdGhlIGJvdHRvbSBvZiB0aGUgc3BlY2lmaWVkIGFyZWEsIGFzIGluZGljYXRlZCBieSB0aGUgdGFnLlxyXG4gIC8vXHJcbiAgcHJpdmF0ZSBjaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIG9mZnNldCwgbGVuZ3RoIClcclxuICB7XHJcbiAgICB2YXIgZGF0YUFyZWE7XHJcbiAgICB2YXIgZGF0YU9mZnNldCA9IG9mZnNldDtcclxuICAgIHZhciBhcmVhTGltaXQ7XHJcblxyXG4gICAgc3dpdGNoKCBhZGRyVGFnIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5keW5hbWljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLmR5bmFtaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gdGhpcy5sb2NhbEJhc2U7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEQjpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMuZHluYW1pY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5keW5hbWljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkckxCOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5keW5hbWljQXJlYTtcclxuICAgICAgICBhcmVhTGltaXQgPSB0aGlzLmR5bmFtaWNBcmVhLmdldExlbmd0aCgpO1xyXG4gICAgICAgIGRhdGFPZmZzZXQgKz0gdGhpcy5sb2NhbEJhc2U7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdBRERSLm1lbEFkZHJEVDpcclxuICAgICAgICBkYXRhQXJlYSA9IHRoaXMuZHluYW1pY0FyZWE7XHJcbiAgICAgICAgYXJlYUxpbWl0ID0gdGhpcy5keW5hbWljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBkYXRhT2Zmc2V0ICs9IHRoaXMuZHluYW1pY1RvcDtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclNCOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5zdGF0aWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuc3RhdGljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclNUOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5zdGF0aWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMuc3RhdGljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBkYXRhT2Zmc2V0ICs9IGFyZWFMaW1pdDtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclBCOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5wdWJsaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMucHVibGljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0FERFIubWVsQWRkclBUOlxyXG4gICAgICAgIGRhdGFBcmVhID0gdGhpcy5wdWJsaWNBcmVhO1xyXG4gICAgICAgIGFyZWFMaW1pdCA9IHRoaXMucHVibGljQXJlYS5nZXRMZW5ndGgoKTtcclxuICAgICAgICBkYXRhT2Zmc2V0ICs9IGFyZWFMaW1pdDtcclxuICAgICAgICBicmVhaztcclxuICAgIH1cclxuXHJcbiAgICBkYXRhT2Zmc2V0ICY9IDB4ZmZmZjsgLy8gMTYgYml0cyBhZGRyZXNzZXNcclxuICAgIGlmICggKCBkYXRhT2Zmc2V0IDwgYXJlYUxpbWl0ICkgJiYgKCBkYXRhT2Zmc2V0ICsgbGVuZ3RoIDwgYXJlYUxpbWl0ICkgKVxyXG4gICAge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGFBcmVhOiBkYXRhQXJlYSxcclxuICAgICAgICBkYXRhT2Zmc2V0OiBkYXRhT2Zmc2V0XHJcbiAgICAgIH07XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvL1xyXG4gIC8vIHBlcmZvcm0gYSB2YWxpZGF0ZWQgbXVsdGktYnl0ZSByZWFkLCBzcGVjaWZpZWQgYnkgYWRkcmVzcy10YWcvb2Zmc2V0IHBhaXIgYW5kXHJcbiAgLy8gbGVuZ3RoIHZhbHVlcy4gUmV0dXJuIGRhdGEtYXJyYXksIG9yIHVuZGVmaW5lZFxyXG4gIC8vXHJcbiAgcHJpdmF0ZSByZWFkU2VnbWVudERhdGEoIGFkZHJUYWcsIG9mZnNldCwgbGVuZ3RoIClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIG9mZnNldCwgMSApO1xyXG4gICAgaWYgKCB0YXJnZXRBY2Nlc3MgPT0gdW5kZWZpbmVkIClcclxuICAgICAgcmV0dXJuO1xyXG5cclxuICAgIHJldHVybiB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEucmVhZEJ5dGVzKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgbGVuZ3RoICk7XHJcbiAgfVxyXG5cclxuICAvL1xyXG4gIC8vIHBlcmZvcm0gYSB2YWxpZGF0ZWQgbXVsdGktYnl0ZSB3cml0ZSwgc3BlY2lmaWVkIGJ5IGFkZHJlc3MtdGFnL29mZnNldCBwYWlyIGFuZFxyXG4gIC8vIGRhdGEtYXJyYXkgdG8gYmUgd3JpdHRlbi5cclxuICAvL1xyXG4gIHByaXZhdGUgd3JpdGVTZWdtZW50RGF0YSggYWRkclRhZywgb2Zmc2V0LCB2YWwgKVxyXG4gIHtcclxuICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLmNoZWNrRGF0YUFjY2VzcyggYWRkclRhZywgb2Zmc2V0LCAxICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLndyaXRlQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCB2YWwgKTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgcHVzaFplcm9zVG9TdGFjayggY250IClcclxuICB7XHJcbiAgICB0aGlzLmR5bmFtaWNBcmVhLnplcm9CeXRlcyggdGhpcy5keW5hbWljVG9wLCBjbnQgKTtcclxuXHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgKz0gY250O1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwdXNoQ29uc3RUb1N0YWNrKCBjbnQsIHZhbCApXHJcbiAge1xyXG4gICAgaWYgKCBjbnQgPT0gMSApXHJcbiAgICAgIHRoaXMuZHluYW1pY0FyZWEud3JpdGVCeXRlcyggdGhpcy5keW5hbWljVG9wLCBbIHZhbCBdICk7XHJcbiAgICBlbHNlXHJcbiAgICAgIHRoaXMuZHluYW1pY0FyZWEud3JpdGVCeXRlcyggdGhpcy5keW5hbWljVG9wLCBXMkJBKCB2YWwgKSApO1xyXG5cclxuICAgIHRoaXMuZHluYW1pY1RvcCArPSBjbnQ7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGNvcHlPblN0YWNrKCBmcm9tT2Zmc2V0LCB0b09mZnNldCwgY250IClcclxuICB7XHJcbiAgICB0aGlzLmR5bmFtaWNBcmVhLmNvcHlCeXRlcyggZnJvbU9mZnNldCwgdG9PZmZzZXQsIGNudCApO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwdXNoVG9TdGFjayggYWRkclRhZywgb2Zmc2V0LCBjbnQgKVxyXG4gIHtcclxuICAgIHRoaXMuZHluYW1pY1RvcCArPSBjbnQ7XHJcbiAgICB0aGlzLmR5bmFtaWNBcmVhLndyaXRlQnl0ZXMoIHRoaXMuZHluYW1pY1RvcCwgdGhpcy5yZWFkU2VnbWVudERhdGEoIGFkZHJUYWcsIG9mZnNldCwgY250ICkgKTtcclxuICB9XHJcblxyXG4gIHByaXZhdGUgcG9wRnJvbVN0YWNrQW5kU3RvcmUoIGFkZHJUYWcsIG9mZnNldCwgY250IClcclxuICB7XHJcbiAgICB0aGlzLmR5bmFtaWNUb3AgLT0gY250O1xyXG5cclxuICAgIHRoaXMud3JpdGVTZWdtZW50RGF0YSggYWRkclRhZywgb2Zmc2V0LCB0aGlzLmR5bmFtaWNBcmVhLnJlYWRCeXRlcyggdGhpcy5keW5hbWljVG9wLCBjbnQgKSApO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwb3BGcm9tU3RhY2soIGNudCApXHJcbiAge1xyXG4gICAgdGhpcy5keW5hbWljVG9wIC09IGNudDtcclxuXHJcbiAgICByZXR1cm4gdGhpcy5keW5hbWljQXJlYS5yZWFkQnl0ZXMoIHRoaXMuZHluYW1pY1RvcCwgY250ICk7XHJcbiAgfVxyXG5cclxuICAvLyBzZXR1cCBhcHBsaWNhdGlvbiBmb3IgZXhlY3V0aW9uXHJcbiAgc2V0dXBBcHBsaWNhdGlvbiggZXhlY1BhcmFtcyApXHJcbiAge1xyXG4gICAgdGhpcy5jb2RlQXJlYSA9IGV4ZWNQYXJhbXMuY29kZUFyZWE7XHJcbiAgICB0aGlzLnN0YXRpY0FyZWEgPSBleGVjUGFyYW1zLnN0YXRpY0FyZWE7XHJcbiAgICB0aGlzLnNlc3Npb25TaXplID0gZXhlY1BhcmFtcy5zZXNzaW9uU2l6ZTtcclxuXHJcbiAgICB0aGlzLmR5bmFtaWNBcmVhID0gdGhpcy5yYW1TZWdtZW50Lm5ld0FjY2Vzc29yKCAwLCA1MTIsIFwiRFwiICk7IC8vVE9ETzogZXhlY1BhcmFtcy5zZXNzaW9uU2l6ZVxyXG5cclxuICAgIHRoaXMuaW5pdEV4ZWN1dGlvbigpO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBpbml0RXhlY3V0aW9uKClcclxuICB7XHJcbiAgICB0aGlzLmN1cnJlbnRJUCA9IDA7XHJcbiAgICB0aGlzLmlzRXhlY3V0aW5nID0gdHJ1ZTtcclxuXHJcbiAgICAvLyBUT0RPOiBTZXBhcmF0ZSBzdGFjayBhbmQgc2Vzc2lvblxyXG4gICAgdGhpcy5sb2NhbEJhc2UgPSB0aGlzLnNlc3Npb25TaXplO1xyXG4gICAgdGhpcy5keW5hbWljVG9wID0gdGhpcy5sb2NhbEJhc2U7XHJcblxyXG4gICAgdGhpcy5jb25kaXRpb25Db2RlUmVnID0gMDtcclxuICB9XHJcblxyXG4gIHNlZ3MgPSBbIFwiXCIsIFwiU0JcIiwgXCJTVFwiLCBcIkRCXCIsIFwiTEJcIiwgXCJEVFwiLCBcIlBCXCIsIFwiUFRcIiBdO1xyXG5cclxuICBwcml2YXRlIGNvbnN0Qnl0ZUJpbmFyeU9wZXJhdGlvbiggb3BDb2RlLCBjb25zdFZhbCwgYWRkclRhZywgYWRkck9mZnNldCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBhZGRyT2Zmc2V0LCAxICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgdmFyIHRlbXBWYWwgPSB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEucmVhZEJ5dGUoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0ICk7XHJcblxyXG4gICAgc3dpdGNoKCBvcENvZGUgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEFEREI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCArIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsIDwgY29uc3RWYWwgKSAgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVUJCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgLSBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA+IGNvbnN0VmFsICkgIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ01QQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsIC0gY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPiBjb25zdFZhbCApIC8vIHdyYXA/XHJcbiAgICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfQztcclxuICAgICAgICBicmVhaztcclxuXHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsU0VUQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gY29uc3RWYWw7XHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCB0ZW1wVmFsID09IDAgKVxyXG4gICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgfD0gTUVMLk1FTF9DQ1JfWjtcclxuXHJcbiAgICBpZiAoIG9wQ29kZSAhPSBNRUwuTUVMSU5TVC5tZWxDTVBCIClcclxuICAgIHtcclxuICAgICAgdGFyZ2V0QWNjZXNzLmRhdGFBcmVhLndyaXRlQnl0ZSggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIHRlbXBWYWwgKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgY29uc3RXb3JkQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIGNvbnN0VmFsLCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDIgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICB2YXIgdGVtcFZhbCA9IEJBMlcoIHRhcmdldEFjY2Vzcy5kYXRhQXJlYS5yZWFkQnl0ZXMoIHRhcmdldEFjY2Vzcy5kYXRhT2Zmc2V0LCAyICkgKTtcclxuXHJcbiAgICBzd2l0Y2goIG9wQ29kZSApXHJcbiAgICB7XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQUREQjpcclxuICAgICAgICB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJj0gfiggTUVMLk1FTF9DQ1JfQyB8IE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgICB0ZW1wVmFsID0gKCB0ZW1wVmFsICsgY29uc3RWYWwgKTtcclxuICAgICAgICBpZiAoIHRlbXBWYWwgPCBjb25zdFZhbCApICAvLyB3cmFwP1xyXG4gICAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnIHw9IE1FTC5NRUxfQ0NSX0M7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNVQkI6XHJcbiAgICAgICAgdGhpcy5jb25kaXRpb25Db2RlUmVnICY9IH4oIE1FTC5NRUxfQ0NSX0MgfCBNRUwuTUVMX0NDUl9aICk7XHJcbiAgICAgICAgdGVtcFZhbCA9ICggdGVtcFZhbCAtIGNvbnN0VmFsICk7XHJcbiAgICAgICAgaWYgKCB0ZW1wVmFsID4gY29uc3RWYWwgKSAgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTVBCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSAoIHRlbXBWYWwgLSBjb25zdFZhbCApO1xyXG4gICAgICAgIGlmICggdGVtcFZhbCA+IGNvbnN0VmFsICkgLy8gd3JhcD9cclxuICAgICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9DO1xyXG4gICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTRVRCOlxyXG4gICAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmPSB+KCBNRUwuTUVMX0NDUl9DIHwgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICAgIHRlbXBWYWwgPSBjb25zdFZhbDtcclxuICAgICAgICBicmVhaztcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIHRlbXBWYWwgPT0gMCApXHJcbiAgICAgIHRoaXMuY29uZGl0aW9uQ29kZVJlZyB8PSBNRUwuTUVMX0NDUl9aO1xyXG5cclxuICAgIGlmICggb3BDb2RlICE9IE1FTC5NRUxJTlNULm1lbENNUFcgKVxyXG4gICAge1xyXG4gICAgICB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEud3JpdGVCeXRlcyggdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIFcyQkEoIHRlbXBWYWwgKSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBiaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgb3BTaXplLCBhZGRyVGFnLCBhZGRyT2Zmc2V0IClcclxuICB7XHJcbiAgICB2YXIgdGFyZ2V0QWNjZXNzID0gdGhpcy5jaGVja0RhdGFBY2Nlc3MoIGFkZHJUYWcsIGFkZHJPZmZzZXQsIDEgKTtcclxuICAgIGlmICggdGFyZ2V0QWNjZXNzID09IHVuZGVmaW5lZCApXHJcbiAgICAgIHJldHVybjtcclxuXHJcbiAgICB0aGlzLmNoZWNrRGF0YUFjY2VzcyggLW9wU2l6ZSAtIDEsIG9wU2l6ZSwgTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApOyAvLyBGaXJzdFxyXG5cclxuICAgIC8vIHRvZG86XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHVuYXJ5T3BlcmF0aW9uKCBvcENvZGUsIG9wU2l6ZSwgYWRkclRhZywgYWRkck9mZnNldCApXHJcbiAge1xyXG4gICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMuY2hlY2tEYXRhQWNjZXNzKCBhZGRyVGFnLCBhZGRyT2Zmc2V0LCAxICk7XHJcbiAgICBpZiAoIHRhcmdldEFjY2VzcyA9PSB1bmRlZmluZWQgKVxyXG4gICAgICByZXR1cm47XHJcblxyXG4gICAgc3dpdGNoKCBvcENvZGUgKVxyXG4gICAge1xyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENMRUFSTjpcclxuICAgICAgICB0YXJnZXRBY2Nlc3MuZGF0YUFyZWEuemVyb0J5dGVzKCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgb3BTaXplICk7XHJcbiAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFRFU1ROOiAgICAgICAgIC8vIDE2XHJcbiAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsSU5DTjogICAgICAgICAgLy8gMTdcclxuICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxERUNOOiAgICAgICAgICAvLyAxOFxyXG4gICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbE5PVE46ICAgICAgICAgIC8vIDE5XHJcbiAgICAgICAgO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBoYW5kbGVSZXR1cm4oIGluQnl0ZXMsIG91dEJ5dGVzIClcclxuICB7XHJcbiAgICB2YXIgcmV0VmFsT2Zmc2V0ID0gdGhpcy5keW5hbWljVG9wIC0gb3V0Qnl0ZXM7XHJcblxyXG4gICAgdmFyIHJldHVybklQID0gQkEyVyggdGhpcy5keW5hbWljQXJlYS5yZWFkQnl0ZXMoIHRoaXMubG9jYWxCYXNlIC0gMiwgMiApICk7XHJcbiAgICB0aGlzLmxvY2FsQmFzZSA9IEJBMlcoIHRoaXMuZHluYW1pY0FyZWEucmVhZEJ5dGVzKCB0aGlzLmxvY2FsQmFzZSAtIDQsIDIgKSApO1xyXG5cclxuICAgIHRoaXMuZHluYW1pY1RvcCA9IHRoaXMubG9jYWxCYXNlICsgb3V0Qnl0ZXM7XHJcbiAgICBpZiAoIG91dEJ5dGVzIClcclxuICAgICAgdGhpcy5jb3B5T25TdGFjayggcmV0VmFsT2Zmc2V0LCB0aGlzLmxvY2FsQmFzZSwgb3V0Qnl0ZXMgKTtcclxuXHJcbiAgICByZXR1cm4gcmV0dXJuSVA7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGlzQ29uZGl0aW9uKCB0YWcgKVxyXG4gIHtcclxuICAgIHN3aXRjaCggdGFnIClcclxuICAgIHtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kRVE6XHJcbiAgICAgICAgcmV0dXJuICggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfWiApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRMVDpcclxuICAgICAgICByZXR1cm4gISggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfQyApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRMRTpcclxuICAgICAgICByZXR1cm4gKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9aICkgfHwgISggdGhpcy5jb25kaXRpb25Db2RlUmVnICYgTUVMLk1FTF9DQ1JfQyApO1xyXG4gICAgICBjYXNlIE1FTC5NRUxUQUdDT05ELm1lbENvbmRHVDpcclxuICAgICAgICByZXR1cm4gKCB0aGlzLmNvbmRpdGlvbkNvZGVSZWcgJiBNRUwuTUVMX0NDUl9DICk7XHJcbiAgICAgIGNhc2UgTUVMLk1FTFRBR0NPTkQubWVsQ29uZEdFOlxyXG4gICAgICAgIHJldHVybiAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX1ogKSB8fCAoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX0MgKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kTkU6XHJcbiAgICAgICAgcmV0dXJuICEoIHRoaXMuY29uZGl0aW9uQ29kZVJlZyAmIE1FTC5NRUxfQ0NSX1ogKTtcclxuICAgICAgY2FzZSBNRUwuTUVMVEFHQ09ORC5tZWxDb25kQUxMOlxyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICBkZWZhdWx0OiAvLyBtZWxDb25kU1BFQ1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBmYWxzZTtcclxuICB9XHJcblxyXG4gIGV4ZWN1dGVTdGVwKClcclxuICB7XHJcbiAgICB0cnlcclxuICAgIHtcclxuICAgICAgdmFyIG5leHRJUCA9IHRoaXMuY3VycmVudElQO1xyXG4gICAgICB2YXIgaW5zdEJ5dGUgPSB0aGlzLmNvZGVBcmVhLnJlYWRCeXRlKCBuZXh0SVArKyApO1xyXG4gICAgICB2YXIgcGFyYW1Db3VudCA9IDA7XHJcbiAgICAgIHZhciBwYXJhbVZhbCA9IFtdO1xyXG4gICAgICB2YXIgcGFyYW1EZWYgPSBbXTtcclxuXHJcbiAgICAgIHZhciBtZWxJbnN0ID0gTUVMLk1FTERlY29kZVsgaW5zdEJ5dGUgXTtcclxuXHJcbiAgICAgIGlmICggbWVsSW5zdCA9PSB1bmRlZmluZWQgKVxyXG4gICAgICB7XHJcbiAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgIH1cclxuICAgICAgZWxzZVxyXG4gICAgICB7XHJcbiAgICAgICAgdmFyIHBhcmFtRGVmcyA9IG1lbEluc3QucGFyYW1EZWZzO1xyXG5cclxuICAgICAgICB3aGlsZSggcGFyYW1EZWZzICE9IDAgKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHBhcmFtRGVmWyBwYXJhbUNvdW50IF0gPSBwYXJhbURlZnMgJiAweEZGO1xyXG4gICAgICAgICAgc3dpdGNoKCBwYXJhbURlZnMgJiAweEYwIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSAweDAwOiBicmVhaztcclxuICAgICAgICAgICAgY2FzZSAweDEwOiBwYXJhbVZhbFsgcGFyYW1Db3VudCBdID0gdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKTsgYnJlYWs7XHJcbiAgICAgICAgICAgIGNhc2UgMHgyMDogcGFyYW1WYWxbIHBhcmFtQ291bnQgXSA9IEJBMlcoIFsgdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKSwgdGhpcy5jb2RlQXJlYS5yZWFkQnl0ZSggbmV4dElQKysgKSBdICk7IGJyZWFrO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgcGFyYW1Db3VudCsrO1xyXG4gICAgICAgICAgcGFyYW1EZWZzID4+PSA4O1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgdmFyIG9wQ29kZSA9IE1FTC5NRUwyT1BDT0RFKCBpbnN0Qnl0ZSApO1xyXG4gICAgICB2YXIgdGFnID0gTUVMLk1FTDJUQUcoIGluc3RCeXRlICk7XHJcblxyXG4gICAgICBzd2l0Y2goIG9wQ29kZSApXHJcbiAgICAgIHtcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNZU1RFTTogICAgICAgIC8vIDAwXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIHB1YmxpY1RvcCA9IHRoaXMucHVibGljQXJlYS5nZXRMZW5ndGgoKTtcclxuXHJcbiAgICAgICAgICBzd2l0Y2goIHRhZyApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtRXhpdDpcclxuICAgICAgICAgICAgICB0aGlzLmlzRXhlY3V0aW5nID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgLy9ubyBicmVha1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbU5PUDpcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtRXhpdFNXOlxyXG4gICAgICAgICAgICAgIHRoaXMuaXNFeGVjdXRpbmcgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAvL25vIGJyZWFrXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtU2V0U1c6XHJcbiAgICAgICAgICAgICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDIsIFcyQkEoIHBhcmFtVmFsWyAwIF0gKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1FeGl0TGE6XHJcbiAgICAgICAgICAgICAgdGhpcy5pc0V4ZWN1dGluZyA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgIC8vbm8gYnJlYWtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1lTVEVNLiBtZWxTeXN0ZW1TZXRMYTpcclxuICAgICAgICAgICAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gNCwgVzJCQSggcGFyYW1WYWxbIDAgXSApICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTWVNURU0uIG1lbFN5c3RlbUV4aXRTV0xhOlxyXG4gICAgICAgICAgICAgIHRoaXMuaXNFeGVjdXRpbmcgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAvL25vIGJyZWFrXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NZU1RFTS4gbWVsU3lzdGVtU2V0U1dMYTpcclxuICAgICAgICAgICAgICB0aGlzLnB1YmxpY0FyZWEud3JpdGVCeXRlcyggcHVibGljVG9wIC0gMiwgVzJCQSggcGFyYW1WYWxbIDAgXSApICk7XHJcbiAgICAgICAgICAgICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDQsIFcyQkEoIHBhcmFtVmFsWyAxIF0gKSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEJSQU5DSDogICAgICAgIC8vIDAxXHJcbiAgICAgICAgICBpZiAoIHRoaXMuaXNDb25kaXRpb24oIHRhZyApIClcclxuICAgICAgICAgICAgbmV4dElQID0gbmV4dElQICsgcGFyYW1WYWxbIDAgXTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEpVTVA6ICAgICAgICAgIC8vIDAyXHJcbiAgICAgICAgICBpZiAoIHRoaXMuaXNDb25kaXRpb24oIHRhZyApIClcclxuICAgICAgICAgICAgbmV4dElQID0gcGFyYW1WYWxbIDAgXTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbENBTEw6ICAgICAgICAgIC8vIDAzXHJcbiAgICAgICAgICBpZiAoIHRoaXMuaXNDb25kaXRpb24oIHRhZyApIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgdGhpcy5wdXNoQ29uc3RUb1N0YWNrKCAyLCB0aGlzLmxvY2FsQmFzZSApO1xyXG4gICAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDIsIG5leHRJUCApO1xyXG5cclxuICAgICAgICAgICAgbmV4dElQID0gcGFyYW1WYWxbIDAgXTtcclxuICAgICAgICAgICAgdGhpcy5sb2NhbEJhc2UgPSB0aGlzLmR5bmFtaWNUb3A7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVEFDSzogICAgICAgICAvLyAwNFxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHN3aXRjaCggdGFnIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQVVNIWjpcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgIHRoaXMucHVzaFplcm9zVG9TdGFjayggcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUFVTSEI6XHJcbiAgICAgICAgICAgICAgdGhpcy5wdXNoQ29uc3RUb1N0YWNrKCAxLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BVU0hXOlxyXG4gICAgICAgICAgICAgIHRoaXMucHVzaENvbnN0VG9TdGFjayggMiwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHU1RBQ0subWVsU3RhY2tQT1BOOlxyXG4gICAgICAgICAgICAgIHRoaXMucG9wRnJvbVN0YWNrKCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdTVEFDSy5tZWxTdGFja1BPUEI6XHJcbiAgICAgICAgICAgICAgdGhpcy5wb3BGcm9tU3RhY2soIDEgKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1NUQUNLLm1lbFN0YWNrUE9QVzpcclxuICAgICAgICAgICAgICB0aGlzLnBvcEZyb21TdGFjayggMiApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFBSSU1SRVQ6ICAgICAgIC8vIDA1XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgc3dpdGNoKCB0YWcgKVxyXG4gICAgICAgICAge1xyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMDpcclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UFJJTTE6XHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFBSSU0yOlxyXG4gICAgICAgICAgICBjYXNlIE1FTC5NRUxUQUdQUklNUkVULm1lbFByaW1SZXRQUklNMzpcclxuICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgIGNhc2UgTUVMLk1FTFRBR1BSSU1SRVQubWVsUHJpbVJldFJFVDpcclxuICAgICAgICAgICAgICBuZXh0SVAgPSB0aGlzLmhhbmRsZVJldHVybiggMCwgMCApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUSTpcclxuICAgICAgICAgICAgICBuZXh0SVAgPSB0aGlzLmhhbmRsZVJldHVybiggcGFyYW1WYWxbIDAgXSwgMCApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUTzpcclxuICAgICAgICAgICAgICBuZXh0SVAgPSB0aGlzLmhhbmRsZVJldHVybiggMCwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgY2FzZSBNRUwuTUVMVEFHUFJJTVJFVC5tZWxQcmltUmV0UkVUSU86XHJcbiAgICAgICAgICAgICAgbmV4dElQID0gdGhpcy5oYW5kbGVSZXR1cm4oIHBhcmFtVmFsWyAwIF0sIHBhcmFtVmFsWyAxIF0gKTtcclxuICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxMT0FEOiAgICAgICAgICAvLyAwN1xyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIC8vIERVUCBUT1NcclxuICAgICAgICAgICAgdGhpcy5jb3B5T25TdGFjayggdGhpcy5keW5hbWljVG9wIC0gcGFyYW1WYWxbIDAgXSwgdGhpcy5keW5hbWljVG9wLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICAgIHRoaXMuZHluYW1pY1RvcCArPSBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICB0aGlzLnB1c2hUb1N0YWNrKCB0YWcsIHBhcmFtVmFsWyAxIF0sIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbFNUT1JFOiAgICAgICAgIC8vIDA4XHJcbiAgICAgICAgICBpZiAoIHRhZyA9PSBNRUwuTUVMVEFHQUREUi5tZWxBZGRyVE9TIClcclxuICAgICAgICAgIHtcclxuICAgICAgICAgICAgLy8gU0hJRlQgVE9TXHJcbiAgICAgICAgICAgIHRoaXMuZHluYW1pY1RvcCAtPSBwYXJhbVZhbFsgMCBdO1xyXG4gICAgICAgICAgICB0aGlzLmNvcHlPblN0YWNrKCB0aGlzLmR5bmFtaWNUb3AsIHRoaXMuZHluYW1pY1RvcCAtIHBhcmFtVmFsWyAwIF0sIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5wb3BGcm9tU3RhY2tBbmRTdG9yZSggdGFnLCBwYXJhbVZhbFsgMSBdLCBwYXJhbVZhbFsgMCBdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTE9BREk6ICAgICAgICAgLy8gMDlcclxuICAgICAgICB7XHJcbiAgICAgICAgICB2YXIgc2VnbWVudEFkZHIgPSBCQTJXKCB0aGlzLnJlYWRTZWdtZW50RGF0YSggdGFnLCBwYXJhbVZhbFsgMSBdLCAyICkgKTtcclxuICAgICAgICAgIHZhciB0YXJnZXRBY2Nlc3MgPSB0aGlzLm1hcEZyb21TZWdtZW50QWRkciggc2VnbWVudEFkZHIgKTtcclxuICAgICAgICAgIHRoaXMucHVzaFRvU3RhY2soIHRhcmdldEFjY2Vzcy5kYXRhQWRkclRhZywgdGFyZ2V0QWNjZXNzLmRhdGFPZmZzZXQsIHBhcmFtVmFsWyAwIF0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVE9SRUk6ICAgICAgICAvLyAwQVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciBzZWdtZW50QWRkciA9IEJBMlcoIHRoaXMucmVhZFNlZ21lbnREYXRhKCB0YWcsIHBhcmFtVmFsWyAxIF0sIDIgKSApO1xyXG4gICAgICAgICAgdmFyIHRhcmdldEFjY2VzcyA9IHRoaXMubWFwRnJvbVNlZ21lbnRBZGRyKCBzZWdtZW50QWRkciApO1xyXG4gICAgICAgICAgdGhpcy5wb3BGcm9tU3RhY2tBbmRTdG9yZSggdGFyZ2V0QWNjZXNzLmRhdGFBZGRyVGFnLCB0YXJnZXRBY2Nlc3MuZGF0YU9mZnNldCwgcGFyYW1WYWxbIDAgXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbExPQURBOiAgICAgICAgIC8vIDBCXHJcbiAgICAgICAgICB0aGlzLnB1c2hDb25zdFRvU3RhY2soIDIsIHRoaXMubWFwVG9TZWdtZW50QWRkciggdGFnLCBwYXJhbVZhbFsgMCBdICkgKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbElOREVYOiAgICAgICAgIC8vIDBDXHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTRVRCOiAgICAgICAgICAvLyAwRFxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ01QQjogICAgICAgICAgLy8gMEVcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEFEREI6ICAgICAgICAgIC8vIDBGXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVUJCOiAgICAgICAgICAvLyAxMFxyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICAgIHRoaXMuY29uc3RCeXRlQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQsIC0xICk7XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMuY29uc3RCeXRlQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCB0YWcsIHBhcmFtVmFsWzFdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTRVRXOiAgICAgICAgICAvLyAxMVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ01QVzogICAgICAgICAgLy8gMTJcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEFERFc6ICAgICAgICAgIC8vIDEzXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVUJXOiAgICAgICAgICAvLyAxNFxyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICAgIHRoaXMuY29uc3RXb3JkQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQsIC0yICk7XHJcbiAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHRoaXMuY29uc3RXb3JkQmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCB0YWcsIHBhcmFtVmFsWzFdICk7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxDTEVBUk46ICAgICAgICAvLyAxNVxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsVEVTVE46ICAgICAgICAgLy8gMTZcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbElOQ046ICAgICAgICAgIC8vIDE3XHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxERUNOOiAgICAgICAgICAvLyAxOFxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsTk9UTjogICAgICAgICAgLy8gMTlcclxuICAgICAgICAgIGlmICggdGFnID09IE1FTC5NRUxUQUdBRERSLm1lbEFkZHJUT1MgKVxyXG4gICAgICAgICAgICB0aGlzLnVuYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQsIC0xICogcGFyYW1WYWxbMF0gKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy51bmFyeU9wZXJhdGlvbiggb3BDb2RlLCBwYXJhbVZhbFswXSwgdGFnLCBwYXJhbVZhbFsxXSApO1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQ01QTjogICAgICAgICAgLy8gMUFcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbEFERE46ICAgICAgICAgIC8vIDFCXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxTVUJOOiAgICAgICAgICAvLyAxQ1xyXG4gICAgICAgIGNhc2UgTUVMLk1FTElOU1QubWVsQU5ETjogICAgICAgICAgLy8gMURcclxuICAgICAgICBjYXNlIE1FTC5NRUxJTlNULm1lbE9STjogICAgICAgICAgIC8vIDFFXHJcbiAgICAgICAgY2FzZSBNRUwuTUVMSU5TVC5tZWxYT1JOOiAgICAgICAgICAvLyAxRlxyXG4gICAgICAgICAgaWYgKCB0YWcgPT0gTUVMLk1FTFRBR0FERFIubWVsQWRkclRPUyApXHJcbiAgICAgICAgICAgIHRoaXMuYmluYXJ5T3BlcmF0aW9uKCBvcENvZGUsIHBhcmFtVmFsWzBdLCBNRUwuTUVMVEFHQUREUi5tZWxBZGRyRFQsIC0yICogcGFyYW1WYWxbMF0gKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgdGhpcy5iaW5hcnlPcGVyYXRpb24oIG9wQ29kZSwgcGFyYW1WYWxbMF0sIHRhZywgcGFyYW1WYWxbMV0gKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmN1cnJlbnRJUCA9IG5leHRJUDtcclxuICAgIH1cclxuICAgIGNhdGNoKCBlIClcclxuICAgIHtcclxuICAgICAgLy9wcmludCggZSApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgc2V0Q29tbWFuZEFQRFUoIGNvbW1hbmRBUERVOiBDb21tYW5kQVBEVSApXHJcbiAge1xyXG4gICAgdmFyIHB1YmxpY1RvcCA9IHRoaXMucHVibGljQXJlYS5nZXRMZW5ndGgoKTtcclxuXHJcbiAgICAvLyAtMiwtMSA9IFNXMTJcclxuICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSAyLCBXMkJBKCAweDkwMDAgKSApO1xyXG5cclxuICAgIC8vIC00LC0zID0gTGFcclxuICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSA0LCBXMkJBKCAweDAwMDAgKSApO1xyXG5cclxuICAgIC8vIC02LC01ID0gTGVcclxuICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSA2LCBXMkJBKCBjb21tYW5kQVBEVS5MZSApICk7XHJcblxyXG4gICAgLy8gLTgsLTcgPSBMY1xyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIHB1YmxpY1RvcCAtIDgsIFcyQkEoIGNvbW1hbmRBUERVLmRhdGEubGVuZ3RoICkgKTtcclxuICAgIHRoaXMucHVibGljQXJlYS53cml0ZUJ5dGVzKCBwdWJsaWNUb3AgLSAxMywgY29tbWFuZEFQRFUuaGVhZGVyICk7XHJcblxyXG4gICAgdGhpcy5wdWJsaWNBcmVhLndyaXRlQnl0ZXMoIDAsIGNvbW1hbmRBUERVLmRhdGEgKTtcclxuXHJcbiAgICB0aGlzLmluaXRFeGVjdXRpb24oKTtcclxuICB9XHJcblxyXG4gIGdldFJlc3BvbnNlQVBEVSgpOiBSZXNwb25zZUFQRFVcclxuICB7XHJcbiAgICB2YXIgcHVibGljVG9wID0gdGhpcy5wdWJsaWNBcmVhLmdldExlbmd0aCgpO1xyXG5cclxuICAgIHZhciBsYSA9IEJBMlcoIHRoaXMucHVibGljQXJlYS5yZWFkQnl0ZXMoIHB1YmxpY1RvcCAtIDQsIDIgKSApO1xyXG5cclxuICAgIHJldHVybiBuZXcgUmVzcG9uc2VBUERVKCB7IHN3OiBCQTJXKCB0aGlzLnB1YmxpY0FyZWEucmVhZEJ5dGVzKCBwdWJsaWNUb3AgLSAyLCAyICkgKSwgZGF0YTogdGhpcy5wdWJsaWNBcmVhLnJlYWRCeXRlcyggMCwgbGEgKSAgfSApXHJcblxyXG4gIH1cclxuXHJcbiAgZ2V0IGdldERlYnVnKCk6IHt9XHJcbiAge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgcmFtU2VnbWVudDogdGhpcy5yYW1TZWdtZW50LFxyXG4gICAgICBkeW5hbWljQXJlYTogdGhpcy5keW5hbWljQXJlYSxcclxuICAgICAgcHVibGljQXJlYTogdGhpcy5wdWJsaWNBcmVhLFxyXG4gICAgICBzdGF0aWNBcmVhOiB0aGlzLnN0YXRpY0FyZWEsXHJcbiAgICAgIGN1cnJlbnRJUDogdGhpcy5jdXJyZW50SVAsXHJcbiAgICAgIGR5bmFtaWNUb3A6IHRoaXMuZHluYW1pY1RvcCxcclxuICAgICAgbG9jYWxCYXNlOiB0aGlzLmxvY2FsQmFzZVxyXG4gICAgfTtcclxuICB9XHJcbi8vICBpc0V4ZWN1dGluZzogZnVuY3Rpb24oKSB7IHJldHVybiBpc0V4ZWN1dGluZzsgfSxcclxufVxyXG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICdjcnlwdG9ncmFwaGl4LXNpbS1jb3JlJztcclxuaW1wb3J0IHsgTWVtb3J5TWFuYWdlciwgTUVNRkxBR1MgfSBmcm9tICcuL21lbW9yeS1tYW5hZ2VyJztcclxuaW1wb3J0IHsgTUVMVmlydHVhbE1hY2hpbmUgfSBmcm9tICcuL3ZpcnR1YWwtbWFjaGluZSc7XHJcblxyXG5pbXBvcnQgeyBJU083ODE2IH0gZnJvbSAnLi4vYmFzZS9JU083ODE2JztcclxuaW1wb3J0IHsgQ29tbWFuZEFQRFUgfSBmcm9tICcuLi9iYXNlL2NvbW1hbmQtYXBkdSc7XHJcbmltcG9ydCB7IFJlc3BvbnNlQVBEVSB9IGZyb20gJy4uL2Jhc2UvcmVzcG9uc2UtYXBkdSc7XHJcblxyXG5pbXBvcnQgeyBKU0lNQ2FyZCB9IGZyb20gJy4uL2pzaW0tY2FyZC9qc2ltLWNhcmQnO1xyXG5cclxuZnVuY3Rpb24gIEJBMlcoIHZhbCApXHJcbntcclxuICByZXR1cm4gKCB2YWxbIDAgXSA8PCA4ICkgfCB2YWxbIDEgXTtcclxufVxyXG5cclxuZXhwb3J0IGNsYXNzIEpTSU1NdWx0b3NBcHBsZXRcclxue1xyXG4gIHNlc3Npb25TaXplO1xyXG4gIGNvZGVBcmVhO1xyXG4gIHN0YXRpY0FyZWE7XHJcblxyXG4gIGNvbnN0cnVjdG9yKCBjb2RlQXJlYSwgc3RhdGljQXJlYSwgc2Vzc2lvblNpemUgKVxyXG4gIHtcclxuICAgIHRoaXMuY29kZUFyZWEgPSBjb2RlQXJlYTtcclxuICAgIHRoaXMuc3RhdGljQXJlYSA9IHN0YXRpY0FyZWE7XHJcbiAgICB0aGlzLnNlc3Npb25TaXplID0gc2Vzc2lvblNpemU7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgY2xhc3MgSlNJTU11bHRvc0NhcmQgaW1wbGVtZW50cyBKU0lNQ2FyZFxyXG57XHJcbiAgcHJpdmF0ZSBjYXJkQ29uZmlnO1xyXG5cclxuICBzdGF0aWMgZGVmYXVsdENvbmZpZyA9IHtcclxuICAgIHJvbVNpemU6IDAsXHJcbiAgICByYW1TaXplOiAxMDI0LFxyXG4gICAgcHVibGljU2l6ZTogNTEyLFxyXG4gICAgbnZyYW1TaXplOiAzMjc2OFxyXG4gIH07XHJcblxyXG4gIHByaXZhdGUgcG93ZXJJc09uOiBib29sZWFuO1xyXG4gIHByaXZhdGUgYXRyOiBCeXRlQXJyYXk7XHJcblxyXG4gIGFwcGxldHM6IHsgYWlkOiBCeXRlQXJyYXksIGFwcGxldDogSlNJTU11bHRvc0FwcGxldCB9W107XHJcblxyXG4gIHNlbGVjdGVkQXBwbGV0OiBKU0lNTXVsdG9zQXBwbGV0O1xyXG5cclxuICBjb25zdHJ1Y3RvciggY29uZmlnPyApXHJcbiAge1xyXG4gICAgaWYgKCBjb25maWcgKVxyXG4gICAgICB0aGlzLmNhcmRDb25maWcgPSBjb25maWc7XHJcbiAgICBlbHNlXHJcbiAgICAgIHRoaXMuY2FyZENvbmZpZyA9IEpTSU1NdWx0b3NDYXJkLmRlZmF1bHRDb25maWc7XHJcblxyXG4gICAgdGhpcy5hdHIgPSBuZXcgQnl0ZUFycmF5KCBbXSApO1xyXG5cclxuICAgIHRoaXMuYXBwbGV0cyA9IFtdO1xyXG4gIH1cclxuXHJcbiAgbG9hZEFwcGxpY2F0aW9uKCBhaWQ6IEJ5dGVBcnJheSwgYWx1OiBCeXRlQXJyYXkgKVxyXG4gIHtcclxuICAgIHZhciBsZW4gPSAwO1xyXG5cclxuICAgIHZhciBvZmYgPSA4O1xyXG5cclxuICAgIC8vIExFTjo6Q09ERVxyXG4gICAgbGVuID0gYWx1LndvcmRBdCggb2ZmICk7XHJcbiAgICBvZmYgKz0gMjtcclxuXHJcbiAgICBsZXQgY29kZUFyZWEgPSB0aGlzLm52cmFtU2VnbWVudC5uZXdBY2Nlc3NvciggMCwgbGVuLCBcImNvZGVcIiApO1xyXG4gICAgY29kZUFyZWEud3JpdGVCeXRlcyggMCwgYWx1LnZpZXdBdCggb2ZmLCBsZW4gKSApO1xyXG4gICAgb2ZmICs9IGxlbjtcclxuXHJcbiAgICAvLyBMRU46OkRBVEFcclxuICAgIGxlbiA9IGFsdS53b3JkQXQoIG9mZiApO1xyXG4gICAgb2ZmICs9IDI7XHJcblxyXG4gICAgbGV0IHN0YXRpY0FyZWEgPSB0aGlzLm52cmFtU2VnbWVudC5uZXdBY2Nlc3NvciggY29kZUFyZWEuZ2V0TGVuZ3RoKCksIGxlbiwgXCJTXCIgKTtcclxuICAgIHN0YXRpY0FyZWEud3JpdGVCeXRlcyggMCwgYWx1LnZpZXdBdCggb2ZmLCBsZW4gKSApO1xyXG4gICAgb2ZmICs9IGxlbjtcclxuXHJcbiAgICBsZXQgYXBwbGV0ID0gbmV3IEpTSU1NdWx0b3NBcHBsZXQoIGNvZGVBcmVhLCBzdGF0aWNBcmVhLCAwICk7XHJcblxyXG4gICAgdGhpcy5hcHBsZXRzLnB1c2goIHsgYWlkOiBhaWQsIGFwcGxldDogYXBwbGV0IH0gKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBnZXQgaXNQb3dlcmVkKCk6IGJvb2xlYW5cclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5wb3dlcklzT247XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcG93ZXJPbigpOiBQcm9taXNlPEJ5dGVBcnJheT5cclxuICB7XHJcbiAgICB0aGlzLnBvd2VySXNPbiA9IHRydWU7XHJcblxyXG4gICAgdGhpcy5pbml0aWFsaXplVk0oIHRoaXMuY2FyZENvbmZpZyApO1xyXG5cclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoIHRoaXMuYXRyICk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcG93ZXJPZmYoKTogUHJvbWlzZTxhbnk+XHJcbiAge1xyXG4gICAgdGhpcy5wb3dlcklzT24gPSBmYWxzZTtcclxuXHJcbiAgICB0aGlzLnJlc2V0Vk0oKTtcclxuXHJcbiAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xyXG5cclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoICApO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHJlc2V0KCk6IFByb21pc2U8Qnl0ZUFycmF5PlxyXG4gIHtcclxuICAgIHRoaXMucG93ZXJJc09uID0gdHJ1ZTtcclxuXHJcbiAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xyXG5cclxuICAgIHRoaXMuc2h1dGRvd25WTSgpO1xyXG5cclxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoIHRoaXMuYXRyICk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgZXhjaGFuZ2VBUERVKCBjb21tYW5kQVBEVTogQ29tbWFuZEFQRFUgKTogUHJvbWlzZTxSZXNwb25zZUFQRFU+XHJcbiAge1xyXG4gICAgaWYgKCBjb21tYW5kQVBEVS5JTlMgPT0gMHhBNCApXHJcbiAgICB7XHJcbiAgICAgIGlmICggdGhpcy5zZWxlY3RlZEFwcGxldCApXHJcbiAgICAgIHtcclxuICAgICAgICAvL3RoaXMuc2VsZWN0ZWRBcHBsZXQuZGVzZWxlY3RBcHBsaWNhdGlvbigpO1xyXG5cclxuICAgICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdW5kZWZpbmVkO1xyXG4gICAgICB9XHJcblxyXG4gICAgICAvL1RPRE86IExvb2t1cCBBcHBsaWNhdGlvblxyXG4gICAgICB0aGlzLnNlbGVjdGVkQXBwbGV0ID0gdGhpcy5hcHBsZXRzWyAwIF0uYXBwbGV0O1xyXG5cclxuICAgICAgbGV0IGZjaSA9IG5ldyBCeXRlQXJyYXkoIFsgMHg2RiwgMHgwMCBdICk7XHJcblxyXG4gICAgICB0aGlzLm12bS5zZXR1cEFwcGxpY2F0aW9uKCB0aGlzLnNlbGVjdGVkQXBwbGV0ICk7XHJcblxyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlPFJlc3BvbnNlQVBEVT4oIG5ldyBSZXNwb25zZUFQRFUoIHsgc3c6IDB4OTAwMCwgZGF0YTogZmNpICB9ICkgKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLm12bS5zZXRDb21tYW5kQVBEVSggY29tbWFuZEFQRFUpO1xyXG5cclxuLy8gICAgZ2V0UmVzcG9uc2VBUERVKClcclxuLy8gICAge1xyXG4vLyAgICAgIHJldHVybiB0aGlzLm12bS5nZXRSZXNwb25zZUFQRFUoKTtcclxuLy8gICAgfVxyXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZTxSZXNwb25zZUFQRFU+KCBuZXcgUmVzcG9uc2VBUERVKCB7IHN3OiAweDkwMDAsIGRhdGE6IFtdICB9ICkgKTtcclxuXHJcbiAgICAvL3JldHVybiB0aGlzLmV4ZWN1dGVBUERVKCBjb21tYW5kQVBEVSApO1xyXG4gIH1cclxuXHJcbiAgbWVtb3J5TWFuYWdlcjogTWVtb3J5TWFuYWdlcjtcclxuXHJcbiAgLy8gQ2FyZCBNZW1vcnkgU2VnbWVudHNcclxuICByb21TZWdtZW50OyAgICAgIC8vIFJPTTogY29kZWxldHNcclxuICBudnJhbVNlZ21lbnQ7ICAgIC8vIE5WUkFNOiBhcHBsZXRzIGNvZGUgKyBkYXRhXHJcbiAgcmFtU2VnbWVudDsgICAgICAvLyBSQU06IHdvcmtzcGFjZVxyXG5cclxuICBtdm07XHJcblxyXG4gIGluaXRpYWxpemVWTSggY29uZmlnIClcclxuICB7XHJcbiAgICB0aGlzLm1lbW9yeU1hbmFnZXIgPSBuZXcgTWVtb3J5TWFuYWdlcigpO1xyXG5cclxuICAgIHRoaXMucm9tU2VnbWVudCA9IHRoaXMubWVtb3J5TWFuYWdlci5uZXdTZWdtZW50KCAwLCB0aGlzLmNhcmRDb25maWcucm9tU2l6ZSwgTUVNRkxBR1MuUkVBRF9PTkxZIClcclxuICAgIHRoaXMucmFtU2VnbWVudCA9IHRoaXMubWVtb3J5TWFuYWdlci5uZXdTZWdtZW50KCAxLCB0aGlzLmNhcmRDb25maWcucmFtU2l6ZSwgMCApO1xyXG4gICAgdGhpcy5udnJhbVNlZ21lbnQgPSB0aGlzLm1lbW9yeU1hbmFnZXIubmV3U2VnbWVudCggMiwgdGhpcy5jYXJkQ29uZmlnLm52cmFtU2l6ZSwgTUVNRkxBR1MuVFJBTlNBQ1RJT05BQkxFICk7XHJcblxyXG4gICAgdGhpcy5tdm0gPSBuZXcgTUVMVmlydHVhbE1hY2hpbmUoKTtcclxuXHJcbiAgICB0aGlzLnJlc2V0Vk0oKTtcclxuICB9XHJcblxyXG4gIHJlc2V0Vk0oKVxyXG4gIHtcclxuICAgIC8vIGZpcnN0IHRpbWUgLi4uXHJcbiAgICAvLyBpbml0IFZpcnR1YWxNYWNoaW5lXHJcbiAgICB2YXIgbXZtUGFyYW1zID0ge1xyXG4gICAgICByYW1TZWdtZW50OiB0aGlzLnJhbVNlZ21lbnQsXHJcbiAgICAgIHJvbVNlZ21lbnQ6IHRoaXMucm9tU2VnbWVudCxcclxuICAgICAgcHVibGljU2l6ZTogdGhpcy5jYXJkQ29uZmlnLnB1YmxpY1NpemVcclxuICAgIH07XHJcblxyXG4gICAgdGhpcy5tdm0uaW5pdE1WTSggbXZtUGFyYW1zICk7XHJcbiAgfVxyXG5cclxuICBzaHV0ZG93blZNKClcclxuICB7XHJcbiAgICB0aGlzLnJlc2V0Vk0oKTtcclxuICAgIHRoaXMubXZtID0gbnVsbDtcclxuICB9XHJcblxyXG4gIHNlbGVjdEFwcGxpY2F0aW9uKCBhcHBsZXQ6IEpTSU1NdWx0b3NBcHBsZXQsIHNlc3Npb25TaXplIClcclxuICB7XHJcbiAgICB2YXIgZXhlY1BhcmFtcyA9IHtcclxuICAgICAgY29kZUFyZWE6IGFwcGxldC5jb2RlQXJlYSxcclxuICAgICAgc3RhdGljQXJlYTogYXBwbGV0LnN0YXRpY0FyZWEsXHJcbiAgICAgIHNlc3Npb25TaXplOiBzZXNzaW9uU2l6ZVxyXG4gICAgfTtcclxuXHJcbiAgICB0aGlzLm12bS5leGVjQXBwbGljYXRpb24oIGV4ZWNQYXJhbXMgKTtcclxuICB9XHJcblxyXG4gIGV4ZWN1dGVTdGVwKClcclxuICB7XHJcbiAgICByZXR1cm4gdGhpcy5tdm0uZXhlY3V0ZVN0ZXAoKTtcclxuICB9XHJcbn1cclxuIiwidmFyIHNldFplcm9QcmltaXRpdmVzID1cclxue1xyXG4gIDB4MDE6IHtcclxuICAgIG5hbWU6IFwiQ0hFQ0tfQ0FTRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgXHQgIHZhciBleHBlY3RlZElTTz0gcG9wQnl0ZSgpO1xyXG5cclxuICBcdCAgaWYgKGV4cGVjdGVkSVNPPCAxIHx8IGV4cGVjdGVkSVNPPiA0KVxyXG4gIFx0ICAgIFNldENDUkZsYWcoWmZsYWcsIGZhbHNlKTtcclxuICBcdCAgZWxzZVxyXG4gIFx0ICAgIFNldENDUkZsYWcoWmZsYWcsIENoZWNrSVNPQ2FzZShleHBlY3RlZElTT0Nhc2UpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMjoge1xyXG4gICAgbmFtZTogXCJSRVNFVF9XV1RcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBzZW5kV2FpdFJlcXVlc3QoKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwNToge1xyXG4gICAgbmFtZTogXCJMT0FEX0NDUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHB1c2hCeXRlKENDUigpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwNjoge1xyXG4gICAgbmFtZTogXCJTVE9SRV9DQ1JcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBDQ1IoKSA9IHBvcEJ5dGUoKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwNzoge1xyXG4gICAgbmFtZTogXCJTRVRfQVRSX0ZJTEVfUkVDT1JEXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIHZhciBsZW4gPSBnZXRCeXRlKGFkZHIpO1xyXG5cclxuICAgICAgTUVMQXBwbGljYXRpb24gKmEgPSBzdGF0ZS5hcHBsaWNhdGlvbjtcclxuICAgICAgaWYgKGEuQVRSRmlsZVJlY29yZFNpemUpXHJcbiAgICAgICAgZGVsZXRlIFtdYS5BVFJGaWxlUmVjb3JkO1xyXG5cclxuICAgICAgYS5BVFJGaWxlUmVjb3JkU2l6ZSA9IGxlbjtcclxuXHJcbiAgICAgIGlmIChsZW4pXHJcbiAgICAgIHtcclxuICAgICAgICBhLkFUUkZpbGVSZWNvcmQgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgICAgcmVhZChhZGRyLCBsZW4sIGEuQVRSRmlsZVJlY29yZCk7XHJcbiAgICAgIH1cclxuICAgICAgRFQoLTIpO1xyXG4gICAgICBwdXNoQnl0ZShsZW4pO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA4OiB7XHJcbiAgICBuYW1lOiBcIlNFVF9BVFJfSElTVE9SSUNBTF9DSEFSQUNURVJTXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgIHZhciBsZW4gPSBnZXRCeXRlKGFkZHIpO1xyXG4gICAgICB2YXIgd3JpdHRlbjtcclxuICAgICAgdmFyIG9rYXkgPSBzZXRBVFJIaXN0b3JpY2FsQ2hhcmFjdGVycyhsZW4sIGFkZHIrMSwgd3JpdHRlbik7XHJcblxyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIHB1c2hCeXRlKHdyaXR0ZW4pO1xyXG4gICAgICBTZXRDQ1JGbGFnKENmbGFnLCB3cml0dGVuIDwgbGVuKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgIW9rYXkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA5OiB7XHJcbiAgICBuYW1lOiBcIkdFVF9NRU1PUllfUkVMSUFCSUxJVFlcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBTZXRDQ1JGbGFnKENmbGFnLCBmYWxzZSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGZhbHNlKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhhOiB7XHJcbiAgICBuYW1lOiBcIkxPT0tVUFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciB2YWx1ZSA9IGdldEJ5dGUoZHluYW1pY1RvcC0zKTtcclxuICAgICAgdmFyIGFyckFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGZhbHNlKTtcclxuXHJcbiAgICAgIHZhciBhcnJsZW4gPSBnZXRCeXRlKGFyckFkZHIpO1xyXG4gICAgICBmb3IgKHZhciBpPTA7aTxhcnJsZW47aSsrKVxyXG4gICAgICAgIGlmIChnZXRCeXRlKGFyckFkZHIraSsxKSA9PSB2YWx1ZSlcclxuICAgICAgICB7XHJcbiAgICAgICAgICBzZXRCeXRlKGR5bmFtaWNUb3AtMSwgKHZhcilpKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoWmZsYWcsIHRydWUpO1xyXG4gICAgICAgICAgaSA9IGFycmxlbjtcclxuICAgICAgICB9XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Yjoge1xyXG4gICAgbmFtZTogXCJNRU1PUllfQ09NUEFSRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgIHZhciBvcDEgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBvcDIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBibG9ja0NvbXBhcmUob3AxLCBvcDIsIGxlbik7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjOiB7XHJcbiAgICBuYW1lOiBcIk1FTU9SWV9DT1BZXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIG51bSA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgdmFyIGRzdCA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgdmFyIHNyYyA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIGNvcHkoZHN0LCBzcmMsIG51bSk7XHJcbiAgICAgIERUKC02KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhkOiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZX0lOVEVSRkFDRV9UWVBFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgZmFsc2UpOyAvLyBjb250YWN0XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MTA6IHtcclxuICAgIG5hbWU6IFwiQ09OVFJPTF9BVVRPX1JFU0VUX1dXVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIC8vIERvZXNuJ3QgZG8gYW55dGhpbmdcclxuICAgICAgRFQoLTIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDExOiB7XHJcbiAgICBuYW1lOiBcIlNFVF9GQ0lfRklMRV9SRUNPUkRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIGxlbiA9IGdldEJ5dGUoYWRkcik7XHJcblxyXG4gICAgICBNRUxBcHBsaWNhdGlvbiAqYSA9IHN0YXRlLmFwcGxpY2F0aW9uO1xyXG5cclxuICAgICAgaWYgKGEuRkNJUmVjb3JkU2l6ZSlcclxuICAgICAgICBkZWxldGUgW11hLkZDSVJlY29yZDtcclxuXHJcbiAgICAgIGEuRkNJUmVjb3JkU2l6ZSA9IGxlbjtcclxuICAgICAgYS5GQ0lSZWNvcmQgPSBuZXcgdmFyW2xlbl07XHJcbiAgICAgIHJlYWQoYWRkciArIDEsIGxlbiwgYS5GQ0lSZWNvcmQpO1xyXG4gICAgICBEVCgtMik7XHJcbiAgICAgIHB1c2hCeXRlKGxlbik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODA6IHtcclxuICAgIG5hbWU6IFwiREVMRUdBVEVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICAvLyByb2xsYmFjayBhbmQgdHVybiBvZmYgdHJhbnNhY3Rpb24gcHJvdGVjdGlvblxyXG4gICAgICB2YXIgbSA9IHN0YXRlLmFwcGxpY2F0aW9uLnN0YXRpY0RhdGE7XHJcbiAgICAgIGlmIChtLm9uKVxyXG4gICAgICB7XHJcbiAgICAgICAgbS5kaXNjYXJkKCk7XHJcbiAgICAgICAgbS5vbiA9IGZhbHNlO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB2YXIgQUlEQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgRFQoLTIpO1xyXG5cclxuICAgICAgdmFyIEFJRGxlbiA9IGdldEJ5dGUoQUlEQWRkcik7XHJcbiAgICAgIGlmIChBSURsZW4gPCAxIHx8IEFJRGxlbiA+IDE2KVxyXG4gICAgICAgIHNldFdvcmQoUFQoKStTVzEsIDB4NmE4Myk7XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIHZhciBBSUQgPSBuZXcgdmFyW0FJRGxlbl07XHJcblxyXG4gICAgICAgIHJlYWQoQUlEQWRkcisxLCBBSURsZW4sIEFJRCk7XHJcbiAgICAgICAgaWYgKCFkZWxlZ2F0ZUFwcGxpY2F0aW9uKEFJRGxlbiwgQUlEKSlcclxuICAgICAgICAgIHNldFdvcmQoUFQoKStTVzEsIDB4NmE4Myk7XHJcbiAgICAgIH1cclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHg4MToge1xyXG4gICAgbmFtZTogXCJSRVNFVF9TRVNTSU9OX0RBVEFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpZiAoc3RhdGUuYXBwbGljYXRpb24uaXNTaGVsbEFwcClcclxuICAgICAgICBSZXNldFNlc3Npb25EYXRhKCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODI6IHtcclxuICAgIG5hbWU6IFwiQ0hFQ0tTVU1cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuZ3RoID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgdmFyIGNoZWNrc3VtWzRdID0geyAweDVhLCAweGE1LCAweDVhLCAweGE1IH07XHJcblxyXG4gICAgICB2YXIgbSA9IHN0YXRlLmFwcGxpY2F0aW9uLnN0YXRpY0RhdGE7XHJcbiAgICAgIHZhciBhY2NvdW50Rm9yVHJhbnNhY3Rpb25Qcm90ZWN0aW9uID0gKGFkZHIgPj0gbS5zdGFydCgpICYmIGFkZHIgPD0gbS5zdGFydCgpICsgbS5zaXplKCkgJiYgbS5vbik7XHJcblxyXG4gICAgICBmb3IgKHZhciBqPTA7IGogPCBsZW5ndGg7IGorKylcclxuICAgICAge1xyXG4gICAgICAgIGlmIChhY2NvdW50Rm9yVHJhbnNhY3Rpb25Qcm90ZWN0aW9uKVxyXG4gICAgICAgICAgY2hlY2tzdW1bMF0gKz0gKHZhciltLnJlYWRQZW5kaW5nQnl0ZU1lbW9yeShhZGRyK2opO1xyXG4gICAgICAgIGVsc2VcclxuICAgICAgICAgIGNoZWNrc3VtWzBdICs9ICh2YXIpZ2V0Qnl0ZShhZGRyICsgaik7XHJcblxyXG4gICAgICAgIGNoZWNrc3VtWzFdICs9IGNoZWNrc3VtWzBdO1xyXG4gICAgICAgIGNoZWNrc3VtWzJdICs9IGNoZWNrc3VtWzFdO1xyXG4gICAgICAgIGNoZWNrc3VtWzNdICs9IGNoZWNrc3VtWzJdO1xyXG4gICAgICB9XHJcbiAgICAgIHdyaXRlKGR5bmFtaWNUb3AtNCwgNCwgY2hlY2tzdW0pO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgzOiB7XHJcbiAgICBuYW1lOiBcIkNBTExfQ09ERUxFVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBjb2RlbGV0SWQgPSBnZXRXb3JkKGR5bmFtaWNUb3AtNCk7XHJcbiAgICAgIHZhciBjb2RlYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIERUKC00KTtcclxuICAgICAgY2FsbENvZGVsZXQoY29kZWxldElkLCBjb2RlYWRkcik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODQ6IHtcclxuICAgIG5hbWU6IFwiUVVFUllfQ09ERUxFVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBjb2RlbGV0SWQgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcblxyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBxdWVyeUNvZGVsZXQoY29kZWxldElkKSk7XHJcbiAgICAgIERUKC0yKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjMToge1xyXG4gICAgbmFtZTogXCJERVNfRUNCX0VOQ0lQSEVSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyICprZXkgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDYpLDgpO1xyXG4gICAgICB2YXIgcGxhaW50ZXh0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDQpO1xyXG4gICAgICB2YXIgKmNpcGhlcnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDIpLDgpO1xyXG4gICAgICB2YXIgcGxhaW50ZXh0WzhdO1xyXG5cclxuICAgICAgbXRoX2RlcyhERVNfREVDUllQVCwga2V5LCBjaXBoZXJ0ZXh0LCBwbGFpbnRleHQpO1xyXG4gICAgICB3cml0ZShwbGFpbnRleHRBZGRyLCA4LCBwbGFpbnRleHQpO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzI6IHtcclxuICAgIG5hbWU6IFwiTU9EVUxBUl9NVUxUSVBMSUNBVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBtb2RsZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtOCk7XHJcbiAgICAgIGNvbnN0IHZhciAqbGhzID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIG1vZGxlbik7XHJcbiAgICAgIGNvbnN0IHZhciAqcmhzID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG1vZGxlbik7XHJcbiAgICAgIGNvbnN0IHZhciAqbW9kID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIG1vZGxlbik7XHJcbiAgICAgIHZhciAqcmVzID0gbmV3IHZhclttb2RsZW5dO1xyXG4gICAgICBtdGhfbW9kX211bHQobGhzLCBtb2RsZW4sIHJocywgbW9kbGVuLCBtb2QsIG1vZGxlbiwgcmVzKTtcclxuICAgICAgd3JpdGUoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBtb2RsZW4sIHJlcyk7XHJcbiAgICAgIERUKC04KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjMzoge1xyXG4gICAgbmFtZTogXCJNT0RVTEFSX1JFRFVDVElPTlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBvcGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgdmFyIG1vZGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC02KTtcclxuICAgICAgY29uc3QgdmFyICpvcCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBvcGxlbik7XHJcbiAgICAgIGNvbnN0IHZhciAqbW9kID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIG9wbGVuKTtcclxuICAgICAgdmFyICpyZXMgPSBuZXcgdmFyW29wbGVuXTtcclxuICAgICAgbXRoX21vZF9yZWQob3AsIG9wbGVuLCBtb2QsIG1vZGxlbiwgcmVzKTtcclxuICAgICAgd3JpdGUoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBvcGxlbiwgcmVzKTtcclxuICAgICAgRFQoLTgpO1xyXG4gICAgICBkZWxldGUgW11yZXM7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzQ6IHtcclxuICAgIG5hbWU6IFwiR0VUX1JBTkRPTV9OVU1CRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgcmFuZFs4XTtcclxuICAgICAgcmFuZGRhdGEocmFuZCwgOCk7XHJcbiAgICAgIERUKDgpO1xyXG4gICAgICB3cml0ZShkeW5hbWljVG9wLTgsIDgsIHJhbmQpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM1OiB7XHJcbiAgICBuYW1lOiBcIkRFU19FQ0JfREVDSVBIRVJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksOCk7XHJcbiAgICAgIHZhciBjaXBoZXJBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIHZhciAqcGxhaW50ZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMHgyKSw4KTtcclxuICAgICAgdmFyIGNpcGhlcnRleHRbOF07XHJcblxyXG4gICAgICBtdGhfZGVzKERFU19FTkNSWVBULCBrZXksIHBsYWludGV4dCwgY2lwaGVydGV4dCk7XHJcbiAgICAgIHdyaXRlKGNpcGhlckFkZHIsIDgsIGNpcGhlcnRleHQpO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzY6IHtcclxuICAgIG5hbWU6IFwiR0VORVJBVEVfREVTX0NCQ19TSUdOQVRVUkVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgcGxhaW5UZXh0TGVuZ3RoID0gZ2V0V29yZChkeW5hbWljVG9wLTB4YSk7XHJcbiAgICAgIHZhciBJVmFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg4KTtcclxuICAgICAgdmFyICprZXkgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDYpLCA4KTtcclxuICAgICAgdmFyIHNpZ25hdHVyZUFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgdmFyICpwbGFpblRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDIpLCBwbGFpblRleHRMZW5ndGgpO1xyXG4gICAgICB2YXIgc2lnbmF0dXJlWzhdO1xyXG5cclxuICAgICAgcmVhZChJVmFkZHIsIDgsIHNpZ25hdHVyZSk7XHJcbiAgICAgIHdoaWxlIChwbGFpblRleHRMZW5ndGggPj0gOClcclxuICAgICAge1xyXG4gICAgICAgIGZvciAodmFyIGk9MDtpPDg7aSsrKVxyXG4gICAgICAgICAgc2lnbmF0dXJlW2ldIF49IHBsYWluVGV4dFtpXTtcclxuXHJcbiAgICAgICAgdmFyIGVuY3J5cHRlZFNpZ25hdHVyZVs4XTtcclxuXHJcbiAgICAgICAgbXRoX2RlcyhERVNfRU5DUllQVCwga2V5LCBzaWduYXR1cmUsIGVuY3J5cHRlZFNpZ25hdHVyZSk7XHJcbiAgICAgICAgbWVtY3B5KHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlLCA4KTtcclxuICAgICAgICBwbGFpblRleHRMZW5ndGggLT0gODtcclxuICAgICAgICBwbGFpblRleHQgKz0gODtcclxuICAgICAgfVxyXG4gICAgICB3cml0ZShzaWduYXR1cmVBZGRyLCA4LCBzaWduYXR1cmUpO1xyXG4gICAgICBEVCgtMTApO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGM3OiB7XHJcbiAgICBuYW1lOiBcIkdFTkVSQVRFX1RSSVBMRV9ERVNfQ0JDX1NJR05BVFVSRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGludCBwbGFpblRleHRMZW5ndGggPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHhhKTtcclxuICAgICAgdmFyIElWYWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDgpO1xyXG4gICAgICB2YXIga2V5MSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NiksIDE2KTtcclxuICAgICAgdmFyIGtleTIgPSBrZXkxICsgODtcclxuICAgICAgdmFyIHNpZ25hdHVyZUFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgdmFyIHBsYWluVGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksIHBsYWluVGV4dExlbmd0aCk7XHJcbiAgICAgIHZhciBzaWduYXR1cmVbOF07XHJcblxyXG4gICAgICByZWFkKElWYWRkciwgOCwgc2lnbmF0dXJlKTtcclxuICAgICAgd2hpbGUgKHBsYWluVGV4dExlbmd0aCA+IDApXHJcbiAgICAgIHtcclxuICAgICAgICBmb3IgKHZhciBpPTA7aTw4O2krKylcclxuICAgICAgICAgIHNpZ25hdHVyZVtpXSBePSBwbGFpblRleHRbaV07XHJcblxyXG4gICAgICAgIHZhciBlbmNyeXB0ZWRTaWduYXR1cmVbOF07XHJcblxyXG4gICAgICAgIG10aF9kZXMoREVTX0VOQ1JZUFQsIGtleTEsIHNpZ25hdHVyZSwgZW5jcnlwdGVkU2lnbmF0dXJlKTtcclxuICAgICAgICBtdGhfZGVzKERFU19ERUNSWVBULCBrZXkyLCBlbmNyeXB0ZWRTaWduYXR1cmUsIHNpZ25hdHVyZSk7XHJcbiAgICAgICAgbXRoX2RlcyhERVNfRU5DUllQVCwga2V5MSwgc2lnbmF0dXJlLCBlbmNyeXB0ZWRTaWduYXR1cmUpO1xyXG4gICAgICAgIG1lbWNweShzaWduYXR1cmUsIGVuY3J5cHRlZFNpZ25hdHVyZSwgOCk7XHJcbiAgICAgICAgcGxhaW5UZXh0TGVuZ3RoIC09IDg7XHJcbiAgICAgICAgcGxhaW5UZXh0ICs9IDg7XHJcbiAgICAgIH1cclxuICAgICAgd3JpdGUoc2lnbmF0dXJlQWRkciwgOCwgc2lnbmF0dXJlKTtcclxuICAgICAgRFQoLTEwKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjODoge1xyXG4gICAgbmFtZTogXCJNT0RVTEFSX0VYUE9ORU5USUFUSU9OXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGV4cGxlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0weGMpO1xyXG4gICAgICB2YXIgbW9kbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTB4YSk7XHJcbiAgICAgIHZhciBleHBvbmVudCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4OCksIGV4cGxlbik7XHJcbiAgICAgIHZhciBtb2QgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0weDYpLCBtb2RsZW4pO1xyXG4gICAgICB2YXIgYmFzZSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4NCksIG1vZGxlbik7XHJcbiAgICAgIHZhciByZXNBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4Mik7XHJcbiAgICAgIHZhciByZXMgPSBuZXcgdmFyW21vZGxlbl07XHJcblxyXG4gICAgICBtdGhfbW9kX2V4cChiYXNlLCBtb2RsZW4sIGV4cG9uZW50LCBleHBsZW4sIG1vZCwgbW9kbGVuLCByZXMpO1xyXG4gICAgICB3cml0ZShyZXNBZGRyLCBtb2RsZW4sIHJlcyk7XHJcbiAgICAgIERUKC0xMik7XHJcblxyXG4gICAgICBkZWxldGUgW11yZXM7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4Yzk6IHtcclxuICAgIG5hbWU6IFwiTU9EVUxBUl9FWFBPTkVOVElBVElPTl9DUlRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTApO1xyXG4gICAgICB2YXIgZHBkcSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTgpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgIHZhciBwcXUgID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNiksIG1vZHVsdXNfbGVuICogMyAvIDIpO1xyXG4gICAgICB2YXIgYmFzZSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTQpLCBtb2R1bHVzX2xlbik7XHJcbiAgICAgIHZhciBvdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICB2YXIgcmVzID0gbmV3IHZhclttb2R1bHVzX2xlbl07XHJcblxyXG4gICAgICBtdGhfbW9kX2V4cF9jcnQobW9kdWx1c19sZW4sIGRwZHEsIHBxdSwgYmFzZSwgcmVzKTtcclxuICAgICAgd3JpdGUob3V0QWRkciwgbW9kdWx1c19sZW4sIHJlcyk7XHJcbiAgICAgIERUKC0xMCk7XHJcbiAgICAgIGRlbGV0ZVtdIHJlcztcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjYToge1xyXG4gICAgbmFtZTogXCJTSEExXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIHBsYWludGV4dExlbmd0aCA9IGdldFdvcmQoZHluYW1pY1RvcC0weDYpO1xyXG4gICAgICB2YXIgaGFzaERpZ2VzdEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgdmFyIHBsYWludGV4dCA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTB4MiksIHBsYWludGV4dExlbmd0aCk7XHJcbiAgICAgIHZhciBsb25nIGhhc2hEaWdlc3RbNV07IC8vIDIwIGJ5dGUgaGFzaFxyXG5cclxuICAgICAgbXRoX3NoYV9pbml0KGhhc2hEaWdlc3QpO1xyXG5cclxuICAgICAgd2hpbGUgKHBsYWludGV4dExlbmd0aCA+IDY0KVxyXG4gICAgICB7XHJcbiAgICAgICAgbXRoX3NoYV91cGRhdGUoaGFzaERpZ2VzdCwgKHZhciAqKXBsYWludGV4dCk7XHJcbiAgICAgICAgcGxhaW50ZXh0ICs9IDY0O1xyXG4gICAgICAgIHBsYWludGV4dExlbmd0aCAtPSA2NDtcclxuICAgICAgfVxyXG5cclxuICAgICAgbXRoX3NoYV9maW5hbChoYXNoRGlnZXN0LCAodmFyICopcGxhaW50ZXh0LCBwbGFpbnRleHRMZW5ndGgpO1xyXG5cclxuICAgICAgZm9yIChpbnQgaT0wO2k8NTtpKyspXHJcbiAgICAgICAgd3JpdGVOdW1iZXIoaGFzaERpZ2VzdEFkZHIrKGkqNCksIDQsIGhhc2hEaWdlc3RbaV0pO1xyXG5cclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGNjOiB7XHJcbiAgICBuYW1lOiBcIkdFTkVSQVRFX1JBTkRPTV9QUklNRVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBnY2RGbGFnID0gZ2V0Qnl0ZShkeW5hbWljVG9wLTEzKTtcclxuICAgICAgdmFyIGNvbmYgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTIpO1xyXG4gICAgICB2YXIgdGltZW91dCA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgIHZhciByZ0V4cCA9IGdldFdvcmQoZHluYW1pY1RvcC04KTtcclxuICAgICAgY29uc3QgdmFyICptaW5Mb2MgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgNCk7XHJcbiAgICAgIGNvbnN0IHZhciAqbWF4TG9jID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIDQpO1xyXG4gICAgICB2YXIgcmVzQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0weDIpO1xyXG4gICAgICBpZiAoKHJnRXhwIDwgNSkgfHwgKHJnRXhwID4gMjU2KSlcclxuICAgICAge1xyXG4gICAgICAgIEFiZW5kKFwicmdFeHAgcGFyYW1ldGVyIG91dCBvZiByYW5nZVwiKTtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICBzdGF0aWMgY29uc3Qgdmxvbmcgb25lKDEpO1xyXG4gICAgICAgIHN0YXRpYyBjb25zdCB2bG9uZyB0aHJlZSgzKTtcclxuICAgICAgICBzdGQ6OnZlY3Rvcjx2YXI+IGNhbmRpZGF0ZShyZ0V4cCk7XHJcbiAgICAgICAgZm9yICg7OylcclxuICAgICAgICB7XHJcbiAgICAgICAgICBzdGQ6OmdlbmVyYXRlKGNhbmRpZGF0ZS5iZWdpbigpLCBjYW5kaWRhdGUuZW5kKCksIHJhbmQpO1xyXG4gICAgICAgICAgaWYgKHN0ZDo6bGV4aWNvZ3JhcGhpY2FsX2NvbXBhcmUoXHJcbiAgICAgICAgICAgICAgICBjYW5kaWRhdGUuYmVnaW4oKSwgY2FuZGlkYXRlLmVuZCgpLFxyXG4gICAgICAgICAgICAgICAgbWluTG9jLCBtaW5Mb2MgKyA0KSlcclxuICAgICAgICAgICAgY29udGludWU7XHJcbiAgICAgICAgICBpZiAoc3RkOjpsZXhpY29ncmFwaGljYWxfY29tcGFyZShcclxuICAgICAgICAgICAgICAgIG1heExvYywgbWF4TG9jICsgNCxcclxuICAgICAgICAgICAgICAgIGNhbmRpZGF0ZS5iZWdpbigpLCBjYW5kaWRhdGUuZW5kKCkpKVxyXG4gICAgICAgICAgICBjb250aW51ZTtcclxuICAgICAgICAgIHZsb25nIHZsb25nX2NhbmRpZGF0ZShjYW5kaWRhdGUuc2l6ZSgpLCAmY2FuZGlkYXRlWzBdKTtcclxuICAgICAgICAgIGlmICgweDgwID09IGdjZEZsYWcpXHJcbiAgICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmIChvbmUgIT0gZ2NkKHRocmVlLCB2bG9uZ19jYW5kaWRhdGUpKVxyXG4gICAgICAgICAgICAgIGNvbnRpbnVlO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgaWYgKCFpc19wcm9iYWJsZV9wcmltZSh2bG9uZ19jYW5kaWRhdGUpKVxyXG4gICAgICAgICAgICBjb250aW51ZTtcclxuXHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgICB9XHJcbiAgICAgICAgd3JpdGUocmVzQWRkciwgcmdFeHAsICZjYW5kaWRhdGVbMF0pO1xyXG4gICAgICAgIERUKC0xMyk7XHJcbiAgICAgIH1cclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHhjZDoge1xyXG4gICAgbmFtZTogXCJTRUVEX0VDQl9ERUNJUEhFUlwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHN0YXRpYyBjb25zdCB2YXIgYmxvY2tfc2l6ZSA9IDE2O1xyXG5cclxuICAgICAgY29uc3QgdmFyICprZXkgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgYmxvY2tfc2l6ZSk7XHJcbiAgICAgIHZhciByZXNBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTB4NCk7XHJcbiAgICAgIGNvbnN0IHZhciAqcGxhaW50ZXh0ID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIGJsb2NrX3NpemUpO1xyXG5cclxuICAgICAgdmFyIGJ1ZmZlcltibG9ja19zaXplXTtcclxuICAgICAgbWVtY3B5KGJ1ZmZlciwga2V5LCBibG9ja19zaXplKTtcclxuICAgICAgRFdPUkQgcm91bmRfa2V5WzIgKiBibG9ja19zaXplXTtcclxuICAgICAgU2VlZEVuY1JvdW5kS2V5KHJvdW5kX2tleSwgYnVmZmVyKTtcclxuICAgICAgbWVtY3B5KGJ1ZmZlciwgcGxhaW50ZXh0LCBibG9ja19zaXplKTtcclxuICAgICAgU2VlZERlY3J5cHQoYnVmZmVyLCByb3VuZF9rZXkpO1xyXG5cclxuICAgICAgd3JpdGUocmVzQWRkciwgYmxvY2tfc2l6ZSwgYnVmZmVyKTtcclxuICAgICAgRFQoLTYpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweGNlOiB7XHJcbiAgICBuYW1lOiBcIlNFRURfRUNCX0VOQ0lQSEVSXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgc3RhdGljIGNvbnN0IHZhciBibG9ja19zaXplID0gMTY7XHJcblxyXG4gICAgICBjb25zdCB2YXIgKmtleSA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBibG9ja19zaXplKTtcclxuICAgICAgdmFyIHJlc0FkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMHg0KTtcclxuICAgICAgY29uc3QgdmFyICpwbGFpbnRleHQgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgYmxvY2tfc2l6ZSk7XHJcblxyXG4gICAgICB2YXIgYnVmZmVyW2Jsb2NrX3NpemVdO1xyXG4gICAgICBtZW1jcHkoYnVmZmVyLCBrZXksIGJsb2NrX3NpemUpO1xyXG4gICAgICBEV09SRCByb3VuZF9rZXlbMiAqIGJsb2NrX3NpemVdO1xyXG4gICAgICBTZWVkRW5jUm91bmRLZXkocm91bmRfa2V5LCBidWZmZXIpO1xyXG4gICAgICBtZW1jcHkoYnVmZmVyLCBwbGFpbnRleHQsIGJsb2NrX3NpemUpO1xyXG4gICAgICBTZWVkRW5jcnlwdChidWZmZXIsIHJvdW5kX2tleSk7XHJcblxyXG4gICAgICB3cml0ZShyZXNBZGRyLCBibG9ja19zaXplLCBidWZmZXIpO1xyXG4gICAgICBEVCgtNik7XHJcbiAgICAqL31cclxuICB9XHJcbn07XHJcblxyXG52YXIgc2V0T25lUHJpbWl0aXZlcyA9XHJcbntcclxuICAweDAwOiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZMFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGkgPSBwcmltMC5maW5kKGFyZzEpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBpICE9IHByaW0wLmVuZCgpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMToge1xyXG4gICAgbmFtZTogXCJRVUVSWTFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBpID0gcHJpbTEuZmluZChhcmcxKTtcclxuICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgaSAhPSBwcmltMS5lbmQoKSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDI6IHtcclxuICAgIG5hbWU6IFwiUVVFUlkyXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgaSA9IHByaW0yLmZpbmQoYXJnMSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGkgIT0gcHJpbTIuZW5kKCkpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDAzOiB7XHJcbiAgICBuYW1lOiBcIlFVRVJZM1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIGkgPSBwcmltMy5maW5kKGFyZzEpO1xyXG4gICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBpICE9IHByaW0zLmVuZCgpKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwODoge1xyXG4gICAgbmFtZTogXCJESVZJREVOXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGFyZzE7XHJcbiAgICAgIHZhciAqZGVub21pbmF0b3IgPSBkdW1wKGR5bmFtaWNUb3AtbGVuLCBsZW4pO1xyXG4gICAgICBpZiAoYmxvY2tJc1plcm8oZGVub21pbmF0b3IsIGxlbikpXHJcbiAgICAgIHtcclxuICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCB0cnVlKTtcclxuICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgIHtcclxuICAgICAgICBjb25zdCB2YXIgKm51bWVyYXRvciA9IGR1bXAoZHluYW1pY1RvcC0yKmxlbiwgbGVuKTtcclxuICAgICAgICB2YXIgKnF1b3RpZW50ID0gbmV3IHZhcltsZW5dO1xyXG4gICAgICAgIHZhciAqcmVtYWluZGVyID0gbmV3IHZhcltsZW5dO1xyXG4gICAgICAgIG10aF9kaXYobnVtZXJhdG9yLCBkZW5vbWluYXRvciwgbGVuLCBxdW90aWVudCwgcmVtYWluZGVyKTtcclxuICAgICAgICB3cml0ZShkeW5hbWljVG9wLTIqbGVuLCBsZW4sIHF1b3RpZW50KTtcclxuICAgICAgICB3cml0ZShkeW5hbWljVG9wLWxlbiwgbGVuLCByZW1haW5kZXIpO1xyXG4gICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGZhbHNlKTtcclxuICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBibG9ja0lzWmVybyhxdW90aWVudCxsZW4pKTtcclxuICAgICAgICBkZWxldGUgW11xdW90aWVudDtcclxuICAgICAgICBkZWxldGUgW11yZW1haW5kZXI7XHJcbiAgICAgIH1cclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwOToge1xyXG4gICAgbmFtZTogXCJHRVRfRElSX0ZJTEVfUkVDT1JEXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgLy8gU2FtZSBhcyBiZWxvd1xyXG4gICAgICBNVUxUT1MuUHJpbWl0aXZlcy5zZXRPbmVQcmltaXRpdmVzWyAweDBhIF0ucHJvYygpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBhOiB7XHJcbiAgICBuYW1lOiBcIkdFVF9GSUxFX0NPTlRST0xfSU5GT1JNQVRJT05cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbGVuID0gYXJnMTtcclxuICAgICAgdmFyIGFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMyk7XHJcbiAgICAgIHZhciByZWNvcmROdW1iZXIgPSBnZXRCeXRlKGR5bmFtaWNUb3AtMSk7XHJcbiAgICAgIHZhciBva2F5O1xyXG4gICAgICB2YXIgKmRhdGE7XHJcbiAgICAgIHZhciBkYXRhbGVuO1xyXG4gICAgICBpZiAocHJpbSA9PSBHRVRfRElSX0ZJTEVfUkVDT1JEKVxyXG4gICAgICAgIG9rYXkgPSBnZXREaXJGaWxlUmVjb3JkKHJlY29yZE51bWJlci0xLCAmZGF0YWxlbiwgJmRhdGEpO1xyXG4gICAgICBlbHNlXHJcbiAgICAgICAgb2theSA9IGdldEZDSShyZWNvcmROdW1iZXItMSwgJmRhdGFsZW4sICZkYXRhKTtcclxuICAgICAgaWYgKG9rYXkpXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgdmFyIGNvcGllZCA9IGxlbiA8IGRhdGFsZW4gPyBsZW4gOiBkYXRhbGVuO1xyXG4gICAgICAgICAgaWYgKGNvcGllZClcclxuICAgICAgICAgICAgd3JpdGUoYWRkciwgY29waWVkLCBkYXRhKTtcclxuICAgICAgICAgIHB1c2hCeXRlKGNvcGllZCk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCAoY29waWVkIDwgbGVuKSk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCAwKTtcclxuICAgICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAgICB7XHJcbiAgICAgICAgICBwdXNoQnl0ZSgwKTtcclxuICAgICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIDEpO1xyXG4gICAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgMSk7XHJcbiAgICAgICAgfVxyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBiOiB7XHJcbiAgICBuYW1lOiBcIkdFVF9NQU5VRkFDVFVSRVJfREFUQVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBEVCgtMSk7XHJcbiAgICAgIHZhciBtYW51ZmFjdHVyZXJbMjU2XTtcclxuICAgICAgdmFyIGxlbiA9IGdldE1hbnVmYWN0dXJlckRhdGEobWFudWZhY3R1cmVyKTtcclxuICAgICAgbGVuID0gYXJnMSA8IGxlbiA/IGFyZzEgOiBsZW47XHJcbiAgICAgIGlmIChsZW4pXHJcbiAgICAgICAgd3JpdGUoYWRkciwgbGVuLCBtYW51ZmFjdHVyZXIpO1xyXG4gICAgICBzZXRCeXRlKGR5bmFtaWNUb3AtMSwgKHZhcilsZW4pO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBjOiB7XHJcbiAgICBuYW1lOiBcIkdFVF9NVUxUT1NfREFUQVwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBhZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBEVCgtMSk7XHJcbiAgICAgIHZhciBNVUxUT1NEYXRhWzI1Nl07XHJcbiAgICAgIHZhciBsZW4gPSBnZXRNVUxUT1NEYXRhKE1VTFRPU0RhdGEpO1xyXG4gICAgICBpZiAobGVuKVxyXG4gICAgICAgIGxlbiA9IGFyZzEgPCBsZW4gPyBhcmcxIDogbGVuO1xyXG4gICAgICB3cml0ZShhZGRyLCBsZW4sIE1VTFRPU0RhdGEpO1xyXG4gICAgICBzZXRCeXRlKGR5bmFtaWNUb3AtMSwgKHZhcilsZW4pO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDBkOiB7XHJcbiAgICBuYW1lOiBcIkdFVF9QVVJTRV9UWVBFXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgQWJlbmQoXCJwcmltaXRpdmUgbm90IHN1cHBvcnRlZFwiKTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwZToge1xyXG4gICAgbmFtZTogXCJNRU1PUllfQ09QWV9GSVhFRF9MRU5HVEhcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgZHN0ID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgc3JjID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG5cclxuICAgICAgY29weShkc3QsIHNyYywgYXJnMSk7XHJcbiAgICAgIERUKC00KTtcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwZjoge1xyXG4gICAgbmFtZTogXCJNRU1PUllfQ09NUEFSRV9GSVhFRF9MRU5HVEhcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgb3AxID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICB2YXIgb3AyID0gZ2V0V29yZChkeW5hbWljVG9wLTIpO1xyXG4gICAgICBibG9ja0NvbXBhcmUob3AxLCBvcDIsIGFyZzEpO1xyXG4gICAgICBEVCgtNCk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MTA6IHtcclxuICAgIG5hbWU6IFwiTVVMVElQTFlOXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgdmFyIGxlbiA9IGFyZzE7XHJcbiAgICAgIGNvbnN0IHZhciAqb3AxID0gZHVtcChkeW5hbWljVG9wLTIqbGVuLCBsZW4pO1xyXG4gICAgICBjb25zdCB2YXIgKm9wMiA9IGR1bXAoZHluYW1pY1RvcC1sZW4sIGxlbik7XHJcbiAgICAgIHZhciAqcmVzID0gbmV3IHZhcltsZW4qMl07XHJcbiAgICAgIG10aF9tdWwob3AxLCBvcDIsIGxlbiwgcmVzKTtcclxuICAgICAgd3JpdGUoZHluYW1pY1RvcC0yKmxlbiwgbGVuKjIsIHJlcyk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGJsb2NrSXNaZXJvKHJlcyxsZW4qMikpO1xyXG4gICAgICBkZWxldGUgW11yZXM7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODA6IHtcclxuICAgIG5hbWU6IFwiU0VUX1RSQU5TQUNUSU9OX1BST1RFQ1RJT05cIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgbSA9IHN0YXRlLmFwcGxpY2F0aW9uLnN0YXRpY0RhdGE7XHJcbiAgICAgIGlmIChtLm9uKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIGlmIChhcmcxICYgMSlcclxuICAgICAgICAgICAgbS5jb21taXQoKTtcclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgbS5kaXNjYXJkKCk7XHJcbiAgICAgICAgfVxyXG4gICAgICBpZiAoYXJnMSAmIDIpXHJcbiAgICAgICAgbS5vbiA9IHRydWU7XHJcbiAgICAgIGVsc2VcclxuICAgICAgICBtLm9uID0gZmFsc2U7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4ODE6IHtcclxuICAgIG5hbWU6IFwiR0VUX0RFTEVHQVRPUl9BSURcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgQUlEQWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuICAgICAgRFQoLTIpO1xyXG4gICAgICBNRUxFeGVjdXRpb25TdGF0ZSAqZSA9IGdldERlbGVnYXRvclN0YXRlKCk7XHJcbiAgICAgIGlmIChlKVxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHZhciBsZW47XHJcbiAgICAgICAgICBpZiAoIGFyZzEgPCBlLmFwcGxpY2F0aW9uLkFJRGxlbmd0aClcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgIGxlbiA9IGFyZzE7XHJcbiAgICAgICAgICAgICAgU2V0Q0NSRmxhZyhDZmxhZywgdHJ1ZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgIGxlbiA9ICBlLmFwcGxpY2F0aW9uLkFJRGxlbmd0aDtcclxuICAgICAgICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCBmYWxzZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIHNldEJ5dGUoQUlEQWRkciwgKHZhcilsZW4pO1xyXG4gICAgICAgICAgQUlEQWRkcisrO1xyXG4gICAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgbGVuOyBpKyspXHJcbiAgICAgICAgICAgIHNldEJ5dGUoQUlEQWRkcitpLCBlLmFwcGxpY2F0aW9uLkFJRFtpXSk7XHJcbiAgICAgICAgICBTZXRDQ1JGbGFnKFpmbGFnLCBmYWxzZSk7XHJcbiAgICAgICAgfVxyXG4gICAgICBlbHNlXHJcbiAgICAgICAgU2V0Q0NSRmxhZyhaZmxhZywgdHJ1ZSk7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4YzQ6IHtcclxuICAgIG5hbWU6IFwiR0VORVJBVEVfQVNZTU1FVFJJQ19IQVNIXCIsXHJcbiAgICBwcm9jOiBmdW5jdGlvbigpIHsgLypcclxuICAgICAgY29uc3QgdmFyICppdjtcclxuICAgICAgdmFyIHBsYWluX2xlbjtcclxuICAgICAgdmFyIGRpZ2VzdE91dEFkZHI7XHJcbiAgICAgIGNvbnN0IHZhciAqcGxhaW47XHJcbiAgICAgIE1FTEtleSogYWhhc2hLZXk7XHJcbiAgICAgIGludCBkdHZhbDtcclxuICAgICAgc3RkOjphdXRvX3B0cjxTaW1wbGVNRUxLZXlXcmFwcGVyPiBzbWt3O1xyXG4gICAgICB2YXIgaGNsID0gMTY7XHJcblxyXG4gICAgICBzd2l0Y2ggKGFyZzEpXHJcbiAgICAgIHtcclxuICAgICAgICBjYXNlIDA6XHJcbiAgICAgICAgICBpdiA9IDA7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC0yKSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gZ2V0QUhhc2hLZXkoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTY7XHJcbiAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgY2FzZSAxOlxyXG4gICAgICAgICAgaXYgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC04KSwgMTYpO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICBhaGFzaEtleSA9IGdldEFIYXNoS2V5KCk7XHJcbiAgICAgICAgICBkdHZhbCA9IC02O1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGNhc2UgMjpcclxuICAgICAgICAgIGl2ID0gMDtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTgpO1xyXG4gICAgICAgICAgcGxhaW4gPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC02KSwgcGxhaW5fbGVuKTtcclxuICAgICAgICAgIHZhciBtb2R1bHVzX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC00KTtcclxuICAgICAgICAgIHZhciBtb2R1bHVzID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgICAgIHNta3cgPSBzdGQ6OmF1dG9fcHRyPFNpbXBsZU1FTEtleVdyYXBwZXI+KG5ldyBTaW1wbGVNRUxLZXlXcmFwcGVyKG1vZHVsdXNfbGVuLCBtb2R1bHVzKSk7XHJcbiAgICAgICAgICBhaGFzaEtleSA9IHNta3cuZ2V0KCk7XHJcbiAgICAgICAgICBkdHZhbCA9IC0xMDtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIDM6XHJcbiAgICAgICAgICBpdiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTEyKSwgMTYpO1xyXG4gICAgICAgICAgcGxhaW5fbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgICAgIGRpZ2VzdE91dEFkZHIgPSBnZXRXb3JkKGR5bmFtaWNUb3AtOCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTYpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXNfbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTQpO1xyXG4gICAgICAgICAgY29uc3QgdmFyKiBtb2R1bHVzID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtMiksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgICAgIHNta3cgPSBzdGQ6OmF1dG9fcHRyPFNpbXBsZU1FTEtleVdyYXBwZXI+KG5ldyBTaW1wbGVNRUxLZXlXcmFwcGVyKG1vZHVsdXNfbGVuLCBtb2R1bHVzKSk7XHJcbiAgICAgICAgICBhaGFzaEtleSA9IHNta3cuZ2V0KCk7XHJcbiAgICAgICAgICBkdHZhbCA9IC0xMjtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIDQ6XHJcbiAgICAgICAgICBpdiA9IDA7XHJcbiAgICAgICAgICBwbGFpbl9sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtMTIpO1xyXG4gICAgICAgICAgZGlnZXN0T3V0QWRkciA9IGdldFdvcmQoZHluYW1pY1RvcC0xMCk7XHJcbiAgICAgICAgICBwbGFpbiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTgpLCBwbGFpbl9sZW4pO1xyXG4gICAgICAgICAgdmFyIG1vZHVsdXNfbGVuID0gZ2V0V29yZChkeW5hbWljVG9wLTYpO1xyXG4gICAgICAgICAgY29uc3QgdmFyKiBtb2R1bHVzID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtNCksIG1vZHVsdXNfbGVuKTtcclxuICAgICAgICAgIHNta3cgPSBzdGQ6OmF1dG9fcHRyPFNpbXBsZU1FTEtleVdyYXBwZXI+KG5ldyBTaW1wbGVNRUxLZXlXcmFwcGVyKG1vZHVsdXNfbGVuLCBtb2R1bHVzKSk7XHJcbiAgICAgICAgICBhaGFzaEtleSA9IHNta3cuZ2V0KCk7XHJcbiAgICAgICAgICBoY2wgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgICAgICBkdHZhbCA9IC0xMjtcclxuICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICBjYXNlIDU6XHJcbiAgICAgICAgICBoY2wgPSBnZXRXb3JkKGR5bmFtaWNUb3AtMik7XHJcbiAgICAgICAgICBpdiA9IGR1bXAoZ2V0V29yZChkeW5hbWljVG9wLTE0KSwgaGNsKTtcclxuICAgICAgICAgIHBsYWluX2xlbiA9IGdldFdvcmQoZHluYW1pY1RvcC0xMik7XHJcbiAgICAgICAgICBkaWdlc3RPdXRBZGRyID0gZ2V0V29yZChkeW5hbWljVG9wLTEwKTtcclxuICAgICAgICAgIHBsYWluID0gZHVtcChnZXRXb3JkKGR5bmFtaWNUb3AtOCksIHBsYWluX2xlbik7XHJcbiAgICAgICAgICB2YXIgbW9kdWx1c19sZW4gPSBnZXRXb3JkKGR5bmFtaWNUb3AtNik7XHJcbiAgICAgICAgICBjb25zdCB2YXIqIG1vZHVsdXMgPSBkdW1wKGdldFdvcmQoZHluYW1pY1RvcC00KSwgbW9kdWx1c19sZW4pO1xyXG4gICAgICAgICAgc21rdyA9IHN0ZDo6YXV0b19wdHI8U2ltcGxlTUVMS2V5V3JhcHBlcj4obmV3IFNpbXBsZU1FTEtleVdyYXBwZXIobW9kdWx1c19sZW4sIG1vZHVsdXMpKTtcclxuICAgICAgICAgIGFoYXNoS2V5ID0gc21rdy5nZXQoKTtcclxuICAgICAgICAgIGR0dmFsID0gLTE0O1xyXG4gICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICBBYmVuZChcImJhZCBiMiB2YWx1ZSBmb3IgR2VuZXJhdGVBc3ltbWV0cmljSGFzaCBwcmltaXRpdmVcIik7XHJcbiAgICAgICAgICBicmVhaztcclxuICAgICAgfVxyXG5cclxuICAgICAgc3RkOjp2ZWN0b3I8dmFyPiBoYXNoKGhjbCk7XHJcbiAgICAgIEFIYXNoKGFoYXNoS2V5LCBwbGFpbl9sZW4sIHBsYWluLCAmaGFzaFswXSwgaXYsIGhjbCk7XHJcbiAgICAgIHdyaXRlKGRpZ2VzdE91dEFkZHIsIGhjbCwgJmhhc2hbMF0pO1xyXG4gICAgICBEVChkdHZhbCk7XHJcbiAgICAqL31cclxuICB9XHJcbn07XHJcblxyXG5mdW5jdGlvbiBiaXRNYW5pcHVsYXRlKGJpdG1hcCwgbGl0ZXJhbCwgZGF0YSlcclxue1xyXG4gIHZhciBtb2RpZnkgPSAoKGJpdG1hcCAmICgxPDw3KSkgPT0gKDE8PDcpKTtcclxuICBpZiAoYml0bWFwICYgMHg3YykgLy8gYml0cyA2LTIgc2hvdWxkIGJlIHplcm9cclxuICAgIHRocm93IG5ldyBFcnJvciggXCJVbmRlZmluZWQgYXJndW1lbnRzXCIpO1xyXG5cclxuICBzd2l0Y2ggKGJpdG1hcCAmIDMpXHJcbiAge1xyXG4gICAgY2FzZSAzOlxyXG4gICAgICBkYXRhICY9IGxpdGVyYWw7XHJcbiAgICAgIGJyZWFrO1xyXG4gICAgY2FzZSAyOlxyXG4gICAgICBkYXRhIHw9IGxpdGVyYWw7XHJcbiAgICAgIGJyZWFrO1xyXG4gICAgY2FzZSAxOlxyXG4gICAgICBkYXRhID0gfihkYXRhIF4gbGl0ZXJhbCk7XHJcbiAgICAgIGJyZWFrO1xyXG4gICAgY2FzZSAwOlxyXG4gICAgICBkYXRhIF49IGxpdGVyYWw7XHJcbiAgICAgIGJyZWFrO1xyXG4gIH1cclxuXHJcbiAgLy9TZXRDQ1JGbGFnKFpmbGFnLCBkYXRhPT0wKTtcclxuXHJcbiAgcmV0dXJuIG1vZGlmeTsgLy9UT0RPOiByZXR1cm4gZGF0YVxyXG59XHJcblxyXG52YXIgc2V0VHdvUHJpbWl0aXZlcyA9XHJcbntcclxuICAweDAxOiB7XHJcbiAgICBuYW1lOiBcIkJJVF9NQU5JUFVMQVRFX0JZVEVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKi8qXHJcbiAgICAgIHZhciBiID0gZ2V0Qnl0ZShkeW5hbWljVG9wLTEpO1xyXG5cclxuICAgICAgaWYgKGJpdE1hbmlwdWxhdGUoYXJnMSwgYXJnMiwgYikpXHJcbiAgICAgICAgc2V0Qnl0ZShkeW5hbWljVG9wLTEsICh2YXIpYik7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDI6IHtcclxuICAgIG5hbWU6IFwiU0hJRlRfTEVGVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIC8vIHNhbWUgYXMgU0hJRlRfUklHSFRcclxuICAgICovfVxyXG4gIH0sXHJcbiAgMHgwMzoge1xyXG4gICAgbmFtZTogXCJTSElGVF9SSUdIVFwiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHZhciBsZW4gPSBhcmcxO1xyXG4gICAgICB2YXIgbnVtU2hpZnRCaXRzID0gYXJnMjtcclxuICAgICAgaWYgKCFsZW4gfHwgIW51bVNoaWZ0Qml0cyB8fCBudW1TaGlmdEJpdHM+PTgqbGVuKVxyXG4gICAgICAgIEFiZW5kKFwidW5kZWZpbmVkIHNoaWZ0IGFyZ3VtZW50c1wiKTtcclxuXHJcbiAgICAgIHZhciAqZGF0YSA9IG5ldyB2YXJbbGVuXTtcclxuICAgICAgcmVhZChkeW5hbWljVG9wLWxlbiwgbGVuLCBkYXRhKTtcclxuXHJcbiAgICAgIGlmIChwcmltID09IFNISUZUX0xFRlQpXHJcbiAgICAgIHtcclxuICAgICAgICBTZXRDQ1JGbGFnKENmbGFnLCBibG9ja0JpdFNldChsZW4sIGRhdGEsIGxlbio4LW51bVNoaWZ0Qml0cykpO1xyXG4gICAgICAgIG10aF9zaGwoZGF0YSwgbGVuLCBudW1TaGlmdEJpdHMpO1xyXG4gICAgICB9XHJcbiAgICAgIGVsc2VcclxuICAgICAge1xyXG4gICAgICAgIFNldENDUkZsYWcoQ2ZsYWcsIGJsb2NrQml0U2V0KGxlbiwgZGF0YSwgbnVtU2hpZnRCaXRzLTEpKTtcclxuICAgICAgICBtdGhfc2hyKGRhdGEsIGxlbiwgbnVtU2hpZnRCaXRzKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgd3JpdGUoZHluYW1pY1RvcC1sZW4sIGxlbiwgZGF0YSk7XHJcbiAgICAgIFNldENDUkZsYWcoWmZsYWcsIGJsb2NrSXNaZXJvKGRhdGEsbGVuKSk7XHJcbiAgICAgIGRlbGV0ZSBbXWRhdGE7XHJcbiAgICAqL31cclxuICB9LFxyXG4gIDB4MDQ6IHtcclxuICAgIG5hbWU6IFwiU0VUX1NFTEVDVF9TV1wiLFxyXG4gICAgcHJvYzogZnVuY3Rpb24oKSB7IC8qXHJcbiAgICAgIHNldFNlbGVjdFNXKGFyZzEsIGFyZzIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDA1OiB7XHJcbiAgICBuYW1lOiBcIkNBUkRfQkxPQ0tcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgwOiB7XHJcbiAgICBuYW1lOiBcIlJFVFVSTl9GUk9NX0NPREVMRVRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICByZXR1cm5Gcm9tQ29kZWxldChhcmcxLCBhcmcyKTtcclxuICAgICovfVxyXG4gIH1cclxufVxyXG5cclxudmFyIHNldFRocmVlUHJpbWl0aXZlcyA9XHJcbntcclxuICAweDAxOiB7XHJcbiAgICBuYW1lOiBcIkJJVF9NQU5JUFVMQVRFX1dPUkRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICB2YXIgdyA9IGdldFdvcmQoZHluYW1pY1RvcC0yKTtcclxuXHJcbiAgICAgIGlmIChiaXRNYW5pcHVsYXRlKGFyZzEsIG1rV29yZChhcmcyLCBhcmczKSwgdykpXHJcbiAgICAgICAgc2V0V29yZChkeW5hbWljVG9wLTIsIHcpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgwOiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTBcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgxOiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTFcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgyOiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTJcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDgzOiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTNcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDg0OiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTRcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDg1OiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTVcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfSxcclxuICAweDg2OiB7XHJcbiAgICBuYW1lOiBcIkNBTExfRVhURU5TSU9OX1BSSU1JVElWRTZcIixcclxuICAgIHByb2M6IGZ1bmN0aW9uKCkgeyAvKlxyXG4gICAgICBBYmVuZChcInByaW1pdGl2ZSBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgKi99XHJcbiAgfVxyXG59O1xyXG5cclxudmFyIHByaW1pdGl2ZVNldHMgPSBbXHJcbiAgc2V0WmVyb1ByaW1pdGl2ZXMsXHJcbiAgc2V0T25lUHJpbWl0aXZlcyxcclxuICBzZXRUd29QcmltaXRpdmVzLFxyXG4gIHNldFRocmVlUHJpbWl0aXZlc1xyXG5dO1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGNhbGxQcmltaXRpdmUoIGN0eCwgcHJpbSwgc2V0LCBhcmcxLCBhcmcyLCBhcmczIClcclxue1xyXG4gIHZhciBwcmltSW5mbyA9IHByaW1pdGl2ZVNldHNbIHNldCBdWyBwcmltIF07XHJcblxyXG4gIGlmICggcHJpbUluZm8gKVxyXG4gIHtcclxuICAgIHN3aXRjaCggc2V0IClcclxuICAgIHtcclxuICAgICAgY2FzZSAwOiBwcmltSW5mby5wcm9jKCk7IGJyZWFrO1xyXG4gICAgICBjYXNlIDE6IHByaW1JbmZvLnByb2MoIGFyZzEgKTsgYnJlYWs7XHJcbiAgICAgIGNhc2UgMjogcHJpbUluZm8ucHJvYyggYXJnMSwgYXJnMiApOyBicmVhaztcclxuICAgICAgY2FzZSAzOiBwcmltSW5mby5wcm9jKCBhcmcxLCBhcmcyLCBhcmczICk7IGJyZWFrO1xyXG4gICAgfVxyXG4gIH1cclxuICBlbHNlXHJcbiAge1xyXG4gICAgLy8gbm8gcHJpbVxyXG4gICAgdGhyb3cgbmV3IEVycm9yKCBcIlByaW1pdGl2ZSBub3QgSW1wbGVtZW50ZWRcIiApO1xyXG4gIH1cclxufVxyXG4iLCJleHBvcnQgY2xhc3MgU2VjdXJpdHlNYW5hZ2VyXHJcbntcclxuICBpbml0U2VjdXJpdHkoKVxyXG4gIHtcclxuICB9XHJcblxyXG4gIHByb2Nlc3NBUERVKCBhcGR1IClcclxuICB7XHJcbiAgICByZXR1cm4gZmFsc2U7XHJcbiAgfVxyXG59XHJcbiIsImltcG9ydCB7IEJ5dGVBcnJheSxLaW5kLEtpbmRJbmZvIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmV4cG9ydCBjbGFzcyBBRENcbntcbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSxLaW5kLEtpbmRJbmZvIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XG5cbmV4cG9ydCBjbGFzcyBBTENcbntcbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSwgS2luZCwgS2luZEluZm8sIEtpbmRCdWlsZGVyIH0gZnJvbSAnY3J5cHRvZ3JhcGhpeC1zaW0tY29yZSc7XHJcblxyXG4vKipcclxuICogRW5jb2Rlci9EZWNvZG9yIGZvciBhIE1VTFRPUyBBcHBsaWNhdGlvbiBMb2FkIFVuaXRcclxuICovXHJcbmV4cG9ydCBjbGFzcyBBTFUgaW1wbGVtZW50cyBLaW5kXHJcbntcclxuICBzdGF0aWMga2luZEluZm86IEtpbmRJbmZvO1xyXG5cclxuICBjb2RlOiBCeXRlQXJyYXkgPSBuZXcgQnl0ZUFycmF5KCk7XHJcbiAgZGF0YTogQnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSgpO1xyXG4gIGZjaTogQnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSgpO1xyXG4gIGRpcjogQnl0ZUFycmF5ID0gbmV3IEJ5dGVBcnJheSgpO1xyXG5cclxuICAvKipcclxuICAgKiBAY29uc3RydWN0b3JcclxuICAgKi9cclxuICBjb25zdHJ1Y3RvciggYXR0cmlidXRlcz86IHt9IClcclxuICB7XHJcbiAgICBpZiAoIGF0dHJpYnV0ZXMgKVxyXG4gICAge1xyXG4gICAgICBmb3IoIGxldCBmaWVsZCBpbiBBTFUua2luZEluZm8uZmllbGRzIClcclxuICAgICAgICBpZiAoIGF0dHJpYnV0ZXNbIGZpZWxkLmlkIF0gKVxyXG4gICAgICAgICAgdGhpc1sgZmllbGQuaWQgXSA9IGF0dHJpYnV0ZXNbIGZpZWxkLmlkIF07XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTZXJpYWxpemF0aW9uLCByZXR1cm5zIGEgSlNPTiBvYmplY3RcclxuICAgKi9cclxuICBwdWJsaWMgdG9KU09OKCk6IHt9XHJcbiAge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgY29kZTogdGhpcy5jb2RlLFxyXG4gICAgICBkYXRhOiB0aGlzLmRhdGEsXHJcbiAgICAgIGZjaTogdGhpcy5mY2ksXHJcbiAgICAgIGRpcjogdGhpcy5kaXJcclxuICAgIH07XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGdldEFMVVNlZ21lbnQoIGJ5dGVzOiBCeXRlQXJyYXksIHNlZ21lbnRJRDogbnVtYmVyIClcclxuICB7XHJcbiAgICB2YXIgb2Zmc2V0ID0gODtcclxuXHJcbiAgICB3aGlsZSggKCBzZWdtZW50SUQgPiAxICkgJiYgKCBvZmZzZXQgPCBieXRlcy5sZW5ndGggKSApXHJcbiAgICB7XHJcbiAgICAgIG9mZnNldCArPSAyICsgYnl0ZXMud29yZEF0KCBvZmZzZXQgKTtcclxuICAgICAgLS1zZWdtZW50SUQ7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGJ5dGVzLnZpZXdBdCggb2Zmc2V0ICsgMiwgYnl0ZXMud29yZEF0KCBvZmZzZXQgKSApO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogRGVjb2RlciBmYWN0b3J5IGZ1bmN0aW9uLCBkZWNvZGVzIGEgYmxvYiBpbnRvIGEgTXVsdG9zQUxVIG9iamVjdFxyXG4gICAqL1xyXG4gIHB1YmxpYyBkZWNvZGVCeXRlcyggYnl0ZXM6IEJ5dGVBcnJheSwgb3B0aW9ucz86IE9iamVjdCApOiBBTFVcclxuICB7XHJcbiAgICB0aGlzLmNvZGUgPSB0aGlzLmdldEFMVVNlZ21lbnQoIGJ5dGVzLCAxICk7XHJcbiAgICB0aGlzLmRhdGEgPSB0aGlzLmdldEFMVVNlZ21lbnQoIGJ5dGVzLCAyICk7XHJcbiAgICB0aGlzLmRpciA9IHRoaXMuZ2V0QUxVU2VnbWVudCggYnl0ZXMsIDMgKTtcclxuICAgIHRoaXMuZmNpID0gdGhpcy5nZXRBTFVTZWdtZW50KCBieXRlcywgNCApO1xyXG5cclxuICAgIHJldHVybiB0aGlzO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogRW5jb2RlciBmdW5jdGlvbiwgcmV0dXJucyBhIGJsb2IgZnJvbSBhIE11bHRvc0FMVSBvYmplY3RcclxuICAgKi9cclxuICBwdWJsaWMgZW5jb2RlQnl0ZXMoIG9wdGlvbnM/OiB7fSApOiBCeXRlQXJyYXlcclxuICB7XHJcbiAgICAvL0AgVE9ETzogcmVidWlsZCBiaW5hcnkgQUxVXHJcbiAgICByZXR1cm4gbmV3IEJ5dGVBcnJheSggW10gKTtcclxuICB9XHJcbn1cclxuXHJcbktpbmRCdWlsZGVyLmluaXQoIEFMVSwgXCJNVUxUT1MgQXBwbGljYXRpb24gTG9hZCBVbml0XCIgKVxyXG4gIC5maWVsZCggXCJjb2RlXCIsIFwiQ29kZSBTZWdtZW50XCIsIEJ5dGVBcnJheSApXHJcbiAgLmZpZWxkKCBcImRhdGFcIiwgXCJEYXRhIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICAuZmllbGQoIFwiZmNpXCIsIFwiRkNJIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICAuZmllbGQoIFwiZGlyXCIsIFwiRElSIFNlZ21lbnRcIiwgQnl0ZUFycmF5IClcclxuICA7XHJcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
