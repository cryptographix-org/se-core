define(['exports', 'cryptographix-sim-core'], function (exports, _cryptographixSimCore) {
    'use strict';

    exports.__esModule = true;

    var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

    exports.hex2 = hex2;
    exports.hex4 = hex4;
    exports.MEL2OPCODE = MEL2OPCODE;
    exports.MEL2INST = MEL2INST;
    exports.MEL2TAG = MEL2TAG;
    exports.callPrimitive = callPrimitive;

    function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }

    var BaseTLV = (function () {
        function BaseTLV(tag, value, encoding) {
            _classCallCheck(this, BaseTLV);

            this.encoding = encoding || BaseTLV.Encodings.EMV;
            switch (this.encoding) {
                case BaseTLV.Encodings.EMV:
                    {
                        var tlvBuffer = new _cryptographixSimCore.ByteArray([]);
                        if (tag >= 0x100) tlvBuffer.addByte(tag >> 8 & 0xFF);
                        tlvBuffer.addByte(tag & 0xFF);
                        var len = value.length;
                        if (len > 0xFF) {
                            tlvBuffer.addByte(0x82);
                            tlvBuffer.addByte(len >> 8 & 0xFF);
                        } else if (len > 0x7F) tlvBuffer.addByte(0x81);
                        tlvBuffer.addByte(len & 0xFF);
                        tlvBuffer.concat(value);
                        this.byteArray = tlvBuffer;
                        break;
                    }
            }
        }

        BaseTLV.parseTLV = function parseTLV(buffer, encoding) {
            var res = { tag: 0, len: 0, value: undefined, lenOffset: 0, valueOffset: 0 };
            var off = 0;
            var bytes = buffer.backingArray;
            switch (encoding) {
                case BaseTLV.Encodings.EMV:
                    {
                        while (off < bytes.length && (bytes[off] == 0x00 || bytes[off] == 0xFF)) ++off;
                        if (off >= bytes.length) return res;
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
                        var ll = bytes[off] & 0x80 ? bytes[off++] & 0x7F : 1;
                        while (ll-- > 0) {
                            if (off >= bytes.length) {
                                return null;
                            }
                            res.len = res.len << 8 | bytes[off++];
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
        };

        _createClass(BaseTLV, [{
            key: 'tag',
            get: function get() {
                return BaseTLV.parseTLV(this.byteArray, this.encoding).tag;
            }
        }, {
            key: 'value',
            get: function get() {
                return BaseTLV.parseTLV(this.byteArray, this.encoding).value;
            }
        }, {
            key: 'len',
            get: function get() {
                return BaseTLV.parseTLV(this.byteArray, this.encoding).len;
            }
        }]);

        return BaseTLV;
    })();

    exports.BaseTLV = BaseTLV;

    BaseTLV.Encodings = {
        EMV: 1,
        DGI: 2
    };
    BaseTLV.Encodings["CTV"] = 4;

    var CommandAPDU = (function () {
        function CommandAPDU(attributes) {
            _classCallCheck(this, CommandAPDU);

            this.INS = 0;
            this.P1 = 0;
            this.P2 = 0;
            this.data = new _cryptographixSimCore.ByteArray();
            this.Le = 0;
            _cryptographixSimCore.Kind.initFields(this, attributes);
        }

        CommandAPDU.init = function init(CLA, INS, P1, P2, data, expectedLen) {
            return new CommandAPDU().set(CLA, INS, P1, P2, data, expectedLen);
        };

        CommandAPDU.prototype.set = function set(CLA, INS, P1, P2, data, expectedLen) {
            this.CLA = CLA;
            this.INS = INS;
            this.P1 = P1;
            this.P2 = P2;
            this.data = data || new _cryptographixSimCore.ByteArray();
            this.Le = expectedLen || 0;
            return this;
        };

        CommandAPDU.prototype.setCLA = function setCLA(CLA) {
            this.CLA = CLA;return this;
        };

        CommandAPDU.prototype.setINS = function setINS(INS) {
            this.INS = INS;return this;
        };

        CommandAPDU.prototype.setP1 = function setP1(P1) {
            this.P1 = P1;return this;
        };

        CommandAPDU.prototype.setP2 = function setP2(P2) {
            this.P2 = P2;return this;
        };

        CommandAPDU.prototype.setData = function setData(data) {
            this.data = data;return this;
        };

        CommandAPDU.prototype.setLe = function setLe(Le) {
            this.Le = Le;return this;
        };

        CommandAPDU.prototype.toJSON = function toJSON() {
            return {
                CLA: this.CLA,
                INS: this.INS,
                P1: this.P1,
                P2: this.P2,
                data: this.data,
                Le: this.Le
            };
        };

        CommandAPDU.prototype.encodeBytes = function encodeBytes(options) {
            var dlen = this.Lc > 0 ? 1 + this.Lc : 0;
            var len = 4 + dlen + (this.Le > 0 ? 1 : 0);
            var ba = new _cryptographixSimCore.ByteArray().setLength(len);
            ba.setBytesAt(0, this.header);
            if (this.Lc) {
                ba.setByteAt(4, this.Lc);
                ba.setBytesAt(5, this.data);
            }
            if (this.Le > 0) {
                ba.setByteAt(4 + dlen, this.Le);
            }
            return ba;
        };

        CommandAPDU.prototype.decodeBytes = function decodeBytes(byteArray, options) {
            if (byteArray.length < 4) throw new Error('CommandAPDU: Invalid buffer');
            var offset = 0;
            this.CLA = byteArray.byteAt(offset++);
            this.INS = byteArray.byteAt(offset++);
            this.P1 = byteArray.byteAt(offset++);
            this.P2 = byteArray.byteAt(offset++);
            if (byteArray.length > offset + 1) {
                var Lc = byteArray.byteAt(offset++);
                this.data = byteArray.bytesAt(offset, Lc);
                offset += Lc;
            }
            if (byteArray.length > offset) this.Le = byteArray.byteAt(offset++);
            if (byteArray.length != offset) throw new Error('CommandAPDU: Invalid buffer');
            return this;
        };

        _createClass(CommandAPDU, [{
            key: 'Lc',
            get: function get() {
                return this.data.length;
            }
        }, {
            key: 'header',
            get: function get() {
                return new _cryptographixSimCore.ByteArray([this.CLA, this.INS, this.P1, this.P2]);
            }
        }]);

        return CommandAPDU;
    })();

    exports.CommandAPDU = CommandAPDU;

    _cryptographixSimCore.KindBuilder.init(CommandAPDU, 'ISO7816 Command APDU').byteField('CLA', 'Class').byteField('INS', 'Instruction').byteField('P1', 'P1 Param').byteField('P2', 'P2 Param').integerField('Lc', 'Command Length', { calculated: true }).field('data', 'Command Data', _cryptographixSimCore.ByteArray).integerField('Le', 'Expected Length');

    var ISO7816;
    exports.ISO7816 = ISO7816;
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
    })(ISO7816 || (exports.ISO7816 = ISO7816 = {}));

    var ResponseAPDU = (function () {
        function ResponseAPDU(attributes) {
            _classCallCheck(this, ResponseAPDU);

            this.SW = ISO7816.SW_SUCCESS;
            this.data = new _cryptographixSimCore.ByteArray();
            _cryptographixSimCore.Kind.initFields(this, attributes);
        }

        ResponseAPDU.init = function init(sw, data) {
            return new ResponseAPDU().set(sw, data);
        };

        ResponseAPDU.prototype.set = function set(sw, data) {
            this.SW = sw;
            this.data = data || new _cryptographixSimCore.ByteArray();
            return this;
        };

        ResponseAPDU.prototype.setSW = function setSW(SW) {
            this.SW = SW;return this;
        };

        ResponseAPDU.prototype.setSW1 = function setSW1(SW1) {
            this.SW = this.SW & 0xFF | SW1 << 8;return this;
        };

        ResponseAPDU.prototype.setSW2 = function setSW2(SW2) {
            this.SW = this.SW & 0xFF00 | SW2;return this;
        };

        ResponseAPDU.prototype.setData = function setData(data) {
            this.data = data;return this;
        };

        ResponseAPDU.prototype.encodeBytes = function encodeBytes(options) {
            var ba = new _cryptographixSimCore.ByteArray().setLength(this.La + 2);
            ba.setBytesAt(0, this.data);
            ba.setByteAt(this.La, this.SW >> 8 & 0xff);
            ba.setByteAt(this.La + 1, this.SW >> 0 & 0xff);
            return ba;
        };

        ResponseAPDU.prototype.decodeBytes = function decodeBytes(byteArray, options) {
            if (byteArray.length < 2) throw new Error('ResponseAPDU Buffer invalid');
            var la = byteArray.length - 2;
            this.SW = byteArray.wordAt(la);
            this.data = la ? byteArray.bytesAt(0, la) : new _cryptographixSimCore.ByteArray();
            return this;
        };

        _createClass(ResponseAPDU, [{
            key: 'La',
            get: function get() {
                return this.data.length;
            }
        }]);

        return ResponseAPDU;
    })();

    exports.ResponseAPDU = ResponseAPDU;

    _cryptographixSimCore.KindBuilder.init(ResponseAPDU, 'ISO7816 Response APDU').integerField('SW', 'Status Word', { maximum: 0xFFFF }).integerField('La', 'Actual Length', { calculated: true }).field('Data', 'Response Data', _cryptographixSimCore.ByteArray);

    var SlotProtocolHandler = (function () {
        function SlotProtocolHandler() {
            _classCallCheck(this, SlotProtocolHandler);
        }

        SlotProtocolHandler.prototype.linkSlot = function linkSlot(slot, endPoint) {
            this.endPoint = endPoint;
            this.slot = slot;
            endPoint.onMessage(this.onMessage);
        };

        SlotProtocolHandler.prototype.unlinkSlot = function unlinkSlot() {
            this.endPoint.onMessage(undefined);
            this.endPoint = undefined;
            this.slot = undefined;
        };

        SlotProtocolHandler.prototype.onMessage = function onMessage(packet, receivingEndPoint) {
            var hdr = packet.header;
            var payload = packet.payload;
            switch (hdr.command) {
                case "executeAPDU":
                    {
                        if (!(hdr.kind instanceof CommandAPDU)) break;
                        var commandAPDU = payload;
                        var resp = this.slot.executeAPDU(commandAPDU);
                        var x = null;
                        resp.then(function (responseAPDU) {
                            var replyPacket = new _cryptographixSimCore.Message({ method: "executeAPDU" }, responseAPDU);
                            receivingEndPoint.sendMessage(replyPacket);
                        })['catch'](function () {
                            var errorPacket = new _cryptographixSimCore.Message({ method: "error" }, undefined);
                            receivingEndPoint.sendMessage(errorPacket);
                        });
                        break;
                    }
            }
        };

        return SlotProtocolHandler;
    })();

    exports.SlotProtocolHandler = SlotProtocolHandler;

    var Key = (function () {
        function Key() {
            _classCallCheck(this, Key);

            this._type = 0;
            this._size = -1;
            this._componentArray = [];
        }

        Key.prototype.setType = function setType(keyType) {
            this._type = keyType;
        };

        Key.prototype.getType = function getType() {
            return this._type;
        };

        Key.prototype.setSize = function setSize(size) {
            this._size = size;
        };

        Key.prototype.getSize = function getSize() {
            return this._size;
        };

        Key.prototype.setComponent = function setComponent(comp, value) {
            this._componentArray[comp] = value;
        };

        Key.prototype.getComponent = function getComponent(comp) {
            return this._componentArray[comp];
        };

        return Key;
    })();

    exports.Key = Key;

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

    var Crypto = (function () {
        function Crypto() {
            _classCallCheck(this, Crypto);
        }

        Crypto.prototype.encrypt = function encrypt(key, mech, data) {
            var k = key.getComponent(Key.SECRET).byteArray;
            if (k.length == 16) {
                var orig = k;
                k = new _cryptographixSimCore.ByteArray([]).setLength(24);
                k.setBytesAt(0, orig);
                k.setBytesAt(16, orig.viewAt(0, 8));
            }
            var cryptoText = new _cryptographixSimCore.ByteArray(this.des(k.backingArray, data.byteArray.backingArray, 1, 0));
            return new ByteString(cryptoText);
        };

        Crypto.prototype.decrypt = function decrypt(key, mech, data) {
            return data;
        };

        Crypto.prototype.sign = function sign(key, mech, data, iv) {
            var k = key.getComponent(Key.SECRET).byteArray;
            var keyData = k;
            if (k.length == 16) {
                keyData = new _cryptographixSimCore.ByteArray();
                keyData.setLength(24).setBytesAt(0, k).setBytesAt(16, k.bytesAt(0, 8));
            }
            if (iv == undefined) iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            var cryptoText = new _cryptographixSimCore.ByteArray(this.des(keyData.backingArray, data.byteArray.backingArray, 1, 1, iv, 4));
            return new ByteString(cryptoText).bytes(-8);
        };

        Crypto.prototype.des = function des(key, message, encrypt, mode, iv, padding) {
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
                var lefttemp,
                    righttemp,
                    m = 0,
                    n = 0,
                    temp;
                for (var j = 0; j < iterations; j++) {
                    left = key[m++] << 24 | key[m++] << 16 | key[m++] << 8 | key[m++];
                    right = key[m++] << 24 | key[m++] << 16 | key[m++] << 8 | key[m++];
                    temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
                    right ^= temp;
                    left ^= temp << 4;
                    temp = (right >>> -16 ^ left) & 0x0000ffff;
                    left ^= temp;
                    right ^= temp << -16;
                    temp = (left >>> 2 ^ right) & 0x33333333;
                    right ^= temp;
                    left ^= temp << 2;
                    temp = (right >>> -16 ^ left) & 0x0000ffff;
                    left ^= temp;
                    right ^= temp << -16;
                    temp = (left >>> 1 ^ right) & 0x55555555;
                    right ^= temp;
                    left ^= temp << 1;
                    temp = (right >>> 8 ^ left) & 0x00ff00ff;
                    left ^= temp;
                    right ^= temp << 8;
                    temp = (left >>> 1 ^ right) & 0x55555555;
                    right ^= temp;
                    left ^= temp << 1;
                    temp = left << 8 | right >>> 20 & 0x000000f0;
                    left = right << 24 | right << 8 & 0xff0000 | right >>> 8 & 0xff00 | right >>> 24 & 0xf0;
                    right = temp;
                    for (var i = 0; i < shifts.length; i++) {
                        if (shifts[i]) {
                            left = left << 2 | left >>> 26;
                            right = right << 2 | right >>> 26;
                        } else {
                            left = left << 1 | left >>> 27;
                            right = right << 1 | right >>> 27;
                        }
                        left &= -0xf;
                        right &= -0xf;
                        lefttemp = Crypto.desPC.pc2bytes0[left >>> 28] | Crypto.desPC.pc2bytes1[left >>> 24 & 0xf] | Crypto.desPC.pc2bytes2[left >>> 20 & 0xf] | Crypto.desPC.pc2bytes3[left >>> 16 & 0xf] | Crypto.desPC.pc2bytes4[left >>> 12 & 0xf] | Crypto.desPC.pc2bytes5[left >>> 8 & 0xf] | Crypto.desPC.pc2bytes6[left >>> 4 & 0xf];
                        righttemp = Crypto.desPC.pc2bytes7[right >>> 28] | Crypto.desPC.pc2bytes8[right >>> 24 & 0xf] | Crypto.desPC.pc2bytes9[right >>> 20 & 0xf] | Crypto.desPC.pc2bytes10[right >>> 16 & 0xf] | Crypto.desPC.pc2bytes11[right >>> 12 & 0xf] | Crypto.desPC.pc2bytes12[right >>> 8 & 0xf] | Crypto.desPC.pc2bytes13[right >>> 4 & 0xf];
                        temp = (righttemp >>> 16 ^ lefttemp) & 0x0000ffff;
                        keys[n++] = lefttemp ^ temp;
                        keys[n++] = righttemp ^ temp << 16;
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
                    spfunction8: new Uint32Array([0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000])
                };
            }
            var keys = des_createKeys(key);
            var m = 0,
                i,
                j,
                temp,
                left,
                right,
                looping;
            var cbcleft, cbcleft2, cbcright, cbcright2;
            var len = message.length;
            var iterations = keys.length == 32 ? 3 : 9;
            if (iterations == 3) {
                looping = encrypt ? [0, 32, 2] : [30, -2, -2];
            } else {
                looping = encrypt ? [0, 32, 2, 62, 30, -2, 64, 96, 2] : [94, 62, -2, 32, 64, 2, 30, -2, -2];
            }
            if (padding != undefined && padding != 4) {
                var unpaddedMessage = message;
                var pad = 8 - len % 8;
                message = new Uint8Array(len + 8);
                message.set(unpaddedMessage, 0);
                switch (padding) {
                    case 0:
                        message.set(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), len);
                        break;
                    case 1:
                        {
                            message.set(new Uint8Array([pad, pad, pad, pad, pad, pad, pad, pad]), 8);
                            if (pad == 8) len += 8;
                            break;
                        }
                    case 2:
                        message.set(new Uint8Array([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20]), 8);
                        break;
                }
                len += 8 - len % 8;
            }
            var result = new Uint8Array(len);
            if (mode == 1) {
                var m = 0;
                cbcleft = iv[m++] << 24 | iv[m++] << 16 | iv[m++] << 8 | iv[m++];
                cbcright = iv[m++] << 24 | iv[m++] << 16 | iv[m++] << 8 | iv[m++];
            }
            var rm = 0;
            while (m < len) {
                left = message[m++] << 24 | message[m++] << 16 | message[m++] << 8 | message[m++];
                right = message[m++] << 24 | message[m++] << 16 | message[m++] << 8 | message[m++];
                if (mode == 1) {
                    if (encrypt) {
                        left ^= cbcleft;
                        right ^= cbcright;
                    } else {
                        cbcleft2 = cbcleft;
                        cbcright2 = cbcright;
                        cbcleft = left;
                        cbcright = right;
                    }
                }
                temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
                right ^= temp;
                left ^= temp << 4;
                temp = (left >>> 16 ^ right) & 0x0000ffff;
                right ^= temp;
                left ^= temp << 16;
                temp = (right >>> 2 ^ left) & 0x33333333;
                left ^= temp;
                right ^= temp << 2;
                temp = (right >>> 8 ^ left) & 0x00ff00ff;
                left ^= temp;
                right ^= temp << 8;
                temp = (left >>> 1 ^ right) & 0x55555555;
                right ^= temp;
                left ^= temp << 1;
                left = left << 1 | left >>> 31;
                right = right << 1 | right >>> 31;
                for (j = 0; j < iterations; j += 3) {
                    var endloop = looping[j + 1];
                    var loopinc = looping[j + 2];
                    for (i = looping[j]; i != endloop; i += loopinc) {
                        var right1 = right ^ keys[i];
                        var right2 = (right >>> 4 | right << 28) ^ keys[i + 1];
                        temp = left;
                        left = right;
                        right = temp ^ (Crypto.desSP.spfunction2[right1 >>> 24 & 0x3f] | Crypto.desSP.spfunction4[right1 >>> 16 & 0x3f] | Crypto.desSP.spfunction6[right1 >>> 8 & 0x3f] | Crypto.desSP.spfunction8[right1 & 0x3f] | Crypto.desSP.spfunction1[right2 >>> 24 & 0x3f] | Crypto.desSP.spfunction3[right2 >>> 16 & 0x3f] | Crypto.desSP.spfunction5[right2 >>> 8 & 0x3f] | Crypto.desSP.spfunction7[right2 & 0x3f]);
                    }
                    temp = left;
                    left = right;
                    right = temp;
                }
                left = left >>> 1 | left << 31;
                right = right >>> 1 | right << 31;
                temp = (left >>> 1 ^ right) & 0x55555555;
                right ^= temp;
                left ^= temp << 1;
                temp = (right >>> 8 ^ left) & 0x00ff00ff;
                left ^= temp;
                right ^= temp << 8;
                temp = (right >>> 2 ^ left) & 0x33333333;
                left ^= temp;
                right ^= temp << 2;
                temp = (left >>> 16 ^ right) & 0x0000ffff;
                right ^= temp;
                left ^= temp << 16;
                temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
                right ^= temp;
                left ^= temp << 4;
                if (mode == 1) {
                    if (encrypt) {
                        cbcleft = left;
                        cbcright = right;
                    } else {
                        left ^= cbcleft2;
                        right ^= cbcright2;
                    }
                }
                result.set(new Uint8Array([left >>> 24 & 0xff, left >>> 16 & 0xff, left >>> 8 & 0xff, left & 0xff, right >>> 24 & 0xff, right >>> 16 & 0xff, right >>> 8 & 0xff, right & 0xff]), rm);
                rm += 8;
            }
            return result;
        };

        Crypto.prototype.verify = function verify(key, mech, data, signature, iv) {
            return data;
        };

        Crypto.prototype.digest = function digest(mech, data) {
            return data;
        };

        return Crypto;
    })();

    exports.Crypto = Crypto;

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

    var ByteString = (function () {
        function ByteString(value, encoding) {
            _classCallCheck(this, ByteString);

            if (!encoding) {
                if (value instanceof ByteString) this.byteArray = value.byteArray.clone();else if (value instanceof _cryptographixSimCore.ByteArray) this.byteArray = value.clone();
            } else {
                switch (encoding) {
                    case ByteString.HEX:
                        this.byteArray = new _cryptographixSimCore.ByteArray(value, _cryptographixSimCore.ByteArray.HEX);
                        break;
                    default:
                        throw "ByteString unsupported encoding";
                }
            }
        }

        ByteString.prototype.bytes = function bytes(offset, count) {
            return new ByteString(this.byteArray.viewAt(offset, count));
        };

        ByteString.prototype.byteAt = function byteAt(offset) {
            return this.byteArray.byteAt(offset);
        };

        ByteString.prototype.equals = function equals(otherByteString) {};

        ByteString.prototype.concat = function concat(value) {
            this.byteArray.concat(value.byteArray);
            return this;
        };

        ByteString.prototype.left = function left(count) {
            return new ByteString(this.byteArray.viewAt(0));
        };

        ByteString.prototype.right = function right(count) {
            return new ByteString(this.byteArray.viewAt(-count));
        };

        ByteString.prototype.not = function not() {
            return new ByteString(this.byteArray.clone().not());
        };

        ByteString.prototype.and = function and(value) {
            return new ByteString(this.byteArray.clone().and(value.byteArray));
        };

        ByteString.prototype.or = function or(value) {
            return new ByteString(this.byteArray.clone().or(value.byteArray));
        };

        ByteString.prototype.pad = function pad(method, optional) {
            var bs = new ByteBuffer(this.byteArray);
            if (optional == undefined) optional = false;
            if ((bs.length & 7) != 0 || !optional) {
                var newlen = bs.length + 8 & ~7;
                if (method == Crypto.ISO9797_METHOD_1) bs.append(0x80);
                while (bs.length < newlen) bs.append(0x00);
            }
            return bs.toByteString();
        };

        ByteString.prototype.toString = function toString(encoding) {
            return this.byteArray.toString(_cryptographixSimCore.ByteArray.HEX);
        };

        _createClass(ByteString, [{
            key: 'length',
            get: function get() {
                return this.byteArray.length;
            }
        }]);

        return ByteString;
    })();

    exports.ByteString = ByteString;

    ByteString.HEX = _cryptographixSimCore.ByteArray.HEX;
    ByteString.BASE64 = _cryptographixSimCore.ByteArray.HEX;
    var HEX = ByteString.HEX;
    exports.HEX = HEX;
    var BASE64 = ByteString.BASE64;

    exports.BASE64 = BASE64;

    var ByteBuffer = (function () {
        function ByteBuffer(value, encoding) {
            _classCallCheck(this, ByteBuffer);

            if (value instanceof _cryptographixSimCore.ByteArray) {
                this.byteArray = value.clone();
            } else if (value instanceof ByteString) {
                this.byteArray = value.byteArray.clone();
            } else if (encoding != undefined) {
                this.byteArray = new ByteString(value, encoding).byteArray.clone();
            } else this.byteArray = new _cryptographixSimCore.ByteArray([]);
        }

        ByteBuffer.prototype.toByteString = function toByteString() {
            return new ByteString(this.byteArray);
        };

        ByteBuffer.prototype.clear = function clear() {
            this.byteArray = new _cryptographixSimCore.ByteArray([]);
        };

        ByteBuffer.prototype.append = function append(value) {
            var valueArray = undefined;
            if (value instanceof ByteString || value instanceof ByteBuffer) {
                valueArray = value.byteArray;
            } else if (typeof value == "number") {
                valueArray = new _cryptographixSimCore.ByteArray([value & 0xff]);
            }
            this.byteArray.concat(valueArray);
            return this;
        };

        _createClass(ByteBuffer, [{
            key: 'length',
            get: function get() {
                return this.byteArray.length;
            }
        }]);

        return ByteBuffer;
    })();

    exports.ByteBuffer = ByteBuffer;

    var TLV = (function () {
        function TLV(tag, value, encoding) {
            _classCallCheck(this, TLV);

            this.tlv = new BaseTLV(tag, value.byteArray, encoding);
            this.encoding = encoding;
        }

        TLV.prototype.getTLV = function getTLV() {
            return new ByteString(this.tlv.byteArray);
        };

        TLV.prototype.getTag = function getTag() {
            return this.tlv.tag;
        };

        TLV.prototype.getValue = function getValue() {
            return new ByteString(this.tlv.value);
        };

        TLV.prototype.getL = function getL() {
            var info = BaseTLV.parseTLV(this.tlv.byteArray, this.encoding);
            return new ByteString(this.tlv.byteArray.viewAt(info.lenOffset, info.valueOffset));
        };

        TLV.prototype.getLV = function getLV() {
            var info = BaseTLV.parseTLV(this.tlv.byteArray, this.encoding);
            return new ByteString(this.tlv.byteArray.viewAt(info.lenOffset, info.valueOffset + info.len));
        };

        TLV.parseTLV = function parseTLV(buffer, encoding) {
            var info = BaseTLV.parseTLV(buffer.byteArray, encoding);
            return {
                tag: info.tag,
                len: info.len,
                value: new ByteString(info.value),
                lenOffset: info.lenOffset,
                valueOffset: info.valueOffset
            };
        };

        return TLV;
    })();

    exports.TLV = TLV;

    TLV.EMV = BaseTLV.Encodings.EMV;
    TLV.DGI = BaseTLV.Encodings.DGI;

    var TLVList = (function () {
        function TLVList(tlvStream, encoding) {
            _classCallCheck(this, TLVList);

            this._tlvs = [];
            var off = 0;
            while (off < tlvStream.length) {
                var tlvInfo = TLV.parseTLV(tlvStream.bytes(off), encoding);
                if (tlvInfo == null) {
                    break;
                } else {
                    if (tlvInfo.valueOffset == 0) break;
                    this._tlvs.push(new TLV(tlvInfo.tag, tlvInfo.value, encoding));
                    off += tlvInfo.valueOffset + tlvInfo.len;
                }
            }
        }

        TLVList.prototype.index = function index(_index) {
            return this._tlvs[_index];
        };

        return TLVList;
    })();

    exports.TLVList = TLVList;

    var JSSimulatedSlot = (function () {
        function JSSimulatedSlot() {
            _classCallCheck(this, JSSimulatedSlot);
        }

        JSSimulatedSlot.prototype.OnMessage = function OnMessage(e) {
            if (this.stop) return;
            if (e.data.command == "debug") {
                console.log(e.data.data);
            } else if (e.data.command == "executeAPDU") {
                if (this.onAPDUResponse) {
                    var bs = e.data.data,
                        len = bs.length;
                    this.onAPDUResponse(bs[len - 2] << 8 | bs[len - 1], len > 2 ? new _cryptographixSimCore.ByteArray(bs.subarray(0, len - 2)) : null);
                }
            } else {
                console.log("cmd: " + e.data.command + " data: " + e.data.data);
            }
        };

        JSSimulatedSlot.prototype.init = function init() {
            this.cardWorker = new Worker("js/SmartCardSlotSimulator/SmartCardSlotWorker.js");
            this.cardWorker.onmessage = this.OnMessage.bind(this);
            this.cardWorker.onerror = function (e) {};
        };

        JSSimulatedSlot.prototype.sendToWorker = function sendToWorker(command, data) {
            this.cardWorker.postMessage({
                "command": command,
                "data": data
            });
        };

        JSSimulatedSlot.prototype.executeAPDUCommand = function executeAPDUCommand(bCLA, bINS, bP1, bP2, commandData, wLe, onAPDUResponse) {
            var cmd = [bCLA, bINS, bP1, bP2];
            var len = 4;
            var bsCommandData = commandData instanceof _cryptographixSimCore.ByteArray ? commandData : new _cryptographixSimCore.ByteArray(commandData, _cryptographixSimCore.ByteArray.HEX);
            if (bsCommandData.length > 0) {
                cmd[len++] = bsCommandData.length;
                for (var i = 0; i < bsCommandData.length; ++i) cmd[len++] = bsCommandData.byteAt(i);
            } else if (wLe != undefined) cmd[len++] = wLe & 0xFF;
            this.sendToWorker("executeAPDU", cmd);
            this.onAPDUResponse = onAPDUResponse;
            return;
        };

        return JSSimulatedSlot;
    })();

    var JSIMScriptApplet = (function () {
        function JSIMScriptApplet() {
            _classCallCheck(this, JSIMScriptApplet);
        }

        JSIMScriptApplet.prototype.selectApplication = function selectApplication(commandAPDU) {
            return Promise.resolve(new ResponseAPDU({ sw: 0x9000 }));
        };

        JSIMScriptApplet.prototype.deselectApplication = function deselectApplication() {};

        JSIMScriptApplet.prototype.executeAPDU = function executeAPDU(commandAPDU) {
            return Promise.resolve(new ResponseAPDU({ sw: 0x6D00 }));
        };

        return JSIMScriptApplet;
    })();

    exports.JSIMScriptApplet = JSIMScriptApplet;

    var JSIMScriptCard = (function () {
        function JSIMScriptCard() {
            _classCallCheck(this, JSIMScriptCard);

            this.applets = [];
            this._atr = new _cryptographixSimCore.ByteArray([]);
        }

        JSIMScriptCard.prototype.loadApplication = function loadApplication(aid, applet) {
            this.applets.push({ aid: aid, applet: applet });
        };

        JSIMScriptCard.prototype.powerOn = function powerOn() {
            this._powerIsOn = true;
            return Promise.resolve(this._atr);
        };

        JSIMScriptCard.prototype.powerOff = function powerOff() {
            this._powerIsOn = false;
            this.selectedApplet = undefined;
            return Promise.resolve();
        };

        JSIMScriptCard.prototype.reset = function reset() {
            this._powerIsOn = true;
            this.selectedApplet = undefined;
            return Promise.resolve(this._atr);
        };

        JSIMScriptCard.prototype.exchangeAPDU = function exchangeAPDU(commandAPDU) {
            if (commandAPDU.INS == 0xA4) {
                if (this.selectedApplet) {
                    this.selectedApplet.deselectApplication();
                    this.selectedApplet = undefined;
                }
                this.selectedApplet = this.applets[0].applet;
                return this.selectedApplet.selectApplication(commandAPDU);
            }
            return this.selectedApplet.executeAPDU(commandAPDU);
        };

        _createClass(JSIMScriptCard, [{
            key: 'isPowered',
            get: function get() {
                return this._powerIsOn;
            }
        }]);

        return JSIMScriptCard;
    })();

    exports.JSIMScriptCard = JSIMScriptCard;

    var JSIMSlot = (function () {
        function JSIMSlot(card) {
            _classCallCheck(this, JSIMSlot);

            this.card = card;
        }

        JSIMSlot.prototype.powerOn = function powerOn() {
            if (!this.isPresent) return Promise.reject(new Error("JSIM: Card not present"));
            return this.card.powerOn();
        };

        JSIMSlot.prototype.powerOff = function powerOff() {
            if (!this.isPresent) return Promise.reject(new Error("JSIM: Card not present"));
            return this.card.powerOff();
        };

        JSIMSlot.prototype.reset = function reset() {
            if (!this.isPresent) return Promise.reject(new Error("JSIM: Card not present"));
            return this.card.reset();
        };

        JSIMSlot.prototype.executeAPDU = function executeAPDU(commandAPDU) {
            if (!this.isPresent) return Promise.reject(new Error("JSIM: Card not present"));
            if (!this.isPowered) return Promise.reject(new Error("JSIM: Card unpowered"));
            return this.card.exchangeAPDU(commandAPDU);
        };

        JSIMSlot.prototype.insertCard = function insertCard(card) {
            if (this.card) this.ejectCard();
            this.card = card;
        };

        JSIMSlot.prototype.ejectCard = function ejectCard() {
            if (this.card) {
                if (this.card.isPowered) this.card.powerOff();
                this.card = undefined;
            }
        };

        _createClass(JSIMSlot, [{
            key: 'isPresent',
            get: function get() {
                return !!this.card;
            }
        }, {
            key: 'isPowered',
            get: function get() {
                return this.isPresent && this.card.isPowered;
            }
        }]);

        return JSIMSlot;
    })();

    exports.JSIMSlot = JSIMSlot;

    function hex2(val) {
        return ("00" + val.toString(16).toUpperCase()).substr(-2);
    }

    function hex4(val) {
        return ("0000" + val.toString(16).toUpperCase()).substr(-4);
    }

    var MEMFLAGS;
    exports.MEMFLAGS = MEMFLAGS;
    (function (MEMFLAGS) {
        MEMFLAGS[MEMFLAGS["READ_ONLY"] = 1] = "READ_ONLY";
        MEMFLAGS[MEMFLAGS["TRANSACTIONABLE"] = 2] = "TRANSACTIONABLE";
        MEMFLAGS[MEMFLAGS["TRACE"] = 4] = "TRACE";
    })(MEMFLAGS || (exports.MEMFLAGS = MEMFLAGS = {}));

    var Segment = (function () {
        function Segment(segType, size, flags, base) {
            _classCallCheck(this, Segment);

            this.inTransaction = false;
            this.transBlocks = [];
            this.memType = segType;
            this.readOnly = flags & MEMFLAGS.READ_ONLY ? true : false;
            if (base) {
                this.memData = new _cryptographixSimCore.ByteArray(base);
            } else {
                this.memData = new _cryptographixSimCore.ByteArray([]).setLength(size);
            }
        }

        Segment.prototype.getType = function getType() {
            return this.memType;
        };

        Segment.prototype.getLength = function getLength() {
            return this.memData.length;
        };

        Segment.prototype.getFlags = function getFlags() {
            return this.flags;
        };

        Segment.prototype.getDebug = function getDebug() {
            return { memData: this.memData, memType: this.memType, readOnly: this.readOnly, inTransaction: this.inTransaction, transBlocks: this.transBlocks };
        };

        Segment.prototype.beginTransaction = function beginTransaction() {
            this.inTransaction = true;
            this.transBlocks = [];
        };

        Segment.prototype.endTransaction = function endTransaction(commit) {
            if (!commit && this.inTransaction) {
                this.inTransaction = false;
                for (var i = 0; i < this.transBlocks.length; i++) {
                    var block = this.transBlocks[i];
                    this.writeBytes(block.addr, block.data);
                }
            }
            this.transBlocks = [];
        };

        Segment.prototype.readByte = function readByte(addr) {
            return this.memData[addr];
        };

        Segment.prototype.zeroBytes = function zeroBytes(addr, len) {
            for (var i = 0; i < len; ++i) this.memData[addr + i] = 0;
        };

        Segment.prototype.readBytes = function readBytes(addr, len) {
            return this.memData.viewAt(addr, len);
        };

        Segment.prototype.copyBytes = function copyBytes(fromAddr, toAddr, len) {
            this.writeBytes(toAddr, this.readBytes(fromAddr, len));
        };

        Segment.prototype.writeBytes = function writeBytes(addr, val) {
            if (this.inTransaction && this.flags & MEMFLAGS.TRANSACTIONABLE) {
                this.transBlocks.push({ addr: addr, data: this.readBytes(addr, val.length) });
            }
            this.memData.setBytesAt(addr, val);
        };

        Segment.prototype.newAccessor = function newAccessor(addr, len, name) {
            return new Accessor(this, addr, len, name);
        };

        return Segment;
    })();

    exports.Segment = Segment;

    var Accessor = (function () {
        function Accessor(seg, addr, len, name) {
            _classCallCheck(this, Accessor);

            this.seg = seg;
            this.offset = addr;
            this.length = len;
            this.id = name;
        }

        Accessor.prototype.traceMemoryOp = function traceMemoryOp(op, addr, len, addr2) {
            if (this.id != "code") this.seg.memTraces.push({ op: op, name: this.id, addr: addr, len: len, addr2: addr2 });
        };

        Accessor.prototype.traceMemoryValue = function traceMemoryValue(val) {
            if (this.id != "code") {
                var memTrace = this.seg.memTraces[this.seg.memTraces.length - 1];
                memTrace.val = val;
            }
        };

        Accessor.prototype.zeroBytes = function zeroBytes(addr, len) {
            if (addr + len > this.length) {
                this.traceMemoryOp("ZR-error", addr, this.length);
                throw new Error("MM: Invalid Zero");
            }
            this.traceMemoryOp("ZR", addr, len);
            this.seg.zeroBytes(this.offset + addr, len);
            this.traceMemoryValue([0]);
        };

        Accessor.prototype.readByte = function readByte(addr) {
            if (addr + 1 > this.length) {
                this.traceMemoryOp("RD-error", addr, 1);
                throw new Error("MM: Invalid Read");
            }
            this.traceMemoryOp("RD", addr, 1);
            var val = this.seg.readByte(this.offset + addr);
            this.traceMemoryValue([val]);
            return val;
        };

        Accessor.prototype.readBytes = function readBytes(addr, len) {
            if (addr + len > this.length) {
                this.traceMemoryOp("RD-error", addr, len);
                throw new Error("MM: Invalid Read");
            }
            this.traceMemoryOp("RD", addr, len);
            var val = this.seg.readBytes(this.offset + addr, len);
            this.traceMemoryValue(val);
            return val;
        };

        Accessor.prototype.copyBytes = function copyBytes(fromAddr, toAddr, len) {
            if (fromAddr + len > this.length || toAddr + len > this.length) {
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
        };

        Accessor.prototype.writeByte = function writeByte(addr, val) {
            if (addr + 1 > this.length) {
                this.traceMemoryOp("WR-error", addr, 1);
                throw new Error("MM: Invalid Write");
            }
            this.traceMemoryOp("WR", addr, 1);
            this.seg.writeBytes(this.offset + addr, new _cryptographixSimCore.ByteArray([val]));
            this.traceMemoryValue([val]);
        };

        Accessor.prototype.writeBytes = function writeBytes(addr, val) {
            if (addr + val.length > this.length) {
                this.traceMemoryOp("WR-error", addr, val.length);
                throw new Error("MM: Invalid Write");
            }
            this.traceMemoryOp("WR", addr, val.length);
            this.seg.writeBytes(this.offset + addr, val);
            this.traceMemoryValue(val);
        };

        Accessor.prototype.getType = function getType() {
            return this.seg.getType();
        };

        Accessor.prototype.getLength = function getLength() {
            return this.length;
        };

        Accessor.prototype.getID = function getID() {
            return this.id;
        };

        Accessor.prototype.getDebug = function getDebug() {
            return { offset: this.offset, length: this.length, seg: this.seg };
        };

        return Accessor;
    })();

    exports.Accessor = Accessor;

    function sliceData(base, offset, size) {
        return base.subarray(offset, offset + size);
    }

    var MemoryManager = (function () {
        function MemoryManager() {
            _classCallCheck(this, MemoryManager);

            this.memorySegments = [];
            this.memTraces = [];
        }

        MemoryManager.prototype.newSegment = function newSegment(memType, size, flags) {
            var newSeg = new Segment(memType, size, flags);
            this.memorySegments[memType] = newSeg;
            newSeg.memTraces = this.memTraces;
            return newSeg;
        };

        MemoryManager.prototype.getMemTrace = function getMemTrace() {
            return this.memTraces;
        };

        MemoryManager.prototype.initMemTrace = function initMemTrace() {
            this.memTraces = [];
        };

        MemoryManager.prototype.getSegment = function getSegment(type) {
            return this.memorySegments[type];
        };

        return MemoryManager;
    })();

    exports.MemoryManager = MemoryManager;
    var MELINST;
    exports.MELINST = MELINST;
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
    })(MELINST || (exports.MELINST = MELINST = {}));
    ;
    var MELTAGADDR;
    exports.MELTAGADDR = MELTAGADDR;
    (function (MELTAGADDR) {
        MELTAGADDR[MELTAGADDR["melAddrTOS"] = 0] = "melAddrTOS";
        MELTAGADDR[MELTAGADDR["melAddrSB"] = 1] = "melAddrSB";
        MELTAGADDR[MELTAGADDR["melAddrST"] = 2] = "melAddrST";
        MELTAGADDR[MELTAGADDR["melAddrDB"] = 3] = "melAddrDB";
        MELTAGADDR[MELTAGADDR["melAddrLB"] = 4] = "melAddrLB";
        MELTAGADDR[MELTAGADDR["melAddrDT"] = 5] = "melAddrDT";
        MELTAGADDR[MELTAGADDR["melAddrPB"] = 6] = "melAddrPB";
        MELTAGADDR[MELTAGADDR["melAddrPT"] = 7] = "melAddrPT";
    })(MELTAGADDR || (exports.MELTAGADDR = MELTAGADDR = {}));
    ;
    var MELTAGCOND;
    exports.MELTAGCOND = MELTAGCOND;
    (function (MELTAGCOND) {
        MELTAGCOND[MELTAGCOND["melCondSPEC"] = 0] = "melCondSPEC";
        MELTAGCOND[MELTAGCOND["melCondEQ"] = 1] = "melCondEQ";
        MELTAGCOND[MELTAGCOND["melCondLT"] = 2] = "melCondLT";
        MELTAGCOND[MELTAGCOND["melCondLE"] = 3] = "melCondLE";
        MELTAGCOND[MELTAGCOND["melCondGT"] = 4] = "melCondGT";
        MELTAGCOND[MELTAGCOND["melCondGE"] = 5] = "melCondGE";
        MELTAGCOND[MELTAGCOND["melCondNE"] = 6] = "melCondNE";
        MELTAGCOND[MELTAGCOND["melCondALL"] = 7] = "melCondALL";
    })(MELTAGCOND || (exports.MELTAGCOND = MELTAGCOND = {}));
    ;
    var MELTAGSYSTEM;
    exports.MELTAGSYSTEM = MELTAGSYSTEM;
    (function (MELTAGSYSTEM) {
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemNOP"] = 0] = "melSystemNOP";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemSetSW"] = 1] = "melSystemSetSW";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemSetLa"] = 2] = "melSystemSetLa";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemSetSWLa"] = 3] = "melSystemSetSWLa";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemExit"] = 4] = "melSystemExit";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemExitSW"] = 5] = "melSystemExitSW";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemExitLa"] = 6] = "melSystemExitLa";
        MELTAGSYSTEM[MELTAGSYSTEM["melSystemExitSWLa"] = 7] = "melSystemExitSWLa";
    })(MELTAGSYSTEM || (exports.MELTAGSYSTEM = MELTAGSYSTEM = {}));
    ;
    var MELTAGSTACK;
    exports.MELTAGSTACK = MELTAGSTACK;
    (function (MELTAGSTACK) {
        MELTAGSTACK[MELTAGSTACK["melStackPUSHZ"] = 0] = "melStackPUSHZ";
        MELTAGSTACK[MELTAGSTACK["melStackPUSHB"] = 1] = "melStackPUSHB";
        MELTAGSTACK[MELTAGSTACK["melStackPUSHW"] = 2] = "melStackPUSHW";
        MELTAGSTACK[MELTAGSTACK["melStackXX4"] = 3] = "melStackXX4";
        MELTAGSTACK[MELTAGSTACK["melStackPOPN"] = 4] = "melStackPOPN";
        MELTAGSTACK[MELTAGSTACK["melStackPOPB"] = 5] = "melStackPOPB";
        MELTAGSTACK[MELTAGSTACK["melStackPOPW"] = 6] = "melStackPOPW";
        MELTAGSTACK[MELTAGSTACK["melStackXX7"] = 7] = "melStackXX7";
    })(MELTAGSTACK || (exports.MELTAGSTACK = MELTAGSTACK = {}));
    ;
    var MELTAGPRIMRET;
    exports.MELTAGPRIMRET = MELTAGPRIMRET;
    (function (MELTAGPRIMRET) {
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM0"] = 0] = "melPrimRetPRIM0";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM1"] = 1] = "melPrimRetPRIM1";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM2"] = 2] = "melPrimRetPRIM2";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetPRIM3"] = 3] = "melPrimRetPRIM3";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRET"] = 4] = "melPrimRetRET";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRETI"] = 5] = "melPrimRetRETI";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRETO"] = 6] = "melPrimRetRETO";
        MELTAGPRIMRET[MELTAGPRIMRET["melPrimRetRETIO"] = 7] = "melPrimRetRETIO";
    })(MELTAGPRIMRET || (exports.MELTAGPRIMRET = MELTAGPRIMRET = {}));
    ;
    var MELPARAMDEF;
    exports.MELPARAMDEF = MELPARAMDEF;
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
    })(MELPARAMDEF || (exports.MELPARAMDEF = MELPARAMDEF = {}));
    ;
    function MELPARAM4(a, b, c, d) {
        return d << 24 | c << 16 | b << 8 | a << 0;
    }
    function OPTAG2MELINST(opCode, tag) {
        return (opCode & 0x1f) << 3 | tag;
    }

    function MEL2OPCODE(byteCode) {
        return byteCode >> 3 & 0x1f;
    }

    function MEL2INST(byteCode) {
        return MEL2OPCODE(byteCode);
    }

    function MEL2TAG(byteCode) {
        return byteCode & 7;
    }

    ;
    function MELPARAMSIZE(paramType) {
        return paramType == MELPARAMDEF.melParamDefNone ? 0 : paramType < MELPARAMDEF.melParamDefWordImmediate ? 1 : 2;
    }

    var MEL = function MEL() {
        _classCallCheck(this, MEL);
    };

    exports.MEL = MEL;

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
    var MELDecode = MEL.melDecode;
    exports.MELDecode = MELDecode;
    var MEL_CCR_Z = 0x01;
    exports.MEL_CCR_Z = MEL_CCR_Z;
    var MEL_CCR_C = 0x02;

    exports.MEL_CCR_C = MEL_CCR_C;
    function hex(val) {
        return val.toString(16);
    }
    function hex2(val) {
        return ("00" + val.toString(16)).substr(-2);
    }
    function hex4(val) {
        return ("0000" + val.toString(16)).substr(-4);
    }
    function ljust(str, w) {
        return (str + Array(w + 1).join(" ")).substr(0, w);
    }
    function rjust(str, w) {
        return (Array(w + 1).join(" ") + str).substr(-w);
    }
    function BA2W(val) {
        return val[0] << 8 | val[1];
    }
    function W2BA(val) {
        return new _cryptographixSimCore.ByteArray([val >> 8, val & 0xFF]);
    }

    var MELVirtualMachine = (function () {
        function MELVirtualMachine() {
            _classCallCheck(this, MELVirtualMachine);

            this.segs = ["", "SB", "ST", "DB", "LB", "DT", "PB", "PT"];
        }

        MELVirtualMachine.prototype.initMVM = function initMVM(params) {
            this.romSegment = params.romSegment;
            this.ramSegment = params.ramSegment;
            this.publicArea = this.ramSegment.newAccessor(0, 512, "P");
        };

        MELVirtualMachine.prototype.disassembleCode = function disassembleCode(resetIP, stepToNextIP) {
            var dismText = "";
            function print(str) {
                dismText += str;
            }
            if (resetIP) this.currentIP = 0;
            if (this.currentIP >= this.codeArea.getLength()) return null;
            try {
                var nextIP = this.currentIP;
                var instByte = this.codeArea.readByte(nextIP++);
                var paramCount = 0;
                var paramVal = [];
                var paramDef = [];
                var melInst = MEL.MELDecode[instByte];
                if (melInst == undefined) {
                    print("[" + hex4(this.currentIP) + "]          " + ljust("ERROR:" + hex2(instByte), 8) + " ********\n");
                } else {
                    var paramDefs = melInst.paramDefs;
                    while (paramDefs != 0) {
                        paramDef[paramCount] = paramDefs & 0xFF;
                        switch (paramDefs & 0xF0) {
                            case 0x00:
                                break;
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
                    if (paramCount > 1 && (paramDef[0] == MEL.MELPARAMDEF.melParamDefByteOperLen || paramDef[0] == MEL.MELPARAMDEF.melParamDefByteImmediate || paramDef[0] == MEL.MELPARAMDEF.melParamDefWordImmediate) && paramDef[1] != MEL.MELPARAMDEF.melParamDefByteImmediate && paramDef[1] != MEL.MELPARAMDEF.melParamDefByteOperLen) {
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
                                if (v > 0) print("0x" + hex(v));else print(v);
                                break;
                            case MEL.MELPARAMDEF.melParamDefByteImmediate:
                                if (v > 0) print("0x" + hex(v));else print(v);
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
                                    if (v > 0) print("[0x" + hex(v) + "]");else print("[" + v + "]");
                                    break;
                                }
                        }
                        if (paramIndex < paramCount - 1) print(", ");
                    }
                    print("\n");
                }
                if (stepToNextIP) this.currentIP = nextIP;
            } catch (e) {
                print(e);
            }
            ;
            return dismText;
        };

        MELVirtualMachine.prototype.mapToSegmentAddr = function mapToSegmentAddr(addrTag, addrOffset) {
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
        };

        MELVirtualMachine.prototype.mapFromSegmentAddr = function mapFromSegmentAddr(segmentAddr) {
            if (segmentAddr & 0x8000) {
                if (segmentAddr >= 0xF000) {
                    return {
                        dataArea: this.publicArea,
                        dataAddrTag: MEL.MELTAGADDR.melAddrPB,
                        dataOffset: segmentAddr & 0x0FFF
                    };
                } else {
                    return {
                        dataArea: this.dynamicArea,
                        dataAddrTag: MEL.MELTAGADDR.melAddrDB,
                        dataOffset: segmentAddr & 0x3FFF
                    };
                }
            } else {
                return {
                    dataArea: this.staticArea,
                    dataAddrTag: MEL.MELTAGADDR.melAddrSB,
                    dataOffset: segmentAddr & 0x7FFF
                };
            }
        };

        MELVirtualMachine.prototype.checkDataAccess = function checkDataAccess(addrTag, offset, length) {
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
            if (dataOffset < areaLimit && dataOffset + length < areaLimit) {
                return {
                    dataArea: dataArea,
                    dataOffset: dataOffset
                };
            }
        };

        MELVirtualMachine.prototype.readSegmentData = function readSegmentData(addrTag, offset, length) {
            var targetAccess = this.checkDataAccess(addrTag, offset, 1);
            if (targetAccess == undefined) return;
            return targetAccess.dataArea.readBytes(targetAccess.dataOffset, length);
        };

        MELVirtualMachine.prototype.writeSegmentData = function writeSegmentData(addrTag, offset, val) {
            var targetAccess = this.checkDataAccess(addrTag, offset, 1);
            if (targetAccess == undefined) return;
            targetAccess.dataArea.writeBytes(targetAccess.dataOffset, val);
        };

        MELVirtualMachine.prototype.pushZerosToStack = function pushZerosToStack(cnt) {
            this.dynamicArea.zeroBytes(this.dynamicTop, cnt);
            this.dynamicTop += cnt;
        };

        MELVirtualMachine.prototype.pushConstToStack = function pushConstToStack(cnt, val) {
            if (cnt == 1) this.dynamicArea.writeBytes(this.dynamicTop, [val]);else this.dynamicArea.writeBytes(this.dynamicTop, W2BA(val));
            this.dynamicTop += cnt;
        };

        MELVirtualMachine.prototype.copyOnStack = function copyOnStack(fromOffset, toOffset, cnt) {
            this.dynamicArea.copyBytes(fromOffset, toOffset, cnt);
        };

        MELVirtualMachine.prototype.pushToStack = function pushToStack(addrTag, offset, cnt) {
            this.dynamicTop += cnt;
            this.dynamicArea.writeBytes(this.dynamicTop, this.readSegmentData(addrTag, offset, cnt));
        };

        MELVirtualMachine.prototype.popFromStackAndStore = function popFromStackAndStore(addrTag, offset, cnt) {
            this.dynamicTop -= cnt;
            this.writeSegmentData(addrTag, offset, this.dynamicArea.readBytes(this.dynamicTop, cnt));
        };

        MELVirtualMachine.prototype.popFromStack = function popFromStack(cnt) {
            this.dynamicTop -= cnt;
            return this.dynamicArea.readBytes(this.dynamicTop, cnt);
        };

        MELVirtualMachine.prototype.setupApplication = function setupApplication(execParams) {
            this.codeArea = execParams.codeArea;
            this.staticArea = execParams.staticArea;
            this.sessionSize = execParams.sessionSize;
            this.dynamicArea = this.ramSegment.newAccessor(0, 512, "D");
            this.initExecution();
        };

        MELVirtualMachine.prototype.initExecution = function initExecution() {
            this.currentIP = 0;
            this.isExecuting = true;
            this.localBase = this.sessionSize;
            this.dynamicTop = this.localBase;
            this.conditionCodeReg = 0;
        };

        MELVirtualMachine.prototype.constByteBinaryOperation = function constByteBinaryOperation(opCode, constVal, addrTag, addrOffset) {
            var targetAccess = this.checkDataAccess(addrTag, addrOffset, 1);
            if (targetAccess == undefined) return;
            var tempVal = targetAccess.dataArea.readByte(targetAccess.dataOffset);
            switch (opCode) {
                case MEL.MELINST.melADDB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = tempVal + constVal;
                    if (tempVal < constVal) this.conditionCodeReg |= MEL.MEL_CCR_C;
                    break;
                case MEL.MELINST.melSUBB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = tempVal - constVal;
                    if (tempVal > constVal) this.conditionCodeReg |= MEL.MEL_CCR_C;
                    break;
                case MEL.MELINST.melCMPB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = tempVal - constVal;
                    if (tempVal > constVal) this.conditionCodeReg |= MEL.MEL_CCR_C;
                    break;
                case MEL.MELINST.melSETB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = constVal;
                    break;
            }
            if (tempVal == 0) this.conditionCodeReg |= MEL.MEL_CCR_Z;
            if (opCode != MEL.MELINST.melCMPB) {
                targetAccess.dataArea.writeByte(targetAccess.dataOffset, tempVal);
            }
        };

        MELVirtualMachine.prototype.constWordBinaryOperation = function constWordBinaryOperation(opCode, constVal, addrTag, addrOffset) {
            var targetAccess = this.checkDataAccess(addrTag, addrOffset, 2);
            if (targetAccess == undefined) return;
            var tempVal = BA2W(targetAccess.dataArea.readBytes(targetAccess.dataOffset, 2));
            switch (opCode) {
                case MEL.MELINST.melADDB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = tempVal + constVal;
                    if (tempVal < constVal) this.conditionCodeReg |= MEL.MEL_CCR_C;
                    break;
                case MEL.MELINST.melSUBB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = tempVal - constVal;
                    if (tempVal > constVal) this.conditionCodeReg |= MEL.MEL_CCR_C;
                    break;
                case MEL.MELINST.melCMPB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = tempVal - constVal;
                    if (tempVal > constVal) this.conditionCodeReg |= MEL.MEL_CCR_C;
                    break;
                case MEL.MELINST.melSETB:
                    this.conditionCodeReg &= ~(MEL.MEL_CCR_C | MEL.MEL_CCR_Z);
                    tempVal = constVal;
                    break;
            }
            if (tempVal == 0) this.conditionCodeReg |= MEL.MEL_CCR_Z;
            if (opCode != MEL.MELINST.melCMPW) {
                targetAccess.dataArea.writeBytes(targetAccess.dataOffset, W2BA(tempVal));
            }
        };

        MELVirtualMachine.prototype.binaryOperation = function binaryOperation(opCode, opSize, addrTag, addrOffset) {
            var targetAccess = this.checkDataAccess(addrTag, addrOffset, 1);
            if (targetAccess == undefined) return;
            this.checkDataAccess(-opSize - 1, opSize, MEL.MELTAGADDR.melAddrTOS);
        };

        MELVirtualMachine.prototype.unaryOperation = function unaryOperation(opCode, opSize, addrTag, addrOffset) {
            var targetAccess = this.checkDataAccess(addrTag, addrOffset, 1);
            if (targetAccess == undefined) return;
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
        };

        MELVirtualMachine.prototype.handleReturn = function handleReturn(inBytes, outBytes) {
            var retValOffset = this.dynamicTop - outBytes;
            var returnIP = BA2W(this.dynamicArea.readBytes(this.localBase - 2, 2));
            this.localBase = BA2W(this.dynamicArea.readBytes(this.localBase - 4, 2));
            this.dynamicTop = this.localBase + outBytes;
            if (outBytes) this.copyOnStack(retValOffset, this.localBase, outBytes);
            return returnIP;
        };

        MELVirtualMachine.prototype.isCondition = function isCondition(tag) {
            switch (tag) {
                case MEL.MELTAGCOND.melCondEQ:
                    return this.conditionCodeReg & MEL.MEL_CCR_Z;
                case MEL.MELTAGCOND.melCondLT:
                    return !(this.conditionCodeReg & MEL.MEL_CCR_C);
                case MEL.MELTAGCOND.melCondLE:
                    return this.conditionCodeReg & MEL.MEL_CCR_Z || !(this.conditionCodeReg & MEL.MEL_CCR_C);
                case MEL.MELTAGCOND.melCondGT:
                    return this.conditionCodeReg & MEL.MEL_CCR_C;
                case MEL.MELTAGCOND.melCondGE:
                    return this.conditionCodeReg & MEL.MEL_CCR_Z || this.conditionCodeReg & MEL.MEL_CCR_C;
                case MEL.MELTAGCOND.melCondNE:
                    return !(this.conditionCodeReg & MEL.MEL_CCR_Z);
                case MEL.MELTAGCOND.melCondALL:
                    return true;
                default:
            }
            return false;
        };

        MELVirtualMachine.prototype.executeStep = function executeStep() {
            try {
                var nextIP = this.currentIP;
                var instByte = this.codeArea.readByte(nextIP++);
                var paramCount = 0;
                var paramVal = [];
                var paramDef = [];
                var melInst = MEL.MELDecode[instByte];
                if (melInst == undefined) {
                    return null;
                } else {
                    var paramDefs = melInst.paramDefs;
                    while (paramDefs != 0) {
                        paramDef[paramCount] = paramDefs & 0xFF;
                        switch (paramDefs & 0xF0) {
                            case 0x00:
                                break;
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
                        if (this.isCondition(tag)) nextIP = nextIP + paramVal[0];
                        break;
                    case MEL.MELINST.melJUMP:
                        if (this.isCondition(tag)) nextIP = paramVal[0];
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
                        } else this.pushToStack(tag, paramVal[1], paramVal[0]);
                        break;
                    case MEL.MELINST.melSTORE:
                        if (tag == MEL.MELTAGADDR.melAddrTOS) {
                            this.dynamicTop -= paramVal[0];
                            this.copyOnStack(this.dynamicTop, this.dynamicTop - paramVal[0], paramVal[0]);
                        } else this.popFromStackAndStore(tag, paramVal[1], paramVal[0]);
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
                        if (tag == MEL.MELTAGADDR.melAddrTOS) this.constByteBinaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -1);else this.constByteBinaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                        break;
                    case MEL.MELINST.melSETW:
                    case MEL.MELINST.melCMPW:
                    case MEL.MELINST.melADDW:
                    case MEL.MELINST.melSUBW:
                        if (tag == MEL.MELTAGADDR.melAddrTOS) this.constWordBinaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -2);else this.constWordBinaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                        break;
                    case MEL.MELINST.melCLEARN:
                    case MEL.MELINST.melTESTN:
                    case MEL.MELINST.melINCN:
                    case MEL.MELINST.melDECN:
                    case MEL.MELINST.melNOTN:
                        if (tag == MEL.MELTAGADDR.melAddrTOS) this.unaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -1 * paramVal[0]);else this.unaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                        break;
                    case MEL.MELINST.melCMPN:
                    case MEL.MELINST.melADDN:
                    case MEL.MELINST.melSUBN:
                    case MEL.MELINST.melANDN:
                    case MEL.MELINST.melORN:
                    case MEL.MELINST.melXORN:
                        if (tag == MEL.MELTAGADDR.melAddrTOS) this.binaryOperation(opCode, paramVal[0], MEL.MELTAGADDR.melAddrDT, -2 * paramVal[0]);else this.binaryOperation(opCode, paramVal[0], tag, paramVal[1]);
                        break;
                }
                this.currentIP = nextIP;
            } catch (e) {}
        };

        MELVirtualMachine.prototype.setCommandAPDU = function setCommandAPDU(commandAPDU) {
            var publicTop = this.publicArea.getLength();
            this.publicArea.writeBytes(publicTop - 2, W2BA(0x9000));
            this.publicArea.writeBytes(publicTop - 4, W2BA(0x0000));
            this.publicArea.writeBytes(publicTop - 6, W2BA(commandAPDU.Le));
            this.publicArea.writeBytes(publicTop - 8, W2BA(commandAPDU.data.length));
            this.publicArea.writeBytes(publicTop - 13, commandAPDU.header);
            this.publicArea.writeBytes(0, commandAPDU.data);
            this.initExecution();
        };

        MELVirtualMachine.prototype.getResponseAPDU = function getResponseAPDU() {
            var publicTop = this.publicArea.getLength();
            var la = BA2W(this.publicArea.readBytes(publicTop - 4, 2));
            return new ResponseAPDU({ sw: BA2W(this.publicArea.readBytes(publicTop - 2, 2)), data: this.publicArea.readBytes(0, la) });
        };

        _createClass(MELVirtualMachine, [{
            key: 'getDebug',
            get: function get() {
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
        }]);

        return MELVirtualMachine;
    })();

    exports.MELVirtualMachine = MELVirtualMachine;

    function BA2W(val) {
        return val[0] << 8 | val[1];
    }

    var JSIMMultosApplet = function JSIMMultosApplet(codeArea, staticArea, sessionSize) {
        _classCallCheck(this, JSIMMultosApplet);

        this.codeArea = codeArea;
        this.staticArea = staticArea;
        this.sessionSize = sessionSize;
    };

    exports.JSIMMultosApplet = JSIMMultosApplet;

    var JSIMMultosCard = (function () {
        function JSIMMultosCard(config) {
            _classCallCheck(this, JSIMMultosCard);

            if (config) this.cardConfig = config;else this.cardConfig = JSIMMultosCard.defaultConfig;
            this.atr = new _cryptographixSimCore.ByteArray([]);
            this.applets = [];
        }

        JSIMMultosCard.prototype.loadApplication = function loadApplication(aid, alu) {
            var len = 0;
            var off = 8;
            len = alu.wordAt(off);
            off += 2;
            var codeArea = this.nvramSegment.newAccessor(0, len, "code");
            codeArea.writeBytes(0, alu.viewAt(off, len));
            off += len;
            len = alu.wordAt(off);
            off += 2;
            var staticArea = this.nvramSegment.newAccessor(codeArea.getLength(), len, "S");
            staticArea.writeBytes(0, alu.viewAt(off, len));
            off += len;
            var applet = new JSIMMultosApplet(codeArea, staticArea, 0);
            this.applets.push({ aid: aid, applet: applet });
        };

        JSIMMultosCard.prototype.powerOn = function powerOn() {
            this.powerIsOn = true;
            this.initializeVM(this.cardConfig);
            return Promise.resolve(this.atr);
        };

        JSIMMultosCard.prototype.powerOff = function powerOff() {
            this.powerIsOn = false;
            this.resetVM();
            this.selectedApplet = undefined;
            return Promise.resolve();
        };

        JSIMMultosCard.prototype.reset = function reset() {
            this.powerIsOn = true;
            this.selectedApplet = undefined;
            this.shutdownVM();
            return Promise.resolve(this.atr);
        };

        JSIMMultosCard.prototype.exchangeAPDU = function exchangeAPDU(commandAPDU) {
            if (commandAPDU.INS == 0xA4) {
                if (this.selectedApplet) {
                    this.selectedApplet = undefined;
                }
                this.selectedApplet = this.applets[0].applet;
                var fci = new _cryptographixSimCore.ByteArray([0x6F, 0x00]);
                this.mvm.setupApplication(this.selectedApplet);
                return Promise.resolve(new ResponseAPDU({ sw: 0x9000, data: fci }));
            }
            this.mvm.setCommandAPDU(commandAPDU);
            return Promise.resolve(new ResponseAPDU({ sw: 0x9000, data: [] }));
        };

        JSIMMultosCard.prototype.initializeVM = function initializeVM(config) {
            this.memoryManager = new MemoryManager();
            this.romSegment = this.memoryManager.newSegment(0, this.cardConfig.romSize, MEMFLAGS.READ_ONLY);
            this.ramSegment = this.memoryManager.newSegment(1, this.cardConfig.ramSize, 0);
            this.nvramSegment = this.memoryManager.newSegment(2, this.cardConfig.nvramSize, MEMFLAGS.TRANSACTIONABLE);
            this.mvm = new MELVirtualMachine();
            this.resetVM();
        };

        JSIMMultosCard.prototype.resetVM = function resetVM() {
            var mvmParams = {
                ramSegment: this.ramSegment,
                romSegment: this.romSegment,
                publicSize: this.cardConfig.publicSize
            };
            this.mvm.initMVM(mvmParams);
        };

        JSIMMultosCard.prototype.shutdownVM = function shutdownVM() {
            this.resetVM();
            this.mvm = null;
        };

        JSIMMultosCard.prototype.selectApplication = function selectApplication(applet, sessionSize) {
            var execParams = {
                codeArea: applet.codeArea,
                staticArea: applet.staticArea,
                sessionSize: sessionSize
            };
            this.mvm.execApplication(execParams);
        };

        JSIMMultosCard.prototype.executeStep = function executeStep() {
            return this.mvm.executeStep();
        };

        _createClass(JSIMMultosCard, [{
            key: 'isPowered',
            get: function get() {
                return this.powerIsOn;
            }
        }]);

        return JSIMMultosCard;
    })();

    exports.JSIMMultosCard = JSIMMultosCard;

    JSIMMultosCard.defaultConfig = {
        romSize: 0,
        ramSize: 1024,
        publicSize: 512,
        nvramSize: 32768
    };

    var setZeroPrimitives = {
        0x01: {
            name: "CHECK_CASE",
            proc: function proc() {}
        },
        0x02: {
            name: "RESET_WWT",
            proc: function proc() {}
        },
        0x05: {
            name: "LOAD_CCR",
            proc: function proc() {}
        },
        0x06: {
            name: "STORE_CCR",
            proc: function proc() {}
        },
        0x07: {
            name: "SET_ATR_FILE_RECORD",
            proc: function proc() {}
        },
        0x08: {
            name: "SET_ATR_HISTORICAL_CHARACTERS",
            proc: function proc() {}
        },
        0x09: {
            name: "GET_MEMORY_RELIABILITY",
            proc: function proc() {}
        },
        0xa: {
            name: "LOOKUP",
            proc: function proc() {}
        },
        0xb: {
            name: "MEMORY_COMPARE",
            proc: function proc() {}
        },
        0xc: {
            name: "MEMORY_COPY",
            proc: function proc() {}
        },
        0xd: {
            name: "QUERY_INTERFACE_TYPE",
            proc: function proc() {}
        },
        0x10: {
            name: "CONTROL_AUTO_RESET_WWT",
            proc: function proc() {}
        },
        0x11: {
            name: "SET_FCI_FILE_RECORD",
            proc: function proc() {}
        },
        0x80: {
            name: "DELEGATE",
            proc: function proc() {}
        },
        0x81: {
            name: "RESET_SESSION_DATA",
            proc: function proc() {}
        },
        0x82: {
            name: "CHECKSUM",
            proc: function proc() {}
        },
        0x83: {
            name: "CALL_CODELET",
            proc: function proc() {}
        },
        0x84: {
            name: "QUERY_CODELET",
            proc: function proc() {}
        },
        0xc1: {
            name: "DES_ECB_ENCIPHER",
            proc: function proc() {}
        },
        0xc2: {
            name: "MODULAR_MULTIPLICATION",
            proc: function proc() {}
        },
        0xc3: {
            name: "MODULAR_REDUCTION",
            proc: function proc() {}
        },
        0xc4: {
            name: "GET_RANDOM_NUMBER",
            proc: function proc() {}
        },
        0xc5: {
            name: "DES_ECB_DECIPHER",
            proc: function proc() {}
        },
        0xc6: {
            name: "GENERATE_DES_CBC_SIGNATURE",
            proc: function proc() {}
        },
        0xc7: {
            name: "GENERATE_TRIPLE_DES_CBC_SIGNATURE",
            proc: function proc() {}
        },
        0xc8: {
            name: "MODULAR_EXPONENTIATION",
            proc: function proc() {}
        },
        0xc9: {
            name: "MODULAR_EXPONENTIATION_CRT",
            proc: function proc() {}
        },
        0xca: {
            name: "SHA1",
            proc: function proc() {}
        },
        0xcc: {
            name: "GENERATE_RANDOM_PRIME",
            proc: function proc() {}
        },
        0xcd: {
            name: "SEED_ECB_DECIPHER",
            proc: function proc() {}
        },
        0xce: {
            name: "SEED_ECB_ENCIPHER",
            proc: function proc() {}
        }
    };
    var setOnePrimitives = {
        0x00: {
            name: "QUERY0",
            proc: function proc() {}
        },
        0x01: {
            name: "QUERY1",
            proc: function proc() {}
        },
        0x02: {
            name: "QUERY2",
            proc: function proc() {}
        },
        0x03: {
            name: "QUERY3",
            proc: function proc() {}
        },
        0x08: {
            name: "DIVIDEN",
            proc: function proc() {}
        },
        0x09: {
            name: "GET_DIR_FILE_RECORD",
            proc: function proc() {}
        },
        0x0a: {
            name: "GET_FILE_CONTROL_INFORMATION",
            proc: function proc() {}
        },
        0x0b: {
            name: "GET_MANUFACTURER_DATA",
            proc: function proc() {}
        },
        0x0c: {
            name: "GET_MULTOS_DATA",
            proc: function proc() {}
        },
        0x0d: {
            name: "GET_PURSE_TYPE",
            proc: function proc() {}
        },
        0x0e: {
            name: "MEMORY_COPY_FIXED_LENGTH",
            proc: function proc() {}
        },
        0x0f: {
            name: "MEMORY_COMPARE_FIXED_LENGTH",
            proc: function proc() {}
        },
        0x10: {
            name: "MULTIPLYN",
            proc: function proc() {}
        },
        0x80: {
            name: "SET_TRANSACTION_PROTECTION",
            proc: function proc() {}
        },
        0x81: {
            name: "GET_DELEGATOR_AID",
            proc: function proc() {}
        },
        0xc4: {
            name: "GENERATE_ASYMMETRIC_HASH",
            proc: function proc() {}
        }
    };
    function bitManipulate(bitmap, literal, data) {
        var modify = (bitmap & 1 << 7) == 1 << 7;
        if (bitmap & 0x7c) throw new Error("Undefined arguments");
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
            proc: function proc() {}
        },
        0x02: {
            name: "SHIFT_LEFT",
            proc: function proc() {}
        },
        0x03: {
            name: "SHIFT_RIGHT",
            proc: function proc() {}
        },
        0x04: {
            name: "SET_SELECT_SW",
            proc: function proc() {}
        },
        0x05: {
            name: "CARD_BLOCK",
            proc: function proc() {}
        },
        0x80: {
            name: "RETURN_FROM_CODELET",
            proc: function proc() {}
        }
    };
    var setThreePrimitives = {
        0x01: {
            name: "BIT_MANIPULATE_WORD",
            proc: function proc() {}
        },
        0x80: {
            name: "CALL_EXTENSION_PRIMITIVE0",
            proc: function proc() {}
        },
        0x81: {
            name: "CALL_EXTENSION_PRIMITIVE1",
            proc: function proc() {}
        },
        0x82: {
            name: "CALL_EXTENSION_PRIMITIVE2",
            proc: function proc() {}
        },
        0x83: {
            name: "CALL_EXTENSION_PRIMITIVE3",
            proc: function proc() {}
        },
        0x84: {
            name: "CALL_EXTENSION_PRIMITIVE4",
            proc: function proc() {}
        },
        0x85: {
            name: "CALL_EXTENSION_PRIMITIVE5",
            proc: function proc() {}
        },
        0x86: {
            name: "CALL_EXTENSION_PRIMITIVE6",
            proc: function proc() {}
        }
    };
    var primitiveSets = [setZeroPrimitives, setOnePrimitives, setTwoPrimitives, setThreePrimitives];

    function callPrimitive(ctx, prim, set, arg1, arg2, arg3) {
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
        } else {
            throw new Error("Primitive not Implemented");
        }
    }

    var SecurityManager = (function () {
        function SecurityManager() {
            _classCallCheck(this, SecurityManager);
        }

        SecurityManager.prototype.initSecurity = function initSecurity() {};

        SecurityManager.prototype.processAPDU = function processAPDU(apdu) {
            return false;
        };

        return SecurityManager;
    })();

    exports.SecurityManager = SecurityManager;

    var ADC = function ADC() {
        _classCallCheck(this, ADC);
    };

    exports.ADC = ADC;

    var ALC = function ALC() {
        _classCallCheck(this, ALC);
    };

    exports.ALC = ALC;

    var ALU = (function () {
        function ALU(attributes) {
            _classCallCheck(this, ALU);

            this.code = new _cryptographixSimCore.ByteArray();
            this.data = new _cryptographixSimCore.ByteArray();
            this.fci = new _cryptographixSimCore.ByteArray();
            this.dir = new _cryptographixSimCore.ByteArray();
            if (attributes) {
                for (var field in ALU.kindInfo.fields) {
                    if (attributes[field.id]) this[field.id] = attributes[field.id];
                }
            }
        }

        ALU.prototype.toJSON = function toJSON() {
            return {
                code: this.code,
                data: this.data,
                fci: this.fci,
                dir: this.dir
            };
        };

        ALU.prototype.getALUSegment = function getALUSegment(bytes, segmentID) {
            var offset = 8;
            while (segmentID > 1 && offset < bytes.length) {
                offset += 2 + bytes.wordAt(offset);
                --segmentID;
            }
            return bytes.viewAt(offset + 2, bytes.wordAt(offset));
        };

        ALU.prototype.decodeBytes = function decodeBytes(bytes, options) {
            this.code = this.getALUSegment(bytes, 1);
            this.data = this.getALUSegment(bytes, 2);
            this.dir = this.getALUSegment(bytes, 3);
            this.fci = this.getALUSegment(bytes, 4);
            return this;
        };

        ALU.prototype.encodeBytes = function encodeBytes(options) {
            return new _cryptographixSimCore.ByteArray([]);
        };

        return ALU;
    })();

    exports.ALU = ALU;

    _cryptographixSimCore.KindBuilder.init(ALU, "MULTOS Application Load Unit").field("code", "Code Segment", _cryptographixSimCore.ByteArray).field("data", "Data Segment", _cryptographixSimCore.ByteArray).field("fci", "FCI Segment", _cryptographixSimCore.ByteArray).field("dir", "DIR Segment", _cryptographixSimCore.ByteArray);
});