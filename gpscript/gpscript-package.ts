import PackageInfo from "../../../sim-core/base/package-info";

import ByteString from "./byte-string";
import ByteBuffer from "./byte-buffer";
import Crypto from "./crypto";
import Key from "./key";
import TLV from "./tlv";
import TLVList from "./tlv-list";

var $packageInfo : PackageInfo = {
  title: "seCore.GPScript",

  description: "GlobalPlatform Scripting",

  author: "SE:Core Team",

  members: {
    "ByteString": ByteString,
    "ByteBuffer": ByteBuffer,
    "Crypto": Crypto,
    "Key": Key,
    "TLV": TLV,
    "TLVList": TLVList
  }
};

export {
  $packageInfo,
  ByteString,
  ByteBuffer,
  Crypto,
  Key,
  TLV,
  TLVList
};
