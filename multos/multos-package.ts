import PackageInfo from "../../../sim-core/base/package-info";
import ALU from "./ALU";

var $packageInfo : PackageInfo = {
  title: "seCore.MULTOS",

  description: "simCore simulation for MULTOS Card Operating System",

  author: "SE:Core Team",

  members: {
    "ALU": ALU

  }
}

export {
  $packageInfo,
  ALU,
};
