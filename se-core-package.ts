import PackageInfo from "../../sim-core/base/package-info";

import * as GPScript from "./gpscript/gpscript-package";
import * as MULTOS from "./multos/multos-package";

var $packageInfo: PackageInfo = {
  title: "seCore",

  description: "SE:Core",

  author: "SE:Core Team",

  members: {
    "GPScript": GPScript,
    "MULTOS": MULTOS,
  }
};

export {
  $packageInfo,
  GPScript,
  MULTOS,
};
