'use strict';
const binding = require(`./build/Release/test`);

const rsa_private_key = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
"MIICoTAbBgkqhkiG9w0BBQMwDgQIZaaYSta+xyECAggABIICgG1tpsGMdE9IE26N\n" + 
"lLkBo74QntMCvmkiNhhFCMvaQdiL5CowmsDB/fGJ/jHnrZZaym98WBAsQjcVcPdI\n" +
"IIYe0J/dyQuU7dENoXLRG2QyRhuo2AZlgMg5Jn1OLjAg3wp2/1Spb/z8WfE3FcDv\n" +
"14NTePWpUi/6NDULDe53H9G8YurDRGc/jLCZtcRlxKLbWV6ZYkJy3acFABzAG22O\n" +
"Auwu25af1VjHe+YJuUo16QHX9K6sDCWSE6ZlrtjrfBQyfqPUhj0DN7x+YK6qzfLP\n" +
"7MiU/FmjtX/nDYyAxzhk5/dTPc9XJcuqALebFYMG+58Mvb66F+M4ifLPFc0b3C7k\n" +
"b0iiDwp3vCJxuxchoQxvzEcXdCEq0l8vToipKOH/gPJlmh7qaHX9/iaEaQi4gwmX\n" +
"4lbFWiA72f7fAGePAIj03QWjOBk+YPOrcPmywO6i3SOGmEeVE///getqeWWM1ml3\n" +
"XmfTHpqil3U284dcvL9HbgXuF/oZCAF9gGOF5OZ0mc8wygfweYoids9M0OO7lVxe\n" +
"PQ5jY4jT2BTl4ArUapufIbBBamQLsfNR5rIkYu9bY2DuEadN2ikLzGk8pr0/2x+d\n" +
"scP3hgxgYKIW+EnjIRHD84NLcQHZEOnC+4XG8M3lBbJQxCHuaKVmRSitl/58Fo31\n" +
"6SDpqMHQ+ZJOQc/GaULhg77HOSW/cIB3j3NHNVsu+mohRS2WV6aZcCgQ28Mbw2lK\n" +
"3amB1WQ+jkamap5bqm1yEy0b4czGma3wqers4vm8wogSHPJVoP+w2hWQWsLWKHFH\n" +
"on9ZjtwvofwMiB0SzjTUO1dc+KTVag9Q9nhYnCy6Ry6ffLAeR1ZsMYE36tHa1wHG\n" +
"IK5OYIg=\n" +
"-----END ENCRYPTED PRIVATE KEY-----";

const rsa_public_key = "-----BEGIN PUBLIC KEY-----\n" +
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxxjGoXL0b33mQEap05ES\n" +
"F9Fws4lTqqv5g/xt6c3JHsEWjRsCAo9lGX0jWohWWlQecJ3MbuguHszLcNctCfa5\n" +
"QMjrcj/LhT+o5kBpjtxndGkw6CloRlFLUXNugta3VmDt5lVBtPmloEuGdjtKf/wS\n" +
"hAD439KgTDjRm2bo1yqg+/pNqF882foTphJ7UR0N/9BKHFOChxZ4IsKeke3SvEKy\n" +
"Yr98vUpQa2YkD4iGC6H2laPwJg5kzA3Gb44uvazX3hyqGJQsKayUMgFyasssW/KZ\n" +
"kbReveFTS1bqGbWtJcFRoSSzX+RIyVZm61xtorwQhdnQC1SUv14Tbx5Foa0VpTUt\n" +
"hwIDAQAB\n" +
"-----END PUBLIC KEY-----";

var str = "45678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890456789045678904567890abcdefghijklmnopqrstuvwxyz";

try {
    var res = binding.encrypt(0, "rsa_private_key.pem", 1, 0, str);
    console.log(res);
    console.log("");
    res = binding.decrypt(0, "rsa_public_key.pem", 1, 0, res);
    console.log(res);
} catch (e) {
    console.log(e.toString());
}
