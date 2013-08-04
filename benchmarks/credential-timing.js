/**
 * In the case of password hash timing, slower is more secure.
 *
 * The sweet spot is a time that won't annoy users, but will
 * significantly delay a brute-force attack.
 */

'use strict';
var crypto = require('crypto'),
  pw = require('../credential.js');

function testMd5() {
  var i,
    length = 100,
    s = new Date().getTime(),
    hash;

  for (i = 0; i < length; i++) {
    hash = crypto.createHash('md5');
    hash.update(
      (Math.random()*Math.pow(36, 14)).toString(36)
    );
    console.log(hash.digest('base64'));
  }

  return (new Date().getTime() - s);
}

function testCredential(callback) {
  var i = 0,
    l = 100,
    d = 0,
    s = new Date().getTime(),
    inc = function () {
      d++;
    };

  for (i = 0; i < l; i++) {
    pw.hash((Math.random()*Math.pow(36, 14)).toString(36),
      inc);
  }

  (function check() {
    setTimeout(function () {
      var f;
      if (d===l) {
        f = (new Date().getTime() -s);
        return callback(f);
      }
      check();
    }, 0);
  }());
}

module.exports = {
  testMd5: testMd5,
  testCredential: testCredential
};
