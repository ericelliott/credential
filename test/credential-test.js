'use strict';
var test = require('tape'),
  pw = require('../credential.js');

test('hash', function (t) {

  pw.hash('foo', function (err, hash) {

    t.equal(typeof hash, 'string',
      'should produce a hash string.');

    t.ok(JSON.parse(hash).hash,
      'should a json object representing the hash.');

    t.end();
  });

});

test('hash with different passwords', function (t) {

  pw.hash('foo', function (err, fooHash) {

    pw.hash('bar', function (err, barHash) {

      t.notEqual(fooHash, barHash,
        'should produce a different hash.');

      t.end();
    });
  });
});

test('hash with same passwords', function (t) {

  pw.hash('foo', function (err, fooHash) {

    pw.hash('foo', function (err, barHash) {

      t.notEqual(fooHash, barHash,
        'should produce a different hash.');

      t.end();
    });
  });
});

test('hash with undefined password', function(t) {

  try {
    pw.hash(undefined, function(err) {
      t.ok(err,
        'should cause error.');
      t.end();
    });
  } catch (e) {
    t.fail('should not throw');
  }

});

test('hash with empty password', function(t) {

  try {
    pw.hash("", function(err) {
      t.ok(err,
        'should cause error.');
      t.end();
    });
  } catch (e) {
    t.fail('should not throw');
  }

});


test('verify with right pw', function (t) {
  var pass = 'foo';

  pw.hash(pass, function (err, storedHash) {
    pw.verify(storedHash, pass, function (err, isValid) {
      t.error(err,
        'should not cause error.');

      t.ok(isValid,
        'should return true for matching password.');
      t.end();
    });
  });

});

test('verify with broken stored hash', function (t) {
  var pass = 'foo',
    storedHash = 'aoeuntkh;kbanotehudil,.prcgidax$aoesnitd,riouxbx;qjkwmoeuicgr';

  pw.verify(storedHash, pass, function (err) {

    t.ok(err,
      'should cause error.');

    t.end();
  });

});


test('verify with wrong pw', function (t) {
  var pass = 'foo';

  pw.hash(pass, function (err, storedHash) {
    pw.verify(storedHash, 'bar', function (err, isValid) {
      t.ok(!isValid,
        'should return false for matching password.');
      t.end();
    });
  });

});

test('verify with undefined password', function(t) {
  var pass = 'foo';

  pw.hash(pass, function (err, storedHash) {
    try {
      pw.verify(storedHash, undefined, function(err, isValid) {
        t.ok(!isValid,
          'should return false for matching password.');
        t.ok(err,
          'should cause error.');
        t.end();
      });
    } catch (e) {
      t.fail('should not throw');
    }
  });

});

test('verify with empty password', function(t) {
  var pass = 'foo';
  
  pw.hash(pass, function (err, storedHash) {
    try {
      pw.verify(storedHash, "", function(err, isValid) {
        t.ok(!isValid,
          'should return false for matching password.');
        t.ok(err,
          'should cause error.');
        t.end();
      });
    } catch (e) {
      t.fail('should not throw');
    }
  });

});

test('verify with legacy hash (default workKey)', function (t) {
  var pass = 'foo',
    storedHash = '{"hash":"y7rqv8KRSlZSlCyZHHMF/DJskppsa3/buewuvswqf6ISqYurNCBKCU41DC1BO+XYxb6OPWRIPAH2TiOK+CeEc42N","salt":"qkMhX7h8sH7MMUvkYaVXPmz7oXhs1CAjuxmNdj/WQCKUGNUBVLg/0rYY03mVsWoYRcVg/wD+tTGEcgesdMD1IfJl","keyLength":66,"hashMethod":"pbkdf2","workUnits":60}';

  pw.verify(storedHash, pass, function (err, isValid) {
    t.error(err,
      'should not cause error.');

    t.ok(isValid,
      'should return true for matching password.');
    t.end();
  });
});

test('verify with legacy hash (custom workKey and workUnits)', function (t) {
  var pass = 'foo',
    storedHash = '{"hash":"k8WWmP2ROCeZiBVuIyi+EOFWwbIh2nPSncsSAi1PYNimGMrE51ynK5qJTIlNDCy3kqHBQpyl2NJ1wZ5hyX/wFRt1","salt":"UXnjqZ1cemn2fWFB0Pa/rgsEKkMIeTYulDOJrLA3km1A0903uud44cJt0zXbbsg8SYivGzpjWLJDUbH9Ym7xMC0o","keyLength":66,"hashMethod":"pbkdf2","workUnits":70}';

  var originalWorkKey = pw.workKey;

  pw.workKey = 400;

  pw.verify(storedHash, pass, function (err, isValid) {
    t.error(err,
      'should not cause error.');

    t.ok(isValid,
      'should return true for matching password.');
    t.end();
  });

  pw.workKey = originalWorkKey;
});

test('expired with valid hash and default expiry', function(t) {
  var pass = 'foo';

  pw.hash(pass, function (err, storedHash) {
    t.notOk(pw.expired(storedHash),
      'should return false when expiry is default.');
    t.end();
  });

});

test('expired with short expiry', function(t) {
  var pass = 'foo';

  pw.hash(pass, function (err, storedHash) {
    t.notOk(pw.expired(storedHash, 2),
      'should return false when expiry is default.');
    t.end();
  });

});

test('expired with expiry in the past', function(t) {
  var pass = 'foo';

  pw.hash(pass, function (err, storedHash) {
    t.ok(pw.expired(storedHash, -2),
      'should return true when expiry is in the future.');
    t.end();
  });

});

test('overrides', function (t) {
  var workUnits = 50;
  var workKey = 463;
  var keyLength = 12;
  pw.configure({
    workUnits: workUnits,
    workKey: workKey,
    keyLength: keyLength
  });

  pw.hash('foo', function (err, hash) {

    t.equal(JSON.parse(hash).iterations, pw.iterations(workUnits / 60),
      'should allow workUnits override');

    t.equal(JSON.parse(hash).keyLength, keyLength,
      'should allow keylength override');
    t.end();
  });
});
