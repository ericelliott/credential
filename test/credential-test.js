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

test('constantEquals', function (t) {
  var ctc = require('../constantTimeCompare');

  function timed_compare(a, b) {
    var start = process.hrtime();
    ctc(a, b);
    return process.hrtime(start)[1];
  }
  var i,
      iterations = 5000,
      equal_results = 0,
      inequal_results = 0,
      difflen_results = 0;
  // Ensure it works
  t.ok(ctc("abc", "abc"), 'equality')
  t.ok(ctc("", ""), 'equal empty')
  t.ok(!ctc("a", ""), 'inequal 1-char')
  t.ok(ctc("a", "a"), 'equal 1-char')
  t.ok(!ctc("ab", "ac"), 'inequal 2-char')
  t.ok(ctc("ab", "ab"), 'equal 2-char')
  t.ok(!ctc("abc", "abC"), 'inequality - difference')
  t.ok(!ctc("abc", "abcD"), 'inequality - addition')
  t.ok(!ctc("abc", "ab"), 'inequality - missing')

  // Ensure timing is sane
  // Differing lengths
  for (i = 0; i < iterations; i++) {
    difflen_results += timed_compare("abcd", "abcdefghijklmnopqrstuvwxyz");
  }

  for (i = 0; i < iterations; i++) {
    equal_results   += timed_compare("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz");
  }

  for (i = 0; i < iterations; i++) {
    inequal_results += timed_compare("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  }

  // This is a point of some statistical importance. A tolerance of 
  // 0.05 is not actually particularly useful; it must be combined
  // with the time-per-iteration and number of iterations to ensure
  // that there is no statistically significant difference that
  // illuminates what's happening in the comparison.
  // 
  // So `tolerance` here is really just a placeholder until a more
  // sensible statistically sound comparison can be teased out of this test.
  var tolerance = 0.05;
  t.ok(Math.abs((equal_results - inequal_results)/equal_results) < tolerance,
      "inequal and equal results within " + tolerance)
  t.ok(Math.abs((equal_results - difflen_results)/equal_results) < tolerance, 
      "differing-lengths and equal results within " + tolerance)
  t.end()
});


test('overrides', function (t) {
  var workUnits = 60;
  var workKey = 463;
  var keyLength = 12;
  pw.configure({
    workUnits: workUnits,
    workKey: workKey,
    keyLength: keyLength
  });

  pw.hash('foo', function (err, hash) {

    t.equal(pw.workUnits, workUnits,
      'should allow workUnits override');

    t.equal(JSON.parse(hash).keyLength, keyLength,
      'should allow keylength override');
    t.end();
  });
});
