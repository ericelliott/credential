'use strict';
var test = require('tape'),
  childProcess = require('child_process'),
  credential = require('../credential');

function execCli (args, cb) {

  var child = childProcess.execFile(
    process.execPath,
    ['../bin/cmd.js'].concat(args),
    {cwd: __dirname},
    cb);

  return child.stdin;
}

test('cli - hash', function (t){
  var stdin = execCli(['hash', 'password'], function (err, stdout){
    t.ifError(err);

    credential().verify(stdout, 'password', function (err, valid){
      t.ifError(err);

      t.ok(valid);

      t.end();
    });
  });

  stdin.end();
});

test('cli - hash - stdin', function (t){
  var stdin = execCli(['hash', '-'], function (err, stdout){
    t.ifError(err);

    credential().verify(stdout, 'password', function (err, valid){
      t.ifError(err);

      t.ok(valid);

      t.end();
    });
  });

  stdin.write('password');
  stdin.end();
});

test('cli - verify', function (t){
  credential().hash('password', function (err, hash){
    t.ifError(err);

    var stdin = execCli(['verify', hash, 'password'], function (err, stdout){
      t.ifError(err);

      var actual = stdout.trim();
      var expected = 'Verified';

      t.is(actual, expected);

      t.end();
    });

    stdin.end();
  });
});

test('cli - verify - stdin', function (t){

  credential().hash('password', function (err, hash){
    t.ifError(err);

    var stdin = execCli(['verify', '-', 'password'], function (err, stdout){
      t.ifError(err);

      var actual = stdout.trim();
      var expected = 'Verified';

      t.is(actual, expected);

      t.end();
    });

    stdin.write(hash);
    stdin.end();
  });
});

test('cli - hash - no password', function (t){
  var stdin = execCli(['hash'], function (err, stdout, stderr){
    t.ifError(err);

    var actual = stderr.trim();
    var expected = /Error: Password must be a non-empty string/;

    t.ok(expected.test(actual));

    t.end();
  });

  stdin.end();
});

test('cli - expired', function (t){
  credential().hash('password', function (err, hash){
    t.ifError(err);

    var stdin = execCli(['expired', hash, 90], function (err, stdout){
      t.ifError(err);

      var actual = stdout.trim();
      var expected = 'Not expired';

      t.is(actual, expected);

      t.end();
    });

    stdin.end();
  });
});

test('cli - expired - stdin', function (t){

  credential().hash('password', function (err, hash){
    t.ifError(err);

    var stdin = execCli(['expired', '-', 90], function (err, stdout){
      t.ifError(err);

      var actual = stdout.trim();
      var expected = 'Not expired';

      t.is(actual, expected);

      t.end();
    });

    stdin.write(hash);
    stdin.end();
  });
});

test('cli - expired - without days argument', function (t){
  credential().hash('password', function (err, hash){
    t.ifError(err);

    var stdin = execCli(['expired', hash], function (err, stdout){
      t.ifError(err);

      var actual = stdout.trim();
      var expected = 'Not expired';

      t.is(actual, expected);

      t.end();
    });

    stdin.end();
  });
});

var pseudoOldHash = '{"iterations": 0}';

test('cli - expired - did expired', function (t){
  var stdin = execCli(['expired', pseudoOldHash, 0], function (err, stdout, stderr){
    var actual = stderr.trim();
    var expected = /Error: Expired/;
    t.ok(expected.test(actual));
    t.end();
  });

  stdin.end();
});
