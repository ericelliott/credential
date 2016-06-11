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

    var expected = /Error: Password must be a non-empty string/;

    t.throws(function (){
      throw stderr;
    }, expected, 'should throw non-empty string error');

    t.end();
  });

  stdin.end();
});
